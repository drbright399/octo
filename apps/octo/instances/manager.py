"""InstanceManager + per-row CRUD helpers for adapter_instances.

The data layer (`create_instance`, `list_instances`, `update_instance_status`)
is intentionally split from the lifecycle layer (`InstanceManager`) so the
HTTP layer can persist a row without owning a manager — useful in tests +
useful for the catalog smoke-test flow (which never starts a poller).

The manager keeps a process-local registry of {instance_id → adapter object}
so it can call `.stop()` later. There's exactly one manager per process,
held on `app.state.instance_manager`.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from apps.octo import credentials, paths
from apps.octo.db import connect, transaction
from apps.octo.framework.registry import AdapterRegistry

logger = logging.getLogger(__name__)


class InstanceLifecycleError(Exception):
    """Raised on adapter start/stop failures from the manager perspective."""


# ---------------------------------------------------------------------------
# Row dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InstanceRecord:
    id: int
    vendor_slug: str
    display_name: str
    cred_ref: str
    instance_config_json: str
    default_tenant_slug: Optional[str]
    status: str
    status_detail: Optional[str]
    configured_at: str
    configured_by_operator_id: Optional[int]
    last_test_at: Optional[str]
    last_event_at: Optional[str]
    disabled_at: Optional[str]
    disabled_by_operator_id: Optional[int]
    disabled_reason: Optional[str]

    @property
    def instance_config(self) -> dict[str, Any]:
        try:
            data = json.loads(self.instance_config_json or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}


def _row_to_record(row: sqlite3.Row) -> InstanceRecord:
    return InstanceRecord(
        id=row["id"],
        vendor_slug=row["vendor_slug"],
        display_name=row["display_name"],
        cred_ref=row["cred_ref"],
        instance_config_json=row["instance_config_json"] or "{}",
        default_tenant_slug=row["default_tenant_slug"],
        status=row["status"],
        status_detail=row["status_detail"],
        configured_at=row["configured_at"],
        configured_by_operator_id=row["configured_by_operator_id"],
        last_test_at=row["last_test_at"],
        last_event_at=row["last_event_at"],
        disabled_at=row["disabled_at"],
        disabled_by_operator_id=row["disabled_by_operator_id"],
        disabled_reason=row["disabled_reason"],
    )


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Persistence helpers (HTTP layer + manager both use these)
# ---------------------------------------------------------------------------

def create_instance(
    *,
    vendor_slug: str,
    display_name: str,
    credentials_dict: dict[str, Any],
    instance_config: dict[str, Any] | None = None,
    default_tenant_slug: str | None = None,
    configured_by_operator_id: int | None = None,
    last_test_at: str | None = None,
) -> InstanceRecord:
    """Encrypt credentials, persist a row, return the InstanceRecord.

    Caller is responsible for running smoke_test() FIRST — this function
    does NOT validate credentials against the upstream. Pass the time that
    test passed as `last_test_at` so the row is born with it.
    """
    cred_ref = credentials.store(credentials_dict)
    cfg_json = json.dumps(instance_config or {}, sort_keys=True)

    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            cur = reg.execute(
                """
                INSERT INTO adapter_instances (
                    vendor_slug, display_name, cred_ref,
                    instance_config_json, default_tenant_slug,
                    status, configured_by_operator_id, last_test_at
                ) VALUES (?, ?, ?, ?, ?, 'starting', ?, ?)
                """,
                (
                    vendor_slug, display_name, cred_ref,
                    cfg_json, default_tenant_slug,
                    configured_by_operator_id, last_test_at,
                ),
            )
            new_id = cur.lastrowid
        row = reg.execute(
            "SELECT * FROM adapter_instances WHERE id = ?",
            (new_id,),
        ).fetchone()
    finally:
        reg.close()
    if row is None:
        raise InstanceLifecycleError("inserted row could not be re-read")
    return _row_to_record(row)


def list_instances(*, include_disabled: bool = False) -> list[InstanceRecord]:
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM adapter_instances"
        if not include_disabled:
            sql += " WHERE disabled_at IS NULL"
        sql += " ORDER BY id"
        rows = reg.execute(sql).fetchall()
    finally:
        reg.close()
    return [_row_to_record(r) for r in rows]


def get_instance(instance_id: int) -> InstanceRecord | None:
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        row = reg.execute(
            "SELECT * FROM adapter_instances WHERE id = ?",
            (instance_id,),
        ).fetchone()
    finally:
        reg.close()
    return _row_to_record(row) if row else None


def update_instance_status(
    instance_id: int,
    *,
    status: str,
    status_detail: str | None = None,
    last_event_at: str | None = None,
    last_test_at: str | None = None,
) -> None:
    """Set the row's status (and optionally last_*_at timestamps)."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                """
                UPDATE adapter_instances
                   SET status = ?,
                       status_detail = COALESCE(?, status_detail),
                       last_event_at = COALESCE(?, last_event_at),
                       last_test_at = COALESCE(?, last_test_at)
                 WHERE id = ?
                """,
                (status, status_detail, last_event_at, last_test_at, instance_id),
            )
    finally:
        reg.close()


def set_contact_status(
    instance_id: int, *, status: str, status_detail: str,
) -> bool:
    """Record what a running poller observed (see `vendor_contact`). True when
    a row changed.

    Differs from `update_instance_status` in two ways that matter here:
    status_detail is SET, not COALESCEd — a recovered instance must not keep
    its old error line — and a disabled row is never touched, because a
    poller can report once more while its stop is still being delivered and
    must not flip 'disabled' back to 'running'.
    """
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                """
                UPDATE adapter_instances
                   SET status = ?,
                       status_detail = ?
                 WHERE id = ?
                   AND disabled_at IS NULL
                """,
                (status, status_detail, instance_id),
            )
            return cur.rowcount > 0
    finally:
        reg.close()


def update_instance_config(
    instance_id: int, updates: dict[str, Any],
) -> dict[str, Any]:
    """Merge NON-SECRET keys into the row's instance_config_json (a value of
    None deletes the key) and return the new config. Read-modify-write under
    one transaction. Credentials never live in this column."""
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = reg.execute(
                "SELECT instance_config_json FROM adapter_instances WHERE id = ?",
                (instance_id,),
            ).fetchone()
            if row is None:
                raise InstanceLifecycleError(f"no adapter instance {instance_id}")
            try:
                config = json.loads(row["instance_config_json"] or "{}")
            except json.JSONDecodeError:
                config = {}
            if not isinstance(config, dict):
                config = {}
            for key, value in updates.items():
                if value is None:
                    config.pop(key, None)
                else:
                    config[key] = value
            reg.execute(
                "UPDATE adapter_instances SET instance_config_json = ? WHERE id = ?",
                (json.dumps(config, sort_keys=True), instance_id),
            )
            return config
    finally:
        reg.close()


def mark_started_if_new(instance_id: int) -> bool:
    """'starting' → 'running' / 'started', and ONLY that. For adapters whose
    poller reports vendor contact: a row that already says 'error' (or
    'running') carries the last OBSERVATION, and a process restart must not
    replace it with a claim nobody has observed yet — the reporter's first
    report is always written, so the row converges within one poll."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                """
                UPDATE adapter_instances
                   SET status = 'running',
                       status_detail = 'started'
                 WHERE id = ?
                   AND status = 'starting'
                """,
                (instance_id,),
            )
            return cur.rowcount > 0
    finally:
        reg.close()


def disable_instance(
    instance_id: int,
    *,
    disabled_by_operator_id: int | None,
    reason: str,
) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                """
                UPDATE adapter_instances
                   SET status = 'disabled',
                       disabled_at = ?,
                       disabled_by_operator_id = ?,
                       disabled_reason = ?
                 WHERE id = ?
                """,
                (_utc_iso_now(), disabled_by_operator_id, reason, instance_id),
            )
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# InstanceManager — runtime lifecycle owner
# ---------------------------------------------------------------------------

@dataclass
class _RunningInstance:
    record: InstanceRecord
    adapter: Any  # SourceAdapter instance (no shared base type-import needed)


_current: Optional["weakref.ReferenceType[InstanceManager]"] = None


def current_manager() -> Optional["InstanceManager"]:
    """The process's manager (the newest constructed; held weakly), or None.
    For a background job that runs inside an adapter and must read what the
    OTHER running instances know — the Autotask poller's daily location
    proposals read the Fleet (UniFi sites and their names)."""
    ref = _current
    return ref() if ref is not None else None


class InstanceManager:
    """Process-local registry of {instance_id → live adapter object}.

    Composed with — not bolted onto — `AdapterRegistry`. Registry tracks
    adapter CLASSES; manager tracks per-row live OBJECTS.
    """

    def __init__(self, *, adapter_registry: AdapterRegistry) -> None:
        global _current
        self._adapter_registry = adapter_registry
        self._running: dict[int, _RunningInstance] = {}
        _current = weakref.ref(self)

    # --- query ---

    def is_running(self, instance_id: int) -> bool:
        return instance_id in self._running

    def list_running(self) -> list[InstanceRecord]:
        return [r.record for r in self._running.values()]

    def running_adapter(self, instance_id: int) -> Any:
        """The live adapter object of a running instance, or None. For
        on-demand capabilities that must use the instance's OWN client
        (device portal links) instead of decrypting credentials again."""
        running = self._running.get(instance_id)
        return running.adapter if running is not None else None

    # --- lifecycle ---

    def start_instance(self, record: InstanceRecord) -> None:
        """Construct the adapter, decrypt creds, call adapter.start().

        Raises InstanceLifecycleError on misconfiguration. Updates the DB
        row's status from 'starting' to 'running' (or 'error').

        'running' / 'started' here only means start() returned. From then on
        the row follows what the poller OBSERVES, for adapters that report it
        (see `vendor_contact`): 'error' + an actionable detail while contact
        with the vendor fails, back to 'running' when it works again. For
        those adapters only a brand-new ('starting') row is promoted here: on
        a process restart the row keeps its last observation until the first
        poll reports.
        """
        if record.id in self._running:
            return None
        adapter_cls = self._adapter_registry.get_adapter_class(record.vendor_slug)
        if adapter_cls is None:
            msg = (
                f"vendor_slug={record.vendor_slug!r} not registered in framework "
                "(was the adapter package not discovered at boot?)"
            )
            update_instance_status(
                record.id, status="error", status_detail=msg,
            )
            raise InstanceLifecycleError(msg)

        try:
            creds = credentials.load(record.cred_ref)
        except Exception as exc:
            msg = f"failed to decrypt cred_ref: {exc}"
            update_instance_status(
                record.id, status="error", status_detail=msg,
            )
            raise InstanceLifecycleError(msg) from exc

        # Merge the row's runtime config with credentials. Credentials win
        # on key collision so a stale config can't shadow the real cred.
        merged_config: dict[str, Any] = {**record.instance_config, **creds}
        if record.default_tenant_slug:
            merged_config.setdefault("default_tenant_slug", record.default_tenant_slug)
        # Framework-injected: lets the adapter route ingest through this
        # instance's tenant map (vendor tenant id → OCTO client slug).
        merged_config["_instance_id"] = record.id

        self._record_derived_portal_base(record, adapter_cls, merged_config)

        adapter = adapter_cls()
        try:
            adapter.start(merged_config)
        except Exception as exc:
            msg = f"adapter.start() raised: {exc}"
            update_instance_status(
                record.id, status="error", status_detail=msg,
            )
            raise InstanceLifecycleError(msg) from exc

        self._running[record.id] = _RunningInstance(record=record, adapter=adapter)
        if getattr(adapter_cls, "reports_vendor_contact", False):
            mark_started_if_new(record.id)
        else:
            update_instance_status(
                record.id, status="running", status_detail="started",
            )
        logger.info(
            "[instance-manager] started id=%s vendor=%s",
            record.id, record.vendor_slug,
        )

    @staticmethod
    def _record_derived_portal_base(
        record: InstanceRecord, adapter_cls: Any, merged_config: dict[str, Any],
    ) -> None:
        """Vendor portal links need the portal's base URL, which an adapter
        can derive from its API URL — but that URL sits in the ENCRYPTED
        credential blob, and a dashboard read must never decrypt credentials.
        This is the one place the blob is open anyway: keep the derived,
        non-secret base in instance_config (see `instances.vendor_links`).
        Best-effort — a link nicety never blocks a start."""
        derive = getattr(adapter_cls, "derive_portal_base", None)
        if not callable(derive):
            return
        from apps.octo.instances.vendor_links import DERIVED_BASE_KEY

        try:
            derived = derive(merged_config)
            derived = derived if isinstance(derived, str) and derived else None
            if record.instance_config.get(DERIVED_BASE_KEY) != derived:
                update_instance_config(record.id, {DERIVED_BASE_KEY: derived})
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[instance-manager] id=%s could not record the vendor portal "
                "base (%s) — no portal links until the next start",
                record.id, type(exc).__name__,
            )

    def stop_instance(self, instance_id: int) -> None:
        """Call adapter.stop() and drop from the running set. Idempotent."""
        running = self._running.pop(instance_id, None)
        if running is None:
            return None
        try:
            running.adapter.stop()
        except Exception as exc:
            logger.warning(
                "[instance-manager] stop_instance id=%s adapter.stop() raised: %s",
                instance_id, exc,
            )
        logger.info("[instance-manager] stopped id=%s", instance_id)

    def nudge(self, instance_id: int) -> bool:
        """Ask a running instance's poller to poll NOW (adapters that offer
        `poll_now()`). True when delivered. Never raises."""
        running = self._running.get(instance_id)
        poll_now = getattr(running.adapter, "poll_now", None) if running else None
        if not callable(poll_now):
            return False
        try:
            poll_now()
        except Exception as exc:  # noqa: BLE001 — a courtesy, never fatal
            logger.warning(
                "[instance-manager] nudge id=%s failed (%s)",
                instance_id, type(exc).__name__,
            )
            return False
        return True

    def start_all_persisted(self) -> dict[str, list[int]]:
        """Boot hook: start every persisted non-disabled instance.

        Returns {'started': [ids], 'failed': [ids]}. Failures don't stop
        the loop — one broken adapter shouldn't take the bundle down.
        """
        started: list[int] = []
        failed: list[int] = []
        for record in list_instances(include_disabled=False):
            if record.status == "disabled":
                continue
            try:
                self.start_instance(record)
                started.append(record.id)
            except Exception as exc:
                logger.error(
                    "[instance-manager] boot-time start failed id=%s vendor=%s: %s",
                    record.id, record.vendor_slug, exc,
                )
                failed.append(record.id)
        return {"started": started, "failed": failed}

    def stop_all_running(self) -> None:
        """Shutdown hook: stop everything we started. Idempotent."""
        for instance_id in list(self._running.keys()):
            self.stop_instance(instance_id)
