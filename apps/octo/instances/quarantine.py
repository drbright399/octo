"""Quarantine — the bucket for integration traffic nobody can attribute yet.

Every vendor event gets a bucket (product ruling). When the ingest path
cannot say WHICH tenant an event belongs to — no vendor tenant id, a site
name that matches two clients, a site that belongs to an offboarded tenant,
the auto-create bound reached — the event is HELD here, whole, for a human
to route (`POST /admin/quarantine/{id}/route`) or discard. Nothing is dropped
any more; nothing here creates anything by itself either.

Threat model. Held payloads come straight from a vendor's API or webhook and
are UNTRUSTED: they are stored as opaque text, bounded (`MAX_PAYLOAD_BYTES`),
never parsed on the way in beyond what the adapter already did, and only
rendered as text on the way out. The store is bounded per instance
(`MAX_ROWS_PER_INSTANCE`, `MAX_AGE_DAYS`), idempotent per (instance, payload
sha) so a poller re-listing an open alert holds it ONCE, and admin-only — a
viewer is a client user and never sees it. Retention prefers a human's
decision over the clock: routed/discarded rows age out and are the first to
go when the row cap is reached; a HELD row is only ever evicted by the row cap
under a flood, and every such eviction is counted and shown on the card.

Storage: `global/quarantine.db`, a platform DB (never a client dir). Its
schema is the `-- @target: quarantine` section of the migrations (033+),
applied lazily by `ensure_db()` with the same user_version tracking the other
targets use — so the file appears the first time something is held and a
bundle upgrade catches it up on next use.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from apps.octo import paths
from apps.octo.ingest.presentation import clean_line
from apps.octo.ingest.timestamps import format_utc_ms, utcnow_iso
from apps.octo.migration import apply_migration, list_migrations

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 256 * 1024
MAX_ROWS_PER_INSTANCE = 5000
MAX_AGE_DAYS = 30
MAX_ID_CHARS = 256
MAX_LABEL_CHARS = 200
MAX_SUMMARY_CHARS = 160
MAX_REASON_CHARS = 64

# The closed set of reasons an event can be held for. Anything else is a
# programming error, not vendor input.
REASONS: tuple[str, ...] = (
    "no-tenant-id",        # nothing on the payload says which vendor tenant
    "name-unknown",        # vendor id known, no name to match or create from
    "ambiguous-name",      # the name matches two or more active clients
    "name-already-mapped", # the name matches one client, but another site of
                           # this instance is already mapped to it
    "name-match-suggested",  # the name matches exactly one client: a
                             # SUGGESTION for a human, never a link (the
                             # same-name rule) — one click maps the site
    "offboarded-tenant",   # the site belongs to a tenant that is not active
                           # (offboarded / archived / disabled)
    "default-tenant-missing",  # id-less event; the instance's default tenant
                               # names a client that does not exist
    "autocreate-limit",    # the per-instance auto-create bound is reached
    "instance-disabled",   # traffic from an instance that is switched off
    "store-failed",        # the tenant is known but its store refused the write
)

_QUARANTINE_TARGET = "quarantine"
_lock = threading.Lock()
_schema_ensured: set[str] = set()
# HELD rows evicted by the row cap since restart, per instance — for the
# card ("N held events were evicted"). Memory only, like the other card
# counters. Routed/discarded rows going away is housekeeping, not news.
_evicted: dict[int, int] = {}


def db_path() -> Path:
    return paths.global_dir() / "quarantine.db"


@dataclass(frozen=True)
class Held:
    id: int
    created: bool          # False = this payload was already held (idempotent)


@dataclass(frozen=True)
class QuarantineRow:
    id: int
    received_at: str
    adapter_instance_id: int
    vendor_slug: str
    source: str
    vendor_tenant_id: Optional[str]
    vendor_tenant_label: Optional[str]
    reason: str
    payload_sha256: str
    payload_truncated: bool
    event_summary: Optional[str]
    routed_to_slug: Optional[str]
    routed_at: Optional[str]
    routed_by: Optional[str]
    discarded_at: Optional[str]
    discarded_by: Optional[str]
    discard_reason: Optional[str]

    @property
    def state(self) -> str:
        if self.routed_at:
            return "routed"
        if self.discarded_at:
            return "discarded"
        return "held"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def _quarantine_migration_numbers() -> list[int]:
    return [
        m.number for m in list_migrations(kind="forward")
        if f"-- @target: {_QUARANTINE_TARGET}" in m.sql
    ]


def ensure_db(path: Optional[Path] = None) -> list[int]:
    """Create/upgrade the quarantine DB. Returns the migration numbers applied
    this call ([] when current). Cheap after the first call per process."""
    target = path or db_path()
    key = str(target)
    if key in _schema_ensured:
        return []
    with _lock:
        if key in _schema_ensured:
            return []
        target.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(target)
        applied: list[int] = []
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            by_number = {m.number: m for m in list_migrations(kind="forward")}
            for num in _quarantine_migration_numbers():
                current = conn.execute("PRAGMA user_version").fetchone()[0]
                if current >= num:
                    continue
                apply_migration(conn, by_number[num], target=_QUARANTINE_TARGET)
                applied.append(num)
            conn.commit()
        finally:
            conn.close()
        _schema_ensured.add(key)
    return applied


def _connect() -> sqlite3.Connection:
    ensure_db()
    conn = sqlite3.connect(db_path(), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def reset_schema_cache() -> None:
    """Tests: forget which files were ensured (a new tmp data root)."""
    with _lock:
        _schema_ensured.clear()
        _evicted.clear()


# ---------------------------------------------------------------------------
# Hold
# ---------------------------------------------------------------------------

def _bounded_payload(payload: Any) -> tuple[str, bool, str]:
    """Opaque JSON text, cut at MAX_PAYLOAD_BYTES; sha over the FULL text so
    identity survives truncation. Non-serialisable input → its repr."""
    try:
        text = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = json.dumps({"_unserialisable": repr(payload)[:1000]})
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    if len(raw) <= MAX_PAYLOAD_BYTES:
        return text, False, sha
    cut = raw[:MAX_PAYLOAD_BYTES].decode("utf-8", errors="ignore")
    return cut, True, sha


def _opt(value: Any, limit: int) -> Optional[str]:
    text = clean_line(value, limit)
    return text or None


def hold(
    *,
    instance_id: int,
    vendor_slug: str,
    source: str,
    reason: str,
    payload: Any,
    vendor_tenant_id: Optional[str] = None,
    vendor_tenant_label: Optional[str] = None,
    event_summary: Optional[str] = None,
    payload_sha256: Optional[str] = None,
) -> Held:
    """Hold one payload. Idempotent on (instance, payload_sha256): a second
    hold of the same payload returns the existing id with `created=False`
    and writes nothing. Retention runs after every NEW row."""
    if reason not in REASONS:
        raise ValueError(f"unknown quarantine reason {reason!r}")
    text, truncated, sha = _bounded_payload(payload)
    sha = payload_sha256 or sha
    conn = _connect()
    try:
        existing = conn.execute(
            "SELECT id FROM quarantine WHERE adapter_instance_id = ? AND payload_sha256 = ?",
            (instance_id, sha),
        ).fetchone()
        if existing is not None:
            return Held(id=int(existing["id"]), created=False)
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO quarantine ("
                " adapter_instance_id, vendor_slug, source, vendor_tenant_id, "
                " vendor_tenant_label, reason, payload, payload_truncated, "
                " payload_sha256, event_summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    instance_id, clean_line(vendor_slug, 64), clean_line(source, 32),
                    _opt(vendor_tenant_id, MAX_ID_CHARS),
                    _opt(vendor_tenant_label, MAX_LABEL_CHARS),
                    reason, text, 1 if truncated else 0, sha,
                    _opt(event_summary, MAX_SUMMARY_CHARS),
                ),
            )
            if cur.rowcount == 0:  # lost a race with an identical hold
                row = conn.execute(
                    "SELECT id FROM quarantine WHERE adapter_instance_id = ? "
                    "AND payload_sha256 = ?", (instance_id, sha),
                ).fetchone()
                conn.execute("COMMIT")
                return Held(id=int(row["id"]), created=False)
            new_id = int(cur.lastrowid)
            evicted = _enforce_retention(conn, instance_id)
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    if evicted:
        with _lock:
            _evicted[instance_id] = _evicted.get(instance_id, 0) + evicted
        logger.warning(
            "[quarantine] instance id=%s: %d HELD event(s) evicted unreviewed — the "
            "cap of %d rows per integration was reached; review quarantine sooner",
            instance_id, evicted, MAX_ROWS_PER_INSTANCE,
        )
    return Held(id=new_id, created=True)


_RESOLVED = "(routed_at IS NOT NULL OR discarded_at IS NOT NULL)"


def _enforce_retention(conn: sqlite3.Connection, instance_id: int) -> int:
    """Resolved (routed / discarded) rows older than MAX_AGE_DAYS go; then,
    beyond MAX_ROWS_PER_INSTANCE, resolved rows go before held ones, oldest
    first within each. A held row is never aged out — a human's route or
    discard is what removes it, unless the cap forces it. Returns the number
    of HELD rows evicted (the only removal worth telling the operator)."""
    cutoff = format_utc_ms(datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS))
    conn.execute(
        f"DELETE FROM quarantine WHERE adapter_instance_id = ? AND received_at < ? "
        f"AND {_RESOLVED}",
        (instance_id, cutoff),
    )
    total = conn.execute(
        "SELECT COUNT(*) FROM quarantine WHERE adapter_instance_id = ?", (instance_id,),
    ).fetchone()[0]
    excess = int(total) - MAX_ROWS_PER_INSTANCE
    if excess <= 0:
        return 0
    held_before = conn.execute(
        f"SELECT COUNT(*) FROM quarantine WHERE adapter_instance_id = ? AND NOT {_RESOLVED}",
        (instance_id,),
    ).fetchone()[0]
    conn.execute(
        f"DELETE FROM quarantine WHERE id IN ("
        f" SELECT id FROM quarantine WHERE adapter_instance_id = ? "
        f" ORDER BY {_RESOLVED} DESC, id LIMIT ?)",
        (instance_id, excess),
    )
    held_after = conn.execute(
        f"SELECT COUNT(*) FROM quarantine WHERE adapter_instance_id = ? AND NOT {_RESOLVED}",
        (instance_id,),
    ).fetchone()[0]
    return max(0, int(held_before) - int(held_after))


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

_COLUMNS = (
    "id, received_at, adapter_instance_id, vendor_slug, source, vendor_tenant_id, "
    "vendor_tenant_label, reason, payload_sha256, payload_truncated, event_summary, "
    "routed_to_slug, routed_at, routed_by, discarded_at, discarded_by, discard_reason"
)


def _row(r: sqlite3.Row) -> QuarantineRow:
    return QuarantineRow(
        id=int(r["id"]), received_at=r["received_at"],
        adapter_instance_id=int(r["adapter_instance_id"]),
        vendor_slug=r["vendor_slug"], source=r["source"],
        vendor_tenant_id=r["vendor_tenant_id"],
        vendor_tenant_label=r["vendor_tenant_label"], reason=r["reason"],
        payload_sha256=r["payload_sha256"],
        payload_truncated=bool(r["payload_truncated"]),
        event_summary=r["event_summary"], routed_to_slug=r["routed_to_slug"],
        routed_at=r["routed_at"], routed_by=r["routed_by"],
        discarded_at=r["discarded_at"], discarded_by=r["discarded_by"],
        discard_reason=r["discard_reason"],
    )


def exists() -> bool:
    return db_path().exists()


def list_rows(
    *,
    instance_id: Optional[int] = None,
    reason: Optional[str] = None,
    vendor_tenant_id: Optional[str] = None,
    state: str = "held",
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[QuarantineRow], int]:
    """Newest first. `state`: held (default) | routed | discarded | all.
    Returns (rows, total matching)."""
    if not exists():
        return [], 0
    where = ["1=1"]
    args: list[Any] = []
    if instance_id is not None:
        where.append("adapter_instance_id = ?"); args.append(instance_id)
    if reason:
        where.append("reason = ?"); args.append(reason)
    if vendor_tenant_id is not None:
        where.append("vendor_tenant_id = ?"); args.append(vendor_tenant_id)
    if state == "held":
        where.append("routed_at IS NULL AND discarded_at IS NULL")
    elif state == "routed":
        where.append("routed_at IS NOT NULL")
    elif state == "discarded":
        where.append("discarded_at IS NOT NULL")
    clause = " AND ".join(where)
    conn = _connect()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM quarantine WHERE {clause}", args,
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM quarantine WHERE {clause} "
            "ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset],
        ).fetchall()
    finally:
        conn.close()
    return [_row(r) for r in rows], int(total)


def get(row_id: int) -> Optional[QuarantineRow]:
    if not exists():
        return None
    conn = _connect()
    try:
        r = conn.execute(f"SELECT {_COLUMNS} FROM quarantine WHERE id = ?", (row_id,)).fetchone()
    finally:
        conn.close()
    return _row(r) if r else None


def payload_text(row_id: int) -> Optional[str]:
    """The held payload, as the opaque text it was stored as."""
    if not exists():
        return None
    conn = _connect()
    try:
        r = conn.execute("SELECT payload FROM quarantine WHERE id = ?", (row_id,)).fetchone()
    finally:
        conn.close()
    return r["payload"] if r else None


def payload_json(row_id: int) -> Optional[dict[str, Any]]:
    """The held payload parsed back into the envelope the adapter saw, or
    None when it was truncated on the way in (cannot be re-ingested
    faithfully) or is not a JSON object."""
    row = get(row_id)
    if row is None or row.payload_truncated:
        return None
    text = payload_text(row_id)
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def counts(instance_id: Optional[int]) -> dict[str, int]:
    """`{held, evicted_since_restart}` for one instance."""
    with _lock:
        evicted = _evicted.get(instance_id, 0) if instance_id is not None else 0
    if instance_id is None or not exists():
        return {"held": 0, "evicted_since_restart": evicted}
    conn = _connect()
    try:
        held = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE adapter_instance_id = ? "
            "AND routed_at IS NULL AND discarded_at IS NULL", (instance_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    return {"held": int(held), "evicted_since_restart": evicted}


def held_count() -> int:
    """Held rows across every instance (for the tenant list header)."""
    if not exists():
        return 0
    conn = _connect()
    try:
        return int(conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE routed_at IS NULL AND discarded_at IS NULL",
        ).fetchone()[0])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------

def mark_routed(row_id: int, *, slug: str, by: str) -> bool:
    """True when the row was held and is now routed (a routed/discarded row
    is left alone)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE quarantine SET routed_to_slug = ?, routed_at = ?, routed_by = ? "
            "WHERE id = ? AND routed_at IS NULL AND discarded_at IS NULL",
            (slug, utcnow_iso(), clean_line(by, 64), row_id),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def mark_discarded(row_id: int, *, by: str, reason: str) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE quarantine SET discarded_at = ?, discarded_by = ?, discard_reason = ? "
            "WHERE id = ? AND routed_at IS NULL AND discarded_at IS NULL",
            (utcnow_iso(), clean_line(by, 64), clean_line(reason, 500), row_id),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def held_ids_for_vendor_tenant(
    instance_id: int, vendor_tenant_id: str, *, reason: Optional[str] = None,
    replayable_only: bool = False,
) -> list[int]:
    """Every held row from one vendor tenant on one instance — the bulk
    route/discard unit (30 held alerts from one site). `reason` narrows it
    to one hold reason (the console groups by site AND reason);
    `replayable_only` leaves out payloads truncated on arrival (they can be
    discarded, never routed)."""
    if not exists():
        return []
    where = (
        "adapter_instance_id = ? AND vendor_tenant_id = ? AND routed_at IS NULL "
        "AND discarded_at IS NULL"
    )
    args: list[Any] = [instance_id, vendor_tenant_id]
    if reason:
        where += " AND reason = ?"
        args.append(reason)
    if replayable_only:
        where += " AND payload_truncated = 0"
    conn = _connect()
    try:
        rows = conn.execute(
            f"SELECT id FROM quarantine WHERE {where} ORDER BY id", args,
        ).fetchall()
    finally:
        conn.close()
    return [int(r["id"]) for r in rows]


def card_warnings(instance_id: Optional[int], vendor_display_name: str) -> list[str]:
    """Operator-facing lines for the Integrations card; [] when nothing is
    held and nothing was evicted."""
    c = counts(instance_id)
    lines: list[str] = []
    if c["held"]:
        lines.append(
            f"{c['held']} event(s) from {vendor_display_name} are held in quarantine "
            "pending review — they could not be attributed to a tenant. Nothing is "
            "lost while it is held: route or discard them under Settings → Tenants → "
            f"Quarantine (the store keeps the newest {MAX_ROWS_PER_INSTANCE} events "
            "per integration)."
        )
    if c["evicted_since_restart"]:
        lines.append(
            f"{c['evicted_since_restart']} held event(s) from {vendor_display_name} "
            "were evicted from quarantine UNREVIEWED since the service last started: "
            f"the cap of {MAX_ROWS_PER_INSTANCE} events per integration was reached. "
            "Review quarantine sooner, or discard the noise."
        )
    return lines
