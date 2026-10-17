"""PSA write settings — slice 0 of the PSA write design: the writes kill switch.

  GET /api/v1/admin/psa/instances/{instance_id}/settings   admin+
  PUT /api/v1/admin/psa/instances/{instance_id}/settings   super_admin + step-up
      body: {"writes_enabled": bool, "reason": "<3..500 chars>"}

The switch is the Autotask instance's `writes_enabled` key (registry
`adapter_instances.instance_config_json` — persisted, so it survives every
restart; no migration). Default OFF. See
`apps/octo/adapters/autotask/writes_switch.py` for everything it gates.

A flip is audited BEFORE the write (`psa.instance.writes_toggle`, global
chain; a failed audit changes nothing), and a write that then fails gets its
`psa.instance.writes_toggle_failed` twin. After the write the running
adapter is told (`apply_writes_enabled`): OFF stops the pusher now; even if
that stop could not be delivered, the pusher re-reads the persisted switch
before every send and refuses. A PUT that changes nothing writes and audits
nothing.

Slice 1 grows this route into the full settings body (kinds, API resource
ids, budget, notes freeze); slice 0 accepts the switch only.
"""
from __future__ import annotations

import logging
import threading
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, Path, Request
from pydantic import BaseModel, ConfigDict, StrictBool

from apps.octo import paths
from apps.octo.adapters.autotask.writes_switch import (
    PSA_VENDOR_SLUGS,
    WRITES_ENABLED_KEY,
    writes_enabled_in,
)
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason
from apps.octo.api.role_gates import session_admin_plus, session_super_admin
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.instances.manager import InstanceRecord, get_instance, update_instance_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/psa", tags=["admin-psa"])

# One switch flip at a time (the route runs on the threadpool): the
# read-compare-audit-write-apply sequence below must not interleave, or two
# identical PUTs would both see "off", both audit, both write and both ask
# the adapter for a pusher.
_SETTINGS_LOCK = threading.Lock()


class PsaInstanceSettings(BaseModel):
    instance_id: int
    vendor_slug: str
    writes_enabled: bool
    pusher_running: Optional[bool] = None
    """Whether this process runs a write-back pusher for the instance; None
    when the instance is not running here."""
    applied_live: Optional[bool] = None
    """PUT only: whether the running adapter took the change at once (the
    persisted switch rules either way)."""


class PsaInstanceSettingsPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    writes_enabled: StrictBool
    reason: AuditReason


def _super_admin_with_step_up():
    """super_admin first (403 for anyone else), then an active step-up
    window (401 STEP_UP_REQUIRED) — the bar for every PSA setting."""

    def _dep(
        _role: sessions.SessionInfo = Depends(session_super_admin),
        info: sessions.SessionInfo = Depends(require_step_up),
    ) -> sessions.SessionInfo:
        return info

    _dep.__name__ = "session_super_admin_with_step_up"
    return _dep


def _psa_record(instance_id: int) -> InstanceRecord:
    record = get_instance(instance_id)
    if record is None or record.vendor_slug not in PSA_VENDOR_SLUGS:
        raise APIError("NOT_FOUND", f"no PSA instance {instance_id}")
    return record


def _running_adapter(request: Request, instance_id: int) -> Any:
    manager = getattr(request.app.state, "instance_manager", None)
    running = getattr(manager, "running_adapter", None)
    return running(instance_id) if callable(running) else None


def _out(record: InstanceRecord, adapter: Any, *,
         applied_live: Optional[bool] = None) -> PsaInstanceSettings:
    pusher = getattr(adapter, "pusher_running", None) if adapter is not None else None
    return PsaInstanceSettings(
        instance_id=record.id,
        vendor_slug=record.vendor_slug,
        writes_enabled=writes_enabled_in(record.instance_config),
        pusher_running=bool(pusher) if pusher is not None else None,
        applied_live=applied_live,
    )


def _audit(info: sessions.SessionInfo, action: str, instance_id: int,
           before: Any, after: Any, reason: str) -> None:
    """Append to the global chain. Raises when the chain cannot be written:
    a change nobody can see never happens."""
    g = connect(paths.global_audit_db_path())
    try:
        audit.append(g, audit.AuditEntry(
            actor=str(info.operator_id), actor_kind="human", action=action,
            target_kind="adapter_instance", target_id=str(instance_id),
            client_slug="global", before_state=before, after_state=after,
            reason=reason, request_id=str(uuid.uuid4()),
        ))
    finally:
        g.close()


@router.get("/instances/{instance_id}/settings", response_model=PsaInstanceSettings)
def get_psa_settings(
    request: Request,
    instance_id: int = Path(..., ge=1),
    _info: sessions.SessionInfo = Depends(session_admin_plus),
) -> PsaInstanceSettings:
    record = _psa_record(instance_id)
    return _out(record, _running_adapter(request, instance_id))


@router.put("/instances/{instance_id}/settings", response_model=PsaInstanceSettings)
def put_psa_settings(
    body: PsaInstanceSettingsPut,
    request: Request,
    instance_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(_super_admin_with_step_up()),
) -> PsaInstanceSettings:
    with _SETTINGS_LOCK:
        return _put_psa_settings_locked(body, request, instance_id, info)


def _put_psa_settings_locked(
    body: PsaInstanceSettingsPut, request: Request, instance_id: int,
    info: sessions.SessionInfo,
) -> PsaInstanceSettings:
    # Read INSIDE the lock: a PUT that waited sees what the one before it
    # wrote, so a repeated request is the no-op it should be.
    record = _psa_record(instance_id)
    if record.disabled_at is not None:
        raise APIError("CONFLICT", f"PSA instance {instance_id} is disabled; its "
                                   "settings can no longer be changed")
    before = writes_enabled_in(record.instance_config)
    after = bool(body.writes_enabled)
    adapter = _running_adapter(request, instance_id)
    if before == after:
        return _out(record, adapter)

    state_before = {"vendor_slug": record.vendor_slug, WRITES_ENABLED_KEY: before}
    state_after = {"vendor_slug": record.vendor_slug, WRITES_ENABLED_KEY: after}
    # Audit FIRST: if the chain cannot take the row, nothing changes.
    _audit(info, "psa.instance.writes_toggle", instance_id,
           state_before, state_after, body.reason)
    try:
        update_instance_config(instance_id, {WRITES_ENABLED_KEY: after})
    except Exception as exc:
        _audit(info, "psa.instance.writes_toggle_failed", instance_id,
               state_before, {"error": type(exc).__name__},
               f"writes switch not saved: {type(exc).__name__}; nothing was changed")
        raise

    applied: Optional[bool] = None
    apply = getattr(adapter, "apply_writes_enabled", None)
    if callable(apply):
        try:
            applied = bool(apply(after))
        except Exception:  # noqa: BLE001 — the persisted switch rules anyway
            logger.exception("[psa] instance %s: switch saved but not applied live", instance_id)
            applied = False
        if not applied:
            logger.error(
                "[psa] instance %s: writes switch set to %s but the running adapter did "
                "not take it; the pusher re-reads the switch before every send",
                instance_id, after,
            )
    fresh = get_instance(instance_id) or record
    return _out(fresh, adapter, applied_live=applied)
