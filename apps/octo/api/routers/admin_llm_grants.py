"""Admin endpoint: grant / revoke L2 LLM access per operator.

Per the octo-llm triage-taxonomy design decision + Rick's 2026-05-21
design call, octo-llm enrichment is per-operator opt-in. The OPERATOR
opts in via /api/v1/account/preferences (slice 5b — their own
toggle). The ADMIN must FIRST GRANT them eligibility via this
endpoint. Both must be true for the bridge to reach octo-llm.

Tier rule (same shape as the existing role-grant tier rule in
admin_ops.py):
  factory     can grant to / revoke from super_admin and below
  super_admin can grant to / revoke from admin and below
  admin       can grant to / revoke from analyst and viewer
  analyst     cannot grant
  viewer      cannot grant

The factory super_admin is implicitly granted by migration 027.
Other operators land with granted=0 and must be promoted.

Audit row per grant + revoke. Captures caller, target, before/after
state, and the request_id so the bundle's compliance reporting can
trace LLM access changes alongside role grants.

Banked 2026-05-21 as slice 5d-2.
"""
from __future__ import annotations

import sqlite3
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import (
    ROLE_TIER,
    get_operator_roles,
    operator_max_tier,
    session_at_least,
)
from apps.octo.api.routers.auth import _audit_append
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="/admin/operators", tags=["admin", "llm"])


class LlmGrantRequest(BaseModel):
    granted: bool


class LlmGrantResponse(BaseModel):
    operator_id: int
    granted: bool


# ---------------------------------------------------------------------------
# Tier rule for LLM grants
# ---------------------------------------------------------------------------

def _enforce_llm_grant_tier_rule(caller_id: int, target_id: int) -> None:
    """Raise ISOLATION_VIOLATION if `caller_id` cannot grant/revoke
    LLM access for `target_id`.

    The check is symmetric to the role-grant tier rule but uses the
    target operator's HIGHEST current role to compute their tier.
    """
    caller_tier = operator_max_tier(caller_id)
    if caller_tier < ROLE_TIER["admin"]:
        raise APIError(
            "ISOLATION_VIOLATION",
            "only admin and above may grant/revoke LLM access",
        )
    target_roles = get_operator_roles(target_id)
    if not target_roles:
        # Operator has no Console role — nothing to gate, but
        # also nothing to grant. Treat as not-permitted.
        raise APIError(
            "ISOLATION_VIOLATION",
            f"target operator {target_id} has no Console role",
        )
    target_tier = max(ROLE_TIER.get(r, 0) for r in target_roles)
    if caller_tier < target_tier:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"caller tier {caller_tier} insufficient to manage LLM access "
            f"for operator with tier {target_tier}",
        )
    # Prevent revoking the factory's grant — even super_admins can
    # ask, but it's a no-op the factory undoes anyway. Defensive:
    # refuse outright at the gate so the audit doesn't fill with
    # noise.
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT is_factory FROM operators WHERE id = ?",
                (target_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
    finally:
        reg.close()
    if row is not None:
        is_fac = row[0] if not hasattr(row, "keys") else row["is_factory"]
        if is_fac and caller_id != target_id:
            raise APIError(
                "ISOLATION_VIOLATION",
                "the factory super_admin's LLM grant cannot be modified by others",
            )


def _read_grant(operator_id: int) -> Optional[bool]:
    """Read the current grant state. None if operator not found or
    column doesn't exist."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = reg.execute(
                "SELECT l2_llm_granted FROM operators WHERE id = ?",
                (operator_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None
    finally:
        reg.close()
    if row is None:
        return None
    val = row[0] if not hasattr(row, "keys") else row["l2_llm_granted"]
    return bool(val)


def _write_grant(operator_id: int, granted: bool) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE operators SET l2_llm_granted = ? WHERE id = ?",
            (1 if granted else 0, operator_id),
        )
        reg.commit()
    finally:
        reg.close()


@router.put("/{operator_id}/llm-grant", response_model=LlmGrantResponse)
def set_llm_grant(
    body: LlmGrantRequest,
    operator_id: int = Path(ge=1),
    info: sessions.SessionInfo = Depends(session_at_least("admin")),
) -> LlmGrantResponse:
    """Grant or revoke a subordinate operator's L2 LLM access.

    Requires caller's tier ≥ target's tier. Factory super_admin's
    grant is locked (can only be modified by the factory themself,
    which is a no-op since they're already granted).
    """
    _enforce_llm_grant_tier_rule(info.operator_id, operator_id)

    # Confirm the operator exists and capture before-state for audit.
    before = _read_grant(operator_id)
    if before is None:
        raise APIError("NOT_FOUND", f"operator {operator_id} not found")

    if before == body.granted:
        # No-op — don't write or audit. Saves audit noise from
        # idempotent UI toggles.
        return LlmGrantResponse(operator_id=operator_id, granted=body.granted)

    _write_grant(operator_id, body.granted)
    _audit_append(
        "l2_llm_grant_change",
        actor=str(info.operator_id),
        target_id=f"operator:{operator_id}",
        before={"granted": before},
        after={"granted": body.granted},
        reason=None,
        request_id=str(uuid.uuid4()),
    )
    return LlmGrantResponse(operator_id=operator_id, granted=body.granted)


# ---------------------------------------------------------------------------
# Public helper for the bridge endpoint
# ---------------------------------------------------------------------------

def operator_l2_llm_granted(operator_id: int) -> bool:
    """Bridge convenience — True iff the operator has been granted
    L2 LLM access by an admin+. False on missing column (pre-027) so
    the gate fail-closes if the migration hasn't landed."""
    return _read_grant(operator_id) is True
