"""Operator notices — `/api/v1/admin/notices` (v0.10, migration 035).

When a super_admin applies a tenant merge or offboard ALONE (the attested
single-person exception, `admin_tenants.py`), every other admin+ operator
gets a notice (`auth.operator_notices`). The console shows a recipient their
open notices on every load until they acknowledge them:

  GET  /admin/notices                 analyst+ (an analyst receives the threat_*
                                      notices — Tier Black's paging — and sees
                                      only those, only their own, and only
                                      about tenants STILL in their scope: a
                                      former admin, or an analyst taken off a
                                      tenant, reads nothing older about it).
                                      The CALLER's own notices, newest
                                      first — open ones only, or with
                                      ?include_acknowledged=1 the recent ones
                                      too — and the open count. Unaudited (a
                                      read of one's own inbox is not a
                                      decision; docs/audit-policy.md).
  POST /admin/notices/{id}/acknowledge
                                      analyst+, the recipient only (another
                                      admin's notice is a 404 — not theirs to
                                      see). Audited
                                      'operator_notice_acknowledge'.
                                      Idempotent: acknowledging twice writes
                                      nothing the second time.

A notice carries what the server wrote — who did what to which tenants, and
when — never the typed attestation (the change record holds it; the requests
panel shows it) and never a credential.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_analyst_plus,
)
from apps.octo.api.routers.admin_tenants import _audit_row
from apps.octo.auth import operator_notices, sessions
from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import utcnow_iso

router = APIRouter(prefix="/admin/notices", tags=["admin-notices"])


class NoticeOut(BaseModel):
    id: int
    kind: str
    actor_id: int
    subject_slug: str
    target_slug: Optional[str] = None
    change_request_id: Optional[int] = None
    title: str
    body: str
    created_at: str
    acknowledged_at: Optional[str] = None
    # pending | sent | failed | not_configured | no_address — the e-mail copy.
    email_state: str


class NoticeListResponse(BaseModel):
    notices: list[NoticeOut] = Field(default_factory=list)
    open: int = 0


def _threat_scope(operator_id: int) -> Optional[list[str]]:
    """None for admin+ (every notice of theirs); below admin, the scope
    their threat notices are limited to (`operator_notices._limited`)."""
    if operator_max_tier(operator_id) >= ROLE_TIER["admin"]:
        return None
    return resolve_caller_scope(operator_id)


def _notice_out(r: sqlite3.Row) -> NoticeOut:
    return NoticeOut(
        id=int(r["id"]), kind=r["kind"], actor_id=int(r["actor_id"]),
        subject_slug=r["subject_slug"], target_slug=r["target_slug"],
        change_request_id=r["change_request_id"], title=r["title"], body=r["body"],
        created_at=r["created_at"], acknowledged_at=r["acknowledged_at"],
        email_state=r["email_state"],
    )


@router.get("", response_model=NoticeListResponse)
def list_notices(
    response: Response,
    include_acknowledged: int = Query(default=0),
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
) -> NoticeListResponse:
    response.headers["Cache-Control"] = "no-store"
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        limit = _threat_scope(caller.operator_id)
        rows = operator_notices.list_for(
            reg, caller.operator_id, include_acknowledged=bool(include_acknowledged),
            threat_scope=limit,
        )
        return NoticeListResponse(
            notices=[_notice_out(r) for r in rows],
            open=operator_notices.open_count(reg, caller.operator_id, threat_scope=limit),
        )
    finally:
        reg.close()


@router.post("/{notice_id}/acknowledge", response_model=NoticeOut)
def acknowledge_notice(
    notice_id: int,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
) -> NoticeOut:
    limit = _threat_scope(caller.operator_id)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            row = operator_notices.get_for(reg, notice_id, caller.operator_id,
                                           threat_scope=limit)
            if row is None:
                raise APIError("NOT_FOUND", f"no notice {notice_id} for you")
            if row["acknowledged_at"] is None:
                now = utcnow_iso()
                _audit_row(
                    operator_id=caller.operator_id, action="operator_notice_acknowledge",
                    slug=row["subject_slug"], target_kind="operator_notice",
                    target_id=str(notice_id),
                    after={"kind": row["kind"], "change_request_id": row["change_request_id"],
                           "acknowledged_at": now},
                    reason="notice acknowledged by its recipient",
                )
                operator_notices.acknowledge(reg, notice_id, caller.operator_id, now=now)
                row = operator_notices.get_for(reg, notice_id, caller.operator_id,
                                               threat_scope=limit)
            return _notice_out(row)
    finally:
        reg.close()
