"""Per-buoy notepad endpoints (slice 12 backend).

Two streams, scoped per-buoy:

    GET    /api/v1/buoy/{slug}/notes/user     list user notes (newest first)
    POST   /api/v1/buoy/{slug}/notes/user     create a user note
    DELETE /api/v1/buoy/notes/user/{note_id}  delete (author or admin)

    GET    /api/v1/buoy/{slug}/notes/agent    list agent notes (newest first)
    POST   /api/v1/buoy/{slug}/notes/agent    create an agent note
                                              (admin+ + step-up; called by
                                              the agent CLI helper)

Visibility: governed by the same scope-slug grant the rest of the buoy
surface uses — operator must be able to see this slug. No per-note
privacy tier (per 2026-05-18 product call).

Note: this module imports `_operator_can_see_slug` from `routers.buoy`
to keep the access logic single-source. If that helper migrates to a
shared module later, this import follows.

Added 2026-05-18 — slice 12 backend.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Path, Query
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.api.routers.buoy import _operator_can_see_slug  # noqa: PLC2701
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="/buoy", tags=["buoy", "notes"])

AGENT_NOTE_ACTION_CLASSES = ("alert-behavior", "client-network", "state-change")
MAX_NOTE_BODY_BYTES = 32 * 1024  # 32KB Markdown — generous, prevents abuse
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


def _scope_or_403(operator_id: int, slug: str) -> None:
    if not _operator_can_see_slug(operator_id, slug):
        raise APIError("ISOLATION_VIOLATION")


# ---------------------------------------------------------------------------
# User notes — schemas
# ---------------------------------------------------------------------------

class BuoyUserNoteRequest(BaseModel):
    body_md: str = Field(min_length=1, max_length=MAX_NOTE_BODY_BYTES)


class BuoyUserNoteRow(BaseModel):
    id: int
    slug: str
    author_id: int
    body_md: str
    created_at: str
    updated_at: str


class BuoyUserNoteList(BaseModel):
    rows: list[BuoyUserNoteRow]
    next_cursor: Optional[int] = None


# ---------------------------------------------------------------------------
# User notes — endpoints
# ---------------------------------------------------------------------------

@router.get("/{slug}/notes/user", response_model=BuoyUserNoteList)
def list_user_notes(
    slug: str = Path(min_length=1, max_length=64),
    limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    cursor: Optional[int] = Query(default=None, ge=1),
    info: sessions.SessionInfo = Depends(session_identity),
) -> BuoyUserNoteList:
    _scope_or_403(info.operator_id, slug)
    reg = connect(paths.registry_db_path())
    try:
        q = (
            "SELECT id, slug, author_id, body_md, created_at, updated_at "
            "FROM buoy_user_notes WHERE slug = ?"
        )
        params: list = [slug]
        if cursor is not None:
            q += " AND id < ?"
            params.append(cursor)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit + 1)
        rows = reg.execute(q, params).fetchall()
    finally:
        reg.close()

    has_more = len(rows) > limit
    visible = rows[:limit]
    next_cursor = visible[-1][0] if has_more and visible else None
    return BuoyUserNoteList(
        rows=[BuoyUserNoteRow(
            id=r[0], slug=r[1], author_id=r[2], body_md=r[3],
            created_at=r[4], updated_at=r[5],
        ) for r in visible],
        next_cursor=next_cursor,
    )


@router.post("/{slug}/notes/user", response_model=BuoyUserNoteRow)
def create_user_note(
    body: BuoyUserNoteRequest,
    slug: str = Path(min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_identity),
) -> BuoyUserNoteRow:
    _scope_or_403(info.operator_id, slug)
    now = _iso_now()
    reg = connect(paths.registry_db_path())
    try:
        cur = reg.execute(
            "INSERT INTO buoy_user_notes "
            "(slug, author_id, body_md, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (slug, info.operator_id, body.body_md, now, now),
        )
        reg.commit()
        new_id = cur.lastrowid
    finally:
        reg.close()

    _audit_append(
        "buoy_user_note_create",
        actor=str(info.operator_id),
        target_id=f"buoy_user_notes:{new_id}",
        before=None,
        after={"slug": slug, "len_chars": len(body.body_md)},
        reason=None,
        request_id=str(uuid.uuid4()),
    )
    return BuoyUserNoteRow(
        id=new_id, slug=slug, author_id=info.operator_id,
        body_md=body.body_md, created_at=now, updated_at=now,
    )


@router.delete("/notes/user/{note_id}")
def delete_user_note(
    note_id: int = Path(ge=1),
    info: sessions.SessionInfo = Depends(session_identity),
) -> dict:
    reg = connect(paths.registry_db_path())
    try:
        row = reg.execute(
            "SELECT slug, author_id FROM buoy_user_notes WHERE id = ?",
            (note_id,),
        ).fetchone()
        if row is None:
            raise APIError("NOT_FOUND")
        slug, author_id = row[0], row[1]

        # Author or admin+ may delete. Scope still applies — even an admin
        # can't reach across a tenant they have no scope for.
        _scope_or_403(info.operator_id, slug)
        if info.operator_id != author_id:
            if operator_max_tier(info.operator_id) < ROLE_TIER["admin"]:
                raise APIError(
                    "ISOLATION_VIOLATION",
                    "only the author or admin+ may delete this note",
                )

        reg.execute("DELETE FROM buoy_user_notes WHERE id = ?", (note_id,))
        reg.commit()
    finally:
        reg.close()

    _audit_append(
        "buoy_user_note_delete",
        actor=str(info.operator_id),
        target_id=f"buoy_user_notes:{note_id}",
        before={"slug": slug, "author_id": author_id},
        after=None,
        reason=None,
        request_id=str(uuid.uuid4()),
    )
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Agent notes — schemas
# ---------------------------------------------------------------------------

class BuoyAgentNoteRequest(BaseModel):
    """Body the agent CLI helper POSTs to record an action.

    `action_class` must be one of the three categories from the
    2026-05-18 write-threshold agreement:
      - 'alert-behavior'  (rule changes, suppressions, severity edits)
      - 'client-network'  (Pi-hole, DNS, firewall/ACL edits)
      - 'state-change'    (deploys, restarts, migrations, command-queue
                           dispatches)

    `correlation_id` ties fleet-wide actions together: one logical
    action that lands on N buoys becomes N rows with the same
    correlation_id, so the UI can roll them up.

    `session_id` is the chat-session identifier so we can trace
    "which conversation produced this note."
    """
    action_class: str = Field(min_length=1, max_length=32)
    body_md: str = Field(min_length=1, max_length=MAX_NOTE_BODY_BYTES)
    correlation_id: Optional[str] = Field(default=None, max_length=64)
    session_id: Optional[str] = Field(default=None, max_length=64)


class BuoyAgentNoteRow(BaseModel):
    id: int
    slug: str
    action_class: str
    body_md: str
    correlation_id: Optional[str]
    session_id: Optional[str]
    created_at: str


class BuoyAgentNoteList(BaseModel):
    rows: list[BuoyAgentNoteRow]
    next_cursor: Optional[int] = None


# ---------------------------------------------------------------------------
# Agent notes — endpoints
# ---------------------------------------------------------------------------

@router.get("/{slug}/notes/agent", response_model=BuoyAgentNoteList)
def list_agent_notes(
    slug: str = Path(min_length=1, max_length=64),
    limit: int = Query(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT),
    cursor: Optional[int] = Query(default=None, ge=1),
    info: sessions.SessionInfo = Depends(session_identity),
) -> BuoyAgentNoteList:
    _scope_or_403(info.operator_id, slug)
    reg = connect(paths.registry_db_path())
    try:
        q = (
            "SELECT id, slug, action_class, body_md, correlation_id, "
            "session_id, created_at FROM buoy_agent_notes WHERE slug = ?"
        )
        params: list = [slug]
        if cursor is not None:
            q += " AND id < ?"
            params.append(cursor)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit + 1)
        rows = reg.execute(q, params).fetchall()
    finally:
        reg.close()

    has_more = len(rows) > limit
    visible = rows[:limit]
    next_cursor = visible[-1][0] if has_more and visible else None
    return BuoyAgentNoteList(
        rows=[BuoyAgentNoteRow(
            id=r[0], slug=r[1], action_class=r[2], body_md=r[3],
            correlation_id=r[4], session_id=r[5], created_at=r[6],
        ) for r in visible],
        next_cursor=next_cursor,
    )


@router.post("/{slug}/notes/agent", response_model=BuoyAgentNoteRow)
def create_agent_note(
    body: BuoyAgentNoteRequest,
    slug: str = Path(min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(require_step_up),
) -> BuoyAgentNoteRow:
    # admin+ tier required — only the agent CLI helper, run by an
    # admin operator, should be writing to this stream.
    if operator_max_tier(info.operator_id) < ROLE_TIER["admin"]:
        raise APIError(
            "ISOLATION_VIOLATION",
            "agent note write requires at least admin",
        )

    if body.action_class not in AGENT_NOTE_ACTION_CLASSES:
        raise APIError(
            "VALIDATION_FAILED",
            f"action_class must be one of {AGENT_NOTE_ACTION_CLASSES}",
        )

    _scope_or_403(info.operator_id, slug)

    now = _iso_now()
    reg = connect(paths.registry_db_path())
    try:
        cur = reg.execute(
            "INSERT INTO buoy_agent_notes "
            "(slug, action_class, body_md, correlation_id, session_id, "
            " created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (slug, body.action_class, body.body_md,
             body.correlation_id, body.session_id, now),
        )
        reg.commit()
        new_id = cur.lastrowid
    finally:
        reg.close()

    _audit_append(
        "buoy_agent_note_create",
        actor=str(info.operator_id),
        target_id=f"buoy_agent_notes:{new_id}",
        before=None,
        after={
            "slug": slug,
            "action_class": body.action_class,
            "len_chars": len(body.body_md),
            "correlation_id": body.correlation_id,
        },
        reason=None,
        request_id=str(uuid.uuid4()),
    )
    return BuoyAgentNoteRow(
        id=new_id, slug=slug, action_class=body.action_class,
        body_md=body.body_md, correlation_id=body.correlation_id,
        session_id=body.session_id, created_at=now,
    )
