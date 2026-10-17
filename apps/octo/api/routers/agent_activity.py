"""Agent activity API.

Surfaces a live-ish feed of what the agent layer has been doing across
the caller's in-scope tenants. Today: most-recent agent_notes pulled
from each tenant's events.db (migration 011). Tomorrow: also includes
agent-driven status transitions, auto-triage rule firings, and
upstream-close round-trip outcomes.

Toward the noise-dismissal goal, this is the operator's
"is the agent doing what I expect" surface — the trust-building layer
under any auto-close workflow.

Endpoint:

  GET /api/v1/agent/activity

Returns the N most-recent agent_notes across tenants in caller scope.
analyst+ may call; viewer denied (this surface reveals agent reasoning
patterns across the bundle).
"""
from __future__ import annotations

import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier, resolve_caller_scope
from apps.octo.api.routers.auth import session_identity
from apps.octo.auth import sessions
from apps.octo.auth.audit_rollup import PolledReadAudit
from apps.octo.db import connect


router = APIRouter(prefix="/agent", tags=["agent"])


def _caller_scope(operator_id: int) -> list[str]:
    """['*'] or the caller's concrete slugs, ACTIVE tenants only — the shared
    rule in `role_gates.resolve_caller_scope`."""
    return resolve_caller_scope(operator_id)


def _active_client_slugs() -> list[str]:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT slug FROM clients WHERE status = 'active'",
        ).fetchall()
    finally:
        reg.close()
    return [r["slug"] for r in rows]


def _caller_role_tier(operator_id: int) -> int:
    return operator_max_tier(operator_id)


class AgentActivityItem(BaseModel):
    client_slug: str
    agent_id: str  # 'octo' | 'athena'
    ref_kind: str  # 'event' | 'ticket' | 'indicator'
    ref_id: int
    note_text: str
    confidence: float
    created_at: str
    # Slice 7d — query_kind identifies operator-triggered "ask octo"
    # responses (tell_me_more / recognized_patterns / etc.) vs
    # autonomous notes (auto_enrich or NULL). Surfaces in the feed
    # as a small chip so triage trust is "operator asked" vs
    # "octo volunteered" at a glance. NULL for pre-028 rows.
    query_kind: Optional[str] = None
    # Cross-link fields — resolved server-side so the UI can render
    # "go to ticket / go to alert" buttons without N+1 round-trips.
    # When the agent annotated an EVENT, linked_ticket_id is set if a
    # ticket was derived from that event. When the agent annotated a
    # TICKET, linked_event_id is the ticket's source_event_id.
    linked_ticket_id: Optional[int] = None
    linked_ticket_title: Optional[str] = None
    linked_event_id: Optional[int] = None


class AgentActivityResponse(BaseModel):
    items: list[AgentActivityItem]
    tenants_searched: list[str]
    limit: int


class TriageStatusResponse(BaseModel):
    """Status of the autonomous Triage L1 worker (Task #119e).

    `state` is the fine-grained detail for the /tickets pill; `online`
    is the coarse up/down for the global topbar indicator. When the
    worker isn't running at all (OCTO_TRIAGE_WORKER unset), state is
    'disabled' and online is False."""
    state: str  # disabled | idle | triaging | error
    online: bool
    last_tick_at: Optional[str] = None
    last_run: Optional[dict] = None  # {processed, by_disposition}
    last_error: Optional[str] = None
    consecutive_errors: int = 0
    interval_seconds: Optional[int] = None
    # "uncalibrated" until an eval harness runs — UI flags confidence as
    # advisory so operators don't gate decisions on the raw number.
    calibration_state: str = "uncalibrated"


@router.get("/status", response_model=TriageStatusResponse)
def get_agent_status(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TriageStatusResponse:
    """Autonomous triage worker status. Analyst+ tier (same bar as the
    activity feed — it reveals agent operational state). Cheap: reads an
    in-memory snapshot, no DB scan."""
    tier = _caller_role_tier(info.operator_id)
    if tier < ROLE_TIER["analyst"]:
        raise APIError("ISOLATION_VIOLATION",
                       "agent status requires analyst tier or higher")
    worker = getattr(request.app.state, "triage_worker", None)
    if worker is None:
        # Worker not wired (OCTO_TRIAGE_WORKER unset) → disabled.
        return TriageStatusResponse(state="disabled", online=False)
    return TriageStatusResponse(**worker.status())


@router.get("/activity", response_model=AgentActivityResponse)
def get_agent_activity(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
    limit: int = Query(20, ge=1, le=100),
    ref_kind: Optional[str] = Query(None, pattern="^(event|ticket|indicator)$"),
) -> AgentActivityResponse:
    """Recent agent annotations across the caller's tenants.

    Analyst+ tier required. The feed is global within scope — analyst
    sees all agent activity in their tenants regardless of which
    tickets are theirs (this is intentional: triage trust requires
    seeing the agent's overall pattern, not just your queue)."""
    tier = _caller_role_tier(info.operator_id)
    # 2 = analyst minimum. Viewer (1) and 'none' (0) denied.
    if tier < ROLE_TIER["analyst"]:
        raise APIError("ISOLATION_VIOLATION",
                       "agent activity feed requires analyst tier or higher")

    scope = _caller_scope(info.operator_id)
    if scope == ["*"]:
        scope = _active_client_slugs()
    if not scope:
        return AgentActivityResponse(items=[], tenants_searched=[], limit=limit)

    all_items: list[AgentActivityItem] = []
    tenants_seen: list[str] = []
    for slug in scope:
        edb = paths.client_dir(slug) / "events.db"
        if not edb.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                params: tuple = ()
                where = "1=1"
                if ref_kind is not None:
                    where = "ref_kind = ?"
                    params = (ref_kind,)
                # Slice 7f — filter out synthetic dev-seeded notes by
                # default. The dev_seed.py path stamps these with an
                # audit_request_id of "synthetic-XXXXXXXX"; real bridge
                # inserts use uuid4. Operators with octo-llm running
                # want the feed to show only what the real agent + LLM
                # produced, not the legacy fixture data. ?include_synthetic
                # =true is the escape hatch for QA / comparison work.
                synthetic_clause = (
                    "" if False  # placeholder for future include flag
                    else " AND (audit_request_id IS NULL "
                         "OR audit_request_id NOT LIKE 'synthetic-%')"
                )
                # query_kind column is migration 028; pre-028 DBs are
                # tolerated by the OUTER OperationalError catch below —
                # we retry the query without query_kind and assign NULL.
                try:
                    rows = conn.execute(
                        f"SELECT ref_kind, ref_id, agent_id, note_text, "
                        f"       confidence, created_at, query_kind "
                        f"  FROM agent_notes WHERE {where}{synthetic_clause} "
                        f" ORDER BY created_at DESC LIMIT ?",
                        params + (limit,),
                    ).fetchall()
                    has_query_kind = True
                except sqlite3.OperationalError:
                    rows = conn.execute(
                        f"SELECT ref_kind, ref_id, agent_id, note_text, "
                        f"       confidence, created_at "
                        f"  FROM agent_notes WHERE {where}{synthetic_clause} "
                        f" ORDER BY created_at DESC LIMIT ?",
                        params + (limit,),
                    ).fetchall()
                    has_query_kind = False
                for r in rows:
                    all_items.append(AgentActivityItem(
                        client_slug=slug,
                        agent_id=r["agent_id"],
                        ref_kind=r["ref_kind"], ref_id=r["ref_id"],
                        note_text=r["note_text"],
                        confidence=r["confidence"],
                        created_at=r["created_at"],
                        query_kind=r["query_kind"] if has_query_kind else None,
                    ))
            finally:
                conn.close()
            tenants_seen.append(slug)
        except sqlite3.OperationalError:
            # Pre-011 events.db without agent_notes. Skip.
            continue

    # Global sort across tenants, newest-first, then cap.
    all_items.sort(key=lambda i: i.created_at, reverse=True)
    items = all_items[:limit]

    # Cross-link resolution — for each item in the page, figure out:
    #   ref_kind='event'  → find tickets where source_event_id = ref_id
    #   ref_kind='ticket' → load that ticket's source_event_id
    # Group by tenant to keep query count linear.
    by_tenant: dict[str, list[AgentActivityItem]] = {}
    for it in items:
        by_tenant.setdefault(it.client_slug, []).append(it)
    for slug, group in by_tenant.items():
        tdb = paths.client_dir(slug) / "tickets.db"
        if not tdb.exists():
            continue
        try:
            tconn = sqlite3.connect(f"file:{tdb}?mode=ro", uri=True)
            tconn.row_factory = sqlite3.Row
            try:
                # 1. Event-kind items → look up derived tickets.
                event_ids = [g.ref_id for g in group if g.ref_kind == "event"]
                if event_ids:
                    placeholders = ",".join("?" for _ in event_ids)
                    rows = tconn.execute(
                        f"SELECT id, title, source_event_id FROM tickets "
                        f" WHERE source_event_id IN ({placeholders})",
                        tuple(event_ids),
                    ).fetchall()
                    by_event = {r["source_event_id"]: (r["id"], r["title"]) for r in rows}
                    for g in group:
                        if g.ref_kind == "event" and g.ref_id in by_event:
                            g.linked_ticket_id, g.linked_ticket_title = by_event[g.ref_id]

                # 2. Ticket-kind items → look up their source_event_id.
                ticket_ids = [g.ref_id for g in group if g.ref_kind == "ticket"]
                if ticket_ids:
                    placeholders = ",".join("?" for _ in ticket_ids)
                    rows = tconn.execute(
                        f"SELECT id, title, source_event_id FROM tickets "
                        f" WHERE id IN ({placeholders})",
                        tuple(ticket_ids),
                    ).fetchall()
                    by_id = {r["id"]: r for r in rows}
                    for g in group:
                        if g.ref_kind == "ticket" and g.ref_id in by_id:
                            g.linked_ticket_title = by_id[g.ref_id]["title"]
                            g.linked_event_id = by_id[g.ref_id]["source_event_id"]
            finally:
                tconn.close()
        except sqlite3.OperationalError:
            continue

    # A POLLED read (the tickets page refreshes it every 15 s): rolled up
    # per session per hour — `auth.audit_rollup`, docs/audit-policy.md.
    PolledReadAudit.for_app(request.app).record(
        "agent.activity.fetch",
        operator_id=info.operator_id, session_id=info.id,
        reason="agent activity feed", rows=len(items),
        shape=f"limit={limit} ref_kind={ref_kind or '*'}",
        detail={"limit": limit, "ref_kind_filter": ref_kind,
                "returned": len(items), "tenant_count": len(tenants_seen)},
    )

    return AgentActivityResponse(
        items=items, tenants_searched=tenants_seen, limit=limit,
    )
