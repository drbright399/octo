"""Tickets API router.

Per-tenant ticket surface. Three endpoints in Phase 1:

  GET /api/v1/tickets                    — list with filters + scope
  GET /api/v1/tickets/{slug}/{id}        — detail (incl. status history)
  PATCH /api/v1/tickets/{slug}/{id}      — status / assignment transitions

All routes are session-authed (no step-up requirement — tickets are
operator daily-work, not the cross-tenant TI surface). Scope follows
the same pattern as /search: caller's `scope_slugs` ∩ requested
tenants. Visibility within scope follows the Kaseya-pattern rules
(analyst sees own + queues; admin sees all in scope; viewer sees
nothing here).

Per-tenant DB: `<data_root>/clients/<slug>/tickets.db` (migration
013). Schema is applied lazily on first access by `_ensure_schema`.

Future work, not in P1:
  - POST /api/v1/tickets (create human ticket)
  - Autotask round-trip ingest + push
  - Per-ticket secure-notepad routes (#18)
  - agent_notes + agent_pattern_links sidecar payload (#113 already
    has the tables; this router will join on `ref_kind='ticket'`)
"""
from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.adapters.autotask.writes_switch import psa_writes_enabled
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier, resolve_caller_scope
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.auth import sessions
from apps.octo.auth.audit_rollup import PolledReadAudit
from apps.octo.db import connect


router = APIRouter(prefix="/tickets", tags=["tickets"])


# ---------------------------------------------------------------------------
# Per-tenant schema bootstrap
# ---------------------------------------------------------------------------

_MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"


_TICKETS_LATEST_VERSION = 17


def _ensure_schema(slug: str) -> Path:
    """Make sure `<slug>/tickets.db` exists at the latest tickets schema
    version. Idempotent — applies only the migrations the DB is missing.
    Returns the resolved DB path."""
    cdir = paths.client_dir(slug)
    cdir.mkdir(parents=True, exist_ok=True)
    db = cdir / "tickets.db"
    conn = sqlite3.connect(db)
    try:
        current_version = conn.execute("PRAGMA user_version").fetchone()[0]
        for ver, filename in (
            (13, "013-tickets.sql"),
            (14, "014-ticket-notes.sql"),
            # 015 only touches registry.db, not per-tenant tickets.db,
            # so the per-tenant chain jumps straight to 016.
            (16, "016-ticket-autotask-writeback.sql"),
            (17, "017-ticket-due-at.sql"),
        ):
            if current_version >= ver:
                continue
            sql = (_MIGRATIONS_DIR / filename).read_text()
            tickets_section = _extract_target(sql, "tickets")
            prelude = _extract_target(sql, None)
            conn.executescript(prelude)
            conn.executescript(tickets_section)
            conn.commit()
            current_version = ver
        return db
    finally:
        conn.close()


def _extract_target(sql: str, target: Optional[str]) -> str:
    """Pull the chunk of `sql` that belongs to a given `@target:` block.
    `target=None` returns the prelude (lines before any @target marker).
    Mirrors `apps/octo/migration.py::_split_by_target` but returns a
    string we can pass to `executescript`."""
    out: list[str] = []
    current: Optional[str] = None
    for line in sql.splitlines():
        m = line.strip()
        if m.startswith("-- @target:"):
            current = m.split(":", 1)[1].strip()
            continue
        if current == target:
            out.append(line)
        elif current is None and target is None:
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Scope helpers — borrowed from search.py shape
# ---------------------------------------------------------------------------

def _caller_scope(operator_id: int) -> list[str]:
    """['*'] if any role has wildcard scope; otherwise the caller's concrete
    slugs, ACTIVE tenants only — the shared rule in
    `role_gates.resolve_caller_scope` (agent_query imports it from here)."""
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


def _caller_role_name(operator_id: int) -> str:
    """The caller's HIGHEST role tier across all operator_roles rows,
    expressed as a name. Returns one of the keys of role_gates.ROLE_TIER
    (or the literal 'none' when the operator has zero recognized roles
    — treated as below-viewer)."""
    tier = operator_max_tier(operator_id)
    if tier <= 0:
        return "none"
    # Reverse lookup
    for name, t in ROLE_TIER.items():
        if t == tier:
            return name
    return "none"


# ---------------------------------------------------------------------------
# Meta — what the console may offer (slice 0: the PSA writes switch)
# ---------------------------------------------------------------------------

class TicketsMeta(BaseModel):
    psa_writes_enabled: bool
    """False while the PSA (Autotask) writes kill switch is off — the
    console hides every "push to Autotask" option, and both enqueue paths
    answer 409 PSA_WRITES_DISABLED."""


def _refuse_psa_writes_when_disabled() -> None:
    """The enqueue gate: 409 PSA_WRITES_DISABLED unless the switch is on.
    Called BEFORE anything is written, so a refused request leaves no row."""
    if not psa_writes_enabled():
        raise APIError("PSA_WRITES_DISABLED")


@router.get("/_meta", response_model=TicketsMeta)
def tickets_meta(
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketsMeta:
    """Console capabilities for the tickets surface (analyst+; viewers get
    the same 403 as every other tickets route). Reads the switch only — no
    tenant data, nothing audited."""
    role = _caller_role_name(info.operator_id)
    if role not in ("analyst", "admin", "super_admin"):
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    return TicketsMeta(psa_writes_enabled=psa_writes_enabled())


# ---------------------------------------------------------------------------
# List endpoint
# ---------------------------------------------------------------------------

class TicketSummary(BaseModel):
    id: int
    client_slug: str
    autotask_id: Optional[str]
    title: str
    severity: str
    status: str
    assignee_operator_id: Optional[int]
    queue: Optional[str]
    source_event_id: Optional[int]
    opened_at: str
    updated_at: str
    agent_note_count: int = 0
    """How many agent_notes are attached to this ticket (ref_kind='ticket'
    in the tenant's events.db). The /tickets list UI surfaces a small
    badge when count > 0 so operators can see which tickets the agent
    has already weighed in on without opening each one."""


class TicketListResponse(BaseModel):
    tickets: list[TicketSummary]
    total: int
    page_size: int
    offset: int
    tenants_searched: list[str]


_OPEN_STATUSES = ("new", "in_progress", "waiting_customer", "waiting_vendor", "reopened")


@router.get("", response_model=TicketListResponse)
def list_tickets(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
    tenant: Optional[str] = Query(None, description="Limit to single tenant slug"),
    status: Optional[str] = Query(None, pattern="^(open|closed|all)$"),
    assignee: Optional[str] = Query(None, description="'me' = caller, or operator id"),
    severity: Optional[str] = Query(
        None,
        description="Filter to one or more severities (comma-separated). "
                    "Values: info,low,medium,high,critical",
    ),
    queue: Optional[str] = Query(
        None, max_length=120,
        description="Exact-match queue label filter (e.g., 'triage', 'L1')",
    ),
    q: Optional[str] = Query(
        None, max_length=200,
        description="Free-text search across title + description (LIKE %q%)",
    ),
    page_size: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> TicketListResponse:
    """List tickets across the caller's in-scope tenants.

    Visibility rules (Kaseya pattern):
      - viewer: 403 (tickets are not a viewer surface in P1)
      - analyst: own tickets only (assignee_operator_id = caller)
      - admin, super_admin: all tickets in scope
    """
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")

    scope = _caller_scope(info.operator_id)
    if scope == ["*"]:
        scope = _active_client_slugs()
    if tenant is not None:
        if tenant not in scope:
            raise APIError("ISOLATION_VIOLATION", f"tenant {tenant!r} not in caller scope")
        scope = [tenant]
    if not scope:
        return TicketListResponse(
            tickets=[], total=0, page_size=page_size, offset=offset,
            tenants_searched=[],
        )

    # Status filter
    if status == "open" or status is None:
        status_clause = f"status IN ({','.join('?' * len(_OPEN_STATUSES))})"
        status_params: tuple = _OPEN_STATUSES
    elif status == "closed":
        status_clause = "status IN (?, ?)"
        status_params = ("closed", "resolved")
    else:  # 'all'
        status_clause = "1 = 1"
        status_params = ()

    # Assignee filter
    assignee_clause = ""
    assignee_params: tuple = ()
    if role == "analyst":
        # Analysts ALWAYS see only their own — assignee param ignored.
        assignee_clause = " AND assignee_operator_id = ?"
        assignee_params = (info.operator_id,)
    elif assignee == "me":
        assignee_clause = " AND assignee_operator_id = ?"
        assignee_params = (info.operator_id,)
    elif assignee is not None:
        try:
            op_id = int(assignee)
        except ValueError:
            raise APIError("VALIDATION_FAILED", f"assignee must be 'me' or an operator id, got {assignee!r}")
        assignee_clause = " AND assignee_operator_id = ?"
        assignee_params = (op_id,)

    # Severity filter — comma-separated list. Validate every value
    # before building the SQL clause so a typo fails fast.
    severity_clause = ""
    severity_params: tuple = ()
    if severity:
        wanted = [s.strip().lower() for s in severity.split(",") if s.strip()]
        for s in wanted:
            if s not in _VALID_SEVERITIES:
                raise APIError("VALIDATION_FAILED",
                               f"unknown severity {s!r}; "
                               f"valid: {list(_VALID_SEVERITIES)}")
        if wanted:
            severity_clause = (
                f" AND severity IN ({','.join('?' * len(wanted))})"
            )
            severity_params = tuple(wanted)

    # Queue filter — exact match on the free-text label.
    queue_clause = ""
    queue_params: tuple = ()
    if queue:
        queue_clause = " AND queue = ?"
        queue_params = (queue,)

    # Free-text — case-insensitive LIKE %q% on title OR description.
    q_clause = ""
    q_params: tuple = ()
    if q:
        like = f"%{q}%"
        q_clause = " AND (title LIKE ? OR description LIKE ?)"
        q_params = (like, like)

    # Walk tenants, gather rows, then sort + paginate in memory. With
    # 50-tenant typical bundle + open ticket counts in the hundreds
    # per tenant, this stays well under any concerning threshold; the
    # alternative (UNION ALL across attach-database) is a Postgres-
    # migration trigger, not a P1 design.
    all_rows: list[TicketSummary] = []
    tenants_seen: list[str] = []
    for slug in scope:
        db = paths.client_dir(slug) / "tickets.db"
        if not db.exists():
            continue  # tenant has no tickets yet → no schema yet

        # Pull agent-note counts in one shot from the tenant's events.db
        # so we can annotate each ticket row below. ticket_ids → count.
        # events.db may not exist (or may predate migration 011) for
        # an empty tenant — tolerate that as "no agent notes".
        agent_counts: dict[int, int] = {}
        edb = paths.client_dir(slug) / "events.db"
        if edb.exists():
            try:
                econ = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
                try:
                    for r in econ.execute(
                        "SELECT ref_id, COUNT(*) FROM agent_notes "
                        " WHERE ref_kind = 'ticket' GROUP BY ref_id",
                    ).fetchall():
                        agent_counts[r[0]] = r[1]
                finally:
                    econ.close()
            except sqlite3.OperationalError:
                # agent_notes table not present (pre-011 events.db).
                pass

        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            sql_q = (
                "SELECT id, autotask_id, title, severity, status, "
                "       assignee_operator_id, queue, source_event_id, "
                "       opened_at, updated_at "
                f"  FROM tickets WHERE {status_clause}{assignee_clause}"
                f"{severity_clause}{queue_clause}{q_clause} "
                " ORDER BY updated_at DESC LIMIT 1000"
            )
            sql_params = (status_params + assignee_params
                          + severity_params + queue_params + q_params)
            for r in conn.execute(sql_q, sql_params).fetchall():
                all_rows.append(TicketSummary(
                    id=r["id"], client_slug=slug,
                    autotask_id=r["autotask_id"], title=r["title"],
                    severity=r["severity"], status=r["status"],
                    assignee_operator_id=r["assignee_operator_id"],
                    queue=r["queue"], source_event_id=r["source_event_id"],
                    opened_at=r["opened_at"], updated_at=r["updated_at"],
                    agent_note_count=agent_counts.get(r["id"], 0),
                ))
        finally:
            conn.close()
        tenants_seen.append(slug)

    # Global sort by updated_at desc, then paginate
    all_rows.sort(key=lambda t: t.updated_at, reverse=True)
    total = len(all_rows)
    page = all_rows[offset:offset + page_size]

    # A POLLED read (the dashboard's counters + feed hit it every 20-30 s):
    # rolled up per session per hour, not one row per call — see
    # `auth.audit_rollup` and docs/audit-policy.md. The shape names the
    # filters used; free text (q, queue) only ever as `*`.
    shape = " ".join(f"{k}={v}" for k, v in (
        ("tenant", tenant), ("status", status or "open"),
        ("assignee", assignee), ("severity", severity),
        ("queue", "*" if queue else None), ("q", "*" if q else None),
        ("page_size", page_size), ("offset", "paged" if offset else None),
    ) if v is not None)
    PolledReadAudit.for_app(request.app).record(
        "tickets.list",
        operator_id=info.operator_id, session_id=info.id,
        reason="ticket list view", rows=len(page), shape=shape,
        detail={"tenant_count": len(tenants_seen), "returned": len(page)},
    )

    return TicketListResponse(
        tickets=page, total=total, page_size=page_size, offset=offset,
        # Return the FULL in-scope tenant list, not just tenants where
        # a tickets.db happens to exist. The NewTicketModal pulls this
        # to populate its tenant picker — if we returned only "tenants
        # with existing tickets," the operator could never create the
        # FIRST ticket in a fresh tenant (chicken-and-egg). Same field
        # serves the /tickets filter rail's tenant dropdown.
        tenants_searched=scope,
    )


# ---------------------------------------------------------------------------
# Detail endpoint
# ---------------------------------------------------------------------------

class TicketStatusEvent(BaseModel):
    from_status: Optional[str]
    to_status: str
    changed_by_operator_id: Optional[int]
    reason: str
    source: str
    changed_at: str


class AgentInsight(BaseModel):
    agent_id: str  # 'octo' | 'athena'
    note_text: str
    confidence: float
    created_at: str


class AgentPatternEdge(BaseModel):
    """One agent-detected cross-reference edge from this ticket OR its
    source event to another ref. Mirrors the shape /search uses for
    its event-payload drawer so the UI can render the same component."""
    from_kind: str  # 'ticket' | 'event'
    from_id: int
    to_kind: str
    to_id: int
    relation: str
    strength: float
    rationale: str
    created_by_agent: str
    created_at: str


class TicketChargeRow(BaseModel):
    id: int
    name: str
    description: str
    unit_cost: float
    unit_price: float
    quantity: float
    is_billable: bool
    billing_code_id: Optional[str]
    autotask_charge_id: Optional[str]
    created_by_operator_id: Optional[int]
    created_at: str
    last_pushed_at: Optional[str]


class TicketPushStateRow(BaseModel):
    state: str
    attempts: int
    last_attempt_at: Optional[str]
    last_error: Optional[str]
    autotask_ticket_id: Optional[str]
    queued_at: Optional[str]
    queued_by_operator_id: Optional[int]


class TicketDetail(BaseModel):
    id: int
    client_slug: str
    autotask_id: Optional[str]
    title: str
    description: str
    severity: str
    status: str
    assignee_operator_id: Optional[int]
    queue: Optional[str]
    source_event_id: Optional[int]
    opened_at: str
    updated_at: str
    closed_at: Optional[str]
    last_autotask_sync_at: Optional[str]
    due_at: Optional[str] = None
    """SLA target / due date. ISO-8601. Settable on create + patch.
    The full SLA policy engine (auto-compute from contract +
    severity, overdue badge, escalation) is Zack's extension."""

    # P4-c2 fields — present on every ticket post-migration 016. Older
    # tickets (created pre-016) get default values via the column
    # defaults, so this is always populated.
    push_to_autotask: bool = False
    is_billable: bool = True
    billing_code_id: Optional[str] = None
    contract_id: Optional[str] = None
    charges: list[TicketChargeRow] = []
    push_state: Optional[TicketPushStateRow] = None

    status_history: list[TicketStatusEvent]
    agent_insights: list[AgentInsight] = []
    """Agent-layer annotations attached to this ticket (ref_kind='ticket'
    in the tenant's events.db). Surfaced inline in the ticket window so
    the operator never has to leave the ticket to see what octo or
    athena said about it. Empty list when the agent hasn't weighed in."""
    agent_pattern_links: list[AgentPatternEdge] = []
    """Cross-reference edges the agent drew from this ticket OR from
    its source event (when one exists). Same shape as the /search
    drawer uses, so the ticket window renders an identical component
    and the operator's mental model carries over. Strongest edges
    first."""


def _check_visibility(role: str, operator_id: int, row: sqlite3.Row) -> bool:
    """True if `operator_id` (with athena_role `role`) may see `row`."""
    if role in ("super_admin", "admin"):
        return True
    if role == "analyst":
        return row["assignee_operator_id"] == operator_id
    return False  # viewer — already blocked at the router level


@router.get("/{slug}/{ticket_id}", response_model=TicketDetail)
def get_ticket(
    slug: str,
    ticket_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketDetail:
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")

    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION", f"tenant {slug!r} not in caller scope")

    if not (paths.client_dir(slug) / "tickets.db").exists():
        raise APIError("NOT_FOUND", f"no tickets for {slug}")
    # Lazy forward-migrate — covers the case where a tickets.db was
    # created pre-016 and is missing the push/billing columns. Idempotent.
    db = _ensure_schema(slug)

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE id = ?", (ticket_id,),
        ).fetchone()
        if row is None:
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        if not _check_visibility(role, info.operator_id, row):
            # Indistinguishable from NOT_FOUND on purpose — don't
            # leak existence of tickets the caller can't see.
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        history = conn.execute(
            "SELECT from_status, to_status, changed_by_operator_id, "
            "       reason, source, changed_at "
            "  FROM ticket_status_history WHERE ticket_id = ? "
            " ORDER BY changed_at ASC",
            (ticket_id,),
        ).fetchall()
        charge_rows = conn.execute(
            "SELECT id, name, description, unit_cost, unit_price, "
            "       quantity, is_billable, billing_code_id, "
            "       autotask_charge_id, created_by_operator_id, "
            "       created_at, last_pushed_at "
            "  FROM ticket_charges WHERE ticket_id = ? "
            " ORDER BY id ASC",
            (ticket_id,),
        ).fetchall()
        push_row = conn.execute(
            "SELECT state, attempts, last_attempt_at, last_error, "
            "       autotask_ticket_id, queued_at, queued_by_operator_id "
            "  FROM autotask_push_state WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
    finally:
        conn.close()

    # Agent insights + cross-reference edges. Pulls from the tenant's
    # events.db (where the agent_notes + agent_pattern_links tables
    # live per migration 011). Best-effort: tolerate missing DB or
    # pre-011 schema.
    agent_insights: list[AgentInsight] = []
    agent_links: list[AgentPatternEdge] = []
    edb = paths.client_dir(slug) / "events.db"
    if edb.exists():
        try:
            econ = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
            econ.row_factory = sqlite3.Row
            try:
                for r in econ.execute(
                    "SELECT agent_id, note_text, confidence, created_at "
                    "  FROM agent_notes "
                    " WHERE ref_kind = 'ticket' AND ref_id = ? "
                    " ORDER BY created_at DESC",
                    (ticket_id,),
                ).fetchall():
                    agent_insights.append(AgentInsight(
                        agent_id=r["agent_id"],
                        note_text=r["note_text"],
                        confidence=r["confidence"],
                        created_at=r["created_at"],
                    ))

                # Edges from THIS ticket + edges from the source event
                # (when present) — the latter gives "what was this
                # alert similar to" context that often matters more
                # than what the ticket-as-ticket has been linked to.
                edge_filters = [("ticket", ticket_id)]
                source_event_id = row["source_event_id"]
                if source_event_id is not None:
                    edge_filters.append(("event", source_event_id))
                for from_kind, from_id in edge_filters:
                    for r in econ.execute(
                        "SELECT from_kind, from_id, to_kind, to_id, "
                        "       relation, strength, rationale, "
                        "       created_by_agent, created_at "
                        "  FROM agent_pattern_links "
                        " WHERE from_kind = ? AND from_id = ? "
                        " ORDER BY strength DESC, created_at DESC",
                        (from_kind, from_id),
                    ).fetchall():
                        agent_links.append(AgentPatternEdge(
                            from_kind=r["from_kind"], from_id=r["from_id"],
                            to_kind=r["to_kind"], to_id=r["to_id"],
                            relation=r["relation"], strength=r["strength"],
                            rationale=r["rationale"],
                            created_by_agent=r["created_by_agent"],
                            created_at=r["created_at"],
                        ))
            finally:
                econ.close()
        except sqlite3.OperationalError:
            pass  # pre-011 events.db — no agent tables yet

    _audit_append(
        "tickets.fetch",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}",
        before=None,
        after={"session_id_prefix": info.id[:8]},
        reason="ticket detail view",
        request_id=str(uuid.uuid4()),
    )

    return TicketDetail(
        id=row["id"], client_slug=slug,
        autotask_id=row["autotask_id"], title=row["title"],
        description=row["description"], severity=row["severity"],
        status=row["status"],
        assignee_operator_id=row["assignee_operator_id"],
        queue=row["queue"], source_event_id=row["source_event_id"],
        opened_at=row["opened_at"], updated_at=row["updated_at"],
        closed_at=row["closed_at"],
        last_autotask_sync_at=row["last_autotask_sync_at"],
        due_at=row["due_at"],
        push_to_autotask=bool(row["push_to_autotask"]),
        is_billable=bool(row["is_billable"]),
        billing_code_id=row["billing_code_id"],
        contract_id=row["contract_id"],
        charges=[
            TicketChargeRow(
                id=c["id"], name=c["name"], description=c["description"],
                unit_cost=c["unit_cost"], unit_price=c["unit_price"],
                quantity=c["quantity"],
                is_billable=bool(c["is_billable"]),
                billing_code_id=c["billing_code_id"],
                autotask_charge_id=c["autotask_charge_id"],
                created_by_operator_id=c["created_by_operator_id"],
                created_at=c["created_at"],
                last_pushed_at=c["last_pushed_at"],
            )
            for c in charge_rows
        ],
        push_state=(
            TicketPushStateRow(
                state=push_row["state"],
                attempts=push_row["attempts"],
                last_attempt_at=push_row["last_attempt_at"],
                last_error=push_row["last_error"],
                autotask_ticket_id=push_row["autotask_ticket_id"],
                queued_at=push_row["queued_at"],
                queued_by_operator_id=push_row["queued_by_operator_id"],
            ) if push_row is not None else None
        ),
        status_history=[
            TicketStatusEvent(
                from_status=h["from_status"], to_status=h["to_status"],
                changed_by_operator_id=h["changed_by_operator_id"],
                reason=h["reason"], source=h["source"],
                changed_at=h["changed_at"],
            )
            for h in history
        ],
        agent_insights=agent_insights,
        agent_pattern_links=agent_links,
    )


# ---------------------------------------------------------------------------
# POST — create a new ticket (manual or from an event)
# ---------------------------------------------------------------------------

class TicketChargeInput(BaseModel):
    """Inline charge line-item submitted alongside the ticket. Mirrors
    Autotask's TicketCharge entity. is_billable defaults true (matches
    Autotask's own default)."""
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    unit_cost: float = Field(default=0.0, ge=0.0)
    unit_price: float = Field(default=0.0, ge=0.0)
    quantity: float = Field(default=1.0, ge=0.0)
    is_billable: bool = True
    billing_code_id: Optional[str] = None


class TicketCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="", max_length=8000)
    severity: str = "medium"
    status: str = "new"
    assignee_operator_id: Optional[int] = None
    queue: Optional[str] = None
    source_event_id: Optional[int] = None
    """When set, this ticket was opened FROM an alert. The /search
    drawer's "Create ticket from this alert" flow uses this. The
    server verifies the event exists in the same tenant before
    accepting (so an operator can't link a ticket to an event from
    out of scope)."""

    # ---- Autotask write-back opt-in (P4-c2) ----
    # Per-ticket opt-in. Setting True alone does NOT trigger a push;
    # the operator (or the future agent path) must explicitly POST
    # /push-to-autotask to enqueue. We split the flag from the trigger
    # so an operator can stage a ticket as "pushable" but hold off
    # until charges are finalized.
    push_to_autotask: bool = False
    is_billable: bool = True
    billing_code_id: Optional[str] = Field(default=None, max_length=120)
    contract_id: Optional[str] = Field(default=None, max_length=120)
    # Optional inline charges — useful for "create ticket + drop a
    # part charge in one shot" UI flows. Empty list = no charges
    # (still allowed, charges can be added later via /charges).
    charges: list[TicketChargeInput] = Field(default_factory=list)
    # P5-d — SLA target / due date. Optional ISO-8601 timestamp.
    due_at: Optional[str] = Field(default=None, max_length=40)


_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


@router.post("/{slug}", response_model=TicketDetail, status_code=201)
def create_ticket(
    slug: str,
    body: TicketCreateRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketDetail:
    """Open a new ticket in `slug`'s tickets.db.

    Analyst+ may create. Per the Kaseya pattern, a newly-created
    ticket is assigned to the caller by default unless an explicit
    assignee is provided (and only admin+ may assign to someone
    else).

    `source_event_id`, when present, links the ticket back to the
    alert it came from — this is the field /search uses to surface
    the "associated ticket" cross-link, and it's the canonical
    identity for the future auto-spawn workflow (elevated alerts
    spawning tickets without operator intervention).
    """
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    if role == "analyst" and body.assignee_operator_id is not None \
            and body.assignee_operator_id != info.operator_id:
        raise APIError("ISOLATION_VIOLATION",
                       "analysts may only create tickets assigned to themselves")
    if body.severity not in _VALID_SEVERITIES:
        raise APIError("VALIDATION_FAILED",
                       f"unknown severity {body.severity!r}; "
                       f"valid: {list(_VALID_SEVERITIES)}")
    if body.status not in _VALID_STATUSES:
        raise APIError("VALIDATION_FAILED",
                       f"unknown status {body.status!r}; "
                       f"valid: {list(_VALID_STATUSES)}")

    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")
    # Asking for an Autotask push is an enqueue path: refused whole (no
    # ticket row either) while the PSA writes switch is off.
    if body.push_to_autotask:
        _refuse_psa_writes_when_disabled()

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())
    assignee = body.assignee_operator_id
    if assignee is None and role == "analyst":
        # Analyst-created tickets default-assign to the caller so they
        # show up in the "Mine" filter immediately.
        assignee = info.operator_id

    # If source_event_id is set, verify the event exists in this
    # tenant's events.db. This blocks "ticket pretends to be linked
    # to an event the operator can't see" attacks at the SQL layer,
    # not just at the policy layer.
    if body.source_event_id is not None:
        edb = paths.client_dir(slug) / "events.db"
        if not edb.exists():
            raise APIError("VALIDATION_FAILED",
                           f"source_event_id {body.source_event_id!r} "
                           f"references no event in {slug!r}")
        econ = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
        try:
            ev = econ.execute(
                "SELECT 1 FROM events WHERE id = ?",
                (body.source_event_id,),
            ).fetchone()
        finally:
            econ.close()
        if ev is None:
            raise APIError("VALIDATION_FAILED",
                           f"source_event_id {body.source_event_id!r} "
                           f"references no event in {slug!r}")

    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "INSERT INTO tickets "
            "(title, description, severity, status, "
            " assignee_operator_id, queue, source_event_id, "
            " push_to_autotask, is_billable, "
            " billing_code_id, contract_id, due_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (body.title, body.description, body.severity, body.status,
             assignee, body.queue, body.source_event_id,
             1 if body.push_to_autotask else 0,
             1 if body.is_billable else 0,
             body.billing_code_id, body.contract_id, body.due_at),
        )
        ticket_id = cur.lastrowid
        conn.execute(
            "INSERT INTO ticket_status_history "
            "(ticket_id, from_status, to_status, "
            " changed_by_operator_id, reason, source) "
            "VALUES (?, NULL, ?, ?, "
            "        CASE WHEN ? IS NOT NULL "
            "             THEN 'opened from event'"
            "             ELSE 'opened manually' END, "
            "        'operator')",
            (ticket_id, body.status, info.operator_id, body.source_event_id),
        )
        # Inline charges, if any. Same shape as POST /charges — kept in
        # the same txn so a partial-failure can't leave the ticket
        # half-charged.
        for ch in body.charges:
            conn.execute(
                "INSERT INTO ticket_charges "
                "(ticket_id, name, description, unit_cost, unit_price, "
                " quantity, is_billable, billing_code_id, "
                " created_by_operator_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ticket_id, ch.name, ch.description, ch.unit_cost,
                 ch.unit_price, ch.quantity,
                 1 if ch.is_billable else 0,
                 ch.billing_code_id, info.operator_id),
            )
        conn.commit()
    finally:
        conn.close()

    _audit_append(
        "tickets.create",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}",
        before=None,
        after={"severity": body.severity, "status": body.status,
               "assignee": assignee,
               "source_event_id": body.source_event_id,
               "session_id_prefix": info.id[:8]},
        reason="ticket open",
        request_id=request_id,
    )

    return get_ticket(slug, ticket_id, request, info)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# PATCH — status + assignee transitions
# ---------------------------------------------------------------------------

class TicketPatchRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    """Severity transitions are audit-logged like status transitions —
    operator + reason captured. Analyst+ may change severity on their
    own tickets; admin+ on any."""
    assignee_operator_id: Optional[int] = Field(default=None)
    due_at: Optional[str] = Field(default=None, max_length=40)
    """ISO-8601 SLA target. Set to "" or null to clear. Pass-through
    storage today; Zack's SLA policy engine will validate against
    contract terms in a future pass."""
    reason: str = Field(default="", max_length=500)


_VALID_STATUSES = (
    "new", "in_progress", "waiting_customer", "waiting_vendor",
    "resolved", "closed", "reopened",
)


@router.patch("/{slug}/{ticket_id}", response_model=TicketDetail)
def patch_ticket(
    slug: str,
    ticket_id: int,
    body: TicketPatchRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketDetail:
    """Update status and/or assignee. Status changes write an entry to
    ticket_status_history. The full updated ticket detail is returned
    on success so the UI re-renders without a follow-up GET."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    if role == "analyst" and body.assignee_operator_id is not None:
        # Analysts can transition status on tickets assigned to them
        # but can't reassign (that's admin+).
        raise APIError("ISOLATION_VIOLATION", "analysts may not reassign tickets")
    if body.status is not None and body.status not in _VALID_STATUSES:
        raise APIError("VALIDATION_FAILED", f"unknown status {body.status!r}")
    if body.severity is not None and body.severity not in _VALID_SEVERITIES:
        raise APIError("VALIDATION_FAILED", f"unknown severity {body.severity!r}")

    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION", f"tenant {slug!r} not in caller scope")

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())

    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE id = ?", (ticket_id,),
        ).fetchone()
        if row is None:
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        if not _check_visibility(role, info.operator_id, row):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")

        sets: list[str] = []
        params: list[object] = []
        before_state = {"status": row["status"],
                        "severity": row["severity"],
                        "assignee_operator_id": row["assignee_operator_id"]}

        if body.status is not None and body.status != row["status"]:
            sets.append("status = ?")
            params.append(body.status)
            if body.status in ("closed", "resolved"):
                sets.append("closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")

        if body.severity is not None and body.severity != row["severity"]:
            sets.append("severity = ?")
            params.append(body.severity)

        if body.due_at is not None:
            # Empty string means "clear the due date". Otherwise just
            # pass-through — we don't validate format yet (Zack's SLA
            # engine will), but cap at 40 chars to avoid garbage.
            new_due = body.due_at.strip() or None
            if new_due != row["due_at"]:
                sets.append("due_at = ?")
                params.append(new_due)

        if body.assignee_operator_id is not None and body.assignee_operator_id != row["assignee_operator_id"]:
            sets.append("assignee_operator_id = ?")
            params.append(body.assignee_operator_id)

        if not sets:
            # Nothing to change; treat as no-op rather than an error.
            return get_ticket(slug, ticket_id, request, info)  # type: ignore[arg-type]

        sets.append("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")
        params.append(ticket_id)
        conn.execute(
            f"UPDATE tickets SET {', '.join(sets)} WHERE id = ?",
            tuple(params),
        )
        if body.status is not None and body.status != row["status"]:
            conn.execute(
                "INSERT INTO ticket_status_history "
                "(ticket_id, from_status, to_status, "
                " changed_by_operator_id, reason, source) "
                "VALUES (?, ?, ?, ?, ?, 'operator')",
                (ticket_id, row["status"], body.status,
                 info.operator_id, body.reason),
            )
        conn.commit()
    finally:
        conn.close()

    after_state = {
        "status": body.status or row["status"],
        "severity": body.severity or row["severity"],
        "assignee_operator_id":
            body.assignee_operator_id
            if body.assignee_operator_id is not None
            else row["assignee_operator_id"],
        "session_id_prefix": info.id[:8],
    }
    _audit_append(
        "tickets.patch",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}",
        before=before_state, after=after_state,
        reason=body.reason or "ticket update",
        request_id=request_id,
    )

    return get_ticket(slug, ticket_id, request, info)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Notes — Autotask-aligned per-ticket notes (migration 014)
# ---------------------------------------------------------------------------

# Canonical label sets — mapped to Autotask's per-instance picklist
# integer IDs at sync time (TicketNotes.noteType + TicketNotes.publish
# are picklists whose values are tenant-specific). Keeping our values
# as labels means a fresh MSP can wire in without touching the schema.
_VALID_NOTE_TYPES = (
    "task_detail", "workflow", "internal", "detail",
    "summary", "resolution", "system_workflow",
)
_VALID_PUBLISH = ("internal", "all_autotask_users", "client_portal")

# Autotask's hard caps on TicketNotes.title (250) + .description (32000)
# — we match them so a long note can't accumulate locally and then
# truncate silently on push.
_NOTE_TITLE_MAX = 250
_NOTE_BODY_MAX = 32000


class TicketNote(BaseModel):
    id: int
    ticket_id: int
    autotask_id: Optional[str]
    title: Optional[str]
    body: str
    note_type: str
    publish: str
    author_operator_id: Optional[int]
    created_at: str
    updated_at: str
    last_activity_at: str
    pushed_to_autotask_at: Optional[str]


class TicketNotesListResponse(BaseModel):
    notes: list[TicketNote]


@router.get("/{slug}/{ticket_id}/notes", response_model=TicketNotesListResponse)
def list_ticket_notes(
    slug: str,
    ticket_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketNotesListResponse:
    """Notes on a ticket, newest-first. Scope + visibility match the
    parent ticket — analyst sees own only, admin+ sees all-in-scope,
    viewer denied."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")

    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    if not (paths.client_dir(slug) / "tickets.db").exists():
        raise APIError("NOT_FOUND", f"no tickets for {slug}")

    # Lazy-migrate forward — covers the case where a tickets.db was
    # provisioned under migration 013 (which lacked ticket_notes) and
    # the operator opens a ticket before any note has been authored.
    # Without this the SELECT below would 500 on "no such table".
    # `_ensure_schema` is idempotent + only writes when the user_version
    # is behind, so the cost on already-current DBs is one PRAGMA read.
    db = _ensure_schema(slug)

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        ticket_row = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if ticket_row is None:
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        if not _check_visibility(role, info.operator_id, ticket_row):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        rows = conn.execute(
            "SELECT id, ticket_id, autotask_id, title, body, note_type, "
            "       publish, author_operator_id, created_at, updated_at, "
            "       last_activity_at, pushed_to_autotask_at "
            "  FROM ticket_notes "
            " WHERE ticket_id = ? "
            " ORDER BY created_at DESC",
            (ticket_id,),
        ).fetchall()
    finally:
        conn.close()

    return TicketNotesListResponse(
        notes=[
            TicketNote(
                id=r["id"], ticket_id=r["ticket_id"],
                autotask_id=r["autotask_id"], title=r["title"],
                body=r["body"], note_type=r["note_type"],
                publish=r["publish"],
                author_operator_id=r["author_operator_id"],
                created_at=r["created_at"], updated_at=r["updated_at"],
                last_activity_at=r["last_activity_at"],
                pushed_to_autotask_at=r["pushed_to_autotask_at"],
            )
            for r in rows
        ],
    )


class TicketNoteCreateRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=_NOTE_TITLE_MAX)
    body: str = Field(..., min_length=1, max_length=_NOTE_BODY_MAX)
    note_type: str = "internal"
    publish: str = "internal"


@router.post("/{slug}/{ticket_id}/notes", response_model=TicketNote, status_code=201)
def create_ticket_note(
    slug: str,
    ticket_id: int,
    body: TicketNoteCreateRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketNote:
    """Append a note to a ticket. analyst+ may write notes on tickets
    they can see; analyst can only write on tickets assigned to them
    (same rule as the PATCH endpoint)."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")

    if body.note_type not in _VALID_NOTE_TYPES:
        raise APIError("VALIDATION_FAILED",
                       f"unknown note_type {body.note_type!r}; "
                       f"valid: {list(_VALID_NOTE_TYPES)}")
    if body.publish not in _VALID_PUBLISH:
        raise APIError("VALIDATION_FAILED",
                       f"unknown publish {body.publish!r}; "
                       f"valid: {list(_VALID_PUBLISH)}")
    if body.title is not None and not body.title.strip():
        # Treat an all-whitespace title as null so the UI's optional
        # field doesn't accidentally persist as a blank-but-non-null.
        body.title = None

    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())

    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        ticket_row = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if ticket_row is None:
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        if not _check_visibility(role, info.operator_id, ticket_row):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")

        cur = conn.execute(
            "INSERT INTO ticket_notes "
            "(ticket_id, title, body, note_type, publish, "
            " author_operator_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ticket_id, body.title, body.body, body.note_type,
             body.publish, info.operator_id),
        )
        note_id = cur.lastrowid
        conn.commit()
        row = conn.execute(
            "SELECT id, ticket_id, autotask_id, title, body, note_type, "
            "       publish, author_operator_id, created_at, updated_at, "
            "       last_activity_at, pushed_to_autotask_at "
            "  FROM ticket_notes WHERE id = ?", (note_id,),
        ).fetchone()
    finally:
        conn.close()

    _audit_append(
        "tickets.note.create",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}/note/{note_id}",
        before=None,
        after={"note_type": body.note_type, "publish": body.publish,
               "title_len": len(body.title) if body.title else 0,
               "body_len": len(body.body),
               "session_id_prefix": info.id[:8]},
        reason="ticket note authored",
        request_id=request_id,
    )

    return TicketNote(
        id=row["id"], ticket_id=row["ticket_id"],
        autotask_id=row["autotask_id"], title=row["title"],
        body=row["body"], note_type=row["note_type"],
        publish=row["publish"],
        author_operator_id=row["author_operator_id"],
        created_at=row["created_at"], updated_at=row["updated_at"],
        last_activity_at=row["last_activity_at"],
        pushed_to_autotask_at=row["pushed_to_autotask_at"],
    )


# ---------------------------------------------------------------------------
# P4-c2: Autotask write-back surface — charges + push trigger + state
# ---------------------------------------------------------------------------
#
# These endpoints back the Settings → Integrations → Autotask write-back
# workflow. The actual push of payload-to-Autotask happens in
# apps/octo/adapters/autotask/writeback.py — these endpoints stage the
# data + queue the push. Operator role gates mirror the rest of the
# tickets surface: viewer locked out, analyst can only touch their own
# tickets, admin+ can touch any.

class ChargeCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    unit_cost: float = Field(default=0.0, ge=0.0)
    unit_price: float = Field(default=0.0, ge=0.0)
    quantity: float = Field(default=1.0, ge=0.0)
    is_billable: bool = True
    billing_code_id: Optional[str] = Field(default=None, max_length=120)


@router.get("/{slug}/{ticket_id}/charges",
            response_model=list[TicketChargeRow])
def list_ticket_charges(
    slug: str, ticket_id: int, request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> list[TicketChargeRow]:
    """List add-on charges on a ticket. Same visibility rules as the
    parent ticket — if the caller can't see the ticket they can't see
    its charges."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    if not (paths.client_dir(slug) / "tickets.db").exists():
        raise APIError("NOT_FOUND", f"no tickets for {slug}")
    db = _ensure_schema(slug)
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        t = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if t is None or not _check_visibility(role, info.operator_id, t):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        rows = conn.execute(
            "SELECT id, name, description, unit_cost, unit_price, "
            "       quantity, is_billable, billing_code_id, "
            "       autotask_charge_id, created_by_operator_id, "
            "       created_at, last_pushed_at "
            "  FROM ticket_charges WHERE ticket_id = ? "
            " ORDER BY id ASC",
            (ticket_id,),
        ).fetchall()
    finally:
        conn.close()
    return [
        TicketChargeRow(
            id=r["id"], name=r["name"], description=r["description"],
            unit_cost=r["unit_cost"], unit_price=r["unit_price"],
            quantity=r["quantity"],
            is_billable=bool(r["is_billable"]),
            billing_code_id=r["billing_code_id"],
            autotask_charge_id=r["autotask_charge_id"],
            created_by_operator_id=r["created_by_operator_id"],
            created_at=r["created_at"],
            last_pushed_at=r["last_pushed_at"],
        )
        for r in rows
    ]


@router.post("/{slug}/{ticket_id}/charges",
             response_model=TicketChargeRow, status_code=201)
def create_ticket_charge(
    slug: str, ticket_id: int,
    body: ChargeCreateRequest, request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketChargeRow:
    """Add an add-on charge line to a ticket. Charges are independent
    from the push state — adding a charge doesn't trigger a push, but
    a subsequent /push-to-autotask will include any unpushed charges
    in its payload sequence."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())
    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        t = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if t is None or not _check_visibility(role, info.operator_id, t):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        cur = conn.execute(
            "INSERT INTO ticket_charges "
            "(ticket_id, name, description, unit_cost, unit_price, "
            " quantity, is_billable, billing_code_id, "
            " created_by_operator_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, body.name, body.description, body.unit_cost,
             body.unit_price, body.quantity,
             1 if body.is_billable else 0,
             body.billing_code_id, info.operator_id),
        )
        charge_id = cur.lastrowid
        conn.execute(
            "UPDATE tickets "
            "SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
            "WHERE id = ?", (ticket_id,),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM ticket_charges WHERE id = ?", (charge_id,),
        ).fetchone()
    finally:
        conn.close()

    _audit_append(
        "tickets.charge.create",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}/charge/{charge_id}",
        before=None,
        after={"name": body.name, "unit_price": body.unit_price,
               "quantity": body.quantity, "is_billable": body.is_billable,
               "session_id_prefix": info.id[:8]},
        reason="ticket charge added",
        request_id=request_id,
    )

    return TicketChargeRow(
        id=row["id"], name=row["name"], description=row["description"],
        unit_cost=row["unit_cost"], unit_price=row["unit_price"],
        quantity=row["quantity"],
        is_billable=bool(row["is_billable"]),
        billing_code_id=row["billing_code_id"],
        autotask_charge_id=row["autotask_charge_id"],
        created_by_operator_id=row["created_by_operator_id"],
        created_at=row["created_at"],
        last_pushed_at=row["last_pushed_at"],
    )


@router.delete("/{slug}/{ticket_id}/charges/{charge_id}",
               status_code=204)
def delete_ticket_charge(
    slug: str, ticket_id: int, charge_id: int, request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> None:
    """Remove an unpushed charge. Charges already pushed to Autotask
    (autotask_charge_id IS NOT NULL) cannot be deleted via this
    endpoint — the operator must void via Autotask directly so the
    round-trip stays consistent."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())
    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        t = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if t is None or not _check_visibility(role, info.operator_id, t):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        chrg = conn.execute(
            "SELECT id, autotask_charge_id FROM ticket_charges "
            "WHERE id = ? AND ticket_id = ?",
            (charge_id, ticket_id),
        ).fetchone()
        if chrg is None:
            raise APIError("NOT_FOUND", f"charge {charge_id} not found")
        if chrg["autotask_charge_id"] is not None:
            raise APIError("VALIDATION_FAILED",
                           "charge already pushed to Autotask; void in "
                           "Autotask directly")
        conn.execute("DELETE FROM ticket_charges WHERE id = ?", (charge_id,))
        conn.commit()
    finally:
        conn.close()

    _audit_append(
        "tickets.charge.delete",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}/charge/{charge_id}",
        before={"charge_id": charge_id},
        after=None,
        reason="ticket charge removed",
        request_id=request_id,
    )


@router.get("/{slug}/{ticket_id}/push-state",
            response_model=Optional[TicketPushStateRow])
def get_push_state(
    slug: str, ticket_id: int, request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> Optional[TicketPushStateRow]:
    """Current Autotask push state for a ticket. None when the ticket
    has never been queued. Used by the ticket window's push-state
    badge."""
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")

    if not (paths.client_dir(slug) / "tickets.db").exists():
        raise APIError("NOT_FOUND", f"no tickets for {slug}")
    db = _ensure_schema(slug)
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        t = conn.execute(
            "SELECT id, assignee_operator_id FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if t is None or not _check_visibility(role, info.operator_id, t):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        row = conn.execute(
            "SELECT state, attempts, last_attempt_at, last_error, "
            "       autotask_ticket_id, queued_at, queued_by_operator_id "
            "  FROM autotask_push_state WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return TicketPushStateRow(
        state=row["state"], attempts=row["attempts"],
        last_attempt_at=row["last_attempt_at"],
        last_error=row["last_error"],
        autotask_ticket_id=row["autotask_ticket_id"],
        queued_at=row["queued_at"],
        queued_by_operator_id=row["queued_by_operator_id"],
    )


@router.post("/{slug}/{ticket_id}/push-to-autotask",
             response_model=TicketPushStateRow, status_code=202)
def push_to_autotask(
    slug: str, ticket_id: int, request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketPushStateRow:
    """Enqueue (or re-enqueue) a ticket for push to Autotask. Idempotent
    when the ticket is already in 'in_flight' or 'pushed' state — it
    just returns the current state. When in 'failed' state it bumps
    the attempts and resets to 'pending' for retry.

    The actual REST POST happens out-of-band in the writeback worker
    (apps/octo/adapters/autotask/writeback.py). This endpoint only
    advances the outbox queue — it returns 202 to signal "accepted,
    will process".

    While the PSA writes switch is off: 409 PSA_WRITES_DISABLED, and
    nothing is queued or re-queued.
    """
    role = _caller_role_name(info.operator_id)
    if role == "viewer":
        raise APIError("ISOLATION_VIOLATION",
                       "tickets surface not available to viewer role")
    scope = _caller_scope(info.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("ISOLATION_VIOLATION",
                       f"tenant {slug!r} not in caller scope")
    _refuse_psa_writes_when_disabled()

    db = _ensure_schema(slug)
    request_id = str(uuid.uuid4())
    conn = connect(db)
    conn.row_factory = sqlite3.Row
    try:
        t = conn.execute(
            "SELECT id, assignee_operator_id, push_to_autotask, autotask_id "
            "  FROM tickets WHERE id = ?", (ticket_id,),
        ).fetchone()
        if t is None or not _check_visibility(role, info.operator_id, t):
            raise APIError("NOT_FOUND", f"ticket {ticket_id} not found")
        if not bool(t["push_to_autotask"]):
            # Operator forgot to flip the opt-in. Be explicit rather
            # than silently flipping it for them — push-to-Autotask
            # should be an active choice.
            raise APIError("VALIDATION_FAILED",
                           "ticket has push_to_autotask=False; enable "
                           "via PATCH before requesting push")

        existing = conn.execute(
            "SELECT state FROM autotask_push_state WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO autotask_push_state "
                "(ticket_id, state, queued_by_operator_id) "
                "VALUES (?, 'pending', ?)",
                (ticket_id, info.operator_id),
            )
        elif existing["state"] == "failed":
            # Retry: clear last_error so the next attempt starts clean.
            conn.execute(
                "UPDATE autotask_push_state "
                "SET state = 'pending', last_error = NULL, "
                "    queued_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
                "    queued_by_operator_id = ? "
                "WHERE ticket_id = ?",
                (info.operator_id, ticket_id),
            )
        # If state is 'in_flight' or 'pushed', we return current state
        # without change — caller knows the push is already in motion.

        conn.commit()
        row = conn.execute(
            "SELECT state, attempts, last_attempt_at, last_error, "
            "       autotask_ticket_id, queued_at, queued_by_operator_id "
            "  FROM autotask_push_state WHERE ticket_id = ?",
            (ticket_id,),
        ).fetchone()
    finally:
        conn.close()

    _audit_append(
        "tickets.push.enqueue",
        actor=f"operator:{info.operator_id}",
        target_id=f"{slug}/{ticket_id}",
        before=None,
        after={"state": row["state"], "attempts": row["attempts"],
               "session_id_prefix": info.id[:8]},
        reason="ticket queued for Autotask push",
        request_id=request_id,
    )

    return TicketPushStateRow(
        state=row["state"], attempts=row["attempts"],
        last_attempt_at=row["last_attempt_at"],
        last_error=row["last_error"],
        autotask_ticket_id=row["autotask_ticket_id"],
        queued_at=row["queued_at"],
        queued_by_operator_id=row["queued_by_operator_id"],
    )


# ---------------------------------------------------------------------------
# P5-c: bulk PATCH — apply the same patch to N tickets across tenants.
# ---------------------------------------------------------------------------
#
# Dispatch-grade affordance: "select 12 tickets, close them all" /
# "reassign these to Bob". Each row is validated + applied independently
# (so a single bad ref doesn't abort the batch) and the response carries
# per-row outcome for the UI.
#
# Path note: `/_bulk/patch` (two-segment under /tickets) avoids
# colliding with `/{slug}` — FastAPI tries `/{slug}/{ticket_id}` for
# this path but {ticket_id: int} rejects `patch`, so it falls through
# to this explicit handler regardless of registration order.

class TicketBulkRef(BaseModel):
    slug: str = Field(..., min_length=1, max_length=120)
    ticket_id: int = Field(..., ge=1)


class TicketBulkPatchRequest(BaseModel):
    refs: list[TicketBulkRef] = Field(..., min_length=1, max_length=100)
    patch: TicketPatchRequest


class TicketBulkPatchOutcome(BaseModel):
    slug: str
    ticket_id: int
    ok: bool
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class TicketBulkPatchResponse(BaseModel):
    results: list[TicketBulkPatchOutcome]
    succeeded: int
    failed: int


@router.post("/_bulk/patch", response_model=TicketBulkPatchResponse)
def bulk_patch_tickets(
    body: TicketBulkPatchRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> TicketBulkPatchResponse:
    """Apply the same patch to N tickets. Per-row scope + visibility
    checks happen via the existing single-ticket PATCH path — no
    isolation shortcuts. Hard cap of 100 refs per call so a runaway
    UI doesn't accidentally close-everything.
    """
    results: list[TicketBulkPatchOutcome] = []
    for ref in body.refs:
        try:
            # Reuse patch_ticket() — it handles scope, visibility,
            # validation, audit. We discard its return value (the
            # caller does a list refresh anyway).
            patch_ticket(ref.slug, ref.ticket_id, body.patch, request, info)
            results.append(TicketBulkPatchOutcome(
                slug=ref.slug, ticket_id=ref.ticket_id, ok=True,
            ))
        except APIError as e:
            results.append(TicketBulkPatchOutcome(
                slug=ref.slug, ticket_id=ref.ticket_id, ok=False,
                error_code=e.code, error_message=e.message,
            ))
        except Exception as e:  # noqa: BLE001
            results.append(TicketBulkPatchOutcome(
                slug=ref.slug, ticket_id=ref.ticket_id, ok=False,
                error_code="INTERNAL_ERROR",
                error_message=str(e)[:400],
            ))

    succeeded = sum(1 for r in results if r.ok)

    # Single bulk-op audit row capturing the batch shape — individual
    # ticket changes are already audited by the per-row patch_ticket()
    # calls, so this is a compact summary not a duplicate.
    _audit_append(
        "tickets.bulk_patch",
        actor=f"operator:{info.operator_id}",
        target_id=None,
        before=None,
        after={
            "refs_count": len(body.refs),
            "succeeded": succeeded,
            "failed": len(results) - succeeded,
            "patch_keys": [k for k, v in body.patch.model_dump().items()
                            if v not in (None, "")],
            "session_id_prefix": info.id[:8],
        },
        reason="bulk ticket patch",
        request_id=str(uuid.uuid4()),
    )

    return TicketBulkPatchResponse(
        results=results,
        succeeded=succeeded,
        failed=len(results) - succeeded,
    )
