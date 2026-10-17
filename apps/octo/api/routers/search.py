"""Client DB search — step-up auth + cross-tenant query.

Implements M2 (auth scaffolding) and M3 (events search) of the
2026-05-12 client-search design (kept outside the repo).

Endpoints in this file:
    POST /api/v1/search/elevate    — re-auth (password + TOTP) → set step-up
    GET  /api/v1/search/status     — caller's current elevation state
    POST /api/v1/search/events     — search across in-scope tenants' events.db

The /event/{slug}/{id} endpoint (M4) — full payload fetch — lands next.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pyotp
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.client_ip import client_ip
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier, resolve_caller_scope
from apps.octo.api.routers.auth import session_identity, _audit_append
from apps.octo.api.vendor_deep_links import resolve_alert_link
from apps.octo.api.vendor_links import VendorLinkResolver
from apps.octo.auth import core as core_auth, crypto, sessions, step_up
from apps.octo.db import connect
from apps.octo.threat import restricted


router = APIRouter(prefix="/search", tags=["search"])


# ---------------------------------------------------------------------------
# /status
# ---------------------------------------------------------------------------

class StepUpStatusResponse(BaseModel):
    elevated: bool
    granted_at: Optional[str] = None
    expires_at: Optional[str] = None
    absolute_expires_at: Optional[str] = None
    ttl_minutes: int
    absolute_cap_hours: int


def _iso_or_none(dt) -> Optional[str]:
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@router.get("/status", response_model=StepUpStatusResponse)
def get_status(
    info: sessions.SessionInfo = Depends(session_identity),
) -> StepUpStatusResponse:
    """Return the caller's step-up elevation state. Always 200 — the SPA
    uses this to decide whether to show the search page or trigger the
    elevate modal."""
    s = step_up.status_for(info)
    return StepUpStatusResponse(
        elevated=s.elevated,
        granted_at=_iso_or_none(s.granted_at),
        expires_at=_iso_or_none(s.expires_at),
        absolute_expires_at=_iso_or_none(s.absolute_expires_at),
        ttl_minutes=s.ttl_minutes,
        absolute_cap_hours=s.absolute_cap_hours,
    )


# ---------------------------------------------------------------------------
# /elevate
# ---------------------------------------------------------------------------

class ElevateRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    totp_code: str = Field(min_length=4, max_length=10)


class ElevateResponse(BaseModel):
    elevated: bool
    granted_at: str
    expires_at: str
    absolute_expires_at: str
    ttl_minutes: int
    absolute_cap_hours: int


@router.post("/elevate", response_model=ElevateResponse)
def elevate(
    body: ElevateRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> ElevateResponse:
    """Re-authenticate (password + TOTP) the already-signed-in operator to
    grant them a step-up window for /search/*.

    Even though the operator already has a valid session cookie, we
    re-verify both factors because step-up is meant to be an active
    proof-of-presence — not a passive consequence of a long-lived cookie.

    Failure modes:
      - wrong password → AUTH_PASSWORD_INVALID
      - wrong TOTP code → AUTH_TOTP_INVALID
      - operator disabled / locked → AUTH_LOCKED / AUTH_INVALID
      - MFA never enrolled → AUTH_MFA_NOT_ENROLLED

    Successful and failed attempts are BOTH audited so an admin can see
    patterns (e.g., correct-password + wrong-TOTP repeated = likely
    stolen credential + missing 2FA device).
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    reg = connect(paths.registry_db_path())
    try:
        row = reg.execute(
            "SELECT id, username, password_hash, mfa_enabled, mfa_secret_enc, "
            "       disabled_at, locked_until "
            "FROM operators WHERE id = ?",
            (info.operator_id,),
        ).fetchone()
        if row is None or row["disabled_at"] is not None:
            # Defensive — should be unreachable since session_identity
            # would have failed first. Treat as generic failure.
            raise APIError("AUTH_INVALID")
        if row["locked_until"] is not None:
            from datetime import datetime, timezone
            try:
                lu = datetime.fromisoformat(row["locked_until"].rstrip("Z") + "+00:00")
                if lu > datetime.now(timezone.utc):
                    raise APIError("AUTH_LOCKED")
            except ValueError:
                pass
        if not row["password_hash"]:
            raise APIError("AUTH_INVALID")
        # Password check (verify_token returns bool, not raises)
        if not core_auth.verify_token(body.current_password, row["password_hash"]):
            _audit_append(
                "step_up_failed",
                actor=row["username"],
                target_id=str(row["id"]),
                before=None,
                after={"outcome": "wrong_password", "ip": ip,
                        "session_id_prefix": info.id[:8]},
                reason="step-up re-auth — password did not verify",
                request_id=request_id,
            )
            raise APIError("AUTH_PASSWORD_INVALID")
        # MFA enrollment check
        if not row["mfa_enabled"] or not row["mfa_secret_enc"]:
            raise APIError("AUTH_MFA_NOT_ENROLLED")
        # TOTP check
        try:
            secret_b32 = crypto.decrypt_at_rest(row["mfa_secret_enc"]).decode()
        except (InvalidToken, ValueError):
            raise APIError("AUTH_TOTP_INVALID")
        totp = pyotp.TOTP(secret_b32)
        if not totp.verify(body.totp_code, valid_window=1):
            _audit_append(
                "step_up_failed",
                actor=row["username"],
                target_id=str(row["id"]),
                before=None,
                after={"outcome": "wrong_totp", "ip": ip,
                        "session_id_prefix": info.id[:8]},
                reason="step-up re-auth — TOTP did not verify",
                request_id=request_id,
            )
            raise APIError("AUTH_TOTP_INVALID")
    finally:
        reg.close()

    # Both factors confirmed — grant elevation, binding to the request's
    # network prefix (per SEARCH_STEP_UP_IP_BINDING — default subnet /24).
    # The address is client_ip(): X-Forwarded-For only from a trusted proxy
    # (OCTO_TRUSTED_PROXIES), else the socket peer.
    operator_ip = client_ip(request)
    status = step_up.grant(info.id, ip_address=operator_ip)
    _audit_append(
        "step_up_granted",
        actor=row["username"],
        target_id=str(row["id"]),
        before=None,
        after={"ip": ip, "session_id_prefix": info.id[:8],
                "granted_at": _iso_or_none(status.granted_at),
                "expires_at": _iso_or_none(status.expires_at),
                "ttl_minutes": status.ttl_minutes},
        reason="step-up re-auth succeeded for /search access",
        request_id=request_id,
    )
    return ElevateResponse(
        elevated=True,
        granted_at=_iso_or_none(status.granted_at) or "",
        expires_at=_iso_or_none(status.expires_at) or "",
        absolute_expires_at=_iso_or_none(status.absolute_expires_at) or "",
        ttl_minutes=status.ttl_minutes,
        absolute_cap_hours=status.absolute_cap_hours,
    )


# ---------------------------------------------------------------------------
# Step-up dependency for downstream /search/* routes (M3+ will use this)
# ---------------------------------------------------------------------------

def require_step_up(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> sessions.SessionInfo:
    """FastAPI dep: caller must hold an active step-up window AND
    request must come from the same network prefix the elevation was
    granted from (per SEARCH_STEP_UP_IP_BINDING).

    On success: slides the window forward, returns the fresh SessionInfo.
    Failure modes:
      - Not elevated / window expired / absolute cap hit → STEP_UP_REQUIRED
      - IP prefix mismatch → STEP_UP_NETWORK_CHANGED (clearance revoked)

    The SPA catches both codes and opens the re-auth modal — the
    distinction is for clearer UX messaging ("your session expired" vs
    "your network changed").
    """
    status = step_up.status_for(info)
    if not status.elevated:
        raise APIError("STEP_UP_REQUIRED")
    current_ip = client_ip(request)
    if not step_up.check_ip_binding(info, current_ip):
        # Revoke the clearance — same machine, different network is the
        # exact stolen-cookie pattern this defends against.
        step_up.revoke(info.id)
        raise APIError("STEP_UP_NETWORK_CHANGED")
    try:
        step_up.slide(info)
    except step_up.StepUpError:
        raise APIError("STEP_UP_REQUIRED")
    return info


# ---------------------------------------------------------------------------
# M3 — POST /api/v1/search/events
#
# The actual search. Scope enforcement happens BEFORE the SQL — caller's
# scope_slugs ∩ requested tenants is the effective set, and we only ever
# open events.db files in that set. An operator with scope=['acme'] cannot
# construct a query whose execution path reaches globex/events.db.
# ---------------------------------------------------------------------------

# Severity values that exist in events.db. Inputs outside this set are
# rejected as 400 before any SQL runs.
_VALID_SEVERITIES = frozenset(["info", "low", "medium", "high", "critical"])

# Hard caps from the design doc.
SEARCH_MAX_LIMIT = 100
SEARCH_MAX_OFFSET = 9900           # 100 pages × 100 rows
SEARCH_MAX_WINDOW_DAYS = 90        # max time range per query
SEARCH_FANOUT_BUDGET_MS = 500      # per-tenant SQLite query budget


class SearchEventsRequest(BaseModel):
    tenants: list[str] = Field(default_factory=list)
    query: Optional[str] = Field(default=None, max_length=200)
    event_types: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    time_from: Optional[str] = None  # ISO-8601 UTC
    time_to: Optional[str] = None
    source_host: Optional[str] = Field(default=None, max_length=200)
    limit: int = Field(default=100, ge=1, le=SEARCH_MAX_LIMIT)
    offset: int = Field(default=0, ge=0, le=SEARCH_MAX_OFFSET)


class SearchResultRow(BaseModel):
    client_slug: str
    event_id: int
    received_at: str
    event_type: str
    severity: str
    source: str
    """Vendor slug (e.g. 'datto', 'wazuh'). UI uses this to render a
    provenance badge per row. The clickable vendor deep-link itself is
    only surfaced on the per-event drawer fetch — computing it for every
    list row would require parsing every payload (too expensive)."""
    source_host: Optional[str]
    summary: str
    agent_note_count: int = 0
    """Count of `agent_notes` rows attached to this event. UI renders a
    `+N` chip when > 0; clicking the row opens the drawer which fetches
    the actual note bodies. Cheap to compute (indexed COUNT)."""


class SearchEventsResponse(BaseModel):
    results: list[SearchResultRow]
    total_estimate: int
    truncated: bool
    page_size: int
    offset: int
    tenants_searched: list[str]
    step_up_expires_at: Optional[str] = None


def _resolve_caller_scope(operator_id: int) -> list[str]:
    """`*` → ['*']; otherwise the caller's concrete slugs, ACTIVE tenants
    only (a tenant that was offboarded or archived is no longer a client
    user's to search) — the shared rule in `role_gates.resolve_caller_scope`,
    kept under this name for search_export and the tests."""
    return resolve_caller_scope(operator_id)


def _all_active_client_slugs() -> list[str]:
    """Used when caller scope is '*' AND request.tenants is empty
    (= "search everything I can see")."""
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(
            "SELECT slug FROM clients WHERE status = 'active'"
        ).fetchall()
    finally:
        reg.close()
    return [r["slug"] for r in rows]


def _intersect_scope(caller_scope: list[str], requested: list[str]) -> list[str]:
    """Intersect caller's allowed scope with explicit request.tenants.

    Rules:
      - caller scope=['*'] + empty request → all active clients
      - caller scope=['*'] + concrete request → request as-is (caller can see all)
      - caller scope=[concrete...] + empty request → caller's scope
      - caller scope=[concrete...] + concrete request → set intersection
      - empty result → caller asked for tenants they can't see → 403 later
    """
    if caller_scope == ["*"]:
        return sorted(requested) if requested else _all_active_client_slugs()
    if not requested:
        return list(caller_scope)
    allowed = set(caller_scope)
    return sorted(t for t in requested if t in allowed)


def _validate_time_range(time_from: Optional[str], time_to: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse ISO timestamps, enforce 90-day max window. Returns the
    (possibly-clamped) range as canonical 'Z'-suffixed ISO strings.

    A None bound on either side means open-ended on that side. If BOTH
    bounds are set and span > 90 days, we raise 400."""
    def _parse(s: str) -> datetime:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)

    f: Optional[datetime] = None
    t: Optional[datetime] = None
    try:
        if time_from is not None:
            f = _parse(time_from)
        if time_to is not None:
            t = _parse(time_to)
    except ValueError:
        raise APIError("VALIDATION_FAILED")
    if f is not None and t is not None and (t - f) > timedelta(days=SEARCH_MAX_WINDOW_DAYS):
        raise APIError("VALIDATION_FAILED")
    if f is not None and t is not None and f > t:
        raise APIError("VALIDATION_FAILED")

    def _iso(d: datetime) -> str:
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        d = d.astimezone(timezone.utc)
        return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"

    return (_iso(f) if f else None, _iso(t) if t else None)


def _validate_severities(sevs: list[str]) -> list[str]:
    if not sevs:
        return []
    bad = [s for s in sevs if s not in _VALID_SEVERITIES]
    if bad:
        raise APIError("VALIDATION_FAILED")
    return sorted(set(sevs))


def _normalize_filters_for_audit(req: SearchEventsRequest, tenants: list[str]) -> dict:
    """Produce a stable, low-cardinality summary of the search filters
    for the audit log. Concrete values are kept (so an auditor can see
    "operator searched for 'ssh brute'"), but ordered + de-duped so the
    same intent always produces the same audit entry. The free-text
    query is hashed in addition to stored so audit-pattern detection
    can spot "operator ran the same query N times" without grepping."""
    q = (req.query or "").strip()
    return {
        "tenants": sorted(tenants),
        "event_types": sorted(set(req.event_types)),
        "severities": sorted(set(req.severities)),
        "has_query": bool(q),
        "query_hash": hashlib.sha256(q.encode("utf-8")).hexdigest()[:16] if q else None,
        "time_from": req.time_from,
        "time_to": req.time_to,
        "source_host": req.source_host,
        "limit": req.limit,
        "offset": req.offset,
    }


# Athena's OWN incident records in events.db (Tier Black's `athena.incident`
# lifecycle events — `threat.store.EVENT_SOURCE` / `EVENT_TYPE`): an
# operator's search returns them; a CLIENT user's never does (what a client
# user may know of an incident is `threat.client_view`'s neutral line, after
# acknowledgement or 60 minutes — never its device, rule or analyst text).
OWN_RECORD_SOURCE, OWN_RECORD_TYPE = "athena", "athena.incident"


def sees_own_records(operator_id: int) -> bool:
    """Operators (analyst+) see Athena's incident records; a client user
    (viewer) never does."""
    return operator_max_tier(operator_id) >= ROLE_TIER["analyst"]


def _build_where_clause(req: SearchEventsRequest,
                          time_from: Optional[str],
                          time_to: Optional[str], *,
                          own_records: bool = True) -> tuple[str, list]:
    """Return (sql_fragment, params) — composed via parameterized
    SQL ONLY. NEVER string-interpolate user input into the SQL.
    `own_records` False (a client user): Athena's incident records are
    left out."""
    where: list[str] = []
    params: list = []
    if not own_records:
        where.append("NOT (source = ? AND event_type = ?)")
        params.extend([OWN_RECORD_SOURCE, OWN_RECORD_TYPE])
    if time_from is not None:
        where.append("received_at >= ?")
        params.append(time_from)
    if time_to is not None:
        where.append("received_at <= ?")
        params.append(time_to)
    if req.event_types:
        placeholders = ",".join("?" * len(req.event_types))
        where.append(f"event_type IN ({placeholders})")
        params.extend(req.event_types)
    if req.severities:
        placeholders = ",".join("?" * len(req.severities))
        where.append(f"severity IN ({placeholders})")
        params.extend(req.severities)
    if req.source_host:
        where.append("source_host = ?")
        params.append(req.source_host)
    if req.query:
        # LIKE on summary — uses idx_events_summary partial index when
        # summary != ''. Wildcard at end only would index-prefix-scan;
        # wildcard both sides forces full scan within other filters'
        # candidate set. That's acceptable v1 — FTS5 lands later.
        where.append("summary LIKE ?")
        params.append(f"%{req.query}%")
    sql = ("WHERE " + " AND ".join(where)) if where else ""
    return sql, params


def _query_one_tenant(slug: str, req: SearchEventsRequest,
                       time_from: Optional[str], time_to: Optional[str],
                       per_tenant_limit: int, *,
                       own_records: bool = True) -> tuple[list[SearchResultRow], int]:
    """Run the search against one tenant's events.db. Returns
    (rows_in_tenant_order_received_at_desc, count_estimate).

    The count is bounded — we count up to per_tenant_limit + offset + 1
    so the response's total_estimate can say "247 if known, else 1000+".
    Doing a true COUNT(*) on multi-million-row tables is too expensive
    for an interactive search.
    """
    db_path = paths.client_db_path(slug, "events")
    if not db_path.exists():
        return [], 0
    where_sql, params = _build_where_clause(req, time_from, time_to, own_records=own_records)
    gate = restricted.Gate.for_tenant(slug)
    try:
        conn = connect(db_path, read_only=True)
        conn.row_factory = sqlite3.Row
        # RESTRICTED (B7, CSAM): a row that names a domain the tenant holds
        # as restricted evidence (a Pi-hole upstream block, a Suricata DNS
        # alert) is left out for EVERY role — admins read it in the
        # restricted incident's audited detail. The count uses the same
        # predicate, so nothing hints at it.
        where_sql = restricted.gate_sql(gate, conn, where_sql, "summary", "payload",
                                        "source_host")
        # SQLite query-time cap. progress_handler runs every N ops; if
        # the handler returns non-zero, the query aborts. We give 500ms
        # converted to roughly an op-count via a coarse estimate.
        # Approximate: ~100k ops per 100ms on modern HW.
        try:
            # Best-effort cancel — if SQLite can't honor it, query just
            # runs to completion. Don't fail-loud.
            conn.set_progress_handler(lambda: 0, 100_000)
        except Exception:
            pass
        try:
            # Per-tenant migration 011 (agent_notes) applies lazily on
            # first write. On a freshly-provisioned tenant whose ingest
            # path hasn't triggered 011 yet, the table is absent. Probe
            # sqlite_master ONCE per query and drop the subquery if so —
            # otherwise the whole SELECT throws OperationalError and the
            # outer handler swallows every row in the tenant.
            has_agent_notes = conn.execute(
                "SELECT 1 FROM sqlite_master "
                " WHERE type='table' AND name='agent_notes' LIMIT 1"
            ).fetchone() is not None
            agent_note_count_expr = (
                "COALESCE((SELECT COUNT(*) FROM agent_notes n "
                "          WHERE n.ref_kind = 'event' AND n.ref_id = e.id), 0)"
                if has_agent_notes else "0"
            )
            rows = conn.execute(
                f"SELECT e.id, e.received_at, e.event_type, e.severity, "
                f"  e.source, e.source_host, e.summary, "
                f"  {agent_note_count_expr} AS agent_note_count "
                f"FROM events e {where_sql} "
                f"ORDER BY e.received_at DESC LIMIT ?",
                (*params, per_tenant_limit),
            ).fetchall()
            # Bounded count estimate (capped at 10k for performance)
            count_cap = 10_000
            count_row = conn.execute(
                f"SELECT COUNT(*) FROM ("
                f"  SELECT 1 FROM events {where_sql} LIMIT ?)",
                (*params, count_cap),
            ).fetchone()
            count_estimate = count_row[0] if count_row else 0
        finally:
            conn.close()
    except sqlite3.OperationalError:
        # DB busy or cancelled — return what we have (nothing) without
        # 500ing the whole search.
        return [], 0
    out: list[SearchResultRow] = []
    for r in rows:
        out.append(SearchResultRow(
            client_slug=slug,
            event_id=r["id"],
            received_at=r["received_at"],
            event_type=r["event_type"],
            severity=r["severity"],
            source=r["source"],
            source_host=r["source_host"],
            summary=r["summary"] or "",
            agent_note_count=r["agent_note_count"] or 0,
        ))
    return out, count_estimate


@router.post("/events", response_model=SearchEventsResponse)
def search_events(
    body: SearchEventsRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(require_step_up),
) -> SearchEventsResponse:
    """Search ingested events across the caller's in-scope tenants.

    Security pre-flight (BEFORE any SQL):
      1. Caller has a valid session (handled by session_identity)
      2. Caller has an active step-up window (require_step_up)
      3. Caller's scope ∩ request.tenants determines the effective set
      4. Empty intersection (caller asked for tenants they can't see)
         → ISOLATION_VIOLATION
      5. Severities + time-range validated
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    # Validate inputs
    req_severities = _validate_severities(body.severities)
    body = body.model_copy(update={"severities": req_severities})
    time_from, time_to = _validate_time_range(body.time_from, body.time_to)
    # Default time range: 24h back from now if neither bound given
    if time_from is None and time_to is None:
        now = datetime.now(timezone.utc)
        time_from = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Scope enforcement — this is the load-bearing security check
    caller_scope = _resolve_caller_scope(info.operator_id)
    effective_tenants = _intersect_scope(caller_scope, body.tenants)
    if not effective_tenants:
        # Caller asked for tenants they can't see (or has no role
        # grants at all). 403, not 200-with-empty-results, so an
        # exfiltration attempt becomes visible in audit + rate-limit.
        raise APIError("ISOLATION_VIOLATION")

    # Per-tenant fan-out. Each tenant fetches up to (offset + limit + 1)
    # rows so the merge-sort + slice produces correct pagination.
    over_fetch = body.offset + body.limit + 1
    all_rows: list[SearchResultRow] = []
    total_estimate = 0
    truncated = False
    own = sees_own_records(info.operator_id)
    for slug in effective_tenants:
        rows, count = _query_one_tenant(slug, body, time_from, time_to, over_fetch,
                                        own_records=own)
        all_rows.extend(rows)
        total_estimate += count
        if count >= 10_000:
            truncated = True

    # Merge-sort by received_at DESC, paginate
    all_rows.sort(key=lambda r: r.received_at, reverse=True)
    page = all_rows[body.offset : body.offset + body.limit]

    # Step-up window may have slid since the require_step_up dep ran.
    # Re-read the row to get the current expiry for the response.
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        sess_row = reg.execute(
            "SELECT step_up_auth_until FROM sessions WHERE id = ?",
            (info.id,),
        ).fetchone()
    finally:
        reg.close()
    step_up_until = sess_row["step_up_auth_until"] if sess_row else None

    # Compute step_up_age_seconds for audit (time since grant)
    if info.step_up_auth_granted_at is not None:
        age = (datetime.now(timezone.utc) - info.step_up_auth_granted_at).total_seconds()
        step_up_age_seconds = int(age)
    else:
        step_up_age_seconds = None

    # Audit — every search logged, success or empty alike
    filters_norm = _normalize_filters_for_audit(body, effective_tenants)
    _audit_append(
        "search.events",
        actor=f"operator:{info.operator_id}",
        target_id=info.id[:8],
        before=None,
        after={
            "tenants": effective_tenants,
            "filters": filters_norm,
            "rows_returned": len(page),
            "total_estimate": total_estimate,
            "truncated": truncated,
            "step_up_age_seconds": step_up_age_seconds,
            "ip": ip,
        },
        reason="search across in-scope tenants",
        request_id=request_id,
    )

    return SearchEventsResponse(
        results=page,
        total_estimate=total_estimate,
        truncated=truncated,
        page_size=body.limit,
        offset=body.offset,
        tenants_searched=effective_tenants,
        step_up_expires_at=step_up_until,
    )


# ---------------------------------------------------------------------------
# M4 — GET /api/v1/search/event/{client_slug}/{event_id}
#
# Drawer-click target. Returns the full payload for one event. Separately
# audited as `search.event_payload` so reviewing "operator X opened event
# Y at time Z" has its own log entries — bulk-search vs. drill-down show
# different patterns.
# ---------------------------------------------------------------------------

class AgentNote(BaseModel):
    """A single agent note attached to an event/ticket/indicator.
    See migration 011 (agent notes in search, with pattern links)."""
    id: int
    agent_id: str  # 'octo' | 'athena' (see migration 011)
    note_text: str
    confidence: float
    created_at: str
    updated_at: Optional[str] = None


class AgentPatternLink(BaseModel):
    """A typed edge from this event to another ref (event / ticket /
    indicator) in the SAME tenant. Cross-tenant edges are reserved for
    the sanitized-pool variant (Task #114) — not surfaced here."""
    id: int
    to_kind: str  # 'event' | 'ticket' | 'indicator'
    to_id: int
    relation: str  # 'same_ioc' | 'same_host' | 'same_ttp' | 'temporal' | 'semantic'
    strength: float
    rationale: str
    created_by_agent: str
    created_at: str


class EventPayloadResponse(BaseModel):
    client_slug: str
    event_id: int
    received_at: str
    source: str
    source_host: Optional[str]
    event_type: str
    severity: str
    summary: str
    payload: dict  # parsed JSON
    payload_sha256: str
    relay_status: str
    relay_attempts: int
    relayed_at: Optional[str]
    step_up_expires_at: Optional[str] = None
    vendor_deep_link: Optional[str] = None
    """`adapter.deep_link(event, 'alert')`. None when no adapter is
    registered for `source`, the payload lacks `vendor_event_id`, or the
    adapter returns None (e.g., env-based portal URL not configured)."""
    vendor_display_name: Optional[str] = None
    """Human-readable vendor name (e.g. 'Datto RMM'). Surfaced even
    when `vendor_deep_link` is None so the UI can still show a
    provenance badge."""
    agent_notes: list[AgentNote] = []
    """All `agent_notes` rows attached to this event. Ordered most
    recent first. Empty when no agent has annotated."""
    agent_pattern_links: list[AgentPatternLink] = []
    """Outgoing edges from this event to other refs in the same tenant.
    Drawer / sidebar renders the relation icon + strength + rationale
    + clickable target. Empty when no patterns detected."""
    derived_ticket_id: Optional[int] = None
    """If a ticket was opened from this event (tickets.source_event_id),
    that ticket's id. NULL when no ticket has been derived. Used by the
    drawer to surface a "Open ticket #N" cross-link so the operator can
    pivot from the alert into the working surface in one click."""
    derived_ticket_title: Optional[str] = None
    """Title of the derived ticket — shown alongside the id when the
    cross-link is rendered."""


@router.get("/event/{client_slug}/{event_id}",
              response_model=EventPayloadResponse)
def get_event_payload(
    client_slug: str,
    event_id: int,
    request: Request,
    info: sessions.SessionInfo = Depends(require_step_up),
) -> EventPayloadResponse:
    """Fetch a single event's full payload. Step-up + scope gated +
    separately audited from the bulk search action."""
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    # Scope check — caller must have visibility into this specific slug.
    caller_scope = _resolve_caller_scope(info.operator_id)
    effective = _intersect_scope(caller_scope, [client_slug])
    if client_slug not in effective:
        raise APIError("ISOLATION_VIOLATION")

    db_path = paths.client_db_path(client_slug, "events")
    if not db_path.exists():
        raise APIError("NOT_FOUND")

    conn = connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, received_at, source, source_host, event_type, "
            "  severity, payload, payload_sha256, relay_status, "
            "  relay_attempts, relayed_at, summary "
            "FROM events WHERE id = ?",
            (event_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or (row["source"] == OWN_RECORD_SOURCE
                       and row["event_type"] == OWN_RECORD_TYPE
                       and not sees_own_records(info.operator_id)):
        raise APIError("NOT_FOUND")
    if restricted.Gate.for_tenant(client_slug).hits(row["summary"], row["payload"],
                                                    row["source_host"]):
        # RESTRICTED (B7, CSAM): the record names a domain the tenant holds
        # as restricted evidence — never previewed here, for any role (the
        # same answer as no such event). Admins read it, defanged, in the
        # restricted incident's audited detail. The try is audited.
        _audit_append(
            "search.event_payload",
            actor=f"operator:{info.operator_id}",
            target_id=f"{client_slug}:{event_id}",
            before=None,
            after={"client_slug": client_slug, "event_id": event_id,
                   "restricted_refused": True, "session_id_prefix": info.id[:8], "ip": ip},
            reason="payload drawer drill-down refused: restricted content",
            request_id=request_id,
        )
        raise APIError("NOT_FOUND")

    # Parse payload — events.db stores JSON-as-text
    try:
        payload_parsed = json.loads(row["payload"])
        if not isinstance(payload_parsed, dict):
            payload_parsed = {"_raw": payload_parsed}
    except (json.JSONDecodeError, TypeError):
        payload_parsed = {"_raw_text": row["payload"]}

    # Step-up window may have slid since require_step_up ran.
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        sess_row = reg.execute(
            "SELECT step_up_auth_until FROM sessions WHERE id = ?",
            (info.id,),
        ).fetchone()
    finally:
        reg.close()
    step_up_until = sess_row["step_up_auth_until"] if sess_row else None

    # Audit — payload-fetch is its own category. Includes the specific
    # event id so an auditor can trace "operator X opened payload Y".
    _audit_append(
        "search.event_payload",
        actor=f"operator:{info.operator_id}",
        target_id=f"{client_slug}:{event_id}",
        before=None,
        after={
            "client_slug": client_slug,
            "event_id": event_id,
            "event_type": row["event_type"],
            "severity": row["severity"],
            "session_id_prefix": info.id[:8],
            "ip": ip,
        },
        reason="payload drawer drill-down",
        request_id=request_id,
    )

    deep_link_url, vendor_display = resolve_alert_link(
        request,
        source_slug=row["source"],
        payload=payload_parsed,
        payload_sha256=row["payload_sha256"],
        source_host=row["source_host"],
        received_at=row["received_at"],
        severity=row["severity"],
        summary=row["summary"] or "",
    )
    # Per-instance links (built from the vendor's own ids) win over the
    # contract's env-based deep_link(). A Viewer gets neither: the vendor
    # portal is the MSP's, not the client's.
    link_resolver = VendorLinkResolver(request, operator_id=info.operator_id)
    if not link_resolver.allowed:
        deep_link_url = None
    else:
        instance_links = link_resolver.links(
            source=row["source"], client_slug=client_slug,
            payload=payload_parsed, kinds=("alert",),
        )
        if instance_links:
            deep_link_url = instance_links[0].url

    # Agent layer — fetch notes + outgoing pattern links for this
    # event. Both are indexed reads (idx_agent_notes_ref +
    # idx_pattern_links_from). Tables may not exist yet on older dev
    # DBs that haven't applied migration 011 — guard with try/except.
    agent_notes_out: list[AgentNote] = []
    agent_links_out: list[AgentPatternLink] = []
    try:
        ag_conn = connect(db_path, read_only=True)
        ag_conn.row_factory = sqlite3.Row
        try:
            note_rows = ag_conn.execute(
                "SELECT id, agent_id, note_text, confidence, created_at, "
                "       updated_at "
                "  FROM agent_notes "
                " WHERE ref_kind = 'event' AND ref_id = ? "
                " ORDER BY created_at DESC",
                (event_id,),
            ).fetchall()
            for n in note_rows:
                agent_notes_out.append(AgentNote(
                    id=n["id"],
                    agent_id=n["agent_id"],
                    note_text=n["note_text"],
                    confidence=n["confidence"],
                    created_at=n["created_at"],
                    updated_at=n["updated_at"],
                ))
            link_rows = ag_conn.execute(
                "SELECT id, to_kind, to_id, relation, strength, "
                "       rationale, created_by_agent, created_at "
                "  FROM agent_pattern_links "
                " WHERE from_kind = 'event' AND from_id = ? "
                " ORDER BY strength DESC, created_at DESC",
                (event_id,),
            ).fetchall()
            for lk in link_rows:
                agent_links_out.append(AgentPatternLink(
                    id=lk["id"],
                    to_kind=lk["to_kind"],
                    to_id=lk["to_id"],
                    relation=lk["relation"],
                    strength=lk["strength"],
                    rationale=lk["rationale"],
                    created_by_agent=lk["created_by_agent"],
                    created_at=lk["created_at"],
                ))
        finally:
            ag_conn.close()
    except sqlite3.OperationalError:
        # Tables not yet present (pre-migration-011). Leave both lists
        # empty; the UI renders the drawer without an Agent Notes section.
        pass

    # Derived-ticket cross-link — if a ticket was opened from this
    # event, surface its id + title so the drawer can render a
    # one-click pivot back to /tickets. Best-effort: tolerate a
    # tenant whose tickets.db doesn't exist yet, or a schema that
    # predates migration 013.
    derived_ticket_id: Optional[int] = None
    derived_ticket_title: Optional[str] = None
    tdb_path = paths.client_dir(client_slug) / "tickets.db"
    if tdb_path.exists():
        try:
            tconn = sqlite3.connect(f"file:{tdb_path}?mode=ro", uri=True)
            tconn.row_factory = sqlite3.Row
            try:
                trow = tconn.execute(
                    "SELECT id, title FROM tickets "
                    " WHERE source_event_id = ? "
                    " ORDER BY id DESC LIMIT 1",
                    (event_id,),
                ).fetchone()
                if trow is not None:
                    derived_ticket_id = trow["id"]
                    derived_ticket_title = trow["title"]
            finally:
                tconn.close()
        except sqlite3.OperationalError:
            pass

    return EventPayloadResponse(
        client_slug=client_slug,
        event_id=row["id"],
        received_at=row["received_at"],
        source=row["source"],
        source_host=row["source_host"],
        event_type=row["event_type"],
        severity=row["severity"],
        summary=row["summary"] or "",
        payload=payload_parsed,
        payload_sha256=row["payload_sha256"],
        relay_status=row["relay_status"],
        relay_attempts=row["relay_attempts"],
        relayed_at=row["relayed_at"],
        step_up_expires_at=step_up_until,
        vendor_deep_link=deep_link_url,
        vendor_display_name=vendor_display,
        agent_notes=agent_notes_out,
        agent_pattern_links=agent_links_out,
        derived_ticket_id=derived_ticket_id,
        derived_ticket_title=derived_ticket_title,
    )


# ---------------------------------------------------------------------------
# M9 — POST /api/v1/search/indicators
#
# Threat-intel / indicator-of-compromise search. Reads from per-tenant
# `indicators.db` files, same scope-enforcement + step-up + audit pattern
# as /events. Different filter shape because IOCs are higher-signal
# lower-volume:
#   - type (ip/domain/url/hash/cidr/cve/...)
#   - severity (low/medium/high/critical — note: no 'info' for IOCs)
#   - confidence range (0.0..1.0)
#   - source (which feed/integration brought it in)
#   - free-text on value OR context
#   - indicator_ids (per-tenant row ids: how the dashboard pulse's masked
#     rows resolve to their full value, behind this route's step-up)
#
# Future M10 = cross-tenant sanitized pool — same shape but reads from a
# yet-to-be-built global pool. Defer until the pool exists.
# ---------------------------------------------------------------------------

_VALID_INDICATOR_TYPES = frozenset([
    "ip", "ipv6", "domain", "url",
    "md5", "sha1", "sha256",
    "email", "cidr", "cve", "other",
])
_VALID_INDICATOR_SEVERITIES = frozenset(["low", "medium", "high", "critical"])


class SearchIndicatorsRequest(BaseModel):
    tenants: list[str] = Field(default_factory=list)
    query: Optional[str] = Field(default=None, max_length=200)
    types: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    confidence_min: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    confidence_max: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    promoted_only: bool = False
    include_deleted: bool = False
    indicator_ids: list[int] = Field(default_factory=list, max_length=SEARCH_MAX_LIMIT)
    """Row ids — how a dashboard pulse `search_ref` ("<tenant>:<id>")
    resolves to its full value: `tenants=[tenant]`, `indicator_ids=[id]`.
    Ids are per-tenant, so pair them with the one tenant they came from."""
    limit: int = Field(default=100, ge=1, le=SEARCH_MAX_LIMIT)
    offset: int = Field(default=0, ge=0, le=SEARCH_MAX_OFFSET)


class IndicatorResultRow(BaseModel):
    client_slug: str
    indicator_id: int
    value: str
    type: str
    source: str
    severity: str
    confidence: float
    context: Optional[str]
    first_seen: str
    last_seen: str
    hits: int
    promoted_at: Optional[str]


class SearchIndicatorsResponse(BaseModel):
    results: list[IndicatorResultRow]
    total_estimate: int
    truncated: bool
    page_size: int
    offset: int
    tenants_searched: list[str]
    step_up_expires_at: Optional[str] = None


def _validate_indicator_types(types: list[str]) -> list[str]:
    if not types:
        return []
    bad = [t for t in types if t not in _VALID_INDICATOR_TYPES]
    if bad:
        raise APIError("VALIDATION_FAILED")
    return sorted(set(types))


def _validate_indicator_severities(sevs: list[str]) -> list[str]:
    if not sevs:
        return []
    bad = [s for s in sevs if s not in _VALID_INDICATOR_SEVERITIES]
    if bad:
        raise APIError("VALIDATION_FAILED")
    return sorted(set(sevs))


def _build_indicator_where(req: SearchIndicatorsRequest) -> tuple[str, list]:
    where: list[str] = []
    params: list = []
    if not req.include_deleted:
        where.append("deleted_at IS NULL")
    if req.promoted_only:
        where.append("promoted_at IS NOT NULL")
    if req.indicator_ids:
        placeholders = ",".join("?" * len(req.indicator_ids))
        where.append(f"id IN ({placeholders})")
        params.extend(req.indicator_ids)
    if req.types:
        placeholders = ",".join("?" * len(req.types))
        where.append(f"type IN ({placeholders})")
        params.extend(req.types)
    if req.severities:
        placeholders = ",".join("?" * len(req.severities))
        where.append(f"severity IN ({placeholders})")
        params.extend(req.severities)
    if req.sources:
        placeholders = ",".join("?" * len(req.sources))
        where.append(f"source IN ({placeholders})")
        params.extend(req.sources)
    if req.confidence_min is not None:
        where.append("confidence >= ?")
        params.append(req.confidence_min)
    if req.confidence_max is not None:
        where.append("confidence <= ?")
        params.append(req.confidence_max)
    if req.query:
        where.append("(value LIKE ? OR context LIKE ?)")
        pat = f"%{req.query}%"
        params.extend([pat, pat])
    sql = ("WHERE " + " AND ".join(where)) if where else ""
    return sql, params


def _query_one_tenant_indicators(
    slug: str, req: SearchIndicatorsRequest, per_tenant_limit: int,
) -> tuple[list[IndicatorResultRow], int]:
    db_path = paths.client_db_path(slug, "indicators")
    if not db_path.exists():
        return [], 0
    where_sql, params = _build_indicator_where(req)
    gate = restricted.Gate.for_tenant(slug)
    try:
        conn = connect(db_path, read_only=True)
        conn.row_factory = sqlite3.Row
        # RESTRICTED (B7, CSAM): an indicator naming a restricted domain is
        # never listed (every role; the count agrees).
        where_sql = restricted.gate_sql(gate, conn, where_sql, "value", "context")
        try:
            rows = conn.execute(
                f"SELECT id, value, type, source, severity, confidence, "
                f"  context, first_seen, last_seen, hits, promoted_at "
                f"FROM indicators {where_sql} "
                f"ORDER BY last_seen DESC LIMIT ?",
                (*params, per_tenant_limit),
            ).fetchall()
            count_cap = 10_000
            count_row = conn.execute(
                f"SELECT COUNT(*) FROM ("
                f"  SELECT 1 FROM indicators {where_sql} LIMIT ?)",
                (*params, count_cap),
            ).fetchone()
            count_estimate = count_row[0] if count_row else 0
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return [], 0
    out: list[IndicatorResultRow] = []
    for r in rows:
        out.append(IndicatorResultRow(
            client_slug=slug,
            indicator_id=r["id"],
            value=r["value"],
            type=r["type"],
            source=r["source"],
            severity=r["severity"],
            confidence=r["confidence"],
            context=r["context"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            hits=r["hits"],
            promoted_at=r["promoted_at"],
        ))
    return out, count_estimate


@router.post("/indicators", response_model=SearchIndicatorsResponse)
def search_indicators(
    body: SearchIndicatorsRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(require_step_up),
) -> SearchIndicatorsResponse:
    """Search IOCs across the caller's in-scope tenants' indicators.db
    files. Same security model as /events — step-up + scope + audit.

    `promoted_only=true` filters to indicators that have been promoted
    (the future sanitized-pool candidate set — currently still per-
    tenant since M10 hasn't shipped).
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    body_types = _validate_indicator_types(body.types)
    body_sevs = _validate_indicator_severities(body.severities)
    body = body.model_copy(update={"types": body_types, "severities": body_sevs})
    if (body.confidence_min is not None and body.confidence_max is not None
            and body.confidence_min > body.confidence_max):
        raise APIError("VALIDATION_FAILED")

    caller_scope = _resolve_caller_scope(info.operator_id)
    effective_tenants = _intersect_scope(caller_scope, body.tenants)
    if not effective_tenants:
        raise APIError("ISOLATION_VIOLATION")

    over_fetch = body.offset + body.limit + 1
    all_rows: list[IndicatorResultRow] = []
    total_estimate = 0
    truncated = False
    for slug in effective_tenants:
        rows, count = _query_one_tenant_indicators(slug, body, over_fetch)
        all_rows.extend(rows)
        total_estimate += count
        if count >= 10_000:
            truncated = True

    all_rows.sort(key=lambda r: r.last_seen, reverse=True)
    page = all_rows[body.offset : body.offset + body.limit]

    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        sess_row = reg.execute(
            "SELECT step_up_auth_until FROM sessions WHERE id = ?",
            (info.id,),
        ).fetchone()
    finally:
        reg.close()
    step_up_until = sess_row["step_up_auth_until"] if sess_row else None

    # Audit — search.indicators distinguishes from search.events even
    # though the security shape is identical. Auditors want to filter
    # one or the other separately.
    q = (body.query or "").strip()
    _audit_append(
        "search.indicators",
        actor=f"operator:{info.operator_id}",
        target_id=info.id[:8],
        before=None,
        after={
            "tenants": effective_tenants,
            "filters": {
                "types": body.types,
                "severities": body.severities,
                "sources": sorted(set(body.sources)),
                "confidence_min": body.confidence_min,
                "confidence_max": body.confidence_max,
                "promoted_only": body.promoted_only,
                "include_deleted": body.include_deleted,
                "indicator_ids": sorted(set(body.indicator_ids)),
                "has_query": bool(q),
                "query_hash": hashlib.sha256(q.encode("utf-8")).hexdigest()[:16] if q else None,
                "limit": body.limit,
                "offset": body.offset,
            },
            "rows_returned": len(page),
            "total_estimate": total_estimate,
            "truncated": truncated,
            "ip": ip,
        },
        reason="indicator search across in-scope tenants",
        request_id=request_id,
    )

    return SearchIndicatorsResponse(
        results=page,
        total_estimate=total_estimate,
        truncated=truncated,
        page_size=body.limit,
        offset=body.offset,
        tenants_searched=effective_tenants,
        step_up_expires_at=step_up_until,
    )
