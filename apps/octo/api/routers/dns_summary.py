"""DNS telemetry summary — the dashboard's view of the tiered telemetry store.

  GET  /api/v1/dashboard/dns-summary   analyst+, scoped, MASKED, unaudited
  POST /api/v1/search/dns              analyst+, step-up, UNMASKED, audited

Since migration 036, answered DNS (pihole.query / suricata.dns) and TLS /
HTTP / flow metadata live in each tenant's telemetry.db — hourly roll-ups
and a first-seen-domain ledger — not in events.db. Per in-scope tenant with
telemetry, over the last `hours`:

  * lookups     answered DNS lookups, from ONE sensor (`lookups_source`):
                Pi-hole's answered queries when the tenant has Pi-hole data
                in the window — it sees each client lookup exactly once —
                else Suricata's DNS QUERY records. Never a sum or max of the
                two: Suricata logs each lookup as a query AND an answer
                record, and sees Pi-hole's own upstream re-queries, so its
                count is about twice the real one (the answers roll up
                apart, as `suricata.dns.answer`). Both sensors' counts are
                returned per domain alongside;
  * blocked     Pi-hole lookups filed as SIGNALS in the window — blocked
                (or of unknown status, fail-safe) — counted from events.db
                by the ingest classifier on each stored payload
                (`tiering.classify_stored`), so an ANSWERED lookup that sits
                in events.db only because the telemetry store refused it at
                ingest is NOT counted as blocked; such rows — stamped with
                their arrival by the 036 sink — are reported as
                `fallback_rows` (the nightly sweep moves them), together
                with this process's count of writes refused in the last
                24 hours (`recent_store_fallbacks`) — a store fault is
                visible here, and the warning clears a day after it did.
                Answered lookups stored BEFORE the upgrade (no arrival
                stamp) are not a fault: they are `awaiting_move_rows`,
                waiting for the one-off move (upgrade step 4) — said
                neutrally, not counted as lookups until moved;
  * top domains by lookups (a domain with no answered lookup — only
                blocked ones — is not a "top looked-up" domain), with the
                number of distinct devices;
  * first-seen  domains the tenant had never looked up before (within the
                ledger's memory — a domain unseen for a year is new again),
                newest first, plus when the ledger started (`baseline_since`:
                during a tenant's first week everything is "new").

MASKING (decision, following the v0.9 threat-intel pulse rule, owner
decision 2026-09-28 (a)): a domain a client's devices looked up is tenant
data exactly like an IOC — it can reveal what a clinic's staff browse, which
bank a firm uses, which vendor portal it depends on. The dashboard route
therefore returns every domain masked server-side (`mask_indicator(…,
'domain')`, e.g. "wi*****.com") and never a device name or address (only a
count). The full values come only from the step-up-gated
`POST /search/dns`, audited per call (`search.dns_summary`) as an on-demand
sensitive read — the same split as the pulse and /search/indicators.

The dashboard route is a polled, scope-gated aggregate with masked values
only, so — like ti-pulse — it writes no audit row (docs/audit-policy.md:
not audited), and answers Cache-Control: no-store. Viewers (client users)
get 403, as for the pulse.
"""
from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.ingest import arrival, tiering
from apps.octo.api.indicator_mask import mask_indicator
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_at_least,
)
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import sessions
from apps.octo.threat import restricted
from apps.octo.db import connect
from apps.octo.ingest.sink import FAULT_WINDOW_HOURS, telemetry_fallbacks

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
search_router = APIRouter(prefix="/search", tags=["search"])

session_analyst_plus = session_at_least("analyst")


def _analyst_step_up(
    _role: sessions.SessionInfo = Depends(session_analyst_plus),
    info: sessions.SessionInfo = Depends(require_step_up),
) -> sessions.SessionInfo:
    """analyst+ FIRST (a viewer gets 403, not a re-auth prompt that would
    only end in a 403 — nor a step-up window slid for a route it cannot
    use), then an active step-up window on the same session."""
    return info

DNS_TYPES = ("pihole.query", "suricata.dns")
BASELINE_DAYS = 7
MAX_HOURS = 168
MAX_ROLLUP_DAYS = 180

LookupsSource = Literal["pihole", "suricata"]

DnsEmptyReason = Literal["no_tenants", "no_telemetry", "unavailable"]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class DnsDomainRow(BaseModel):
    masked_domain: str
    lookups: int
    """The tenant's `lookups_source` count for this domain."""
    pihole: int
    suricata: int
    """Suricata DNS QUERY records (answers are not counted)."""
    devices: int


class DnsFirstSeenRow(BaseModel):
    masked_domain: str
    first_seen: str
    first_event_type: str


class DnsTenantSummary(BaseModel):
    tenant: str
    lookups: int
    lookups_source: Optional[LookupsSource] = None
    """Which sensor `lookups` counts: Pi-hole when the tenant has any Pi-hole
    data in the window, else Suricata's query records."""
    by_type: dict[str, int]
    """Every telemetry roll-up key's count in the window (raw, not
    de-duplicated) — pihole.query, suricata.dns (queries),
    suricata.dns.answer, suricata.tls / http / flow."""
    blocked: int
    fallback_rows: int = 0
    """Answered-lookup rows in events.db in the window that the 036 sink
    stored there (they carry an arrival stamp) because the telemetry store
    refused them at ingest; the nightly sweep moves them. Non-zero = a
    telemetry-store fault."""
    awaiting_move_rows: int = 0
    """Answered-lookup rows in events.db in the window stored BEFORE the
    upgrade (no arrival stamp): not a fault — the one-off move
    (move_telemetry_out_of_events.py) takes them to telemetry.db."""
    recent_store_fallbacks: int = 0
    """Telemetry writes for this tenant stored in events.db instead in the
    last `store_fallback_window_hours` (this server process; memory only)."""
    store_fallback_window_hours: int = 24
    top_domains: list[DnsDomainRow]
    first_seen: list[DnsFirstSeenRow]
    first_seen_count: int
    baseline_since: Optional[str] = None
    baseline_building: bool = False
    """The ledger is younger than a week: nearly every domain is "new"."""


class DnsSummaryTotals(BaseModel):
    lookups: int = 0
    blocked: int = 0
    first_seen: int = 0
    fallback_rows: int = 0
    awaiting_move_rows: int = 0


class DnsSummaryResponse(BaseModel):
    window_hours: int
    tenants: list[DnsTenantSummary]
    totals: DnsSummaryTotals
    masked: bool = True
    unreadable_tenants: int = 0
    empty_reason: Optional[DnsEmptyReason] = None
    empty_detail: Optional[str] = None


class DnsDomainFull(BaseModel):
    domain: str
    lookups: int
    pihole: int
    suricata: int
    devices: int


class DnsFirstSeenFull(BaseModel):
    domain: str
    first_seen: str
    first_device: str
    first_event_type: str


class DnsSearchRequest(BaseModel):
    tenant: str = Field(min_length=1, max_length=64)
    hours: int = Field(default=24, ge=1, le=MAX_HOURS)
    """Window for the summary and the RAW lookups (raw rows are kept 7
    days; older ones are in the cold archive)."""
    limit: int = Field(default=20, ge=1, le=100)
    domain: Optional[str] = Field(default=None, max_length=253)
    """Who looked this name up? Answered lookups of it (and, with
    `include_subdomains`, of any name under it)."""
    include_subdomains: bool = True
    device: Optional[str] = Field(default=None, max_length=128)
    """What did this device (LAN address / Pi-hole client name) look up?"""
    rollup_days: int = Field(default=30, ge=1, le=MAX_ROLLUP_DAYS)
    """Window for `sightings` (the hourly roll-up is kept 180 days)."""


class DnsSighting(BaseModel):
    """One (domain, device, sensor) seen in the roll-up window. `device` is
    the client's address (the key every sensor shares), `device_name` the
    name Pi-hole v6 knows it by ("" when none)."""
    domain: str
    device: str
    device_name: str = ""
    event_type: str
    lookups: int
    first_hour: str
    last_seen: str


class DnsRawLookup(BaseModel):
    received_at: str
    event_type: str
    domain: str
    device: str
    device_name: str = ""
    source_host: Optional[str] = None


class DnsSearchResponse(BaseModel):
    tenant: str
    window_hours: int
    lookups: int
    lookups_source: Optional[LookupsSource] = None
    blocked: int
    top_domains: list[DnsDomainFull]
    first_seen: list[DnsFirstSeenFull]
    first_seen_count: int
    baseline_since: Optional[str] = None
    # Domain / device search — only when `domain` or `device` was given.
    rollup_days: Optional[int] = None
    sightings: list[DnsSighting] = []
    sightings_truncated: bool = False
    lookups_found: list[DnsRawLookup] = []
    lookups_found_truncated: bool = False
    note: Optional[str] = None


_EMPTY_DETAIL: dict[str, str] = {
    "no_tenants": "No active tenants are in your scope.",
    "no_telemetry": (
        "No DNS telemetry yet. It comes from buoys (Pi-hole and Suricata); "
        "a tenant without a reporting buoy has none."
    ),
    "unavailable": "The telemetry store couldn't be read just now — the next refresh retries.",
}


# ---------------------------------------------------------------------------
# Reading one tenant
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class _Raw:
    """One tenant's unmasked summary (internal)."""

    def __init__(self) -> None:
        self.lookups = 0
        self.lookups_source: Optional[str] = None
        self.by_type: dict[str, int] = {}
        self.blocked = 0
        self.fallback_rows = 0
        self.awaiting_move_rows = 0
        self.top: list[tuple[str, int, int, int, int]] = []
        self.first_seen: list[tuple[str, str, str, str]] = []
        self.first_seen_count = 0
        self.baseline_since: Optional[str] = None


_CANDIDATES = sorted(tiering.TELEMETRY_CANDIDATE_TYPES)


def _events_db_dns(slug: str, since_ts: str) -> tuple[int, int, int]:
    """(blocked, fallback_rows, awaiting_move_rows) in the window, from
    events.db: every candidate-type row classified by the ingest classifier
    on its stored payload (grouped in SQL — one classify() per distinct
    shape, not per row). blocked = Pi-hole lookups that are signals;
    telemetry-class rows (they belong in telemetry.db) are fallback_rows
    when the 036 sink stored them (arrival stamp: a store fault) and
    awaiting_move_rows when stored before the upgrade (no stamp: the
    one-off move has not run yet — not a fault)."""
    events_db = paths.client_db_path(slug, "events")
    if not events_db.exists():
        return 0, 0, 0
    marks = ",".join("?" * len(_CANDIDATES))
    blocked = fallback = awaiting = 0
    try:
        econn = connect(events_db, read_only=True)
        try:
            stamped = (f"({arrival.COLUMN} IS NOT NULL)" if arrival.has_column(econn)
                       else "0")
            for et, sev, *rest in econn.execute(
                f"SELECT event_type, severity, {tiering.STORED_FEATURES_SQL}, "
                f"       {stamped}, COUNT(*) "
                f"FROM events WHERE received_at >= ? AND event_type IN ({marks}) "
                "GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13",
                (since_ts, *_CANDIDATES),
            ):
                *features, has_stamp, n = rest
                c = tiering.classify_stored(et, sev, tuple(features))
                if c.is_telemetry:
                    if has_stamp:
                        fallback += int(n)
                    else:
                        awaiting += int(n)
                elif et == "pihole.query":
                    blocked += int(n)
        finally:
            econn.close()
    except sqlite3.OperationalError:
        return 0, 0, 0
    return blocked, fallback, awaiting


def _tenant_raw(
    slug: str, *, since: datetime, top_limit: int, fs_limit: int,
) -> Optional[_Raw]:
    """None when the tenant has no telemetry store; raises sqlite3.Error when
    it has one that can't be read."""
    db = paths.client_db_path(slug, "telemetry")
    if not db.exists():
        return None
    since_hour = since.strftime("%Y-%m-%dT%H:00:00Z")
    since_ts = _iso(since)
    out = _Raw()
    conn = connect(db, read_only=True)
    try:
        # RESTRICTED (B7, CSAM): a domain the tenant holds as restricted
        # evidence (Suricata logs the query NextDNS blocked) is never listed
        # — top, first seen — for any role; the totals stay counts.
        pred = restricted.Gate.for_tenant(slug).where(conn, "domain")
        keep = f" AND {pred}" if pred else ""
        for et, n in conn.execute(
            "SELECT event_type, SUM(count) FROM telemetry_hourly WHERE hour >= ? "
            "GROUP BY event_type", (since_hour,),
        ):
            out.by_type[et] = int(n or 0)
        # ONE sensor counts lookups: Pi-hole when it reported, else
        # Suricata's query records (see the module docstring).
        if out.by_type.get("pihole.query", 0) > 0:
            out.lookups_source, source_type = "pihole", "pihole.query"
        elif out.by_type.get("suricata.dns", 0) > 0:
            out.lookups_source, source_type = "suricata", "suricata.dns"
        else:
            source_type = "pihole.query"
        out.lookups = out.by_type.get(source_type, 0)
        out.top = [
            (r[0], int(r[1]), int(r[2]), int(r[3]), int(r[4]))
            for r in conn.execute(
                "SELECT domain, "
                "  SUM(CASE WHEN event_type = ? THEN count ELSE 0 END) AS lookups, "
                "  SUM(CASE WHEN event_type = 'pihole.query' THEN count ELSE 0 END), "
                "  SUM(CASE WHEN event_type = 'suricata.dns' THEN count ELSE 0 END), "
                "  COUNT(DISTINCT CASE WHEN event_type = ? THEN NULLIF(device, '') END) "
                "FROM telemetry_hourly "
                f"WHERE hour >= ? AND domain != '' AND event_type IN (?, ?){keep} "
                "GROUP BY domain HAVING lookups > 0 "
                "ORDER BY lookups DESC, domain LIMIT ?",
                (source_type, source_type, since_hour, *DNS_TYPES, top_limit),
            )
        ]
        out.first_seen = [
            (r[0], r[1], r[2], r[3]) for r in conn.execute(
                "SELECT domain, first_seen, first_device, first_event_type "
                f"FROM first_seen_domains WHERE first_seen >= ?{keep} "
                "ORDER BY first_seen DESC, domain LIMIT ?",
                (since_ts, fs_limit),
            )
        ]
        out.first_seen_count = int(conn.execute(
            f"SELECT COUNT(*) FROM first_seen_domains WHERE first_seen >= ?{keep}", (since_ts,),
        ).fetchone()[0])
        out.baseline_since = conn.execute(
            "SELECT MIN(first_seen) FROM first_seen_domains",
        ).fetchone()[0]
    finally:
        conn.close()
    out.blocked, out.fallback_rows, out.awaiting_move_rows = _events_db_dns(slug, since_ts)
    return out


def _baseline_building(baseline: Optional[str], now: datetime) -> bool:
    if not baseline:
        return True
    return baseline > _iso(now - timedelta(days=BASELINE_DAYS))


def _concrete_scope(operator_id: int) -> list[str]:
    scope = resolve_caller_scope(operator_id)
    if scope != ["*"]:
        return scope
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return [r[0] for r in reg.execute(
            "SELECT slug FROM clients WHERE status = 'active' ORDER BY slug",
        )]
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# GET /dashboard/dns-summary — masked
# ---------------------------------------------------------------------------

@router.get("/dns-summary", response_model=DnsSummaryResponse)
def get_dns_summary(
    response: Response,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
    hours: int = Query(24, ge=1, le=MAX_HOURS),
    top: int = Query(5, ge=1, le=20),
    first_seen_limit: int = Query(10, ge=1, le=50),
) -> DnsSummaryResponse:
    response.headers["Cache-Control"] = "no-store"
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    slugs = _concrete_scope(caller.operator_id)
    totals = DnsSummaryTotals()
    tenants: list[DnsTenantSummary] = []
    unreadable = 0
    if not slugs:
        return DnsSummaryResponse(
            window_hours=hours, tenants=[], totals=totals,
            empty_reason="no_tenants", empty_detail=_EMPTY_DETAIL["no_tenants"],
        )
    store_fallbacks = telemetry_fallbacks()
    for slug in slugs:
        try:
            raw = _tenant_raw(slug, since=since, top_limit=top, fs_limit=first_seen_limit)
        except sqlite3.Error:
            unreadable += 1
            continue
        refused = int((store_fallbacks.get(slug) or {}).get("count") or 0)
        if raw is None and refused:
            # No telemetry.db at all, yet writes were refused: show the fault.
            raw = _Raw()
            raw.blocked, raw.fallback_rows, raw.awaiting_move_rows = _events_db_dns(
                slug, _iso(since))
        if raw is None or (not raw.by_type and not raw.first_seen_count and not raw.blocked
                           and not raw.fallback_rows and not raw.awaiting_move_rows
                           and not refused):
            continue
        tenants.append(DnsTenantSummary(
            tenant=slug,
            lookups=raw.lookups,
            lookups_source=raw.lookups_source,
            by_type=raw.by_type,
            blocked=raw.blocked,
            fallback_rows=raw.fallback_rows,
            awaiting_move_rows=raw.awaiting_move_rows,
            recent_store_fallbacks=refused,
            store_fallback_window_hours=FAULT_WINDOW_HOURS,
            top_domains=[
                DnsDomainRow(
                    masked_domain=mask_indicator(d, "domain"),
                    lookups=n, pihole=ph, suricata=su, devices=dev,
                )
                for d, n, ph, su, dev in raw.top
            ],
            first_seen=[
                DnsFirstSeenRow(
                    masked_domain=mask_indicator(d, "domain"),
                    first_seen=fs, first_event_type=et,
                )
                for d, fs, _dev, et in raw.first_seen
            ],
            first_seen_count=raw.first_seen_count,
            baseline_since=raw.baseline_since,
            baseline_building=_baseline_building(raw.baseline_since, now),
        ))
        totals.lookups += raw.lookups
        totals.blocked += raw.blocked
        totals.first_seen += raw.first_seen_count
        totals.fallback_rows += raw.fallback_rows
        totals.awaiting_move_rows += raw.awaiting_move_rows
    tenants.sort(key=lambda t: (-t.lookups, t.tenant))
    empty: Optional[DnsEmptyReason] = None
    if not tenants:
        empty = "unavailable" if unreadable else "no_telemetry"
    return DnsSummaryResponse(
        window_hours=hours, tenants=tenants, totals=totals,
        unreadable_tenants=unreadable, empty_reason=empty,
        empty_detail=_EMPTY_DETAIL[empty] if empty else None,
    )


# ---------------------------------------------------------------------------
# POST /search/dns — unmasked, step-up, audited
# ---------------------------------------------------------------------------

def _search_matches(
    slug: str, *, domain: Optional[str], include_subdomains: bool, device: Optional[str],
    now: datetime, hours: int, rollup_days: int, limit: int,
) -> tuple[list[DnsSighting], bool, list[DnsRawLookup], bool]:
    """Answered lookups matching `domain` (and names under it) and/or
    `device`: per (domain, device, sensor) from the hourly roll-up over
    `rollup_days`, and the raw rows (7-day store) within `hours`. Blocked
    lookups are signals — they are in the events search, not here."""
    db = paths.client_db_path(slug, "telemetry")
    if not db.exists():
        return [], False, [], False
    where: list[str] = []
    params: list = []
    if domain:
        if include_subdomains:
            where.append("(domain = ? OR substr(domain, -?) = ?)")
            params += [domain, len(domain) + 1, "." + domain]
        else:
            where.append("domain = ?")
            params.append(domain)
    if device:
        # A device is found by its address OR the name Pi-hole v6 knows it
        # by (names compared without case).
        where.append("(device = ? OR (device_name != '' AND device_name = ? COLLATE NOCASE))")
        params += [device, device]
    since_hour = (now - timedelta(days=rollup_days)).strftime("%Y-%m-%dT%H:00:00Z")
    since_ts = _iso(now - timedelta(hours=hours))
    conn = connect(db, read_only=True)
    try:
        # RESTRICTED (B7, CSAM): who looked up a restricted domain is never
        # answered here, for any role (no rows — as for a name nobody
        # looked up); admins read it in the restricted incident.
        pred = restricted.Gate.for_tenant(slug).where(conn, "domain")
        cond = " AND ".join(where + ([pred] if pred else []))
        sight = conn.execute(
            "SELECT domain, device, event_type, SUM(count), MIN(hour), MAX(last_seen), "
            "       MAX(device_name) "
            f"FROM telemetry_hourly WHERE hour >= ? AND {cond} "
            "GROUP BY domain, device, event_type "
            "ORDER BY MAX(last_seen) DESC, domain, device LIMIT ?",
            (since_hour, *params, limit + 1),
        ).fetchall()
        raw = conn.execute(
            "SELECT received_at, event_type, domain, device, source_host, device_name "
            f"FROM telemetry_raw WHERE received_at >= ? AND {cond} "
            "ORDER BY received_at DESC, id DESC LIMIT ?",
            (since_ts, *params, limit + 1),
        ).fetchall()
    finally:
        conn.close()
    sightings = [
        DnsSighting(domain=r[0], device=r[1], event_type=r[2], lookups=int(r[3] or 0),
                    first_hour=r[4], last_seen=r[5], device_name=r[6] or "")
        for r in sight[:limit]
    ]
    found = [
        DnsRawLookup(received_at=r[0], event_type=r[1], domain=r[2], device=r[3],
                     source_host=r[4], device_name=r[5] or "")
        for r in raw[:limit]
    ]
    return sightings, len(sight) > limit, found, len(raw) > limit


def _sha16(text: Optional[str]) -> Optional[str]:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else None


@search_router.post("/dns", response_model=DnsSearchResponse)
def search_dns(
    body: DnsSearchRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(_analyst_step_up),
) -> DnsSearchResponse:
    """One tenant's DNS summary with full domains and first devices — and,
    given `domain` and/or `device`, WHO looked a name up / WHAT a device
    looked up (answered lookups: the hourly roll-up for `rollup_days`, raw
    rows for `hours`). Analyst+ (a viewer is a client user: 403 — checked
    before the step-up), the tenant must be a valid slug in the caller's
    scope (403 otherwise, '*' included), step-up required (401),
    one audit row per call (`search.dns_summary`; the searched name / device
    recorded as a hash, like the events search's query)."""
    from apps.octo.api.routers.auth import _audit_append

    if operator_max_tier(info.operator_id) < ROLE_TIER["analyst"]:   # defence in depth
        raise APIError("ISOLATION_VIOLATION", "this action requires at least the 'analyst' role")
    # A tenant that is not a valid slug — '*' above all, which IS in a
    # wildcard caller's scope list — is never a tenant: 403, before any
    # scope match or file path.
    try:
        paths.validate_slug(body.tenant)
    except paths.SlugError:
        raise APIError("ISOLATION_VIOLATION")
    scope = resolve_caller_scope(info.operator_id)
    # `resolve_caller_scope` lists ACTIVE tenants only; '*' reaches any
    # active tenant. Either way the slug is checked against the registry
    # before any file path is built from it.
    allowed = (body.tenant != "*" and body.tenant in scope) or (
        scope == ["*"] and _is_active(body.tenant))
    if not allowed:
        raise APIError("ISOLATION_VIOLATION")
    domain = tiering.normalize_domain(body.domain) if body.domain else None
    device = tiering.normalize_device(body.device) if body.device else None
    if body.domain and not domain:
        raise APIError("VALIDATION_FAILED", "domain is not a usable DNS name")
    if body.device and not device:
        raise APIError("VALIDATION_FAILED", "device is not a usable device name / address")
    now = datetime.now(timezone.utc)
    try:
        raw = _tenant_raw(
            body.tenant, since=now - timedelta(hours=body.hours),
            top_limit=body.limit, fs_limit=body.limit,
        )
        sightings, s_trunc, found, f_trunc = (
            _search_matches(
                body.tenant, domain=domain, include_subdomains=body.include_subdomains,
                device=device, now=now, hours=body.hours, rollup_days=body.rollup_days,
                limit=body.limit,
            )
            if (domain or device) else ([], False, [], False)
        )
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the tenant's telemetry store could not be read")
    raw = raw or _Raw()
    request_id = str(uuid.uuid4())
    _audit_append(
        "search.dns_summary",
        actor=f"operator:{info.operator_id}",
        target_id=info.id[:8],
        before=None,
        after={
            "tenants": [body.tenant],
            "hours": body.hours,
            "limit": body.limit,
            "rows_returned": len(raw.top) + len(raw.first_seen) + len(sightings) + len(found),
            "domains_sha256_16": hashlib.sha256(
                "\n".join(sorted({d for d, *_ in raw.top} | {d for d, *_ in raw.first_seen}))
                .encode()
            ).hexdigest()[:16],
            "has_domain_query": bool(domain),
            "domain_query_hash": _sha16(domain),
            "include_subdomains": body.include_subdomains if domain else None,
            "has_device_query": bool(device),
            "device_query_hash": _sha16(device),
            "rollup_days": body.rollup_days if (domain or device) else None,
            "ip": request.client.host if request.client else None,
        },
        reason="DNS telemetry search (unmasked domains)",
        request_id=request_id,
    )
    return DnsSearchResponse(
        tenant=body.tenant, window_hours=body.hours,
        lookups=raw.lookups, lookups_source=raw.lookups_source, blocked=raw.blocked,
        top_domains=[
            DnsDomainFull(domain=d, lookups=n, pihole=ph, suricata=su, devices=dev)
            for d, n, ph, su, dev in raw.top
        ],
        first_seen=[
            DnsFirstSeenFull(domain=d, first_seen=fs, first_device=dev, first_event_type=et)
            for d, fs, dev, et in raw.first_seen
        ],
        first_seen_count=raw.first_seen_count,
        baseline_since=raw.baseline_since,
        rollup_days=body.rollup_days if (domain or device) else None,
        sightings=sightings, sightings_truncated=s_trunc,
        lookups_found=found, lookups_found_truncated=f_trunc,
        note=(
            "Answered lookups only: raw rows are kept 7 days (older ones are in the "
            "cold archive — restore_telemetry_archive.py), hourly sightings 180 days. "
            "Blocked lookups are signals: search events (pihole.query)."
        ) if (domain or device) else None,
    )


def _is_active(slug: str) -> bool:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute("SELECT status FROM clients WHERE slug = ?", (slug,)).fetchone()
    finally:
        reg.close()
    return row is not None and row[0] == "active"
