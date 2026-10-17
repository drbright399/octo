"""GET /api/v1/dashboard/throughput — fleet-wide events-per-bucket sparkline.

Aggregates `events.db` row counts across every client slug the caller's
session has visibility into, bucketed by time. Used by V3's "Event
throughput" widget to render the actual live ingest rate instead of mock
data.

The widget renders 24 buckets by default (24 hours, 1-hour each). Buckets
are returned oldest-first so the SVG sparkline reads left-to-right as
time → now.

Visibility model: a session's scope_slugs is the union of `scope_slugs`
across every role row for the operator. `*` means all-tenants (returns
data for every client dir under `data_root/clients/`). Otherwise filtered
to the named slugs.

Read-only against per-client events.db files. Each connection is opened
with `read_only=True` so concurrent writers (G.1 ingest, adapters) are
not blocked.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api import buoy_health
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason
from apps.octo.api.role_gates import (
    resolve_caller_scope,
    session_analyst_plus,
    session_super_admin,
    session_viewer_plus,
)
from apps.octo.auth import audit, sessions
from apps.octo.db import connect, transaction
from apps.octo.threat import restricted


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class OctoLocation(BaseModel):
    """OCTO hub location for the Fleet map's central marker.

    Reads from the `bundle_config.octo_location` row (migration 022).
    Falls back to a placeholder if the row is missing (e.g. a fresh
    deploy before init has been re-run). The frontend uses this in
    place of the hardcoded `DEFAULT_OCTO` const in fleet.tsx.
    """
    slug: str
    display: str
    city: str
    msp: str
    lat: float
    lng: float


@router.get("/octo-location", response_model=OctoLocation)
def get_octo_location(
    _info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> OctoLocation:
    """Return the configured OCTO hub location.

    Operators (analyst+) only: client users (viewers) never see
    coordinates — and a super_admin may set the hub to an exact geocoded
    street address (`PUT`). No client screen reads it (the Fleet page skips
    it for a client user; the buoys mode is operator-only).
    """
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        data = _read_octo_row(reg)
    finally:
        reg.close()
    if data is None:
        # Pre-022 bundle or a bundle where the seed row was never
        # written. Return the same placeholder the frontend used to
        # hardcode so the map renders something.
        return _PLACEHOLDER
    fields = OctoLocation.model_fields
    try:
        return OctoLocation(**{**_PLACEHOLDER.model_dump(),
                               **{k: v for k, v in data.items() if k in fields}})
    except ValueError:
        return _PLACEHOLDER


# Pre-022 bundle or a missing seed row: the placeholder the frontend used to
# hardcode, so the map renders something (a super_admin moves it).
_PLACEHOLDER = OctoLocation(slug="primary", display="Primary", city="Kansas City",
                            msp="", lat=39.099724, lng=-94.578331)


class OctoLocationIn(BaseModel):
    """The host pin (super_admin): where the map's OCTO hub is drawn. msp
    and the slug are kept unless given (msp only)."""
    model_config = ConfigDict(extra="forbid")
    lat: float = Field(ge=-90.0, le=90.0)
    lng: float = Field(ge=-180.0, le=180.0)
    display: Optional[str] = Field(default=None, max_length=60)
    city: Optional[str] = Field(default=None, max_length=120)
    msp: Optional[str] = Field(default=None, max_length=120)
    reason: AuditReason


_OCTO_KEY = "octo_location"
_OCTO_DESCRIPTION = ("Lat/lng + display name of this bundle's OCTO hub. Drives the hub icon "
                     "position on the Fleet map.")


def _read_octo_row(reg: sqlite3.Connection) -> Optional[dict[str, Any]]:
    try:
        row = reg.execute("SELECT value_json FROM bundle_config WHERE key = ?",
                          (_OCTO_KEY,)).fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    try:
        data = json.loads(row[0])
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@router.put("/octo-location", response_model=OctoLocation)
def put_octo_location(
    body: OctoLocationIn,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> OctoLocation:
    """Move the host pin (the OCTO hub on the Fleet map) — a bundle-level
    setting, so super_admin only. Validated like a site pin (±90 / ±180,
    never (0, 0); labels cleaned), audited BEFORE the write (global audit,
    `octo_location_set`, before / after, the reason). Creates the
    bundle_config row when it is missing."""
    from apps.octo.fleet.locations import clean_label, valid_pair

    pair = valid_pair(body.lat, body.lng)
    if pair is None:
        raise APIError("VALIDATION_FAILED", "latitude must be within ±90 and longitude within "
                                            "±180, and (0, 0) is not a location")
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        before = _read_octo_row(reg)
    finally:
        reg.close()
    current = before or _PLACEHOLDER.model_dump()
    after = {
        "slug": clean_label(current.get("slug")) or _PLACEHOLDER.slug,
        "display": clean_label(body.display) or clean_label(current.get("display"))
        or _PLACEHOLDER.display,
        "city": clean_label(body.city) if body.city is not None
        else clean_label(current.get("city")),
        "msp": clean_label(body.msp) if body.msp is not None
        else clean_label(current.get("msp")),
        "lat": round(pair[0], 6), "lng": round(pair[1], 6),
    }
    def _audit(action: str, before_state: Any, after_state: Any, reason: str) -> None:
        g = connect(paths.global_audit_db_path())
        try:
            audit.append(g, audit.AuditEntry(
                actor=str(info.operator_id), actor_kind="human", action=action,
                target_kind="bundle_config", target_id=_OCTO_KEY, client_slug="global",
                before_state=before_state, after_state=after_state, reason=reason,
                request_id=str(uuid.uuid4())))
        finally:
            g.close()

    _audit("octo_location_set", before, after, body.reason)
    try:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    "INSERT INTO bundle_config (key, value_json, description, updated_at, "
                    "updated_by) VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?) "
                    "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, "
                    "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                    (_OCTO_KEY, json.dumps(after, sort_keys=True), _OCTO_DESCRIPTION,
                     info.operator_id))
        finally:
            reg.close()
    except sqlite3.Error as exc:
        # The change audited above did not happen (the error class only).
        _audit("octo_location_set_failed", before, {"error": type(exc).__name__},
               f"host location not saved: {type(exc).__name__}; nothing was written")
        raise
    return OctoLocation(**after)


class ThroughputPoint(BaseModel):
    t: str  # ISO-8601 UTC, bucket start
    v: int  # event count in that bucket


class ThroughputResponse(BaseModel):
    points: list[ThroughputPoint]
    window_minutes: int
    window_hours: int  # back-compat (= window_minutes // 60); 0 if sub-hour
    bucket_minutes: int
    scope_slugs: list[str]  # what the caller's session was filtered to


def _resolve_scope_slugs(operator_id: int) -> list[str]:
    """`*` → ['*']; otherwise the caller's concrete slugs, ACTIVE tenants
    only — the shared rule in `role_gates.resolve_caller_scope` (kept under
    this name for the routers that import it from here)."""
    return resolve_caller_scope(operator_id)


def _expand_scope_to_concrete_slugs(scope: list[str]) -> list[str]:
    """Translate ['*'] → every active client slug. Concrete slugs pass through."""
    if scope == ["*"]:
        reg = connect(paths.registry_db_path(), read_only=True)
        reg.row_factory = sqlite3.Row
        try:
            rows = reg.execute(
                "SELECT slug FROM clients WHERE status = 'active'",
            ).fetchall()
        finally:
            reg.close()
        return [r["slug"] for r in rows]
    return scope


def _bucket_for(key: object, now_floor: datetime, bucket_seconds: int) -> str | None:
    """The grid bucket (start, 'YYYY-MM-DDTHH:MM:SSZ') a minute/hour key
    falls in; None for an unreadable key."""
    if not isinstance(key, str):
        return None
    try:
        t = datetime.strptime(key, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    k = int((t - now_floor).total_seconds() // bucket_seconds)
    start = now_floor + timedelta(seconds=k * bucket_seconds)
    return start.isoformat().replace("+00:00", "Z")


@router.get("/throughput", response_model=ThroughputResponse)
def get_throughput(
    window_minutes: int | None = Query(default=None, ge=5, le=10080),
    window_hours: int | None = Query(default=None, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=1, le=120),
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> ThroughputResponse:
    # Caller can pass either window_minutes (preferred, supports
    # sub-hour granularity) or window_hours (kept for back-compat with
    # the original wire-up). Default = 24h if neither is set.
    if window_minutes is None and window_hours is None:
        effective_minutes = 1440
    elif window_minutes is not None:
        effective_minutes = window_minutes
    else:
        effective_minutes = (window_hours or 24) * 60

    scope = _resolve_scope_slugs(info.operator_id)
    concrete = _expand_scope_to_concrete_slugs(scope)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    bucket_count = effective_minutes // bucket_minutes
    bucket_seconds = bucket_minutes * 60

    # Anchor the bucket grid on "now's bucket" and walk backward so the
    # most recent bucket is always the rightmost point in the sparkline.
    # Floor `now` to its bucket boundary.
    now_floor = now.replace(second=0, microsecond=0)
    if bucket_minutes >= 60:
        now_floor = now_floor.replace(minute=0)
    elif bucket_minutes > 1:
        now_floor = now_floor.replace(
            minute=(now_floor.minute // bucket_minutes) * bucket_minutes
        )

    # Initialize all buckets to 0 — important so a flat-line at zero shows
    # up rather than a sparse irregular series. Bucket key = start-of-bucket
    # UTC ISO with 'Z' suffix.
    buckets: dict[str, int] = {}
    earliest_bucket: datetime = now_floor
    for i in range(bucket_count):
        bucket_start = now_floor - timedelta(
            seconds=(bucket_count - 1 - i) * bucket_seconds
        )
        if bucket_start < earliest_bucket:
            earliest_bucket = bucket_start
        buckets[bucket_start.isoformat().replace("+00:00", "Z")] = 0

    window_start_iso = earliest_bucket.isoformat().replace("+00:00", "Z")
    # SQLite strftime format matches received_at column (ISO with 'Z' suffix).
    #
    # Counted per HOUR (bucket sizes that are whole hours) or per MINUTE
    # (everything else) in SQL, then floored onto the bucket grid here — the
    # grid is anchored on "now's bucket", so a 5- or 15-minute bucket takes
    # every minute inside it (keying rows on the minute and keeping only the
    # keys that happened to equal a bucket start used to drop most of them).
    #
    # Telemetry (migration 036: answered DNS, TLS / HTTP / flow metadata) is
    # ingest like any other and counts here too: from its hourly roll-up for
    # whole-hour buckets, from the raw rows (kept 7 days — the widest window
    # this route allows) otherwise.
    hourly = bucket_minutes % 60 == 0
    key_expr = (
        "strftime('%Y-%m-%dT%H:00:00Z', received_at)" if hourly
        else "strftime('%Y-%m-%dT%H:%M:00Z', received_at)"
    )
    # Athena's own incident records (`athena.incident`, Tier Black) are not
    # ingest: left out (a client user's chart must not show when an
    # incident changed before they may see it).
    queries: list[tuple[str, str, str, str]] = [
        ("events", "events",
         f"SELECT {key_expr} AS k, COUNT(*) FROM events WHERE received_at >= ? "
         "AND source <> 'athena' GROUP BY k",
         window_start_iso),
        ("telemetry", "telemetry_hourly",
         "SELECT hour AS k, SUM(count) FROM telemetry_hourly WHERE hour >= ? GROUP BY k",
         window_start_iso[:13] + ":00:00Z")
        if hourly else
        ("telemetry", "telemetry_raw",
         f"SELECT {key_expr} AS k, COUNT(*) FROM telemetry_raw "
         "WHERE received_at >= ? GROUP BY k",
         window_start_iso),
    ]

    for slug in concrete:
        for db_name, _table, sql, since in queries:
            db_path = paths.client_db_path(slug, db_name)
            if not db_path.exists():
                continue
            try:
                conn = connect(db_path, read_only=True)
                try:
                    rows = conn.execute(sql, (since,)).fetchall()
                finally:
                    conn.close()
            except sqlite3.OperationalError:
                # DB busy/locked (or a store without the table yet) — skip this
                # contribution rather than 500 the whole dashboard. Surfaces as
                # a slight count dip; next poll will recover.
                continue
            for key, cnt in rows:
                bucket_key = _bucket_for(key, now_floor, bucket_seconds)
                if bucket_key in buckets:
                    buckets[bucket_key] += int(cnt or 0)

    points = [
        ThroughputPoint(t=k, v=v)
        for k, v in sorted(buckets.items())
    ]
    return ThroughputResponse(
        points=points,
        window_minutes=effective_minutes,
        window_hours=effective_minutes // 60,
        bucket_minutes=bucket_minutes,
        scope_slugs=scope,
    )


# ---------------------------------------------------------------------------
# GET /dashboard/integrations — analyst-visible integration health snapshot.
#
# The full /api/v1/integrations surface is admin+-gated because it carries
# config detail. The Source-Health widget on the analyst dashboard only
# needs name + slug + category + a coarse "is it up?" reading, so this
# endpoint exposes that subset without the config bits. Analyst+ tier.
# ---------------------------------------------------------------------------

from fastapi import Request

from apps.octo.api.role_gates import session_at_least
from apps.octo.api.vendor_links import (
    VendorDeviceRefOut,
    VendorLinkOut,
    VendorLinkResolver,
)
from apps.octo.ingest.presentation import clean_text

session_analyst_plus = session_at_least("analyst")

# The feed row's own bound on a stored summary (the drawer shows the same
# text whole; /search carries the payload).
_ROW_SUMMARY_MAX = 240


class IntegrationHealthRow(BaseModel):
    slug: str
    name: str
    category: str
    # Coarse health bucket for the StatusPanel widget. Maps from the
    # InstanceRecord.status:
    #   running          → 'ok'
    #   error            → 'down' (could not start, OR it is running and its
    #                       poller's most recent vendor contact failed)
    #   disabled         → 'unknown' (purposefully unconfigured, not failed)
    #   anything else    → 'pending'
    health: str
    detail: str | None


class IntegrationHealthResponse(BaseModel):
    items: list[IntegrationHealthRow]


def _status_to_health(status: str) -> str:
    if status == "running":
        return "ok"
    if status == "error":
        return "down"
    if status == "disabled":
        return "unknown"
    return "pending"


@router.get("/integrations", response_model=IntegrationHealthResponse)
def get_integration_health(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
) -> IntegrationHealthResponse:
    """Compact integration health for the analyst dashboard. No config
    surface, no secret material — just the 'is it up?' read.

    Analyst+ only: which vendors the MSP runs is not for client users
    (viewers — owner decision 2026-09-28 (b)). A caller with a concrete
    scope sees the instances that deliver into one of their tenants."""
    from apps.octo.instances import list_instances, vendor_contact
    from apps.octo.instances.tenant_map import instance_tenant_slugs

    registry = getattr(request.app.state, "adapter_registry", None)
    scope = _resolve_scope_slugs(caller.operator_id)
    allowed = None if scope == ["*"] else set(scope)
    rows = list_instances(include_disabled=False)
    items: list[IntegrationHealthRow] = []
    for rec in rows:
        if allowed is not None and not (instance_tenant_slugs(rec) & allowed):
            continue
        adapter_cls = (
            registry.get_adapter_class(rec.vendor_slug) if registry else None
        )
        name = (
            adapter_cls.vendor_display_name if adapter_cls else rec.vendor_slug
        )
        category = (
            getattr(adapter_cls, "vendor_category", "other")
            if adapter_cls else "other"
        )
        items.append(IntegrationHealthRow(
            slug=rec.vendor_slug,
            name=name,
            category=category,
            health=_status_to_health(rec.status),
            # An error row's status_detail is admin text (it can quote the
            # vendor): analysts get a fixed per-failure sentence instead.
            detail=(
                vendor_contact.analyst_summary(rec.id)
                if rec.status == "error" else rec.status_detail
            ),
        ))
    # Sort: down first (so eyes hit problems immediately), then pending,
    # then ok, then unknown. Alphabetical within tier.
    health_order = {"down": 0, "pending": 1, "ok": 2, "unknown": 3}
    items.sort(key=lambda x: (health_order.get(x.health, 99), x.name.lower()))
    return IntegrationHealthResponse(items=items)


# ---------------------------------------------------------------------------
# GET /dashboard/recent-events — analyst-friendly alert feed.
#
# Same per-tenant events.db source as /search, but no step-up auth and no
# RAW payload. Returns just enough for the DefaultAlertFeed row strip —
# severity, source, a headline, a bounded detail, device/site, when. The
# operator clicks through to /search (which is gated) for the payload.
#
# Why a separate endpoint: the /search surface guards the cross-tenant
# pool with re-auth because event payloads carry IOCs + PII. This endpoint is
# per-tenant-scoped and analyst+ only.
#
# Headline/detail: an adapter that offers `present_event(payload)` (Datto)
# gets its rows presented from the STORED payload at read time — the adapter's
# own bounded, sanitised excerpt (≤ 1000 chars), never the payload itself.
# Read-time because (a) rows stored before presentation existed have an empty
# summary and an event_type of "alert", and must be readable without a data
# migration, and (b) a presentation fix then applies to every row at once.
# Cost: ≤ `limit` small JSON parses per tenant per request.
# ---------------------------------------------------------------------------


class RecentEventRow(BaseModel):
    event_id: int
    client_slug: str
    severity: str
    status: str
    """`open` until a ticket with source_event_id=this exists in the
    tenant's tickets.db, then `acknowledged`. v1 returns 'open' for
    every row; the ticket-join refinement lands in W4."""
    source: str
    title: str
    """The headline for a presented row ("Event log · Security 4625 — An
    account failed to log on"); the event_type for every other source."""
    summary: str
    """The longer text under the title. May contain newlines; render as text."""
    occurred_at: str
    device: str | None = None
    site: str | None = None
    """The vendor's own site/organisation name, when the payload carries it."""
    vendor_links: list[VendorLinkOut] = []
    """"Open in <vendor>" targets (the alert). Always empty for a Viewer."""
    vendor_device_ref: VendorDeviceRefOut | None = None
    """"Open device in <vendor>": a REFERENCE the console posts to
    /dashboard/vendor-device-link on click — the device page's address has to
    be looked up at the vendor, which never happens per row. Null when no
    lookup could succeed, and for a Viewer."""


class RecentEventsResponse(BaseModel):
    items: list[RecentEventRow]
    scope_slugs: list[str]


_VALID_DASHBOARD_SEVERITIES = ("info", "low", "medium", "high", "critical")
_DEFAULT_MIN_SEVERITIES = ("medium", "high", "critical")


def _presenters(registry: object) -> dict[str, object]:
    """vendor slug → the adapter class's `present_event`, where offered."""
    if registry is None:
        return {}
    out: dict[str, object] = {}
    for cls in registry.list_adapter_classes():
        present = getattr(cls, "present_event", None)
        if callable(present):
            out[cls.vendor_slug] = present
    return out


def _suffixers(registry: object) -> dict[str, object]:
    """vendor slug → the adapter class's `presentation_suffixes`, where
    offered: extra text per stored row from the adapter's own local state
    (NextDNS: "Seen N times this hour" — the coalescing count; never a
    vendor call)."""
    if registry is None:
        return {}
    out: dict[str, object] = {}
    for cls in registry.list_adapter_classes():
        suffixes = getattr(cls, "presentation_suffixes", None)
        if callable(suffixes):
            out[cls.vendor_slug] = suffixes
    return out


def _apply_suffixes(
    slug: str, pending: dict[str, list[tuple["RecentEventRow", object]]],
    suffixers: dict[str, object],
) -> None:
    for source, items in pending.items():
        try:
            extra = suffixers[source](slug, [
                (row.event_id, _parsed_payload(text) or {}) for row, text in items
            ])
        except Exception:  # noqa: BLE001 — a count never blanks the feed
            continue
        for row, _text in items:
            line = extra.get(row.event_id) if isinstance(extra, dict) else None
            if isinstance(line, str) and line:
                row.summary = f"{row.summary}\n{clean_text(line, 240)}".strip()


def _parsed_payload(text: object) -> dict | None:
    if not isinstance(text, str):
        return None
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _recent_event_row(
    slug: str,
    r: sqlite3.Row,
    presenters: dict[str, object],
    resolver: VendorLinkResolver,
) -> RecentEventRow:
    source = r["source"] or ""
    # Use event_type as the row title — short label ("auth.failure",
    # "ids.brute_force") that lines up with how operators describe alerts.
    title = r["event_type"] or "event"
    # The stored summary is an adapter's own text (vendor-derived, cleaned
    # only if that adapter did so): the same hygiene a presenter's output gets,
    # for every source alike.
    summary = clean_text(r["summary"], _ROW_SUMMARY_MAX)
    device = r["source_host"] or None
    site: str | None = None
    links: list[VendorLinkOut] = []
    device_ref: VendorDeviceRefOut | None = None

    payload = _parsed_payload(r["payload"])
    if payload is not None:
        present = presenters.get(source)
        if present is not None:
            try:
                shown = present(payload)
            except Exception:  # noqa: BLE001 — one odd payload never blanks the feed
                shown = None
            # A presenter that recognised nothing must not replace a summary
            # the row already has with its bare label.
            if shown is not None and shown.headline and not (shown.fallback and summary):
                title, summary = shown.headline, shown.detail
                device = shown.device or device
                site = shown.site
        links = resolver.links(source=source, client_slug=slug, payload=payload)
        device_ref = resolver.device_ref(
            source=source, client_slug=slug, event_id=r["id"], payload=payload,
        )
    if summary == title:
        summary = ""
    return RecentEventRow(
        event_id=r["id"],
        client_slug=slug,
        severity=r["severity"],
        status="open",
        source=source,
        title=title,
        summary=summary,
        occurred_at=r["received_at"],
        device=device,
        site=site,
        vendor_links=links,
        vendor_device_ref=device_ref,
    )


@router.get("/recent-events", response_model=RecentEventsResponse)
def get_recent_events(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
    limit: int = Query(20, ge=1, le=100),
    min_severity: str = Query(
        "medium",
        description="Lower bound: info|low|medium|high|critical. Default 'medium' "
                    "filters out noise — set 'info' to see everything.",
    ),
) -> RecentEventsResponse:
    if min_severity not in _VALID_DASHBOARD_SEVERITIES:
        from apps.octo.api.errors import APIError
        raise APIError("VALIDATION_FAILED",
                       f"unknown min_severity {min_severity!r}")
    # Map min_severity to the set of allowed values (info < low < medium < high < critical).
    sev_order = list(_VALID_DASHBOARD_SEVERITIES)
    idx = sev_order.index(min_severity)
    allowed = sev_order[idx:]

    scope = _resolve_scope_slugs(caller.operator_id)
    slugs = _expand_scope_to_concrete_slugs(scope)
    if not slugs:
        return RecentEventsResponse(items=[], scope_slugs=[])

    registry = getattr(request.app.state, "adapter_registry", None)
    resolver = VendorLinkResolver(request, operator_id=caller.operator_id)
    presenters = _presenters(registry)
    suffixers = _suffixers(registry)
    # Payloads are only read for sources that present or link from them.
    payload_sources = sorted(set(presenters) | resolver.linkable_sources())
    payload_expr = (
        f"CASE WHEN source IN ({','.join(['?'] * len(payload_sources))}) "
        "THEN payload END"
        if payload_sources else "NULL"
    )

    placeholders = ",".join(["?"] * len(allowed))
    rows: list[RecentEventRow] = []
    for slug in slugs:
        edb = paths.client_dir(slug) / "events.db"
        if not edb.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                # RESTRICTED (B7, CSAM): a row naming a restricted domain is
                # never in the feed (any role).
                pred = restricted.Gate.for_tenant(slug).where(
                    conn, "events.summary", "events.payload", "events.source_host")
                keep = f" AND {pred}" if pred else ""
                # Per-tenant limit = full limit (we slice + sort across
                # tenants in memory below). For typical bundles this is
                # bounded; if a tenant has 50k events/hour this still
                # only fetches `limit` per cycle which is fine.
                cur = conn.execute(
                    "SELECT id, received_at, event_type, severity, source, "
                    f"       source_host, summary, {payload_expr} AS payload "
                    "  FROM events "
                    f" WHERE severity IN ({placeholders}){keep} "
                    " ORDER BY received_at DESC LIMIT ?",
                    (*payload_sources, *allowed, limit),
                )
                extra: dict[str, list[tuple[RecentEventRow, object]]] = {}
                for r in cur.fetchall():
                    row = _recent_event_row(slug, r, presenters, resolver)
                    rows.append(row)
                    if r["source"] in suffixers:
                        extra.setdefault(r["source"], []).append((row, r["payload"]))
                _apply_suffixes(slug, extra, suffixers)
            finally:
                conn.close()
        except sqlite3.OperationalError:
            # Tenant DB busy or pre-migration; skip rather than 500.
            continue

    rows.sort(key=lambda x: x.occurred_at, reverse=True)
    return RecentEventsResponse(
        items=rows[:limit],
        scope_slugs=slugs,
    )


# ---------------------------------------------------------------------------
# GET /dashboard/devices-attention — ranked devices with one-line reasons.
#
# "Device" = events.source_host (no first-class hosts table yet). Across
# the operator's scope, for each non-null source_host we count recent
# high+critical events and roll up the top reason. Output is sorted by
# severity weight desc (critical=4, high=3, medium=2) then count desc.
#
# Returns just enough for the dashboard widget: tenant + host + a coarse
# severity badge + one-line reason. Detail lives behind /search.
# ---------------------------------------------------------------------------

class DeviceAttentionRow(BaseModel):
    tenant: str
    host: str
    severity: str
    """Highest severity observed in the lookback window."""
    reason: str
    """One-line, sanitized — no IOC / no payload. e.g.
    '5 critical events · auth.brute_force, ids.malware'."""
    event_count: int
    vendor_device_ref: VendorDeviceRefOut | None = None
    """The widget's "open" target. Rows key on a HOST NAME, which is not a
    vendor id: the reference names the most recent event for this host+tenant
    from a source that can link, whose stored payload carries the vendor's
    device id. The console posts it to /dashboard/vendor-device-link on click.
    Null when there is no such event — and for a Viewer."""


class DevicesAttentionResponse(BaseModel):
    items: list[DeviceAttentionRow]
    scope_slugs: list[str]


def _severity_weight(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0)


@router.get("/devices-attention", response_model=DevicesAttentionResponse)
def get_devices_attention(
    request: Request,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
    limit: int = Query(20, ge=1, le=100),
    lookback_hours: int = Query(
        24, ge=1, le=168,
        description="How far back to scan events when ranking hosts.",
    ),
) -> DevicesAttentionResponse:
    """Rank source_hosts by recent high+critical event volume across the
    operator's scope. Returns top `limit` rows."""
    scope = _resolve_scope_slugs(caller.operator_id)
    slugs = _expand_scope_to_concrete_slugs(scope)
    if not slugs:
        return DevicesAttentionResponse(items=[], scope_slugs=[])

    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    ).strftime("%Y-%m-%dT%H:%M:%fZ")

    resolver = VendorLinkResolver(request, operator_id=caller.operator_id)
    linkable = resolver.linkable_sources()

    # (tenant, host) → {top_severity, top_event_type set, count, link_event}
    agg: dict[tuple[str, str], dict[str, object]] = {}
    for slug in slugs:
        edb = paths.client_dir(slug) / "events.db"
        if not edb.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.execute(
                    "SELECT id, received_at, source, source_host, severity, "
                    "       event_type "
                    "  FROM events "
                    " WHERE received_at >= ? "
                    "   AND severity IN ('medium', 'high', 'critical') "
                    "   AND source_host IS NOT NULL "
                    "   AND source_host != '' ",
                    (cutoff,),
                )
                for r in cur.fetchall():
                    key = (slug, r["source_host"])
                    bucket = agg.setdefault(key, {
                        "top_severity": "info",
                        "event_types": set(),
                        "count": 0,
                    })
                    if _severity_weight(r["severity"]) > _severity_weight(
                        bucket["top_severity"],
                    ):
                        bucket["top_severity"] = r["severity"]
                    bucket["event_types"].add(r["event_type"] or "event")
                    bucket["count"] = int(bucket["count"]) + 1
                    # The host's MOST RECENT event from a source that can
                    # link: its stored payload names the vendor's device.
                    if r["source"] in linkable:
                        newest = (r["received_at"] or "", r["id"], r["source"])
                        if newest > bucket.get("link_event", ("", 0, "")):
                            bucket["link_event"] = newest
            finally:
                conn.close()
        except sqlite3.OperationalError:
            continue

    rows: list[DeviceAttentionRow] = []
    for (tenant, host), v in agg.items():
        count = int(v["count"])
        sev = str(v["top_severity"])
        # Pick at most 3 event_types so the reason stays one line.
        types_preview = ", ".join(sorted(list(v["event_types"]))[:3])
        if len(v["event_types"]) > 3:
            types_preview += "…"
        reason = f"{count} {sev} event{'s' if count != 1 else ''} · {types_preview}"
        rows.append(DeviceAttentionRow(
            tenant=tenant, host=host, severity=sev,
            reason=reason, event_count=count,
        ))

    rows.sort(key=lambda r: (
        -_severity_weight(r.severity),
        -r.event_count,
        r.tenant, r.host,
    ))
    rows = rows[:limit]
    # One payload read per SHOWN device (≤ limit), only where a link is
    # possible. Local reads only — the vendor is contacted on click.
    for row in rows:
        link_event = agg[(row.tenant, row.host)].get("link_event")
        if link_event:
            _, event_id, source = link_event
            row.vendor_device_ref = resolver.device_ref(
                source=source, client_slug=row.tenant, event_id=event_id,
                payload=_event_payload(row.tenant, event_id),
            )
    return DevicesAttentionResponse(items=rows, scope_slugs=slugs)


def _event_payload(slug: str, event_id: int) -> dict | None:
    edb = paths.client_dir(slug) / "events.db"
    try:
        conn = sqlite3.connect(f"file:{edb}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT payload FROM events WHERE id = ?", (event_id,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return None
    return _parsed_payload(row[0]) if row else None


# ---------------------------------------------------------------------------
# GET /dashboard/ti-pulse — recently sighted indicators across the scope.
#
# The threat-intel pulse widget. Reads each in-scope tenant's indicators.db
# (written by the ingest sink when an ingested event carries an IOC) and
# returns the most recently SIGHTED rows, newest first, merged across tenants.
#
# Values are MASKED here (owner decision 2026-09-28): an IOC value is tenant
# data, readable in full only through the step-up-gated /search/indicators.
# Each row carries a `search_ref` ("<tenant>:<indicator id>") the console
# hands to that search — it names a row, never a value, and resolves only
# for a stepped-up caller whose scope includes the tenant. The stored
# `context` (the sighting event's summary, which usually quotes the value)
# is never read.
#
# Analyst+, read-only, no audit row (a dashboard poll), Cache-Control
# no-store. Bounded: at most `limit` rows per tenant (last_seen is indexed)
# and `limit` overall. A tenant whose store can't be read is skipped and
# COUNTED (`unreadable_tenants`), so a partial list never reads as complete.
# ---------------------------------------------------------------------------

from typing import Literal

from fastapi import Response

from apps.octo.api.indicator_mask import mask_indicator

TiPulseEmptyReason = Literal["no_tenants", "no_indicators", "none_recent", "unavailable"]

# The Wazuh and UniFi adapters are the only ones that put an IOC (the alert's
# IP) on the events they emit; Datto RMM and RocketCyber alerts carry none, so
# a bundle running only those records no indicators at all.
_TI_PULSE_EMPTY_DETAIL: dict[str, str] = {
    "no_tenants": "No active tenants are in your scope.",
    "no_indicators": (
        "No indicators recorded yet. One is recorded when an ingested event "
        "carries an IOC — today only Wazuh- and UniFi-sourced events carry "
        "one (an IP); Datto RMM and RocketCyber alerts don't."
    ),
    "unavailable": (
        "The indicator store couldn't be read just now — the next refresh "
        "retries."
    ),
}


class TiPulseItem(BaseModel):
    tenant: str
    type: str
    """indicators.db type (ip, ipv6, domain, url, md5, sha1, sha256, email,
    cidr, cve, other)."""
    masked_value: str
    """Display-safe form (203.0.x.x, ex*****.test, first 8 of a hash…). The
    raw value is never in this response."""
    severity: str
    """Severity of the event that first recorded it (low…critical)."""
    first_seen: str
    last_seen: str
    count: int
    """Times sighted (indicators.hits)."""
    source_kind: Literal["integration", "internal", "msp_pool"]
    """Provenance. Every indicators.db writer today is the ingest sink, so
    every row is `integration` (sighted in an event from one of the MSP's
    integrations); `internal` (agent-derived) and `msp_pool` (cross-MSP
    pool) are reserved and have no writer yet."""
    search_ref: str
    """"<tenant>:<indicator id>" — pass to POST /search/indicators as
    `tenants=[tenant]`, `indicator_ids=[id]` (step-up required) for the
    full value."""


class TiPulseResponse(BaseModel):
    items: list[TiPulseItem]
    pool_status: Literal["not_running", "running"]
    """The cross-MSP sanitized pool. Its extractor is never invoked on this
    build (a pre-LIVE hold), so this is always `not_running` and the pulse
    shows only the caller's own tenants' sightings."""
    empty_reason: TiPulseEmptyReason | None = None
    """Why `items` is empty (null when it isn't)."""
    empty_detail: str | None = None
    """One sentence for the widget, matching `empty_reason`."""
    unreadable_tenants: int = 0
    """In-scope tenants whose indicator store couldn't be read this time
    (busy, pre-migration, damaged). Non-zero with items = a PARTIAL list."""
    lookback_days: int


def _pulse_cutoff(lookback_days: int) -> str:
    # indicators.db stamps millisecond-precision UTC with a 'Z'.
    t = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _pulse_rows_for_tenant(
    slug: str, cutoff: str, limit: int,
) -> list[sqlite3.Row] | None:
    """Up to `limit` live rows sighted since `cutoff`, newest first. [] when
    the tenant has no indicators.db; None when it could not be read (busy,
    pre-migration or damaged — one tenant never 500s the dashboard)."""
    db_path = paths.client_db_path(slug, "indicators")
    if not db_path.exists():
        return []
    try:
        conn = connect(db_path, read_only=True)
        try:
            # RESTRICTED (B7, CSAM): never in the pulse, not even masked.
            pred = restricted.Gate.for_tenant(slug).where(conn, "value", "context")
            keep = f" AND {pred}" if pred else ""
            return conn.execute(
                "SELECT id, value, type, severity, first_seen, last_seen, hits "
                "  FROM indicators "
                f" WHERE deleted_at IS NULL AND last_seen >= ?{keep} "
                " ORDER BY last_seen DESC, id DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return None


def _tenant_has_indicators(slug: str) -> bool:
    db_path = paths.client_db_path(slug, "indicators")
    if not db_path.exists():
        return False
    try:
        conn = connect(db_path, read_only=True)
        try:
            return conn.execute(
                "SELECT 1 FROM indicators WHERE deleted_at IS NULL LIMIT 1",
            ).fetchone() is not None
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False


@router.get("/ti-pulse", response_model=TiPulseResponse)
def get_ti_pulse(
    response: Response,
    caller: sessions.SessionInfo = Depends(session_analyst_plus),
    limit: int = Query(20, ge=1, le=50),
    lookback_days: int = Query(7, ge=1, le=30),
) -> TiPulseResponse:
    response.headers["Cache-Control"] = "no-store"
    slugs = _expand_scope_to_concrete_slugs(_resolve_scope_slugs(caller.operator_id))
    # Tenants whose store couldn't be read: reported, never silently dropped.
    unreadable = 0

    def _empty(reason: TiPulseEmptyReason) -> TiPulseResponse:
        if reason == "none_recent":
            detail = (
                f"No indicator sighted in the last {lookback_days} "
                f"day{'s' if lookback_days != 1 else ''}. Older ones are in "
                "Search → Indicators."
            )
        else:
            detail = _TI_PULSE_EMPTY_DETAIL[reason]
        return TiPulseResponse(
            items=[], pool_status="not_running", empty_reason=reason,
            empty_detail=detail, unreadable_tenants=unreadable,
            lookback_days=lookback_days,
        )

    if not slugs:
        return _empty("no_tenants")

    cutoff = _pulse_cutoff(lookback_days)
    merged: list[tuple[str, sqlite3.Row]] = []
    for slug in slugs:
        rows = _pulse_rows_for_tenant(slug, cutoff, limit)
        if rows is None:
            unreadable += 1
            continue
        merged.extend((slug, r) for r in rows)

    if not merged:
        if unreadable:
            return _empty("unavailable")
        if any(_tenant_has_indicators(s) for s in slugs):
            return _empty("none_recent")
        return _empty("no_indicators")

    merged.sort(key=lambda sr: (sr[1]["last_seen"] or "", sr[0], sr[1]["id"]),
                reverse=True)
    items = [
        TiPulseItem(
            tenant=slug,
            type=r["type"],
            masked_value=mask_indicator(r["value"], r["type"]),
            severity=r["severity"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            count=r["hits"],
            source_kind="integration",
            search_ref=f"{slug}:{r['id']}",
        )
        for slug, r in merged[:limit]
    ]
    return TiPulseResponse(
        items=items, pool_status="not_running", unreadable_tenants=unreadable,
        lookback_days=lookback_days,
    )


# ---------------------------------------------------------------------------
# GET /dashboard/host-metrics — container/host CPU + memory feed.
#
# Universal function: returns the container's runtime CPU + memory
# utilization as a time series. Whatever host the container is running
# on is what gets reported. In a live OCTO bundle this is the deployed
# container's metrics; in dev it's whatever box the developer is on.
#
# Same {t, v} bucket shape as /dashboard/throughput so the dashboard
# Oscilloscope component drives them identically.
# ---------------------------------------------------------------------------


class HostMetricPoint(BaseModel):
    t: str
    v: float


class HostMetricsResponse(BaseModel):
    cpu_points: list[HostMetricPoint]
    mem_points: list[HostMetricPoint]
    window_minutes: int
    bucket_minutes: int


@router.get("/host-metrics", response_model=HostMetricsResponse)
def get_host_metrics(
    request: Request,
    info: sessions.SessionInfo = Depends(session_viewer_plus),
    window_minutes: int = Query(60, ge=1, le=1440),
    bucket_minutes: int = Query(1, ge=1, le=60),
) -> HostMetricsResponse:
    """Operator-visible. No tenant scoping — these are container-wide
    metrics, not per-customer telemetry. Same gate as /throughput so
    any signed-in operator can read it."""
    sampler = getattr(request.app.state, "host_metrics_sampler", None)
    if sampler is None:
        # Sampler not wired (test app, or boot in progress). Return
        # an empty series rather than 500-ing.
        return HostMetricsResponse(
            cpu_points=[], mem_points=[],
            window_minutes=window_minutes,
            bucket_minutes=bucket_minutes,
        )
    cpu, mem = sampler.get_window(
        window_minutes=window_minutes,
        bucket_minutes=bucket_minutes,
    )
    return HostMetricsResponse(
        cpu_points=[
            HostMetricPoint(t=s.t, v=s.cpu_pct) for s in cpu
        ],
        mem_points=[
            HostMetricPoint(t=s.t, v=s.mem_pct) for s in mem
        ],
        window_minutes=window_minutes,
        bucket_minutes=bucket_minutes,
    )


# ---------------------------------------------------------------------------
# GET /dashboard/buoy-fleet — current state of every buoy in scope.
#
# Reads the `buoys` table (migration 018) and returns one row per buoy
# the caller has visibility into. Each row carries:
#   - identity (slug, hostname, uptime)
#   - load + memory + disk
#   - services map (raw, UI renders chips)
#   - last_event_at (when buoy-forwarder last successfully relayed)
#   - derived `health` and `staleness_sec` (computed server-side so the
#     UI doesn't have to know the interval thresholds).
#
# Visibility:
#   - super_admin (scope=['*']) → every row
#   - admin / analyst → rows where slug ∈ scope_slugs
#   - viewer → rows where slug ∈ scope_slugs (typically a single slug)
#
# Read-only against registry.db. No audit row — fleet status is not
# tenant data, and we'd flood audit if every dashboard poll wrote one.
# ---------------------------------------------------------------------------

class BuoyFleetRow(BaseModel):
    slug: str
    hostname: str
    last_heartbeat_at: str
    staleness_sec: int           # now - last_heartbeat
    health: str                  # 'green' | 'yellow' | 'red' | 'unknown' | 'stale'
    uptime_sec: int
    interval_sec: int
    boot_time: str | None
    load_1: float | None
    load_5: float | None
    load_15: float | None
    mem_used_mb: int | None
    mem_total_mb: int | None
    disk_used_pct: int | None
    services: dict[str, dict[str, str | None]]
    """Per-unit service info. New shape (2026-05-19 contract extension):
    each value is `{ state, enabled?, version?, stat?, last_activity? }`
    (`enabled` = `systemctl is-enabled`, heartbeat daemons from v0.11).
    Legacy rows in registry.db (flat `{ unit: state_string }`) are
    normalized by `_normalize_services_read` before they reach the
    response."""
    retired_services: list[str] = []
    """Units disabled on purpose and not running — shown grey, never a
    fault (`apps.octo.api.buoy_health`)."""
    last_event_at: str | None
    lat: float | None
    lng: float | None
    """Geo coords for the Fleet map view (migration 021). Buoys without
    LAT/LNG configured in heartbeat.env come back as null and don't
    render on the map (frontend filters them out)."""


class BuoyFleetResponse(BaseModel):
    buoys: list[BuoyFleetRow]
    scope_slugs: list[str]


def _service_state(entry: object) -> str:
    """Extract the `state` string from a service entry, normalizing
    both legacy flat-string entries and new dict-of-dicts entries."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        s = entry.get("state")
        return s if isinstance(s, str) else "unknown"
    return "unknown"


def _normalize_services_read(raw: object) -> dict[str, dict[str, str | None]]:
    """Read-side normalizer: convert whatever's in services_json to the
    new dict-of-dicts shape with state/version/stat/last_activity keys.
    Legacy flat-string rows get wrapped so the response is uniform."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str | None]] = {}
    for unit, v in raw.items():
        entry: dict[str, str | None] = {
            "state": None, "enabled": None, "version": None, "stat": None,
            "last_activity": None,
        }
        if isinstance(v, str):
            entry["state"] = v
        elif isinstance(v, dict):
            for k in ("state", "enabled", "version", "stat", "last_activity"):
                val = v.get(k)
                entry[k] = val if isinstance(val, str) else None
            if entry["state"] is None:
                entry["state"] = "unknown"
        else:
            entry["state"] = "unknown"
        out[unit] = entry
    return out


def _derive_fleet_row_health(
    services: dict[str, dict[str, str | None]],
    staleness_sec: int, interval_sec: int,
) -> str:
    """Same rollup as the heartbeat publisher, plus a 'stale' tier when
    no heartbeat has landed in 2× interval. Above 5× interval = 'red'.

    Reads `state` from each service entry (works against the
    normalized dict-of-dicts shape)."""
    if staleness_sec > 5 * interval_sec:
        return "red"
    if staleness_sec > 2 * interval_sec:
        return "stale"
    # A unit disabled on purpose is retired, not a fault (buoy_health).
    return buoy_health.rollup(services)


@router.get("/buoy-fleet", response_model=BuoyFleetResponse)
def get_buoy_fleet(
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> BuoyFleetResponse:
    scope = _resolve_scope_slugs(info.operator_id)
    is_super = scope == ["*"]

    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        if is_super:
            rows = reg.execute(
                "SELECT slug, hostname, last_heartbeat_at, boot_time, "
                "  uptime_sec, interval_sec, load_1, load_5, load_15, "
                "  mem_used_mb, mem_total_mb, disk_used_pct, "
                "  services_json, last_event_at, lat, lng "
                "FROM buoys ORDER BY slug"
            ).fetchall()
        elif not scope:
            return BuoyFleetResponse(buoys=[], scope_slugs=[])
        else:
            placeholders = ",".join("?" * len(scope))
            rows = reg.execute(
                f"SELECT slug, hostname, last_heartbeat_at, boot_time, "
                f"  uptime_sec, interval_sec, load_1, load_5, load_15, "
                f"  mem_used_mb, mem_total_mb, disk_used_pct, "
                f"  services_json, last_event_at, lat, lng "
                f"FROM buoys WHERE slug IN ({placeholders}) ORDER BY slug",
                tuple(scope),
            ).fetchall()
    finally:
        reg.close()

    now = datetime.now(timezone.utc)
    out: list[BuoyFleetRow] = []
    for r in rows:
        try:
            last = r["last_heartbeat_at"]
            last_dt = datetime.fromisoformat(
                last[:-1] + "+00:00" if last.endswith("Z") else last
            )
            staleness = max(0, int((now - last_dt).total_seconds()))
        except (ValueError, TypeError):
            staleness = 10 ** 9  # effectively "very stale"

        try:
            raw_services = json.loads(r["services_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            raw_services = {}
        services = _normalize_services_read(raw_services)

        out.append(BuoyFleetRow(
            slug=r["slug"],
            hostname=r["hostname"],
            last_heartbeat_at=r["last_heartbeat_at"],
            staleness_sec=staleness,
            health=_derive_fleet_row_health(
                services, staleness, r["interval_sec"] or 60
            ),
            uptime_sec=r["uptime_sec"],
            interval_sec=r["interval_sec"] or 60,
            boot_time=r["boot_time"],
            load_1=r["load_1"], load_5=r["load_5"], load_15=r["load_15"],
            mem_used_mb=r["mem_used_mb"],
            mem_total_mb=r["mem_total_mb"],
            disk_used_pct=r["disk_used_pct"],
            services=services,
            retired_services=buoy_health.retired_units(services),
            last_event_at=r["last_event_at"],
            lat=r["lat"],
            lng=r["lng"],
        ))

    return BuoyFleetResponse(buoys=out, scope_slugs=scope)
