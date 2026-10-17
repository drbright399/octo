"""GET /api/v1/dashboard/source-health — one view of every ingest source.

Three kinds of source, each with a status, a last-event age on Athena's
RECEIVE clock and a stale threshold:

  adapter       one configured integration instance (poller / webhook). The
                instance row's status, the poller's last successful vendor
                contact (`vendor_contact`, in memory) and the receive-clock
                last event (`instances.freshness`: memory, else the row's
                `last_event_at`).
  ingest_token  a live `service` client token — something pushing into
                /ingest/{slug}/… (the Wazuh shim). Freshness = the token's
                last ACCEPTED post (`freshness.token_last_post`; after a
                restart, the newest stored event under its source label
                from the token's own lifetime that no post in this process
                stored — see "Shared labels" below). Its last request (`auth.core`:
                memory, else `client_tokens.last_used_at`) is the contact
                time — set before the body is validated, so it counts
                refused posts too, and is never the freshness basis. Ingest
                requests newer than the last accepted post
                (`freshness.token_last_request`) mean the posts are being
                refused.
  buoy          a buoy's heartbeat row (the same health rollup as
                /dashboard/buoy-fleet).

Stale thresholds, per freshness basis:

  contact    pollers — 2 × poll interval + POLL_SLACK_SEC since the last
             successful poll. A quiet vendor is not stale; a stuck poller is.
  event      push sources — no accepted event for SERVICE_TOKEN_STALE_SEC
             (ingest tokens) or PUSH_ADAPTER_STALE_SEC (webhook-only
             adapters). Neither has a heartbeat (the shim posts only when
             Wazuh raises an alert), so the window is a day, not an
             overnight lull. An ingest token whose requests in this process
             are newer than its last accepted post by REFUSED_AFTER_SEC is
             degraded at once: it is posting, and being refused — for as
             long as refused requests keep coming (REFUSED_RECENT_SEC after
             the latest). After that, a token whose last TWO or more
             requests were all refused stays degraded ("its last N posts
             were refused") until one is accepted or the latest refusal is
             a stale window old — a quiet feed that alerts less than hourly
             and is refused every time never flips back to ok. A single
             isolated refusal decays: the token is judged by its last
             accepted post like any token, with a note that its latest
             post was refused, until one is accepted (or the refusal is a
             stale window old).
  heartbeat  buoys — 2 × their own heartbeat interval (the fleet's rule).

Shared labels. A stored event carries the posting token's LABEL
(`events.source` = "buoy:<label>"), not its id, and two live tokens of one
tenant may share a label — a rotation overlap. Only the restart fallback
reads stored events, and it takes none from before the token was created and
none that a post in this process stored (every post accepted here is in
memory, by token id). What is left may still be another token's; the card
then says so ("Shares its label with token #N …") instead of passing it off
as the token's own.

Plus one row per tenant: when that tenant last received an event from ANY
source ("alerts last received 4 min ago"). The age is information, never a
health verdict by itself — no alerts is good news. In the full view a
tenant is `degraded` when a source delivering into it is degraded or down.

Visibility (owner decision 2026-09-28 (b)): client users must not learn which
vendors the MSP runs.

  viewer     `view: "tenant"` — their own tenants' freshness rows only
             (`ok` / `none`). No sources, no vendor or instance names, no
             thresholds, nothing MSP-wide; a tenant still named with the
             auto-create placeholder ("<vendor> site …") is shown as
             VIEWER_PLACEHOLDER_NAME.
  analyst+   `view: "full"` — sources and tenant rows in their scope. `*` =
             every active tenant. A concrete scope sees the adapter instances
             that deliver into one of its tenants, and only its own tenants'
             tokens and buoys.

Read-only. No audit row (dashboard polling — like buoy-fleet).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api import buoy_health
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_viewer_plus,
)
from apps.octo.api.routers.dashboard import (
    _derive_fleet_row_health,
    _expand_scope_to_concrete_slugs,
    _normalize_services_read,
)
from apps.octo.api.routers.ingest import _TOKEN_CACHE_TTL_SEC, ingest_source_label
from apps.octo.auth import core as auth_core
from apps.octo.auth import sessions
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp
from apps.octo.instances import freshness

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

POLL_SLACK_SEC = 60
DEFAULT_POLL_INTERVAL_SEC = 60.0
SERVICE_TOKEN_STALE_SEC = 24 * 3600
PUSH_ADAPTER_STALE_SEC = 24 * 3600
# An accepted post is recorded milliseconds after its request: a request
# this much newer than the last accepted post was refused (422, …).
REFUSED_AFTER_SEC = 60
# "Posts are arriving but being refused" is a claim about NOW. A sender that
# is being refused keeps posting (each new alert is another refused request),
# so an hour — 1/24 of the stale window — without a further request means
# posts are no longer arriving: a one-off refusal (one malformed alert) or a
# sender gone quiet. From then on the stale window on the last ACCEPTED post
# judges the token (which still catches a drift that persists on a quiet
# feed), and the card notes that the latest post was refused. One refused
# post used to hold the token degraded until the next accepted one — for a
# quiet feed, indefinitely.
REFUSED_RECENT_SEC = 3600
# This many refusals in a row (none accepted in between) is a pattern, not a
# one-off: the token stays degraded while the latest is within the stale
# window, whatever the feed's cadence.
REFUSED_STREAK_MIN = 2
# After a restart, a token's last accepted post is looked up among stored
# events this far back (the source column is not indexed).
TOKEN_STORED_LOOKBACK_SEC = 2 * SERVICE_TOKEN_STALE_SEC
VIEWER_PLACEHOLDER_NAME = "Your organization"

SourceStatus = Literal["ok", "degraded", "down", "pending", "unknown"]
_STATUS_ORDER = {"down": 0, "degraded": 1, "pending": 2, "unknown": 3, "ok": 4}
_IMPAIRED: frozenset[str] = frozenset({"degraded", "down"})


class ProtectionProfileRow(BaseModel):
    """One DNS-filtering profile (NextDNS) of an adapter row: its protection
    as the poller last saw it. Only profiles of tenants in the caller's
    scope are listed."""
    profile_id: str
    name: str
    tenant_slug: Optional[str]
    state: Literal["new", "pending", "active", "lapsed"]
    since: Optional[str] = None
    queries_24h: Optional[int] = None
    missing: bool = False
    """NextDNS no longer shows the profile to the key (HTTP 404)."""
    problem: Optional[str] = None
    """The poller's current problem with this profile (operator text)."""


class ProtectionSummary(BaseModel):
    active: int = 0
    pending: int = 0
    lapsed: int = 0
    missing: int = 0
    problems: int = 0
    profiles: list[ProtectionProfileRow] = []


class SourceHealthRow(BaseModel):
    id: str                          # "adapter:<id>" | "token:<id>" | "buoy:<slug>"
    kind: Literal["adapter", "ingest_token", "buoy"]
    name: str                        # vendor display name / token label / hostname
    vendor: Optional[str]            # vendor slug, or a token's bound source type
    tenant_slug: Optional[str]       # None for an adapter (it serves many)
    status: SourceStatus
    stale: bool
    detail: Optional[str]            # platform-authored; never vendor text
    freshness_basis: Literal["contact", "event", "heartbeat"]
    stale_after_sec: int
    # Receive clock. A buoy's is what the buoy reports (its forwarder's
    # last relay); its receive-clock freshness is the heartbeat below. A
    # token's is its last ACCEPTED post.
    last_event_at: Optional[str]
    last_event_age_sec: Optional[int]
    # Last successful poll (adapter) / last heartbeat (buoy) / last request,
    # accepted or not (token).
    last_contact_at: Optional[str]
    last_contact_age_sec: Optional[int]
    # The vendor is rate limiting this integration right now (NextDNS): its
    # calls wait out a backoff. Shown as "throttled" — not a failure.
    throttled: bool = False
    # Per-profile DNS-filtering protection (NextDNS), scoped to the caller.
    protection: Optional[ProtectionSummary] = None


class TenantFreshnessRow(BaseModel):
    slug: str
    display_name: str
    last_event_at: Optional[str]
    last_event_age_sec: Optional[int]
    # none = nothing received yet; degraded (full view only) = a source
    # delivering into this tenant is degraded or down; ok = otherwise. The
    # age alone never makes a tenant degraded.
    state: Literal["ok", "degraded", "none"]


class SourceHealthResponse(BaseModel):
    view: Literal["full", "tenant"]
    generated_at: str
    sources: list[SourceHealthRow]
    tenants: list[TenantFreshnessRow]


# ---------------------------------------------------------------------------
# Adapter instances
# ---------------------------------------------------------------------------

def _poll_interval(record: Any, adapter_cls: Any) -> float:
    raw = record.instance_config.get("poll_interval_sec")
    try:
        value = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        value = None
    if value is None or value <= 0:
        value = float(getattr(adapter_cls, "default_poll_interval_sec", DEFAULT_POLL_INTERVAL_SEC))
    return value


def _adapter_row(record: Any, adapter_cls: Any, now: datetime) -> SourceHealthRow:
    from apps.octo.instances import vendor_contact

    name = getattr(adapter_cls, "vendor_display_name", None) or record.vendor_slug
    last_event = freshness.instance_last_event(record.id, record.last_event_at)
    event_age = freshness.age_seconds(last_event, now=now)
    polls = (
        adapter_cls is not None
        and getattr(adapter_cls, "delivery_mode", "poll") in ("poll", "hybrid")
        and bool(getattr(adapter_cls, "reports_vendor_contact", False))
    )
    contact = vendor_contact.snapshot(record.id)["last_ok_at"] if polls else None
    contact_age = freshness.age_seconds(contact, now=now)

    if polls:
        basis = "contact"
        stale_after = int(2 * _poll_interval(record, adapter_cls) + POLL_SLACK_SEC)
        basis_age = contact_age
    else:
        basis = "event"
        stale_after = PUSH_ADAPTER_STALE_SEC
        basis_age = event_age

    stale = basis_age is not None and basis_age > stale_after
    if record.status == "error":
        status, detail = "down", vendor_contact.analyst_summary(record.id)
    elif record.status == "starting":
        status, detail = "pending", "Starting."
    elif record.status != "running":
        status, detail = "unknown", None
    elif basis_age is None:
        status = "pending"
        detail = "Awaiting the first poll." if polls else "No event received yet."
    elif stale:
        status = "degraded"
        detail = (
            "No successful poll within the expected interval."
            if polls else "No event received within the expected interval."
        )
    else:
        status, detail = "ok", None
    return SourceHealthRow(
        id=f"adapter:{record.id}",
        kind="adapter",
        name=name,
        vendor=record.vendor_slug,
        tenant_slug=None,
        status=status,
        stale=stale,
        detail=detail,
        freshness_basis=basis,
        stale_after_sec=stale_after,
        last_event_at=last_event,
        last_event_age_sec=event_age,
        last_contact_at=contact,
        last_contact_age_sec=contact_age,
    )


def _adapter_rows(
    request: Request, scope: list[str], now: datetime,
) -> list[tuple[SourceHealthRow, set[str]]]:
    """Each instance in scope, with the tenant slugs it delivers into."""
    from apps.octo.instances import list_instances
    from apps.octo.instances.tenant_map import instance_tenant_slugs

    registry = getattr(request.app.state, "adapter_registry", None)
    manager = getattr(request.app.state, "instance_manager", None)
    allowed = None if scope == ["*"] else set(scope)
    rows: list[tuple[SourceHealthRow, set[str]]] = []
    for record in list_instances(include_disabled=False):
        served = instance_tenant_slugs(record)
        if allowed is not None and not (served & allowed):
            continue
        adapter_cls = registry.get_adapter_class(record.vendor_slug) if registry else None
        row = _adapter_row(record, adapter_cls, now)
        running = manager.running_adapter(record.id) if manager is not None else None
        lapsed_only = _with_protection(row, running, allowed)
        # Degraded ONLY because some sites lapsed: those sites' tenants are
        # the impaired ones, not every tenant the integration serves.
        rows.append((row, lapsed_only if lapsed_only is not None else served))
    return rows


def _with_protection(
    row: SourceHealthRow, adapter: Any, allowed: Optional[set[str]],
) -> Optional[set[str]]:
    """An adapter that reports per-profile protection (`protection()`,
    NextDNS): its throttle state and the in-scope profiles' states. A
    throttle is said as such — never as a failure — and a LAPSED profile
    (a site whose DNS filtering stopped reporting) makes the row degraded:
    something at a site needs a look, even though the integration works."""
    report = getattr(adapter, "protection", None) if adapter is not None else None
    if not callable(report):
        return None
    try:
        data = report(allowed)
    except Exception:  # noqa: BLE001 — health never fails for a snapshot
        return None
    fields = set(ProtectionProfileRow.model_fields)
    profiles = [
        ProtectionProfileRow(**{k: v for k, v in p.items() if k in fields})
        for p in data.get("profiles", [])
        if p.get("state") in ("new", "pending", "active", "lapsed") and p.get("profile_id")
    ]
    row.protection = ProtectionSummary(
        active=int(data.get("active", 0)), pending=int(data.get("pending", 0)),
        lapsed=int(data.get("lapsed", 0)), missing=int(data.get("missing", 0)),
        problems=int(data.get("problems", 0)), profiles=profiles,
    )
    notes: list[str] = []
    if data.get("throttled"):
        row.throttled = True
        wait = int(data.get("throttled_for_sec") or 0)
        notes.append(
            "Throttled by the vendor (rate limit) — calls wait"
            + (f" {wait} s" if wait else "") + "; not a failure, nothing is lost."
        )
    lapsed_only: Optional[set[str]] = None
    # A site needs a look: its filtering stopped reporting, NextDNS no longer
    # shows its profile to the key, or its profile's polling keeps failing.
    impaired = [p for p in profiles if p.state == "lapsed" or p.missing or p.problem]
    if row.protection.lapsed:
        lapsed = [p.name or p.profile_id for p in profiles if p.state == "lapsed"][:5]
        notes.append(
            f"DNS filtering stopped reporting at {row.protection.lapsed} site(s): "
            + ", ".join(lapsed) + "."
        )
    if row.protection.missing:
        gone = [p.name or p.profile_id for p in profiles if p.missing][:5]
        notes.append(
            f"NextDNS no longer shows {row.protection.missing} mapped profile(s) to the "
            "API key: " + ", ".join(gone) + "."
        )
    troubled = [p for p in profiles if p.problem and not p.missing]
    if troubled:
        notes.append(
            f"{len(troubled)} profile(s) need a look: "
            + "; ".join(f"{p.name or p.profile_id} — {p.problem}" for p in troubled[:3]) + "."
        )
    if impaired and row.status == "ok":
        row.status = "degraded"
        lapsed_only = {p.tenant_slug for p in impaired if p.tenant_slug}
    fleet = data.get("fleet_outage") if isinstance(data.get("fleet_outage"), dict) else None
    if fleet and fleet.get("sites"):
        notes.append(
            f"{int(fleet['sites'])} of {int(fleet.get('watched') or 0)} sites stopped reporting "
            "at the same time — one fleet-wide incident (check NextDNS status and the UniFi "
            "DNS template)."
        )
    gaps = data.get("analytics_gaps") or []
    if gaps:
        notes.append(
            f"NextDNS analytics returned no data for most sites in {len(gaps)} recent "
            "hour(s) — read as a NextDNS-side gap (at most 2 hours in a row; no lapse "
            "alerts for them)."
        )
    lag = int(data.get("rollup_lag_hours") or 0)
    if lag >= 2:
        notes.append(f"Hourly roll-ups are {lag} h behind (the polling does not fit the "
                     "rate limit; checks come less often).")
    if notes:
        row.detail = " ".join(part for part in (row.detail, *notes) if part)
    return lapsed_only


# ---------------------------------------------------------------------------
# Service tokens + buoys
# ---------------------------------------------------------------------------

def _iso_from_epoch(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return format_utc_ms(datetime.fromtimestamp(epoch, tz=timezone.utc))


def _epoch_from_iso(iso: str) -> Optional[float]:
    canonical = normalize_timestamp(iso, naive_is_utc=True)
    if not canonical:
        return None
    return datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc,
    ).timestamp()


def _latest(*values: Optional[str]) -> Optional[str]:
    canonical = [c for c in (normalize_timestamp(v, naive_is_utc=True) for v in values if v) if c]
    return max(canonical) if canonical else None


def _refused_request_age(token_id: int, now: datetime) -> Optional[int]:
    """Seconds since the token's latest ingest request in this process, when
    that request was refused — it came after the last accepted post here (or
    none has been accepted since start). None when the latest request was
    accepted, or there was none. Only in-process clocks are compared — the
    persisted ones are debounced or vendor-stamped."""
    requested = freshness.token_last_request(token_id)
    requested_epoch = _epoch_from_iso(requested) if requested else None
    if requested_epoch is None:
        return None
    posted = freshness.token_last_post(token_id)
    posted_epoch = _epoch_from_iso(posted) if posted else None
    if posted_epoch is not None and requested_epoch - posted_epoch <= REFUSED_AFTER_SEC:
        return None
    return freshness.age_seconds(requested, now=now)


def _label_holders(
    reg: sqlite3.Connection, slugs: list[str],
) -> dict[tuple[str, str], list[tuple[int, Optional[str]]]]:
    """(slug, label) → [(token id, revoked_at)] for every client token of
    these tenants — revoked ones too (one revoked inside a fallback window
    posted in it) and of any kind (a buoy token posting to /ingest stamps
    its events the same way)."""
    marks = ",".join("?" * len(slugs))
    out: dict[tuple[str, str], list[tuple[int, Optional[str]]]] = {}
    for r in reg.execute(
        f"SELECT id, slug, label, revoked_at FROM client_tokens WHERE slug IN ({marks})",
        slugs,
    ).fetchall():
        out.setdefault((r["slug"], r["label"]), []).append((int(r["id"]), r["revoked_at"]))
    return out


def _stored_post(
    token: sqlite3.Row, holders: list[tuple[int, Optional[str]]], now: datetime,
) -> tuple[Optional[str], list[int]]:
    """A token's last accepted post read back from its tenant's stored
    events, for when this process has none on record (a restart forgot it):
    the newest event under the token's source label (a vendor timestamp —
    never later than receipt, so it can only make the token look older),
    no older than the lookback or the token itself, and stored before any
    post in this process — every post accepted here is in memory by token
    id, and this token has none, so such a row is another token's. Returns
    it with the ids of the other tokens holding the same label that may
    have posted in that window: the event may be theirs."""
    not_before = format_utc_ms(now - timedelta(seconds=TOKEN_STORED_LOOKBACK_SEC))
    created = normalize_timestamp(token["created_at"], naive_is_utc=True)
    if created and created > not_before:
        not_before = created
    posted = freshness.newest_stored_event(
        token["slug"], source=ingest_source_label(token["label"], ""),
        not_before=not_before, before_id=freshness.first_posted_event_id(token["slug"]),
        before_telemetry_id=freshness.first_posted_telemetry_id(token["slug"]),
    )
    if posted is None:
        return None, []
    window_start = _epoch_from_iso(not_before) or 0.0
    others: list[int] = []
    for other_id, revoked_at in holders:
        if other_id == token["id"]:
            continue
        revoked = _epoch_from_iso(revoked_at) if revoked_at else None
        # A revoked token keeps posting until the ingest token cache drops it.
        if revoked is None or revoked + _TOKEN_CACHE_TTL_SEC >= window_start:
            others.append(other_id)
    return posted, sorted(others)


def _token_rows(reg: sqlite3.Connection, slugs: list[str], now: datetime) -> list[SourceHealthRow]:
    if not slugs:
        return []
    marks = ",".join("?" * len(slugs))
    try:
        found = reg.execute(
            f"SELECT t.id, t.slug, t.label, t.created_at, t.last_used_at, "
            f"  (SELECT s.source_type FROM source_instances s "
            f"    WHERE s.slug = t.slug AND s.source_instance_id = t.source_instance_id "
            f"      AND s.revoked_at IS NULL LIMIT 1) AS source_type "
            f"FROM client_tokens t WHERE t.kind = 'service' AND t.revoked_at IS NULL "
            f"AND t.slug IN ({marks}) ORDER BY t.slug, t.id",
            slugs,
        ).fetchall()
    except sqlite3.OperationalError:  # pre-004 registry: no source_instances
        found = reg.execute(
            f"SELECT id, slug, label, created_at, last_used_at, NULL AS source_type "
            f"FROM client_tokens WHERE kind = 'service' AND revoked_at IS NULL "
            f"AND slug IN ({marks}) ORDER BY slug, id",
            slugs,
        ).fetchall()
    holders = _label_holders(reg, slugs) if found else {}
    rows: list[SourceHealthRow] = []
    for t in found:
        token_id = t["id"]
        posted = freshness.token_last_post(token_id)
        shared_with: list[int] = []
        if posted is None and t["label"]:
            posted, shared_with = _stored_post(
                t, holders.get((t["slug"], t["label"]), []), now,
            )
        age = freshness.age_seconds(posted, now=now)
        contact = _latest(t["last_used_at"], _iso_from_epoch(auth_core.last_use_seen(token_id)))
        contact_age = freshness.age_seconds(contact, now=now)
        if age is None:
            # Never used: pending. Used, but no accepted post on record
            # (or none within the lookback): as good as stale.
            stale = contact is not None
        else:
            stale = age > SERVICE_TOKEN_STALE_SEC
        refused_age = _refused_request_age(token_id, now)
        refused_streak = (freshness.token_requests_since_post(token_id)
                          if refused_age is not None else 0)
        notes: list[str] = []
        if refused_age is not None and refused_age <= REFUSED_RECENT_SEC:
            status, detail = "degraded", "Posts are arriving but being refused."
        elif (refused_age is not None and refused_age <= SERVICE_TOKEN_STALE_SEC
              and refused_streak >= REFUSED_STREAK_MIN):
            status = "degraded"
            detail = f"Its last {refused_streak} posts were refused; none accepted since."
        else:
            if refused_age is not None and refused_age <= SERVICE_TOKEN_STALE_SEC:
                notes.append("Its latest post was refused; none accepted since.")
            if age is None and contact is None:
                status, detail = "pending", "No data received yet."
            elif stale:
                status, detail = "degraded", "No data received within the expected interval."
            else:
                status, detail = "ok", None
        if shared_with:
            notes.append(
                "Shares its label with "
                + ", ".join(f"token #{other}" for other in shared_with)
                + " — this freshness may be the other token's."
            )
        detail = " ".join(part for part in (detail, *notes) if part) or None
        rows.append(SourceHealthRow(
            id=f"token:{token_id}",
            kind="ingest_token",
            name=t["label"],
            vendor=t["source_type"],
            tenant_slug=t["slug"],
            status=status,
            stale=stale,
            detail=detail,
            freshness_basis="event",
            stale_after_sec=SERVICE_TOKEN_STALE_SEC,
            last_event_at=posted,
            last_event_age_sec=age,
            last_contact_at=contact,
            last_contact_age_sec=contact_age,
        ))
    return rows


_BUOY_STATUS: dict[str, SourceStatus] = {
    "green": "ok", "yellow": "degraded", "stale": "degraded", "red": "down",
}
_BUOY_DETAIL: dict[str, str] = {
    "yellow": "A monitored service the buoy should be running is not active.",
    "stale": "Heartbeat overdue.",
    "red": "Heartbeat long overdue, or the buoy's tunnel is down.",
}


def _buoy_rows(reg: sqlite3.Connection, slugs: list[str], now: datetime) -> list[SourceHealthRow]:
    if not slugs:
        return []
    marks = ",".join("?" * len(slugs))
    try:
        found = reg.execute(
            f"SELECT slug, hostname, last_heartbeat_at, interval_sec, services_json, "
            f"last_event_at FROM buoys WHERE slug IN ({marks}) ORDER BY slug",
            slugs,
        ).fetchall()
    except sqlite3.OperationalError:  # pre-018 registry
        return []
    rows: list[SourceHealthRow] = []
    for b in found:
        interval = int(b["interval_sec"] or 60)
        heartbeat = normalize_timestamp(b["last_heartbeat_at"], naive_is_utc=True) or None
        hb_age = freshness.age_seconds(heartbeat, now=now)
        try:
            services = _normalize_services_read(json.loads(b["services_json"] or "{}"))
        except (json.JSONDecodeError, TypeError):
            services = {}
        health = _derive_fleet_row_health(
            services, hb_age if hb_age is not None else 10 ** 9, interval,
        )
        retired = buoy_health.retired_units(services)
        disabled = buoy_health.disabled_units(services)
        detail = _BUOY_DETAIL.get(health)
        if retired:
            # Information, not a fault: said beside whatever the verdict is.
            note = f"Retired (disabled on purpose): {', '.join(retired)}."
            detail = f"{detail} {note}" if detail else note
        if disabled:
            # A fault (the buoy is degraded): switched off on the buoy but
            # not retired by an operator — a security tool disabled?
            note = (f"Disabled on the buoy but not retired: {', '.join(disabled)} — "
                    "if on purpose, add it to OCTO_BUOY_RETIRED_UNITS.")
            detail = f"{detail} {note}" if detail else note
        reported = normalize_timestamp(b["last_event_at"], naive_is_utc=True) or None
        rows.append(SourceHealthRow(
            id=f"buoy:{b['slug']}",
            kind="buoy",
            name=b["hostname"],
            vendor=None,
            tenant_slug=b["slug"],
            status=_BUOY_STATUS.get(health, "unknown"),
            stale=hb_age is None or hb_age > 2 * interval,
            detail=detail,
            freshness_basis="heartbeat",
            stale_after_sec=2 * interval,
            last_event_at=reported,
            last_event_age_sec=freshness.age_seconds(reported, now=now),
            last_contact_at=heartbeat,
            last_contact_age_sec=hb_age,
        ))
    return rows


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

def _impaired_tenants(
    adapters: list[tuple[SourceHealthRow, set[str]]], others: list[SourceHealthRow],
) -> set[str]:
    """Tenants that a degraded or down source delivers into."""
    out: set[str] = set()
    for row, served in adapters:
        if row.status in _IMPAIRED:
            out |= served
    for row in others:
        if row.status in _IMPAIRED and row.tenant_slug:
            out.add(row.tenant_slug)
    return out


def _placeholder_named(reg: sqlite3.Connection, names: dict[str, str]) -> set[str]:
    """Auto-created tenants still carrying their placeholder name, which
    names the vendor that created them ("<vendor> site 1a2b3c4d")."""
    from apps.octo.instances.tenant_autocreate import placeholder_parts

    return {slug for slug, parts in placeholder_parts(reg, names).items() if "name" in parts}


def _tenant_rows(
    reg: sqlite3.Connection, slugs: list[str], now: datetime,
    *, impaired: Optional[set[str]],
) -> list[TenantFreshnessRow]:
    """`impaired` = tenants a failing source feeds (full view). None = the
    client (viewer) view: freshness only, and no vendor-derived name."""
    if not slugs:
        return []
    marks = ",".join("?" * len(slugs))
    names = {
        r["slug"]: r["display_name"]
        for r in reg.execute(
            f"SELECT slug, display_name FROM clients WHERE slug IN ({marks})", slugs,
        ).fetchall()
    }
    neutral = _placeholder_named(reg, names) if impaired is None else set()
    rows: list[TenantFreshnessRow] = []
    for slug in slugs:
        last = freshness.tenant_last_event(slug)
        age = freshness.age_seconds(last, now=now)
        if impaired is not None and slug in impaired:
            state = "degraded"
        elif age is None:
            state = "none"
        else:
            state = "ok"
        rows.append(TenantFreshnessRow(
            slug=slug,
            display_name=(
                VIEWER_PLACEHOLDER_NAME if slug in neutral else (names.get(slug) or slug)
            ),
            last_event_at=last,
            last_event_age_sec=age,
            state=state,
        ))
    order = {"degraded": 0, "none": 1, "ok": 2}
    rows.sort(key=lambda r: (order[r.state], r.display_name.lower(), r.slug))
    return rows


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.get("/source-health", response_model=SourceHealthResponse)
def get_source_health(
    request: Request,
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> SourceHealthResponse:
    scope = resolve_caller_scope(info.operator_id)
    slugs = sorted(_expand_scope_to_concrete_slugs(scope))
    full = operator_max_tier(info.operator_id) >= ROLE_TIER["analyst"]
    now = datetime.now(timezone.utc)

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        sources: list[SourceHealthRow] = []
        if full:
            adapters = _adapter_rows(request, scope, now)
            others = _token_rows(reg, slugs, now) + _buoy_rows(reg, slugs, now)
            sources = [row for row, _served in adapters] + others
            tenants = _tenant_rows(
                reg, slugs, now, impaired=_impaired_tenants(adapters, others),
            )
        else:
            tenants = _tenant_rows(reg, slugs, now, impaired=None)
    finally:
        reg.close()
    sources.sort(key=lambda s: (_STATUS_ORDER[s.status], s.name.lower(), s.id))
    return SourceHealthResponse(
        view="full" if full else "tenant",
        generated_at=format_utc_ms(now),
        sources=sources,
        tenants=tenants,
    )
