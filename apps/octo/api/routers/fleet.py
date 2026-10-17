"""Fleet v2 — the site-centric fleet.

  GET    /api/v1/fleet/sites                  viewer+  (scoped; polled read,
                                                       hourly audit roll-up)
  GET    /api/v1/fleet/sites/{key}/alerts     analyst+ (scoped; the drawer's
                                                       recent alerts: "needs
                                                       attention" — ?include=
                                                       acknowledged adds the
                                                       acknowledged / expected
                                                       ones, greyed — with the
                                                       operator enrichment)
  GET    /api/v1/fleet/sites/{key}/location   admin+   (scoped; the drawer's
                                                       site location editor)
  PUT    /api/v1/fleet/sites/{key}/location   admin+, audited BEFORE the write
  DELETE /api/v1/fleet/sites/{key}/location   admin+, audited BEFORE the write
  POST   /api/v1/fleet/geocode                admin+   (an address → up to 3
                                                       matches; nothing stored)
  GET    /api/v1/fleet/geocoder               admin+   (is the lookup on? — the
                                                       host pin's editor)
  GET    /api/v1/fleet/locations/{slug}       admin+   (scoped; the tenant
                                                       settings' fallback editor)
  PUT    /api/v1/fleet/locations/{slug}       admin+, audited BEFORE the write
  DELETE /api/v1/fleet/locations/{slug}       admin+, audited BEFORE the write

Built from what the pollers already store (`apps.octo.fleet`): no vendor call
on a page load, one cached model per data root (30 s), built under a time
bound (a model past it says `partial`).

ROLE MATRIX
  analyst / admin / super_admin  `view: "operator"` — every site of the
      tenants in their scope (`*` = every active tenant) WITH its location,
      vendor names, deep links (UniFi, NextDNS, Datto), the UniFi ids, the
      open ISP-outage incidents (a concrete scope sees only its own tenants
      among the members, and counts over those members only) and, for `*`,
      the count of unmapped UniFi sites and a suppressed fleet-wide wave.
  viewer (a client user)  `view: "client"` — ONLY their own tenants' sites:
      the four layers' states and counts with NEUTRAL wording (never a vendor
      name: "DNS protection lapsed", not "NextDNS lapsed"), no location (site
      locations are for operator roles only — 2026-09-30 plan), no deep link,
      no vendor id, no console name, no ISP, no other tenant, no ISP-outage
      incident; a tenant still carrying its auto-create placeholder name is
      "Your organization"; a site is named by its OWN name only — never the
      mapping label (console + address text) nor the console's name: the
      client's name for its only site, else "Site N". The alerts drawer is
      analyst+.

LOCATION. Two hand-set overrides, both admin+, scoped, audited (the
before/after values and the reason) BEFORE the registry row is written:
  * a SITE's own location (042; `site_location_set` / `site_location_clear`)
    from the Fleet drawer — typed, pasted from a map, or an address the
    operator looked up (POST /geocode: the US Census geocoder, the typed
    address only, nothing stored; `OCTO_GEOCODER=off` turns it off) — the
    saved pair is LOCKED;
  * a TENANT's fallback location (041; `tenant_location_set` / `_clear`) from
    Settings → Tenants.
Precedence at read time (`locations.resolve`): the site's override, else the
UniFi console location (a single-site console, or a multi-site console that
is the tenant's alone), else the tenant fallback, else no pin. No IP
geolocation. Coordinates are for operator roles only.

A site override may also come from an Autotask address an operator
CONFIRMED (`/api/v1/proposals`, 043): operators see its `provenance` ("from
Autotask, confirmed by …"), and the site's editor lists the open proposals
for that site ("Autotask suggests …") and the client's not yet assigned to
a site. Never a client user.

ALERT VERDICTS + ENRICHMENT (v0.17.2, 046). The drawer's list is "needs
attention" by default: an alert an analyst acknowledged (until a new
occurrence re-surfaces it) or that an expected condition matches is left
out (`hidden` says how many) and, with `?include=acknowledged`, shown with
who / when / the rule. Each item says whether it may be marked expected
(`can_expect`, else `expected_refusal`) and carries the operator
enrichment (`apps.octo.enrich.alerts`: UniFi IPS direction / remote owner /
PTR / labels / the local device's name / "N× in 24 h"; Datto one-line
summary / host / open-resolved / repeats, full text behind "details") —
computed from local stores and the enrichment cache only (a remote without
a cached answer is queued for the background worker: `pending`). The
routes that write the verdicts are `/api/v1/alerts/...` (alert_verdicts).

THREAT (Tier Black slice 1, 044). Every site carries a fifth layer, `threat`
(first): its incidents. Operators get `incident` on each site (the worst open
one: id, tier, acknowledged by whom, contained, age, rule, device), the open
Reds / Blacks as `threats` (the banner and strip — scoped like the ISP
outages), the detection sources Athena is blind to (`blind`, FR2) and the
WAN coverage count (`coverage.sites_without_backup`). A client user gets ONLY
what `threat.client_view` allows: an incident they may see (acknowledged, or
60 min old) as {ref, tier, status_neutral, opened_at, actions} — never a
device, an indicator, a rule, an acknowledgement or a pulse; incidents not
visible yet and operator-only reasons (WAN2 not configured, shadow rules)
are taken out of their layers AND their verdict.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    resolve_caller_scope,
    session_admin_plus,
    session_analyst_plus,
    session_viewer_plus,
)
from apps.octo.auth import audit, sessions
from apps.octo.auth.audit_rollup import PolledReadAudit
from apps.octo.db import connect
from apps.octo.fleet import build, geocode, locations, sources
from apps.octo.fleet import state as fs
from apps.octo.ingest.presentation import clean_text
from apps.octo.threat import client_view, restricted
from apps.octo.threat import registry as threat_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fleet", tags=["fleet"])

VIEWER_PLACEHOLDER_NAME = "Your organization"
ALERT_WINDOW = timedelta(hours=24)
ALERT_SCAN_ROWS = 2_000
ALERT_LIMIT = 15
_ALERT_SEVERITIES = ("medium", "high", "critical")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ReasonOut(BaseModel):
    state: str
    text: str
    layer: str = ""


class LayerOut(BaseModel):
    name: str
    present: bool
    state: str
    scope: str = "site"
    reasons: list[ReasonOut] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    as_of: Optional[str] = None
    note: Optional[str] = None


class LocationOut(BaseModel):
    lat: float
    lng: float
    label: str
    source: str


class ProvenanceOut(BaseModel):
    """Where a hand-set pin came from (043): 'autotask' = an Autotask
    address an operator confirmed (`by`, `at`). Operators only."""
    origin: str
    by: Optional[str] = None
    at: Optional[str] = None


class LinkOut(BaseModel):
    vendor: str
    label: str
    url: str
    verified: bool


class UnifiRefOut(BaseModel):
    instance_id: int
    host_id: str
    site_id: str
    problem: Optional[str] = None


class SiteOut(BaseModel):
    key: str
    kind: Literal["site", "tenant"]
    """'site' = a UniFi site; 'tenant' = a client without one (listed at the
    tenant level). Field names and values never name a vendor: a client
    user's response is checked for that."""
    name: str
    tenant_slug: Optional[str] = None
    tenant_name: str
    console_name: Optional[str] = None
    state: str
    reason: str
    reasons: list[ReasonOut]
    location: Optional[LocationOut] = None
    provenance: Optional[ProvenanceOut] = None
    """Operators: set when the pin is one confirmed from an integration's
    proposal ("from Autotask, confirmed by …")."""
    layers: dict[str, LayerOut]
    links: list[LinkOut] = Field(default_factory=list)
    vendor_ref: Optional[UnifiRefOut] = None
    """Operators: the UniFi console / site ids (the integration instance)."""
    tenant_sites: int = 1
    partial: bool = False
    incident: Optional[dict[str, Any]] = None
    """Operators: the site's worst OPEN incident (id, tier, status, acked,
    acked_by, contained, opened_at, age_s, rule_id, device_label, …). A
    client user: a visible incident's {ref, tier, status_neutral,
    opened_at, actions} only."""


class TenantRefOut(BaseModel):
    slug: str
    name: str


class FleetSitesResponse(BaseModel):
    view: Literal["operator", "client"]
    generated_at: str
    partial: bool
    sites: list[SiteOut]
    counts: dict[str, int]
    isp_outages: list[dict[str, Any]] = Field(default_factory=list)
    unmapped_sites: Optional[int] = None
    """Operators with every tenant in scope: UniFi sites neither mapped nor
    ignored (not on the map — map them under Integrations)."""
    tenants: list[TenantRefOut] = Field(default_factory=list)
    regional: list[dict[str, Any]] = Field(default_factory=list)
    """Operators: groups of sites whose internet issues are held at notice
    as likely regional (one ISP / one area) — the members in the caller's
    scope only."""
    threats: list[dict[str, Any]] = Field(default_factory=list)
    """Operators: every open Red / Black in scope (worst first)."""
    blind: list[dict[str, Any]] = Field(default_factory=list)
    """Operators: FR2 — "Athena is blind to <source> since …"."""
    coverage: Optional[dict[str, int]] = None
    """Operators: WAN coverage over the UniFi sites in scope."""
    threats_stopped_week: Optional[int] = None
    """Operators (A5, v0.17.1): "Threats stopped this week: N" — security-
    category DNS blocks over 7 days across the caller's scope (known-benign
    and CSAM out). A client user never gets it (their wording is unchanged)."""


class SiteAlertOut(BaseModel):
    event_id: int
    occurred_at: str
    severity: str
    source: str
    title: str
    tenant_wide: bool = False
    status: Literal["open", "acknowledged", "expected", "resurfaced"] = "open"
    """'open' / 'resurfaced' need attention; 'acknowledged' / 'expected' are
    listed only with ?include=acknowledged (greyed)."""
    ack: Optional[dict[str, Any]] = None
    """{verdict_id, by, by_name, at, note, repeat_until, by_repeat, recalled,
    notes} — the ack that covers the alert (or that a new occurrence outgrew:
    `resurfaced`; or, v0.17.5, that decided it and was RECALLED: `open` with
    `recalled` = {by, by_name, at, reason}). `notes` = the follow-up notes
    under it, [{by, by_name, at, note}] oldest first (newest last)."""
    rule: Optional[dict[str, Any]] = None
    """{id, label, review_at, remote} — the expected condition matching it."""
    new_since_ack: int = 0
    can_expect: bool = False
    expected_refusal: Optional[str] = None
    can_repeat: bool = False
    """May "acknowledge repeats for 24 h" be offered (an alert that names no
    device, a CSAM lookup: no)."""
    network: bool = False
    """A network (IPS) alert: an expected condition may name its remote."""
    hits: Optional[int] = None
    last_seen: Optional[str] = None
    """A coalesced row's count / last-seen as read now — the ack sends them
    back (`seen_hits` / `seen_last`): it covers no more than was shown."""
    enrichment: Optional[dict[str, Any]] = None


class SiteAlertsResponse(BaseModel):
    key: str
    items: list[SiteAlertOut]
    hidden: int = 0
    """Acknowledged / expected alerts left out of "needs attention"."""
    include_acknowledged: bool = False


class LocationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lat: float = Field(ge=-90.0, le=90.0)
    lng: float = Field(ge=-180.0, le=180.0)
    label: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=500)


class LocationClearIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)


class UnifiLocationOut(BaseModel):
    name: str
    lat: float
    lng: float
    label: str


class TenantLocationResponse(BaseModel):
    slug: str
    tenant_name: str
    override: Optional[dict[str, Any]] = None
    unifi_sites: list[UnifiLocationOut] = Field(default_factory=list)
    unlocated_unifi_sites: int = 0
    multi_site_console_sites: int = 0
    """The tenant's sites on a console that carries several sites: the
    console reports its OWN location, not each site's."""
    site_pins: int = 0
    """The tenant's sites pinned by their OWN override (the Fleet drawer)."""
    effective: Literal["unifi", "manual", "mixed", "none"]
    """'manual': every pinned site uses this fallback; 'mixed': some do;
    'unifi': none does (consoles / site pins); 'none': nothing is pinned."""


class PointOut(BaseModel):
    lat: float
    lng: float
    label: str


class SiteLocationResponse(BaseModel):
    key: str
    kind: Literal["site", "tenant"]
    name: str
    tenant_slug: str
    tenant_name: str
    override: Optional[dict[str, Any]] = None
    """This site's own (locked) location: lat, lng, label, set_at."""
    console: Optional[PointOut] = None
    """What the UniFi console REPORTS — shown even when overridden."""
    console_sites: int = 1
    console_shared: bool = False
    """A console with several sites shared with another tenant: its location
    pins nobody."""
    tenant_fallback: Optional[PointOut] = None
    current: Optional[LocationOut] = None
    effective: Literal["site", "unifi", "tenant", "none"]
    geocoder: Optional[str] = None
    """'census' when the address lookup is on, else None (hide Find)."""
    proposals: list[dict[str, Any]] = Field(default_factory=list)
    """Open location proposals for THIS site ({id, source, label,
    unassigned: false}) — the editor's "Autotask suggests …" — and the
    client's open ones not yet assigned to any site ("pick a site":
    unassigned: true). Reviewed in the proposals panel."""


class GeocoderOut(BaseModel):
    provider: Optional[str] = None


class GeocodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(min_length=1, max_length=400)


class GeocodeResponse(BaseModel):
    provider: str
    matches: list[PointOut]


# ---------------------------------------------------------------------------
# Shaping
# ---------------------------------------------------------------------------

def _model(request: Request) -> build.FleetModel:
    manager = getattr(request.app.state, "instance_manager", None)
    return build.get_model(manager)


def _in_scope(scope: list[str], slug: str) -> bool:
    return scope == ["*"] or slug in scope


_NETWORK_CLIENT_KEYS = ("devices_total", "devices_online", "devices_offline", "gateway_online",
                        "console_online", "internet_issues", "internet_issues_recent",
                        "internet_issues_level", "pending_updates", "critical_notifications")


def _client_data(layer: fs.Layer) -> dict[str, Any]:
    """A layer's data as a client user may see it: counts and states, never
    a vendor's name, id or the ISP."""
    d = layer.data
    if layer.name == "network":
        out = {k: d.get(k) for k in _NETWORK_CLIENT_KEYS}
        out["connections_up"] = len(d.get("wan_up") or [])
        out["connections_down"] = len([w for w in (d.get("wan_down") or [])
                                       if w not in (d.get("backup_down") or [])])
        return out
    if layer.name == "security":
        out = {k: d[k] for k in ("ips_detected_24h", "ips_blocked_24h", "dns_threats_24h",
                                 "open_incidents") if k in d}
        if d.get("dns_profiles"):
            counts: dict[str, int] = {}
            for p in d["dns_profiles"]:
                counts[p["state"]] = counts.get(p["state"], 0) + 1
            out["dns_protection"] = counts
        return out
    if layer.name == "endpoints":
        return {k: d.get(k) for k in ("agents_total", "agents_online", "agents_offline",
                                      "servers_offline") if k in d}
    if layer.name == "buoy":
        return {"health": d.get("health")} if d else {}
    if layer.name == "threat":
        # Built from what the client view allows (`_site_out`) — never the
        # operator's data (ids, counts of hidden incidents, would-fires).
        return {}
    return {}


def _layer_out(layer: fs.Layer, *, client: bool, note: Optional[str] = None) -> LayerOut:
    return LayerOut(
        name=layer.name, present=layer.present, state=layer.state if layer.present else "absent",
        scope=layer.scope,
        reasons=[ReasonOut(**r.as_dict(neutral=client)) for r in layer.reasons],
        data=_client_data(layer) if client else dict(layer.data),
        as_of=layer.as_of, note=None if client else note,
    )


def _kind(e: build.SiteEntry) -> Literal["site", "tenant"]:
    return "site" if e.kind == "unifi" else "tenant"


def client_site_name(e: build.SiteEntry, tenant_name: str) -> str:
    """A site's name as a client user reads it: the site's OWN name (what
    UniFi reports for a site someone named) — never the mapping label (it
    carries the console's name and its address text) nor the console's name
    (UniFi's default site takes it; it often names the model / vendor). No
    such name: the client's name for its only site, else "Site N"."""
    if e.kind == "tenant":
        return tenant_name
    own = (e.client_name or "").strip()
    console = (e.console_name or "").strip().lower()
    if own and own.lower() != console and not (console and console in own.lower()):
        return own
    return tenant_name if e.tenant_sites <= 1 else f"Site {e.site_no}"


def operator_names(ids: Any) -> dict[int, str]:
    """operator id → display name (else username); {} when unreadable."""
    wanted = sorted({int(i) for i in ids if isinstance(i, int) and not isinstance(i, bool)})
    if not wanted:
        return {}
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    try:
        rows = reg.execute(
            f"SELECT id, COALESCE(NULLIF(display_name, ''), username) FROM operators "
            f"WHERE id IN ({','.join('?' * len(wanted))})", wanted).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        reg.close()
    return {int(r[0]): str(r[1]) for r in rows}


def _provenance(loc: Optional[locations.Location],
                names: dict[int, str]) -> Optional[ProvenanceOut]:
    """A hand-set pin confirmed from a proposal: its origin, who, when."""
    if loc is None or loc.source not in ("site", "manual") or loc.origin == "manual":
        return None
    return ProvenanceOut(origin=loc.origin, by=names.get(loc.set_by) if loc.set_by else None,
                         at=loc.set_at)


def _worst_open(e: build.SiteEntry) -> Optional[Any]:
    opened = [i for i in e.incidents if i.is_open]
    opened.sort(key=lambda i: (0 if i.tier == "black" else 1, 1 if i.acked else 0,
                               i.detected_at or ""))
    return opened[0] if opened else None


def _operator_incident(e: build.SiteEntry, now: datetime) -> Optional[dict[str, Any]]:
    i = _worst_open(e)
    if i is None:
        return None
    # Who acknowledged it BY NAME: the acknowledged Black pin shows their
    # initials (an operator id would draw a digit).
    names = sources.operator_display_names({i.acknowledged_by}) if i.acked else {}
    # A RESTRICTED incident (B7): no rule, summary or device for any
    # operator here — the audited, admin-only detail has them.
    hidden = bool(getattr(i, "restricted", False))
    return {"tenant_slug": e.tenant_slug, "id": i.id, "tier": i.tier, "status": i.status,
            "acked": i.acked, "acked_by": i.acknowledged_by,
            "acked_by_name": names.get(str(i.acknowledged_by or "")),
            "contained": i.contained,
            "opened_at": i.detected_at, "age_s": i.age_s(now),
            "rule_id": "restricted" if hidden else i.rule_id,
            "rule_version": 0 if hidden else i.rule_version,
            "summary": fs.RESTRICTED_TEXT if hidden else i.summary,
            "device_label": None if hidden else (i.device_label or i.device_ref),
            "restricted": hidden,
            "unknown_location": i.id in e.unknown_location and not hidden,
            "open_count": sum(1 for x in e.incidents if x.is_open)}


def _client_view(e: build.SiteEntry, now: datetime) -> tuple[dict[str, fs.Layer], fs.Verdict,
                                                             Optional[dict[str, Any]]]:
    """A client user's layers and verdict: incidents they may not see yet
    and operator-only reasons taken out; a visible incident's reason reads
    its neutral line."""
    # The tenant's own watch length (3–30 d): a client sees the post-incident
    # watch exactly as long as its operators do.
    watch = int(threat_registry.settings(e.tenant_slug).get("watch_days") or 7) \
        if e.incidents else 7
    hidden = {i.id for i in e.incidents if not client_view.visible(i, now, watch_days=watch)}
    lines = {i.id: client_view.line(i, now, watch_days=watch) or "" for i in e.incidents
             if i.id not in hidden}
    layers = {name: fs.client_layer(layer, hidden=hidden, lines=lines)
              for name, layer in e.layers.items()}
    shown = [i for i in e.incidents if i.id not in hidden and i.is_open]
    shown.sort(key=lambda i: (0 if i.tier == "black" else 1, i.detected_at or ""))
    item = client_view.payload(shown[0], now, watch_days=watch) if shown else None
    if item is not None:
        item = {k: item[k] for k in ("ref", "tier", "status_neutral", "opened_at", "actions")}
    return layers, fs.site_verdict(layers), item


def _site_out(e: build.SiteEntry, *, client: bool, neutral_names: set[str],
              names: Optional[dict[int, str]] = None,
              now: Optional[datetime] = None) -> SiteOut:
    now = now or datetime.now(timezone.utc)
    if client:
        client_layers, verdict, item = _client_view(e, now)
        layers = {name: _layer_out(layer, client=True) for name, layer in client_layers.items()}
        if item is not None and "threat" in layers:
            layers["threat"].data = {"tier": item["tier"],
                                     "status_neutral": item["status_neutral"],
                                     "opened_at": item["opened_at"]}
        tenant_name = VIEWER_PLACEHOLDER_NAME if e.tenant_slug in neutral_names else \
            e.tenant_name
        name = client_site_name(e, tenant_name)
        return SiteOut(
            key=e.key, kind=_kind(e), name=name, tenant_slug=None, tenant_name=tenant_name,
            console_name=None, state=verdict.state,
            reason=fs.reason_line(verdict, neutral=True),
            reasons=[ReasonOut(**r.as_dict(neutral=True)) for r in verdict.reasons],
            location=None, layers=layers, links=[], vendor_ref=None,
            tenant_sites=e.tenant_sites, partial=e.partial, incident=item,
        )
    layers = {name: _layer_out(layer, client=False,
                               note=e.datto_note if name == "endpoints" else None)
              for name, layer in e.layers.items()}
    return SiteOut(
        key=e.key, kind=_kind(e), name=e.name, tenant_slug=e.tenant_slug,
        tenant_name=e.tenant_name, console_name=e.console_name or None,
        state=e.verdict.state, reason=fs.reason_line(e.verdict),
        reasons=[ReasonOut(**r.as_dict()) for r in e.verdict.reasons],
        location=LocationOut(**e.location.as_dict()) if e.location else None,
        provenance=_provenance(e.location, names or {}),
        layers=layers, links=[LinkOut(**link.as_dict()) for link in e.links],
        vendor_ref=UnifiRefOut(instance_id=e.unifi["instance_id"], host_id=e.unifi["host_id"],
                          site_id=e.unifi["site_id"], problem=e.unifi.get("problem"))
        if e.unifi else None,
        tenant_sites=e.tenant_sites, partial=e.partial,
        incident=_operator_incident(e, now),
    )


def _threats(model: build.FleetModel, scope: list[str]) -> list[dict[str, Any]]:
    """The open Reds / Blacks for the banner — the caller's tenants only."""
    return [dict(t) for t in model.threat_incidents if _in_scope(scope, t["tenant"])]


def _blind(model: build.FleetModel, scope: list[str]) -> list[dict[str, Any]]:
    """FR2 — the sources Athena is blind to. A concrete scope sees a source
    only when it covers one of its tenants, and never the other tenants'
    names."""
    out = []
    for b in model.blind:
        tenants = list(b.tenants)
        if scope != ["*"]:
            if getattr(b, "internal", False):
                continue                     # mapped to no client: the MSP's own banner
            if tenants and not any(t in scope for t in tenants):
                continue
            tenants = [t for t in tenants if t in scope]
        out.append({"source": b.source, "label": b.label, "since": b.since,
                    "fleet_wide": b.fleet_wide, "why": b.why, "tenants": tenants})
    return out


def _coverage(entries: list[build.SiteEntry]) -> dict[str, int]:
    """WAN coverage over the UniFi sites (Rick, 2026-10-02): sites with a
    configured backup line, without one (a single-port gateway, or a WAN2
    never configured), and not known."""
    out = {"sites_with_backup": 0, "sites_without_backup": 0, "sites_backup_unknown": 0}
    for e in entries:
        if e.kind != "unifi" or not e.layers["network"].present:
            continue
        has = e.layers["network"].data.get("has_backup")
        key = "sites_with_backup" if has is True else "sites_without_backup" \
            if has is False else "sites_backup_unknown"
        out[key] += 1
    return out


def _outages(model: build.FleetModel, scope: list[str]) -> list[dict[str, Any]]:
    out = []
    for inc in model.isp_outages:
        if inc.get("suppressed"):
            if scope == ["*"]:
                out.append({"suppressed": inc["suppressed"], "open": False})
            continue
        members = [m for m in (inc.get("members") or []) if _in_scope(scope, m.get("tenant"))]
        if scope != ["*"] and not members:
            continue
        item = {k: inc.get(k) for k in ("vid", "open", "asn", "isp", "since", "opened_at",
                                       "closed_at", "sites", "sites_down")}
        if scope != ["*"]:
            # A concrete scope sees ITS members' numbers only — the fleet-wide
            # count would tell how many other clients' sites are on that ISP.
            item["sites"] = len(members)
            item["sites_down"] = sum(1 for m in members if not m.get("recovered_at"))
        item["members"] = [{k: m.get(k) for k in ("tenant", "name", "since", "why",
                                                  "recovered_at")} | {
            "key": build.site_key("unifi", m["scope"]) if m.get("scope") else None}
            for m in members]
        if scope == ["*"]:
            item["tenant"] = inc.get("tenant")
            item["event_id"] = inc.get("event_id")
        out.append(item)
    return out


def _regional(model: build.FleetModel, scope: list[str]) -> list[dict[str, Any]]:
    """The regional groups as the caller may see them: a concrete scope sees
    its own members only, and counts over those (never how many other
    clients' sites share the ISP / area)."""
    out = []
    for g in model.regional:
        members = [m for m in g.get("members") or [] if _in_scope(scope, m.get("tenant"))]
        if not members:
            continue
        item: dict[str, Any] = {"kind": g["kind"], "sites": len(members),
                                "keys": [m["key"] for m in members]}
        if g["kind"] == "isp":
            item["asn"], item["isp"] = g.get("asn"), g.get("isp")
        else:
            item["km"] = g.get("km")
        out.append(item)
    return out


def _counts(sites: list[SiteOut]) -> dict[str, int]:
    counts = {"total": len(sites), "located": 0, "unlocated": 0,
              **{s: 0 for s in fs.STATES}}
    for s in sites:
        counts[s.state] = counts.get(s.state, 0) + 1
        counts["located" if s.location else "unlocated"] += 1
    return counts


# ---------------------------------------------------------------------------
# Routes — the fleet
# ---------------------------------------------------------------------------

@router.get("/sites", response_model=FleetSitesResponse)
def get_fleet_sites(
    request: Request,
    response: Response,
    info: sessions.SessionInfo = Depends(session_viewer_plus),
) -> FleetSitesResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    operator = operator_max_tier(info.operator_id) >= ROLE_TIER["analyst"]
    if not operator and scope == ["*"]:
        # A viewer is a client user scoped to concrete tenants (v0.10): a
        # legacy `*` viewer row sees nothing (never every tenant).
        scope = []
    model = _model(request)
    entries = [e for e in model.sites if _in_scope(scope, e.tenant_slug)] if scope else []
    neutral: set[str] = set()
    if not operator and entries:
        from apps.octo.fleet.sources import placeholder_named

        neutral = placeholder_named(sorted({e.tenant_slug for e in entries}))
    names = operator_names(e.location.set_by for e in entries
                           if e.location is not None and e.location.origin != "manual") \
        if operator else {}
    now = datetime.now(timezone.utc)
    sites = [_site_out(e, client=not operator, neutral_names=neutral, names=names, now=now)
             for e in entries]
    view: Literal["operator", "client"] = "operator" if operator else "client"
    PolledReadAudit.for_app(request.app).record(
        "fleet.sites", operator_id=info.operator_id, session_id=info.id,
        reason="fleet view", rows=len(sites), shape=f"view={view}",
        detail={"sites": len(sites), "view": view},
    )
    tenants = []
    if operator:
        seen = sorted({e.tenant_slug for e in entries})
        tenants = [TenantRefOut(slug=s, name=model.tenants.get(s, s)) for s in seen]
    return FleetSitesResponse(
        view=view, generated_at=model.generated_at, partial=model.partial, sites=sites,
        counts=_counts(sites),
        isp_outages=_outages(model, scope) if operator else [],
        unmapped_sites=model.unmapped_unifi_sites if operator and scope == ["*"] else None,
        tenants=tenants,
        regional=_regional(model, scope) if operator else [],
        threats=_threats(model, scope) if operator else [],
        blind=_blind(model, scope) if operator else [],
        coverage=_coverage(entries) if operator else None,
        threats_stopped_week=sum(n for slug, n in model.dns_week.items()
                                 if _in_scope(scope, slug)) if operator and scope else None,
    )


def _presenters(request: Request) -> dict[str, Any]:
    from apps.octo.api.routers.dashboard import _presenters as presenters

    return presenters(getattr(request.app.state, "adapter_registry", None))


@router.get("/sites/{key}/alerts", response_model=SiteAlertsResponse)
def get_site_alerts(
    request: Request,
    response: Response,
    key: str = Path(..., min_length=3, max_length=40, pattern=r"^[ut]-[0-9a-f]{20}$"),
    include: Optional[Literal["acknowledged"]] = Query(default=None),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> SiteAlertsResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    entry = next((e for e in _model(request).sites if e.key == key), None)
    if entry is None or not _in_scope(scope, entry.tenant_slug):
        raise APIError("NOT_FOUND", "no such site in your scope")
    handled = include == "acknowledged"
    items, hidden = _recent_alerts(request, entry, include_handled=handled)
    PolledReadAudit.for_app(request.app).record(
        "fleet.site_alerts", operator_id=info.operator_id, session_id=info.id,
        reason="fleet site drawer", rows=len(items), shape="drawer",
        detail={"tenant": entry.tenant_slug},
    )
    return SiteAlertsResponse(key=key, items=items, hidden=hidden,
                              include_acknowledged=handled)


# The alerts annotated per drawer read (keys, coalesced row, verdict): the
# newest ones of the site — bounded, whatever the tenant's volume.
ALERT_ANNOTATE_ROWS = 300
ALERT_LIMIT_HANDLED = 30


def _recent_alerts(request: Request, entry: build.SiteEntry, *,
                   include_handled: bool = False) -> tuple[list[SiteAlertOut], int]:
    from apps.octo.adapters.unifi import store as ustore
    from apps.octo.enrich import alerts as enrich_alerts
    from apps.octo.verdicts import annotate
    from apps.octo.verdicts import store as vstore
    from apps.octo.verdicts.state import TenantVerdicts

    db = paths.client_dir(entry.tenant_slug) / "events.db"
    if not db.exists():
        return [], 0
    now = datetime.now(timezone.utc)
    since = (now - ALERT_WINDOW).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return [], 0
    conn.row_factory = sqlite3.Row
    try:
        marks = ",".join("?" * len(_ALERT_SEVERITIES))
        # RESTRICTED (B7, CSAM): an alert naming a restricted domain is never
        # listed here (any role) — admins read it in the restricted incident.
        pred = restricted.Gate.for_tenant(entry.tenant_slug).where(
            conn, "summary", "payload", "source_host")
        keep = f"AND {pred} " if pred else ""
        # Athena's own incident records (`athena.incident`) are not alerts:
        # the incident panel shows the incident; an alert row is a signal an
        # analyst may confirm (R8) — never the incident's own record.
        rows = conn.execute(
            f"SELECT id, received_at, source, source_host, event_type, severity, summary, "
            f"payload FROM events WHERE received_at >= ? AND severity IN ({marks}) "
            f"AND source <> 'athena' {keep}"
            f"ORDER BY received_at DESC, id DESC LIMIT ?",
            (since, *_ALERT_SEVERITIES, ALERT_SCAN_ROWS)).fetchall()
    except sqlite3.Error:
        return [], 0
    finally:
        conn.close()
    scope = (entry.unifi or {}).get("scope")
    mine: list[tuple[dict[str, Any], dict[str, Any], bool]] = []
    for r in rows:
        try:
            payload = json.loads(r["payload"]) if r["payload"] else {}
        except (ValueError, RecursionError):
            payload = {}
        payload = payload if isinstance(payload, dict) else {}
        source = str(r["source"] or "")
        own = source == "unifi" and isinstance(payload.get("scope"), str)
        if own and payload.get("scope") != scope:
            continue                              # another site's UniFi alert
        mine.append((dict(r), payload, own))
        if len(mine) >= ALERT_ANNOTATE_ROWS:
            break
    if not mine:
        return [], 0
    slug = entry.tenant_slug
    try:
        verdicts: Optional[TenantVerdicts] = TenantVerdicts.load(slug, now)
    except Exception:  # noqa: BLE001 — unreadable verdicts hide nothing (louder)
        verdicts = None
    anns = annotate.annotate(slug, [m[0] for m in mine], verdicts=verdicts, now=now)
    hidden = sum(1 for a in anns if a.state is not None and a.state.hidden)
    limit = ALERT_LIMIT_HANDLED if include_handled else ALERT_LIMIT
    shown = [(a, m) for a, m in zip(anns, mine)
             if include_handled or a.state is None or not a.state.hidden][:limit]
    rows_shown = [m[0] for _a, m in shown]
    unifi_ids = [int(r["id"]) for r in rows_shown if r.get("source") == "unifi"]
    extra: dict[int, dict[str, Any]] = {}
    try:
        extra.update(enrich_alerts.unifi_ips(slug, rows_shown,
                                             ustore.bucket_info(slug, unifi_ids), now=now))
        extra.update(enrich_alerts.datto(slug, rows_shown, now=now))
    except Exception as exc:  # noqa: BLE001 — enrichment never blanks the drawer
        logger.warning("[fleet] alert enrichment failed (%s)", type(exc).__name__)
    shown_acks = {a.state.ack.id: a.state.ack for a, _m in shown
                  if a.state is not None and a.state.ack is not None}
    # v0.17.5: the notes and the recall under each ack shown (fail-soft:
    # none when the registry cannot be read — the state above already knows
    # a recall).
    fups = vstore.followups(slug, shown_acks) if shown_acks else {}
    actors = {str(v.actor) for v in shown_acks.values()} | \
        {str(f.actor) for fs in fups.values() for f in fs}
    names = sources.operator_display_names(actors)
    presenters = _presenters(request)
    out: list[SiteAlertOut] = []
    for a, (r, payload, own) in shown:
        source = str(r["source"] or "")
        title = ""
        present = presenters.get(source)
        if callable(present):
            try:
                title = present(payload).headline
            except Exception:  # noqa: BLE001 — a title never blanks the drawer
                title = ""
        title = clean_text(title or r["summary"] or r["event_type"] or "alert", 240)
        st = a.state
        ack = None
        if st is not None and st.ack is not None:
            ack = _ack_out(st.ack, by_repeat=st.by_repeat, followups=fups.get(st.ack.id, []),
                           names=names)
        rule = None
        if st is not None and st.rule is not None:
            rule = {"id": st.rule.id, "label": st.rule.label, "review_at": st.rule.review_at,
                    "remote": st.rule.remote}
        out.append(SiteAlertOut(
            event_id=int(r["id"]), occurred_at=str(r["received_at"] or ""),
            severity=str(r["severity"] or ""), source=source, title=title,
            tenant_wide=(not own) and entry.tenant_sites > 1,
            status=st.status if st is not None else "open", ack=ack, rule=rule,
            new_since_ack=st.new_hits if st is not None else 0,
            can_expect=a.refusal is None, expected_refusal=a.refusal,
            can_repeat=a.repeat_refusal is None,
            network=a.key.family == "unifi_ips", hits=a.hits, last_seen=a.last_seen,
            enrichment=extra.get(int(r["id"])),
        ))
    return out, hidden


def _ack_out(ack: Any, *, by_repeat: bool, followups: list[Any],
             names: dict[str, Any]) -> dict[str, Any]:
    """The drawer's ack payload (operators only): who / when / its own note,
    plus (v0.17.5) its id — the recall and notes routes name it —, its
    recall and its follow-up notes (oldest first). A recall the follow-ups
    could not be read for still says WHEN (the verdict read carries it)."""
    recall = next((f for f in followups if f.kind == "recall"), None)
    recalled = None
    if recall is not None:
        recalled = {"by": recall.actor, "by_name": names.get(str(recall.actor)),
                    "at": recall.at, "reason": recall.text}
    elif ack.recalled:
        recalled = {"by": None, "by_name": None, "at": ack.recalled_at, "reason": None}
    return {"verdict_id": ack.id, "by": ack.actor, "by_name": names.get(str(ack.actor)),
            "at": ack.at, "note": ack.note, "repeat_until": ack.repeat_until,
            "by_repeat": by_repeat, "recalled": recalled,
            "notes": [{"by": f.actor, "by_name": names.get(str(f.actor)), "at": f.at,
                       "note": f.text} for f in followups if f.kind == "note"]}


# ---------------------------------------------------------------------------
# Routes — the manual location (tenant settings)
# ---------------------------------------------------------------------------

def _tenant(slug: str) -> sqlite3.Row:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute("SELECT slug, display_name, status FROM clients WHERE slug = ?",
                          (slug,)).fetchone()
    finally:
        reg.close()
    if row is None:
        raise APIError("NOT_FOUND", "no such tenant")
    return row


def _scoped_tenant(info: sessions.SessionInfo, slug: str) -> sqlite3.Row:
    """The tenant, if the caller's scope holds it — out of scope is the same
    404 as no such tenant."""
    if not paths.SLUG_RE.match(slug):
        raise APIError("NOT_FOUND", "no such tenant")
    scope = resolve_caller_scope(info.operator_id)
    if not _in_scope(scope, slug):
        raise APIError("NOT_FOUND", "no such tenant")
    return _tenant(slug)


def _location_response(request: Request, row: sqlite3.Row) -> TenantLocationResponse:
    slug = row["slug"]
    override = locations.get(slug)
    unifi = []
    unlocated = 0
    multi = 0
    mine = [e for e in _model(request).sites if e.tenant_slug == slug]
    for e in mine:
        if e.kind != "unifi":
            continue
        multi += 1 if int((e.unifi or {}).get("console_sites") or 1) > 1 else 0
        reported = (e.unifi or {}).get("console_location")
        if reported is not None:
            unifi.append(UnifiLocationOut(name=e.name, lat=reported.lat, lng=reported.lng,
                                          label=reported.label))
        else:
            unlocated += 1
    sources = [e.location.source for e in mine if e.location is not None]
    fallback = sum(1 for src in sources if src == "manual")
    if not sources:
        effective = "none"
    elif fallback == len(sources):
        effective = "manual"
    elif fallback:
        effective = "mixed"
    else:
        effective = "unifi"
    return TenantLocationResponse(
        slug=slug, tenant_name=row["display_name"] or slug,
        override={k: override[k] for k in ("lat", "lng", "label", "set_at")} if override
        else None,
        unifi_sites=unifi, unlocated_unifi_sites=unlocated, multi_site_console_sites=multi,
        site_pins=sum(1 for src in sources if src == "site"), effective=effective,
    )


def _audit(info: sessions.SessionInfo, action: str, slug: str, before: Any, after: Any,
           reason: str, *, target_kind: str = "tenant_location",
           target_id: Optional[str] = None) -> None:
    g = connect(paths.global_audit_db_path())
    try:
        audit.append(g, audit.AuditEntry(
            actor=str(info.operator_id), actor_kind="human", action=action,
            target_kind=target_kind, target_id=target_id or slug, client_slug=slug,
            before_state=before, after_state=after, reason=reason,
            request_id=str(uuid.uuid4())))
    finally:
        g.close()


@router.get("/locations/{slug}", response_model=TenantLocationResponse)
def get_location(
    request: Request,
    response: Response,
    slug: str = Path(..., min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantLocationResponse:
    response.headers["Cache-Control"] = "no-store"
    return _location_response(request, _scoped_tenant(info, slug))


@router.put("/locations/{slug}", response_model=TenantLocationResponse)
def put_location(
    body: LocationIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantLocationResponse:
    row = _scoped_tenant(info, slug)
    if row["status"] != "active":
        raise APIError("CONFLICT", "only an active tenant can be placed on the map")
    try:
        lat, lng, label = locations.validated(body.lat, body.lng, body.label)
    except locations.LocationError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    before = locations.get(slug)
    after = {"lat": lat, "lng": lng, "label": label}
    _audit(info, "tenant_location_set", slug,
           {k: before[k] for k in ("lat", "lng", "label")} if before else None, after,
           body.reason)
    locations.set_override(slug, lat, lng, label, actor=info.operator_id)
    build.invalidate()
    return _location_response(request, row)


@router.delete("/locations/{slug}", response_model=TenantLocationResponse)
def delete_location(
    body: LocationClearIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantLocationResponse:
    row = _scoped_tenant(info, slug)
    before = locations.get(slug)
    if before is None:
        raise APIError("NOT_FOUND", "this tenant has no manual location")
    _audit(info, "tenant_location_clear", slug,
           {k: before[k] for k in ("lat", "lng", "label")}, None, body.reason)
    locations.clear_override(slug)
    build.invalidate()
    return _location_response(request, row)


# ---------------------------------------------------------------------------
# Routes — one SITE's location (the Fleet drawer) and the address lookup
# ---------------------------------------------------------------------------

_SITE_KEY = r"^[ut]-[0-9a-f]{20}$"


def _scoped_site(request: Request, info: sessions.SessionInfo, key: str) -> build.SiteEntry:
    """The site, if the caller's scope holds its tenant — out of scope is
    the same 404 as no such site."""
    scope = resolve_caller_scope(info.operator_id)
    entry = next((e for e in _model(request).sites if e.key == key), None)
    if entry is None or not _in_scope(scope, entry.tenant_slug):
        raise APIError("NOT_FOUND", "no such site in your scope")
    return entry


def _point(loc: Optional[locations.Location]) -> Optional[PointOut]:
    return PointOut(lat=loc.lat, lng=loc.lng, label=loc.label) if loc is not None else None


def _site_location_response(request: Request, key: str) -> SiteLocationResponse:
    entry = next((e for e in _model(request).sites if e.key == key), None)
    if entry is None:
        raise APIError("NOT_FOUND", "no such site in your scope")
    from apps.octo.proposals import site_location, store

    own = locations.get_site(key, entry.tenant_slug)
    fallback = locations.from_manual(locations.get(entry.tenant_slug), entry.tenant_name)
    unifi = entry.unifi or {}
    src = entry.location.source if entry.location is not None else None
    effective: Literal["site", "unifi", "tenant", "none"] = \
        "site" if src == "site" else "unifi" if src == "unifi" else \
        "tenant" if src == "manual" else "none"
    override = None
    if own:
        override = {k: own[k] for k in ("lat", "lng", "label", "set_at")}
        override["origin"] = own.get("origin") or "manual"
        if override["origin"] != "manual" and isinstance(own.get("set_by"), int):
            override["set_by_name"] = operator_names([own["set_by"]]).get(own["set_by"])
    hints = [{"id": p.id, "source": p.source, "label": p.payload.get("label") or "",
              "unassigned": p.target_key is None}
             for p in sorted(store.list_proposals(site_location.KIND, statuses=(store.OPEN,),
                                                  tenants=[entry.tenant_slug]),
                             key=lambda q: (q.target_key is None, q.id))
             if p.target_key == key or p.target_key is None]
    return SiteLocationResponse(
        key=key, kind=_kind(entry), name=entry.name, tenant_slug=entry.tenant_slug,
        tenant_name=entry.tenant_name,
        override=override,
        console=_point(unifi.get("console_location")),
        console_sites=int(unifi.get("console_sites") or 1),
        console_shared=bool(unifi.get("console_shared")),
        tenant_fallback=_point(fallback),
        current=LocationOut(**entry.location.as_dict()) if entry.location else None,
        effective=effective, geocoder=geocode.provider(), proposals=hints,
    )


@router.get("/sites/{key}/location", response_model=SiteLocationResponse)
def get_site_location(
    request: Request,
    response: Response,
    key: str = Path(..., min_length=3, max_length=40, pattern=_SITE_KEY),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> SiteLocationResponse:
    response.headers["Cache-Control"] = "no-store"
    _scoped_site(request, info, key)
    return _site_location_response(request, key)


@router.put("/sites/{key}/location", response_model=SiteLocationResponse)
def put_site_location(
    body: LocationIn,
    request: Request,
    key: str = Path(..., min_length=3, max_length=40, pattern=_SITE_KEY),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> SiteLocationResponse:
    entry = _scoped_site(request, info, key)
    try:
        lat, lng, label = locations.validated(body.lat, body.lng, body.label)
    except locations.LocationError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    slug = entry.tenant_slug
    before = locations.get_site(key, slug)
    after = {"lat": lat, "lng": lng, "label": label, "site": entry.name}
    _audit(info, "site_location_set", slug,
           {k: before[k] for k in ("lat", "lng", "label")} if before else None, after,
           body.reason, target_kind="site_location", target_id=key)
    locations.set_site_override(key, slug, lat, lng, label, actor=info.operator_id)
    build.invalidate()
    return _site_location_response(request, key)


@router.delete("/sites/{key}/location", response_model=SiteLocationResponse)
def delete_site_location(
    body: LocationClearIn,
    request: Request,
    key: str = Path(..., min_length=3, max_length=40, pattern=_SITE_KEY),
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> SiteLocationResponse:
    entry = _scoped_site(request, info, key)
    before = locations.get_site(key, entry.tenant_slug)
    if before is None:
        raise APIError("NOT_FOUND", "this site has no manual location")
    _audit(info, "site_location_clear", entry.tenant_slug,
           {k: before[k] for k in ("lat", "lng", "label")}, None, body.reason,
           target_kind="site_location", target_id=key)
    locations.clear_site_override(key)
    build.invalidate()
    return _site_location_response(request, key)


@router.get("/geocoder", response_model=GeocoderOut)
def get_geocoder(
    response: Response,
    _info: sessions.SessionInfo = Depends(session_admin_plus),
) -> GeocoderOut:
    """Whether the address lookup is on ('census') or off (None) — the
    location editors that have no site to read it from (the host pin)
    show or hide Find with it."""
    response.headers["Cache-Control"] = "no-store"
    return GeocoderOut(provider=geocode.provider())


@router.post("/geocode", response_model=GeocodeResponse)
def geocode_address(
    body: GeocodeIn,
    request: Request,
    response: Response,
    info: sessions.SessionInfo = Depends(session_admin_plus),
) -> GeocodeResponse:
    """An address → up to 3 candidate points. Only the typed address leaves
    the box (US Census geocoder); nothing is stored — the operator saves the
    match they pick as a site location (audited there)."""
    response.headers["Cache-Control"] = "no-store"
    name = geocode.provider()
    if name is None:
        raise APIError("CONFLICT", "address lookup is turned off on this server — paste the "
                                   "coordinates or a map link instead")
    try:
        address = geocode.clean_address(body.address)
    except geocode.GeocodeError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    if not geocode.LIMITER.allow(info.operator_id):
        raise APIError("RATE_LIMITED", "too many address lookups — wait a minute and try again")
    try:
        matches = geocode.lookup(address)
    except geocode.GeocodeError as exc:
        raise APIError("CONFLICT" if exc.kind == "off" else "VENDOR_UNREACHABLE",
                       str(exc)) from None
    # Who looked something up and how many matches — never the address.
    PolledReadAudit.for_app(request.app).record(
        "fleet.geocode", operator_id=info.operator_id, session_id=info.id,
        reason="site location address lookup", rows=len(matches), shape=f"provider={name}",
        detail={"matches": len(matches)},
    )
    return GeocodeResponse(provider=name,
                           matches=[PointOut(**m.as_dict()) for m in matches])
