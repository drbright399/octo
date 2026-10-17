"""The whole fleet model — every site of every active tenant with its four
layers, its worst state and its location — built from what the pollers
already store (sources.py), CACHED and built under a TIME BOUND. The API
filters it per caller (role + scope); nothing here knows who is asking.

SITES. A UniFi site mapped to an active tenant is one entry, keyed by
(hostId, siteId) (an opaque `key` derived from it is what the API shows). A
tenant with no UniFi site but another source (NextDNS, Datto, RocketCyber, a
buoy) is ONE tenant-level entry. A tenant with no source at all is not on the
fleet.

WHAT SITS ON WHICH SITE. The UniFi network and IPS are the site's own. The
NextDNS profiles: those linked to the site by entity resolution when the
tenant's switch is ON (auto / confirmed site links), the tenant's unlinked
profiles on each of its sites (tenant-level) — with the switch off / shadow,
every profile is tenant-level. Datto: the same rule over the tenant's Datto
sites (the device list is read for EVERY Datto-mapped tenant since v0.17.2 —
Rick's decision D; site LINKS still need the switch ON). RocketCyber open
incidents and the buoy are the tenant's, shown on each of its sites.

HUMAN VERDICTS (v0.17.2, A / B). An alert an analyst ACKNOWLEDGED (until a
new occurrence re-surfaces it) or that an EXPECTED condition matches stops
counting towards its site's Yellow: the IPS hits, the DNS threat blocks,
the RocketCyber incident and the decoy port touch behind it are left out of
the health layers' STATE and reasons (`verdicts.state`) — the counts in the
layer data stay every hit (a client user's "N intrusion attempts blocked"
is a fact, not a judgement); operators see how many were left out:
`ips_hidden_24h`, `dns_hidden_24h`, `rc_hidden`, `canary_hidden_24h`. The
THREAT layer — Red and Black — never reads them.

LINKS ("Open in", operators only — the API never sends one to a viewer).
UniFi: the site's dashboard on its console (the hostId keeps its ':' —
`vendor_links.KeptIdChars`). NextDNS: each profile's logs. Datto: each Datto
site on the entry (the endpoints rule above) opens its own page,
``/site/<numeric id>/<name slug>``, from the id the inventory poller learned
(`adapters.datto.site_ids` — a registry read here, never a vendor call); a
site whose id is not known yet gets the portal's home instead, once, labelled
"(home)".

LOCATION. Each entry's pin is `locations.resolve`: the site's own override
(042, keyed by the entry's key), else the console's location, else the
tenant's override (041), else none.

THE THREAT LAYER (Tier Black, slice 1). Each tenant's incident records
(`sources.open_incidents`: open, and closed ≤ 30 d) are read on EVERY build —
past the time budget too: an open Red / Black is never dropped for time. An
incident is attached to its HOME site (`site_key` = an entry's key); one
whose site is not known (no key, or a key not on the fleet) is painted on
EVERY site of the tenant, labelled "device location unknown". Detection
blindness (FR2, `threat.intake`) and the shadow rules' would-fires feed the
same layer. `FleetModel.threat_incidents` lists the open Reds and Blacks
(the banner / strip), `blind` the blind sources (the internal banner).
Entries sort by RANK (black first — never a literal order that a new state
breaks), unacknowledged Black first, then the oldest open incident.

REGIONAL COLLAPSE (the quiet tier, owner decision 2026-10-02). Rural,
weather-prone links blip together: when ≥3 sites with an internet issue in
the last hour share an ISP (ASN), or sit within ~80 km of each other
(single-linkage over the resolved pins), each one's internet-issue reason is
held at NOTICE ("likely regional") — one fleet-level notice (`regional`)
instead of a ring of yellow pins. Only that reason: a WAN down, a gateway
offline and everything else keep their state. The ISP-outage correlator (hard
failures, its own incidents) is untouched.

CACHE + TIME BOUND. One model per data root, rebuilt at most every
`OCTO_FLEET_CACHE_SEC` (30 s; 0..300) — the console polls every 30 s, so a
fleet of viewers costs one build. One build at a time (single flight). A
build that runs past `OCTO_FLEET_BUILD_BUDGET_SEC` (5 s; 0.5..30) stops
reading tenant stores: the remaining tenants are listed from in-memory state
only, their store-backed layers UNKNOWN ("not read in time"), and the model
says `partial`.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.fleet import locations, sources
from apps.octo.fleet import state as fs
from apps.octo.ingest.timestamps import format_utc_ms

logger = logging.getLogger(__name__)

CACHE_ENV = "OCTO_FLEET_CACHE_SEC"
BUDGET_ENV = "OCTO_FLEET_BUILD_BUDGET_SEC"
DEFAULT_CACHE_SEC = 30.0
DEFAULT_BUDGET_SEC = 5.0
IPS_WINDOW = timedelta(hours=24)
REGIONAL_MIN_SITES = 3
REGIONAL_KM = 80.0
REGIONAL_TEXT_AREA = "internet trouble at nearby sites too — likely regional (weather/ISP)"
REGIONAL_TEXT_ISP = "internet trouble on this ISP at other sites too — likely regional " \
    "(weather/ISP)"
REGIONAL_NEUTRAL = "internet trouble in the area — likely regional (weather or provider)"


def _env_float(name: str, default: float, low: float, high: float) -> float:
    raw = os.environ.get(name)
    try:
        value = float(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(low, min(high, value))


def cache_seconds() -> float:
    return _env_float(CACHE_ENV, DEFAULT_CACHE_SEC, 0.0, 300.0)


def budget_seconds() -> float:
    return _env_float(BUDGET_ENV, DEFAULT_BUDGET_SEC, 0.5, 30.0)


def site_key(kind: str, ident: str) -> str:
    """Opaque, stable: never the console's hostId in a URL or a viewer's
    response."""
    return f"{kind[0]}-{hashlib.sha256(f'{kind}:{ident}'.encode()).hexdigest()[:20]}"


@dataclass
class Link:
    vendor: str
    label: str
    url: str
    verified: bool

    def as_dict(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "label": self.label, "url": self.url,
                "verified": self.verified}


@dataclass
class DattoPortal:
    """What the Datto site links are built from (read once per build)."""
    ids: dict[int, dict[str, dict[str, str]]] = field(default_factory=dict)
    """instance id → site uid → {id, name?} (`adapters.datto.site_ids.known`)."""
    labels: dict[tuple[int, str], str] = field(default_factory=dict)
    """(instance id, site uid) → the label the mapping was saved with."""


@dataclass
class SiteEntry:
    key: str
    kind: str                         # 'unifi' | 'tenant'
    tenant_slug: str
    tenant_name: str
    name: str
    console_name: str
    location: Optional[locations.Location]
    layers: dict[str, fs.Layer]
    verdict: fs.Verdict
    links: list[Link] = field(default_factory=list)
    unifi: Optional[dict[str, Any]] = None
    tenant_sites: int = 1
    partial: bool = False
    datto_note: Optional[str] = None
    client_name: Optional[str] = None
    """What a CLIENT user may read as the site's name (sources.UnifiSite
    .client_name); None → a neutral name (the API's rule)."""
    site_no: int = 1
    """1-based position among the tenant's sites (stable: by scope)."""
    incidents: list[Any] = field(default_factory=list)
    """The tenant's incidents painted on this site (open + closed ≤ 30 d,
    `threat.store.Incident`) — the API shapes them per caller."""
    unknown_location: set[int] = field(default_factory=set)
    """Ids among `incidents` whose device's site is not known (painted on
    every site of the tenant)."""


@dataclass
class FleetModel:
    generated_at: str
    sites: list[SiteEntry]
    partial: bool
    unmapped_unifi_sites: int
    isp_outages: list[dict[str, Any]]
    build_ms: int
    tenants: dict[str, str] = field(default_factory=dict)
    regional: list[dict[str, Any]] = field(default_factory=list)
    """Groups of sites whose internet issues were held at notice: {kind:
    'isp' | 'area', asn?, isp?, members: [{key, tenant}]} — the API filters
    the members per caller."""
    threat_incidents: list[dict[str, Any]] = field(default_factory=list)
    """Every OPEN Red / Black (shaped like `isp_outages`: the API filters
    per caller): tenant, id, tier, acked, opened_at, site keys, …"""
    blind: list[Any] = field(default_factory=list)
    """FR2: the detection sources Athena is blind to (`threat.intake.Blind`)."""
    dns_week: dict[str, int] = field(default_factory=dict)
    """A5 (v0.17.1): tenant → security-category DNS blocks over 7 days (HIGH
    + MEDIUM, known-benign and CSAM out) — the operators' "Threats stopped
    this week" (the API sums the caller's scope)."""


# ---------------------------------------------------------------------------
# Links (operators only — the API never sends one to a viewer)
# ---------------------------------------------------------------------------

def _unifi_link(record: Any, host_id: str, ref: Optional[str]) -> Optional[Link]:
    from apps.octo.adapters.unifi.adapter import LINK_SPEC, UniFiSourceAdapter
    from apps.octo.instances import vendor_links

    if not ref or record is None:
        return None
    settings = vendor_links.effective_settings(record.instance_config, LINK_SPEC)
    base = settings.portal_base_url or UniFiSourceAdapter.derive_portal_base({})
    # spec: the hostId keeps its ':' (`<hex>:<digits>` only) — '%3A' opens
    # "Access denied" on the portal (2026-10-08).
    url = vendor_links.build_url(base, settings.alert_path_template,
                                 {"alert_uid": host_id, "site_uid": ref}, spec=LINK_SPEC)
    return Link("unifi", "Open in UniFi Site Manager", url, LINK_SPEC.paths_verified) \
        if url else None


def _nextdns_link(record: Any, profile_id: str, name: str) -> Optional[Link]:
    from apps.octo.adapters.nextdns.adapter import LINK_SPEC, NextDNSSourceAdapter
    from apps.octo.instances import vendor_links

    if record is None:
        return None
    settings = vendor_links.effective_settings(record.instance_config, LINK_SPEC)
    base = settings.portal_base_url or NextDNSSourceAdapter.derive_portal_base({})
    url = vendor_links.build_url(base, settings.alert_path_template,
                                 {"alert_uid": profile_id, "site_uid": profile_id},
                                 spec=LINK_SPEC)
    return Link("nextdns", f"Open NextDNS logs — {name}", url, LINK_SPEC.paths_verified) \
        if url else None


def _datto_base(record: Any) -> Optional[str]:
    """The instance's Datto portal base (entered, else derived) or None."""
    from apps.octo.adapters.datto.adapter import DattoSourceAdapter
    from apps.octo.adapters.datto.links import LINK_SPEC
    from apps.octo.instances import vendor_links

    if record is None:
        return None
    settings = vendor_links.effective_settings(record.instance_config, LINK_SPEC)
    return settings.portal_base_url or DattoSourceAdapter.derive_portal_base(
        record.instance_config)


def _datto_site_link(record: Any, site_id: Optional[str], name: Optional[str]) -> Optional[Link]:
    """The Datto site's own page — ``/site/<numeric id>/<name slug>`` (path
    verified 2026-10-08) — from the id the inventory poller learned
    (`adapters.datto.site_ids`); None when the id or the base is not known."""
    from apps.octo.adapters.datto.links import site_portal_url

    url = site_portal_url(_datto_base(record), site_id, name) if site_id else None
    if not url:
        return None
    label = f"Open in Datto RMM — {name}" if name else f"Open in Datto RMM — site {site_id}"
    return Link("datto", label, url, True)


def _datto_home_link(record: Any) -> Optional[Link]:
    """The Datto RMM portal's HOME — only for a mapped site whose numeric id
    is not known yet (never a guessed site page), and labelled as such."""
    from apps.octo.instances import vendor_links

    base = _datto_base(record)
    url = vendor_links.build_url(base, "/", {}) if base else None
    return Link("datto", "Open Datto RMM (home)", url, False) if url else None


# ---------------------------------------------------------------------------
# The build
# ---------------------------------------------------------------------------

def _timed_out(name: str, scope: str = "site") -> fs.Layer:
    layer = fs.Layer(name, present=True, state=fs.UNKNOWN, scope=scope)
    layer.reasons.append(fs.Reason(fs.UNKNOWN, "not read within the page's time budget",
                                   "data not available right now", name))
    return layer


def build(manager: Any, *, now: Optional[datetime] = None,
          budget_sec: Optional[float] = None,
          clock: Callable[[], float] = time.monotonic) -> FleetModel:
    started = clock()
    now = now or datetime.now(timezone.utc)
    deadline = started + (budget_sec if budget_sec is not None else budget_seconds())
    active = sources.tenants()
    uf = sources.unifi_fleet(manager, active, now)
    dns = sources.nextdns_profiles(manager, active, now)
    rc = sources.rocketcyber_tenants(now)
    buoys = sources.buoy_health(now)
    overrides = locations.all_overrides()
    site_overrides = locations.all_site_overrides()
    records = {r.id: r for v in ("unifi", "nextdns", "datto") for r in sources.instances(v)}
    datto_sites: dict[str, set[tuple[int, str]]] = {}
    # The Datto sites' portal ids (learned by the inventory poller — a
    # registry read here, never a vendor call) and the mappings' labels.
    datto_portal = DattoPortal()
    for rec in sources.instances("datto"):
        if rec.disabled_at is not None:
            continue
        for site_uid, (slug, label) in sources.mappings(rec.id).items():
            if slug in active:
                datto_sites.setdefault(slug, set()).add((rec.id, site_uid))
                if label:
                    datto_portal.labels[(rec.id, site_uid)] = label
        datto_portal.ids[rec.id] = sources.datto_site_ids(rec.id)
    by_tenant: dict[str, list[sources.UnifiSite]] = {}
    for s in uf.sites:
        by_tenant.setdefault(s.slug, []).append(s)
    candidates = set(by_tenant) | set(dns) | {s for s in rc if s in active} \
        | set(datto_sites) | {s for s in buoys if s in active}
    # A tenant with no integration but an incident record (a B6 declared on
    # a client call) is on the fleet too: an incident is never invisible.
    candidates |= {s for s in active if s not in candidates
                   and sources.open_incidents(s, now).incidents}
    candidates = sorted(candidates)
    since = now - IPS_WINDOW
    entries: list[SiteEntry] = []
    partial = False
    threat = _threat_context(manager, now)
    week: dict[str, int] = {}
    for slug in candidates:
        tenant = active[slug]
        timed_out = clock() > deadline
        partial = partial or timed_out
        if not timed_out and dns.get(slug):
            try:
                week[slug] = sources.dns_week(slug, [p.profile_id for p in dns[slug]], now)
            except Exception as exc:  # noqa: BLE001 — a headline never fails a page
                logger.warning("[fleet] %s: weekly DNS count not read (%s)", slug,
                               type(exc).__name__)
        entries.extend(_tenant_entries(
            tenant, by_tenant.get(slug, []), dns.get(slug, []), slug in rc, rc.get(slug, False),
            datto_sites.get(slug, set()), buoys.get(slug), overrides.get(slug), records,
            since=since, now=now, timed_out=timed_out, site_overrides=site_overrides,
            threat=threat, datto_portal=datto_portal))
    regional = regional_collapse(entries)
    entries.sort(key=lambda e: sort_key(e))
    took = int((clock() - started) * 1000)
    if partial:
        logger.warning("[fleet] the fleet build ran past its %.1fs budget; the rest is listed "
                       "from in-memory state only", deadline - started)
    return FleetModel(
        generated_at=format_utc_ms(now), sites=entries, partial=partial,
        unmapped_unifi_sites=uf.unmapped, isp_outages=uf.outages, build_ms=took,
        tenants={slug: t.name for slug, t in active.items()},
        regional=regional, threat_incidents=threat_incidents(entries, now),
        blind=list(threat["blind"]), dns_week=week,
    )


def _open_black_unacked(e: SiteEntry) -> bool:
    return any(i.is_open and i.tier == "black" and not i.acked for i in e.incidents)


def sort_key(e: SiteEntry) -> tuple[Any, ...]:
    """Worst first, by RANK (a state the code adds later can never raise a
    KeyError here); within black, an unacknowledged Black first, then the
    oldest open incident; then by tenant and name."""
    oldest = min((i.detected_at or "" for i in e.incidents if i.is_open), default="~")
    return (-fs.RANK.get(e.verdict.state, fs.RANK[fs.UNKNOWN]),
            0 if _open_black_unacked(e) else 1, oldest,
            e.tenant_name.lower(), e.name.lower())


def _threat_context(manager: Any, now: datetime) -> dict[str, Any]:
    """What every tenant's threat layer shares: the worker's freshness, the
    blind sources (FR2), the operator names (who acknowledged)."""
    from apps.octo.threat import intake

    # The worker's freshness is read on its own: an intake-health fault must
    # never read as "the correlator is running" (stale never reads OK).
    try:
        worker = intake.worker_fresh(now)
    except Exception as exc:  # noqa: BLE001 — a page never fails for this
        logger.warning("[fleet] tier-worker heartbeat not read (%s)", type(exc).__name__)
        worker = False
    try:
        blind = intake.blind_sources(manager, now, check_worker=False)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[fleet] intake health not read (%s)", type(exc).__name__)
        blind = []
    return {"blind": blind, "worker_fresh": worker}


def threat_incidents(entries: list[SiteEntry], now: datetime) -> list[dict[str, Any]]:
    """Every open Red / Black once, with the site keys it is painted on and
    who acknowledged it BY NAME (the acknowledged Black pin's initials — an
    operator id would draw a digit)."""
    out: dict[tuple[str, int], dict[str, Any]] = {}
    names = sources.operator_display_names(
        {i.acknowledged_by for e in entries for i in e.incidents if i.is_open})
    for e in entries:
        for i in e.incidents:
            if not i.is_open:
                continue
            hidden = bool(getattr(i, "restricted", False))
            item = out.setdefault((e.tenant_slug, i.id), {
                "tenant": e.tenant_slug, "tenant_name": e.tenant_name, "id": i.id,
                "tier": i.tier, "status": i.status, "acked": i.acked,
                "acked_by": i.acknowledged_by,
                "acked_by_name": names.get(str(i.acknowledged_by or "")),
                "contained": i.contained,
                "opened_at": i.detected_at, "age_s": i.age_s(now),
                # A RESTRICTED incident (B7): no rule, summary or device for
                # any operator here — the admin-only detail has them.
                "rule_id": "restricted" if hidden else i.rule_id,
                "rule_version": 0 if hidden else i.rule_version,
                "summary": fs.RESTRICTED_TEXT if hidden else i.summary,
                "device_label": None if hidden else (i.device_label or i.device_ref),
                "restricted": hidden,
                "unknown_location": i.id in e.unknown_location and not hidden,
                "site_keys": []})
            item["site_keys"].append(e.key)
    return sorted(out.values(), key=lambda x: (0 if x["tier"] == "black" else 1,
                                               1 if x["acked"] else 0, x["opened_at"] or ""))


def _km(a: locations.Location, b: locations.Location) -> float:
    """Great-circle distance (haversine), km."""
    la1, lo1, la2, lo2 = map(math.radians, (a.lat, a.lng, b.lat, b.lng))
    h = math.sin((la2 - la1) / 2) ** 2 + \
        math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def regional_collapse(entries: list[SiteEntry]) -> list[dict[str, Any]]:
    """Hold the internet-issue reason of sites in a regional group at NOTICE
    (in place: their network layer and verdict) and describe the groups.
    A candidate: a UniFi site whose FRESH network layer has an internet
    issue in the last hour. A group: ≥3 candidates on one ASN, or ≥3 linked
    by ≤80 km hops between their pins."""
    cands = [e for e in entries if e.kind == "unifi" and e.layers["network"].present
             and e.layers["network"].state != fs.UNKNOWN
             and e.layers["network"].data.get("internet_issues_recent") is True]
    groups: list[dict[str, Any]] = []
    held: dict[str, str] = {}
    by_asn: dict[int, list[SiteEntry]] = {}
    for e in cands:
        asn = e.layers["network"].data.get("asn")
        if isinstance(asn, int) and not isinstance(asn, bool):
            by_asn.setdefault(asn, []).append(e)
    for asn, members in sorted(by_asn.items()):
        if len(members) >= REGIONAL_MIN_SITES:
            isp = next((m.layers["network"].data.get("isp") for m in members
                        if m.layers["network"].data.get("isp")), None)
            groups.append({"kind": "isp", "asn": asn, "isp": isp,
                           "members": [{"key": m.key, "tenant": m.tenant_slug} for m in members]})
            for m in members:
                held.setdefault(m.key, REGIONAL_TEXT_ISP)
    located = [e for e in cands if e.location is not None]
    parent = list(range(len(located)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(located)):
        for j in range(i + 1, len(located)):
            if _km(located[i].location, located[j].location) <= REGIONAL_KM:  # type: ignore[arg-type]
                parent[root(i)] = root(j)
    clusters: dict[int, list[SiteEntry]] = {}
    for i, e in enumerate(located):
        clusters.setdefault(root(i), []).append(e)
    for members in sorted(clusters.values(), key=lambda m: m[0].key):
        if len(members) >= REGIONAL_MIN_SITES:
            groups.append({"kind": "area", "km": REGIONAL_KM,
                           "members": [{"key": m.key, "tenant": m.tenant_slug} for m in members]})
            for m in members:
                held[m.key] = REGIONAL_TEXT_AREA
    for e in entries:
        text = held.get(e.key)
        if text and fs.cap_internet_issues(e.layers["network"], text, REGIONAL_NEUTRAL):
            e.verdict = fs.site_verdict(e.layers)
    return groups


def _tenant_entries(
    tenant: sources.Tenant,
    unifi_sites: list[sources.UnifiSite],
    profiles: list[sources.Profile],
    rc_mapped: bool,
    rc_fresh: bool,
    datto_mapped: set[tuple[int, str]],
    buoy: Optional[tuple[str, str]],
    override: Optional[dict[str, Any]],
    records: dict[int, Any],
    *,
    since: datetime,
    now: datetime,
    timed_out: bool,
    site_overrides: Optional[dict[str, dict[str, Any]]] = None,
    threat: Optional[dict[str, Any]] = None,
    datto_portal: Optional[DattoPortal] = None,
) -> list[SiteEntry]:
    from apps.octo.threat import registry as threat_registry

    slug = tenant.slug
    links_on = tenant.entity_mode == "on"
    threat = threat or {"blind": [], "worker_fresh": True}
    settings = threat_registry.settings(slug)
    # The incidents are read WHATEVER the time budget: an open Red / Black is
    # never dropped for time (a floor, P2).
    incidents = sources.open_incidents(slug, now)
    # ---- store-backed reads (skipped once the budget is spent) -------------
    ips: dict[str, tuple[int, int, int]] = {}
    threats: dict[str, sources.DnsCounts] = {}
    rc_open: Optional[int] = None
    inventory: Optional[list[sources.InventorySite]] = None
    site_links: dict[str, dict[str, set[str]]] = {}
    would_fire: dict[str, int] = {}
    touches: Optional[int] = None
    ips_hidden: dict[str, int] = {}
    ips_raw: dict[str, tuple[int, int, int]] = {}
    dns_hidden: dict[str, int] = {}
    other_hidden: dict[str, int] = {}
    if not timed_out:
        verdicts = _verdicts(slug, now)
        if unifi_sites:
            ips = sources.ips_counts(slug, since, verdicts=verdicts, hidden=ips_hidden,
                                     raw=ips_raw)
        if profiles:
            threats = sources.dns_threats(slug, [p.profile_id for p in profiles], since,
                                          verdicts=verdicts, hidden=dns_hidden)
        if rc_mapped:
            rc_open = sources.rocketcyber_open(slug, now, verdicts=verdicts, hidden=other_hidden)
        if datto_mapped:
            # Every Datto-mapped tenant's device list (v0.17.2, D).
            inventory = sources.datto_inventory(
                slug, server_grace_min=int(settings.get("server_offline_grace_min") or 0),
                now=now)
        if links_on and unifi_sites:
            site_links = sources.entity_links(slug)
        would_fire = sources.would_fire_counts(slug, now)
        if buoy is not None:
            touches = sources.canary_touches(slug, now, verdicts=verdicts, hidden=other_hidden)
    # Only links of THIS tenant's current UniFi sites count: a link whose
    # UniFi site is not on the fleet (instance disabled, mapping removed but
    # not reconciled yet) leaves its profile / Datto site tenant-level —
    # never dropped from every entry.
    own_scopes = {s.scope for s in unifi_sites}
    site_links = {scope: refs for scope, refs in site_links.items() if scope in own_scopes}
    linked_profiles = {p for refs in site_links.values() for p in refs.get("nextdns", set())}
    linked_datto = {d for refs in site_links.values() for d in refs.get("datto", set())}
    buoy_l = fs.buoy_layer(buoy[0] if buoy else None, as_of=buoy[1] if buoy else None,
                           canary_touches=touches)
    if buoy_l.present and other_hidden.get("canary"):
        buoy_l.data["canary_hidden_24h"] = other_hidden["canary"]
        # The count shown is every touch; only the Yellow left these out.
        buoy_l.data["canary_touches_24h"] = (touches or 0) + other_hidden["canary"]
    n_sites = max(1, len(unifi_sites))
    # Which incident sits on which entry: its home site, else every site of
    # the tenant ("device location unknown").
    keys = [site_key("unifi", s.scope) for s in unifi_sites] or [site_key("tenant", slug)]
    homed: dict[str, list[Any]] = {k: [] for k in keys}
    unknown: set[int] = set()
    for inc in incidents.incidents:
        if inc.site_key in homed:
            homed[inc.site_key].append(inc)
        else:
            unknown.add(inc.id)
            for k in keys:
                homed[k].append(inc)
    blind = [b for b in threat.get("blind", []) if b.covers(slug)]
    names = sources.operator_display_names({i.acknowledged_by for i in incidents.incidents})

    def threat_layer(key: str) -> fs.Layer:
        return fs.threat_layer(
            homed.get(key, []), now=now, worker_fresh=bool(threat.get("worker_fresh", True)),
            blind=blind, would_fire=would_fire, stale_since=incidents.stale_since,
            unreadable=not incidents.ok, unknown_location=unknown, names=names,
            watch_days=int(settings.get("watch_days") or 7))

    def security(site: Optional[sources.UnifiSite]) -> fs.Layer:
        if site is not None:
            mine = site_links.get(site.scope, {}).get("nextdns", set())
            shown = [p for p in profiles if p.profile_id in mine or
                     p.profile_id not in linked_profiles]
            dns_scope = "site" if shown and all(p.profile_id in mine for p in shown) \
                else "tenant"
        else:
            shown, dns_scope = list(profiles), "tenant"
        if timed_out and (site is not None or shown or rc_mapped):
            return _timed_out("security")
        ips_part = None
        if site is not None:
            det, blk, blk_in = ips.get(site.scope, (0, 0, 0))
            ips_part = fs.IpsPart(det, blk, site.syslog_fresh, blocked_inbound=blk_in)
        none = sources.DnsCounts(0, 0, 0, 0)
        dns_parts = [fs.DnsProfile(p.profile_id, p.name, p.state, p.missing, p.fresh,
                                   threats.get(p.profile_id, none).total,
                                   threats_high=threats.get(p.profile_id, none).high,
                                   threats_medium=threats.get(p.profile_id, none).medium,
                                   threats_benign=threats.get(p.profile_id, none).benign,
                                   threats_bypass=threats.get(p.profile_id, none).bypass,
                                   pending_since=sources.dt(p.since) if p.since else None,
                                   top_reasons=threats.get(p.profile_id, none).reasons,
                                   devices=threats.get(p.profile_id, none).devices,
                                   originated_unattributed=threats.get(
                                       p.profile_id, none).originated_unattributed)
                     for p in shown]
        rc_part = None
        if rc_mapped:
            rc_part = fs.RcPart(rc_open or 0, rc_fresh and rc_open is not None)
        layer = fs.security_layer(ips=ips_part, dns=dns_parts, dns_scope=dns_scope,
                                  rc=rc_part, now=now, settings=settings)
        layer.data["rc_scope"] = "tenant" if rc_mapped else None
        # The COUNTS shown (to a client user too) are every hit / incident —
        # the facts; only the state and its reasons leave out what a human
        # acknowledged / expected. Operators also see how many that was.
        if site is not None and site.scope in ips_raw:
            det, blk, blk_in = ips_raw[site.scope]
            for k, v in (("ips_detected_24h", det), ("ips_blocked_24h", blk),
                         ("ips_blocked_inbound_24h", min(blk_in, blk))):
                if k in layer.data:
                    layer.data[k] = v
        if site is not None and ips_hidden.get(site.scope):
            layer.data["ips_hidden_24h"] = ips_hidden[site.scope]
        dns_gone = sum(dns_hidden.get(p.profile_id, 0) for p in shown)
        if dns_gone:
            layer.data["dns_hidden_24h"] = dns_gone
        if rc_mapped and other_hidden.get("rocketcyber"):
            layer.data["rc_hidden"] = other_hidden["rocketcyber"]
            if "open_incidents" in layer.data and rc_open is not None:
                layer.data["open_incidents"] = rc_open + other_hidden["rocketcyber"]
        return layer

    def endpoints(site: Optional[sources.UnifiSite]) -> tuple[fs.Layer, Optional[str]]:
        if not datto_mapped:
            return fs.endpoints_layer(None), None
        if timed_out:
            return _timed_out("endpoints"), None
        if inventory is None:
            return fs.endpoints_layer(None), "no Datto inventory read yet"
        mine = site_links.get(site.scope, {}).get("datto", set()) if site else set()
        rows = [r for r in inventory if (r.instance_id, r.site_uid) in datto_mapped
                and (r.site_uid in mine or r.site_uid not in linked_datto)]
        if not rows:
            return fs.endpoints_layer(None), "no Datto devices for this site"
        scope = "site" if rows and all(r.site_uid in mine for r in rows) else "tenant"
        fresh = all(sources.fresh(r.updated_at,
                                  sources.datto_inventory_interval(records.get(r.instance_id)),
                                  now)
                    for r in rows)
        inv = fs.Inventory(sum(r.total for r in rows), sum(r.online for r in rows),
                           sum(r.offline for r in rows), sum(r.servers_offline for r in rows),
                           fresh)
        return fs.endpoints_layer(inv, as_of=max((r.updated_at or "") for r in rows) or None,
                                  scope=scope), None

    def links(site: Optional[sources.UnifiSite], layer_sec: fs.Layer) -> list[Link]:
        out: list[Link] = []
        if site is not None:
            link = _unifi_link(records.get(site.instance_id), site.host_id, site.internal_ref)
            if link:
                out.append(link)
        for p in (layer_sec.data.get("dns_profiles") or []):
            prof = next((x for x in profiles if x.profile_id == p["profile_id"]), None)
            if prof is not None:
                link = _nextdns_link(records.get(prof.instance_id), prof.profile_id, prof.name)
                if link:
                    out.append(link)
        # Datto: one link per Datto site on this entry (the endpoints rule:
        # linked to this site, or linked to none of the tenant's sites) — its
        # own page when its numeric id is known, else the portal home (once).
        mine = site_links.get(site.scope, {}).get("datto", set()) if site else set()
        portal = datto_portal or DattoPortal()
        pages: list[Link] = []
        homes: list[Link] = []
        for inst, uid in sorted(datto_mapped):
            if uid not in mine and uid in linked_datto:
                continue
            record = records.get(inst)
            known = portal.ids.get(inst, {}).get(uid) or {}
            name = known.get("name") or portal.labels.get((inst, uid))
            link = _datto_site_link(record, known.get("id"), name)
            if link is None:
                link = _datto_home_link(record)
                bucket = homes
            else:
                bucket = pages
            if link and all(x.url != link.url for x in out + pages + homes):
                bucket.append(link)
        out.extend(sorted(pages, key=lambda x: (x.label.lower(), x.url)))
        out.extend(homes)
        return out

    out: list[SiteEntry] = []
    for site_no, site in enumerate(unifi_sites or [None], start=1):  # type: ignore[list-item]
        if site is not None:
            network = fs.network_layer(site.health, fresh=site.fleet_fresh, as_of=site.fleet_at,
                                       settings=settings)
            if site.health is None:
                network.present = True
                network.state = fs.UNKNOWN
                network.reasons = [fs.Reason(fs.UNKNOWN, "UniFi has not reported this site yet",
                                             "network data not reported yet", "network")]
        else:
            network = fs.network_layer(None, fresh=False)
        sec = security(site)
        end, note = endpoints(site)
        key = site_key("unifi", site.scope) if site is not None else site_key("tenant", slug)
        layers = {"threat": threat_layer(key), "network": network, "security": sec,
                  "endpoints": end, "buoy": buoy_l}
        verdict = fs.site_verdict(layers)
        if site is not None:
            loc = locations.resolve(
                site.location, override,
                site=locations.site_override_for(site_overrides or {}, key, slug),
                fallback_label=site.name, console_sites=site.console_sites,
                console_shared=site.console_shared)
            unifi = {"instance_id": site.instance_id, "scope": site.scope,
                     "host_id": site.host_id, "site_id": site.site_id,
                     "problem": site.problem, "console_sites": site.console_sites,
                     # What the console REPORTS, even when an override pins
                     # the site elsewhere — the location editors show it.
                     "console_location": locations.from_unifi(site.location, site.name),
                     "console_shared": site.console_shared}
            name, console, client_name = site.name, site.console_name, site.client_name
        else:
            loc = locations.resolve(
                None, override, site=locations.site_override_for(site_overrides or {}, key, slug),
                fallback_label=tenant.name)
            unifi = None
            name, console, client_name = tenant.name, "", None
        out.append(SiteEntry(
            key=key, kind="unifi" if site is not None else "tenant", tenant_slug=slug,
            tenant_name=tenant.name, name=name, console_name=console, location=loc,
            layers=layers, verdict=verdict, links=links(site, sec), unifi=unifi,
            tenant_sites=n_sites, partial=timed_out, datto_note=note,
            client_name=client_name, site_no=site_no,
            incidents=list(homed.get(key, [])),
            unknown_location={i.id for i in homed.get(key, []) if i.id in unknown},
        ))
    return out


def _verdicts(slug: str, now: datetime) -> Any:
    """The tenant's acknowledgements and live expected conditions — None
    when they cannot be read (then nothing is hidden: louder, never
    quieter)."""
    from apps.octo.verdicts.state import TenantVerdicts

    try:
        return TenantVerdicts.load(slug, now)
    except Exception as exc:  # noqa: BLE001 — a page never fails for this
        logger.warning("[fleet] verdicts of %s not read (%s)", slug, type(exc).__name__)
        return None


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_cache: dict[str, tuple[float, FleetModel]] = {}


def get_model(manager: Any, *, now: Optional[datetime] = None,
              clock: Callable[[], float] = time.monotonic) -> FleetModel:
    """The cached model for this data root (single flight: one build at a
    time; a caller waiting on a build gets that build)."""
    key = str(paths.registry_db_path())
    ttl = cache_seconds()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and ttl > 0 and clock() - hit[0] < ttl:
            return hit[1]
        model = build(manager, now=now, clock=clock)
        _cache[key] = (clock(), model)
        return model


def invalidate() -> None:
    with _lock:
        _cache.clear()
