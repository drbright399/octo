"""The worst-state calculator — one verdict per LAYER, the site's worst is
the pin colour.

States, worst first (design 2026-10-02, section 2): `black` > `bad` (Red) >
`warn` (Yellow) > `unknown` (grey, stale) > `notice` (grey) > `ok`. The wire
codes `warn` / `bad` stay (the API contract does not churn); only `black` is
new.

RED AND BLACK COME ONLY FROM INCIDENT RECORDS (P1). The THREAT layer (first
in LAYERS, so it wins a tie) reads the tenant's incidents — opened by a rule
or a person, closed only by a person — and is the only layer that can say
`bad` or `black`. The four HEALTH layers (network, security, endpoints,
buoy) are capped at Yellow: none of their reasons emits Red any more (an
outage, a protection gap, a single alert are never Red or Black), and
`_finish()` clamps anything above HEALTH_CEILING again — logged — so a future
reason cannot slip past it (`test_health_layers_never_red_or_black`).

UNKNOWN outranks ok and notice: data older than two polls of its feed (or
never read) is unknown, never ok and never a notice — a stale layer can hide
a problem, so a site with one fresh-ok layer and one stale layer is unknown,
not green. The threat layer is NEVER unknown while an incident is open (P2:
incidents are a floor — a stale feed, a stale worker or an unreadable store
never lowers one). A layer that does not apply to the site (no NextDNS
profile, no buoy) is ABSENT and takes no part. A site with no present layer
is unknown.

NOTICE — the quiet tier (owner decision 2026-10-02): something worth SEEING
that is not worth a tech's attention. It is listed (grey) in the drawer and
the list but does NOT colour the pin: yellow means "a tech should look".

Each reason carries two texts: `text` for operators (names the vendor:
"NextDNS lapsed") and `neutral` for a client user (never a vendor name:
"DNS protection lapsed"); `operator_only` reasons are dropped from a client
user's view altogether (WAN2 not configured, shadow would-fires, …).

Layers (re-tier table, design section 3):
  threat     open Black → black (pulse until acknowledged); open Red → bad;
             a true-positive close inside its watch (7 d, tunable 3–30) →
             warn "post-incident watch"; closed ≤ 30 d → notice; detection
             blindness (FR2) → warn when the tenant's own, notice when
             fleet-wide; shadow would-fires → notice (operators only); no open
             incident and the tier worker stale → unknown.
  network    UniFi /v1/sites statistics (+ /v1/hosts state): console offline,
             gateway offline, every WAN down, the PRIMARY WAN down on backup,
             wired devices offline, recurring internet issues, critical
             notifications → warn; a single internet blip, access points
             offline, a configured BACKUP line down, a WAN2 that was never
             configured (operators only) → notice.
  security   UniFi IPS 24 h (detected-not-blocked → warn either way; blocked
             inbound → notice, outbound / unknown direction → warn — N7);
             NextDNS per profile (lapsed, missing → warn; pending → notice for
             ≤ 7 d after it began, then warn); DNS threat blocks 24 h — "a
             block is NextDNS doing its job" (Rick, 2026-10-06): the count is
             a NOTICE ("N threats blocked today"); WARN only when a DEVICE
             looks wrong — HIGH blocks in ≥ 3 (tunable) distinct clock hours
             on one device, or ANY block in a device-originated reason (DGA,
             tunneling, exfiltration, payload delivery); CSAM is never here
             (rule B7, a restricted Black); RocketCyber open incidents →
             warn. Each part stale → that part unknown.
  endpoints  Datto inventory: a server offline → warn; workstations offline
             are counted, never a verdict (people switch PCs off at night).
  buoy       the heartbeat rollup (yellow → warn, red → warn, stale →
             unknown) + decoy (canary) touches in 24 h → warn.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

OK, NOTICE, WARN, BAD, UNKNOWN, BLACK = "ok", "notice", "warn", "bad", "unknown", "black"
STATES = (OK, NOTICE, WARN, BAD, UNKNOWN, BLACK)
RANK = {OK: 0, NOTICE: 1, UNKNOWN: 2, WARN: 3, BAD: 4, BLACK: 5}
# Every health layer stops at Yellow; Red and Black are the threat layer's.
HEALTH_CEILING = WARN
HEALTH_LAYERS = ("network", "security", "endpoints", "buoy")
LAYERS = ("threat",) + HEALTH_LAYERS
# Recurring internet trouble: this many new issue entries in the last hour,
# or new entries on this many consecutive fleet polls, warn; fewer = notice.
ISSUES_RECUR_ENTRIES = 3
ISSUES_RECUR_POLLS = 3
REASON_INTERNET_ISSUES = "internet_issues"
REASON_WAN_COVERAGE = "wan_coverage"
REASON_INCIDENT = "incident"
REASON_SHADOW = "shadow"
REASON_BLIND = "blind"
REASON_WORKER = "worker"
RECENT_CLOSE = timedelta(days=30)
# What every operator's Fleet says about a RESTRICTED incident (B7, CSAM):
# the incident itself is admin-only (`threat.restricted`).
RESTRICTED_TEXT = "restricted incident — admins only"
# The Yellow / Notice knobs (`threat.registry.KNOBS` bounds them; none can
# name Red or Black).
KNOB_DEFAULTS: dict[str, Any] = {
    "issues_recur_entries": ISSUES_RECUR_ENTRIES,
    "server_offline_grace_min": 0,
    # (v0.17.1: `dns_medium_level` is RETIRED — the DNS block count is always
    # a Notice, Rick's A1 "no WARN merely because blocks happened"; a value
    # stored under v0.17 is ignored, never reinterpreted.)
    # A2a (Rick, 2026-10-06): HIGH-risk DNS blocks on ONE device in this many
    # distinct clock hours within 24 h — beaconing — make it Yellow.
    "dns_beacon_hours": 3,
    "ips_inbound_blocked_level": NOTICE,
    "nextdns_pending_days": 7,
    "watch_days": 7,
    # Re-tier rows 5 and 11: Yellow by default, tunable down to Notice.
    "primary_on_backup_level": WARN,
    "critical_notifications_level": WARN,
}


def knob(settings: Optional[dict[str, Any]], key: str) -> Any:
    value = (settings or {}).get(key, KNOB_DEFAULTS[key])
    if key.endswith("_level") and value not in (NOTICE, WARN):
        return KNOB_DEFAULTS[key]                      # a knob never names Red / Black
    return value


@dataclass(frozen=True)
class Reason:
    state: str
    text: str
    neutral: str
    layer: str = ""
    code: str = ""
    """Internal: what kind of reason (e.g. REASON_INTERNET_ISSUES) — lets
    the build cap one kind; never sent to a caller."""
    operator_only: bool = False
    """Dropped from a client user's view (and their verdict)."""
    incident_id: Optional[int] = None
    """The incident a threat reason is about — a client user sees it only
    once the incident is visible to them (`threat.client_view`)."""

    def as_dict(self, *, neutral: bool = False) -> dict[str, str]:
        return {"state": self.state, "text": self.neutral if neutral else self.text,
                "layer": self.layer}


@dataclass
class Layer:
    name: str
    present: bool = False
    state: str = UNKNOWN
    reasons: list[Reason] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    as_of: Optional[str] = None
    scope: str = "site"
    """'site' (this site's own data) or 'tenant' (the client's, shown on each
    of its sites: RocketCyber, NextDNS without a site link, …)."""


def worst(states: Iterable[str]) -> str:
    """The worst of `states` (black > bad > warn > unknown > notice > ok);
    unknown when empty."""
    out: Optional[str] = None
    for s in states:
        if s not in RANK:
            s = UNKNOWN
        if out is None or RANK[s] > RANK[out]:
            out = s
    return out if out is not None else UNKNOWN


def _finish(layer: Layer, parts: list[str]) -> Layer:
    if layer.name in HEALTH_LAYERS:
        clamped = [r for r in layer.reasons if RANK.get(r.state, 0) > RANK[HEALTH_CEILING]]
        if clamped or any(RANK.get(p, 0) > RANK[HEALTH_CEILING] for p in parts):
            # P1: a health condition is never Red or Black. Logged — it means
            # a reason generator emitted what it must not.
            logger.warning("[fleet] %s layer clamped to %s: %s", layer.name, HEALTH_CEILING,
                           [r.text for r in clamped] or parts)
            layer.reasons = [Reason(HEALTH_CEILING, r.text, r.neutral, r.layer, r.code,
                                    r.operator_only, r.incident_id)
                             if RANK.get(r.state, 0) > RANK[HEALTH_CEILING] else r
                             for r in layer.reasons]
            parts = [HEALTH_CEILING if RANK.get(p, 0) > RANK[HEALTH_CEILING] else p
                     for p in parts]
            layer.data["clamped"] = True
    layer.state = worst(parts) if parts else UNKNOWN
    layer.reasons.sort(key=lambda r: -RANK[r.state])
    return layer


def _n(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _plural(n: int, word: str, plural: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _parse(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Network (UniFi)
# ---------------------------------------------------------------------------

def _is_v4_wan(w: Any) -> bool:
    return isinstance(w, dict) and bool(w.get("wan")) and \
        not str(w.get("wan")).endswith(("/v6", "/pd"))


def primary_wan(wans: Iterable[dict[str, Any]]) -> Optional[str]:
    """The site's PRIMARY internet connection: a WAN whose `role` says so;
    else the one with the lowest UniFi failover priority; without priorities,
    the one named WAN / WAN1; else the first by name. Every other WAN is a
    BACKUP — nice to have, never by itself grounds for a warning (owner
    decision, 2026-10-02: many clients have no second line, and WAN2 "down"
    was most of the Fleet's yellow)."""
    ws = [w for w in wans if _is_v4_wan(w)]
    if not ws:
        return None
    roled = [w for w in ws if w.get("role") == "primary"]
    if roled:
        return str(roled[0]["wan"])
    prio = [w for w in ws if isinstance(w.get("failover_priority"), int)]
    if prio:
        return str(min(prio, key=lambda w: (w["failover_priority"], str(w["wan"])))["wan"])
    for name in ("WAN", "WAN1"):
        if any(str(w["wan"]) == name for w in ws):
            return name
    return str(sorted(str(w["wan"]) for w in ws)[0])


def wan_edges(wans: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The site's internet edge, VENDOR-AGNOSTIC — what a UniFi, SonicWall or
    Cisco adapter fills: [{name, role 'primary' | 'backup', configured
    (True / False / None = not known), up (True / False / None), asn, isp}].
    A UniFi WAN carries `role` / `configured` from the poller (matched to
    /v1/hosts reportedState.wans: plugged / an IPv4); older snapshots fall
    back to failover priority and `port_up`. `isp` is the WAN's OWN provider
    only — never the site-level one a vendor reports for the primary (the
    poller marks a borrowed name `isp_from: 'site'`)."""
    ws = [w for w in wans if _is_v4_wan(w)]
    primary = primary_wan(ws)
    out = []
    for w in ws:
        up = w.get("up") if isinstance(w.get("up"), bool) else \
            (w.get("port_up") if isinstance(w.get("port_up"), bool) else None)
        configured = w.get("configured") if isinstance(w.get("configured"), bool) else None
        if up is True:
            configured = True                      # a line that is up is configured
        out.append({"name": str(w["wan"]),
                    "role": w.get("role") if w.get("role") in ("primary", "backup")
                    else ("primary" if str(w["wan"]) == primary else "backup"),
                    "configured": configured, "up": up,
                    "asn": w.get("asn") if isinstance(w.get("asn"), int) else None,
                    "isp": (w.get("isp") or None) if w.get("isp_from") != "site" else None})
    return out


def backup_coverage(edges: list[dict[str, Any]]) -> Optional[bool]:
    """True: a configured backup line exists; False: none (a single-port
    gateway, or a WAN2 never configured); None: not known."""
    backups = [e for e in edges if e["role"] == "backup"]
    if any(e["configured"] is True for e in backups):
        return True
    if any(e["configured"] is None for e in backups):
        return None
    return False


def network_layer(site: Optional[dict[str, Any]], *, fresh: bool,
                  as_of: Optional[str] = None,
                  settings: Optional[dict[str, Any]] = None) -> Layer:
    """`site`: the UniFi fleet health of ONE site (`host_connected`,
    `gateway_online`, `wans[]`, `stats{}`), None for a tenant-level entry
    (absent). `fresh`: the last fleet poll is at most two intervals old."""
    layer = Layer("network", as_of=as_of)
    if site is None:
        return layer
    layer.present = True
    stats = site.get("stats") if isinstance(site.get("stats"), dict) else {}
    wans = [w for w in (site.get("wans") or []) if _is_v4_wan(w)]
    edges = wan_edges(wans)
    total = _n(stats.get("devices_total"))
    offline = _n(stats.get("devices_offline"))
    gw_off = _n(stats.get("gateways_offline"))
    issues = _n(stats.get("internet_issues")) or 0
    # The issue lists may be HISTORIES: only an entry that appeared in the
    # last hour (the poller compares fresh polls) is a verdict; the count
    # is shown either way.
    issues_recent = stats.get("issues_recent") is True
    issues_recent_count = _n(stats.get("issues_recent_count")) or 0
    issues_streak = _n(stats.get("issues_streak")) or 0
    wifi_off = _n(stats.get("devices_offline_wifi"))
    wired_off = _n(stats.get("devices_offline_wired"))
    critical = _n(stats.get("critical_notifications")) or 0
    wan_up = [e["name"] for e in edges if e["up"] is True]
    # A WAN nobody connected (configured False: WAN2 enabled, never plugged
    # in / addressed) is not "down" — it is coverage, said below; counting it
    # would make an unknown primary + an unused WAN2 read "every WAN down".
    wan_down = [e["name"] for e in edges if e["up"] is False and e["configured"] is not False]
    wan_unconfigured = [e["name"] for e in edges if e["configured"] is False]
    primary = primary_wan(wans)
    backup_down = [w for w in wan_down if w != primary]
    coverage = backup_coverage(edges)
    layer.data = {
        "devices_total": total,
        "devices_online": (total - offline) if total is not None and offline is not None
        else None,
        "devices_offline": offline,
        "gateway_online": site.get("gateway_online"),
        "console_online": site.get("host_connected"),
        "wan_up": wan_up, "wan_down": wan_down, "wan_unconfigured": wan_unconfigured,
        "wan_primary": primary, "backup_down": backup_down,
        "wans": edges, "has_backup": coverage,
        "isp": stats.get("isp_name") or next((w.get("isp") for w in wans if w.get("isp")), None),
        "asn": stats.get("isp_asn"),
        "internet_issues": issues,
        "internet_issues_recent": issues_recent,
        "internet_issues_recent_count": issues_recent_count,
        "devices_offline_wifi": wifi_off,
        "devices_offline_wired": wired_off,
        "pending_updates": _n(stats.get("pending_updates")),
        "critical_notifications": critical,
    }
    if not fresh:
        layer.reasons.append(Reason(UNKNOWN, "UniFi data is stale (no fresh fleet poll)",
                                    "network data is out of date", "network"))
        return _finish(layer, [UNKNOWN])
    parts = [OK]
    # Outages are Yellow (re-tier rows 2–4): an outage is never a threat.
    if site.get("host_connected") is False:
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, "console offline", "network gateway unreachable",
                                    "network"))
    if gw_off:
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, "gateway offline", "network gateway offline",
                                    "network"))
    if wan_down and not wan_up:
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, "WAN down", "internet connection down", "network"))
    elif primary is not None and primary in wan_down:
        # The PRIMARY line is down and a backup carries the site: worth a
        # look (re-tier row 5: Yellow, tunable to Notice).
        level = knob(settings, "primary_on_backup_level")
        parts.append(level)
        text = f"{primary} down — running on backup ({', '.join(wan_up)})"
        layer.reasons.append(Reason(level, text, "backup internet connection in use",
                                    "network"))
    for e in edges:
        if e["role"] != "backup":
            continue
        if e["configured"] is False:
            # WAN coverage (Rick, 2026-10-02 23:52): a WAN2 enabled but never
            # plugged in / addressed — coverage, not trouble. Operators only.
            parts.append(NOTICE)
            layer.reasons.append(Reason(NOTICE, f"{e['name']} not configured",
                                        "no backup internet line", "network",
                                        REASON_WAN_COVERAGE, operator_only=True))
        elif e["configured"] is True and e["up"] is False and wan_up:
            # A configured backup line that dropped while the primary carries
            # the site: seen, not a tech's emergency.
            isp = f" ({e['isp']})" if e.get("isp") else ""
            parts.append(NOTICE)
            layer.reasons.append(Reason(NOTICE, f"backup line down{isp}",
                                        "backup internet line down", "network",
                                        REASON_WAN_COVERAGE))
    others = (offline or 0) - (gw_off or 0)
    if others > 0 and wifi_off is not None and wired_off is not None:
        # UniFi's split: an access point offline is a notice (one AP down
        # is rarely a tech's emergency); a wired device — a switch, which
        # takes its ports with it — warns. Offline devices of no known kind
        # (counts that do not add up) warn with the wired ones.
        wired = wired_off + max(0, others - wifi_off - wired_off)
        if wired:
            parts.append(WARN)
            layer.reasons.append(Reason(WARN, f"{_plural(wired, 'wired device')} offline",
                                        f"{_plural(wired, 'network device')} offline",
                                        "network"))
        if wifi_off:
            parts.append(NOTICE)
            layer.reasons.append(Reason(NOTICE, f"{_plural(wifi_off, 'access point')} offline",
                                        f"{_plural(wifi_off, 'wireless access point')} offline",
                                        "network"))
    elif others > 0:
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, f"{_plural(others, 'device')} offline",
                                    f"{_plural(others, 'network device')} offline", "network"))
    if issues_recent:
        recur_entries = knob(settings, "issues_recur_entries")
        recurring = issues_recent_count >= recur_entries or \
            issues_streak >= ISSUES_RECUR_POLLS
        if recurring:
            parts.append(WARN)
            n = max(issues_recent_count, issues_streak)
            layer.reasons.append(Reason(
                WARN, f"internet issues keep recurring ({n} in the last hour)",
                "internet connection unstable in the last hour", "network",
                REASON_INTERNET_ISSUES))
        else:
            parts.append(NOTICE)
            layer.reasons.append(Reason(NOTICE, "internet blip in the last hour",
                                        "brief internet interruption in the last hour",
                                        "network", REASON_INTERNET_ISSUES))
        layer.data["internet_issues_level"] = WARN if recurring else NOTICE
    if critical:
        # Re-tier row 11: vendor-rated, not a threat verdict — Yellow,
        # tunable to Notice.
        level = knob(settings, "critical_notifications_level")
        parts.append(level)
        layer.reasons.append(Reason(level, f"{_plural(critical, 'critical notification')}",
                                    f"{_plural(critical, 'critical network notification')}",
                                    "network"))
    return _finish(layer, parts)


# ---------------------------------------------------------------------------
# Security (UniFi IPS, NextDNS, RocketCyber)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IpsPart:
    detected: int
    blocked: int
    fresh: bool
    blocked_inbound: int = 0
    """N7: of `blocked`, the hits blocked on the way IN (prevention worked
    at the edge → notice). The rest — outbound, or a direction not known
    (rows coalesced before N7) — stays Yellow."""


@dataclass(frozen=True)
class DnsProfile:
    profile_id: str
    name: str
    state: str                 # active | pending | new | lapsed
    missing: bool
    fresh: bool
    threats_24h: int = 0
    threats_high: Optional[int] = None
    """N8: blocks with a HIGH reason (known-benign probes taken out). None =
    not split (an older caller): every threat counts as HIGH."""
    threats_medium: int = 0
    """MEDIUM / LOW reasons only."""
    threats_benign: int = 0
    """Blocks a known-benign rule matched (the Samsung probe)."""
    threats_bypass: int = 0
    """v0.17.1: filter-bypass blocks (VPN / proxy / Tor / Private Relay) —
    policy, not a threat; never in a threat count."""
    pending_since: Optional[datetime] = None
    """When a pending profile became pending (the poller's `since`)."""
    top_reasons: tuple[tuple[str, int], ...] = ()
    """v0.17.1: the window's HIGH / MEDIUM reasons by count (no CSAM) — the
    operator's "top reasons"."""
    devices: tuple[Any, ...] = ()
    """v0.17.1: per-device ledger views (`sources.DnsDevice`: name,
    high_hours, originated) — "the device looks wrong"."""
    originated_unattributed: tuple[tuple[str, int], ...] = ()
    """Device-originated reasons counted with no device named."""


@dataclass(frozen=True)
class RcPart:
    open_incidents: int
    fresh: bool


def security_layer(
    *,
    ips: Optional[IpsPart],
    dns: list[DnsProfile],
    dns_scope: str = "site",
    rc: Optional[RcPart],
    as_of: Optional[str] = None,
    now: Optional[datetime] = None,
    settings: Optional[dict[str, Any]] = None,
) -> Layer:
    layer = Layer("security", as_of=as_of)
    now = now or datetime.now(timezone.utc)
    parts: list[str] = []
    if ips is not None:
        layer.present = True
        layer.data["ips_detected_24h"] = ips.detected
        layer.data["ips_blocked_24h"] = ips.blocked
        if not ips.fresh:
            parts.append(UNKNOWN)
            layer.reasons.append(Reason(UNKNOWN, "UniFi system log not read recently",
                                        "intrusion prevention data is out of date", "security"))
        else:
            parts.append(OK)
            if ips.detected:
                # Re-tier row 13: detected-not-blocked is Yellow, both ways —
                # one sensor's word (R3 needs TI on a completed connection).
                parts.append(WARN)
                layer.reasons.append(Reason(
                    WARN, f"{_plural(ips.detected, 'IPS detection')} NOT blocked today",
                    f"{_plural(ips.detected, 'intrusion')} detected and not blocked today",
                    "security"))
            inbound = min(max(0, ips.blocked_inbound), ips.blocked)
            rest = ips.blocked - inbound
            if rest:
                parts.append(WARN)
                layer.reasons.append(Reason(
                    WARN, f"{_plural(rest, 'IPS block')} today",
                    f"{_plural(rest, 'intrusion attempt')} blocked today", "security"))
            if inbound:
                level = knob(settings, "ips_inbound_blocked_level")
                parts.append(level)
                layer.reasons.append(Reason(
                    level, f"{_plural(inbound, 'inbound IPS block')} today",
                    f"{_plural(inbound, 'intrusion attempt')} from outside blocked today",
                    "security"))
            layer.data["ips_blocked_inbound_24h"] = inbound
    if dns:
        layer.present = True
        threats = sum(p.threats_24h for p in dns)
        layer.data["dns_profiles"] = [
            {"profile_id": p.profile_id, "name": p.name, "state": _dns_state(p),
             "threats_24h": p.threats_24h, "fresh": p.fresh} for p in dns]
        layer.data["dns_scope"] = dns_scope
        layer.data["dns_threats_24h"] = threats
        pending_days = knob(settings, "nextdns_pending_days")
        for p in dns:
            state = _dns_state(p)
            if not p.fresh:
                parts.append(UNKNOWN)
                layer.reasons.append(Reason(UNKNOWN, f"NextDNS {p.name}: not checked recently",
                                            "DNS protection data is out of date", "security"))
                continue
            if state == "lapsed":
                # Re-tier row 16: a protection gap is Yellow, never Red.
                parts.append(WARN)
                layer.reasons.append(Reason(WARN, f"NextDNS lapsed ({p.name})",
                                            "DNS protection lapsed", "security"))
            elif state == "missing":
                parts.append(WARN)
                layer.reasons.append(Reason(WARN, f"NextDNS profile missing ({p.name})",
                                            "DNS protection not found", "security"))
            elif state == "pending":
                since = _parse(p.pending_since)
                young = since is not None and now - since <= timedelta(days=pending_days)
                # Onboarding takes days: a newly pending profile is a notice
                # for its first days (when it began is KNOWN), then Yellow.
                level = NOTICE if young else WARN
                parts.append(level)
                layer.reasons.append(Reason(
                    level, f"NextDNS pending ({p.name})" + (" — newly mapped" if young else ""),
                    "DNS protection not confirmed yet", "security"))
            else:
                parts.append(OK)
        if any(p.fresh for p in dns):
            _dns_blocks(layer, parts, dns, settings)
    if rc is not None:
        layer.present = True
        layer.data["open_incidents"] = rc.open_incidents
        if not rc.fresh:
            parts.append(UNKNOWN)
            layer.reasons.append(Reason(UNKNOWN, "RocketCyber not polled recently",
                                        "security incident data is out of date", "security"))
        elif rc.open_incidents:
            # Re-tier row 21: tenant-wide, no device, one source — Yellow.
            parts.append(WARN)
            layer.reasons.append(Reason(
                WARN, f"{_plural(rc.open_incidents, 'open RocketCyber incident')}",
                f"{_plural(rc.open_incidents, 'open security alert')}", "security"))
        else:
            parts.append(OK)
    if not layer.present:
        return layer
    return _finish(layer, parts)


REASON_DNS_BLOCKS = "dns_blocks"
REASON_DNS_DEVICE = "dns_device"
DNS_TOP_REASONS = 2


def _dns_blocks(layer: Layer, parts: list[str], dns: list[DnsProfile],
                settings: Optional[dict[str, Any]]) -> None:
    """DNS threat blocks in the last 24 h (Rick, 2026-10-06: "a block is
    NextDNS doing its job").

    A1  the COUNT is a NOTICE — "N threats blocked today" (operators: the
        top reasons; a client user: "N threats blocked by DNS protection
        today", no vendor) — whatever the reasons were, and ALWAYS a Notice
        ("no WARN merely because blocks happened": the v0.17 knob
        `dns_medium_level` is retired — a stored value is ignored);
        known-benign probes and filter-bypass blocks (VPN / proxy / Tor /
        Private Relay: NextDNS's Parental Control, not Security) are not
        threats — operators read them apart ("not counted"), and alone they
        are an operator-only notice.
    A2  Yellow ONLY when a DEVICE looks wrong:
        a) the same device had HIGH-risk blocks in ≥ `dns_beacon_hours`
           (default 3) distinct clock hours within 24 h — beaconing;
        b) ANY block in a device-originated reason (DGA, tunneling,
           exfiltration, payload delivery): software makes those lookups.
    A3  CSAM is not here at all (rule B7 — a restricted Black)."""
    from apps.octo.adapters.nextdns.classification import short_label

    high = sum((p.threats_24h if p.threats_high is None else p.threats_high) for p in dns)
    lower = sum(p.threats_medium for p in dns if p.threats_high is not None)
    benign = sum(p.threats_benign for p in dns if p.threats_high is not None)
    bypass = sum(p.threats_bypass for p in dns if p.threats_high is not None)
    n = high + lower
    layer.data["dns_threats_high_24h"] = high
    layer.data["dns_blocked_24h"] = n
    # The drawer's "DNS threats 24 h" is the SAME number as the notice's "N
    # threats blocked today" (known-benign probes and filter bypass out).
    layer.data["dns_threats_24h"] = n
    layer.data["dns_bypass_24h"] = bypass
    tally: dict[str, int] = {}
    for p in dns:
        for rid, count in p.top_reasons:
            tally[rid] = tally.get(rid, 0) + count
    top = sorted(tally.items(), key=lambda x: (-x[1], x[0]))[:DNS_TOP_REASONS]
    layer.data["dns_top_reasons"] = [{"reason": rid, "label": short_label(rid), "count": c}
                                     for rid, c in top]
    apart = [f"{benign} known-benign"] if benign else []
    if bypass:
        apart.append(f"{bypass} filter-bypass")
    if n:
        named = ", ".join(f"{short_label(rid)} ×{c}" for rid, c in top)
        text = f"{_plural(n, 'threat')} blocked today" + (f" — top: {named}" if named else "")
        if apart:
            text += " (" + ", ".join(f"+{a}" for a in apart) + " not counted)"
        parts.append(NOTICE)
        layer.reasons.append(Reason(NOTICE, text,
                                    f"{_plural(n, 'threat')} blocked by DNS protection today",
                                    "security", REASON_DNS_BLOCKS))
    elif apart:
        said = ([f"{_plural(benign, 'known-benign DNS block')}"] if benign else []) + (
            [f"{_plural(bypass, 'DNS-filter bypass block')} (VPN / proxy / Tor — policy, "
             "not a threat)"] if bypass else [])
        parts.append(NOTICE)
        layer.reasons.append(Reason(NOTICE, "; ".join(said) + " today", "", "security",
                                    REASON_DNS_BLOCKS, operator_only=True))
    threshold = knob(settings, "dns_beacon_hours")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 2:
        threshold = KNOB_DEFAULTS["dns_beacon_hours"]
    flagged: list[dict[str, Any]] = []
    for p in dns:
        if not p.fresh:
            continue
        for d in p.devices:
            # A NETWORK key (an IP address: no NextDNS device — the whole
            # site behind its public address) is never "one device" for the
            # beacon hours; only a device-originated block flags it.
            network = bool(getattr(d, "network", False))
            hours = 0 if network else int(getattr(d, "high_hours", 0) or 0)
            originated = tuple(getattr(d, "originated", ()) or ())
            what: list[str] = []
            if originated:
                what.append(", ".join(f"{short_label(rid)} lookup{'' if c == 1 else 's'} "
                                      f"blocked" for rid, c in originated))
            if hours >= threshold:
                what.append(f"repeated high-risk lookups in {hours} separate hours")
            if not what:
                continue
            name = str(getattr(d, "name", "") or "a device")
            flagged.append({"name": name, "profile": p.name, "high_hours": hours,
                            "network": network, "reasons": [rid for rid, _c in originated]})
            parts.append(WARN)
            layer.reasons.append(Reason(
                WARN, f"{name}: {'; '.join(what)} — possible infection",
                "a device made automated suspicious lookups — possible infection"
                if originated else
                "a device made repeated high-risk lookups — possible infection",
                "security", REASON_DNS_DEVICE))
        if p.originated_unattributed:
            labels = ", ".join(f"{short_label(rid)} ×{c}" for rid, c in p.originated_unattributed)
            flagged.append({"name": None, "profile": p.name, "high_hours": 0,
                            "reasons": [rid for rid, _c in p.originated_unattributed]})
            parts.append(WARN)
            layer.reasons.append(Reason(
                WARN, f"NextDNS {p.name}: {labels} blocked (device not identified) — "
                      "possible infection",
                "a device made automated suspicious lookups — possible infection",
                "security", REASON_DNS_DEVICE))
    layer.data["dns_flagged_devices"] = flagged


def _dns_state(p: DnsProfile) -> str:
    # Lapsed first: an ACTIVE profile NextDNS stops showing lapses (the
    # poller raises it) — lapsed AND missing stays lapsed, not "missing".
    if p.state == "lapsed":
        return "lapsed"
    if p.missing:
        return "missing"
    if p.state in ("pending", "new"):
        return "pending"
    if p.state == "active":
        return "active"
    return "pending"


# ---------------------------------------------------------------------------
# Endpoints (Datto inventory)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Inventory:
    total: int
    online: int
    offline: int
    servers_offline: int
    fresh: bool


def endpoints_layer(inv: Optional[Inventory], *, as_of: Optional[str] = None,
                    scope: str = "site") -> Layer:
    layer = Layer("endpoints", as_of=as_of, scope=scope)
    if inv is None:
        return layer
    layer.present = True
    layer.data = {"agents_total": inv.total, "agents_online": inv.online,
                  "agents_offline": inv.offline, "servers_offline": inv.servers_offline}
    if not inv.fresh:
        layer.reasons.append(Reason(UNKNOWN, "Datto inventory not read recently",
                                    "device inventory is out of date", "endpoints"))
        return _finish(layer, [UNKNOWN])
    parts = [OK]
    if inv.servers_offline:
        # Re-tier row 23: an outage — Yellow (sorted first within Yellow).
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, f"{_plural(inv.servers_offline, 'server')} offline",
                                    f"{_plural(inv.servers_offline, 'server')} offline",
                                    "endpoints"))
    return _finish(layer, parts)


# ---------------------------------------------------------------------------
# Buoy
# ---------------------------------------------------------------------------

def buoy_layer(health: Optional[str], *, as_of: Optional[str] = None,
               canary_touches: Optional[int] = None) -> Layer:
    layer = Layer("buoy", as_of=as_of, scope="tenant")
    if health is None:
        return layer
    layer.present = True
    layer.data = {"health": health}
    parts: list[str] = []
    if health == "green":
        parts.append(OK)
    elif health == "yellow":
        layer.reasons.append(Reason(WARN, "buoy degraded", "on-site sensor degraded", "buoy"))
        parts.append(WARN)
    elif health == "red":
        # Re-tier row 25: a sensor outage is Yellow (it also degrades R6's
        # coverage, which the drawer says).
        layer.reasons.append(Reason(WARN, "buoy down", "on-site sensor down", "buoy"))
        parts.append(WARN)
    else:
        layer.reasons.append(Reason(UNKNOWN, "buoy heartbeat stale",
                                    "on-site sensor data is out of date", "buoy"))
        return _finish(layer, [UNKNOWN])
    if canary_touches:
        # R6's lesser outcome: a canary port touch (no credential) is Yellow.
        layer.data["canary_touches_24h"] = canary_touches
        parts.append(WARN)
        layer.reasons.append(Reason(WARN, f"decoy touched {_plural(canary_touches, 'time')} "
                                          f"in 24 h", "on-site decoy touched", "buoy"))
    return _finish(layer, parts)


# ---------------------------------------------------------------------------
# Threat (incident records)
# ---------------------------------------------------------------------------

def age_text(seconds: int) -> str:
    if seconds < 3600:
        return f"{max(1, seconds // 60)} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} d"


def _short(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "?"


def threat_layer(
    incidents: Iterable[Any],
    *,
    now: datetime,
    worker_fresh: bool = True,
    blind: Iterable[Any] = (),
    would_fire: Optional[dict[str, int]] = None,
    stale_since: Optional[str] = None,
    unreadable: bool = False,
    unknown_location: Iterable[int] = (),
    names: Optional[dict[str, str]] = None,
    watch_days: int = 7,
) -> Layer:
    """The site's threat layer from its incidents (`threat.store.Incident`,
    open and closed ≤ 30 d) — NEVER unknown while one is open, whatever the
    worker or the store says. `blind`: FR2 sources covering this tenant;
    `would_fire`: rule id → shadow would-fires today (operators only);
    `stale_since`: the store could not be read — `incidents` is the last
    known set; `unreadable` with no last-known set: unknown, never ok."""
    layer = Layer("threat", present=True, scope="site")
    names = names or {}
    unknown_loc = set(unknown_location)
    parts = [OK]
    incs = sorted(incidents, key=lambda i: (
        0 if (i.is_open and i.tier == "black") else 1 if i.is_open else 2,
        1 if i.acked else 0, i.detected_at or ""))
    open_ = [i for i in incs if i.is_open]
    for i in incs:
        # A RESTRICTED incident (B7, CSAM) is admin-only: the Fleet — every
        # operator's — names no summary, device or category for it.
        hidden = bool(getattr(i, "restricted", False))
        summary = RESTRICTED_TEXT if hidden else i.summary
        where = None if hidden else (i.device_label or i.device_ref)
        loc = " — device location unknown" if i.id in unknown_loc and not hidden else ""
        on = f" on {where}" if where else ""
        if i.is_open:
            t0 = _parse(i.detected_at)
            age = age_text(int((now - t0).total_seconds())) if t0 else "?"
            if i.contained:
                ack = "contained"
            elif i.acked:
                who = names.get(str(i.acknowledged_by or ""), f"#{i.acknowledged_by}")
                ack = f"acknowledged by {who}"
            else:
                ack = "unacknowledged"
            if i.tier == "black":
                parts.append(BLACK)
                layer.reasons.append(Reason(
                    BLACK, f"BLACK: {summary}{on} ({age}, {ack}){loc}",
                    "urgent security incident", "threat", REASON_INCIDENT,
                    incident_id=i.id))
            else:
                parts.append(BAD)
                layer.reasons.append(Reason(
                    BAD, f"Red: {summary}{on} ({age}, {ack}){loc}",
                    "security issue under investigation", "threat", REASON_INCIDENT,
                    incident_id=i.id))
            continue
        closed = _parse(i.closed_at)
        if closed is None or now - closed > RECENT_CLOSE:
            continue
        if i.true_positive and now - closed <= timedelta(days=watch_days):
            parts.append(WARN)
            layer.reasons.append(Reason(
                WARN, f"post-incident watch (closed {_short(closed)}): {summary}",
                "recently resolved security incident: under watch", "threat", REASON_INCIDENT,
                incident_id=i.id))
        else:
            parts.append(NOTICE)
            layer.reasons.append(Reason(
                NOTICE, f"security incident closed {_short(closed)}",
                "security incident closed", "threat", REASON_INCIDENT, operator_only=True,
                incident_id=i.id))
    for b in blind:
        since = _parse(getattr(b, "since", None))
        hhmm = since.strftime("%H:%M") if since else "?"
        level = NOTICE if getattr(b, "fleet_wide", True) else WARN
        parts.append(level)
        layer.reasons.append(Reason(
            level, f"Athena is blind to {b.label} here since {hhmm} UTC" if level == WARN
            else f"Athena is blind to {b.label} since {hhmm} UTC (fleet-wide)",
            "security monitoring interrupted", "threat", REASON_BLIND))
    for rule_id, n in sorted((would_fire or {}).items()):
        if n:
            parts.append(NOTICE)
            layer.reasons.append(Reason(
                NOTICE, f"would have been Red: {rule_id} ×{n} (shadow, 24 h)",
                "", "threat", REASON_SHADOW, operator_only=True))
    if stale_since:
        layer.data["stale_since"] = stale_since
        parts.append(NOTICE)
        layer.reasons.append(Reason(
            NOTICE, f"incident records not readable since {stale_since} — the last known "
                    "set is shown", "", "threat", REASON_WORKER, operator_only=True))
    if not open_:
        if unreadable:
            # Stale never reads OK: with no OPEN incident known, a store that
            # cannot be read now could be hiding one opened since the last
            # good read — Unknown, for the client too (whether or not an
            # earlier read is held).
            parts.append(UNKNOWN)
            layer.reasons.append(Reason(
                UNKNOWN, "incident records could not be read"
                + (f" since {stale_since}" if stale_since else ""),
                "security monitoring status unknown", "threat", REASON_WORKER))
        elif not worker_fresh:
            parts.append(UNKNOWN)
            layer.reasons.append(Reason(UNKNOWN, "threat correlator not running",
                                        "security monitoring status unknown", "threat",
                                        REASON_WORKER))
    elif not worker_fresh:
        # Never unknown while an incident is open: said, not coloured (a
        # client user whose incident is not visible yet still reads "status
        # unknown", never a bare ok).
        layer.reasons.append(Reason(NOTICE, "threat correlator not running",
                                    "security monitoring status unknown", "threat",
                                    REASON_WORKER))
    worst_open = open_[0] if open_ else None
    layer.data.update({
        "open_black": sum(1 for i in open_ if i.tier == "black"),
        "open_red": sum(1 for i in open_ if i.tier == "red"),
        "black_unacked": sum(1 for i in open_ if i.tier == "black" and not i.acked),
        "incident_ids": [i.id for i in incs],
        "worst": worst_open.id if worst_open else None,
    })
    return _finish(layer, parts)


# ---------------------------------------------------------------------------
# The site
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    state: str
    reason: Optional[Reason]
    reasons: list[Reason]


NO_SOURCE_TEXT = "no data source reports on this site yet"
NO_SOURCE_NEUTRAL = "no data reported yet"


def site_verdict(layers: dict[str, Layer]) -> Verdict:
    """The site's worst state over its PRESENT layers, with the reason that
    made it (layer order breaks ties — threat first) and every reason, worst
    first. The threat layer is ALWAYS present (an incident can land on any
    site), so it never stands in for data: with no HEALTH layer present the
    site is unknown "no data source reports on this site yet" (re-tier row
    27, P8 — never Green by default) — unless the threat layer says more
    than that (an open incident, a watch, blindness), which outranks it."""
    present = [layers[name] for name in LAYERS if name in layers and layers[name].present]
    states = [layer.state for layer in present]
    reasons = [r for layer in present for r in layer.reasons]
    if not any(layer.name in HEALTH_LAYERS for layer in present):
        nothing = Reason(UNKNOWN, NO_SOURCE_TEXT, NO_SOURCE_NEUTRAL, "")
        if not present:
            return Verdict(UNKNOWN, nothing, [nothing])
        states.append(UNKNOWN)
        reasons.append(nothing)
    state = worst(states)
    reasons.sort(key=lambda r: -RANK[r.state])          # stable: layer order kept
    top = next((r for r in reasons if r.state == state), None)
    return Verdict(state, top, reasons)


def client_layer(layer: Layer, *, hidden: Iterable[int] = (),
                 lines: Optional[dict[int, str]] = None) -> Layer:
    """The layer as a client user sees it: operator-only reasons dropped,
    and the reasons of incidents `hidden` from them (not visible yet: before
    an acknowledgement or 60 minutes); a visible incident's neutral text is
    its client line (`lines`). The state is recomputed from what is left
    (every non-ok part of a present layer carries a reason, so the state is
    the worst of them)."""
    hide = set(hidden)
    lines = lines or {}
    if not layer.present or not any(
            r.operator_only or (r.incident_id is not None and
                                (r.incident_id in hide or r.incident_id in lines))
            for r in layer.reasons):
        return layer
    kept = [Reason(r.state, r.text, lines.get(r.incident_id, r.neutral)
                   if r.incident_id is not None else r.neutral, r.layer, r.code,
                   r.operator_only, r.incident_id)
            for r in layer.reasons
            if not r.operator_only and (r.incident_id is None or r.incident_id not in hide)]
    out = Layer(layer.name, present=True, reasons=list(kept), data=dict(layer.data),
                as_of=layer.as_of, scope=layer.scope)
    out.state = worst([OK] + [r.state for r in kept])
    out.reasons.sort(key=lambda r: -RANK[r.state])
    return out


def cap_internet_issues(layer: Layer, text: str, neutral: str) -> bool:
    """Hold the network layer's internet-issue reason at NOTICE (the build's
    regional collapse: several sites on one ISP / in one area at once is
    likely weather or the provider, not each site's own fault). Only that
    reason changes — a WAN down, a gateway offline, anything else keeps its
    state. True when something changed."""
    if layer.name != "network" or not layer.present or layer.state == UNKNOWN:
        return False
    changed = False
    for i, r in enumerate(layer.reasons):
        if r.code == REASON_INTERNET_ISSUES:
            layer.reasons[i] = Reason(NOTICE, text, neutral, r.layer, r.code)
            changed = True
    if changed:
        layer.data["internet_issues_level"] = NOTICE
        layer.data["internet_issues_regional"] = True
        # Fresh network layer: every non-ok part carries a reason.
        _finish(layer, [OK] + [r.state for r in layer.reasons])
    return changed


def reason_line(v: Verdict, *, neutral: bool = False) -> str:
    """"2 IPS blocks today", "NextDNS lapsed (+2 more)", "all clear". A
    notice shows only when nothing is worse (and is never counted in a
    worse site's "+N more"). A BLACK is never folded into "+N more": every
    Black reason is spelled out."""
    if v.state == OK or v.reason is None:
        return "all clear" if v.state == OK else "no data"
    if v.state == BLACK:
        blacks = [r for r in v.reasons if r.state == BLACK]
        rest = [r for r in v.reasons if r.state not in (OK, NOTICE, BLACK)]
        texts = list(dict.fromkeys((r.neutral if neutral else r.text) for r in blacks))
        text = "; ".join(texts)
        return f"{text} (+{len(rest)} more)" if rest else text
    same = [r for r in v.reasons if r.state != OK and (v.state == NOTICE or r.state != NOTICE)]
    more = len(same) - 1
    text = v.reason.neutral if neutral else v.reason.text
    return f"{text} (+{more} more)" if more > 0 else text
