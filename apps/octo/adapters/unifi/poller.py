"""UniFiPoller — the fleet in two calls, then per MAPPED site only.

Every call goes through the API key's ONE limiter (limiter.py: ≥ 1 s apart,
security first). Per cycle:

  FLEET     every `fleet_interval_sec` (5 min): GET /v1/hosts + GET /v1/sites
            — TWO calls for the whole fleet. Builds the fleet view (per site:
            (hostId, siteId), names, the console's location and time zone,
            each WAN's cloud-observed external IP + ISP ASN, gateway online;
            per WAN also its role (primary / backup), whether its PORT is
            plugged in and holds an IPv4 (/v1/hosts reportedState.wans,
            matched by type 'WAN' / 'WAN2' — on a single-site console only:
            a multi-site console's ports are not each site's) and the
            vendor-agnostic `configured` the Fleet's WAN coverage reads; a
            WAN seen configured in the last 30 days that now reads
            unplugged has DROPPED — configured and down, never "not
            configured" (`_remember_wans`, kept in the poller's state)),
            shares it as the discovery listing (the mapping panel and the
            card never call UniFi themselves), and hands each MAPPED site's
            report to the feed (entity resolution's egress). The only
            fleet-wide fact a report carries is one bit per WAN,
            `shared_external` (the same public IP is another console's WAN).
  SYSTEM LOG every `syslog_interval_sec` (5 min; 5–10 allowed) per mapped site:
            POST system-log/all for the window since the site's cursor (a
            24-hour back-fill the first time a site is read in a tenant), all
            pages — the live log answers NEWEST FIRST: items kept by id,
            pages read up to the latest page count (a write landing mid-read
            pushes the list down), a remainder past the page cap asked for
            as its own range — then applied oldest first. Each event is classified (catalogue.py):
            SIGNALS are coalesced per site + subject per clock hour — the
            first creates ONE alert, later hits only count; ROLL-UPS are
            counted per hour; lease / WAN BOUNDARIES go to the feed. Counts,
            claims and the cursor move in ONE transaction in the tenant's own
            telemetry.db (exactly once, restart-safe); a claimed alert is
            stored right after (outbox — finished on the next pass after a
            crash).
  CLIENTS   every `clients_interval_sec` (5 min) per mapped site whose tenant
            takes them (entity switch shadow / on — the feed's `wants`): every
            page of the connected clients — a whole snapshot or nothing — to
            the feed (entity resolution's leases), with the gateway's state.
            A tenant switched off costs no client-list call.
  NETWORKS  once a day per mapped site: the site's networks (an allowlist of
            fields; every secret dropped at the client) to the feed.

ISOLATION: sites are keyed (hostId, siteId) everywhere — site ids COLLIDE
across consoles (V11, verified on a production fleet). A site not mapped to
an ACTIVE tenant (unmapped, ignored, its tenant gone) is never read beyond
the fleet list, and nothing about it is written anywhere: there is NO default
tenant. The tenant map is re-read every cycle; unreadable → nothing is polled.

FAILURES: one console that cannot answer (offline, 403/404/5xx through the
connector) or one tenant whose store refuses a write holds THAT site on its
own backoff (shown on the card); the others go on. A rejected key, a throttle
or the cloud API itself unreachable ends the cycle (the instance row says so;
a throttle is information, not a failure).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
import threading
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.unifi import catalogue, feed, sanitize, store
from apps.octo.adapters.unifi.client import (
    UniFiAborted,
    UniFiAuthError,
    UniFiClient,
    UniFiClientError,
    UniFiConsoleError,
    UniFiThrottledError,
    valid_host_id,
    valid_internal_ref,
    valid_site_id,
)
from apps.octo.adapters.unifi.limiter import (
    PRIORITY_CLIENTS,
    PRIORITY_DISCOVERY,
    PRIORITY_FLEET,
    PRIORITY_SECURITY,
)
from apps.octo.db import connect
from apps.octo.fleet.isp_outage import IspOutageCorrelator, mapped_site_rows
from apps.octo.fleet.state import primary_wan
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import freshness, poller_state, tenant_map
from apps.octo.instances.vendor_contact import ContactReporter, FailureBackoff

logger = logging.getLogger(__name__)

VENDOR = "unifi"
DEFAULT_FLEET_INTERVAL_SEC = 300.0
DEFAULT_SYSLOG_INTERVAL_SEC = 300.0
MIN_SYSLOG_INTERVAL_SEC = 300.0
MAX_SYSLOG_INTERVAL_SEC = 600.0
DEFAULT_CLIENTS_INTERVAL_SEC = 300.0
NETWORKS_EVERY = timedelta(hours=24)
# A site whose tenant does not take its networks yet (entity switch off) is
# asked again this often — no vendor call until it does.
NETWORKS_RECHECK = timedelta(minutes=15)
INTEGRATION_IDS_EVERY = timedelta(hours=24)
BACKFILL = timedelta(hours=24)
# The system log is re-read this far back each window (late writes), and
# event ids inside it are remembered so each is processed exactly once.
OVERLAP = timedelta(minutes=5)
MAX_WINDOW = timedelta(hours=6)
MIN_WINDOW = timedelta(minutes=5)
MAX_LOG_PAGES_PER_WINDOW = 20
# A minimal window is read whole up to this many pages (100 × 500 events in
# 5 minutes — far beyond any site seen in production).
HARD_MAX_LOG_PAGES = 100
MAX_WINDOW_SPLITS = 8
SITE_BACKOFF = {"console": (60.0, 1800.0), "store": (600.0, 3600.0)}
CREDENTIAL_BACKOFF = (60.0, 900.0)
TRANSPORT_BACKOFF = (60.0, 900.0)
STATE_KEY = "unifi_state"
STATE_VERSION = 1


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return format_utc_ms(dt) if dt is not None else None


def _from_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


def _text(value: Any, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def scope_of(host_id: Any, site_id: Any) -> Optional[str]:
    hid, sid = valid_host_id(host_id), valid_site_id(site_id)
    return f"{hid}/{sid}" if hid and sid else None


def split_scope(scope: Any) -> Optional[tuple[str, str]]:
    """"<hostId>/<siteId>" → (hostId, siteId), validated; None otherwise."""
    if not isinstance(scope, str) or scope.count("/") != 1:
        return None
    host, site = scope.split("/")
    if valid_host_id(host) and valid_site_id(site):
        return host, site
    return None


def _public_ip(value: Any) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(addr)


# ---------------------------------------------------------------------------
# The fleet view
# ---------------------------------------------------------------------------

@dataclass
class SiteInfo:
    scope: str
    host_id: str
    site_id: str
    internal_ref: str
    name: str
    console_name: str
    timezone: str
    location: dict[str, Any]
    wans: list[dict[str, Any]]
    gateway_online: Optional[bool]
    host_connected: Optional[bool]
    counts: dict[str, int]
    # Fleet v2's network layer (`site_stats`): device / gateway counts, the
    # site's ISP, internet and WAN issues. NOT in `report()` — entity
    # resolution's feed is unchanged.
    stats: dict[str, Any] = field(default_factory=dict)

    def report(self, polled_at: str) -> dict[str, Any]:
        return {
            "scope": self.scope, "host_id": self.host_id, "site_id": self.site_id,
            "internal_ref": self.internal_ref, "name": self.name,
            "console_name": self.console_name, "timezone": self.timezone,
            "location": dict(self.location), "wans": [dict(w) for w in self.wans],
            "gateway_online": self.gateway_online, "host_connected": self.host_connected,
            "report_fresh": self.host_connected is not False,
            "polled_at": polled_at,
        }

    def context(self) -> catalogue.SiteContext:
        return catalogue.SiteContext(self.scope, self.host_id, self.site_id, self.internal_ref,
                                     self.name, self.console_name, self.timezone)


_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12",
                                                   "192.168.0.0/16"))


def nat_kind(external: Optional[str], interfaces: list[str]) -> str:
    """How the site reaches the internet, from the console's WAN interface
    addresses (`/v1/hosts` reportedState.wans[].ipv4) against the address the
    cloud sees (`/v1/sites` externalIp): `direct` when the interface holds
    the public address, `cgnat` when an interface is in 100.64/10 (a carrier
    NAT shared with strangers), `double_nat` when it is RFC 1918 (an ISP
    router in front: private WAN, public address nobody else shares),
    `unknown` otherwise. Entity resolution scores egress by it (G4)."""
    if not external:
        return "unknown"
    if external in interfaces:
        return "direct"
    addrs = []
    for text in interfaces:
        try:
            addrs.append(ipaddress.ip_address(text))
        except ValueError:
            continue
    if any(a.version == 4 and a in _CGNAT for a in addrs):
        return "cgnat"
    if any(a.version == 4 and any(a in n for n in _RFC1918) for a in addrs):
        return "double_nat"
    return "unknown"


# The delegated-prefix field of /v1/hosts reportedState.wans[] was NOT seen in
# the live probes (only `ipv6`): these keys are read tolerantly, whichever is
# present ("2001:db8:4200::/56", or {prefix|address, length|prefixLength}).
PD_KEYS = ("ipv6Prefix", "ipv6PrefixDelegation", "prefixDelegation", "delegatedPrefix",
           "ipv6Pd", "ipv6_pd", "pd")
# A delegated LAN prefix is /32 … /64 (anything longer is no LAN prefix).
PD_MIN_LEN, PD_MAX_LEN = 32, 64


def _global_v6(value: Any) -> Optional[ipaddress.IPv6Address]:
    try:
        addr = ipaddress.ip_interface(str(value).strip().split("%")[0]).ip
    except ValueError:
        return None
    if addr.version != 6 or addr.is_link_local or addr.is_loopback or addr.is_multicast \
            or addr.is_unspecified or addr in ipaddress.ip_network("fc00::/7") \
            or addr.ipv4_mapped is not None:
        return None
    return addr


def _v6_prefix(value: Any) -> Optional[ipaddress.IPv6Network]:
    if isinstance(value, dict):
        base = value.get("prefix") or value.get("address") or value.get("network")
        length = value.get("length", value.get("prefixLength", value.get("prefix_len")))
        if isinstance(base, str) and "/" not in base and isinstance(length, int) \
                and not isinstance(length, bool):
            value = f"{base}/{length}"
        else:
            value = base
    if isinstance(value, list):
        for item in value:
            net = _v6_prefix(item)
            if net is not None:
                return net
        return None
    if not isinstance(value, str) or "/" not in value:
        return None
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    if net.version != 6 or not PD_MIN_LEN <= net.prefixlen <= PD_MAX_LEN \
            or _global_v6(net.network_address) is None:
        return None
    return net


def host_v6(rs: dict[str, Any]) -> list[dict[str, Any]]:
    """The console's IPv6 WAN facts from /v1/hosts reportedState.wans[]: the
    WAN's own global address (`ipv6`, kept as a /128) and, when present, the
    prefix delegated to its LAN (`PD_KEYS`) — as extra egress "WANs" of the
    site, named "<WAN>/v6" and "<WAN>/pd". IPv6 has no NAT: `direct`."""
    out: list[dict[str, Any]] = []
    wans = rs.get("wans") if isinstance(rs.get("wans"), list) else []
    for i, w in enumerate(wans):
        w = _m(w)
        if w.get("enabled") is False:
            continue
        kind = _text(w.get("type"), 12).upper()
        name = kind if kind.startswith("WAN") else ("WAN" if i == 0 else f"WAN{i + 1}")
        raw = w.get("ipv6")
        for value in (raw if isinstance(raw, list) else [raw]):
            addr = _global_v6(value) if value else None
            if addr is not None:
                out.append({"wan": f"{name}/v6", "external_ip": str(addr), "prefix_len": 128,
                            "nat_kind": "direct", "family": 6})
                break
        for key in PD_KEYS:
            net = _v6_prefix(w.get(key))
            if net is not None:
                out.append({"wan": f"{name}/pd", "external_ip": str(net.network_address),
                            "prefix_len": net.prefixlen, "nat_kind": "direct", "family": 6})
                break
    return out


def host_wan_ports(rs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The console's WAN PORTS from /v1/hosts reportedState.wans[], by type
    ('WAN', 'WAN2', …: the names /v1/sites statistics.wans uses): {plugged
    (True / False / None), ipv4_present (an IPv4 is assigned), enabled}.
    Calibrated on a production fleet (2026-10-02): most sites had WAN2
    enabled but plugged=false with no IP — a port nobody connected."""
    out: dict[str, dict[str, Any]] = {}
    wans = rs.get("wans") if isinstance(rs.get("wans"), list) else []
    for i, w in enumerate(wans):
        w = _m(w)
        kind = _text(w.get("type"), 12).upper()
        name = kind if kind.startswith("WAN") else ("WAN" if i == 0 else f"WAN{i + 1}")
        raw = w.get("ipv4")
        ipv4 = False
        for value in (raw if isinstance(raw, list) else [raw]):
            try:
                ipv4 = ipv4 or (bool(value) and
                                ipaddress.ip_interface(str(value).strip()).ip.version == 4)
            except ValueError:
                continue
        out[name] = {"plugged": w.get("plugged") if isinstance(w.get("plugged"), bool) else None,
                     "ipv4_present": ipv4,
                     "enabled": w.get("enabled") if isinstance(w.get("enabled"), bool)
                     else None}
    return out


def wan_configured(port: Optional[dict[str, Any]], port_up: Optional[bool]) -> Optional[bool]:
    """Is a line connected to this WAN at all? True when its port is up,
    plugged in or holding an IPv4; False when the port is disabled, or
    unplugged with no IPv4 ever assigned; None when the console says nothing
    of it (never guessed)."""
    if port_up is True:
        return True
    if not port:
        return None
    if port.get("plugged") is True or port.get("ipv4_present"):
        return True
    if port.get("enabled") is False:
        return False
    if port.get("plugged") is False:
        return False
    return None


DEFAULT_SITE_NAMES = frozenset({"", "default"})


def site_name(meta: dict[str, Any], console_name: str, sites_on_console: int,
              site_id: str) -> str:
    """What a site is called. UniFi names every console's first site
    'Default' (meta.desc) unless someone renamed it — on a fleet of
    single-site consoles that is every site called "Default", entity sites
    and Why sentences included. Such a site takes its CONSOLE's name (on a
    console with several sites: "<console> — Default")."""
    desc = _text(meta.get("desc"), 120)
    if desc.lower() not in DEFAULT_SITE_NAMES:
        return desc
    if console_name:
        return console_name if sites_on_console <= 1 else \
            f"{console_name} — {desc or _text(meta.get('name'), 40) or 'Default'}"[:120]
    return desc or _text(meta.get("name"), 120) or site_id


def _issue_keys(value: Any, limit: int = 50) -> list[str]:
    """Stable keys for the entries of an `internetIssues` / `wanIssues` list
    (fixture-shaped: `{index, highLatency, latencyAvgMs, …}` — the live
    entries were not sampled): the entry's `index` when it has one, else a
    digest of the entry. Only NEW keys between two polls say "an issue
    happened now" (the list may be a history)."""
    import hashlib
    import json as _json

    out: list[str] = []
    for item in (value if isinstance(value, list) else [])[-limit:]:
        idx = item.get("index") if isinstance(item, dict) else None
        if isinstance(idx, int) and not isinstance(idx, bool):
            out.append(f"i{idx}")
            continue
        try:
            text = _json.dumps(item, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = repr(item)
        out.append("d" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16])
    return out


def _count(counts: dict[str, int], key: str) -> Optional[int]:
    value = counts.get(key)
    return value if isinstance(value, int) and value >= 0 else None


def site_stats(stats: dict[str, Any], counts: dict[str, int]) -> dict[str, Any]:
    """What Fleet v2's NETWORK layer reads from one `/v1/sites` entry's
    statistics (already stripped at the client): devices, offline gateway,
    pending updates, critical notifications, the site's ISP (name + ASN) and
    its internet / WAN issue lists (as counts and stable keys)."""
    isp = _m(stats.get("ispInfo"))
    asn = isp.get("asn")
    wan_issues: dict[str, list[str]] = {}
    for wan_name, w in sorted(_m(stats.get("wans")).items()):
        keys = _issue_keys(_m(w).get("wanIssues"))
        if keys:
            wan_issues[_text(wan_name, 16)] = keys
    issues = _issue_keys(stats.get("internetIssues"))
    return {
        "devices_total": _count(counts, "totalDevice"),
        "devices_offline": _count(counts, "offlineDevice"),
        "gateways_offline": _count(counts, "offlineGatewayDevice"),
        # The wired / wireless split (Site Manager API counts; absent on a
        # report without them → None, and the Fleet warns on every offline
        # device as before).
        "devices_offline_wifi": _count(counts, "offlineWifiDevice"),
        "devices_offline_wired": _count(counts, "offlineWiredDevice"),
        "pending_updates": _count(counts, "pendingUpdateDevice"),
        "critical_notifications": _count(counts, "criticalNotification"),
        "isp_name": _text(isp.get("name") or isp.get("organization"), 80) or None,
        "isp_asn": asn if isinstance(asn, int) and not isinstance(asn, bool) else None,
        "internet_issues": len(issues),
        "internet_issue_keys": issues,
        "wan_issue_keys": wan_issues,
    }


# Fleet v2: an internet / WAN issue entry that appeared within this long
# makes the site's network layer "internet blip" (notice) — or, when it
# recurs (`fleet.state.ISSUES_RECUR_*`), "internet issues keep recurring"
# (warn). The per-site history of new entries is bounded.
ISSUES_RECENT = timedelta(hours=1)
ISSUE_HITS_MAX = 32
# WAN coverage memory: a WAN seen configured (up / plugged in / addressed) on
# a fleet poll within this long that now reads unplugged with no address has
# DROPPED (a dead modem, a pulled cable) — "backup line down", not "never
# configured". Past it, an unplugged WAN is taken as decommissioned.
WAN_MEMORY = timedelta(days=30)


def _issue_key_set(stats: dict[str, Any], primary: Optional[str] = None) -> set[str]:
    """The site's internet + WAN issue entries as stable keys. With
    `primary`, a BACKUP WAN's issues are left out (a backup line is
    nice-to-have — owner decision 2026-10-02 — its trouble is never the
    site's)."""
    keys = {f"net:{k}" for k in (stats.get("internet_issue_keys") or []) if isinstance(k, str)}
    for wan, wkeys in (stats.get("wan_issue_keys") or {}).items():
        if primary is not None and wan != primary:
            continue
        keys |= {f"{wan}:{k}" for k in (wkeys or []) if isinstance(k, str)}
    return keys


def build_fleet(hosts: list[dict[str, Any]], sites: list[dict[str, Any]],
                owner_of: Optional[Callable[[str], Optional[str]]] = None) -> dict[str, SiteInfo]:
    """The fleet view from the two fleet answers (already stripped at the
    client). Sites without a valid (hostId, siteId) are dropped — and so is a
    site whose internal reference (meta.name, the system-log path) is
    missing or invalid: guessing 'default' would read ANOTHER site's log and
    clients on a multi-site console (fail closed).

    `owner_of(scope)` → the tenant a site is mapped to (None: mapped to no
    tenant). `shared_external` counts OWNERS per address: a tenant, or — for a
    site mapped to nobody — its console (an unknown owner). Two clients on
    ONE multi-site console behind one WAN are two owners (the old count by
    console missed them); two sites of one client sharing an address are
    one."""
    by_host: dict[str, dict[str, Any]] = {}
    for h in hosts:
        hid = valid_host_id(h.get("id"))
        if hid:
            by_host[hid] = h
    per_host: Counter = Counter()
    for s in sites:
        scope = scope_of(s.get("hostId"), s.get("siteId"))
        if scope is not None:
            per_host[scope.split("/")[0]] += 1
    out: dict[str, SiteInfo] = {}
    for s in sites:
        scope = scope_of(s.get("hostId"), s.get("siteId"))
        if scope is None:
            continue
        internal_ref = valid_internal_ref(_m(s.get("meta")).get("name"))
        if internal_ref is None:
            logger.warning("[unifi-poller] site %s has no valid internal reference; it is not "
                           "read (never guessed)", scope)
            continue
        host_id, site_id = scope.split("/")
        host = by_host.get(host_id, {})
        rs = _m(host.get("reportedState"))
        meta = _m(s.get("meta"))
        stats = _m(s.get("statistics"))
        counts = {k: v for k, v in _m(stats.get("counts")).items()
                  if isinstance(v, int) and not isinstance(v, bool)}
        loc = _m(rs.get("location"))
        location = {k: loc[k] for k in ("lat", "long", "radius")
                    if isinstance(loc.get(k), (int, float)) and not isinstance(loc.get(k), bool)}
        if _text(loc.get("text"), 200):
            location["text"] = _text(loc.get("text"), 200)
        wans = []
        ifaces = [ip for ip in (_public_ip(_m(x).get("ipv4"))
                                for x in (rs.get("wans") if isinstance(rs.get("wans"), list)
                                          else [])) if ip]
        # The console's own WAN PORTS describe a site's WANs only on a
        # single-site console: on a multi-site console they are the
        # console's, not each hosted site's (left unknown, never guessed —
        # as host_v6 below).
        ports = host_wan_ports(rs) if per_host[host_id] == 1 else {}
        for wan_name, w in sorted(_m(stats.get("wans")).items()):
            w = _m(w)
            own_isp = _m(w.get("ispInfo"))
            isp = own_isp or _m(stats.get("ispInfo"))
            asn = isp.get("asn")
            external = _public_ip(w.get("externalIp"))
            port_up = w.get("portUp") if isinstance(w.get("portUp"), bool) else None
            port = ports.get(_text(wan_name, 16).upper())
            wans.append({k: v for k, v in {
                "wan": _text(wan_name, 16),
                "external_ip": external,
                "nat_kind": nat_kind(external, ifaces) if external else None,
                "asn": asn if isinstance(asn, int) and not isinstance(asn, bool) else None,
                "isp": _text(isp.get("name") or isp.get("organization"), 80) or None,
                # The site-level provider borrowed for a WAN with none of its
                # own (the primary's): never named as THIS line's provider.
                "isp_from": "site" if isp and not own_isp else None,
                "port_up": port_up,
                "failover_priority": (w.get("failoverPriority")
                                      if isinstance(w.get("failoverPriority"), int)
                                      and not isinstance(w.get("failoverPriority"), bool)
                                      else None),
                # WAN coverage (2026-10-02): what the console says of the
                # PORT behind this WAN — plugged in, holding an IPv4 —
                # and the vendor-agnostic `configured` the Fleet reads.
                "plugged": port.get("plugged") if port else None,
                "ipv4_present": port.get("ipv4_present") if port else None,
                "configured": wan_configured(port, port_up),
            }.items() if v is not None})
        primary = primary_wan(wans)
        for w in wans:
            w["role"] = "primary" if w.get("wan") == primary else "backup"
        if per_host[host_id] == 1:
            # The console's own IPv6 WAN (and delegated prefix) is the site's
            # only on a single-site console — on a multi-site console the
            # console's WAN is not each site's (left unknown, never guessed).
            wans.extend(host_v6(rs))
        state = rs.get("state")
        connected = (state.lower() == "connected") if isinstance(state, str) and state else None
        offline_gw = counts.get("offlineGatewayDevice")
        console_name = _text(rs.get("hostname") or rs.get("name"), 120) or host_id[:12]
        out[scope] = SiteInfo(
            scope=scope, host_id=host_id, site_id=site_id,
            internal_ref=internal_ref,
            name=site_name(meta, console_name, per_host[host_id], site_id),
            console_name=console_name,
            timezone=_text(meta.get("timezone") or rs.get("timezone"), 64),
            location=location, wans=wans,
            gateway_online=(offline_gw == 0) if isinstance(offline_gw, int) else None,
            host_connected=connected, counts=counts,
            stats=site_stats(stats, counts),
        )
    # One bit per WAN: the same public address belongs to ANOTHER owner in
    # this snapshot (another tenant, or a console no tenant's site is on).
    # Nothing about the other site is kept.
    owners: dict[str, set[str]] = {}
    for scope, info in out.items():
        slug = owner_of(scope) if owner_of is not None else None
        owner = f"tenant:{slug}" if slug else f"console:{info.host_id}"
        for w in info.wans:
            if w.get("external_ip"):
                key = f"{w['external_ip']}/{w.get('prefix_len') or ''}"
                owners.setdefault(key, set()).add(owner)
    for info in out.values():
        for w in info.wans:
            ip = w.get("external_ip")
            key = f"{ip}/{w.get('prefix_len') or ''}"
            w["shared_external"] = bool(ip and len(owners.get(key, ())) > 1)
    return out


def tenant_label(info: SiteInfo) -> str:
    """What the mapping picker shows: the site, its console, and where it is
    (two businesses with one name separate on geography)."""
    label = info.name if info.name.lower() == info.console_name.lower() else \
        f"{info.name} — {info.console_name}"
    text = info.location.get("text")
    return f"{label} ({text})" if text else label


# ---------------------------------------------------------------------------
# Per-site state
# ---------------------------------------------------------------------------

@dataclass
class SiteState:
    scope: str
    slug: str
    syslog_due: Optional[datetime] = None
    clients_due: Optional[datetime] = None
    networks_due: Optional[datetime] = None
    failures: int = 0
    held_until: Optional[datetime] = None
    problem: Optional[str] = None
    problem_kind: Optional[str] = None
    last_syslog_at: Optional[datetime] = None
    last_clients_at: Optional[datetime] = None
    clients_seen: Optional[int] = None
    clients_problem: Optional[str] = None
    signals: int = 0


@dataclass
class CycleReport:
    contacted: bool = False
    fleet: bool = False
    sites: int = 0
    signals: int = 0
    rollups: int = 0
    held: bool = False
    errors: list[str] = field(default_factory=list)
    next_due_in: float = DEFAULT_SYSLOG_INTERVAL_SEC


class UniFiPoller:
    def __init__(
        self,
        *,
        adapter: Any,
        client: UniFiClient,
        sink: Any,
        instance_id: Optional[int],
        fleet_interval_sec: float = DEFAULT_FLEET_INTERVAL_SEC,
        syslog_interval_sec: float = DEFAULT_SYSLOG_INTERVAL_SEC,
        clients_interval_sec: float = DEFAULT_CLIENTS_INTERVAL_SEC,
        now: Callable[[], datetime] = _now_utc,
        consumer: Optional[Any] = None,
        reporter: Optional[ContactReporter] = None,
        isp_correlator: Optional[Any] = None,
    ) -> None:
        self._adapter = adapter
        self._client = client
        self._sink = sink
        self._instance_id = instance_id
        self._fleet_every = timedelta(seconds=max(60.0, float(fleet_interval_sec)))
        self._syslog_every = timedelta(seconds=max(
            MIN_SYSLOG_INTERVAL_SEC, min(MAX_SYSLOG_INTERVAL_SEC, float(syslog_interval_sec))))
        self._clients_every = timedelta(seconds=max(60.0, float(clients_interval_sec)))
        self._now = now
        self._consumer = consumer
        self._reporter = reporter or ContactReporter(instance_id, what="unifi-poller")
        self._credential_backoff = FailureBackoff(base_sec=CREDENTIAL_BACKOFF[0],
                                                  ceiling_sec=CREDENTIAL_BACKOFF[1])
        self._transport_backoff = FailureBackoff(base_sec=TRANSPORT_BACKOFF[0],
                                                 ceiling_sec=TRANSPORT_BACKOFF[1])
        self._abort = threading.Event()
        set_abort = getattr(client, "set_abort", None)
        if callable(set_abort):
            set_abort(self._abort)
        self._fleet: Optional[dict[str, SiteInfo]] = None
        self._fleet_at: Optional[datetime] = None
        # Fleet v2: when a site's internet / WAN issue lists last showed a
        # NEW entry between two fresh fleet polls (the lists may be
        # histories: only a new entry says "an issue happened now").
        self._issues_new_at: dict[str, datetime] = {}
        # …every such poll (when, how many new entries) — bounded — and how
        # many CONSECUTIVE fresh polls showed new entries (a recurring
        # problem warns; a one-off blip is a notice).
        self._issue_hits: dict[str, deque[tuple[datetime, int]]] = {}
        self._issue_streak: dict[str, int] = {}
        # WAN coverage: scope → {WAN name: when it was last seen configured}
        # (`_remember_wans`; restart-safe in the poller's state).
        self._wan_seen: dict[str, dict[str, str]] = {}
        self._fleet_due: Optional[datetime] = None
        self._fleet_truncated = False
        self._consoles = 0
        self._sites: dict[str, SiteState] = {}
        self._integration: dict[str, dict[str, Any]] = {}   # host → {at, sites{ref: id}}
        # "<scope>|<slug>" → when the networks were last TAKEN by the feed
        # (a re-map, or a tenant switched off → shadow, reads them again).
        self._networks_at: dict[str, str] = {}
        self._site_turn = 0
        self._state_loaded = False
        self._state_text: Optional[str] = None
        self._throttled_until: Optional[datetime] = None
        self._last_event_at: Optional[str] = None
        self._snapshot: dict[str, Any] = {}
        self._snap_lock = threading.Lock()
        self._publish: Optional[Callable[[str, Any], None]] = None
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()
        # Fleet v2: several mapped sites on ONE ISP losing WAN at once → ONE
        # incident (apps/octo/fleet/isp_outage.py), after every fleet poll.
        self._correlator = isp_correlator
        if self._correlator is None and instance_id is not None:
            self._correlator = IspOutageCorrelator(
                instance_id=instance_id, ingest=self._ingest_derived,
                build_payload=catalogue.isp_outage_payload)

    # ----- read side (API threads; never a vendor call) -----

    @property
    def last_event_at(self) -> Optional[str]:
        return self._last_event_at

    def snapshot(self) -> dict[str, Any]:
        with self._snap_lock:
            snap = dict(self._snapshot)
        until = self._throttled_until
        left = (until - self._now()).total_seconds() if until else 0.0
        snap["throttled"] = left > 0
        snap["throttled_for_sec"] = int(left) if left > 0 else 0
        return snap

    def fleet_view(self) -> dict[str, dict[str, Any]]:
        """scope → the site as the last fleet poll saw it (the mapping panel)."""
        fleet = self._fleet or {}
        at = _iso(self._fleet_at) or ""
        return {scope: info.report(at) for scope, info in fleet.items()}

    def site_states(self) -> dict[str, dict[str, Any]]:
        with self._snap_lock:
            return {k: dict(v) for k, v in (self._snapshot.get("sites") or {}).items()}

    def fleet_health(self) -> dict[str, Any]:
        """Fleet v2's read: every site of the LAST fleet poll (the report the
        mapping panel shows + `stats` + device counts), when that poll was
        and how often it runs — local state only, never a UniFi call.
        `at` None: no fleet poll since start."""
        fleet = self._fleet or {}
        at = _iso(self._fleet_at)
        now = self._now()

        def stats(scope: str, info: SiteInfo) -> dict[str, Any]:
            new_at = self._issues_new_at.get(scope)
            recent = new_at is not None and now - new_at <= ISSUES_RECENT
            hits = sum(n for at, n in self._issue_hits.get(scope, ()) if now - at <= ISSUES_RECENT)
            return {**info.stats, "issues_new_at": _iso(new_at), "issues_recent": recent,
                    "issues_recent_count": hits if recent else 0,
                    "issues_streak": self._issue_streak.get(scope, 0) if recent else 0}

        return {
            "at": at,
            "interval_sec": self._fleet_every.total_seconds(),
            "syslog_interval_sec": self._syslog_every.total_seconds(),
            "sites": {scope: {**info.report(at or ""), "stats": stats(scope, info),
                              "counts": dict(info.counts)}
                      for scope, info in fleet.items()},
        }

    def isp_outages(self) -> list[dict[str, Any]]:
        """The ISP-outage correlator's open (and recently closed) incidents."""
        correlator = self._correlator
        return correlator.snapshot() if correlator is not None else []

    # ----- async lifecycle -----

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._abort.clear()
        self._loop = asyncio.get_running_loop()
        self._publish = self._publish_on_loop
        self._task = asyncio.create_task(self._run(), name="unifi-poller")

    def poll_now(self) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._wake.set)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        self._abort.set()
        self._client.limiter.poke()
        try:
            await asyncio.wait_for(self._task, timeout=20.0)
        except asyncio.TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    async def _run(self) -> None:
        logger.info("[unifi-poller] starting (fleet every %.0fs, system log every %.0fs, "
                    "clients every %.0fs)", self._fleet_every.total_seconds(),
                    self._syslog_every.total_seconds(), self._clients_every.total_seconds())
        try:
            while not self._stopping.is_set():
                self._wake.clear()
                delay = await asyncio.to_thread(self.cycle_with_reporting)
                await self._sleep_or_stop(delay)
        finally:
            logger.info("[unifi-poller] stopped")

    async def _sleep_or_stop(self, seconds: float) -> None:
        waiters = [asyncio.ensure_future(self._stopping.wait()),
                   asyncio.ensure_future(self._wake.wait())]
        try:
            await asyncio.wait(waiters, timeout=max(0.0, seconds),
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waiters:
                w.cancel()

    def _publish_on_loop(self, slug: str, event: Any) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        from apps.octo.ingest import SqliteIngestSink

        publisher = SqliteIngestSink(publish_to_stream=True)
        try:
            loop.call_soon_threadsafe(publisher._publish, slug, VENDOR, event)  # noqa: SLF001
        except RuntimeError:
            pass

    # ----- one cycle, with its outcome reported -----

    def cycle_with_reporting(self) -> float:
        """Run one cycle and report its outcome; return the wait before the
        next. Never raises."""
        try:
            report = self.run_cycle()
        except UniFiAborted:
            return 0.0
        except UniFiThrottledError as exc:
            wait = max(1.0, exc.retry_in_sec)
            self._throttled_until = self._now() + timedelta(seconds=wait)
            self._reporter.throttled(
                f"UniFi is rate limiting Athena (HTTP 429). Every UniFi call waits {int(wait)} s "
                "and backs off further if it persists (up to 10 minutes). Not a failure: "
                "nothing is lost — the system log is read from where it stopped."
            )
            self._update_snapshot()
            return wait
        except UniFiAuthError as exc:
            delay = self._credential_backoff.next()
            self._reporter.failed(
                "auth", f"{exc}. Check the API key at unifi.ui.com → API (Site Manager). Stored "
                "keys cannot be edited: Disable this integration, then Add integration again "
                "with the current key (map your sites again afterwards). Athena keeps retrying "
                f"(at most every {int(CREDENTIAL_BACKOFF[1] // 60)} minutes).")
            logger.warning("[unifi-poller] auth failed: %s (retry in %.0fs)", exc, delay)
            self._update_snapshot()
            return delay
        except UniFiClientError as exc:
            delay = self._transport_backoff.next()
            self._reporter.failed(
                "transport", f"Could not read from UniFi: {exc}. Retrying automatically "
                f"(backing off up to {int(TRANSPORT_BACKOFF[1] // 60)} minutes).")
            logger.warning("[unifi-poller] transport error: %s (retry in %.0fs)", exc, delay)
            self._update_snapshot()
            return delay
        except Exception as exc:  # noqa: BLE001
            logger.exception("[unifi-poller] unexpected error: %s", type(exc).__name__)
            self._reporter.failed(
                "internal", f"The UniFi poll failed inside Athena ({type(exc).__name__}); see "
                "the server log. Retrying automatically.")
            self._update_snapshot()
            return self._syslog_every.total_seconds()
        self._throttled_until = None
        self._credential_backoff.reset()
        self._transport_backoff.reset()
        if report.contacted:
            self._reporter.ok()
        return report.next_due_in

    def run_cycle(self) -> CycleReport:
        """One pass over everything due. Synchronous (a worker thread); raises
        the client's key-wide errors (auth / throttle / unreachable) after
        saving state. One site's failure never ends the cycle."""
        report = CycleReport()
        self._load_state()
        try:
            mapped = self._mapped_sites()
            if mapped is None:
                report.held = True
                report.errors.append("tenant map unreadable")
                report.next_due_in = 60.0
                return report
            self._sync(mapped)
            now = self._now()
            if self._fleet is None or self._fleet_due is None or now >= self._fleet_due:
                self._poll_fleet(report)
            if not mapped:
                report.held = True
                report.next_due_in = self._seconds_until(self._fleet_due)
                return report
            # The start rotates every cycle: one site that ends a cycle can
            # never starve a fixed tail of others.
            order = sorted(self._sites)
            if order:
                turn = self._site_turn % len(order)
                order = order[turn:] + order[:turn]
                self._site_turn += 1
            for scope in order:
                if self._abort.is_set():
                    break
                self._site_tasks(self._sites[scope], report)
            report.next_due_in = self._next_due_in()
            return report
        finally:
            self._save_state()
            self._update_snapshot()

    # ----- the tenant map: mapped sites of ACTIVE tenants only -----

    def _mapped_sites(self) -> Optional[dict[str, str]]:
        """scope → tenant slug for every site mapped to an ACTIVE tenant.
        None when the map cannot be read (then NOTHING is polled)."""
        if self._instance_id is None:
            return {}
        try:
            mappings = tenant_map.get_mappings(self._instance_id)
            reg = connect(paths.registry_db_path(), read_only=True)
            try:
                active = {r[0] for r in reg.execute(
                    "SELECT slug FROM clients WHERE status = 'active'")}
            finally:
                reg.close()
        except sqlite3.Error as exc:
            logger.warning("[unifi-poller] tenant map unreadable (%s); polling nothing this "
                           "cycle", type(exc).__name__)
            return None
        out: dict[str, str] = {}
        for m in mappings:
            if split_scope(m.vendor_tenant_id) is None:
                # A mapping of the retired local-controller adapter (a bare
                # site id — those collide across consoles): never polled.
                continue
            if m.octo_client_slug in active:
                out[m.vendor_tenant_id] = m.octo_client_slug
        return out

    def _still_mapped(self, st: SiteState) -> bool:
        """Re-read the site's mapping right before touching it (fail closed)."""
        if self._instance_id is None:
            return True
        try:
            reg = connect(paths.registry_db_path(), read_only=True)
            try:
                row = reg.execute(
                    "SELECT m.octo_client_slug FROM adapter_tenant_map m "
                    "JOIN clients c ON c.slug = m.octo_client_slug "
                    "WHERE m.adapter_instance_id = ? AND m.vendor_tenant_id = ? "
                    "AND c.status = 'active'", (self._instance_id, st.scope),
                ).fetchone()
            finally:
                reg.close()
        except sqlite3.Error:
            return False
        if row is None or row[0] != st.slug:
            self._sites.pop(st.scope, None)
            return False
        return True

    def _sync(self, mapped: dict[str, str]) -> None:
        for scope, slug in mapped.items():
            st = self._sites.get(scope)
            if st is None or st.slug != slug:
                # New, or re-mapped to another tenant: starts fresh there
                # (its cursor lives in THAT tenant's file).
                self._sites[scope] = SiteState(scope=scope, slug=slug)
        for scope in [s for s in self._sites if s not in mapped]:
            self._sites.pop(scope, None)

    # ----- fleet -----

    def _poll_fleet(self, report: CycleReport) -> None:
        hosts = self._client.list_hosts(priority=PRIORITY_FLEET)
        sites = self._client.list_sites(priority=PRIORITY_FLEET)
        report.contacted = True
        report.fleet = True
        now = self._now()
        mapped = {scope: st.slug for scope, st in self._sites.items()}
        before, before_at = self._fleet, self._fleet_at
        self._fleet = build_fleet(hosts.items, sites.items, owner_of=mapped.get)
        self._note_new_issues(before, before_at, now)
        self._remember_wans(now)
        self._fleet_truncated = hosts.truncated or sites.truncated
        self._consoles = len({info.host_id for info in self._fleet.values()})
        self._fleet_at = now
        self._fleet_due = now + self._fleet_every
        self._share_discovery()
        consumer = self._feed_consumer()
        polled_at = _iso(now) or ""
        for scope, st in sorted(self._sites.items()):
            info = self._fleet.get(scope)
            if info is not None:
                feed.deliver(consumer, "on_site_report", st.slug, scope, info.report(polled_at))
        if self._correlator is not None:
            self._correlator.evaluate(mapped_site_rows(self._fleet, mapped), now,
                                      self._fleet_every)

    def _note_new_issues(self, before: Optional[dict[str, SiteInfo]],
                         before_at: Optional[datetime], now: datetime) -> None:
        """Remember when each site's issue lists last gained an entry since
        the previous FRESH fleet poll (at most two intervals old). No fresh
        previous poll (a start, a gap): nothing is known to be new."""
        fleet = self._fleet or {}
        for book in (self._issues_new_at, self._issue_hits, self._issue_streak):
            for scope in [s for s in book if s not in fleet]:
                book.pop(scope, None)
        if before is None or before_at is None or \
                now - before_at > self._fleet_every * 2 + timedelta(seconds=60):
            self._issue_streak.clear()          # a gap: nothing is consecutive
            return
        for scope, info in fleet.items():
            prev = before.get(scope)
            if prev is None:
                self._issue_streak.pop(scope, None)
                continue
            primary = primary_wan(info.wans)
            new = _issue_key_set(info.stats, primary) - _issue_key_set(prev.stats, primary)
            if new:
                self._issues_new_at[scope] = now
                self._issue_hits.setdefault(scope, deque(maxlen=ISSUE_HITS_MAX)).append(
                    (now, len(new)))
                self._issue_streak[scope] = self._issue_streak.get(scope, 0) + 1
            else:
                self._issue_streak.pop(scope, None)

    def _remember_wans(self, now: datetime) -> None:
        """WAN coverage memory. A WAN seen CONFIGURED (up, plugged in or
        addressed) on a fleet poll within `WAN_MEMORY` that now reads
        unplugged with no address has DROPPED — its modem died, its cable
        was pulled: it is marked configured (`configured_from: 'history'`)
        and down, so the Fleet says "backup line down", never "WAN2 not
        configured", and the site is not counted as having no backup line.
        A WAN unplugged for longer than that is taken as decommissioned."""
        fleet = self._fleet or {}
        for scope in [s for s in self._wan_seen if s not in fleet]:
            self._wan_seen.pop(scope, None)
        # Hour granularity: the memory is 30 days; the saved state changes
        # at most hourly (not on every 5-minute fleet poll).
        stamp = _iso(now.replace(minute=0, second=0, microsecond=0)) or ""
        for scope, info in fleet.items():
            seen = self._wan_seen.setdefault(scope, {})
            for w in info.wans:
                name = w.get("wan")
                if not isinstance(name, str) or not name:
                    continue
                if w.get("configured") is True:
                    seen[name] = stamp
                elif w.get("configured") is False:
                    at = _from_iso(seen.get(name))
                    if at is not None and now - at <= WAN_MEMORY:
                        w["configured"] = True
                        w["configured_from"] = "history"
                        if w.get("port_up") is None:
                            w["port_up"] = False
                    else:
                        seen.pop(name, None)
            if not seen:
                self._wan_seen.pop(scope, None)

    def _share_discovery(self) -> None:
        if self._instance_id is None or self._fleet is None:
            return
        try:
            from shared_adapter_contract.types import VendorTenant, VendorTenantListing

            from apps.octo.instances import vendor_tenants
            from apps.octo.instances.manager import get_instance

            record = get_instance(self._instance_id)
            if record is None or record.disabled_at is not None:
                return
            vendor_tenants.store(self._instance_id, record.cred_ref, VendorTenantListing(
                tenants=[VendorTenant(id=scope, label=tenant_label(info))
                         for scope, info in sorted(self._fleet.items())],
                truncated=self._fleet_truncated,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.debug("[unifi-poller] discovery not shared (%s)", type(exc).__name__)

    def _feed_consumer(self) -> Any:
        return self._consumer if self._consumer is not None else feed.current()

    # ----- one site -----

    def _site_tasks(self, st: SiteState, report: CycleReport) -> None:
        now = self._now()
        if st.held_until is not None and now < st.held_until:
            return
        info = (self._fleet or {}).get(st.scope)
        if info is None:
            st.problem = ("UniFi's site list no longer shows this site (deleted, or the "
                          "console was removed from the account)")
            st.problem_kind = "missing"
            # Nothing to do until the next fleet poll says otherwise: its own
            # due times follow the fleet (never a past due time that would
            # spin the cycle every second).
            st.syslog_due = st.clients_due = self._fleet_due
            return
        if st.problem_kind == "missing":
            st.problem = st.problem_kind = None
        report.sites += 1
        syslog_due = st.syslog_due is None or now >= st.syslog_due
        clients_due = st.clients_due is None or now >= st.clients_due
        networks_due = st.networks_due is None or now >= st.networks_due
        if not (syslog_due or clients_due or networks_due):
            return                       # an idle cycle opens no per-site database
        try:
            if not self._still_mapped(st):
                return
            self._finish_pending(st)
            if syslog_due:
                self._read_syslog(st, info, report)
                st.syslog_due = self._now() + self._syslog_every
            if clients_due:
                if self._wants(st):
                    self._read_clients(st, info, report)
                st.clients_due = self._now() + self._clients_every
            if networks_due:
                self._read_networks(st, info, report)
            st.failures = 0
            st.held_until = None
            st.problem = st.problem_kind = None
        except UniFiConsoleError as exc:
            report.contacted = True
            self._site_failed(st, "console", (
                f"The console did not answer through the UniFi connector ({exc}) — it may be "
                "offline or its Network application unreachable. Retried on its own."))
        except (sqlite3.Error, FileNotFoundError, OSError) as exc:
            self._site_failed(st, "store", (
                f"This tenant's telemetry store could not be written ({type(exc).__name__}); "
                "the site is retried on its own and nothing it read was lost."))

    def _site_failed(self, st: SiteState, kind: str, text: str) -> None:
        base, ceiling = SITE_BACKOFF[kind]
        delay = min(ceiling, base * (2 ** min(st.failures, 16)))
        st.failures += 1
        st.held_until = self._now() + timedelta(seconds=delay)
        st.problem, st.problem_kind = text, kind
        logger.warning("[unifi-poller] site %s held for %.0fs (%s)", st.scope, delay, kind)

    # ----- system log -----

    def _finish_pending(self, st: SiteState) -> None:
        """Alerts claimed but never stored (a crash between the two writes)."""
        for key, payload in store.pending(st.slug, st.scope):
            self._store_alert(st, key, payload)

    def _read_syslog(self, st: SiteState, info: SiteInfo, report: CycleReport) -> None:
        now_ms = _ms(self._now())
        cur = store.cursor(st.slug, st.scope)
        overlap = int(OVERLAP.total_seconds() * 1000)
        if cur is None:
            start = now_ms - int(BACKFILL.total_seconds() * 1000)
            cur = store.Cursor(st.scope, hwm_ms=start, scanned_to_ms=start, recent_ids=[])
            window_from = start
        else:
            window_from = max(0, cur.scanned_to_ms - overlap)
        # Window by window up to now (a back-fill or a long outage is read in
        # bounded windows, each applied whole). Every window ends AFTER the
        # cursor: progress never goes backwards.
        for _ in range(256):
            progress = cur.scanned_to_ms
            if progress >= now_ms:
                break
            window_to = min(now_ms, max(progress, window_from) + int(MAX_WINDOW.total_seconds() * 1000))
            events, window_to = self._read_window(info, window_from, progress, window_to)
            report.contacted = True
            cur = self._apply_window(st, info, cur, events, window_to, report)
            if window_to >= now_ms:
                break
            window_from = max(0, window_to - overlap)
        st.last_syslog_at = self._now()

    def _read_window(self, info: SiteInfo, frm: int, progress: int,
                     to: int) -> tuple[list[dict[str, Any]], int]:
        """Every event of [frm, to]. A window with more than
        MAX_LOG_PAGES_PER_WINDOW pages has its NEW part (after `progress`, the
        cursor) halved until it fits or is MIN_WINDOW long; a minimal window
        is read whole whatever its size (`_read_all`)."""
        min_ms = int(MIN_WINDOW.total_seconds() * 1000)
        first = None
        for _ in range(MAX_WINDOW_SPLITS + 1):
            first = self._client.system_log(info.host_id, info.internal_ref, from_ms=frm,
                                            to_ms=to, page_number=0, priority=PRIORITY_SECURITY)
            if first.total_pages > MAX_LOG_PAGES_PER_WINDOW and to - max(progress, frm) > min_ms:
                to = max(progress, frm) + max(min_ms, (to - max(progress, frm)) // 2)
                continue
            break
        assert first is not None
        return self._read_all(info, frm, to, first), to

    def _read_all(self, info: SiteInfo, frm: int, to: int, first: Any) -> list[dict[str, Any]]:
        """Every page of [frm, to], whatever the order (the live log is
        NEWEST FIRST, verified 2026-10-01), with no event skipped and none
        counted twice:
          * items are kept by id — a write landing while the pages are read
            pushes a descending list down a slot (the same item again on the
            next page);
          * pages are read up to the LATEST answer's page count (that push
            can move the oldest items past the count the first answer gave);
          * past HARD_MAX_LOG_PAGES, the part NOT yet covered is asked for
            again as its own range — newest first, that is [frm, the oldest
            time read]; oldest first, [the newest time read, to] — never
            dropped (the old reader silently lost it)."""
        seen: dict[str, dict[str, Any]] = {}

        def keep(items: list[dict[str, Any]]) -> None:
            for item in items:
                ev = catalogue.normalise(item)
                key = ev.id if ev is not None else repr(sorted(item.items()))[:200]
                seen.setdefault(key, item)

        def ts_of(item: dict[str, Any]) -> Optional[int]:
            return catalogue.to_ms(item.get("timestamp"))

        lo, hi = frm, to
        page0 = first
        for _round in range(64):
            keep(page0.events)
            total, page = page0.total_pages, 1
            read_ts = [t for t in (ts_of(x) for x in page0.events) if t is not None]
            descending = len(read_ts) < 2 or read_ts[0] >= read_ts[-1]
            while page < HARD_MAX_LOG_PAGES and page < total:
                more = self._client.system_log(info.host_id, info.internal_ref, from_ms=lo,
                                               to_ms=hi, page_number=page,
                                               priority=PRIORITY_SECURITY)
                keep(more.events)
                read_ts += [t for t in (ts_of(x) for x in more.events) if t is not None]
                total = max(total, more.total_pages)
                page += 1
                if not more.events:
                    break
            if page < HARD_MAX_LOG_PAGES or page >= total or not read_ts:
                break
            # More pages than the cap: ask for the part not covered yet.
            if descending:
                nxt_lo, nxt_hi = lo, min(read_ts)
            else:
                nxt_lo, nxt_hi = max(read_ts), hi
            if (nxt_lo, nxt_hi) == (lo, hi):
                logger.error("[unifi-poller] %s: more than %d system-log pages share one "
                             "moment; the rest of it is not read", info.scope,
                             HARD_MAX_LOG_PAGES)
                break
            lo, hi = nxt_lo, nxt_hi
            page0 = self._client.system_log(info.host_id, info.internal_ref, from_ms=lo,
                                            to_ms=hi, page_number=0, priority=PRIORITY_SECURITY)
        return list(seen.values())

    def _apply_window(self, st: SiteState, info: SiteInfo, cur: store.Cursor,
                      raw: list[dict[str, Any]], window_to: int,
                      report: CycleReport) -> store.Cursor:
        seen = set(cur.recent_ids)
        events: list[catalogue.LogEvent] = []
        for item in raw:
            ev = catalogue.normalise(item)
            if ev is not None:
                events.append(ev)
        events.sort(key=lambda e: (e.ts_ms, e.id))
        ctx = info.context()
        rollups: dict[tuple[str, str], list[int]] = {}
        claims: list[store.Claim] = []
        boundaries: list[dict[str, Any]] = []
        hwm = cur.hwm_ms
        for ev in events:
            if ev.id in seen:
                continue                 # processed by an earlier, overlapping window
            seen.add(ev.id)
            hwm = max(hwm, ev.ts_ms)
            cls = catalogue.classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity)
            if cls.family == catalogue.SIGNAL:
                payload = catalogue.signal_payload(cls, ev, ctx)
                sig = _m(payload.get("signal"))
                hour = str(sig.get("bucket_hour") or catalogue.bucket_hour(ev.ts_ms))
                subject = str(sig.get("subject") or "")
                remote = _m(payload.get("ips")).get("remote_ip")
                claims.append(store.Claim(
                    key=catalogue.bucket_key(st.scope, cls.kind, subject, hour), hour=hour,
                    kind=cls.kind, subject=subject, seen=ev.iso, payload=payload,
                    remote=str(remote) if isinstance(remote, str) and remote else None))
            else:
                slot = rollups.setdefault((catalogue.bucket_hour(ev.ts_ms), cls.kind),
                                          [0, catalogue.ocsf.class_of(cls.kind)[0]])
                slot[0] += 1
            b = catalogue.boundary_event(ev)
            if b is not None:
                boundaries.append(b)
        # The next window re-reads from window_to - OVERLAP: remember the ids
        # it can see again (processed now or before), and only those.
        keep_from = window_to - int(OVERLAP.total_seconds() * 1000) - 1000
        recent = list(dict.fromkeys(e.id for e in events if e.ts_ms >= keep_from))
        new_cur = store.Cursor(st.scope, hwm_ms=hwm, scanned_to_ms=window_to, recent_ids=recent)
        result = store.apply_page(
            st.slug, st.scope,
            rollups={k: (v[0], v[1]) for k, v in rollups.items()},
            claims=claims, new_cursor=new_cur,
        )
        report.rollups += result.rollups
        for key, payload in result.new_claims:
            if self._store_alert(st, key, payload):
                report.signals += 1
                st.signals += 1
        consumer = self._feed_consumer()
        if boundaries:
            _ran, result = feed.call(consumer, "on_log_events", st.slug, st.scope, boundaries)
            self._derived(st, info, consumer, result, report)
        # The log is written late (hence OVERLAP): what is GUARANTEED read
        # whole is the window's end minus the overlap — an answer that relied
        # on the log never becomes final before a late line could land.
        complete_to = window_to - int(OVERLAP.total_seconds() * 1000)
        if complete_to > 0:
            feed.deliver(consumer, "on_log_progress", st.slug, st.scope,
                         {"scanned_to": catalogue.iso_ms(complete_to)})
        return new_cur

    def _derived(self, st: SiteState, info: SiteInfo, consumer: Any, result: Any,
                 report: CycleReport) -> None:
        """Store the DERIVED signals a feed consumer handed back (the MAC-
        anomaly rule's findings) as UniFi signals — mapped and coalesced here,
        at the adapter boundary (site + MAC + kind per clock hour)."""
        items = feed.derived_signals(result)
        if not items:
            return
        ctx = info.context()
        claims: list[store.Claim] = []
        ids: dict[str, int] = {}
        for item in items:
            payload = catalogue.derived_payload(item, ctx)
            if payload is None:
                continue
            sig = _m(payload.get("signal"))
            hour, subject = str(sig.get("bucket_hour")), str(sig.get("subject"))
            key = catalogue.bucket_key(st.scope, "mac_anomaly", subject, hour)
            ids[key] = int(item["anomaly_id"])
            claims.append(store.Claim(key=key, hour=hour, kind="mac_anomaly", subject=subject,
                                      seen=str(_m(payload.get("event")).get("timestamp")),
                                      payload=payload))
        if not claims:
            return
        result_ = store.claim(st.slug, st.scope, claims)
        stored_keys = {k for k, _p in result_.new_claims}
        for key, payload in result_.new_claims:
            if self._store_alert(st, key, payload):
                report.signals += 1
                st.signals += 1
        for key, anomaly_id in ids.items():
            # Counted into an existing bucket or stored now: either way done.
            feed.deliver(consumer, "on_signal_stored", st.slug, st.scope,
                         {"anomaly_id": anomaly_id, "new_alert": key in stored_keys})

    def _store_alert(self, st: SiteState, key: str, payload: dict[str, Any]) -> bool:
        """Store one claimed alert under the site's tenant — directly: a UniFi
        site never auto-creates or auto-links a tenant — then close its
        outbox row. True when a NEW alert was stored."""
        payload = sanitize.strip(payload)
        event = self._adapter.extract_event(payload)
        inner = getattr(self._sink, "inner", self._sink)
        outcome = inner.ingest(st.slug, VENDOR, event)
        event_id = getattr(outcome, "event_id", None)
        if isinstance(event_id, int):
            store.set_event(st.slug, key, event_id)
        if getattr(outcome, "duplicate", False):
            return False
        freshness.record_event(instance_id=self._instance_id, slug=st.slug)
        ts = event.received_at
        if ts and (self._last_event_at is None or ts > self._last_event_at):
            self._last_event_at = ts
        if self._publish is not None:
            self._publish(st.slug, event)
        return True

    def _ingest_derived(self, slug: str, payload: dict[str, Any]) -> Optional[int]:
        """Store a DERIVED signal (the ISP-outage incident) under `slug` —
        the operator's internal tenant. The stored row's id (an existing one
        for a re-delivery: the sink's identity guard). Raises the store's
        errors (the correlator keeps the item queued)."""
        payload = sanitize.strip(payload)
        event = self._adapter.extract_event(payload)
        inner = getattr(self._sink, "inner", self._sink)
        outcome = inner.ingest(slug, VENDOR, event)
        event_id = getattr(outcome, "event_id", None)
        if not getattr(outcome, "duplicate", False):
            freshness.record_event(instance_id=self._instance_id, slug=slug)
            if self._publish is not None:
                self._publish(slug, event)
        return int(event_id) if isinstance(event_id, int) else None

    # ----- clients (entity resolution's leases) -----

    def _integration_site_id(self, info: SiteInfo) -> str:
        now = self._now()
        cached = self._integration.get(info.host_id) or {}
        at = cached.get("at")
        fresh = False
        if isinstance(at, str):
            try:
                fresh = now - datetime.fromisoformat(at.replace("Z", "+00:00")) < INTEGRATION_IDS_EVERY
            except ValueError:
                fresh = False
        sites = _m(cached.get("sites"))
        if not fresh or info.internal_ref not in sites:
            listed = self._client.integration_sites(info.host_id, priority=PRIORITY_CLIENTS)
            sites = {s.internal_reference: s.id for s in listed}
            self._integration[info.host_id] = {"at": _iso(now), "sites": sites}
        sid = sites.get(info.internal_ref)
        if not sid:
            # FAIL CLOSED: never the console's only listed site — on a
            # multi-site console that is ANOTHER site (and maybe another
            # tenant's): its clients would be written here.
            raise UniFiConsoleError("this site is not listed by the console's Network "
                                    "application")
        return str(sid)

    def _wants(self, st: SiteState) -> bool:
        """Whether the feed takes this site's client list (its tenant's entity
        switch is shadow / on). A consumer without `wants` takes everything.
        A tenant switched off costs no client-list call (otherwise each site
        would cost 12 an hour, every one thrown away)."""
        ran, wanted = feed.call(self._feed_consumer(), "wants", st.slug, st.scope, None)
        if ran and not wanted:
            st.clients_seen = None
            st.clients_problem = None
            return False
        return True

    def _read_clients(self, st: SiteState, info: SiteInfo, report: CycleReport) -> None:
        """A snapshot that cannot be read whole is reported to the feed and
        retried next interval; it never holds the site's system log (the
        security read) — a console that is really down fails that read too."""
        polled = self._now()
        try:
            sid = self._integration_site_id(info)
            snap = self._client.clients(info.host_id, sid, priority=PRIORITY_CLIENTS)
        except UniFiConsoleError as exc:
            report.contacted = True
            self._integration.pop(info.host_id, None)
            st.clients_problem = (f"The client list could not be read whole ({exc}); retried "
                                  "next interval.")
            feed.deliver(self._feed_consumer(), "on_client_snapshot_failed", st.slug, st.scope,
                         {"scope": st.scope, "polled_at": _iso(polled), "reason": str(exc)})
            return
        st.clients_problem = None
        report.contacted = True
        clients = []
        for c in snap.clients:
            access = _m(c.get("access")).get("type")
            mac = catalogue._mac(c.get("macAddress"))  # noqa: SLF001 — one normaliser
            clients.append({k: v for k, v in {
                "id": _text(c.get("id"), 64) or None,
                "name": _text(c.get("name"), 120) or None,
                "mac": mac,
                "ip": catalogue._ip(c.get("ipAddress")),  # noqa: SLF001
                "connected_at": _text(c.get("connectedAt"), 40) or None,
                "type": _text(c.get("type"), 24) or None,
                "uplink_device_id": _text(c.get("uplinkDeviceId"), 64) or None,
                "access": _text(access, 24) if isinstance(access, str) else None,
            }.items() if v is not None})
        st.last_clients_at = polled
        st.clients_seen = len(clients)
        consumer = self._feed_consumer()
        _ran, result = feed.call(consumer, "on_client_snapshot", st.slug, st.scope, {
            "scope": st.scope, "polled_at": _iso(polled), "complete": True,
            "gateway_online": info.gateway_online, "total": snap.total,
            "clients": sanitize.strip(clients),
        })
        self._derived(st, info, consumer, result, report)

    def _read_networks(self, st: SiteState, info: SiteInfo, report: CycleReport) -> None:
        """Daily — and only while the feed takes them: a tenant whose entity
        switch is off is not read at all; the networks count as read only
        when the consumer TOOK them (keyed by site AND tenant: a re-map or a
        switch turned on reads them on the next cycle, not a day later)."""
        key = f"{st.scope}|{st.slug}"
        last = self._networks_at.get(key)
        now = self._now()
        if last:
            try:
                if now - datetime.fromisoformat(last.replace("Z", "+00:00")) < NETWORKS_EVERY:
                    st.networks_due = datetime.fromisoformat(
                        last.replace("Z", "+00:00")) + NETWORKS_EVERY
                    return
            except ValueError:
                pass
        consumer = self._feed_consumer()
        ran, wanted = feed.call(consumer, "wants", st.slug, st.scope, None)
        if ran and not wanted:
            st.networks_due = now + NETWORKS_RECHECK
            return
        networks = self._client.networks(info.host_id, info.internal_ref,
                                         priority=PRIORITY_DISCOVERY)
        report.contacted = True
        ran, taken = feed.call(consumer, "on_networks", st.slug, st.scope, networks)
        if not ran or taken is not False:
            self._networks_at[key] = _iso(now) or ""
            st.networks_due = now + NETWORKS_EVERY
        else:
            st.networks_due = now + NETWORKS_RECHECK

    # ----- scheduling -----

    def _seconds_until(self, when: Optional[datetime]) -> float:
        if when is None:
            return 1.0
        return max(1.0, (when - self._now()).total_seconds())

    def _next_due_in(self) -> float:
        dues = [self._fleet_due]
        for st in self._sites.values():
            if st.held_until is not None:
                dues.append(st.held_until)
                continue
            if st.problem_kind == "missing":
                continue                 # waits for the next fleet poll
            dues.extend([st.syslog_due, st.clients_due])
        dues = [d for d in dues if d is not None]
        if not dues:
            return self._syslog_every.total_seconds()
        return self._seconds_until(min(dues))

    def planned_calls_per_hour(self) -> float:
        fleet = 2 * 3600.0 / self._fleet_every.total_seconds()
        per_site = (3600.0 / self._syslog_every.total_seconds()
                    + 3600.0 / self._clients_every.total_seconds())
        return round(fleet + per_site * len(self._sites), 1)

    # ----- restart-safe state (the fleet-side bits; the system-log cursor is
    # in each tenant's own telemetry.db) -----

    def _load_state(self) -> None:
        if self._state_loaded:
            return
        self._state_loaded = True
        if self._instance_id is None:
            return
        raw = poller_state.load(self._instance_id, STATE_KEY)
        if not isinstance(raw, dict) or raw.get("v") != STATE_VERSION:
            return
        integ = raw.get("integration")
        if isinstance(integ, dict):
            self._integration = {
                h: {"at": v.get("at"), "sites": {r: i for r, i in _m(v.get("sites")).items()
                                                 if valid_internal_ref(r) and valid_site_id(i)}}
                for h, v in integ.items() if valid_host_id(h) and isinstance(v, dict)
            }
        nets = raw.get("networks_at")
        if isinstance(nets, dict):
            self._networks_at = {k: t for k, t in nets.items()
                                 if isinstance(k, str) and k.count("|") == 1
                                 and split_scope(k.split("|")[0]) and isinstance(t, str)}
        wans = raw.get("wan_seen")
        if isinstance(wans, dict):
            self._wan_seen = {
                scope: {str(n): t for n, t in v.items()
                        if isinstance(n, str) and _from_iso(t) is not None}
                for scope, v in wans.items() if split_scope(scope) and isinstance(v, dict)}

    def _save_state(self) -> None:
        if self._instance_id is None:
            return
        live = {f"{scope}|{st.slug}" for scope, st in self._sites.items()}
        value = {"v": STATE_VERSION, "integration": self._integration,
                 "networks_at": {k: t for k, t in self._networks_at.items() if k in live},
                 "wan_seen": {s: dict(v) for s, v in self._wan_seen.items() if v}}
        text = poller_state.dumps(value)
        if text == self._state_text:
            return
        if poller_state.save(self._instance_id, STATE_KEY, value):
            self._state_text = text

    # ----- snapshot for the card / source health -----

    def _update_snapshot(self) -> None:
        fleet = self._fleet or {}
        sites = {}
        for scope, st in self._sites.items():
            info = fleet.get(scope)
            sites[scope] = {
                "scope": scope, "tenant_slug": st.slug,
                "name": info.name if info else None,
                "console_name": info.console_name if info else None,
                "gateway_online": info.gateway_online if info else None,
                "host_connected": info.host_connected if info else None,
                "last_syslog_at": _iso(st.last_syslog_at),
                "last_clients_at": _iso(st.last_clients_at),
                "clients": st.clients_seen,
                "signals": st.signals,
                "problem": st.problem or st.clients_problem,
                "problem_kind": st.problem_kind or ("clients" if st.clients_problem else None),
            }
        snap = {
            "mapped": len(self._sites),
            "known": len(fleet) if self._fleet is not None else None,
            "known_ids": sorted(fleet) if self._fleet is not None else None,
            "known_at": _iso(self._fleet_at),
            "consoles": self._consoles,
            # Only consoles that host a MAPPED site: an ignored personal
            # console that is switched off is nobody's problem.
            "consoles_offline": len({i.host_id for scope, i in fleet.items()
                                     if i.host_connected is False and scope in self._sites}),
            "gateways_offline": sum(1 for s in sites.values() if s["gateway_online"] is False),
            "problems": sum(1 for s in sites.values() if s["problem"]),
            "sites": sites,
            "calls_per_hour_planned": self.planned_calls_per_hour(),
            "spacing_sec": self._client.limiter.min_spacing_sec,
        }
        with self._snap_lock:
            self._snapshot = snap


def counts_by_kind(rows: list[Any]) -> dict[str, int]:
    """Tests / diagnostics: total roll-up events per kind."""
    c: Counter = Counter()
    for r in rows:
        c[r["kind"]] += int(r["events"])
    return dict(c)
