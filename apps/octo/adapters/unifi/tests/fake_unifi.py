"""A fake UniFi cloud (Site Manager API + connector proxy) at the TRANSPORT
layer, on a fake clock.

Tests run the REAL UniFiClient / limiter / UniFiSourceAdapter / UniFiPoller /
sink: only the socket is replaced, by mounting this `requests` transport
adapter on the client's own session (the NextDNS / RocketCyber model).
Nothing here ever touches the network.

FAITHFUL to what the live API answered on 2026-10-01 (read-only key):

  GET /v1/hosts                    {data: [host], httpStatusCode, traceId}
  GET /v1/sites                    {data: [site], …}; site.meta{name, desc,
                                   timezone, gatewayMac}; statistics{counts,
                                   ispInfo, wans{WAN: {externalIp, ispInfo…}}}
  GET …/integration/v1/sites       the console's sites: the SAME id and
                                   internalReference 'default' on every
                                   single-site console (V11)
  GET …/integration/v1/sites/{id}/clients?limit&offset
                                   {offset, limit, count, totalCount, data}
  POST …/v2/api/site/{ref}/system-log/all  body {timestampFrom, timestampTo,
                                   pageNumber, pageSize} → {data (NEWEST
                                   first), page_number, total_element_count,
                                   total_page_count}
  GET …/api/s/{ref}/rest/networkconf  networks WITH secrets (x_*, psk,
                                   RADIUS / VPN keys) — the client must drop
                                   every one of them

  IPS events (live, 2026-10-01 20:00): parameters SRC_IP / DST_IP {id, name,
  not_actionable}, DEVICE {…, name, model_name, ip} (the reporting
  gateway), INITIATOR_ID {id}, CONSOLE_NAME / CONSOLE_WITH_DEVICE_NAME {id,
  name} — NO signature, category or CLIENT parameter: the threat is named in
  title_raw / message_raw.

Assumptions (not observed live; marked `fixture:`): pageSize / nextToken on
the fleet endpoints (none at a few dozen consoles); system-log windows inclusive on
both ends; the WORDING of an IPS event's title_raw / message_raw (only that
the threat is named there); the delegated-prefix key on /v1/hosts wans[].

Every identifier is a documentation / fixture value: TEST-NET addresses
(192.0.2.x, 198.51.100.x, 203.0.113.x) for every public / WAN side, the
fixture LAN built by `lan(n)` (see there: private on purpose), the RFC 7042
documentation MAC range (00:00:5e:00:53:xx), made-up host ids.
"""
from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, unquote, urlsplit

import requests
from requests.adapters import BaseAdapter

from apps.octo.adapters.unifi.client import UniFiClient, UniFiConfig
from apps.octo.adapters.unifi.limiter import UniFiRateLimiter, install_limiter

API_HOST = "api.ui.com"
# Structurally fake: a marker plus padding (redaction rules need ≥ 24 chars).
API_KEY = "fixture-unifi-key-" + "8" * 24
CREDS = {"UNIFI_API_KEY": API_KEY}

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

HOST_A = "F1X7A0000000000000000000000000000000000000000000000000A001:100000001"
HOST_B = "F1X7B0000000000000000000000000000000000000000000000000B002:100000002"
HOST_C = "F1X7C0000000000000000000000000000000000000000000000000C003:100000003"
# The SAME site id on every single-site console (V11: site ids collide).
SITE_DEFAULT = "f1x7517e0000000000000001"
INTEGRATION_DEFAULT = "0f0f0f0f-0000-4000-8000-000000000001"
SCOPE_A = f"{HOST_A}/{SITE_DEFAULT}"
SCOPE_B = f"{HOST_B}/{SITE_DEFAULT}"
SCOPE_C = f"{HOST_C}/{SITE_DEFAULT}"


def mac(n: int) -> str:
    return f"00:00:5e:00:53:{n:02x}"


def lan(n: int, net: int = 20) -> str:
    """Address .n of the fixture site's LAN (`net` 20 = 'Office', 30 =
    'Guest'). RFC 1918 on purpose, never a TEST-NET address: the catalogue
    tells the site's own end of an IPS event from the remote end by its
    address space (`catalogue.is_local`), so a LAN address must be private."""
    return f"10.{net}.0.{n}"


class FakeClock:
    """ONE clock for the poller (`now`), the limiter (`monotonic` + `wait`)
    and the fake server. `wait` advances time instead of sleeping."""

    def __init__(self, start: datetime = T0) -> None:
        self._start = start
        self._t = 0.0
        self._lock = threading.Lock()

    def monotonic(self) -> float:
        with self._lock:
            return self._t

    def now(self) -> datetime:
        with self._lock:
            return self._start + timedelta(seconds=self._t)

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += max(0.0, float(seconds))

    def wait(self, cond: threading.Condition, timeout: Optional[float]) -> None:
        if timeout is None:
            raise AssertionError("a lone caller was told to wait for another caller")
        self.advance(max(timeout, 0.001))


def ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def log_event(
    at: datetime, event: str, *, category: str = "SECURITY", subcategory: str = "",
    severity: str = "HIGH", params: Optional[dict[str, Any]] = None,
    title: str = "", message: str = "", eid: Optional[str] = None,
) -> dict[str, Any]:
    """One system-log item exactly as system-log/all lists it."""
    return {
        "id": eid or f"evt-{event.lower()}-{ms(at)}",
        "timestamp": ms(at),
        "category": category,
        "subcategory": subcategory,
        "event": event,
        "severity": severity,
        "type": "EVENT",
        "status": "NEW",
        "show_on_dashboard": True,
        "target": "",
        "title_raw": title or event.replace("_", " ").title(),
        "message_raw": message,
        "parameters": params or {},
    }


def ips_event(at: datetime, *, blocked: bool = True, client_n: int = 37,
              lan_ip: str = lan(37), remote_ip: str = "203.0.113.66",
              signature: str = "ET MALWARE Example Beacon", sig_id: str = "2030001",
              client_name: str = "FRONT-DESK-PC", eid: Optional[str] = None,
              gateway: str = "acme-gateway", inbound: bool = False) -> dict[str, Any]:
    """An IPS event in the LIVE shape: no signature / category / CLIENT
    parameter — the threat is named in the text (fixture: the exact wording);
    SRC_IP / DST_IP {id, name, not_actionable}; DEVICE = the gateway that
    reported it. `client_n`, `client_name` and `sig_id` are accepted for old
    call sites and not in the event (the live event carries none of them)."""
    del client_n, client_name, sig_id
    src, dst = (remote_ip, lan_ip) if inbound else (lan_ip, remote_ip)
    return log_event(
        at, "THREAT_BLOCKED" if blocked else "THREAT_DETECTED",
        subcategory="SECURITY_INTRUSION_PREVENTION", severity="HIGH", eid=eid,
        title="Threat " + ("Blocked" if blocked else "Detected"),
        message=f"{signature}: {{SRC_IP}} to {{DST_IP}}",
        params={
            "SRC_IP": {"id": src, "name": src, "not_actionable": False},
            "DST_IP": {"id": dst, "name": dst, "not_actionable": False},
            "DEVICE": {"device_fingerprint_id": 0, "fingerprint_source": 0, "id": "gw-0001",
                       "ip": lan(1), "model": "UDMPRO", "model_name": "Dream Machine Pro",
                       "name": gateway, "version": "4.0.0"},
            "INITIATOR_ID": {"id": "fixture-initiator"},
            "CONSOLE_NAME": {"id": "fixture-console", "name": "acme-udm"},
            "CONSOLE_WITH_DEVICE_NAME": {"id": "fixture-console", "name": "acme-udm"},
        },
    )


def legacy_ips_event(at: datetime, *, client_n: int = 37, lan_ip: str = lan(37),
                     remote_ip: str = "203.0.113.66", signature: str = "ET MALWARE Example Beacon",
                     sig_id: str = "2030001", client_name: str = "FRONT-DESK-PC",
                     eid: Optional[str] = None) -> dict[str, Any]:
    """fixture: an IPS event with CLIENT / SIGNATURE / CATEGORY parameters (not
    the live shape) — the tolerant reader still takes them when present."""
    return log_event(
        at, "THREAT_BLOCKED", subcategory="SECURITY_INTRUSION_PREVENTION", severity="HIGH",
        eid=eid, title="Threat {SIGNATURE} blocked", message="{CLIENT} → {DST_IP} matched {SIGNATURE}",
        params={
            "CLIENT": {"id": mac(client_n), "ip": lan_ip, "name": client_name,
                       "hostname": client_name.lower()},
            "SRC_IP": {"id": lan_ip}, "DST_IP": {"id": remote_ip},
            "DST_PORT": {"id": "443"}, "PROTOCOL": {"name": "TCP"},
            "SIGNATURE": {"id": sig_id, "name": signature},
            "CATEGORY": {"name": "Malware"},
        },
    )


def client_event(at: datetime, event: str = "CLIENT_CONNECTED_WIRED", *, n: int = 37,
                 ip: str = lan(37), name: str = "FRONT-DESK-PC") -> dict[str, Any]:
    return log_event(
        at, event, category="CLIENT_DEVICES",
        subcategory="MONITORING_WIRED" if "WIRED" in event else "MONITORING_WIFI",
        severity="LOW", message="{CLIENT} connected",
        params={"CLIENT": {"id": mac(n), "ip": ip, "hostname": name.lower(), "name": name,
                           "device_fingerprint_id": 1, "fingerprint_source": 1},
                "IP": {"id": ip}, "NETWORK": {"id": "net-1", "name": "Office"}},
    )


@dataclass
class FakeSite:
    site_id: str = SITE_DEFAULT
    ref: str = "default"
    desc: str = "Acme Corp"
    integration_id: str = INTEGRATION_DEFAULT
    timezone: str = "America/Chicago"
    wans: dict[str, dict[str, Any]] = field(default_factory=lambda: {
        "WAN": {"externalIp": "203.0.113.129", "asn": 64500, "isp": "Example ISP"}})
    offline_gateway: int = 0
    clients: list[dict[str, Any]] = field(default_factory=list)
    log: list[dict[str, Any]] = field(default_factory=list)
    networks: list[dict[str, Any]] = field(default_factory=list)
    # fixture: False = the console's own integration/v1/sites does not list
    # it (deleted / migrated off, site-scoped permissions) while the cloud's
    # fleet list still does.
    listed: bool = True
    # statistics.internetIssues (fixture-shaped entries: {index, ...}).
    internet_issues: list[dict[str, Any]] = field(default_factory=list)
    # statistics.wans.<name>.wanIssues, per WAN name.
    wan_issues: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # statistics.counts.offlineWifiDevice / offlineWiredDevice (None: the
    # report has no such key).
    offline_wifi: Optional[int] = None
    offline_wired: Optional[int] = None


@dataclass
class FakeConsole:
    host_id: str
    name: str
    location_text: str = "100 Example St, Springfield"
    lat: float = 39.0
    long: float = -89.0
    state: str = "connected"
    sites: list[FakeSite] = field(default_factory=list)
    # The console's WAN interface address (/v1/hosts reportedState.wans[].
    # ipv4): equal to the site's externalIp = direct; 100.64/10 = CGNAT;
    # RFC 1918 = double NAT.
    wan_ipv4: str = "192.0.2.10"
    # A dual-stack WAN: reportedState.wans[].ipv6 (seen live) and the prefix
    # delegated to the LAN (fixture: the key `ipv6Prefix` was NOT seen live).
    wan_ipv6: Optional[str] = None
    wan_pd: Optional[str] = None


@dataclass
class Call:
    method: str
    path: str
    query: dict[str, str]
    body: Any
    at: float
    status: int = 0


def default_networks() -> list[dict[str, Any]]:
    """networkconf as the live console answers it — WITH secrets."""
    return [
        {"_id": "net-1", "name": "Office", "purpose": "corporate", "ip_subnet": f"{lan(1)}/24",
         "vlan_enabled": False, "dhcpd_enabled": True, "dhcpd_dns_enabled": True,
         "dhcpd_dns_1": lan(1), "domain_name": "office.example.test",
         "x_passphrase": "fixture-not-a-real-passphrase",
         "radius_secret_fixture": "fixture-radius-material"},
        {"_id": "net-2", "name": "Guest", "purpose": "guest", "ip_subnet": f"{lan(1, 30)}/24",
         "vlan": 30, "vlan_enabled": True, "dhcpd_enabled": True, "dhcpd_dns_enabled": True,
         "dhcpd_dns_1": "198.51.100.53", "wpa_psk": "fixture-psk-material"},
        {"_id": "net-3", "name": "Site VPN", "purpose": "site-vpn",
         "x_wireguard_private_key": "fixtureFIXTUREfixtureFIXTUREfixture0000000=",
         "x_ipsec_pre_shared_key": "fixture-ipsec-material",
         "openvpn_configuration": "-----BEGIN OPENVPN STATIC KEY V1-----\nfixture\n"},
    ]


class FakeUniFiTransport(BaseAdapter):
    def __init__(self, clock: FakeClock) -> None:
        super().__init__()
        self.clock = clock
        self.key = API_KEY
        self.consoles: list[FakeConsole] = []
        self.calls: list[Call] = []
        self.unreachable = False
        self.throttle_next = 0
        self.retry_after: Optional[str] = None
        self.console_status: dict[str, int] = {}     # host → status for connector calls
        self.console_timeout: set[str] = set()
        self.clients_fail_after_page: dict[str, int] = {}   # host → fail on page N
        self.fleet_page_size: Optional[int] = None
        self.before_request: Optional[Callable[[Call], None]] = None
        self.min_gap_seen: float = math.inf

    # ----- building the fleet -----

    def add_console(self, host_id: str, name: str, **site_kw: Any) -> FakeConsole:
        console = FakeConsole(host_id=host_id, name=name)
        console.sites.append(FakeSite(**site_kw))
        console.sites[0].networks = default_networks()
        self.consoles.append(console)
        return console

    def console(self, host_id: str) -> FakeConsole:
        return next(c for c in self.consoles if c.host_id == host_id)

    def site(self, host_id: str, ref: str = "default") -> FakeSite:
        return next(s for s in self.console(host_id).sites if s.ref == ref)

    # ----- inspection -----

    def paths(self) -> list[str]:
        return [c.path for c in self.calls]

    def calls_to(self, fragment: str) -> list[Call]:
        return [c for c in self.calls if fragment in c.path]

    def gaps(self) -> list[float]:
        at = [c.at for c in self.calls]
        return [b - a for a, b in zip(at, at[1:])]

    # ----- the transport -----

    def send(self, request, **kwargs):  # noqa: ANN001
        for value in request.headers.values():
            if isinstance(value, str):
                value.encode("latin-1")
        parts = urlsplit(request.url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        body = json.loads(request.body) if request.body else None
        call = Call(request.method, unquote(parts.path), query, body, self.clock.monotonic())
        if self.calls:
            self.min_gap_seen = min(self.min_gap_seen, call.at - self.calls[-1].at)
        self.calls.append(call)
        if self.before_request is not None:
            self.before_request(call)
        resp = self._answer(request, parts, call)
        call.status = resp.status_code
        return resp

    def _answer(self, request, parts, call: Call) -> requests.Response:  # noqa: ANN001
        if self.unreachable:
            raise requests.ConnectionError("fixture: connection refused")
        if parts.hostname != API_HOST:
            return self._response(request, 404, {"message": "fixture: unknown host"})
        if request.headers.get("X-API-KEY") != self.key:
            return self._response(request, 401, {"message": "Unauthorized"})
        if self.throttle_next > 0:
            self.throttle_next -= 1
            r = self._response(request, 429, {"message": "Too Many Requests"})
            if self.retry_after:
                r.headers["Retry-After"] = self.retry_after
            return r
        segs = [s for s in call.path.split("/") if s]
        if segs == ["v1", "hosts"]:
            return self._fleet(request, call, [self._host(c) for c in self.consoles])
        if segs == ["v1", "sites"]:
            return self._fleet(request, call, [self._site(c, s) for c in self.consoles
                                               for s in c.sites])
        if len(segs) >= 6 and segs[:3] == ["v1", "connector", "consoles"] \
                and segs[4:6] == ["proxy", "network"]:
            return self._console(request, call, segs[3], segs[6:])
        return self._response(request, 404, {"message": "fixture: not found"})

    def _fleet(self, request, call: Call, items: list[dict[str, Any]]):  # noqa: ANN001
        size = self.fleet_page_size or int(call.query.get("pageSize", "500"))
        offset = int(call.query.get("nextToken", "0") or 0)
        page = items[offset: offset + size]
        out: dict[str, Any] = {"data": page, "httpStatusCode": 200, "traceId": "fixture"}
        if offset + size < len(items):
            out["nextToken"] = str(offset + size)
        return self._response(request, 200, out)

    def _host(self, c: FakeConsole) -> dict[str, Any]:
        return {
            "id": c.host_id, "hardwareId": "fixture-hw", "type": "console",
            "ipAddress": lan(1), "owner": True, "isBlocked": False,
            "reportedState": {
                "hostname": c.name, "name": c.name, "state": c.state,
                "location": {"lat": c.lat, "long": c.long, "radius": 100,
                             "text": c.location_text},
                "timezone": "America/Chicago",
                "wans": [{k: v for k, v in {
                    "ipv4": c.wan_ipv4, "ipv6": c.wan_ipv6, "ipv6Prefix": c.wan_pd,
                    "mac": mac(1), "type": "WAN", "plugged": True, "enabled": True,
                }.items() if v is not None}],
                # Secrets the boundary must drop.
                "x_ssh_password": "fixture-not-a-password",
                "anonid": "fixture-anon",
            },
            "userData": {"apiToken": "fixture-token-material"},
        }

    def _site(self, c: FakeConsole, s: FakeSite) -> dict[str, Any]:
        wans = {name: {"externalIp": w.get("externalIp"),
                       "ispInfo": {"asn": w.get("asn"), "name": w.get("isp"),
                                   "organization": w.get("isp")},
                       "portUp": True, "wanUptime": 99.9,
                       "wanIssues": [dict(i) for i in s.wan_issues.get(name, [])]}
                for name, w in s.wans.items()}
        split = {k: v for k, v in (("offlineWifiDevice", s.offline_wifi),
                                   ("offlineWiredDevice", s.offline_wired)) if v is not None}
        return {
            "hostId": c.host_id, "siteId": s.site_id,
            "meta": {"name": s.ref, "desc": s.desc, "timezone": s.timezone,
                     "gatewayMac": mac(2)},
            "statistics": {
                "counts": {"totalDevice": 4,
                           "offlineDevice": s.offline_gateway + sum(split.values()),
                           "offlineGatewayDevice": s.offline_gateway, "wifiClient": 3,
                           "wiredClient": 6, "guestClient": 0, **split},
                "ispInfo": {"asn": next(iter(s.wans.values()), {}).get("asn"),
                            "name": "Example ISP", "organization": "Example ISP"},
                "wans": wans, "internetIssues": [dict(i) for i in s.internet_issues],
            },
            "permission": "admin", "isOwner": True,
            "utm_token": "fixture-utm-token-material",
        }

    def _console(self, request, call: Call, host: str, rest: list[str]):  # noqa: ANN001
        if host in self.console_timeout:
            raise requests.Timeout("fixture: the console did not answer")
        if host in self.console_status:
            return self._response(request, self.console_status[host], {"message": "fixture"})
        console = next((c for c in self.consoles if c.host_id == host), None)
        if console is None:
            return self._response(request, 404, {"message": "fixture: no such console"})
        if rest == ["integration", "v1", "sites"]:
            data = [{"id": s.integration_id, "internalReference": s.ref, "name": s.desc}
                    for s in console.sites if s.listed]
            return self._response(request, 200, {"offset": 0, "limit": 200, "count": len(data),
                                                 "totalCount": len(data), "data": data})
        if len(rest) == 5 and rest[:3] == ["integration", "v1", "sites"] and rest[4] == "clients":
            site = next((s for s in console.sites if s.integration_id == rest[3]), None)
            if site is None:
                return self._response(request, 404, {"message": "fixture: no such site"})
            limit = int(call.query.get("limit", "25"))
            offset = int(call.query.get("offset", "0"))
            fail_page = self.clients_fail_after_page.get(host)
            if fail_page is not None and offset >= fail_page * limit:
                return self._response(request, 502, {"message": "fixture: bad gateway"})
            page = site.clients[offset: offset + limit]
            return self._response(request, 200, {"offset": offset, "limit": limit,
                                                 "count": len(page),
                                                 "totalCount": len(site.clients), "data": page})
        if len(rest) == 6 and rest[:3] == ["v2", "api", "site"] and rest[4:] == ["system-log", "all"]:
            if request.method != "POST":
                return self._response(request, 405, {"message": "fixture: POST only"})
            site = next((s for s in console.sites if s.ref == rest[3]), None)
            if site is None:
                return self._response(request, 404, {"message": "fixture: no such site"})
            b = call.body or {}
            frm, to = int(b["timestampFrom"]), int(b["timestampTo"])
            size, page_no = int(b.get("pageSize", 100)), int(b.get("pageNumber", 0))
            now = ms(self.clock.now())
            rows = [e for e in site.log if frm <= e["timestamp"] <= to and e["timestamp"] <= now]
            rows.sort(key=lambda e: (e["timestamp"], e["id"]), reverse=True)   # newest first
            pages = max(1, math.ceil(len(rows) / size))
            chunk = rows[page_no * size: (page_no + 1) * size]
            return self._response(request, 200, {
                "data": [json.loads(json.dumps(e)) for e in chunk], "page_number": page_no,
                "total_element_count": len(rows), "total_page_count": pages})
        if len(rest) == 5 and rest[0] == "api" and rest[1] == "s" and rest[3:] == ["rest", "networkconf"]:
            site = next((s for s in console.sites if s.ref == rest[2]), None)
            if site is None:
                return self._response(request, 404, {"message": "fixture: no such site"})
            return self._response(request, 200, {"meta": {"rc": "ok"},
                                                 "data": [dict(n) for n in site.networks]})
        return self._response(request, 404, {"message": "fixture: not found"})

    def close(self) -> None:
        return None

    @staticmethod
    def _response(request, status: int, body: Any) -> requests.Response:  # noqa: ANN001
        resp = requests.Response()
        resp.status_code = status
        resp._content = json.dumps(body).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url = request.url
        resp.request = request
        return resp


def fake_limiter(clock: FakeClock, *, spacing: float = 1.0, key: str = API_KEY) -> UniFiRateLimiter:
    limiter = UniFiRateLimiter(min_spacing_sec=spacing, clock=clock.monotonic, wait=clock.wait)
    return install_limiter(key, limiter)


def real_client(transport: FakeUniFiTransport, config: Optional[UniFiConfig] = None,
                limiter: Optional[UniFiRateLimiter] = None) -> UniFiClient:
    client = UniFiClient(config or UniFiConfig(api_key=API_KEY), limiter=limiter)
    client._session.mount("https://", transport)
    client._session.mount("http://", transport)
    return client


def client_factory(transport: FakeUniFiTransport):
    return lambda config: real_client(transport, config)


def unifi_adapter_class(transport: FakeUniFiTransport, clock: Optional[FakeClock] = None,
                        consumer: Any = None):
    """The real adapter as the framework instantiates it (`cls()`), wired to
    `transport` (and the fake clock, when given)."""
    from apps.octo.adapters.unifi import UniFiSourceAdapter

    class _TransportUniFi(UniFiSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=client_factory(transport),
                             now=clock.now if clock is not None else None, consumer=consumer)

    _TransportUniFi.__module__ = "apps.octo.adapters.unifi"
    return _TransportUniFi


def standard_fleet(transport: FakeUniFiTransport) -> None:
    """Three single-site consoles whose sites share ONE site id and the
    internal reference 'default' (V11): A (Acme Corp), B (Example Bakery) and
    C, a personal console that is never mapped."""
    transport.add_console(HOST_A, "acme-udm", desc="Acme Corp")
    transport.add_console(HOST_B, "bakery-ucg", desc="Example Bakery",
                          wans={"WAN": {"externalIp": "198.51.100.20", "asn": 64501,
                                        "isp": "Other Example ISP"}})
    c = transport.add_console(HOST_C, "home-lab", desc="Default",
                              wans={"WAN": {"externalIp": "192.0.2.200", "asn": 64502,
                                            "isp": "Home ISP"}})
    c.location_text = "Somewhere Else"
    transport.console(HOST_B).location_text = "200 Example Ave, Shelbyville"
