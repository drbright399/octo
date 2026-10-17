"""UniFi API client — the cloud Site Manager API and its connector proxy to each
console. READ-ONLY, every call through the shared limiter, every answer
stripped of secrets at the boundary (`sanitize.strip`) before it is parsed.

Built against the live API (verified read-only 2026-10-01 on a production
fleet — `api.ui.com`, one cloud API key):

  GET /v1/hosts                      {data: [host…], httpStatusCode, traceId,
                                      nextToken?} — no nextToken seen on a
                                      production fleet: one page, complete;
                                      paging is tolerated, never depended on.
                                      A host:
      id, reportedState{hostname, name, state, location{lat, long, radius,
      text}, timezone, wans[{ipv4, ipv6, mac, type, plugged, enabled}]} …
  GET /v1/sites                      {data: [site…], nextToken?}; a site:
      hostId, siteId, meta{name (the internal reference, 'default' on a
      single-site console), desc (the display name), timezone, gatewayMac},
      statistics{counts{…offlineGatewayDevice…}, ispInfo{asn, name,
      organization}, wans{WAN, WAN2: {externalIp, ispInfo, portUp, wanUptime,
      wanIssues}}, internetIssues, gateway}
  Per console, through the connector
  (/v1/connector/consoles/{hostId}/proxy/network/…):
  GET integration/v1/sites           {offset, limit, count, totalCount,
                                      data: [{id, internalReference, name}]}
      SITE IDS COLLIDE ACROSS CONSOLES (V11, verified: the same id and
      internalReference 'default' on every console checked) — every site is
      keyed on (hostId, siteId) and the console is always part of the path.
  GET integration/v1/sites/{id}/clients?limit=200&offset=N
      {offset, limit, count, totalCount, data: [{id, name, macAddress,
      ipAddress, connectedAt, type, uplinkDeviceId, access{type}}]} — a
      snapshot of the CONNECTED clients; read whole or not at all.
  POST v2/api/site/{internalReference}/system-log/all
      body {timestampFrom, timestampTo (ms), pageNumber, pageSize}
      → {data: [{category, event, id, message_raw, parameters, severity,
      show_on_dashboard, status, subcategory, target, timestamp, title_raw,
      type}], page_number, total_element_count, total_page_count} — NEWEST
      FIRST (live)
  The integration site id DIFFERS from the fleet siteId on every console
  (live, on every console checked): the clients endpoint always takes the id
  the console's own integration/v1/sites lists for the site's
  internalReference.
  GET api/s/{internalReference}/rest/networkconf
      {meta, data: [{name, purpose, ip_subnet, vlan, … and SECRETS}]} — only
      an allowlist of fields is ever kept (`NETWORK_FIELDS`).

Statuses: 200 success; 429 throttled (shared backoff); 401 / 403 on the
fleet endpoints → UniFiAuthError — the key; any failure of a connector call
(401 / 403 / 3xx / 404 / 400 / 5xx, a timeout, a body that is not JSON) →
UniFiConsoleError — ONE console (offline, no Network app, an older version,
access removed, its own login redirect), the others go on — a revoked key
fails the fleet calls too, which stay key-wide; anything else →
UniFiClientError. Redirects are never followed (a 3xx would carry the key
elsewhere). The key never appears in an exception message or a log line.
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import requests

from apps.octo.adapters.unifi import sanitize
from apps.octo.adapters.unifi.limiter import (
    DEFAULT_MIN_SPACING_SEC,
    PRIORITY_CLIENTS,
    PRIORITY_DISCOVERY,
    PRIORITY_FLEET,
    PRIORITY_SECURITY,
    LimiterAborted,
    LimiterBusy,
    UniFiRateLimiter,
    limiter_for,
)

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://api.ui.com"
PORTAL_URL = "https://unifi.ui.com"

HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._\-]{0,199}$")
SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$")
INTERNAL_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")

FLEET_PAGE_SIZE = 500
MAX_FLEET_PAGES = 10
CLIENT_PAGE_SIZE = 200
MAX_CLIENT_PAGES = 50                # 10,000 connected clients on one site
CLIENT_READ_ATTEMPTS = 3             # the list changed under the read: start over
LOG_PAGE_SIZE = 500
MAX_VENDOR_TEXT = 160
# The only networkconf fields that ever leave the client (everything else —
# VPN keys, RADIUS secrets, Wi-Fi passphrases, x_* — is dropped unseen).
NETWORK_FIELDS = (
    "_id", "name", "purpose", "ip_subnet", "vlan", "vlan_enabled", "networkgroup",
    "dhcpd_enabled", "dhcpd_dns_enabled", "dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3",
    "dhcpd_dns_4", "domain_name", "enabled",
)


class UniFiClientError(Exception):
    """Transport / protocol error talking to UniFi (operator-safe text)."""


class UniFiAuthError(UniFiClientError):
    """The API key was refused (401 / 403 on the fleet endpoints)."""

    def __init__(self, message: str, status: Optional[int] = None) -> None:
        self.status = status
        super().__init__(message)


class UniFiThrottledError(UniFiClientError):
    def __init__(self, message: str, retry_in_sec: float) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        super().__init__(message)


class UniFiBusyError(UniFiClientError):
    def __init__(self, message: str, retry_in_sec: float) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        super().__init__(message)


class UniFiConsoleError(UniFiClientError):
    """ONE console could not answer through the connector (offline, no
    Network app, access removed, a 5xx). `status` = the HTTP status."""

    def __init__(self, message: str, status: Optional[int] = None) -> None:
        self.status = status
        super().__init__(message)


class UniFiAborted(UniFiClientError):
    """The caller stopped while waiting for its slot."""


@dataclass(frozen=True)
class UniFiConfig:
    api_key: str
    api_url: str = DEFAULT_API_URL
    timeout_seconds: float = 20.0
    min_spacing_sec: float = DEFAULT_MIN_SPACING_SEC


@dataclass(frozen=True)
class LogPage:
    events: list[dict[str, Any]]
    page_number: int
    total_pages: int
    total_events: int


@dataclass(frozen=True)
class ClientSnapshot:
    """Every connected client of one site, read whole."""
    clients: list[dict[str, Any]]
    total: int
    pages: int


@dataclass
class IntegrationSite:
    id: str
    internal_reference: str
    name: str = ""


@dataclass
class FleetPage:
    items: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False


def valid_host_id(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and HOST_ID_RE.fullmatch(value) else None


def valid_site_id(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and SITE_ID_RE.fullmatch(value) else None


def valid_internal_ref(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and INTERNAL_REF_RE.fullmatch(value) else None


def _text(value: Any, limit: int = MAX_VENDOR_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


class UniFiClient:
    def __init__(
        self,
        config: UniFiConfig,
        *,
        limiter: Optional[UniFiRateLimiter] = None,
        abort: Optional[threading.Event] = None,
    ) -> None:
        self._config = config
        self._base = config.api_url.rstrip("/")
        self._limiter = limiter or limiter_for(config.api_key,
                                               min_spacing_sec=config.min_spacing_sec)
        self._abort = abort
        self._session = requests.Session()
        self.calls = 0

    @property
    def limiter(self) -> UniFiRateLimiter:
        return self._limiter

    def set_abort(self, abort: threading.Event) -> None:
        self._abort = abort

    # ----- one request -----

    def _request(
        self,
        method: str,
        path: str,
        *,
        what: str,
        priority: int,
        params: Optional[dict[str, Any]] = None,
        body: Optional[dict[str, Any]] = None,
        console: bool = False,
        max_wait_sec: Optional[float] = None,
    ) -> Any:
        try:
            self._limiter.acquire(priority, max_wait_sec=max_wait_sec, abort=self._abort)
        except LimiterBusy as exc:
            if exc.throttled:
                raise UniFiThrottledError(
                    f"UniFi is rate limiting Athena's requests; calls resume in "
                    f"{int(exc.retry_in_sec + 0.999)} s", exc.retry_in_sec) from None
            raise UniFiBusyError(
                f"Other UniFi requests are queued ahead of this one; try again in "
                f"{int(exc.retry_in_sec + 0.999)} s", exc.retry_in_sec) from None
        except LimiterAborted:
            raise UniFiAborted("stopped while waiting to call UniFi") from None
        self.calls += 1
        try:
            r = self._session.request(
                method, self._base + path,
                headers={"X-API-KEY": self._config.api_key, "Accept": "application/json"},
                params=params, json=body, timeout=self._config.timeout_seconds,
                allow_redirects=False,
            )
        except (requests.RequestException, ValueError) as exc:
            # `from None`: an InvalidHeader message would carry the key.
            if console:
                raise UniFiConsoleError(
                    f"the console did not answer {what} ({type(exc).__name__})") from None
            raise UniFiClientError(f"UniFi unreachable on {what}: {type(exc).__name__}") from None
        status = r.status_code
        if status == 200:
            try:
                data = r.json()
            except ValueError:
                err = UniFiConsoleError if console else UniFiClientError
                raise err(f"UniFi {what} returned a body that is not JSON") from None
            self._limiter.success()
            return sanitize.strip(data)
        if status == 429:
            retry_after = None
            try:
                retry_after = float(r.headers.get("Retry-After", ""))
            except (TypeError, ValueError):
                retry_after = None
            wait = self._limiter.throttled(retry_after)
            raise UniFiThrottledError(
                f"UniFi is rate limiting Athena (HTTP 429 on {what}); every UniFi call "
                f"waits {int(wait + 0.999)} s", wait)
        if console and (status in (401, 403) or 300 <= status < 400):
            # ONE console's answer through the connector (its own login
            # page, a redirect, access removed): that site waits on its own
            # backoff. A key that is really revoked fails the FLEET calls too
            # — those stay key-wide. Redirects are never followed.
            raise UniFiConsoleError(
                f"the console answered HTTP {status} on {what}"
                + (" (a redirect — never followed)" if 300 <= status < 400 else ""), status)
        if status in (401, 403):
            raise UniFiAuthError(f"UniFi rejected the API key (HTTP {status} on {what})", status)
        if 300 <= status < 400:
            raise UniFiClientError(
                f"UniFi {what} answered with a redirect (HTTP {status}); redirects are never "
                "followed")
        if console:
            # One console's answer (offline, no Network app, an older
            # version, access removed): that site waits; the others go on.
            raise UniFiConsoleError(f"the console answered HTTP {status} on {what}", status)
        raise UniFiClientError(f"UniFi {what} returned HTTP {status}")

    def _console_path(self, host_id: str, suffix: str) -> str:
        hid = valid_host_id(host_id)
        if hid is None:
            raise UniFiClientError("refused to request an invalid UniFi console id")
        return f"/v1/connector/consoles/{quote(hid, safe=':')}/proxy/network/{suffix}"

    # ----- the fleet: 2 calls for every console -----

    def _fleet(self, path: str, *, what: str, priority: int,
               max_wait_sec: Optional[float]) -> FleetPage:
        out = FleetPage()
        token: Optional[str] = None
        for _ in range(MAX_FLEET_PAGES):
            params: dict[str, Any] = {"pageSize": FLEET_PAGE_SIZE}
            if token:
                params["nextToken"] = token
            body = self._request("GET", path, what=what, priority=priority, params=params,
                                 max_wait_sec=max_wait_sec)
            data = body.get("data") if isinstance(body, dict) else None
            if not isinstance(data, list):
                raise UniFiClientError(f"UniFi {what} answered without a data list")
            out.items.extend(x for x in data if isinstance(x, dict))
            nxt = body.get("nextToken")
            token = nxt if isinstance(nxt, str) and nxt and len(nxt) <= 2048 else None
            if not token:
                return out
        out.truncated = True
        return out

    def list_hosts(self, *, priority: int = PRIORITY_FLEET,
                   max_wait_sec: Optional[float] = None) -> FleetPage:
        return self._fleet("/v1/hosts", what="host list", priority=priority,
                           max_wait_sec=max_wait_sec)

    def list_sites(self, *, priority: int = PRIORITY_FLEET,
                   max_wait_sec: Optional[float] = None) -> FleetPage:
        return self._fleet("/v1/sites", what="site list", priority=priority,
                           max_wait_sec=max_wait_sec)

    # ----- one console -----

    def integration_sites(self, host_id: str, *,
                          priority: int = PRIORITY_DISCOVERY) -> list[IntegrationSite]:
        """The console's Network sites (integration ids + internal
        references) — how a (hostId, siteId) of the fleet list finds the id
        the clients endpoint takes."""
        body = self._request("GET", self._console_path(host_id, "integration/v1/sites"),
                             what="console site list", priority=priority,
                             params={"limit": 200}, console=True)
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list):
            raise UniFiConsoleError("the console site list answered without a data list")
        out = []
        for item in data:
            if not isinstance(item, dict):
                continue
            sid = valid_site_id(item.get("id"))
            ref = valid_internal_ref(item.get("internalReference"))
            if sid and ref:
                out.append(IntegrationSite(sid, ref, _text(item.get("name"), 120)))
        return out

    def clients(self, host_id: str, integration_site_id: str, *,
                priority: int = PRIORITY_CLIENTS) -> ClientSnapshot:
        """EVERY connected client of the site (all pages) — or an error: a
        partial snapshot is never returned (it would read as clients that
        left). Clients come and go while the pages are read: when the list's
        totalCount changes between pages the read starts over (at most
        CLIENT_READ_ATTEMPTS times); a list that never holds still fails (the
        next poll re-reads)."""
        sid = valid_site_id(integration_site_id)
        if sid is None:
            raise UniFiClientError("refused to request an invalid UniFi site id")
        path = self._console_path(host_id, f"integration/v1/sites/{quote(sid, safe='')}/clients")
        for _attempt in range(CLIENT_READ_ATTEMPTS):
            snap = self._read_clients_once(path, priority)
            if snap is not None:
                return snap
        raise UniFiConsoleError("the client list kept changing while it was read")

    def _read_clients_once(self, path: str, priority: int) -> Optional[ClientSnapshot]:
        """One pass over every page; None when the list changed under it."""
        out: dict[str, dict[str, Any]] = {}
        offset = 0
        total: Optional[int] = None
        pages = 0
        while True:
            body = self._request("GET", path, what="client list", priority=priority,
                                 params={"limit": CLIENT_PAGE_SIZE, "offset": offset},
                                 console=True)
            pages += 1
            data = body.get("data") if isinstance(body, dict) else None
            count = body.get("totalCount") if isinstance(body, dict) else None
            if not isinstance(data, list) or isinstance(count, bool) or not isinstance(count, int):
                raise UniFiConsoleError("the client list answered without data / totalCount")
            if total is not None and count != total:
                return None                       # it shifted: read it again
            total = count
            for item in data:
                if isinstance(item, dict):
                    out.setdefault(str(item.get("id") or item.get("macAddress") or len(out)), item)
            offset += len(data)
            if not data or offset >= total:
                break
            if pages >= MAX_CLIENT_PAGES:
                raise UniFiConsoleError(
                    f"the client list has more than {MAX_CLIENT_PAGES * CLIENT_PAGE_SIZE} "
                    "clients; the snapshot was not read")
        if len(out) != (total or 0):
            raise UniFiConsoleError("the client list ended before its totalCount")
        return ClientSnapshot(list(out.values()), total or 0, pages)

    def system_log(self, host_id: str, internal_ref: str, *, from_ms: int, to_ms: int,
                   page_number: int = 0, page_size: Optional[int] = None,
                   priority: int = PRIORITY_SECURITY) -> LogPage:
        """One page of the system log. The live API answers NEWEST FIRST
        (2026-10-01); the poller pages it whole (`UniFiPoller._read_all`)."""
        page_size = page_size or LOG_PAGE_SIZE
        ref = valid_internal_ref(internal_ref)
        if ref is None:
            raise UniFiClientError("refused to request an invalid UniFi site reference")
        body = self._request(
            "POST", self._console_path(host_id, f"v2/api/site/{ref}/system-log/all"),
            what="system log", priority=priority, console=True,
            body={"timestampFrom": int(from_ms), "timestampTo": int(to_ms),
                  "pageNumber": int(page_number), "pageSize": int(page_size)},
        )
        if not isinstance(body, dict) or not isinstance(body.get("data"), list):
            raise UniFiConsoleError("the system log answered without a data list")

        def _int(key: str, default: int) -> int:
            v = body.get(key)
            return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else default

        return LogPage(
            events=[x for x in body["data"] if isinstance(x, dict)],
            page_number=_int("page_number", page_number),
            total_pages=_int("total_page_count", 1),
            total_events=_int("total_element_count", len(body["data"])),
        )

    def networks(self, host_id: str, internal_ref: str, *,
                 priority: int = PRIORITY_DISCOVERY) -> list[dict[str, Any]]:
        """The site's networks — ONLY `NETWORK_FIELDS` of each (subnet, VLAN,
        purpose, the DHCP DNS servers); every secret is dropped unseen."""
        ref = valid_internal_ref(internal_ref)
        if ref is None:
            raise UniFiClientError("refused to request an invalid UniFi site reference")
        body = self._request("GET", self._console_path(host_id, f"api/s/{ref}/rest/networkconf"),
                             what="network list", priority=priority, console=True)
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list):
            raise UniFiConsoleError("the network list answered without a data list")
        out = []
        for item in data[:500]:
            if isinstance(item, dict):
                out.append({k: item[k] for k in NETWORK_FIELDS if k in item})
        return sanitize.strip(out)

    # ----- Test connection -----

    def check_access(self, *, max_wait_sec: Optional[float] = 20.0) -> tuple[bool, str, int]:
        """ONE call (the host list). Returns (ok, operator-safe detail, consoles)."""
        try:
            hosts = self.list_hosts(priority=PRIORITY_DISCOVERY, max_wait_sec=max_wait_sec)
        except UniFiAuthError as exc:
            return False, (
                f"{exc}. Use an API key from unifi.ui.com → API (Site Manager), copied whole."
            ), 0
        except UniFiThrottledError as exc:
            return False, f"{exc}. Wait a minute and test again.", 0
        except UniFiClientError as exc:
            return False, f"Could not read from UniFi: {exc}", 0
        n = len(hosts.items)
        return True, (
            f"UniFi reachable and the API key works: {n} console(s). Nothing is polled per "
            "site until you map sites to tenants; unmapped sites are never polled."
        ), n
