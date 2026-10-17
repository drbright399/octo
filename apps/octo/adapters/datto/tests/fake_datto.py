"""A fake Datto RMM API at the TRANSPORT layer.

Tests here run the real DattoClient / DattoSourceAdapter / DattoPoller: only
the socket is replaced, by mounting this `requests` transport adapter on the
client's own session. A stubbed client hid a poller bug in this codebase
before — status parsing, exception mapping and re-auth are exactly the code
that must NOT be faked.

Scenario knobs are plain mutable attributes so a test can change the vendor's
behaviour mid-run ("the operator fixed the security level").
"""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import requests
from requests.adapters import BaseAdapter

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.client import DattoClient, DattoConfig

API_URL = "https://datto-api.example.test"
# Structurally fake on purpose: a marker plus padding, never a literal that is
# shaped like a real key (the pre-commit scrub guard rightly refuses those).
# Still long enough to exercise the client's redaction (>= 8 chars) and its
# token-shape scrubber (24+ chars).
API_KEY = "FIXTURE-PUBLIC-" + "0" * 17
API_SECRET = "fixture-private-" + "1" * 26
ACCESS_TOKEN = "fixture-bearer-" + "2" * 40
CREDS = {
    "DATTO_API_URL": API_URL,
    "DATTO_API_KEY": API_KEY,
    "DATTO_API_SECRET_KEY": API_SECRET,
}
SECRETS = (API_KEY, API_SECRET, ACCESS_TOKEN)

# Verbatim from the vendor for an API user whose security level grants nothing.
FORBIDDEN_BODY = {
    "status": 403,
    "error": "Authenticated user doesn't have access to this resource.",
}
FORBIDDEN_TEXT = FORBIDDEN_BODY["error"]
# As an operator reads it: the client makes straight quotes typographic so
# vendor text can never close the quotation it is shown in.
FORBIDDEN_TEXT_SHOWN = FORBIDDEN_TEXT.replace("'", "\u2019")
FORBIDDEN_QUOTED = f'Datto\'s own message: "{FORBIDDEN_TEXT_SHOWN}"'

# The vendor's page ceiling: a larger `max` fails the WHOLE request.
VENDOR_PAGE_LIMIT = 250
ALERTS_PATH = "/api/v2/account/alerts/open"
SITES_PATH = "/api/v2/account/sites"
DEVICE_PATH_PREFIX = "/api/v2/device/"
ALERT_PATH_PREFIX = "/api/v2/alert/"

# A made-up platform name in Datto's documented '<platform>-api' host form,
# and the portal that goes with it.
PLATFORM_API_URL = "https://exampleplat-api.centrastage.net"
PLATFORM_PORTAL = "https://exampleplat.rmm.datto.com"
# The device object's remote-control address. It must never be seen anywhere
# outside this fake: tests search responses, logs and caches for the marker.
WEB_REMOTE_MARKER = "REMOTE-SESSION-MARKER"


def device_object(
    uid: str = "dev-uid-0001", *, numeric_id: int = 4242,
    site_uid: str = "site-uid-0001", hostname: str = "WS-EXAMPLE-01",
    portal_url: Any = None,
) -> dict[str, Any]:
    """A device as GET /api/v2/device/{uid} answers (the fields that matter)."""
    return {
        "id": numeric_id, "uid": uid, "siteUid": site_uid, "hostname": hostname,
        "portalUrl": (
            f"{PLATFORM_PORTAL}/device/{numeric_id}" if portal_url is None else portal_url
        ),
        "webRemoteUrl": f"{PLATFORM_PORTAL}/web-remote/{WEB_REMOTE_MARKER}",
    }

TOKEN_PATH = "/auth/oauth/token"
SITE_DEVICES_RE = r"^/api/v2/site/([^/]+)/devices$"
AUDIT_PATH_PREFIX = "/api/v2/audit/device/"
# Values in a device audit Athena must never keep: tests search stores, logs
# and API answers for each of them.
AUDIT_SECRETS = ("EXAMPLE\\alice", "00:00:5e:00:53:af", "198.51.100.77", "FIXTURE-UDF-VALUE",
                 "Example Secret Software", "AUDIT-REMOTE-MARKER")


def device_audit(*, serial: Any = "EXAMPLE-SN-0001", baseboard_serial: Any = "EXAMPLE-MB-0001",
                 manufacturer: Any = "Example Computers Inc.", model: Any = "Example Model 7090",
                 ) -> dict[str, Any]:
    """A device audit as GET /api/v2/audit/device/{uid} answers it (Datto RMM
    API v2's documented object) — WITH the fields Athena must never keep: the
    logged-in user, network interfaces (MAC + addresses), UDF-like keys,
    installed software and the portal / remote-control URLs."""
    return {
        "portalUrl": "https://exampleplat.rmm.datto.com/device/4242",
        "webRemoteUrl": "https://exampleplat.rmm.datto.com/web-remote/AUDIT-REMOTE-MARKER",
        "systemInfo": {"manufacturer": manufacturer, "model": model,
                       "username": "EXAMPLE\\alice", "totalPhysicalMemory": 17179869184,
                       "dotNetVersion": "4.8", "totalCpuCores": 8},
        "networkInterfaces": [{"instance": "Ethernet", "ipv4": "198.51.100.77",
                               "ipv6": "2001:db8::77", "macAddress": "00:00:5e:00:53:af"}],
        "bios": {"instance": "Example BIOS", "releaseDate": "2026-01-01",
                 "serialNumber": serial, "smBiosVersion": "3.4"},
        "baseBoard": {"manufacturer": manufacturer, "product": "0XYZ00",
                      "serialNumber": baseboard_serial},
        "udf": {"udf1": "FIXTURE-UDF-VALUE"},
        "software": [{"name": "Example Secret Software", "version": "1.0"}],
        "logicalDisks": [{"diskIdentifier": "C:", "freespace": 1, "size": 2}],
    }


def inventory_device(uid: str, hostname: str, *, online: bool = True, site_uid: str = "site-uid-0001",
                     int_ip: str = "192.0.2.11", last_seen_ms: int = 1_790_000_000_000,
                     category: str = "Desktop") -> dict[str, Any]:
    """A device as GET /api/v2/site/{siteUid}/devices lists it (the fields
    verified live 2026-10-01) — WITH the fields Athena must never read: UDFs
    (they may hold BitLocker recovery keys), the logged-in user and the
    remote-control address."""
    return {
        "id": abs(hash(uid)) % 100000, "uid": uid, "siteUid": site_uid, "hostname": hostname,
        "deviceType": {"category": category, "type": "Workstation"}, "online": online,
        "lastSeen": last_seen_ms, "intIpAddress": int_ip, "extIpAddress": "203.0.113.129",
        "operatingSystem": "Microsoft Windows 11 Pro", "domain": "WORKGROUP",
        "lastLoggedInUser": "EXAMPLE\\alice",
        "udf": {"udf1": "FIXTURE-BITLOCKER-KEY-000000-111111-222222", "udf2": "fixture"},
        "webRemoteUrl": f"https://exampleplat.rmm.datto.com/web-remote/{WEB_REMOTE_MARKER}",
    }


class FakeDattoTransport(BaseAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.token_status = 200          # 401 → credentials rejected
        self.token_error_body: Any = {"error": "invalid_grant"}   # body of a non-200
        self.forbid_data = False         # every /api/v2 read → 403 + FORBIDDEN_BODY
        self.forbidden_body: Any = FORBIDDEN_BODY
        self.data_status = 200           # any other status for /api/v2 reads
        self.unreachable = False         # raise ConnectionError instead
        self.stale_token_once = False    # first data read answers 401
        self.raw_data_body: bytes | None = None   # 200 with this non-JSON body
        self.alerts: list[dict[str, Any]] = []
        self.sites: list[dict[str, Any]] = [
            {"uid": "site-uid-0001", "name": "Example Site"},
        ]
        # uid → device object, for GET /api/v2/device/{uid}; unknown uid → 404.
        self.devices: dict[str, dict[str, Any]] = {"dev-uid-0001": device_object()}
        # GET /api/v2/alert/{uid}: answered from `alerts` (the open-alerts
        # list — the SAME object, as the vendor does) or from here (alerts the
        # list no longer carries, e.g. resolved ones); unknown uid → 404.
        self.alerts_by_uid: dict[str, dict[str, Any]] = {}
        # Doorbell-fetch scenario knobs, for that path only: a status to
        # answer instead (403 → FORBIDDEN_BODY), a delay before answering
        # (a slow vendor), or a raised requests.Timeout (the client's own
        # read timeout firing).
        self.alert_fetch_status: int | None = None
        self.alert_fetch_delay_sec: float = 0.0
        self.alert_fetch_times_out = False
        self.timeouts: list[Any] = []            # `timeout` of each request
        # Hosts that ARE the vendor API. Anything else is "off-origin".
        self.api_hosts: set[str] = {urlsplit(API_URL).hostname or ""}
        # Sites pagination, as Datto does it (pageDetails.nextPageUrl). None =
        # one page holding everything. `next_page_origin` is what the vendor
        # puts in nextPageUrl — deliberately NOT the API origin, so a client
        # that follows the URL (bearer token and all) is caught via `hosts`.
        self.sites_page_size: int | None = None
        self.next_page_origin = "https://pagination-lb.example.test"
        self.endless_sites = False       # every page claims there is a next one
        self.stuck_next_page = False     # nextPageUrl never advances
        # Replaces nextPageUrl verbatim whenever there IS a next page (a
        # cursor-style link, a non-integer page, a non-string, …).
        self.next_page_url_override: Any = None
        self.override_next_page_url = False
        # Sites reads with page >= N answer this status (mid-drain failure).
        self.fail_sites_from_page: int | None = None
        self.fail_sites_status = 403
        # Alerts pagination (None = one page). nextPageUrl is on the API
        # origin unless `alerts_next_origin` says otherwise.
        self.alerts_page_size: int | None = None
        self.alerts_next_origin: str | None = None
        # Answer every request with this 3xx + Location instead.
        self.redirect_status: int | None = None
        self.redirect_to = "http://internal.example.test:8080/latest/meta-data?x=1"
        # site uid → the devices GET /api/v2/site/{uid}/devices lists; the
        # page size the vendor uses for it (None = one page).
        self.site_devices: dict[str, list[dict[str, Any]]] = {}
        self.device_page_size: int | None = None
        # device uid → its audit (GET /api/v2/audit/device/{uid}); an unknown
        # uid → 404. `audit_status` answers every audit with that status
        # instead (429 → with `audit_retry_after` as Retry-After when set).
        self.audits: dict[str, Any] = {}
        self.audit_status: int | None = None
        self.audit_retry_after: str | None = None
        self.calls: list[tuple[str, str]] = []   # (METHOD, path)
        self.hosts: set[str] = set()             # every host a request went to
        self.site_pages: list[int | None] = []   # `page` param of each sites read
        self.alert_queries: list[dict[str, str]] = []   # query of each alerts read
        self.bodies: list[str] = []              # request bodies (token form)

    def count(self, path: str) -> int:
        return sum(1 for _, p in self.calls if p == path)

    # -- requests transport API --

    def send(self, request, **kwargs):  # noqa: ANN001 — requests' signature
        parts = urlsplit(request.url)
        path = parts.path
        self.calls.append((request.method, path))
        self.timeouts.append(kwargs.get("timeout"))
        self.hosts.add(parts.hostname or "")
        if isinstance(request.body, (str, bytes)):
            self.bodies.append(
                request.body.decode() if isinstance(request.body, bytes) else request.body
            )
        if self.unreachable:
            raise requests.ConnectionError("fixture: connection refused")
        if parts.hostname not in self.api_hosts:
            # Only reachable by a client that FOLLOWED something off-origin.
            return self._response(request, 200, {
                "sites": [{"uid": "INTERNAL-DATA", "name": "Internal"}],
                "alerts": [], "access_token": "stolen", "expires_in": 1800,
            })
        if self.redirect_status is not None:
            resp = self._response(request, self.redirect_status, b"")
            resp.headers["Location"] = self.redirect_to
            return resp
        if path == TOKEN_PATH:
            if self.token_status != 200:
                return self._response(request, self.token_status, self.token_error_body)
            return self._response(
                request, 200, {"access_token": ACCESS_TOKEN, "expires_in": 1800},
            )
        if self.stale_token_once:
            self.stale_token_once = False
            return self._response(request, 401, {"error": "invalid_token"})
        if self.forbid_data:
            return self._response(request, 403, self.forbidden_body)
        if self.data_status != 200:
            return self._response(request, self.data_status, {"error": "fixture"})
        if self.raw_data_body is not None:
            return self._response(request, 200, self.raw_data_body)
        if path == "/api/v2/account":
            return self._response(request, 200, {"uid": "acct-0001", "name": "Example MSP"})
        if path in (SITES_PATH, ALERTS_PATH) and self._over_page_limit(parts.query):
            return self._response(request, 400, {
                "error": f"max exceeds the defined limit of {VENDOR_PAGE_LIMIT}",
            })
        if path == SITES_PATH:
            raw = (parse_qs(parts.query).get("page") or ["0"])[0]
            if (
                self.fail_sites_from_page is not None
                and raw.isdigit() and int(raw) >= self.fail_sites_from_page
            ):
                body = self.forbidden_body if self.fail_sites_status == 403 else {"error": "fixture"}
                return self._response(request, self.fail_sites_status, body)
            return self._response(request, 200, self._sites_page(parts.query))
        if path == ALERTS_PATH:
            return self._response(request, 200, self._alerts_page(parts.query))
        m = __import__("re").match(SITE_DEVICES_RE, path)
        if m is not None:
            if self._over_page_limit(parts.query):
                return self._response(request, 400, {
                    "error": f"max exceeds the defined limit of {VENDOR_PAGE_LIMIT}"})
            uid = unquote(m.group(1))
            if uid not in self.site_devices:
                return self._response(request, 404, {"error": "fixture: no such site"})
            devices = self.site_devices[uid]
            size = self.device_page_size
            if size is None:
                return self._response(request, 200, {"pageDetails": {"nextPageUrl": None},
                                                     "devices": devices})
            index = int((parse_qs(parts.query).get("page") or ["0"])[0])
            chunk = devices[index * size:(index + 1) * size]
            more = (index + 1) * size < len(devices)
            return self._response(request, 200, {
                "pageDetails": {"count": len(chunk), "nextPageUrl": (
                    f"{API_URL}/api/v2/site/{uid}/devices?max={size}&page={index + 1}"
                    if more else None)},
                "devices": chunk})
        if path.startswith(AUDIT_PATH_PREFIX):
            if self.audit_status is not None:
                resp = self._response(request, self.audit_status, {"error": "fixture"})
                if self.audit_retry_after is not None:
                    resp.headers["Retry-After"] = self.audit_retry_after
                return resp
            audit = self.audits.get(unquote(path[len(AUDIT_PATH_PREFIX):]))
            if audit is None:
                return self._response(request, 404, {"error": "fixture: no such device"})
            return self._response(request, 200, audit)
        if path.startswith(DEVICE_PATH_PREFIX):
            device = self.devices.get(unquote(path[len(DEVICE_PATH_PREFIX):]))
            if device is None:
                return self._response(request, 404, {"error": "fixture: no such device"})
            return self._response(request, 200, device)
        if path.startswith(ALERT_PATH_PREFIX):
            return self._alert_by_uid(request, unquote(path[len(ALERT_PATH_PREFIX):]))
        return self._response(request, 404, {"error": "fixture: unknown path"})

    def _alert_by_uid(self, request, uid: str) -> requests.Response:  # noqa: ANN001
        if self.alert_fetch_times_out:
            raise requests.ReadTimeout("fixture: read timed out")
        if self.alert_fetch_delay_sec:
            time.sleep(self.alert_fetch_delay_sec)
        if self.alert_fetch_status == 403:
            return self._response(request, 403, self.forbidden_body)
        if self.alert_fetch_status is not None:
            return self._response(request, self.alert_fetch_status, {"error": "fixture"})
        found = self.alerts_by_uid.get(uid)
        if found is None:
            found = next((a for a in self.alerts if a.get("alertUid") == uid), None)
        if found is None:
            return self._response(request, 404, {"error": "fixture: no such alert"})
        return self._response(request, 200, found)

    @staticmethod
    def _over_page_limit(query: str) -> bool:
        raw = (parse_qs(query).get("max") or [None])[0]
        return raw is not None and raw.isdigit() and int(raw) > VENDOR_PAGE_LIMIT

    def _alerts_page(self, query: str) -> dict[str, Any]:
        params = {k: v[0] for k, v in parse_qs(query).items()}
        self.alert_queries.append(params)
        size = self.alerts_page_size
        if size is None:
            return {"pageDetails": {"nextPageUrl": None}, "alerts": self.alerts}
        index = int(params.get("page", "0"))
        chunk = self.alerts[index * size:(index + 1) * size]
        more = (index + 1) * size < len(self.alerts)
        origin = self.alerts_next_origin or API_URL
        return {
            "pageDetails": {"nextPageUrl": (
                f"{origin}{ALERTS_PATH}?max={size}&page={index + 1}" if more else None
            )},
            "alerts": chunk,
        }

    def _sites_page(self, query: str) -> dict[str, Any]:
        raw = (parse_qs(query).get("page") or [None])[0]
        page = int(raw) if raw is not None else None
        self.site_pages.append(page)
        size = self.sites_page_size
        if size is None:
            return {"pageDetails": {"nextPageUrl": None}, "sites": self.sites}
        index = page or 0
        chunk = self.sites[index * size:(index + 1) * size]
        more = self.endless_sites or (index + 1) * size < len(self.sites)
        next_index = index if self.stuck_next_page else index + 1
        next_url = (
            f"{self.next_page_origin}/api/v2/account/sites?max={size}&page={next_index}"
            if more else None
        )
        if more and self.override_next_page_url:
            next_url = self.next_page_url_override
        if self.endless_sites and not chunk:
            chunk = [{"uid": f"endless-{index}", "name": f"Endless {index}"}]
        return {
            "pageDetails": {"count": len(chunk), "nextPageUrl": next_url},
            "sites": chunk,
        }

    def close(self) -> None:
        return None

    @staticmethod
    def _response(request, status: int, body: Any) -> requests.Response:  # noqa: ANN001
        resp = requests.Response()
        resp.status_code = status
        resp._content = (
            body if isinstance(body, bytes) else json.dumps(body).encode()
        )
        resp.headers["Content-Type"] = "application/json"
        resp.url = request.url
        resp.request = request
        return resp


def real_client(transport: FakeDattoTransport, config: DattoConfig | None = None) -> DattoClient:
    """A REAL DattoClient whose session talks to `transport`."""
    client = DattoClient(config or DattoConfig(
        api_url=API_URL, api_key=API_KEY, api_secret_key=API_SECRET,
    ))
    client._session.mount("https://", transport)
    client._session.mount("http://", transport)
    return client


def client_factory(transport: FakeDattoTransport):
    return lambda config: real_client(transport, config)


def datto_adapter_class(transport: FakeDattoTransport) -> type[DattoSourceAdapter]:
    """The real adapter as the framework instantiates it (`cls()`, no
    arguments), wired to `transport`."""

    class _TransportDatto(DattoSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=client_factory(transport))

    _TransportDatto.__module__ = "apps.octo.adapters.datto"
    return _TransportDatto
