"""A fake RocketCyber v3 API at the TRANSPORT layer.

Tests run the REAL RocketCyberClient / RocketCyberSourceAdapter /
RocketCyberPoller: only the socket is replaced, by mounting this `requests`
transport adapter on the client's own session (the model: adapters/datto/
tests/fake_datto.py — Datto's first real onboarding found its adapter had been
built against paths that do not exist; this adapter had the same defect).

FAITHFUL to what the live API answered on 2026-09-29 (read-only key):

  GET /v3/account                     the key's (provider) account; its
                                      `customers` a list of int ids, NO id
                                      field — the id ends `accountPath`
  GET /v3/account?accountId=<provider>&details=true
                                      customers as [{accountId, accountName,
                                      accountPath, status}]
  GET /v3/incidents?accountId&page&pageSize&sort&createdAt&status
                                      {totalCount, currentPage, totalPages,
                                      dataCount, data}; a provider accountId
                                      lists every customer's incidents
  updatedAt (or any unknown key)      400 {"message": "\"updatedAt\" is not allowed"}
  /v3/account/{id}, /v3/account/{id}/customers, /v3/account/{id}/incidents,
  /v3/customers, anything else        404 {name, statusCode, message}
  bad key                             401 (or 403, `reject_key_status`)

ASSUMPTIONS (not observed live; each marked `fixture:` in its message):
pageSize above 500 → 400 (500 is the largest value verified); a missing
accountId → 400; an accountId outside the key's hierarchy → 403; the
createdAt range is inclusive, read as UTC dates; page numbers start at 1.
What a listing WITHOUT `status` returns was not observed either: by default
the fake returns every status, and `default_status` makes it answer only that
status instead (a common vendor default) — the client must work either way.

Scenario knobs are plain attributes a test flips mid-run.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

import requests
from requests.adapters import BaseAdapter

from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
from apps.octo.adapters.rocketcyber.client import RocketCyberClient, RocketCyberConfig

API_HOST = "rc-api.example.test"
API_URL = f"https://{API_HOST}/v3"
# Structurally fake on purpose (a marker plus padding): long enough to
# exercise redaction (>= 8 chars) and the token-shape scrubber (24+).
API_KEY = "fixture-rc-key-" + "3" * 24
SECRETS = (API_KEY,)

# New wizard: the key alone (+ the fake's host, since the default URL is the
# real vendor's).
CREDS = {"RC_API_KEY": API_KEY, "RC_API_URL": API_URL, "RC_ACCOUNT_ID": ""}
# What the OLD wizard saved: all three required, the account id typed in.
OLD_CREDS = {"RC_API_URL": API_URL, "RC_ACCOUNT_ID": "1000", "RC_API_KEY": API_KEY}

PARENT_ID = 900
PROVIDER_ID = 1000
PROVIDER_NAME = "Example MSP"
CUSTOMERS: tuple[dict[str, Any], ...] = (
    {"accountId": 2001, "accountName": "Acme Corp",
     "accountPath": "900.1000.2001", "status": "Active"},
    {"accountId": 2002, "accountName": "Example Bakery",
     "accountPath": "900.1000.2002", "status": "Active"},
    {"accountId": 2003, "accountName": "Example Hardware",
     "accountPath": "900.1000.2003", "status": "Inactive"},
)

NOT_FOUND_BODY = {"name": "NotFoundError", "statusCode": 404, "message": "Not Found"}
UPDATED_AT_REFUSED = {"message": "\"updatedAt\" is not allowed"}

ACCOUNT_PATH = "/v3/account"
INCIDENTS_PATH = "/v3/incidents"
# Every account-in-path variant the first client version used: all 404.
OLD_PATHS = (
    f"/v3/account/{PROVIDER_ID}",
    f"/v3/account/{PROVIDER_ID}/customers",
    f"/v3/account/{PROVIDER_ID}/incidents",
    "/v3/customers",
)

_ACCOUNT_KEYS = {"accountId", "details"}
_INCIDENT_KEYS = {"accountId", "page", "pageSize", "sort", "createdAt", "status"}
_DATE_RANGE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\|(\d{4}-\d{2}-\d{2})$")
MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100


def iso(dt: datetime) -> str:
    """RocketCyber's timestamp shape: 2025-12-29T15:20:15.875Z."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ago(*, days: float = 0, hours: float = 0, minutes: float = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours, minutes=minutes)


DESCRIPTION = (
    "## Summary\n"
    "**Suspicious PowerShell** execution was observed on **WS-EXAMPLE-01**.\n\n"
    "| Field | Value |\n|---|---|\n| Host | WS-EXAMPLE-01 |\n| User | alice |\n\n"
    "- Parent process: `winword.exe`\n"
    "- Command line: `powershell -enc ...`\n"
)
REMEDIATION = (
    "1. Isolate the device.\n2. Reset the user's password.\n"
    "3. Review [the process tree](https://portal.example.test/tree/1)."
)


def incident(
    n: int,
    *,
    account_id: int = 2001,
    account_name: str = "Acme Corp",
    status: str = "open",
    created: Optional[datetime] = None,
    updated: Optional[datetime] = None,
    resolved: Optional[datetime] = None,
    event_count: int = 1,
    title: Optional[str] = None,
    description: str = DESCRIPTION,
    remediation: str = REMEDIATION,
    psa_id: Optional[str] = None,
) -> dict[str, Any]:
    """An incident exactly as GET /v3/incidents lists it."""
    created = created or ago(hours=n)
    updated = updated or created
    return {
        "id": 5000 + n,
        "title": title if title is not None else f"Suspicious PowerShell execution {n}",
        "description": description,
        "remediation": remediation,
        "resolvedAt": iso(resolved) if resolved else None,
        "publishedAt": iso(created),
        "createdAt": iso(created),
        "updatedAt": iso(updated),
        "status": status,
        "accountId": account_id,
        "accountName": account_name,
        "eventCount": event_count,
        "creatorName": "SOC Analyst",
        "psaId": psa_id,
    }


def changed(inc: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """A later version of `inc` — the vendor bumps updatedAt on every change."""
    out = dict(inc)
    out.update(fields)
    if "updatedAt" not in fields:
        out["updatedAt"] = iso(datetime.now(timezone.utc))
    return out


def resolved(inc: dict[str, Any]) -> dict[str, Any]:
    now = iso(datetime.now(timezone.utc))
    return changed(inc, status="resolved", resolvedAt=now, updatedAt=now)


class FakeRocketCyberTransport(BaseAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.key = API_KEY                     # the key the vendor accepts
        self.reject_key_status = 401           # its answer to any other key
        self.provider: dict[str, Any] = {
            "name": PROVIDER_NAME,
            "hierarchy": "Provider",
            "accountPath": f"{PARENT_ID}.{PROVIDER_ID}",
            "type": "provider",
            "address": {"city": "Example City", "country": "US"},
            "status": "Active",
            "emails": ["soc@example.test"],
        }
        self.customers: list[dict[str, Any]] = [dict(c) for c in CUSTOMERS]
        self.incidents: list[dict[str, Any]] = []
        self.api_hosts: set[str] = {API_HOST}
        self.unreachable = False              # raise ConnectionError instead
        self.force_status: Optional[int] = None   # answer every accepted request so
        self.force_body: Any = {"message": "fixture"}
        self.raw_body: Optional[bytes] = None     # 200 with this non-JSON body
        self.forbid_incidents = False         # incidents → 403
        self.forbid_details = False           # the customer listing → 403
        # An unfiltered incidents listing returns only this status (None:
        # every status).
        self.default_status: Optional[str] = None
        self.rate_limited = 0                 # answer the next N requests 429
        self.retry_after: Optional[str] = None
        self.redirect_status: Optional[int] = None
        self.redirect_to = "https://elsewhere.example.test/v3/incidents"
        # Called with the page number before an incidents page is answered
        # (an incident created mid-drain, …).
        self.before_incidents_page: Optional[Callable[[int], None]] = None
        self.calls: list[tuple[str, str]] = []            # (METHOD, path)
        self.hosts: set[str] = set()
        self.queries: list[tuple[str, dict[str, str]]] = []   # (path, query)
        self.auth_headers: list[Optional[str]] = []

    # -- inspection --

    def count(self, path: str) -> int:
        return sum(1 for _, p in self.calls if p == path)

    def incident_queries(self) -> list[dict[str, str]]:
        return [q for p, q in self.queries if p == INCIDENTS_PATH]

    # -- requests transport API --

    def send(self, request, **kwargs):  # noqa: ANN001 — requests' signature
        # What http.client does to every header value before a byte is sent
        # (a value outside Latin-1 raises UnicodeEncodeError there).
        for value in request.headers.values():
            if isinstance(value, str):
                value.encode("latin-1")
        parts = urlsplit(request.url)
        path = parts.path
        self.calls.append((request.method, path))
        self.hosts.add(parts.hostname or "")
        self.auth_headers.append(request.headers.get("Authorization"))
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        self.queries.append((path, query))
        if self.unreachable:
            raise requests.ConnectionError("fixture: connection refused")
        if parts.hostname not in self.api_hosts:
            # Only reachable by a client that FOLLOWED something off-origin.
            return self._response(request, 200, {"data": [], "customers": []})
        if self.redirect_status is not None:
            resp = self._response(request, self.redirect_status, b"")
            resp.headers["Location"] = self.redirect_to
            return resp
        if request.method != "GET":
            return self._response(request, 404, NOT_FOUND_BODY)
        if request.headers.get("Authorization") != f"Bearer {self.key}":
            return self._response(
                request, self.reject_key_status, {"message": "fixture: invalid API key"},
            )
        if self.rate_limited > 0:
            self.rate_limited -= 1
            resp = self._response(request, 429, {"message": "fixture: too many requests"})
            if self.retry_after is not None:
                resp.headers["Retry-After"] = self.retry_after
            return resp
        if self.force_status is not None:
            return self._response(request, self.force_status, self.force_body)
        if self.raw_body is not None:
            return self._response(request, 200, self.raw_body)
        if path == ACCOUNT_PATH:
            return self._account(request, query)
        if path == INCIDENTS_PATH:
            return self._incidents(request, query)
        return self._response(request, 404, NOT_FOUND_BODY)

    # -- /v3/account --

    def _account(self, request, query: dict[str, str]) -> requests.Response:  # noqa: ANN001
        refused = self._unknown_key(request, query, _ACCOUNT_KEYS)
        if refused is not None:
            return refused
        raw_id = query.get("accountId")
        details = query.get("details") == "true"
        if raw_id is None:
            return self._response(request, 200, self._provider_body(details=False))
        if not raw_id.isdigit():
            return self._response(request, 400, {"message": "\"accountId\" must be a number"})
        account_id = int(raw_id)
        if account_id == PROVIDER_ID:
            if details and self.forbid_details:
                return self._response(request, 403, {"message": "fixture: forbidden"})
            return self._response(request, 200, self._provider_body(details=details))
        for c in self.customers:
            if c["accountId"] == account_id:
                return self._response(request, 200, {
                    "name": c["accountName"], "accountPath": c["accountPath"],
                    "type": "customer", "status": c["status"], "customers": [],
                })
        return self._response(
            request, 403, {"message": "fixture: account not in this key's hierarchy"},
        )

    def _provider_body(self, *, details: bool) -> dict[str, Any]:
        body = dict(self.provider)
        body["customers"] = (
            [dict(c) for c in self.customers] if details
            else [c["accountId"] for c in self.customers]
        )
        return body

    # -- /v3/incidents --

    def _incidents(self, request, query: dict[str, str]) -> requests.Response:  # noqa: ANN001
        refused = self._unknown_key(request, query, _INCIDENT_KEYS)
        if refused is not None:
            return refused
        raw_id = query.get("accountId")
        if raw_id is None:
            return self._response(request, 400, {"message": "fixture: \"accountId\" is required"})
        if not raw_id.isdigit():
            return self._response(request, 400, {"message": "\"accountId\" must be a number"})
        page_raw = query.get("page", "1")
        size_raw = query.get("pageSize", str(DEFAULT_PAGE_SIZE))
        if not page_raw.isdigit() or int(page_raw) < 1:
            return self._response(request, 400, {"message": "\"page\" must be a positive number"})
        if not size_raw.isdigit() or int(size_raw) < 1:
            return self._response(request, 400, {"message": "\"pageSize\" must be a positive number"})
        if int(size_raw) > MAX_PAGE_SIZE:
            return self._response(request, 400, {
                "message": "fixture: \"pageSize\" must be less than or equal to 500",
            })
        sort = query.get("sort", "createdAt:desc")
        if sort not in ("createdAt:asc", "createdAt:desc"):
            return self._response(request, 400, {"message": "\"sort\" is not valid"})
        status = query.get("status")
        if status is not None and status not in ("open", "resolved", "suppressed"):
            return self._response(request, 400, {"message": "\"status\" is not valid"})
        if status is None:
            status = self.default_status
        window: Optional[tuple[date, date]] = None
        if "createdAt" in query:
            m = _DATE_RANGE_RE.match(query["createdAt"])
            if not m:
                return self._response(request, 400, {"message": "\"createdAt\" is not valid"})
            window = (date.fromisoformat(m.group(1)), date.fromisoformat(m.group(2)))
        if self.forbid_incidents:
            return self._response(request, 403, {"message": "fixture: forbidden"})
        account_id = int(raw_id)
        customer_ids = {c["accountId"] for c in self.customers}
        if account_id != PROVIDER_ID and account_id not in customer_ids:
            return self._response(
                request, 403, {"message": "fixture: account not in this key's hierarchy"},
            )
        page, size = int(page_raw), int(size_raw)
        if self.before_incidents_page is not None:
            self.before_incidents_page(page)
        rows = [
            i for i in self.incidents
            if (account_id == PROVIDER_ID or i.get("accountId") == account_id)
            and (status is None or i.get("status") == status)
            and (window is None or window[0] <= self._created_date(i) <= window[1])
        ]
        rows.sort(key=lambda i: i.get("createdAt") or "", reverse=sort.endswith(":desc"))
        chunk = rows[(page - 1) * size: page * size]
        total_pages = (len(rows) + size - 1) // size
        return self._response(request, 200, {
            "totalCount": len(rows),
            "currentPage": page,
            "totalPages": total_pages,
            "dataCount": len(chunk),
            "data": [dict(i) for i in chunk],
        })

    @staticmethod
    def _created_date(inc: dict[str, Any]) -> date:
        raw = str(inc.get("createdAt") or "")
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(
                timezone.utc).date()
        except ValueError:
            return date.min

    def _unknown_key(self, request, query: dict[str, str], allowed: set[str]):  # noqa: ANN001
        for key in query:
            if key not in allowed:
                return self._response(request, 400, {"message": f"\"{key}\" is not allowed"})
        return None

    def close(self) -> None:
        return None

    @staticmethod
    def _response(request, status: int, body: Any) -> requests.Response:  # noqa: ANN001
        resp = requests.Response()
        resp.status_code = status
        resp._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url = request.url
        resp.request = request
        return resp


def real_client(
    transport: FakeRocketCyberTransport, config: Optional[RocketCyberConfig] = None,
) -> RocketCyberClient:
    """A REAL RocketCyberClient whose session talks to `transport`."""
    client = RocketCyberClient(config or RocketCyberConfig(api_key=API_KEY, api_url=API_URL))
    client._session.mount("https://", transport)
    client._session.mount("http://", transport)
    return client


def client_factory(transport: FakeRocketCyberTransport):
    return lambda config: real_client(transport, config)


def rocketcyber_adapter_class(
    transport: FakeRocketCyberTransport,
) -> type[RocketCyberSourceAdapter]:
    """The real adapter as the framework instantiates it (`cls()`, no
    arguments), wired to `transport`."""

    class _TransportRocketCyber(RocketCyberSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=client_factory(transport))

    _TransportRocketCyber.__module__ = "apps.octo.adapters.rocketcyber"
    return _TransportRocketCyber
