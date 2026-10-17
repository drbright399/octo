"""RocketCyber v3 API client — READ-ONLY, polled.

Built against the live API (verified 2026-09-29 with a read-only key). The
first version of this client used `/account/{id}`, `/account/{id}/customers`
and `/account/{id}/incidents`: every one of those answers HTTP 404 — no
account id ever goes in the PATH. What exists:

  GET /v3/account
      the AUTHENTICATED (provider) account: {name, hierarchy, accountPath,
      type, address, status, emails, customers: [<int id>, …]}. It carries no
      id field of its own: the provider id is the last segment of its
      `accountPath` ("<parent>.<provider>").
  GET /v3/account?accountId=<provider>&details=true
      the same object, `customers` expanded to
      [{accountId, accountName, accountPath, status}, …].
  GET /v3/incidents?accountId=<id>&page=<n>&pageSize=<≤500>
                   &sort=createdAt:asc|desc&createdAt=<YYYY-MM-DD>|<YYYY-MM-DD>
                   [&status=open|resolved|suppressed]
      {totalCount, currentPage, totalPages, dataCount, data: [incident…]}.
      A PROVIDER accountId returns every customer's incidents; each incident
      names its customer in `accountId` / `accountName`.

What does NOT exist: an updated-since filter (`updatedAt` → HTTP 400
'"updatedAt" is not allowed' — unknown query keys are refused, so this client
sends exactly the keys above), a single-incident read, any write (status
change, resolve, suppress: all 404), and webhooks.

What was NOT observed: which statuses a listing WITHOUT `status` returns. The
poller therefore never relies on it — every incidents read names its status
(`poll_queries`).

Auth: `Authorization: Bearer <key>` on every request, sent to the CONFIGURED
origin only — redirects are never followed and no URL taken from a response
body is ever requested.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable, Literal, Optional
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://api-us.rocketcyber.com/v3"

# The largest page size verified live. Nothing above it is ever sent.
MAX_PAGE_SIZE = 500
# 20 × 500 = 10,000 incidents in one window — far past any real provider
# (and a hard stop for a vendor whose paging never ends).
MAX_INCIDENT_PAGES = 20
# The provider account's customer list is one unpaged answer; bound what is
# kept of it all the same.
MAX_CUSTOMERS = 5_000

INCIDENTS_PATH = "/incidents"
ACCOUNT_PATH = "/account"

# The statuses the API documents and accepts as a filter. Each is read
# explicitly: the default of an unfiltered listing was never observed.
STATUSES = ("open", "resolved", "suppressed")
# How far back OPEN incidents are read (by creation date): an incident can
# stay open for months, and its closure must still arrive.
DEFAULT_OPEN_LOOKBACK_DAYS = 365.0
MAX_OPEN_LOOKBACK_DAYS = 3650.0

# A very long upper bound on a vendor-requested wait (HTTP 429 Retry-After).
MAX_RETRY_AFTER_SEC = 3600.0


@dataclass(frozen=True)
class RocketCyberConfig:
    """Connection parameters for one RocketCyber instance.

    `account_id` is the OPTIONAL provider-account override: None = use the
    account the API key belongs to (read from GET /account)."""
    api_key: str
    api_url: str = DEFAULT_API_URL
    account_id: Optional[int] = None
    verify_tls: bool = True
    timeout_seconds: float = 15.0


# Every exception message and every `RocketCyberAccessCheck.detail` built in
# this module is OPERATOR-VISIBLE (status_detail, API responses, log lines).
# They are assembled only from static text, HTTP status codes, exception CLASS
# names, numeric account ids, a credential-free origin (`_safe_origin`) and
# vendor text that went through `_scrub`. Never a response body, a header or
# the API key.

class RocketCyberAuthError(Exception):
    """RocketCyber rejected the API key: HTTP 401 anywhere, or HTTP 403 on
    GET /account — the key's OWN account, which any valid key may read."""


class RocketCyberClientError(Exception):
    """Transport / protocol error talking to RocketCyber."""


class RocketCyberForbiddenError(RocketCyberClientError):
    """AUTHENTICATED BUT FORBIDDEN: GET /account accepted the key, then a data
    read (incidents, the customer listing) answered HTTP 403 — most likely an
    accountId outside this key's hierarchy (a wrong provider-account
    override, or a wrong derivation from accountPath). Subclasses
    RocketCyberClientError: catch it FIRST where the difference matters.

    `vendor_error` is a bounded, scrubbed copy of the vendor's own message
    ("" when the body carried none); `resource` names what was read."""

    def __init__(self, resource: str, account_id: Optional[int], vendor_error: str = "") -> None:
        self.resource = resource
        self.account_id = account_id
        self.vendor_error = vendor_error
        suffix = f" '{vendor_error}'" if vendor_error else ""
        super().__init__(f"RocketCyber answered HTTP 403 on {resource}{suffix}")


class RocketCyberNotFoundError(RocketCyberClientError):
    """HTTP 404: the path does not exist on this host — almost always a wrong
    API base URL (RocketCyber's paths live under /v3)."""


class RocketCyberRequestError(RocketCyberClientError):
    """HTTP 400: RocketCyber refused the request's parameters. A bug on OUR
    side (or an API change) — the vendor's message is kept, scrubbed."""


class RocketCyberRateLimitError(RocketCyberClientError):
    """HTTP 429. `retry_after_sec` is the vendor's Retry-After, bounded, or
    None when it sent none (the caller then applies its own backoff)."""

    def __init__(self, resource: str, retry_after_sec: Optional[float]) -> None:
        self.resource = resource
        self.retry_after_sec = retry_after_sec
        wait = (
            f"; RocketCyber asked to wait {int(retry_after_sec)} s"
            if retry_after_sec is not None else ""
        )
        super().__init__(f"RocketCyber is rate limiting requests (HTTP 429 on {resource}){wait}")


class RocketCyberAccountError(RocketCyberClientError):
    """The provider account could not be determined from GET /account (no id,
    no usable accountPath), or what was determined does not fit the rest of
    the answer. Fixed by entering the provider account ID."""


# ---------------------------------------------------------------------------
# Operator-safe text
# ---------------------------------------------------------------------------

MAX_VENDOR_ERROR_CHARS = 160
_REDACTED = "[redacted]"
# Same rules as the Datto client (each adapter package is self-contained):
# anything key/token/JWT-shaped is redacted, links are removed, straight
# quotes made typographic so vendor text cannot close the quotation it is
# shown in, control characters and newlines collapsed, length bounded.
_TOKEN_SHAPED_RE = re.compile(r"[A-Za-z0-9_\-.=+/]{24,}")
_URL_LIKE_RE = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.\-]*://|\bwww\.)\S*")
_LINK_REMOVED = "[link removed]"
_QUOTE_NEUTRAL = str.maketrans({"'": "’", '"': "”", "`": "’"})


def _scrub(text: Any, secrets: Iterable[str] = ()) -> str:
    if not isinstance(text, str):
        return ""
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, _REDACTED)
    text = _URL_LIKE_RE.sub(_LINK_REMOVED, text)
    text = _TOKEN_SHAPED_RE.sub(_REDACTED, text)
    text = text.translate(_QUOTE_NEUTRAL)
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    if len(text) > MAX_VENDOR_ERROR_CHARS:
        text = text[: MAX_VENDOR_ERROR_CHARS - 1].rstrip() + "…"
    return text


def _safe_origin(url: str) -> str:
    """scheme://host[:port] only — never userinfo, path or query."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "the configured API URL"
    if not parts.scheme or not host:
        return "the configured API URL"
    return f"{parts.scheme}://{host}{port}"


# ---------------------------------------------------------------------------
# Wizard input
# ---------------------------------------------------------------------------

def normalize_api_url(raw: Any) -> str:
    """The API base URL an operator entered, or the US default when blank.

    https only (the API key is a bearer credential), a host, no userinfo /
    query / fragment. A bare host gets RocketCyber's `/v3` path. Raises
    ValueError with operator text that never echoes the value."""
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return DEFAULT_API_URL
    try:
        parts = urlsplit(text)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        raise ValueError(
            "RC_API_URL is not a valid URL — leave it blank for "
            f"{DEFAULT_API_URL}"
        ) from None
    if parts.scheme.lower() != "https" or not host:
        raise ValueError(
            "RC_API_URL must be an https:// URL (the API key is sent to it) — "
            f"leave it blank for {DEFAULT_API_URL}"
        )
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(
            "RC_API_URL must be the plain API base URL (no user name, query or "
            f"fragment), e.g. {DEFAULT_API_URL}"
        )
    path = parts.path.rstrip("/") or "/v3"
    port = f":{parts.port}" if parts.port else ""
    host = host.lower()
    if ":" in host:              # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    return f"https://{host}{port}{path}"


def parse_account_id(raw: Any) -> Optional[int]:
    """The optional provider-account override: None when blank, else a
    positive integer. Raises ValueError (operator text) for anything else."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("RC_ACCOUNT_ID must be a number")
    if isinstance(raw, int):
        text = str(raw)
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        raise ValueError("RC_ACCOUNT_ID must be a number")
    if not text:
        return None
    if not text.isascii() or not text.isdigit() or len(text) > 12 or int(text) <= 0:
        raise ValueError(
            "RC_ACCOUNT_ID must be the numeric RocketCyber provider account ID "
            "— or left blank, so Athena reads it from the API key"
        )
    return int(text)


def incident_window(now: datetime, window_days: float) -> tuple[date, date]:
    """The `createdAt` date range for a poll at `now` (UTC dates, inclusive).

    The filter is by DATE, so the lower bound is the date `window_days`
    before now — a superset of the exact window — and the upper bound is
    TOMORROW: harmless if the vendor treats the range as inclusive, and it
    keeps today's incidents in if it treats the end as exclusive or reads the
    dates in a time zone behind UTC."""
    now = now.astimezone(timezone.utc)
    start = (now - timedelta(days=max(0.0, float(window_days)))).date()
    return start, (now + timedelta(days=1)).date()


@dataclass(frozen=True)
class PollQuery:
    """One incidents read of a poll cycle: a status and a createdAt range."""
    status: str
    created_from: date
    created_to: date


def poll_queries(
    now: datetime, *, window_days: float, open_lookback_days: float,
) -> tuple[PollQuery, ...]:
    """The reads of ONE poll cycle — the poller's, and Test connection's (one
    page each), so the probe can never pass on a request the poller does not
    send:

      open        created in the last `open_lookback_days` (an incident can
                  stay open for months; its later closure must be seen)
      resolved    created in the last `window_days`
      suppressed  created in the last `window_days`

    Every read names its status: what an unfiltered listing returns was
    never observed (open only would be a common vendor default)."""
    window = incident_window(now, window_days)
    opened = incident_window(now, max(float(open_lookback_days), float(window_days)))
    return (
        PollQuery("open", *opened),
        PollQuery("resolved", *window),
        PollQuery("suppressed", *window),
    )


def recheck_range(day: date) -> tuple[date, date]:
    """The createdAt range that finds an incident created on `day` (UTC) —
    one day either side, in case the vendor reads the dates in another time
    zone."""
    return day - timedelta(days=1), day + timedelta(days=1)


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _id_from_account_path(path: Any) -> Optional[int]:
    """'<parent>.<provider>' → provider. The last segment names the account
    itself (a customer's path is '<parent>.<provider>.<customer>')."""
    if not isinstance(path, str):
        return None
    segments = [s for s in re.split(r"[./]", path.strip()) if s]
    if not segments:
        return None
    last = segments[-1]
    if not last.isascii() or not last.isdigit() or len(last) > 12:
        return None
    return int(last) or None


def _retry_after(r: requests.Response) -> Optional[float]:
    raw = r.headers.get("Retry-After")
    if not isinstance(raw, str) or not raw.strip():
        return None
    raw = raw.strip()
    seconds: Optional[float] = None
    if raw.isdigit():
        seconds = float(raw)
    else:
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(MAX_RETRY_AFTER_SEC, seconds))


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RocketCyberAccount:
    """The account incidents are read for.

    account_id  — the EFFECTIVE id (the override when one is set)
    derived_id  — the id GET /account itself identified, None when it could
                  not tell (then an override is required)
    name        — the key's account name (vendor text; never logged)
    customer_ids — GET /account's plain `customers` list
    overridden  — True when account_id came from the operator's override
    says_customer — GET /account's own `type` / `hierarchy` names it a
                  CUSTOMER account (a key created inside one customer)
    """
    account_id: int
    derived_id: Optional[int]
    name: str
    customer_ids: tuple[int, ...] = ()
    overridden: bool = False
    says_customer: bool = False


@dataclass(frozen=True)
class CustomerListing:
    customers: list[dict[str, Any]]
    truncated: bool = False


@dataclass(frozen=True)
class IncidentListing:
    incidents: list[dict[str, Any]]
    truncated: bool = False     # stopped at the page cap: a prefix of the window
    total_count: Optional[int] = None
    pages: int = 0


AccessOutcome = Literal["ok", "credentials_rejected", "forbidden", "transport"]


@dataclass(frozen=True)
class RocketCyberAccessCheck:
    """What a connection check found (see `check_access`).

      ok                   — account, customers and one incidents page read
      credentials_rejected — the key was refused (401, or 403 on /account)
      forbidden            — the key was accepted, a data read answered 403
      transport            — unreachable / unexpected status / body, rate
                             limited, or the provider account undeterminable
    `detail` is operator-safe."""
    outcome: AccessOutcome
    detail: str
    vendor_error: str = ""
    account_id: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


def forbidden_guidance(
    vendor_error: str = "",
    *,
    account_id: Optional[int] = None,
    overridden: bool = False,
    saved: bool = False,
    retry_note: str = "",
) -> str:
    """Operator-actionable text for the accepted-but-forbidden case, shared by
    Test connection, customer discovery and the poller's status_detail.

    Not `overridden` with an `account_id` means Athena DERIVED that id from
    the key's own account answer (its accountPath) — a derivation that can be
    wrong, and the one fix for that is the 'Provider account ID' field, so it
    is named before the key is blamed."""
    which = f"account {account_id}" if account_id else "the account"
    cause = (
        f"RocketCyber accepted the API key but refused to return data for "
        f"{which} (HTTP 403). "
    )
    key_scope = (
        "check in the RocketCyber console that the key was created at the "
        "provider (MSP) account level and is still enabled."
    )
    if overridden:
        fix = (
            "That account ID is the 'Provider account ID' you entered: it must "
            "be your provider (MSP) account, or one of its customers. "
        )
        fix += (
            "Stored credentials cannot be edited — Disable this integration, "
            "then Add integration again with that field left blank (Athena "
            "then reads the account the key belongs to)."
            if saved else
            "Clear the field so Athena reads the account the key belongs to, "
            "or correct it, then press Test connection again."
        )
    elif account_id:
        fix = (
            f"Athena read account {account_id} from the key's own account "
            "answer (its accountPath). If that is not your provider (MSP) "
            "account, enter your provider account ID in 'Provider account ID'"
            + (
                " — stored credentials cannot be edited, so Disable this "
                "integration, then Add integration again with that field "
                "filled in. "
                if saved else ", then press Test connection again. "
            )
            + "If it is, " + key_scope
        )
    else:
        fix = key_scope[0].upper() + key_scope[1:]
    said = f" RocketCyber's own message: \"{vendor_error}\"" if vendor_error else ""
    return cause + fix + retry_note + said


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class RocketCyberClient:
    def __init__(self, config: RocketCyberConfig) -> None:
        self._config = config
        self._base = config.api_url.rstrip("/")
        self._account: Optional[RocketCyberAccount] = None
        self._session = requests.Session()
        if not config.verify_tls:
            self._session.verify = False  # type: ignore[assignment]
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

    @property
    def account(self) -> Optional[RocketCyberAccount]:
        """The provider account as last read (None before the first read)."""
        return self._account

    @property
    def origin(self) -> str:
        """The configured API origin (scheme://host[:port]), operator-safe."""
        return _safe_origin(self._base)

    def _secrets(self) -> tuple[str, ...]:
        return tuple(v for v in (self._config.api_key,) if v)

    # ----- one GET -----

    def _get(
        self,
        path: str,
        *,
        what: str,
        params: Optional[dict[str, Any]] = None,
        key_check: bool = False,
    ) -> dict[str, Any]:
        """One bearer-authenticated GET to the configured origin. The single
        place statuses become exceptions:
          401 (or 403 when `key_check`: the key's own account) → AuthError
          403 → ForbiddenError · 400 → RequestError · 404 → NotFoundError
          429 → RateLimitError · 3xx / other / non-JSON / unreachable →
          RocketCyberClientError."""
        url = self._base + path
        try:
            r = self._session.get(
                url,
                headers={
                    "Authorization": f"Bearer {self._config.api_key}",
                    "Accept": "application/json",
                },
                params=params,
                timeout=self._config.timeout_seconds,
                # A 3xx would send the bearer key to whatever host it names.
                allow_redirects=False,
            )
        except (requests.RequestException, ValueError) as exc:
            # ValueError: a header value http.client cannot encode (the key
            # validation in the adapter keeps such keys out; this keeps the
            # "never raises" promise of check_access if one slips through).
            # `from None`: requests' InvalidHeader carries the full header
            # value — the bearer key — in its message, and a chained cause is
            # printed by any traceback that logs this error.
            raise RocketCyberClientError(
                f"RocketCyber unreachable at {_safe_origin(url)}: {type(exc).__name__}"
            ) from None
        status = r.status_code
        if status == 401 or (status == 403 and key_check):
            raise RocketCyberAuthError(
                f"RocketCyber rejected the API key (HTTP {status})"
            )
        if status == 403:
            # RocketCyber answers a bad key with 401 OR 403. A 403 on a data
            # read means "forbidden" only if the key still reads its own
            # account — a key revoked after the account was cached must say
            # "rejected", not send the operator to check account ids.
            self._recheck_key()
            account = params.get("accountId") if params else None
            raise RocketCyberForbiddenError(
                what, account if isinstance(account, int) else None,
                self._vendor_message(r),
            )
        if 300 <= status < 400:
            raise RocketCyberClientError(
                f"RocketCyber {what} answered with a redirect (HTTP {status}); "
                "redirects are never followed — check the API base URL"
            )
        if status == 400:
            said = self._vendor_message(r)
            raise RocketCyberRequestError(
                f"RocketCyber refused the {what} request (HTTP 400)"
                + (f": “{said}”" if said else "")
            )
        if status == 404:
            raise RocketCyberNotFoundError(
                f"RocketCyber answered HTTP 404 for {what} at {_safe_origin(url)} — "
                f"the API base URL is probably wrong (default {DEFAULT_API_URL})"
            )
        if status == 429:
            raise RocketCyberRateLimitError(what, _retry_after(r))
        if status != 200:
            raise RocketCyberClientError(f"RocketCyber {what} returned HTTP {status}")
        try:
            body = r.json()
        except ValueError as exc:
            raise RocketCyberClientError(
                f"RocketCyber {what} returned a body that is not JSON"
            ) from exc
        if not isinstance(body, dict):
            raise RocketCyberClientError(
                f"RocketCyber {what} returned JSON that is not an object"
            )
        return body

    def _recheck_key(self) -> None:
        """Raise RocketCyberAuthError when the key no longer reads its own
        account; return quietly otherwise (any other failure of this probe
        leaves the caller's 403 to stand)."""
        try:
            self._get(ACCOUNT_PATH, what="account", key_check=True)
        except RocketCyberClientError:
            return

    def _vendor_message(self, r: requests.Response) -> str:
        try:
            body = r.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""
        return _scrub(body.get("message"), self._secrets())

    # ----- the provider account -----

    def provider_account(self, *, refresh: bool = False) -> RocketCyberAccount:
        """GET /account (validates the key) → the account incidents are read
        for. Cached for this client's life; `refresh` re-reads."""
        if self._account is not None and not refresh:
            return self._account
        body = self._get(ACCOUNT_PATH, what="account", key_check=True)
        derived = (
            _positive_int(body.get("accountId"))
            or _positive_int(body.get("id"))
            or _id_from_account_path(body.get("accountPath"))
        )
        raw_customers = body.get("customers")
        customer_ids = tuple(
            c for c in (raw_customers if isinstance(raw_customers, list) else [])[:MAX_CUSTOMERS]
            if _positive_int(c)
        )
        raw_name = body.get("name")
        name = raw_name if isinstance(raw_name, str) else ""
        says_customer = any(
            isinstance(v, str) and v.strip().lower() == "customer"
            for v in (body.get("type"), body.get("hierarchy"))
        )
        override = self._config.account_id
        if override is not None:
            if derived is not None and derived != override:
                logger.warning(
                    "[rocketcyber] provider account override %d differs from the "
                    "key's own account %d: incidents are read for %d only",
                    override, derived, override,
                )
            account = RocketCyberAccount(
                account_id=override, derived_id=derived, name=name,
                customer_ids=customer_ids, overridden=True,
                says_customer=says_customer,
            )
        elif derived is None:
            raise RocketCyberAccountError(
                "RocketCyber's account answer does not say which account this "
                "API key belongs to (no account id or accountPath) — enter your "
                "provider account ID in 'Provider account ID'"
            )
        else:
            account = RocketCyberAccount(
                account_id=derived, derived_id=derived, name=name,
                customer_ids=customer_ids, says_customer=says_customer,
            )
        self._account = account
        return account

    # ----- customers (the mapping picker) -----

    def list_customers(self) -> CustomerListing:
        """The provider account's customers, `{accountId, accountName,
        accountPath, status}` each — one unpaged answer, kept to
        MAX_CUSTOMERS (then truncated=True)."""
        account = self.provider_account()
        body = self._get(
            ACCOUNT_PATH, what="customer list",
            params={"accountId": account.account_id, "details": "true"},
        )
        raw = body.get("customers")
        if not isinstance(raw, list):
            raise RocketCyberClientError(
                "RocketCyber customer list answered without a customers list"
            )
        customers: list[dict[str, Any]] = []
        seen: set[int] = set()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            cid = _positive_int(entry.get("accountId"))
            if cid is None or cid in seen:
                continue
            seen.add(cid)
            customers.append(entry)
            if len(customers) >= MAX_CUSTOMERS:
                break
        truncated = len(customers) >= MAX_CUSTOMERS and len(raw) > MAX_CUSTOMERS
        return CustomerListing(customers, truncated=truncated)

    # ----- incidents -----

    def incidents_query(
        self, *, created_from: date, created_to: date, page: int, page_size: int,
        status: Optional[str] = None,
    ) -> dict[str, Any]:
        """The incidents query — the poller's and Test connection's alike."""
        query: dict[str, Any] = {
            "accountId": self.provider_account().account_id,
            "page": page,
            "pageSize": max(1, min(int(page_size), MAX_PAGE_SIZE)),
            "sort": "createdAt:desc",
            "createdAt": f"{created_from.isoformat()}|{created_to.isoformat()}",
        }
        if status is not None:
            if status not in STATUSES:
                raise ValueError(f"unknown incident status filter {status!r}")
            query["status"] = status
        return query

    def fetch_incidents(
        self,
        *,
        created_from: date,
        created_to: date,
        status: Optional[str] = None,
        page_size: int = MAX_PAGE_SIZE,
        max_pages: int = MAX_INCIDENT_PAGES,
    ) -> IncidentListing:
        """Every incident CREATED in [created_from, created_to] (dates) —
        with `status`, only that status (the poller always names one; see
        `poll_queries`) — following the page numbers to the end.

        Newest first (`createdAt:desc`): an incident created mid-drain shifts
        later pages by one, which can only REPEAT an item at a page boundary
        (deduplicated by id here), never skip one — and if the page cap is
        ever reached, what is missing is the oldest part of the window.
        Only page NUMBERS are sent; nothing from a response body is ever
        requested."""
        incidents: list[dict[str, Any]] = []
        seen: set[int] = set()
        total_count: Optional[int] = None
        pages = max(1, int(max_pages))
        for page in range(1, pages + 1):
            params = self.incidents_query(
                created_from=created_from, created_to=created_to,
                page=page, page_size=page_size, status=status,
            )
            body = self._get(INCIDENTS_PATH, what="incidents", params=params)
            data = body.get("data")
            if not isinstance(data, list):
                raise RocketCyberClientError(
                    "RocketCyber incidents answered without a data list"
                )
            if total_count is None and _positive_int(body.get("totalCount")) is not None:
                total_count = body["totalCount"]
            for item in data:
                if not isinstance(item, dict):
                    continue
                iid = _positive_int(item.get("id"))
                if iid is not None:
                    if iid in seen:
                        continue
                    seen.add(iid)
                incidents.append(item)
            total_pages = _positive_int(body.get("totalPages"))
            if not data:
                return IncidentListing(incidents, False, total_count, page)
            if total_pages is not None and page >= total_pages:
                return IncidentListing(incidents, False, total_count, page)
            if total_pages is None and len(data) < params["pageSize"]:
                return IncidentListing(incidents, False, total_count, page)
        logger.warning(
            "[rocketcyber] incident listing stopped at the page cap (%d pages, "
            "%d incidents); the oldest part of the window was not read",
            pages, len(incidents),
        )
        return IncidentListing(incidents, True, total_count, pages)

    # ----- the connection check -----

    def check_access(
        self,
        *,
        window_days: float = 14.0,
        open_lookback_days: float = DEFAULT_OPEN_LOOKBACK_DAYS,
    ) -> RocketCyberAccessCheck:
        """Verify AUTHORIZATION by reading what Athena depends on: the account
        (validates the key and names the provider), its customer list (the
        mapping picker) and page 1 of EACH incidents read a poll cycle makes,
        in exactly the shape the poller sends them (`poll_queries`). Refuses a
        key that belongs to one customer rather than the provider. Never
        raises."""
        account: Optional[RocketCyberAccount] = None
        counts: dict[str, int] = {}
        try:
            account = self.provider_account(refresh=True)
            if not account.overridden and account.says_customer:
                raise RocketCyberAccountError(_customer_key_text(account, "customer"))
            customers = self.list_customers()
            listed = {c["accountId"] for c in customers.customers}
            own = set(account.customer_ids)
            if not account.overridden and not own and not listed:
                # A provider has customers; an account with none is almost
                # always a key created INSIDE one customer — polling it would
                # silently cover that one customer only.
                raise RocketCyberAccountError(_customer_key_text(account, "empty"))
            if not account.overridden and own and (
                account.account_id in own or not listed & own
            ):
                # The key's account HAS customers, but the derived id lists
                # none of them (or is one of them): polling it would silently
                # cover the wrong account.
                raise RocketCyberAccountError(
                    f"RocketCyber's account answer points at account "
                    f"{account.account_id}, whose customer list does not match "
                    "the key's — enter your provider account ID in 'Provider "
                    "account ID'"
                )
            for query in poll_queries(
                datetime.now(timezone.utc),
                window_days=window_days, open_lookback_days=open_lookback_days,
            ):
                listing = self.fetch_incidents(
                    created_from=query.created_from, created_to=query.created_to,
                    status=query.status, max_pages=1,
                )
                counts[query.status] = (
                    listing.total_count if listing.total_count is not None
                    else len(listing.incidents)
                )
        except RocketCyberAuthError as exc:
            return RocketCyberAccessCheck("credentials_rejected", str(exc))
        except RocketCyberForbiddenError as exc:
            return RocketCyberAccessCheck(
                "forbidden",
                forbidden_guidance(
                    exc.vendor_error,
                    account_id=exc.account_id or (account.account_id if account else None),
                    overridden=bool(account and account.overridden),
                ),
                exc.vendor_error,
                account_id=account.account_id if account else None,
            )
        except RocketCyberClientError as exc:
            return RocketCyberAccessCheck(
                "transport", str(exc),
                account_id=account.account_id if account else None,
            )
        source = (
            "the 'Provider account ID' you entered" if account.overridden
            else "read from the API key"
        )
        # The key's own account name, so the operator sees WHICH account was
        # picked (vendor text: scrubbed and bounded; the operator's browser
        # only — never a log line).
        name = _scrub(account.name, self._secrets()) if account.name else ""
        named = f"“{name}”, " if name and account.derived_id == account.account_id else ""
        detail = (
            f"RocketCyber reachable and the API key works: provider account "
            f"{account.account_id} ({named}{source}), {len(customers.customers)} "
            f"customer(s), and its incidents are readable: "
            f"{counts.get('open', 0)} open, and {counts.get('resolved', 0)} "
            f"resolved / {counts.get('suppressed', 0)} suppressed created in "
            f"the last {int(window_days)} days."
        )
        if account.overridden and account.derived_id not in (None, account.account_id):
            detail += (
                f" Note: the key itself belongs to account {account.derived_id}; "
                f"only account {account.account_id}'s incidents will be read."
            )
        return RocketCyberAccessCheck("ok", detail, account_id=account.account_id)


def _customer_key_text(account: RocketCyberAccount, why: Literal["customer", "empty"]) -> str:
    what = (
        "a customer account" if why == "customer"
        else "an account with no customers"
    )
    return (
        f"RocketCyber says this API key belongs to {what} (account "
        f"{account.account_id}), not to your provider (MSP) account: Athena "
        "would only ever see that one account's incidents. Create the key in "
        "the RocketCyber console at your PROVIDER (MSP) account level — not "
        "inside a customer — and test again. (If this really is your provider "
        "account and it has no customers yet, enter its ID in 'Provider "
        "account ID' to connect anyway.)"
    )
