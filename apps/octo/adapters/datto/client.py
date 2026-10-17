"""Datto RMM API client.

Datto's HTTP API uses an OAuth2 client-credentials-style flow: the
operator's API key + secret are exchanged for a short-lived bearer
token via POST /auth/oauth/token. The token authenticates all subsequent
calls and is cached client-side until expiry.

Regional base URL is operator-configured during onboarding — Datto runs
distinct clusters (US, EU, AU, etc.), each with a different host. The
wizard's CredentialField for `DATTO_API_URL` accepts the operator's
specific regional URL.

Client is intentionally minimal: requests + tight timeouts. TLS verify
is on by default (Datto's certs are public-CA-signed); env override
exists for sandbox/proxy environments but should never run in prod.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Optional
from urllib.parse import parse_qs, quote, urlsplit

import requests

from apps.octo.adapters.datto.fields import is_alert_uid
from apps.octo.ingest.timestamps import utcnow_iso as _now_iso

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DattoConfig:
    """Connection parameters for a configured Datto RMM instance.

    Stored in registry.db's adapter_instances table; passed to the client
    at adapter start time.
    """
    api_url: str               # e.g., "https://merlot-api.centrastage.net"
    api_key: str               # Datto API Key (public half)
    api_secret_key: str        # Datto API Secret Key (private half)
    verify_tls: bool = True
    timeout_seconds: float = 15.0


# Every exception message and every `DattoAccessCheck.detail` built in this
# module is OPERATOR-VISIBLE: callers put them into status_detail, API
# responses and log lines verbatim. They are therefore assembled only from
# static text, HTTP status codes, exception CLASS names, a credential-free
# origin (`_safe_origin`) and vendor text that went through `_scrub`. Never
# interpolate a response body, a header, a token or a config value.

class DattoAuthError(Exception):
    """Datto rejected the API key / secret pair (token endpoint 400/401/403)."""


class DattoClientError(Exception):
    """Generic transport / protocol error talking to Datto."""


class DattoForbiddenError(DattoClientError):
    """AUTHENTICATED BUT FORBIDDEN: Datto issued a token for the key pair and
    then answered a data endpoint with HTTP 403 — the API user's security
    level grants no access to that resource. Distinct from DattoAuthError
    (the key is fine) and from a transport fault (retrying changes nothing
    until a human fixes the user in Datto RMM).

    `vendor_error` is a bounded, scrubbed copy of the vendor's own `error`
    string ("" when the body carried none); `resource` is the API path.
    Subclasses DattoClientError so pre-existing `except DattoClientError`
    callers keep working — catch this one FIRST where the difference matters.
    """

    def __init__(self, resource: str, vendor_error: str = "") -> None:
        self.resource = resource
        self.vendor_error = vendor_error
        suffix = f" '{vendor_error}'" if vendor_error else ""
        super().__init__(f"Datto answered HTTP 403 on {resource}{suffix}")


class DattoThrottledError(DattoClientError):
    """HTTP 429: Datto is rate limiting this account / IP. Datto temporarily
    BLOCKS an IP that keeps calling after a 429 (it answers 403 meanwhile —
    which would stop the alerts poller that shares the IP and token), so a
    caller must STOP, not move on to its next read. `retry_after_sec` is the
    vendor's Retry-After when it sent one (else None). Subclasses
    DattoClientError, so callers that do not care see no difference."""

    def __init__(self, message: str, retry_after_sec: Optional[float] = None) -> None:
        self.retry_after_sec = retry_after_sec
        super().__init__(message)


class DattoNotFoundError(DattoClientError):
    """HTTP 404 on a data endpoint: the vendor does not know the thing asked
    for (a device that was deleted, …). Subclasses DattoClientError, with the
    same message, so callers that do not care see no difference."""


class DattoAuditShapeError(DattoClientError):
    """A device audit answered HTTP 200 with NONE of the fields Athena reads
    (`AUDIT_FIELDS`: no `bios.serialNumber`, no `baseBoard.serialNumber`, no
    `systemInfo.manufacturer` / `model` key at all) — an error object, an
    empty or non-object body, or a shape this build does not know. It is a
    FAILED audit, never "this device has no serial": stored as an answer it
    would stamp every device for 7 days and the first live round would read
    "read N · serials found 0 · failed 0" (v0.17.3 review). Subclasses
    DattoClientError, so callers that do not care see no difference."""


# The ONLY fields of a Datto device object that ever leave `get_device_portal`.
# The object also carries `webRemoteUrl`, which STARTS A REMOTE-CONTROL
# SESSION on the device: it is dropped here, at the socket's edge, so no
# caller can surface, log or cache it by accident.
DEVICE_PORTAL_FIELDS: tuple[str, ...] = ("uid", "siteUid", "portalUrl")
_DEVICE_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

MAX_VENDOR_ERROR_CHARS = 160
_REDACTED = "[redacted]"
# Anything shaped like a key/token/JWT. Ordinary prose never has a 24+ char
# run without whitespace, so this costs nothing on real vendor messages.
_TOKEN_SHAPED_RE = re.compile(r"[A-Za-z0-9_\-.=+/]{24,}")
# Vendor text is QUOTED next to the platform's own instructions. It must not be
# able to close that quotation or carry a link: a hostile endpoint could
# otherwise make "re-enter your secret at https://…" read as Athena's voice.
_URL_LIKE_RE = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.\-]*://|\bwww\.)\S*")
_LINK_REMOVED = "[link removed]"
_QUOTE_NEUTRAL = str.maketrans({"'": "\u2019", '"': "\u201d", "`": "\u2019"})


def _scrub(text: Any, secrets: Iterable[str] = ()) -> str:
    """Make vendor-supplied text safe to show: known secrets, links and
    token-shaped runs redacted, straight quotes made typographic (so the text
    cannot close the quotation it is shown in), control characters and
    newlines collapsed, length bounded. Non-strings become ""."""
    if not isinstance(text, str):
        return ""
    for secret in secrets:
        # A very short value is not a meaningful secret, and replacing every
        # "k" would shred the message (real Datto keys are 32 characters).
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
    """scheme://host[:port] only — an operator can paste a URL carrying
    userinfo or a query string, and neither may reach a message."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "the configured API URL"
    if not parts.scheme or not host:
        return "the configured API URL"
    return f"{parts.scheme}://{host}{port}"


# Datto's documented labels (Setup > Users > the user > Generate API Keys). An
# ordinary "security level" on the user does NOT grant API access — sending an
# operator there cost a support call. Kept in one place; confirm against the
# live UI when Datto renames things.
_FIX_ACCESS_LEVEL = (
    "In Datto RMM open Setup > Users, click the API user and, next to "
    "Generate API Keys, set its API Security Level (and API Component Level) "
    "to one that covers the sites, devices and alerts Athena should read, "
    "then Save User. Labels vary slightly between Datto RMM versions."
)


def forbidden_guidance(
    vendor_error: str = "", *, saved: bool = False, retry_note: str = "",
) -> str:
    """Operator-actionable text for the authenticated-but-forbidden case,
    shared by test-connection, site discovery and the poller's status_detail.

    `saved` = the key pair is already stored (poller / discovery): credentials
    are create-only, so telling that operator to regenerate the key would
    force Disable + re-add and lose the mappings and the webhook token.
    `vendor_error` is `_scrub`bed vendor text. It only ever appears LAST, as a
    labelled quotation — never inside the instruction. Without it the cause is
    not asserted: Datto also answers 403 while it temporarily blocks an IP
    address that kept going after HTTP 429.
    """
    if vendor_error:
        cause = (
            "Datto accepted the API key, but this API user may not read the "
            "account (HTTP 403). "
        )
    else:
        cause = (
            "Datto accepted the API key but answered HTTP 403 without saying "
            "why: either this API user's access level, or a temporary block "
            "of this server's IP address after rate limiting (it lifts by "
            "itself). If it has not cleared in about 10 minutes: "
        )
    closing = (
        " Do NOT regenerate the API keys: the stored pair works as soon as "
        "the access level is fixed."
        if saved else
        " Then press Test connection again — the same key pair keeps working; "
        "do not regenerate it."
    )
    said = f" Datto's own message: \"{vendor_error}\"" if vendor_error else ""
    return cause + _FIX_ACCESS_LEVEL + closing + retry_note + said


# Datto rejects a page size above this with HTTP 400 ("exceeds the defined
# limit of 250") — the whole request fails, not just the excess.
MAX_PAGE_SIZE = 250

# Site pagination: 40 pages = 10,000 sites, far past any real account, and a
# hard stop for a vendor that never ends.
SITES_PAGE_SIZE = MAX_PAGE_SIZE
MAX_SITE_PAGES = 40

ALERTS_PATH = "/api/v2/account/alerts/open"
# N0 — the backstop: alerts RESOLVED since a cursor (an auto-resolving monitor
# can open and resolve between two polls of the open list). Same query shape.
RESOLVED_ALERTS_PATH = "/api/v2/account/alerts/resolved"
# The device list of ONE site (the inventory feed): /api/v2/site/{siteUid}/devices
SITE_DEVICES_PATH = "/api/v2/site/{}/devices"
MAX_DEVICE_PAGES = 40                # 10,000 devices on one site
_SITE_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
# The ONLY device fields the inventory feed ever reads (verified live
# 2026-10-01; `extIpAddress` added for v0.17.2's device list — Rick, D).
# NEVER a UDF: Datto UDFs may hold BitLocker recovery keys — they are dropped
# here, at the socket's edge, unread; so is `lastLoggedInUser` (personal data)
# and `webRemoteUrl` (it starts a remote-control session).
INVENTORY_FIELDS: tuple[str, ...] = (
    "uid", "hostname", "deviceType", "online", "lastSeen", "intIpAddress",
    "extIpAddress", "operatingSystem", "domain",
)
# One alert by uid — the same object shape as an ALERTS_PATH list entry.
ALERT_PATH_PREFIX = "/api/v2/alert/"
# One device's AUDIT (v0.17.3, Rick's decision A of 2026-10-07: the serial
# number, so an analyst knows WHICH machine throws an alert — the device list
# has none). The audit object also carries the logged-in user
# (`systemInfo.username`), every network interface (MACs, addresses), the
# installed software, UDFs and the portal / remote-control URLs: NONE of it
# is ever kept — the ONLY values that leave `device_audit` are these four
# (object, field) pairs, read by name; everything else is dropped here,
# unread. The live shape was NOT probed when this was built: a missing or
# wrong-typed key is simply none.
AUDIT_PATH_PREFIX = "/api/v2/audit/device/"
AUDIT_FIELDS: tuple[tuple[str, str], ...] = (
    ("bios", "serialNumber"), ("baseBoard", "serialNumber"),
    ("systemInfo", "manufacturer"), ("systemInfo", "model"),
)
# A vendor value longer than this is cut before it leaves the client (the
# consumer cleans and bounds it again).
AUDIT_VALUE_MAX = 256


def _alerts_query(since_iso: str, page_size: int) -> dict[str, Any]:
    """The poller's alert query. `check_access()` sends the SAME shape, so
    Test connection cannot pass a request the poller will be refused."""
    return {
        "max": page_size,
        "sortBy": "timestamp",
        "order": "asc",
        "after": since_iso,
    }


@dataclass(frozen=True)
class DeviceListing:
    devices: list[dict[str, Any]]
    truncated: bool = False     # stopped at the page cap: NOT a whole list


@dataclass(frozen=True)
class SiteListing:
    sites: list[dict[str, Any]]
    truncated: bool = False     # stopped at the page cap: `sites` is a prefix


_NO_NEXT_PAGE = -1


def _next_page_number(body: dict[str, Any]) -> int | None:
    """The `page` query value of `pageDetails.nextPageUrl`. `_NO_NEXT_PAGE`
    when the vendor names no next page; None when it names one we cannot use
    (the caller must then report a truncated list, not a complete one).
    Nothing else in that URL is trusted — not its host, scheme or path."""
    details = body.get("pageDetails")
    next_url = details.get("nextPageUrl") if isinstance(details, dict) else None
    if next_url is None or next_url == "":
        return _NO_NEXT_PAGE
    if not isinstance(next_url, str):
        return None
    try:
        values = parse_qs(urlsplit(next_url).query).get("page") or []
        page = int(values[0]) if values else None
    except ValueError:
        return None
    return page if page is not None and page >= 0 else None


AccessOutcome = Literal["ok", "credentials_rejected", "forbidden", "transport"]


@dataclass(frozen=True)
class DattoAccessCheck:
    """What a connection check actually found — `ping()`'s bool could not tell
    a bad key from a key that may read nothing.

      ok                   — token issued AND the data reads succeeded
      credentials_rejected — the token endpoint refused the key pair
      forbidden            — token issued, a data read answered HTTP 403
      transport            — unreachable / unexpected status / malformed body

    `detail` is operator-safe (see the note above the exceptions).
    """
    outcome: AccessOutcome
    detail: str
    vendor_error: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


class DattoClient:
    """Stateful client — caches the bearer token until close to expiry.

    Datto tokens are short-lived (~30 min). We refresh proactively when
    < 60s remains so a long-running poll doesn't get caught mid-cycle
    by a 401.
    """

    _TOKEN_REFRESH_LEEWAY_SEC = 60.0

    def __init__(self, config: DattoConfig) -> None:
        self._config = config
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._session = requests.Session()
        if not config.verify_tls:
            self._session.verify = False  # type: ignore[assignment]
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

    # ----- Auth -----

    def _secrets(self) -> tuple[str, ...]:
        """Values that must never survive into a surfaced message."""
        return tuple(
            v for v in (
                self._config.api_secret_key, self._config.api_key, self._token,
            ) if v
        )

    def authenticate(self) -> str:
        """Exchange the API key/secret for a bearer token. Returns the
        token; cache it for re-use. Raises DattoAuthError on 4xx,
        DattoClientError on transport problems."""
        url = self._config.api_url.rstrip("/") + "/auth/oauth/token"
        try:
            r = self._session.post(
                url,
                data={
                    "grant_type": "password",
                    "username": self._config.api_key,
                    "password": self._config.api_secret_key,
                },
                headers={"Authorization": "Basic cHVibGljLWNsaWVudDpwdWJsaWM="},  # Datto's public client basic auth
                timeout=self._config.timeout_seconds,
                # A 307/308 would re-send this form — the key pair — to
                # whatever host the answer names.
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise DattoClientError(
                f"Datto unreachable at {_safe_origin(url)}: {type(exc).__name__}"
            ) from exc
        if 300 <= r.status_code < 400:
            raise DattoClientError(
                f"Datto auth answered with a redirect (HTTP {r.status_code}); "
                "redirects are never followed — check the API URL"
            )
        if r.status_code in (400, 401) or (
            r.status_code == 403 and self._names_oauth_error(r)
        ):
            raise DattoAuthError(
                f"Datto rejected credentials (HTTP {r.status_code})"
            )
        if r.status_code == 403:
            # No OAuth error in the body: Datto also answers 403 while it
            # temporarily blocks an IP that kept going after HTTP 429. Calling
            # that "rejected credentials" sends the operator to Disable +
            # re-add for a condition that clears by itself.
            raise DattoClientError(
                "Datto auth returned HTTP 403 without an OAuth error — "
                "possibly a temporary block of this server's IP address "
                "after rate limiting"
            )
        if r.status_code != 200:
            raise DattoClientError(
                f"Datto auth returned HTTP {r.status_code}"
            )
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = {}
        token = body.get("access_token") if isinstance(body, dict) else None
        expires_in = body.get("expires_in", 1800) if isinstance(body, dict) else 1800
        if not isinstance(token, str) or not token:
            raise DattoClientError("Datto response missing access_token")
        self._token = token
        try:
            self._token_expires_at = time.time() + float(expires_in)
        except (TypeError, ValueError):
            self._token_expires_at = time.time() + 1800.0
        return token

    @staticmethod
    def _names_oauth_error(r: requests.Response) -> bool:
        """True when the token endpoint's body is an OAuth error object
        (`{"error": "invalid_grant", …}`) — the vendor SAYING the pair is bad."""
        try:
            body = r.json()
        except ValueError:
            return False
        return isinstance(body, dict) and isinstance(body.get("error"), str)

    def _ensure_token(self) -> str:
        if (
            self._token is None
            or time.time() + self._TOKEN_REFRESH_LEEWAY_SEC >= self._token_expires_at
        ):
            self.authenticate()
        assert self._token is not None
        return self._token

    # ----- Authenticated reads -----

    def _get(
        self,
        path: str,
        *,
        what: str,
        params: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """One bearer-authenticated GET, the single place the three outcomes
        are told apart for data endpoints:
          - 401 → the cached token went stale: re-authenticate once, retry
          - 403 → DattoForbiddenError (authenticated, not authorized)
          - unreachable / 3xx / other status / non-JSON → DattoClientError
        (A rejected key pair surfaces as DattoAuthError from authenticate().)

        `timeout_seconds` overrides the configured per-request timeout for
        THIS read (a caller answering someone else's clock — the webhook
        doorbell — cannot wait the poller's 15 s).
        """
        self._ensure_token()
        url = self._config.api_url.rstrip("/") + path
        timeout = (
            self._config.timeout_seconds if timeout_seconds is None
            else min(float(timeout_seconds), self._config.timeout_seconds)
        )

        def _send() -> requests.Response:
            try:
                return self._session.get(
                    url,
                    headers={"Authorization": f"Bearer {self._token}"},
                    params=params,
                    timeout=timeout,
                    # Every read goes to the CONFIGURED origin. Following a
                    # 3xx would fetch — and trust the JSON of — any host the
                    # answer names.
                    allow_redirects=False,
                )
            except requests.RequestException as exc:
                raise DattoClientError(
                    f"Datto unreachable at {_safe_origin(url)}: {type(exc).__name__}"
                ) from exc

        r = _send()
        if r.status_code == 401:
            self.authenticate()
            r = _send()
        if r.status_code == 403:
            vendor_error = self._vendor_error(r)
            # Permissions may be baked into the token at issue time: drop it
            # so the retry after the operator fixes the user gets a fresh one.
            self._token = None
            raise DattoForbiddenError(path, vendor_error)
        if 300 <= r.status_code < 400:
            raise DattoClientError(
                f"Datto {what} answered with a redirect (HTTP {r.status_code}); "
                "redirects are never followed — check the API URL"
            )
        if r.status_code == 404:
            raise DattoNotFoundError(f"Datto {what} returned HTTP 404")
        if r.status_code == 429:
            retry_after: Optional[float] = None
            try:
                retry_after = max(0.0, float(r.headers.get("Retry-After", "")))
            except (TypeError, ValueError):
                retry_after = None
            raise DattoThrottledError(
                f"Datto {what} returned HTTP 429 (rate limited)", retry_after)
        if r.status_code != 200:
            raise DattoClientError(
                f"Datto {what} returned HTTP {r.status_code}"
            )
        try:
            body = r.json()
        except ValueError as exc:
            raise DattoClientError(
                f"Datto {what} returned a body that is not JSON"
            ) from exc
        return body if isinstance(body, dict) else {}

    def _vendor_error(self, r: requests.Response) -> str:
        """The vendor's own `error` string from an error body — scrubbed and
        bounded. "" when there is none (or the body is not JSON)."""
        try:
            body = r.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""
        return _scrub(body.get("error"), self._secrets())

    # ----- Smoke -----

    def check_access(self) -> DattoAccessCheck:
        """Verify AUTHORIZATION, not just authentication: get a token, then
        perform the three reads Athena depends on (account, sites, open
        alerts). Datto issues a token to an API user whose security level
        grants nothing, so "authenticate() worked" proves very little.
        Never raises."""
        try:
            self._ensure_token()
            self._get("/api/v2/account", what="account")
            # The SAME request shapes the site drain and the poller send: a
            # cheaper probe (max=1) passed here while every real poll was
            # refused for its page size.
            self._get(
                "/api/v2/account/sites", what="sites",
                params={"max": SITES_PAGE_SIZE},
            )
            self._get(
                ALERTS_PATH, what="alerts",
                params=_alerts_query(_now_iso(), MAX_PAGE_SIZE),
            )
        except DattoAuthError as exc:
            return DattoAccessCheck("credentials_rejected", str(exc))
        except DattoForbiddenError as exc:
            return DattoAccessCheck(
                "forbidden", forbidden_guidance(exc.vendor_error), exc.vendor_error,
            )
        except DattoClientError as exc:
            return DattoAccessCheck("transport", str(exc))
        return DattoAccessCheck(
            "ok",
            "Datto RMM reachable, credentials valid, and the API user can "
            "read the account, its sites and its alerts.",
        )

    def ping(self) -> bool:
        """True when `check_access()` is fully OK; False on any failure.
        Never raises. Kept for callers that only need the bool — use
        check_access() to learn WHICH failure it was."""
        check = self.check_access()
        if not check.ok:
            logger.info("[datto] ping failed (%s): %s", check.outcome, check.detail)
        return check.ok

    # ----- Sites (for tenant mapping wizard) -----

    def list_sites(self) -> list[dict[str, Any]]:
        """Return ALL of the MSP account's Sites (see `list_sites_drained`).
        Wizard uses this for the tenant-mapping step (Site → OCTO client
        slug)."""
        return self.list_sites_drained().sites

    def list_sites_drained(self, *, max_pages: int | None = None) -> SiteListing:
        """Every Site, following Datto's pagination to the end.

        Datto answers `{"pageDetails": {"nextPageUrl": …}, "sites": […]}`,
        250 sites a page at most; reading only the first page silently hid
        every site after it. Only the `page` number is taken from
        `nextPageUrl` — the request always goes to the CONFIGURED origin and
        this path, so the bearer token is never sent to a host named by a
        response body. Stops at `max_pages` (default `MAX_SITE_PAGES`), or
        when the vendor's next page does not advance, with `truncated=True`
        rather than looping.
        """
        max_pages = MAX_SITE_PAGES if max_pages is None else max_pages
        sites: list[dict[str, Any]] = []
        seen: set[str] = set()
        page: int | None = None      # first request: the vendor's default page
        for _ in range(max(1, max_pages)):
            params: dict[str, Any] = {"max": SITES_PAGE_SIZE}
            if page is not None:
                params["page"] = page
            body = self._get("/api/v2/account/sites", what="sites", params=params)
            batch = body.get("sites", [])
            for site in batch if isinstance(batch, list) else []:
                if not isinstance(site, dict):
                    continue
                uid = site.get("uid")
                if isinstance(uid, str) and uid in seen:
                    continue    # a page boundary that shifted mid-drain
                if isinstance(uid, str):
                    seen.add(uid)
                sites.append(site)
            next_page = _next_page_number(body)
            if next_page == _NO_NEXT_PAGE:
                return SiteListing(sites, truncated=False)
            if next_page is None or (page is not None and next_page <= page):
                break           # unusable / not advancing — never spin
            page = next_page
        logger.warning(
            "[datto] site list stopped early after %d site(s): page cap %d "
            "reached, or the vendor's next page was unusable", len(sites), max_pages,
        )
        return SiteListing(sites, truncated=True)

    # ----- The inventory feed: one site's device list -----

    def site_devices(self, site_uid: str, *, max_pages: int = MAX_DEVICE_PAGES) -> "DeviceListing":
        """Every device of ONE site — ONLY `INVENTORY_FIELDS` of each (never a
        UDF), `deviceType` reduced to its category. Pages of `MAX_PAGE_SIZE`
        (250, the vendor's ceiling); only the `page` number is taken from
        `nextPageUrl` and only when it names the configured origin (the
        alerts drain's rule). `truncated` when the page cap stopped it."""
        if not isinstance(site_uid, str) or not _SITE_UID_RE.fullmatch(site_uid):
            raise ValueError("not a Datto site uid")
        path = SITE_DEVICES_PATH.format(quote(site_uid, safe=""))
        devices: list[dict[str, Any]] = []
        seen: set[str] = set()
        page: int | None = None
        for _ in range(max(1, max_pages)):
            params: dict[str, Any] = {"max": MAX_PAGE_SIZE}
            if page is not None:
                params["page"] = page
            body = self._get(path, what="site devices", params=params)
            batch = body.get("devices")
            for item in batch if isinstance(batch, list) else []:
                if not isinstance(item, dict):
                    continue
                kept = {k: item[k] for k in INVENTORY_FIELDS if k in item}
                dtype = kept.get("deviceType")
                kept["deviceType"] = (dtype.get("category") if isinstance(dtype, dict)
                                      else dtype if isinstance(dtype, str) else None)
                uid = kept.get("uid")
                if not isinstance(uid, str) or uid in seen:
                    continue
                seen.add(uid)
                devices.append(kept)
            next_page = _next_page_number(body)
            if next_page == _NO_NEXT_PAGE:
                return DeviceListing(devices, truncated=False)
            if next_page is None or not self._next_page_is_ours(body) or \
                    (page is not None and next_page <= page):
                # A next page we may not follow (another origin, unusable,
                # not advancing): what we have is NOT the whole list.
                return DeviceListing(devices, truncated=True)
            page = next_page
        return DeviceListing(devices, truncated=True)

    # ----- One device (for the "open device in the portal" link) -----

    def get_device_portal(self, device_uid: str) -> dict[str, Any]:
        """`{uid, siteUid, portalUrl}` of one device — and NOTHING else of the
        device object (see DEVICE_PORTAL_FIELDS: never `webRemoteUrl`).

        One GET, on demand only (an operator clicked Open): never call this
        per row or per poll. Raises DattoNotFoundError when Datto does not
        know the uid, ValueError for a uid that is not shaped like one (it is
        never put into a request path)."""
        if not isinstance(device_uid, str) or not _DEVICE_UID_RE.fullmatch(device_uid):
            raise ValueError("not a Datto device uid")
        body = self._get(
            "/api/v2/device/" + quote(device_uid, safe=""), what="device",
        )
        return {name: body.get(name) for name in DEVICE_PORTAL_FIELDS}

    # ----- One device's audit (the inventory poller's serial numbers) -----

    def device_audit(self, device_uid: str) -> dict[str, Optional[str]]:
        """`{"bios.serialNumber", "baseBoard.serialNumber",
        "systemInfo.manufacturer", "systemInfo.model"}` of one device's audit
        (GET /api/v2/audit/device/{uid}) — and NOTHING else of it (see
        AUDIT_FIELDS). A value is a string or None: a missing object, a
        missing field or a value of another type (a list, a number, …) is
        None. An answer that carries NONE of the four keys (whatever their
        values) is not an audit this build can read: DattoAuditShapeError —
        a failed audit, never "no serial". Raises ValueError for a uid that is
        not shaped like one (it is never put into a request path),
        DattoNotFoundError / DattoForbiddenError / DattoThrottledError /
        DattoClientError as every other read."""
        if not isinstance(device_uid, str) or not _DEVICE_UID_RE.fullmatch(device_uid):
            raise ValueError("not a Datto device uid")
        body = self._get(AUDIT_PATH_PREFIX + quote(device_uid, safe=""), what="device audit")
        out: dict[str, Optional[str]] = {}
        named = False
        for obj, field in AUDIT_FIELDS:
            section = body.get(obj)
            named = named or (isinstance(section, dict) and field in section)
            value = section.get(field) if isinstance(section, dict) else None
            out[f"{obj}.{field}"] = value[:AUDIT_VALUE_MAX] if isinstance(value, str) else None
        if not named:
            raise DattoAuditShapeError(
                "Datto device audit answered without any field Athena reads")
        return out

    # ----- One alert (the webhook doorbell's fetch) -----

    def get_alert(
        self, alert_uid: str, *, timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """ONE alert, as GET /api/v2/alert/{uid} answers it — the same object
        shape an open-alerts list entry has, so what a webhook doorbell
        fetches is exactly what the poller would have stored (and the sink
        collapses the two copies).

        The uid must be shaped like one (`is_alert_uid`) or ValueError is
        raised BEFORE anything is sent: it comes from a webhook body, and a
        body must not be able to steer the request path. The answer is
        shape-checked — it has to name the alert that was asked for — and is
        returned verbatim otherwise. Raises DattoNotFoundError when Datto
        does not know the uid, DattoForbiddenError / DattoClientError as
        every other read."""
        if not is_alert_uid(alert_uid):
            raise ValueError("not a Datto alert uid")
        body = self._get(
            ALERT_PATH_PREFIX + quote(alert_uid, safe=""), what="alert",
            timeout_seconds=timeout_seconds,
        )
        answered = body.get("alertUid")
        if not isinstance(answered, str) or answered.lower() != alert_uid.lower():
            raise DattoClientError("Datto alert answered with a different alert")
        return body

    # ----- Alerts pull -----

    _MAX_PAGES = 20

    def fetch_alerts_since(
        self,
        since_iso: str,
        *,
        max_results: int = 500,
    ) -> list[dict[str, Any]]:
        """Pull open alerts, up to `max_results`, following Datto's paging.
        Re-delivery of an alert already stored is harmless — the ingest
        sink is idempotent on (source, payload, vendor timestamp).
        """
        return self._fetch_alert_list(ALERTS_PATH, since_iso, max_results=max_results)

    def fetch_resolved_alerts_since(
        self,
        since_iso: str,
        *,
        max_results: int = 500,
    ) -> list[dict[str, Any]]:
        """N0: alerts RESOLVED since `since_iso` — read-only, the same query
        and paging rules as the open list (the poller's backstop)."""
        return self._fetch_alert_list(RESOLVED_ALERTS_PATH, since_iso,
                                      max_results=max_results)

    def _fetch_alert_list(
        self, path: str, since_iso: str, *, max_results: int,
    ) -> list[dict[str, Any]]:
        page_size = max(1, min(int(max_results), MAX_PAGE_SIZE))
        alerts: list[dict[str, Any]] = []
        page: int | None = None      # first request: the vendor's default page
        for _ in range(self._MAX_PAGES):
            params = _alerts_query(since_iso, page_size)
            if page is not None:
                params["page"] = page
            body = self._get(path, what="alerts", params=params)
            batch = body.get("alerts", [])
            alerts.extend(a for a in (batch if isinstance(batch, list) else [])
                          if isinstance(a, dict))
            if len(alerts) >= max_results:
                break
            # Same rule as the site drain: only the `page` NUMBER is taken from
            # nextPageUrl and the request goes to the configured origin — and a
            # link naming any other origin is not followed at all.
            if not self._next_page_is_ours(body):
                break
            next_page = _next_page_number(body)
            if next_page is None or next_page <= (page or 0):
                break           # no next page / unusable / not advancing
            page = next_page
        return alerts[:max_results]

    def _next_page_is_ours(self, body: dict[str, Any]) -> bool:
        details = body.get("pageDetails")
        next_url = details.get("nextPageUrl") if isinstance(details, dict) else None
        base = self._config.api_url.rstrip("/")
        return isinstance(next_url, str) and next_url.startswith(base + "/")
