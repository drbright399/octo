"""NextDNS API client — READ-ONLY, every call through the shared limiter.

Built against the live API (verified read-only 2026-09-30):

  GET /profiles
      {data: [{id (6 chars), name, fingerprint, role: owner|editor}]}
  GET /profiles/{id}
      {data: {id, name, fingerprint, settings, security, privacy, …}}
  GET /profiles/{id}/analytics/status?from=&to=
      {data: [{status: default|blocked|allowed, queries}]}; an hour without
      queries answers {data: [], meta: {pagination: {cursor: null}}}
  GET /profiles/{id}/analytics/status;series?from=-21d&interval=3600
      {data: [{status, queries: [504 ints]}], meta: {series: {times: [504
      ISO hour stamps], interval: 3600}}} — three weeks of hourly history in
      ONE call (the baseline seed)
  GET /profiles/{id}/analytics/reasons?from=&to=[&limit=&cursor=]
      {data: [{id, name, queries}], meta?: {pagination: {cursor}}} — the
      blocked-reason aggregates. EVERY reason of a multi-reason block is
      counted (verified: reason counts exceed blocked-query counts by roughly
      2x), so a signal reason is never hidden behind a blocklist that
      matched too; limit=500 is accepted and the cursor comes back null (one
      page)
  GET /profiles/{id}/analytics/devices?from=&to=[&limit=&cursor=]
      {data: [{id, name, model, localIp, queries}]} — the devices NextDNS
      identified (its apps, DoH names). NOT verified live: read tolerantly
      (the entity feed; a refusal falls back to sampling one log page)
  GET /profiles/{id}/analytics/ips?from=&to=[&limit=&cursor=]
      {data: [{ip, network, geo, queries}]} — NOT verified live; only `ip` and
      `queries` are read (the entity feed's L-EGRESS statistic)
  GET /profiles/{id}/logs?status=blocked&from=&to=&limit=&sort=[&cursor=]
      {data: [line…], meta: {pagination: {cursor}, stream: {id}}}; a line:
      timestamp (ISO ms Z), domain, root, tracker, encrypted, protocol,
      clientIp, client, device {id, name, model}, status, reasons [{id, name}].
      NO server-side filter by reason (only status / device / search (domain
      substring) / from / to / limit / cursor / sort).

`from` / `to` accept ISO 8601 (sent as canonical UTC ms) or relative values;
analytics may lag a few minutes (the poller overlaps its windows).

Auth: `X-Api-Key: <key>` to the configured origin only; redirects are never
followed. The key never appears in an exception message, a log line, a
health detail or an audit row: every message here is static text + status
codes + exception CLASS names (+ scrubbed, bounded vendor text).

Statuses (the limiter decides between throttled and auth for 403):
  200            success (the limiter records the key as working)
  401            NextDNSAuthError
  403            NextDNSThrottledError once the key has ever worked (in this
                 process, or per the poller's persisted mark), else
                 NextDNSAuthError
  429            NextDNSThrottledError
  404            NextDNSNotFoundError (unknown profile)
  3xx / other    NextDNSClientError
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

import requests

from apps.octo.adapters.nextdns.limiter import (
    DEFAULT_MIN_SPACING_SEC,
    PRIORITY_DISCOVERY,
    PRIORITY_HEALTH,
    PRIORITY_SECURITY,
    LimiterAborted,
    LimiterBusy,
    NextDNSRateLimiter,
    limiter_for,
)
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://api.nextdns.io"
PORTAL_URL = "https://my.nextdns.io"

# Profile ids are short alphanumerics ("abc123"). Nothing else is ever put
# into a request path.
PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")
MAX_PROFILES = 2_000
MAX_LOG_PAGE = 1000
# Reasons: ask for everything in one page (accepted live, cursor null);
# follow a cursor if one ever comes back.
REASONS_LIMIT = 500
MAX_REASON_PAGES = 5
MAX_VENDOR_ERROR_CHARS = 160
# A time series longer than this is refused (3 weeks hourly = 504 points).
MAX_SERIES_POINTS = 2_000


class NextDNSClientError(Exception):
    """Transport / protocol error talking to NextDNS (operator-safe text)."""


class NextDNSAuthError(Exception):
    """NextDNS rejected the API key (401, or 403 from a key that has never
    worked). `status` = the HTTP status."""

    def __init__(self, message: str, status: Optional[int] = None) -> None:
        self.status = status
        super().__init__(message)


class NextDNSThrottledError(NextDNSClientError):
    """NextDNS is rate limiting (429, or 403 from a key that has worked), or
    the shared limiter refused to wait that long. `retry_in_sec` = when calls
    resume; `status` = the HTTP status NextDNS answered (None when the
    limiter refused before any request)."""

    def __init__(self, message: str, retry_in_sec: float,
                 status: Optional[int] = None) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        self.status = status
        super().__init__(message)


class NextDNSBusyError(NextDNSClientError):
    """The shared limiter could not start the call within the caller's wait
    (other NextDNS calls queued ahead of it)."""

    def __init__(self, message: str, retry_in_sec: float) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        super().__init__(message)


class NextDNSNotFoundError(NextDNSClientError):
    """HTTP 404 — the profile does not exist (or not for this key)."""


class NextDNSAborted(NextDNSClientError):
    """The caller stopped while waiting for its slot."""


@dataclass(frozen=True)
class NextDNSConfig:
    api_key: str
    api_url: str = DEFAULT_API_URL
    verify_tls: bool = True
    timeout_seconds: float = 15.0
    min_spacing_sec: float = DEFAULT_MIN_SPACING_SEC


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    role: str = ""


@dataclass(frozen=True)
class LogPage:
    lines: list[dict[str, Any]]
    cursor: Optional[str]


_URL_LIKE_RE = re.compile(r"(?i)(?:\b[a-z][a-z0-9+.\-]*://|\bwww\.)\S*")
_TOKEN_SHAPED_RE = re.compile(r"[A-Za-z0-9_\-.=+/]{24,}")


def _scrub(text: Any, secrets: Iterable[str] = ()) -> str:
    """Vendor text made operator-safe: secrets and token-shaped runs
    redacted, links removed, flattened, bounded."""
    if not isinstance(text, str):
        return ""
    for secret in secrets:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[redacted]")
    text = _URL_LIKE_RE.sub("[link removed]", text)
    text = _TOKEN_SHAPED_RE.sub("[redacted]", text)
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    if len(text) > MAX_VENDOR_ERROR_CHARS:
        text = text[: MAX_VENDOR_ERROR_CHARS - 1].rstrip() + "…"
    return text


def _safe_origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return "the NextDNS API"
    if not parts.scheme or not host:
        return "the NextDNS API"
    return f"{parts.scheme}://{host}{port}"


def valid_profile_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and PROFILE_ID_RE.fullmatch(value):
        return value
    return None


def iso(value: datetime | str) -> str:
    """A window bound as NextDNS takes it: canonical UTC ms."""
    return value if isinstance(value, str) else format_utc_ms(value)


def _cursor(body: dict[str, Any]) -> Optional[str]:
    meta = body.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    cursor = pagination.get("cursor") if isinstance(pagination, dict) else None
    if isinstance(cursor, str) and cursor and len(cursor) <= 2048 and cursor.isprintable():
        return cursor
    return None


class NextDNSClient:
    def __init__(
        self,
        config: NextDNSConfig,
        *,
        limiter: Optional[NextDNSRateLimiter] = None,
        abort: Optional[threading.Event] = None,
    ) -> None:
        self._config = config
        self._base = config.api_url.rstrip("/")
        self._limiter = limiter or limiter_for(
            config.api_key, min_spacing_sec=config.min_spacing_sec,
        )
        self._abort = abort
        self._session = requests.Session()
        # Analytics `limit` is sent; if this API ever refuses it (HTTP 400),
        # the client falls back to the default page + cursor once.
        self._reasons_limit_ok = True
        self.calls = 0
        if not config.verify_tls:
            self._session.verify = False  # type: ignore[assignment]

    @property
    def limiter(self) -> NextDNSRateLimiter:
        return self._limiter

    def set_abort(self, abort: threading.Event) -> None:
        """A poller's stop flag: a call waiting for its slot gives up when set."""
        self._abort = abort

    @property
    def origin(self) -> str:
        return _safe_origin(self._base)

    def _secrets(self) -> tuple[str, ...]:
        return (self._config.api_key,) if self._config.api_key else ()

    # ----- one GET -----

    def _get(
        self,
        path: str,
        *,
        what: str,
        priority: int,
        params: Optional[dict[str, Any]] = None,
        max_wait_sec: Optional[float] = None,
    ) -> dict[str, Any]:
        try:
            self._limiter.acquire(priority, max_wait_sec=max_wait_sec, abort=self._abort)
        except LimiterBusy as exc:
            if exc.throttled:
                raise NextDNSThrottledError(
                    "NextDNS is rate limiting Athena's requests; calls resume in "
                    f"{int(exc.retry_in_sec + 0.999)} s", exc.retry_in_sec,
                ) from None
            raise NextDNSBusyError(
                "Other NextDNS requests are queued ahead of this one; try again in "
                f"{int(exc.retry_in_sec + 0.999)} s", exc.retry_in_sec,
            ) from None
        except LimiterAborted:
            raise NextDNSAborted("stopped while waiting to call NextDNS") from None
        url = self._base + path
        self.calls += 1
        try:
            r = self._session.get(
                url,
                headers={"X-Api-Key": self._config.api_key, "Accept": "application/json"},
                params=params,
                timeout=self._config.timeout_seconds,
                # A 3xx would send the key to whatever host it names.
                allow_redirects=False,
            )
        except (requests.RequestException, ValueError) as exc:
            # `from None`: requests' InvalidHeader carries the full header
            # value — the key — in its message.
            raise NextDNSClientError(
                f"NextDNS unreachable at {_safe_origin(url)}: {type(exc).__name__}"
            ) from None
        status = r.status_code
        if status == 200:
            try:
                body = r.json()
            except ValueError:
                raise NextDNSClientError(
                    f"NextDNS {what} returned a body that is not JSON"
                ) from None
            if not isinstance(body, dict):
                raise NextDNSClientError(f"NextDNS {what} returned JSON that is not an object")
            self._limiter.success()
            return body
        if status in (401, 403, 429):
            kind, retry_in = self._limiter.refusal(status)
            if kind == "throttled":
                raise NextDNSThrottledError(
                    f"NextDNS is rate limiting Athena's requests (HTTP {status} on "
                    f"{what}); every NextDNS call waits {int(retry_in + 0.999)} s",
                    retry_in, status,
                )
            raise NextDNSAuthError(
                f"NextDNS rejected the API key (HTTP {status} on {what})", status)
        if status == 404:
            raise NextDNSNotFoundError(f"NextDNS answered HTTP 404 for {what}")
        if 300 <= status < 400:
            raise NextDNSClientError(
                f"NextDNS {what} answered with a redirect (HTTP {status}); redirects "
                "are never followed"
            )
        said = ""
        try:
            data = r.json()
            errors = data.get("errors") if isinstance(data, dict) else None
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                said = _scrub(errors[0].get("code") or errors[0].get("detail"), self._secrets())
        except ValueError:
            said = ""
        raise NextDNSClientError(
            f"NextDNS {what} returned HTTP {status}" + (f" ({said})" if said else "")
        )

    def _profile_path(self, profile_id: str, suffix: str = "") -> str:
        pid = valid_profile_id(profile_id)
        if pid is None:
            raise NextDNSClientError("refused to request an invalid NextDNS profile id")
        return f"/profiles/{pid}{suffix}"

    # ----- profiles -----

    def list_profiles(
        self, *, priority: int = PRIORITY_DISCOVERY, max_wait_sec: Optional[float] = None,
    ) -> list[Profile]:
        """Every profile the key sees — ONE call. Ids that could never be a
        path segment are dropped (and logged by count)."""
        body = self._get("/profiles", what="profile list", priority=priority,
                         max_wait_sec=max_wait_sec)
        data = body.get("data")
        if not isinstance(data, list):
            raise NextDNSClientError("NextDNS profile list answered without a data list")
        out: list[Profile] = []
        seen: set[str] = set()
        dropped = 0
        for item in data[: MAX_PROFILES * 2]:
            if not isinstance(item, dict):
                dropped += 1
                continue
            pid = valid_profile_id(item.get("id"))
            if pid is None or pid in seen:
                dropped += 1
                continue
            seen.add(pid)
            name = item.get("name")
            role = item.get("role")
            out.append(Profile(
                id=pid,
                name=name.strip() if isinstance(name, str) else "",
                role=role if isinstance(role, str) and len(role) <= 16 else "",
            ))
            if len(out) >= MAX_PROFILES:
                break
        if dropped:
            logger.warning("[nextdns] %d profile entr(ies) without a usable id ignored", dropped)
        return out

    def profile_logs(
        self, profile_id: str, *, priority: int = PRIORITY_HEALTH,
        max_wait_sec: Optional[float] = None,
    ) -> tuple[Optional[bool], Optional[int]]:
        """(logs enabled, retention in seconds) from GET /profiles/{id}
        `settings.logs` — None where the answer does not say. NextDNS
        analytics follow the profile's logging: logging off = no analytics,
        and a short retention shortens every window Athena can read."""
        body = self._get(self._profile_path(profile_id), what="profile settings",
                         priority=priority, max_wait_sec=max_wait_sec)
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}
        logs = settings.get("logs") if isinstance(settings.get("logs"), dict) else {}
        enabled = logs.get("enabled")
        retention = logs.get("retention")
        return (
            enabled if isinstance(enabled, bool) else None,
            retention if isinstance(retention, int) and not isinstance(retention, bool)
            and retention > 0 else None,
        )

    # ----- analytics -----

    def analytics_status(
        self, profile_id: str, *, from_: datetime | str, to: datetime | str | None = None,
        priority: int = PRIORITY_HEALTH, max_wait_sec: Optional[float] = None,
    ) -> dict[str, int]:
        """{status: queries} for the window (default / blocked / allowed)."""
        params: dict[str, Any] = {"from": iso(from_)}
        if to is not None:
            params["to"] = iso(to)
        body = self._get(self._profile_path(profile_id, "/analytics/status"),
                         what="analytics (status)", priority=priority, params=params,
                         max_wait_sec=max_wait_sec)
        data = body.get("data")
        if not isinstance(data, list):
            raise NextDNSClientError("NextDNS analytics (status) answered without a data list")
        out: dict[str, int] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            status = item.get("status")
            queries = item.get("queries")
            if not isinstance(status, str) or isinstance(queries, bool) or not isinstance(queries, int):
                continue
            if queries < 0:
                continue
            key = status.strip().lower()[:32]
            out[key] = out.get(key, 0) + queries
        return out

    def analytics_status_series(
        self, profile_id: str, *, from_: datetime | str = "-21d", interval: int = 3600,
        priority: int = PRIORITY_HEALTH, max_wait_sec: Optional[float] = None,
    ) -> list[tuple[datetime, int]]:
        """The profile's query history as a time series — ONE call:
        analytics/status;series (verified live with from=-21d&interval=3600:
        504 hourly buckets). Returns [(bucket start, queries of every
        status)], oldest first. An answer that is not a well-formed series
        (times or counts missing, lengths that differ, a count that is not a
        non-negative integer, another interval) is a NextDNSClientError —
        never a guess."""
        params: dict[str, Any] = {"from": iso(from_), "interval": int(interval)}
        body = self._get(self._profile_path(profile_id, "/analytics/status;series"),
                         what="analytics (status series)", priority=priority, params=params,
                         max_wait_sec=max_wait_sec)
        meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
        series = meta.get("series") if isinstance(meta.get("series"), dict) else {}
        times, data = series.get("times"), body.get("data")
        bad = "NextDNS analytics (status series) answered "
        if not isinstance(times, list) or not isinstance(data, list):
            raise NextDNSClientError(bad + "without its time series")
        if len(times) > MAX_SERIES_POINTS:
            raise NextDNSClientError(bad + f"more than {MAX_SERIES_POINTS} points")
        answered = series.get("interval")
        if answered is not None and answered != int(interval):
            raise NextDNSClientError(bad + "with another interval")
        starts: list[datetime] = []
        for value in times:
            canonical = normalize_timestamp(value, naive_is_utc=True) if isinstance(value, str) else ""
            if not canonical:
                raise NextDNSClientError(bad + "a time that is not a timestamp")
            starts.append(datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ")
                          .replace(tzinfo=timezone.utc))
        totals = [0] * len(starts)
        for item in data:
            counts = item.get("queries") if isinstance(item, dict) else None
            if not isinstance(counts, list) or len(counts) != len(starts):
                raise NextDNSClientError(bad + "counts that do not match its times")
            for i, q in enumerate(counts):
                if isinstance(q, bool) or not isinstance(q, int) or q < 0:
                    raise NextDNSClientError(bad + "a count that is not a number of queries")
                totals[i] += q
        return list(zip(starts, totals))

    def analytics_reasons(
        self, profile_id: str, *, from_: datetime | str, to: datetime | str | None = None,
        priority: int = PRIORITY_SECURITY, max_wait_sec: Optional[float] = None,
    ) -> dict[str, tuple[str, int]]:
        """{reason id: (name, blocked queries)} for the window. Asks for
        everything in one page (`limit`), following a cursor if the vendor
        returns one; a vendor that refuses `limit` (HTTP 400) is asked again
        without it, once per client."""
        params: dict[str, Any] = {"from": iso(from_)}
        if to is not None:
            params["to"] = iso(to)
        path = self._profile_path(profile_id, "/analytics/reasons")
        out: dict[str, tuple[str, int]] = {}
        cursor: Optional[str] = None
        for _page in range(MAX_REASON_PAGES):
            query = dict(params)
            if self._reasons_limit_ok:
                query["limit"] = REASONS_LIMIT
            if cursor:
                query["cursor"] = cursor
            try:
                body = self._get(path, what="analytics (reasons)", priority=priority,
                                 params=query, max_wait_sec=max_wait_sec)
            except NextDNSClientError as exc:
                if self._reasons_limit_ok and "HTTP 400" in str(exc):
                    self._reasons_limit_ok = False
                    logger.warning(
                        "[nextdns] analytics (reasons) refused the page-size parameter; "
                        "reading the default page and following its cursor instead",
                    )
                    continue
                raise
            data = body.get("data")
            if not isinstance(data, list):
                raise NextDNSClientError(
                    "NextDNS analytics (reasons) answered without a data list")
            for item in data:
                if not isinstance(item, dict):
                    continue
                rid = item.get("id")
                queries = item.get("queries")
                if not isinstance(rid, str) or not rid.strip() or len(rid) > 128:
                    continue
                if isinstance(queries, bool) or not isinstance(queries, int) or queries < 0:
                    continue
                name = item.get("name")
                prior = out.get(rid, ("", 0))
                out[rid] = (
                    name.strip()[:96] if isinstance(name, str) and name.strip() else prior[0],
                    prior[1] + queries,
                )
            cursor = _cursor(body)
            if not cursor:
                break
        return out

    def _analytics_list(
        self, profile_id: str, suffix: str, what: str, *, from_: datetime | str,
        to: datetime | str, priority: int, max_wait_sec: Optional[float],
        max_pages: int = 3,
    ) -> list[dict[str, Any]]:
        path = self._profile_path(profile_id, suffix)
        out: list[dict[str, Any]] = []
        cursor: Optional[str] = None
        for _page in range(max_pages):
            params: dict[str, Any] = {"from": iso(from_), "to": iso(to), "limit": 500}
            if cursor:
                params["cursor"] = cursor
            body = self._get(path, what=what, priority=priority, params=params,
                             max_wait_sec=max_wait_sec)
            data = body.get("data")
            if not isinstance(data, list):
                raise NextDNSClientError(f"NextDNS {what} answered without a data list")
            out.extend(x for x in data if isinstance(x, dict))
            cursor = _cursor(body)
            if not cursor:
                break
        return out

    def analytics_devices(
        self, profile_id: str, *, from_: datetime | str, to: datetime | str,
        priority: int = PRIORITY_HEALTH, max_wait_sec: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """[{id, name, model, local_ip, queries}] — every device NextDNS
        identified in the window, bounded and cleaned (the unidentified
        traffic's pseudo-device is left out)."""
        out = []
        for item in self._analytics_list(profile_id, "/analytics/devices", "analytics (devices)",
                                         from_=from_, to=to, priority=priority,
                                         max_wait_sec=max_wait_sec):
            did = item.get("id")
            queries = item.get("queries")
            if not isinstance(did, str) or not did.strip() or did.startswith("__"):
                continue
            if isinstance(queries, bool) or not isinstance(queries, int) or queries < 0:
                continue
            out.append({
                "id": did.strip()[:64],
                "name": _scrub(item.get("name"))[:120] or None,
                "model": _scrub(item.get("model"))[:80] or None,
                "local_ip": item.get("localIp") if isinstance(item.get("localIp"), str)
                and len(item.get("localIp")) <= 45 else None,
                "queries": queries,
            })
        return out

    def analytics_ips(
        self, profile_id: str, *, from_: datetime | str, to: datetime | str,
        priority: int = PRIORITY_HEALTH, max_wait_sec: Optional[float] = None,
    ) -> list[tuple[str, int]]:
        """[(client ip, queries)] for the window."""
        out = []
        for item in self._analytics_list(profile_id, "/analytics/ips", "analytics (ips)",
                                         from_=from_, to=to, priority=priority,
                                         max_wait_sec=max_wait_sec):
            ip = item.get("ip")
            queries = item.get("queries")
            if not isinstance(ip, str) or len(ip) > 45:
                continue
            if isinstance(queries, bool) or not isinstance(queries, int) or queries < 0:
                continue
            out.append((ip.strip(), queries))
        return out

    # ----- logs -----

    def logs(
        self,
        profile_id: str,
        *,
        from_: datetime | str,
        to: datetime | str,
        status: Optional[str] = "blocked",
        limit: int = MAX_LOG_PAGE,
        cursor: Optional[str] = None,
        sort: str = "asc",
        device: Optional[str] = None,
        search: Optional[str] = None,
        priority: int = PRIORITY_SECURITY,
        max_wait_sec: Optional[float] = None,
    ) -> LogPage:
        """ONE page of the profile's query log, oldest first by default."""
        params: dict[str, Any] = {
            "from": iso(from_), "to": iso(to),
            "limit": max(10, min(int(limit), MAX_LOG_PAGE)),
            "sort": "desc" if sort == "desc" else "asc",
        }
        if status:
            if status not in ("default", "blocked", "allowed", "error"):
                raise ValueError(f"unknown log status filter {status!r}")
            params["status"] = status
        if cursor:
            params["cursor"] = cursor
        if device:
            params["device"] = device
        if search:
            params["search"] = search
        body = self._get(self._profile_path(profile_id, "/logs"), what="logs",
                         priority=priority, params=params, max_wait_sec=max_wait_sec)
        data = body.get("data")
        if not isinstance(data, list):
            raise NextDNSClientError("NextDNS logs answered without a data list")
        return LogPage([x for x in data if isinstance(x, dict)], _cursor(body))

    # ----- the connection check -----

    def check_access(self, *, max_wait_sec: Optional[float] = 20.0) -> tuple[bool, str, int]:
        """Test connection: ONE call (the profile list) — never one per
        profile. Returns (ok, operator-safe detail, profile count)."""
        try:
            profiles = self.list_profiles(max_wait_sec=max_wait_sec)
        except NextDNSAuthError as exc:
            return False, (
                f"{exc}. Check that the key was copied whole from my.nextdns.io → "
                "Account → API and has not been regenerated."
            ), 0
        except NextDNSThrottledError as exc:
            return False, (
                f"{exc}. NextDNS answers a burst of requests with HTTP 403; wait a "
                "minute and test again."
            ), 0
        except NextDNSClientError as exc:
            return False, f"Could not read from NextDNS: {exc}", 0
        owners = sum(1 for p in profiles if p.role == "owner")
        editors = sum(1 for p in profiles if p.role == "editor")
        roles = f" ({owners} owned, {editors} shared with you)" if owners or editors else ""
        return True, (
            f"NextDNS reachable and the API key works: {len(profiles)} profile(s){roles}. "
            "Nothing is polled until you map profiles to tenants; unmapped profiles "
            "are never polled."
        ), len(profiles)
