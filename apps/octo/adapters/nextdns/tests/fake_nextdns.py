"""A fake NextDNS API at the TRANSPORT layer, on a fake clock.

Tests run the REAL NextDNSClient / limiter / NextDNSSourceAdapter /
NextDNSPoller: only the socket is replaced, by mounting this `requests`
transport adapter on the client's own session (the RocketCyber / Datto
model). Nothing here ever touches the network.

FAITHFUL to what the live API answered on 2026-09-30 (read-only key):

  GET /profiles                          {data: [{id, name, fingerprint, role}]}
  GET /profiles/{id}                     {data: {id, name, fingerprint, settings…}}
  GET /profiles/{id}/analytics/status    {data: [{status, queries}]}
  GET …/analytics/status;series          {data: [{status, queries: [ints]}],
      ?from=-21d&interval=3600            meta: {series: {times: [504 hour
                                          stamps], interval: 3600}}}
  GET /profiles/{id}/analytics/reasons   {data: [{id, name, queries}]}
  GET /profiles/{id}/logs                {data: [line…], meta: {pagination:
                                          {cursor}, stream: {id}}}
  a wrong key                            401 (`reject_key_status`)
  a burst (more than `burst_limit` calls  blanket HTTP 403 — the real rate
  inside `burst_window_sec`)             limit presents as 403, not 429

Verified against the live API (read-only) and modelled here:

  analytics/reasons counts EACH reason of a multi-reason blocked query (on
  a busy profile the reason counts summed to roughly twice the number of
  blocked queries over 24 h), so a signal
  reason is never hidden behind a blocklist that also matched — the cheap
  question cannot miss it. This fake counts every reason of an explicit
  line, and the background policy volume under TWO lists by default
  (`policy_overlap`), so sum(reasons) > blocked here as it is live.
  analytics/reasons accepts limit=500 and answers meta.pagination.cursor
  null (the whole list in one page).
  analytics/status for an hour without queries answers an EMPTY data array
  ({data: [], meta: {pagination: {cursor: null}}}) — normal silence
  (`explicit_zero_rows` switches to rows of zeros instead).

ASSUMPTIONS (not observed live; each marked `fixture:` in its message):
unknown query keys → 400; `from` inclusive / `to` exclusive; logs `sort`
asc | desc with an opaque cursor; the series' 504 stamps are clock hours
ENDING with the current (partial) hour (the live alignment was not
observed — the poller only uses buckets that have closed); only
interval=3600 is modelled.

Failure modes a test can switch on: `profile_status[pid]` (every call for
the profile answers that status — a 404 / a profile-scoped 403),
`series_status[pid]` (only its history series answers that status; "*" =
every profile), `series_malformed` (series counts that do not match times),
`profile_timeout` (every call for those profiles times out), `stuck_cursor`
(the logs answer the same page with the same cursor forever), and
`logs_settings[pid]` (the profile's settings.logs, e.g. logging off).

Traffic is modelled per profile as (a) explicit log LINES (the blocks a test
cares about — they count in the analytics too) and (b) background VOLUME per
hour (`rate_per_hour`: default / blocked / allowed queries, the blocked ones
under a policy reason), so a profile can have 23,000 queries a day without
23,000 dicts. `silent_hours` zeroes the volume of given hours (a lapse), `rate_fn` makes
the volume a function of the hour (weekdays vs weekends);
`analytics_lag_sec` hides the newest lines from the analytics only;
`hour_queries(pid, hour)` is what the analytics say for one closed hour (a
test seeds a baseline with it).
"""
from __future__ import annotations

import json
import math
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlsplit

import requests
from requests.adapters import BaseAdapter

from apps.octo.adapters.nextdns.client import NextDNSClient, NextDNSConfig
from apps.octo.adapters.nextdns.limiter import NextDNSRateLimiter, install_limiter

API_HOST = "api.nextdns.io"
# Structurally fake: a marker plus padding, long enough for the redaction
# rules (>= 8 chars, 24+ token-shaped).
API_KEY = "fixture-nd-key-" + "7" * 24
CREDS = {"NEXTDNS_API_KEY": API_KEY}

T0 = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)

PROFILES: tuple[dict[str, Any], ...] = (
    {"id": "abc123", "name": "Acme Corp Office", "fingerprint": "fp0001", "role": "owner"},
    {"id": "abc124", "name": "Acme Corp Warehouse", "fingerprint": "fp0002", "role": "owner"},
    {"id": "def456", "name": "Example Bakery", "fingerprint": "fp0003", "role": "owner"},
    {"id": "tst001", "name": "Test Profile", "fingerprint": "fp0004", "role": "owner"},
    {"id": "per001", "name": "Home Lab", "fingerprint": "fp0005", "role": "editor"},
)


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

    def set(self, when: datetime) -> None:
        with self._lock:
            self._t = max(self._t, (when - self._start).total_seconds())

    def wait(self, cond: threading.Condition, timeout: Optional[float]) -> None:
        """Single-threaded use: the limiter asked to wait `timeout` — let that
        much fake time pass."""
        if timeout is None:
            raise AssertionError("a lone caller was told to wait for another caller")
        self.advance(max(timeout, 0.0))


def iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def hour_of(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def block_line(
    at: datetime, *, domain: str = "c2.bad-example.test", root: Optional[str] = None,
    reason: str = "threat-intelligence-feeds", reason_name: str = "Threat Intelligence Feeds",
    device_id: Optional[str] = "D1A2B3", device_name: str = "alice-laptop",
    client_ip: str = "192.0.2.10", extra_reasons: tuple[tuple[str, str], ...] = (),
    status: str = "blocked",
) -> dict[str, Any]:
    """A blocked log line exactly as GET /logs lists it."""
    return {
        "timestamp": iso(at),
        "domain": domain,
        "root": root or ".".join(domain.split(".")[-2:]),
        "tracker": None,
        "encrypted": True,
        "protocol": "DNS-over-HTTPS",
        "clientIp": client_ip,
        "client": None,
        "device": ({"id": device_id, "name": device_name, "model": "Example Laptop"}
                   if device_id else None),
        "status": status,
        "reasons": [{"id": reason, "name": reason_name},
                    *({"id": r, "name": n} for r, n in extra_reasons)],
    }


@dataclass
class Call:
    path: str
    query: dict[str, str]
    at: float
    status: int = 0


@dataclass
class ProfileTraffic:
    lines: list[dict[str, Any]] = field(default_factory=list)
    # queries per hour by status (policy blocks carry POLICY_REASON)
    rate_per_hour: dict[str, int] = field(default_factory=dict)
    silent_hours: set[datetime] = field(default_factory=set)
    # volume only from this time on (a profile that starts routing later)
    active_from: Optional[datetime] = None
    # per UTC hour-of-day overrides of rate_per_hour (a site that is quiet
    # at night, a printer that wakes up now and then)
    rate_by_hour_of_day: dict[int, dict[str, int]] = field(default_factory=dict)
    # hour start → rates (overrides both of the above when set)
    rate_fn: Optional[Callable[[datetime], dict[str, int]]] = None
    # The devices NextDNS identifies (its apps): device id → {name, model,
    # localIp, client, per_hour, silent_from, silent_until} — what
    # analytics/devices counts per window (fixture: not observed live).
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Client IP → queries per hour — what analytics/ips counts.
    ips_per_hour: dict[str, int] = field(default_factory=dict)

    def rate(self, hour: datetime) -> dict[str, int]:
        if self.rate_fn is not None:
            return self.rate_fn(hour)
        return self.rate_by_hour_of_day.get(hour.hour, self.rate_per_hour)


POLICY_REASON = ("blocklist:oisd", "OISD")
# The policy volume is ALSO on this list (share of it) — NextDNS counts
# each matching reason, so sum(analytics/reasons) > blocked (verified live).
POLICY_OVERLAP: tuple[tuple[str, str, float], ...] = (
    ("blocklist:nextdns-recommended", "NextDNS Ads & Trackers Blocklist", 1.0),
)

_KEYS = {
    "profiles": set(),
    "profile": set(),
    "status": {"from", "to", "limit", "cursor", "device"},
    "series": {"from", "to", "interval", "alignment", "timezone", "device"},
    "reasons": {"from", "to", "limit", "cursor", "device"},
    "logs": {"from", "to", "limit", "cursor", "sort", "status", "device", "search"},
    "devices": {"from", "to", "limit", "cursor"},
    "ips": {"from", "to", "limit", "cursor"},
}


class FakeNextDNSTransport(BaseAdapter):
    def __init__(self, clock: FakeClock) -> None:
        super().__init__()
        self.clock = clock
        self.key = API_KEY
        self.reject_key_status = 401
        self.profiles: list[dict[str, Any]] = [dict(p) for p in PROFILES]
        self.traffic: dict[str, ProfileTraffic] = {}
        self.analytics_lag_sec = 0.0
        self.calls: list[Call] = []
        self.unreachable = False
        self.force_status: Optional[int] = None     # every accepted request
        self.throttle_next = 0                      # next N requests → 403
        self.status_script: list[int] = []          # statuses for the next requests
        # The real limit: more than `burst_limit` calls within
        # `burst_window_sec` answers 403 (observed: ~9 rapid calls).
        self.burst_limit = 8
        self.burst_window_sec = 5.0
        self.min_gap_seen: float = math.inf
        self.reasons_refuse_limit = False
        self.reasons_page_size: Optional[int] = None    # page the reasons list
        self.before_request: Optional[Callable[[str, dict[str, str]], None]] = None
        self.profile_status: dict[str, int] = {}
        self.series_status: dict[str, int] = {}          # pid (or "*") → status
        self.series_malformed = False
        self.profile_timeout: set[str] = set()
        self.stuck_cursor: Optional[str] = None
        self.logs_settings: dict[str, dict[str, Any]] = {}
        self.policy_overlap = POLICY_OVERLAP
        # An hour without queries: an empty data array (default), or one
        # row per status with 0 queries.
        self.explicit_zero_rows = False
        # analytics/devices + /ips (fixture): a status to answer instead
        # (404 = the endpoint does not exist for this key).
        self.devices_status: Optional[int] = None
        self.ips_status: Optional[int] = None
        # fixture: per-profile refusals of the entity reads (pid → status).
        self.devices_status_by_profile: dict[str, int] = {}
        self._burst: list[float] = []

    # -- traffic --

    def of(self, pid: str) -> ProfileTraffic:
        return self.traffic.setdefault(pid, ProfileTraffic())

    def add_lines(self, pid: str, *lines: dict[str, Any]) -> None:
        self.of(pid).lines.extend(lines)

    def set_rate(self, pid: str, *, default: int = 900, blocked: int = 40,
                 allowed: int = 2, active_from: Optional[datetime] = None) -> None:
        t = self.of(pid)
        t.rate_per_hour = {"default": default, "blocked": blocked, "allowed": allowed}
        t.active_from = active_from

    def silence(self, pid: str, *hours: datetime) -> None:
        self.of(pid).silent_hours.update(hour_of(h) for h in hours)

    # -- inspection --

    def paths(self) -> list[str]:
        return [c.path for c in self.calls]

    def calls_for(self, pid: str) -> list[Call]:
        return [c for c in self.calls if c.path.startswith(f"/profiles/{pid}")]

    def gaps(self) -> list[float]:
        at = [c.at for c in self.calls]
        return [b - a for a, b in zip(at, at[1:])]

    # -- analytics model --

    def _volume(self, pid: str, start: datetime, end: datetime) -> dict[str, float]:
        t = self.traffic.get(pid)
        out = {"default": 0.0, "blocked": 0.0, "allowed": 0.0}
        if t is None or not (t.rate_per_hour or t.rate_fn) or end <= start:
            return out
        h = hour_of(start)
        while h < end:
            seg_start, seg_end = max(h, start), min(h + timedelta(hours=1), end)
            if t.active_from is not None:
                seg_start = max(seg_start, t.active_from)
            if seg_end > seg_start and h not in t.silent_hours:
                frac = (seg_end - seg_start).total_seconds() / 3600.0
                rate = t.rate(h)
                for k in out:
                    out[k] += rate.get(k, 0) * frac
            h += timedelta(hours=1)
        return out

    def hour_queries(self, pid: str, hour: datetime) -> dict[str, int]:
        """What analytics/status says for one CLOSED hour: {status: queries}."""
        start = hour_of(hour)
        end = start + timedelta(hours=1)
        counts = {k: int(round(v)) for k, v in self._volume(pid, start, end).items()}
        for line in (self.traffic.get(pid) or ProfileTraffic()).lines:
            if start <= _parse(line["timestamp"]) < end:
                status = line.get("status", "blocked")
                counts[status] = counts.get(status, 0) + 1
        return counts

    def _visible_lines(self, pid: str, start: datetime, end: datetime, *, analytics: bool):
        t = self.traffic.get(pid)
        if t is None:
            return []
        cutoff = self.clock.now() - timedelta(seconds=self.analytics_lag_sec)
        out = []
        for line in t.lines:
            ts = _parse(line["timestamp"])
            if not (start <= ts < end):
                continue
            if analytics and ts > cutoff:
                continue
            if ts > self.clock.now():
                continue            # not happened yet
            out.append(line)
        return out

    # -- requests transport API --

    def send(self, request, **kwargs):  # noqa: ANN001
        for value in request.headers.values():
            if isinstance(value, str):
                value.encode("latin-1")
        parts = urlsplit(request.url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        call = Call(parts.path, query, self.clock.monotonic())
        if self.calls:
            self.min_gap_seen = min(self.min_gap_seen, call.at - self.calls[-1].at)
        self.calls.append(call)
        if self.before_request is not None:
            self.before_request(parts.path, query)
        resp = self._answer(request, parts, query)
        call.status = resp.status_code
        return resp

    def _answer(self, request, parts, query: dict[str, str]) -> requests.Response:  # noqa: ANN001
        if self.unreachable:
            raise requests.ConnectionError("fixture: connection refused")
        if parts.hostname != API_HOST:
            return self._response(request, 200, {"data": []})
        if request.headers.get("X-Api-Key") != self.key:
            return self._response(request, self.reject_key_status,
                                  {"errors": [{"code": "unauthorized"}]})
        now = self.clock.monotonic()
        self._burst = [t for t in self._burst if now - t < self.burst_window_sec] + [now]
        if len(self._burst) > self.burst_limit:
            return self._response(request, 403, {"errors": [{"code": "forbidden"}]})
        if self.status_script:
            status = self.status_script.pop(0)
            if status != 200:
                return self._response(request, status, {"errors": [{"code": "fixture"}]})
        if self.throttle_next > 0:
            self.throttle_next -= 1
            return self._response(request, 403, {"errors": [{"code": "forbidden"}]})
        if self.force_status is not None:
            return self._response(request, self.force_status, {"errors": [{"code": "fixture"}]})
        segs = [s for s in parts.path.split("/") if s]
        if segs == ["profiles"]:
            return self._checked(request, query, "profiles", lambda: {"data": [
                dict(p) for p in self.profiles]})
        if len(segs) >= 2 and segs[0] == "profiles":
            pid = segs[1]
            if pid in self.profile_timeout:
                raise requests.Timeout("fixture: read timed out")
            if pid in self.profile_status:
                return self._response(request, self.profile_status[pid],
                                      {"errors": [{"code": "fixture"}]})
            profile = next((p for p in self.profiles if p["id"] == pid), None)
            if profile is None:
                return self._response(request, 404, {"errors": [{"code": "notFound"}]})
            rest = segs[2:]
            if rest == []:
                logs = self.logs_settings.get(pid, {"enabled": True, "retention": 63072000})
                return self._checked(request, query, "profile", lambda: {"data": {
                    **profile, "settings": {"logs": dict(logs)},
                    "security": {"threatIntelligenceFeeds": True, "cryptojacking": True},
                }})
            if rest == ["analytics", "status"]:
                return self._checked(request, query, "status", lambda: self._status(pid, query))
            if rest == ["analytics", "status;series"]:
                status = self.series_status.get(pid, self.series_status.get("*"))
                if status is not None:
                    return self._response(request, status, {"errors": [{"code": "fixture"}]})
                return self._checked(request, query, "series", lambda: self._series(pid, query))
            if rest == ["analytics", "reasons"]:
                if self.reasons_refuse_limit and "limit" in query:
                    return self._response(request, 400, {"errors": [{"code": "invalid"}]})
                return self._checked(request, query, "reasons", lambda: self._reasons(pid, query))
            if rest == ["logs"]:
                return self._checked(request, query, "logs", lambda: self._logs(pid, query))
            if rest == ["analytics", "devices"]:
                status = self.devices_status_by_profile.get(pid, self.devices_status)
                if status is not None:
                    return self._response(request, status,
                                          {"errors": [{"code": "fixture"}]})
                return self._checked(request, query, "devices", lambda: self._devices(pid, query))
            if rest == ["analytics", "ips"]:
                if self.ips_status is not None:
                    return self._response(request, self.ips_status,
                                          {"errors": [{"code": "fixture"}]})
                return self._checked(request, query, "ips", lambda: self._ips(pid, query))
        return self._response(request, 404, {"errors": [{"code": "notFound"}]})

    def _checked(self, request, query, kind, build):  # noqa: ANN001
        for key in query:
            if key not in _KEYS[kind]:
                return self._response(request, 400, {"errors": [{
                    "code": "invalid", "detail": f"fixture: {key} is not allowed"}]})
        try:
            body = build()
        except ValueError as exc:
            return self._response(request, 400, {"errors": [{"code": "invalid",
                                                             "detail": f"fixture: {exc}"}]})
        return self._response(request, 200, body)

    def _when(self, value: str) -> datetime:
        """An ISO time, or a relative one ("-21d", "-6h") from now."""
        m = re.fullmatch(r"-(\d+)([smhdw])", value)
        if m:
            unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
            return self.clock.now() - timedelta(**{unit[m.group(2)]: int(m.group(1))})
        return _parse(value)

    def _window(self, query: dict[str, str]) -> tuple[datetime, datetime]:
        if "from" not in query:
            raise ValueError("from is required")
        start = self._when(query["from"])
        end = self._when(query["to"]) if "to" in query else self.clock.now()
        return start, end

    def _series(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        """The hourly series: one stamp per clock hour from the one after
        `from` up to the CURRENT (partial) hour — 504 for from=-21d
        (fixture: the live alignment was not observed)."""
        start, _end = self._window(query)
        if query.get("interval") != "3600":
            raise ValueError("fixture: only interval=3600 is modelled")
        now = self.clock.now()
        cutoff = now - timedelta(seconds=self.analytics_lag_sec)
        last = hour_of(now)
        n = max(0, int((last - hour_of(start)).total_seconds() // 3600))
        stamps = [last - timedelta(hours=n - 1 - i) for i in range(n)]
        lines: dict[datetime, dict[str, int]] = {}
        for line in (self.traffic.get(pid) or ProfileTraffic()).lines:
            ts = _parse(line["timestamp"])
            if ts <= cutoff and stamps and stamps[0] <= ts:
                slot = lines.setdefault(hour_of(ts), {})
                status = line.get("status", "blocked")
                slot[status] = slot.get(status, 0) + 1
        series: dict[str, list[int]] = {"default": [], "blocked": [], "allowed": []}
        for h in stamps:
            vol = self._volume(pid, h, min(h + timedelta(hours=1), cutoff))
            extra = lines.get(h, {})
            for status in series:
                series[status].append(int(round(vol.get(status, 0.0))) + extra.get(status, 0))
        data = [{"status": s, "queries": q} for s, q in series.items() if any(q)]
        if self.series_malformed and data:
            data[0]["queries"] = data[0]["queries"][:-1]
        return {"data": data, "meta": {"series": {"times": [iso(h) for h in stamps],
                                                  "interval": 3600},
                                       "pagination": {"cursor": None}}}

    def _status(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        start, end = self._window(query)
        vol = self._volume(pid, start, min(end, self.clock.now()
                                           - timedelta(seconds=self.analytics_lag_sec)))
        counts = {k: int(round(v)) for k, v in vol.items()}
        for line in self._visible_lines(pid, start, end, analytics=True):
            counts[line.get("status", "blocked")] = counts.get(line.get("status", "blocked"), 0) + 1
        meta = {"pagination": {"cursor": None}}
        if self.explicit_zero_rows:
            return {"data": [{"status": s, "queries": n} for s, n in counts.items()],
                    "meta": meta}
        return {"data": [{"status": s, "queries": n} for s, n in counts.items() if n > 0],
                "meta": meta}

    def _reasons(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        start, end = self._window(query)
        vol = self._volume(pid, start, min(end, self.clock.now()
                                           - timedelta(seconds=self.analytics_lag_sec)))
        rows: dict[str, list] = {}
        if int(round(vol["blocked"])):
            rows[POLICY_REASON[0]] = [POLICY_REASON[1], int(round(vol["blocked"]))]
            # Multi-reason attribution (verified live): the same policy
            # blocks counted again under every other list they match.
            for rid, name, share in self.policy_overlap:
                if int(round(vol["blocked"] * share)):
                    rows[rid] = [name, int(round(vol["blocked"] * share))]
        for line in self._visible_lines(pid, start, end, analytics=True):
            if line.get("status") != "blocked":
                continue
            for r in line.get("reasons") or []:
                entry = rows.setdefault(r["id"], [r.get("name") or r["id"], 0])
                entry[1] += 1
        data = sorted(({"id": k, "name": v[0], "queries": v[1]} for k, v in rows.items()),
                      key=lambda x: -x["queries"])
        size = int(query["limit"]) if "limit" in query else (self.reasons_page_size or 10)
        offset = int(query.get("cursor", "0") or 0)
        page = data[offset: offset + size]
        cursor = str(offset + size) if offset + size < len(data) else None
        return {"data": page, "meta": {"pagination": {"cursor": cursor}}}

    def _device_hours(self, dev: dict[str, Any], start: datetime, end: datetime) -> float:
        total = 0.0
        h = hour_of(start)
        while h < end:
            seg_start, seg_end = max(h, start), min(h + timedelta(hours=1), end)
            silent_from, silent_until = dev.get("silent_from"), dev.get("silent_until")
            silent = silent_from is not None and h >= hour_of(silent_from) and \
                (silent_until is None or h < silent_until)
            if seg_end > seg_start and not silent and (dev.get("active_from") is None
                                                       or h >= dev["active_from"]):
                total += dev.get("per_hour", 0) * (seg_end - seg_start).total_seconds() / 3600.0
            h += timedelta(hours=1)
        return total

    def _devices(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        start, end = self._window(query)
        end = min(end, self.clock.now())
        t = self.traffic.get(pid) or ProfileTraffic()
        counts: dict[str, dict[str, Any]] = {}
        for did, dev in t.devices.items():
            q = int(round(self._device_hours(dev, start, end)))
            counts[did] = {"id": did, "name": dev.get("name"), "model": dev.get("model"),
                           "localIp": dev.get("localIp"), "queries": q}
        for line in self._visible_lines(pid, start, end, analytics=True):
            d = line.get("device") or {}
            if d.get("id"):
                entry = counts.setdefault(d["id"], {"id": d["id"], "name": d.get("name"),
                                                    "model": d.get("model"), "queries": 0})
                entry["queries"] += 1
        data = [v for v in counts.values() if v["queries"] > 0]
        vol = self._volume(pid, start, end)
        unidentified = int(round(sum(vol.values())))
        if unidentified:
            data.append({"id": "__UNIDENTIFIED__", "name": None, "queries": unidentified})
        data.sort(key=lambda x: -x["queries"])
        return {"data": data, "meta": {"pagination": {"cursor": None}}}

    def _ips(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        start, end = self._window(query)
        end = min(end, self.clock.now())
        t = self.traffic.get(pid) or ProfileTraffic()
        hours = max(0.0, (end - start).total_seconds() / 3600.0)
        data = [{"ip": ip, "queries": int(round(rate * hours)),
                 "network": {"isp": "Example ISP"}} for ip, rate in t.ips_per_hour.items()]
        for line in self._visible_lines(pid, start, end, analytics=True):
            ip = line.get("clientIp")
            entry = next((x for x in data if x["ip"] == ip), None)
            if entry is None:
                data.append({"ip": ip, "queries": 1})
            else:
                entry["queries"] += 1
        data = [x for x in data if x["queries"] > 0]
        return {"data": data, "meta": {"pagination": {"cursor": None}}}

    def _logs(self, pid: str, query: dict[str, str]) -> dict[str, Any]:
        start, end = self._window(query)
        status = query.get("status")
        rows = [
            line for line in self._visible_lines(pid, start, end, analytics=False)
            if status is None or line.get("status") == status
        ]
        if "device" in query:
            rows = [r for r in rows if (r.get("device") or {}).get("id") == query["device"]]
        if "search" in query:
            rows = [r for r in rows if query["search"] in (r.get("domain") or "")]
        rows.sort(key=lambda r: r["timestamp"], reverse=query.get("sort", "desc") == "desc")
        limit = int(query.get("limit", "100"))
        if not 10 <= limit <= 1000:
            raise ValueError("limit must be between 10 and 1000")
        if self.stuck_cursor is not None:
            # A broken cursor: the first page again, the same cursor, forever.
            return {"data": [dict(r) for r in rows[:limit]],
                    "meta": {"pagination": {"cursor": self.stuck_cursor},
                             "stream": {"id": "fixture"}}}
        offset = int(query.get("cursor", "0") or 0)
        page = rows[offset: offset + limit]
        cursor = str(offset + limit) if offset + limit < len(rows) else None
        return {"data": [dict(r) for r in page],
                "meta": {"pagination": {"cursor": cursor}, "stream": {"id": "fixture"}}}

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


def fake_limiter(clock: FakeClock, *, spacing: float = 2.0, key: str = API_KEY) -> NextDNSRateLimiter:
    """A limiter on the fake clock, installed as THE limiter of `key`."""
    limiter = NextDNSRateLimiter(min_spacing_sec=spacing, clock=clock.monotonic,
                                 wait=clock.wait)
    return install_limiter(key, limiter)


def real_client(transport: FakeNextDNSTransport, config: Optional[NextDNSConfig] = None,
                limiter: Optional[NextDNSRateLimiter] = None) -> NextDNSClient:
    """A REAL NextDNSClient whose session talks to `transport`."""
    client = NextDNSClient(config or NextDNSConfig(api_key=API_KEY), limiter=limiter)
    client._session.mount("https://", transport)
    client._session.mount("http://", transport)
    return client


def client_factory(transport: FakeNextDNSTransport):
    return lambda config: real_client(transport, config)


def nextdns_adapter_class(transport: FakeNextDNSTransport, clock: Optional[FakeClock] = None):
    """The real adapter as the framework instantiates it (`cls()`), wired to
    `transport` (and the fake clock, when given)."""
    from apps.octo.adapters.nextdns import NextDNSSourceAdapter

    class _TransportNextDNS(NextDNSSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=client_factory(transport),
                             now=clock.now if clock is not None else None)

    _TransportNextDNS.__module__ = "apps.octo.adapters.nextdns"
    return _TransportNextDNS
