"""The ONE rate limiter every UniFi call goes through.

`api.ui.com` (the Site Manager API and its connector proxy to each console)
returns no rate-limit headers (verified live 2026-10-01); the live probes
paced themselves at about one call a second without a refusal. So Athena
never bursts:

  * SPACING — at least `min_spacing_sec` (default 1.0 s, never below 1.0 s)
    between the START of any two calls made with one API key, process-wide:
    the poller (fleet, system log, clients, networks), Test connection and
    the mapping panel's discovery share `limiter_for(api_key)` (the registry
    holds a hash of the key, never the key).
  * STRICT PRIORITY with aging — security first (system log: IPS, rogue AP,
    admin, WAN), then the client snapshots entity resolution needs, then the
    fleet poll, then discovery and the daily network read. A waiting ticket
    moves up one level per `aging_slots` × spacing, so nothing starves.
  * THROTTLE — HTTP 429 is "throttled": every caller backs off together,
    15 s doubling to a 10-minute cap (a `Retry-After` the vendor sends is
    honoured when longer), reset by the next success. 401 / 403 are auth
    answers, never a throttle.

A caller that must not wait long (an API request) passes `max_wait_sec`: it
is refused at once (`LimiterBusy`) rather than hold a request thread.

Time is injectable (`clock`, `wait`) so tests run on a fake clock without
real sleeps.
"""
from __future__ import annotations

import hashlib
import itertools
import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional

PRIORITY_SECURITY = 0      # system log (signals + lease boundaries)
PRIORITY_CLIENTS = 1       # client snapshots (entity resolution)
PRIORITY_FLEET = 2         # /v1/hosts + /v1/sites every 5 minutes
PRIORITY_DISCOVERY = 3     # discovery, Test connection, daily networks

PRIORITY_NAMES = {
    PRIORITY_SECURITY: "security",
    PRIORITY_CLIENTS: "clients",
    PRIORITY_FLEET: "fleet",
    PRIORITY_DISCOVERY: "discovery",
}

DEFAULT_MIN_SPACING_SEC = 1.0
MIN_SPACING_FLOOR_SEC = 1.0
MAX_SPACING_SEC = 30.0
THROTTLE_BACKOFF_BASE_SEC = 15.0
THROTTLE_BACKOFF_CEILING_SEC = 600.0
DEFAULT_AGING_SLOTS = 4.0


def bounded_spacing(value: object) -> float:
    """DEFAULT when unusable, never below the 1 s floor (a config typo must
    not make Athena burst), never above 30 s."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_MIN_SPACING_SEC
    if math.isnan(number):
        return DEFAULT_MIN_SPACING_SEC
    return max(MIN_SPACING_FLOOR_SEC, min(MAX_SPACING_SEC, number))


class LimiterBusy(Exception):
    """The slot could not be granted within the caller's `max_wait_sec`."""

    def __init__(self, retry_in_sec: float, *, throttled: bool) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        self.throttled = throttled
        why = "UniFi is rate limiting Athena" if throttled else "other UniFi calls are queued"
        super().__init__(f"{why}; retry in {int(math.ceil(self.retry_in_sec))} s")


class LimiterAborted(Exception):
    """The caller's abort event was set while it waited (a poller stopping)."""


@dataclass(frozen=True)
class Grant:
    at: float
    priority: int


@dataclass(frozen=True)
class _Ticket:
    priority: int
    seq: int
    since: float


def _default_wait(cond: threading.Condition, timeout: Optional[float]) -> None:
    cond.wait(timeout)


class UniFiRateLimiter:
    def __init__(
        self,
        *,
        min_spacing_sec: float = DEFAULT_MIN_SPACING_SEC,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[threading.Condition, Optional[float]], None] = _default_wait,
        history: int = 2000,
        aging_slots: float = DEFAULT_AGING_SLOTS,
    ) -> None:
        self._spacing = bounded_spacing(min_spacing_sec)
        self._aging_slots = max(0.0, float(aging_slots))
        self._clock = clock
        self._wait = wait
        self._cond = threading.Condition()
        self._waiting: list[_Ticket] = []
        self._seq = itertools.count()
        self._next_at = -math.inf
        self._blocked_until = -math.inf
        self._throttle_failures = 0
        self._grants: deque[Grant] = deque(maxlen=history)
        self.throttle_events = 0

    @property
    def min_spacing_sec(self) -> float:
        return self._spacing

    def set_min_spacing(self, value: object) -> None:
        with self._cond:
            self._spacing = bounded_spacing(value)

    def grants(self) -> list[Grant]:
        with self._cond:
            return list(self._grants)

    def now(self) -> float:
        return self._clock()

    def throttled_for(self) -> float:
        with self._cond:
            return max(0.0, self._blocked_until - self._clock())

    def poke(self) -> None:
        with self._cond:
            self._cond.notify_all()

    def _effective(self, ticket: _Ticket, now: float) -> int:
        aging = self._aging_slots * self._spacing
        if aging <= 0:
            return ticket.priority
        steps = int(max(0.0, now - ticket.since) // aging)
        return max(PRIORITY_SECURITY, ticket.priority - steps)

    def acquire(
        self,
        priority: int,
        *,
        max_wait_sec: Optional[float] = None,
        abort: Optional[threading.Event] = None,
    ) -> Grant:
        """Block until this caller may start ONE call."""
        with self._cond:
            ticket = _Ticket(int(priority), next(self._seq), self._clock())
            self._waiting.append(ticket)
            deadline = None if max_wait_sec is None else self._clock() + max(0.0, max_wait_sec)
            try:
                while True:
                    if abort is not None and abort.is_set():
                        raise LimiterAborted()
                    now = self._clock()
                    ready_at = max(self._next_at, self._blocked_until)
                    order = sorted(self._waiting, key=lambda t: (self._effective(t, now), t.seq))
                    at_head = order[0] is ticket
                    if at_head and now >= ready_at:
                        self._waiting.remove(ticket)
                        self._next_at = now + self._spacing
                        grant = Grant(at=now, priority=int(priority))
                        self._grants.append(grant)
                        self._cond.notify_all()
                        return grant
                    if deadline is not None:
                        if self._blocked_until > now and self._blocked_until > deadline:
                            raise LimiterBusy(self._blocked_until - now, throttled=True)
                        if now >= deadline:
                            ahead = order.index(ticket)
                            raise LimiterBusy(max(0.0, ready_at - now) + ahead * self._spacing,
                                              throttled=False)
                    timeout: Optional[float] = (ready_at - now) if at_head else self._spacing
                    if deadline is not None:
                        timeout = min(timeout, max(0.0, deadline - now))
                    if abort is not None:
                        timeout = min(timeout, 1.0)
                    self._wait(self._cond, max(0.0, timeout))
            finally:
                if ticket in self._waiting:
                    self._waiting.remove(ticket)
                    self._cond.notify_all()

    def success(self) -> None:
        with self._cond:
            self._throttle_failures = 0
            self._cond.notify_all()

    def throttled(self, retry_after_sec: Optional[float] = None) -> float:
        """A 429: start / extend the shared backoff. Returns the seconds
        until calls resume."""
        with self._cond:
            now = self._clock()
            delay = min(THROTTLE_BACKOFF_CEILING_SEC,
                        THROTTLE_BACKOFF_BASE_SEC * (2.0 ** min(self._throttle_failures, 32)))
            if retry_after_sec is not None and math.isfinite(retry_after_sec):
                delay = min(THROTTLE_BACKOFF_CEILING_SEC, max(delay, retry_after_sec))
            self._throttle_failures += 1
            self._blocked_until = max(self._blocked_until, now + delay)
            self.throttle_events += 1
            self._cond.notify_all()
            return self._blocked_until - now


_registry_lock = threading.Lock()
_registry: dict[str, UniFiRateLimiter] = {}


def key_fingerprint(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def limiter_for(api_key: str, *, min_spacing_sec: Optional[float] = None) -> UniFiRateLimiter:
    fp = key_fingerprint(api_key)
    with _registry_lock:
        limiter = _registry.get(fp)
        if limiter is None:
            limiter = UniFiRateLimiter()
            _registry[fp] = limiter
    if min_spacing_sec is not None:
        limiter.set_min_spacing(min_spacing_sec)
    return limiter


def install_limiter(api_key: str, limiter: UniFiRateLimiter) -> UniFiRateLimiter:
    """Tests: make `limiter` THE limiter of `api_key` (a fake clock)."""
    with _registry_lock:
        _registry[key_fingerprint(api_key)] = limiter
    return limiter


def reset_limiters() -> None:
    with _registry_lock:
        _registry.clear()
