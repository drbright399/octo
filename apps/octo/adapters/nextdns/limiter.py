"""The ONE rate limiter every NextDNS call goes through.

NextDNS returns no rate-limit headers. What was observed live (2026-09-30,
read-only): a burst of ~9 calls answered a blanket HTTP 403 — the rate limit
presents as 403, not 429 — while a sweep at one call per 2.5 s made 134 calls
without an error. So Athena never bursts:

  * SPACING — at least `min_spacing_sec` (default 2.0 s, never below 1.0 s)
    between the START of any two calls made with one API key, process-wide.
    The key is the unit NextDNS limits, so the poller, Test connection, the
    mapping panel's discovery and the on-demand investigation search all
    share one limiter (`limiter_for(api_key)`; the registry holds a hash of
    the key, never the key).
  * STRICT PRIORITY — when several callers wait, the next slot goes to the
    most important one: security checks and their log pulls, then an
    analyst's on-demand investigation, then the hourly health / roll-up
    reads, then discovery (profile listing). Equal priority → first come.
    STARVATION GUARD (aging): a waiting ticket moves up one level for every
    `aging_slots` × spacing seconds it has waited (4 s at the default 2 s
    spacing), so a busy poller cannot starve the mapping panel's Reload
    (discovery reaches the top after ~12 s) and an analyst's search cannot
    starve the poller's own health reads. A promoted ticket costs security
    one slot; it never adds a call (the spacing is unchanged).
  * THROTTLE vs AUTH — HTTP 429, or 403 from a key that HAS WORKED (a success
    in this process, or the poller's persisted `key_ok_at` — however long
    ago), is "throttled": every caller backs off together, 15 s doubling to
    a 10-minute cap for as long as it lasts, reset by the next success. 401
    — or 403 from a key that has NEVER worked — is an auth error: the
    limiter does not back off for it (the caller reports it and applies its
    own credential backoff). A regenerated / wrong key answers 401 (verified
    live), so a long 403 run is read as a throttle, never as a dead key.

A caller that must not wait long (an API request) passes `max_wait_sec`: it
is refused at once (`LimiterBusy`, with the wait it would have had) rather
than hold a request thread through a throttle backoff.

Time is injectable (`clock` = a monotonic seconds source, `wait` = how to
block on the condition) so tests run on a fake clock without real sleeps.
"""
from __future__ import annotations

import hashlib
import itertools
import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Literal, Optional

PRIORITY_SECURITY = 0          # security checks + their log pulls
PRIORITY_INVESTIGATION = 1     # an analyst's on-demand logs query
PRIORITY_HEALTH = 2            # hourly status / roll-up, pending checks
PRIORITY_DISCOVERY = 3         # profile listing, Test connection

PRIORITY_NAMES = {
    PRIORITY_SECURITY: "security",
    PRIORITY_INVESTIGATION: "investigation",
    PRIORITY_HEALTH: "health",
    PRIORITY_DISCOVERY: "discovery",
}

DEFAULT_MIN_SPACING_SEC = 2.0
MIN_SPACING_FLOOR_SEC = 1.0
MAX_SPACING_SEC = 60.0
THROTTLE_BACKOFF_BASE_SEC = 15.0
THROTTLE_BACKOFF_CEILING_SEC = 600.0
# A waiting ticket moves up one priority level per this many spacings.
DEFAULT_AGING_SLOTS = 2.0

Refusal = Literal["throttled", "auth"]


def bounded_spacing(value: object) -> float:
    """The spacing to use for a configured value: DEFAULT when unusable,
    never below the 1.0 s floor (a config typo must not make Athena burst),
    never above a minute."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_MIN_SPACING_SEC
    if math.isnan(number):
        return DEFAULT_MIN_SPACING_SEC
    return max(MIN_SPACING_FLOOR_SEC, min(MAX_SPACING_SEC, number))


class LimiterBusy(Exception):
    """The slot could not be granted within the caller's `max_wait_sec`.
    `retry_in_sec` = how long until it could be (for a queue: the calls
    ahead of this one × the spacing, not just the gap to the next slot);
    `throttled` = because of a throttle backoff (rather than a queue)."""

    def __init__(self, retry_in_sec: float, *, throttled: bool) -> None:
        self.retry_in_sec = max(0.0, float(retry_in_sec))
        self.throttled = throttled
        why = "NextDNS is rate limiting Athena" if throttled else "other NextDNS calls are queued"
        super().__init__(f"{why}; retry in {int(math.ceil(self.retry_in_sec))} s")


class LimiterAborted(Exception):
    """The caller's abort event was set while it waited (a poller stopping)."""


@dataclass(frozen=True)
class Grant:
    at: float           # the limiter clock when the call was allowed to start
    priority: int


@dataclass(frozen=True)
class _Ticket:
    priority: int
    seq: int
    since: float        # the limiter clock when it started waiting


def _default_wait(cond: threading.Condition, timeout: Optional[float]) -> None:
    cond.wait(timeout)


class NextDNSRateLimiter:
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
        self._last_success: Optional[float] = None
        self._grants: deque[Grant] = deque(maxlen=history)
        self.throttle_events = 0
        # Every success ever recorded (a serial the poller compares to tell a
        # profile-scoped 403 from a key-wide throttle).
        self.successes = 0

    # ----- configuration / inspection -----

    @property
    def min_spacing_sec(self) -> float:
        return self._spacing

    def set_min_spacing(self, value: object) -> None:
        with self._cond:
            self._spacing = bounded_spacing(value)

    def grants(self) -> list[Grant]:
        """Recent grants, oldest first (bounded) — diagnostics and tests."""
        with self._cond:
            return list(self._grants)

    def waiting(self) -> int:
        with self._cond:
            return len(self._waiting)

    @property
    def aging_sec(self) -> float:
        """Seconds of waiting that move a ticket up one level (0 = never)."""
        return self._aging_slots * self._spacing

    def throttle_failures(self) -> int:
        """Throttle refusals since the last success (the backoff ladder)."""
        with self._cond:
            return self._throttle_failures

    def now(self) -> float:
        """The limiter's clock (monotonic seconds; a fake one in tests)."""
        return self._clock()

    def throttled_for(self) -> float:
        """Seconds left of the current throttle backoff (0 when none)."""
        with self._cond:
            return max(0.0, self._blocked_until - self._clock())

    def ever_worked(self) -> bool:
        with self._cond:
            return self._last_success is not None

    def last_success_age(self) -> Optional[float]:
        with self._cond:
            if self._last_success is None:
                return None
            return max(0.0, self._clock() - self._last_success)

    def poke(self) -> None:
        """Wake every waiter to re-check (a stop request, a test's clock)."""
        with self._cond:
            self._cond.notify_all()

    # ----- the slot -----

    def _effective(self, ticket: _Ticket, now: float) -> int:
        aging = self.aging_sec
        if aging <= 0:
            return ticket.priority
        steps = int(max(0.0, now - ticket.since) // aging)
        return max(PRIORITY_SECURITY, ticket.priority - steps)

    def _ordered(self, now: float) -> list[_Ticket]:
        return sorted(self._waiting, key=lambda t: (self._effective(t, now), t.seq))

    def _next_promotion_in(self, ticket: _Ticket, now: float) -> Optional[float]:
        """Seconds until `ticket` moves up a level (None: it cannot)."""
        aging = self.aging_sec
        if aging <= 0 or self._effective(ticket, now) <= PRIORITY_SECURITY:
            return None
        waited = max(0.0, now - ticket.since)
        return max(0.001, aging - (waited % aging))

    def acquire(
        self,
        priority: int,
        *,
        max_wait_sec: Optional[float] = None,
        abort: Optional[threading.Event] = None,
    ) -> Grant:
        """Block until this caller may start ONE call. Raises LimiterBusy
        when `max_wait_sec` cannot be met, LimiterAborted when `abort` is set
        while waiting."""
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
                    order = self._ordered(now)
                    at_head = order[0] is ticket
                    if at_head and now >= ready_at:
                        self._waiting.remove(ticket)
                        self._next_at = now + self._spacing
                        grant = Grant(at=now, priority=int(priority))
                        self._grants.append(grant)
                        self._cond.notify_all()
                        return grant
                    if deadline is not None:
                        # A throttle backoff that outlasts the caller's patience
                        # is refused NOW — never waited out on a request thread.
                        if self._blocked_until > now and self._blocked_until > deadline:
                            raise LimiterBusy(self._blocked_until - now, throttled=True)
                        if now >= deadline:
                            ahead = order.index(ticket)
                            raise LimiterBusy(
                                max(0.0, ready_at - now) + ahead * self._spacing,
                                throttled=False,
                            )
                    timeout: Optional[float] = (ready_at - now) if at_head else None
                    if not at_head:
                        # Not first: re-check when this ticket is promoted.
                        timeout = self._next_promotion_in(ticket, now)
                    if deadline is not None:
                        left = deadline - now
                        timeout = left if timeout is None else min(timeout, left)
                    if abort is not None:
                        # Re-check the abort flag at least every second.
                        timeout = 1.0 if timeout is None else min(timeout, 1.0)
                    self._wait(self._cond, timeout)
            finally:
                if ticket in self._waiting:
                    self._waiting.remove(ticket)
                    self._cond.notify_all()

    # ----- outcomes -----

    def success(self) -> None:
        with self._cond:
            self._last_success = self._clock()
            self._throttle_failures = 0
            self.successes += 1
            self._cond.notify_all()

    def refusal(self, status: int) -> tuple[Refusal, float]:
        """Classify a refused call and, for a throttle, start / extend the
        shared backoff. Returns (kind, seconds until calls resume)."""
        with self._cond:
            now = self._clock()
            if status == 429 or (status == 403 and self._last_success is not None):
                delay = min(
                    THROTTLE_BACKOFF_CEILING_SEC,
                    THROTTLE_BACKOFF_BASE_SEC * (2.0 ** min(self._throttle_failures, 32)),
                )
                self._throttle_failures += 1
                self._blocked_until = max(self._blocked_until, now + delay)
                self.throttle_events += 1
                self._cond.notify_all()
                return "throttled", self._blocked_until - now
            return "auth", 0.0

    def seed_success_age(self, age_sec: Optional[float]) -> None:
        """After a restart: the key last worked `age_sec` ago (persisted by
        the poller) — however long ago — so a first 403 is read as a
        throttle, not as a rejected key. Never moves a newer success back."""
        if age_sec is None or not math.isfinite(age_sec) or age_sec < 0:
            return
        with self._cond:
            at = self._clock() - age_sec
            if self._last_success is None or at > self._last_success:
                self._last_success = at


# ---------------------------------------------------------------------------
# One limiter per API key, process-wide
# ---------------------------------------------------------------------------

_registry_lock = threading.Lock()
_registry: dict[str, NextDNSRateLimiter] = {}


def key_fingerprint(api_key: str) -> str:
    """What the registry is keyed by — a hash, never the key itself.

    The input is the NextDNS account API key: a long random token NextDNS
    issues (validated as one printable line by the adapter), not a password
    anyone chose — so a fast hash is the right tool. There is no guessable
    input space for a slow KDF to protect, the digest never leaves this
    process's memory, and it is computed for every client built (Test
    connection, each investigation), where argon2 / scrypt would only add
    latency."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def limiter_for(
    api_key: str,
    *,
    min_spacing_sec: Optional[float] = None,
    factory: Optional[Callable[[], NextDNSRateLimiter]] = None,
) -> NextDNSRateLimiter:
    """The shared limiter of `api_key` (created on first use). A configured
    spacing is applied — floored at 1.0 s — to the shared one."""
    fp = key_fingerprint(api_key)
    with _registry_lock:
        limiter = _registry.get(fp)
        if limiter is None:
            limiter = factory() if factory is not None else NextDNSRateLimiter()
            _registry[fp] = limiter
    if min_spacing_sec is not None:
        limiter.set_min_spacing(min_spacing_sec)
    return limiter


def install_limiter(api_key: str, limiter: NextDNSRateLimiter) -> NextDNSRateLimiter:
    """Tests: make `limiter` THE limiter of `api_key` (a fake clock)."""
    with _registry_lock:
        _registry[key_fingerprint(api_key)] = limiter
    return limiter


def reset_limiters() -> None:
    """Tests: forget every limiter."""
    with _registry_lock:
        _registry.clear()
