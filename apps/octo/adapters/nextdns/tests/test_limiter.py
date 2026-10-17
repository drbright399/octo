"""The shared limiter on a FAKE clock (no real sleeps): spacing and its
floor, strict priority, 403-as-throttle vs auth, the backoff ladder, the
fail-fast for request threads, and one limiter per key (by hash)."""
from __future__ import annotations

import threading

import pytest

from apps.octo.adapters.nextdns import limiter as lim
from apps.octo.adapters.nextdns.limiter import (
    PRIORITY_DISCOVERY,
    PRIORITY_HEALTH,
    PRIORITY_INVESTIGATION,
    PRIORITY_SECURITY,
    LimiterAborted,
    LimiterBusy,
    NextDNSRateLimiter,
)
from apps.octo.adapters.nextdns.tests.fake_nextdns import FakeClock


@pytest.fixture(autouse=True)
def _fresh_registry():
    lim.reset_limiters()
    yield
    lim.reset_limiters()


def _limiter(clock: FakeClock, spacing: float = 2.0) -> NextDNSRateLimiter:
    return NextDNSRateLimiter(min_spacing_sec=spacing, clock=clock.monotonic, wait=clock.wait)


def test_calls_are_spaced_by_at_least_the_minimum():
    clock = FakeClock()
    limiter = _limiter(clock)
    for _ in range(10):
        limiter.acquire(PRIORITY_SECURITY)
    at = [g.at for g in limiter.grants()]
    assert at[0] == 0.0
    assert all(b - a >= 2.0 for a, b in zip(at, at[1:]))
    assert at[-1] == pytest.approx(18.0)


def test_a_call_after_a_pause_is_not_delayed():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.acquire(PRIORITY_SECURITY)
    clock.advance(30)
    limiter.acquire(PRIORITY_HEALTH)
    assert [g.at for g in limiter.grants()] == [0.0, 30.0]


@pytest.mark.parametrize("configured,effective", [
    (0.2, 1.0), (0.0, 1.0), (-5, 1.0), ("nan", 2.0), ("junk", 2.0), (None, 2.0),
    (1.0, 1.0), (2.5, 2.5), (600, 60.0),
])
def test_spacing_is_never_below_one_second(configured, effective):
    assert lim.bounded_spacing(configured) == effective
    assert NextDNSRateLimiter(min_spacing_sec=configured).min_spacing_sec == effective


def test_strict_priority_between_concurrent_waiters():
    """A discovery call queued FIRST still goes after a security check that
    arrives while both wait — each on its own thread, on the fake clock."""
    clock = FakeClock()
    limiter = NextDNSRateLimiter(
        min_spacing_sec=2.0, clock=clock.monotonic,
        wait=lambda cond, timeout: cond.wait(0.01),   # re-check the fake clock
    )
    limiter.acquire(PRIORITY_SECURITY)                # t=0: the next slot is t=2
    order: list[int] = []

    def call(priority: int) -> None:
        limiter.acquire(priority)
        order.append(priority)

    def until(pred) -> None:
        done = threading.Event()
        for _ in range(2000):
            if pred():
                return
            done.wait(0.001)
        raise AssertionError("waiter did not register")

    threads = []
    for priority in (PRIORITY_DISCOVERY, PRIORITY_HEALTH, PRIORITY_INVESTIGATION,
                     PRIORITY_SECURITY):
        t = threading.Thread(target=call, args=(priority,))
        t.start()
        threads.append(t)
        until(lambda n=len(threads): limiter.waiting() == n)
    for step in range(4):
        clock.advance(2.0)
        until(lambda s=step: len(order) == s + 1)
    for t in threads:
        t.join(timeout=5)
    assert order == [PRIORITY_SECURITY, PRIORITY_INVESTIGATION, PRIORITY_HEALTH,
                     PRIORITY_DISCOVERY]
    at = [g.at for g in limiter.grants()]
    assert at == [0.0, 2.0, 4.0, 6.0, 8.0]


def test_403_after_a_success_is_a_throttle_with_a_doubling_backoff():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.acquire(PRIORITY_SECURITY)
    limiter.success()
    delays = []
    for _ in range(8):
        kind, delay = limiter.refusal(403)
        assert kind == "throttled"
        delays.append(round(delay))
        clock.advance(delay)
    assert delays == [15, 30, 60, 120, 240, 480, 600, 600]
    # Every caller waits out the backoff — never a burst behind it.
    kind, delay = limiter.refusal(403)
    before = clock.monotonic()
    limiter.acquire(PRIORITY_SECURITY)
    assert limiter.grants()[-1].at >= before + delay
    limiter.success()                                 # resets the ladder
    assert limiter.refusal(429) == ("throttled", 15.0)


def test_403_from_a_key_that_never_worked_is_an_auth_error():
    clock = FakeClock()
    limiter = _limiter(clock)
    assert limiter.refusal(403) == ("auth", 0.0)
    assert limiter.throttled_for() == 0.0


def test_403_long_after_the_last_success_is_still_a_throttle_at_the_cap():
    """A key that has worked is never re-classified as rejected by a long
    run of 403s (NextDNS answers a wrong / regenerated key with 401): the
    throttle stays at its 10-minute cap for as long as it lasts, and every
    caller keeps backing off."""
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.success()
    elapsed = 0.0
    while elapsed < 5 * 3600:
        kind, delay = limiter.refusal(403)
        assert kind == "throttled"
        assert delay <= 600.0
        clock.advance(delay)
        elapsed += delay
    assert limiter.refusal(403) == ("throttled", 600.0)
    assert limiter.throttled_for() == 600.0


def test_401_is_always_auth_and_429_always_a_throttle():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.success()
    assert limiter.refusal(401) == ("auth", 0.0)
    assert limiter.refusal(429)[0] == "throttled"


def test_a_restart_seeds_the_last_success():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.seed_success_age(600)                     # worked 10 minutes ago
    assert limiter.refusal(403)[0] == "throttled"
    fresh = _limiter(clock)
    fresh.seed_success_age(3 * 86400)                 # three days ago: still a key that worked
    assert fresh.refusal(403)[0] == "throttled"
    never = _limiter(clock)
    for bad in (None, -1, float("nan")):
        never.seed_success_age(bad)
    assert never.refusal(403) == ("auth", 0.0)


def test_a_request_thread_is_refused_at_once_during_a_long_backoff():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.success()
    limiter.refusal(403)                              # 15 s
    with pytest.raises(LimiterBusy) as exc:
        limiter.acquire(PRIORITY_INVESTIGATION, max_wait_sec=5)
    assert exc.value.throttled and exc.value.retry_in_sec == pytest.approx(15)
    assert clock.monotonic() == 0.0                   # refused without waiting
    # A wait that fits is waited.
    limiter.acquire(PRIORITY_INVESTIGATION, max_wait_sec=20)
    assert clock.monotonic() == pytest.approx(15)


def test_abort_stops_a_waiter():
    clock = FakeClock()
    limiter = _limiter(clock)
    limiter.acquire(PRIORITY_SECURITY)
    stop = threading.Event()
    stop.set()
    with pytest.raises(LimiterAborted):
        limiter.acquire(PRIORITY_SECURITY, abort=stop)
    assert limiter.waiting() == 0


def test_one_limiter_per_key_keyed_by_hash():
    a = lim.limiter_for("fixture-key-one-" + "1" * 20)
    b = lim.limiter_for("fixture-key-one-" + "1" * 20, min_spacing_sec=0.1)
    c = lim.limiter_for("fixture-key-two-" + "2" * 20)
    assert a is b and a is not c
    assert a.min_spacing_sec == 1.0                   # the configured 0.1 floored
    assert all("fixture" not in k for k in lim._registry)   # hashes only


# ---------------------------------------------------------------------------
# Starvation guard (fix round 2026-09-30)
# ---------------------------------------------------------------------------

def _busy_world(clock: FakeClock):
    """A limiter whose waiters re-check the fake clock, and a helper that
    lets fake time pass while threads compete."""
    limiter = NextDNSRateLimiter(
        min_spacing_sec=2.0, clock=clock.monotonic,
        wait=lambda cond, timeout: cond.wait(0.002),
    )
    return limiter


def _run_busy_poller(limiter, priority, stop: threading.Event, granted: list) -> threading.Thread:
    """A poller-like caller: asks for its next slot the moment it got one."""
    def loop():
        while not stop.is_set():
            try:
                limiter.acquire(priority, abort=stop)
            except LimiterAborted:
                return
            granted.append(priority)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def _advance_until(clock: FakeClock, pred, *, step: float = 0.5, limit: float = 120.0) -> float:
    waited = 0.0
    tick = threading.Event()
    while not pred() and waited < limit:
        clock.advance(step)
        waited += step
        tick.wait(0.003)
    return waited


def test_a_busy_poller_cannot_starve_discovery_or_a_search():
    """The poller always has a security call waiting; a discovery call (the
    panel's Reload, 20 s patience) and an analyst's page (30 s) still get a
    slot — aging moves them up one level per 2 spacings."""
    clock = FakeClock()
    limiter = _busy_world(clock)
    stop = threading.Event()
    granted: list[int] = []
    poller = _run_busy_poller(limiter, PRIORITY_SECURITY, stop, granted)
    try:
        _advance_until(clock, lambda: len(granted) >= 3)
        outcome: dict = {}

        def reload_list():
            try:
                outcome["grant"] = limiter.acquire(PRIORITY_DISCOVERY, max_wait_sec=20.0)
            except LimiterBusy as exc:
                outcome["busy"] = exc
        t = threading.Thread(target=reload_list, daemon=True)
        start = clock.monotonic()
        t.start()
        _advance_until(clock, lambda: outcome)
        t.join(timeout=5)
        assert "grant" in outcome, outcome
        assert outcome["grant"].at - start <= 16.0
        # Strict priority still holds while nothing has waited long: the
        # poller got every other slot.
        assert granted.count(PRIORITY_SECURITY) >= 3
    finally:
        stop.set()
        limiter.poke()
        poller.join(timeout=5)


def test_a_looping_search_cannot_starve_the_pollers_health_reads():
    clock = FakeClock()
    limiter = _busy_world(clock)
    stop = threading.Event()
    granted: list[int] = []
    searcher = _run_busy_poller(limiter, PRIORITY_INVESTIGATION, stop, granted)
    try:
        _advance_until(clock, lambda: len(granted) >= 2)
        got: dict = {}

        def health():
            got["grant"] = limiter.acquire(PRIORITY_HEALTH)
        t = threading.Thread(target=health, daemon=True)
        start = clock.monotonic()
        t.start()
        _advance_until(clock, lambda: got)
        t.join(timeout=5)
        assert got["grant"].at - start <= 10.0
    finally:
        stop.set()
        limiter.poke()
        searcher.join(timeout=5)


def test_a_refusal_says_how_long_the_queue_ahead_really_is():
    clock = FakeClock()
    limiter = _busy_world(clock)
    limiter.acquire(PRIORITY_SECURITY)                 # t=0; the next slot is t=2
    stop = threading.Event()
    waiters = []
    for _ in range(3):
        th = threading.Thread(target=lambda: limiter.acquire(PRIORITY_SECURITY, abort=stop),
                              daemon=True)
        th.start()
        waiters.append(th)
    for _ in range(2000):
        if limiter.waiting() == 3:
            break
        threading.Event().wait(0.001)
    try:
        with pytest.raises(LimiterBusy) as exc:
            limiter.acquire(PRIORITY_DISCOVERY, max_wait_sec=0.0)
        assert not exc.value.throttled
        assert exc.value.retry_in_sec >= 2.0 + 3 * 2.0   # the gap + three calls ahead
    finally:
        stop.set()
        limiter.poke()
        clock.advance(100)
        for th in waiters:
            th.join(timeout=5)


def test_successes_are_counted_for_the_poller():
    limiter = _limiter(FakeClock())
    assert limiter.successes == 0 and not limiter.ever_worked()
    limiter.success()
    limiter.success()
    assert limiter.successes == 2 and limiter.ever_worked()
