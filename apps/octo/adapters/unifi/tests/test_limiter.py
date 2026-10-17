"""The ONE limiter: spacing (never below 1 s), strict priority with aging,
the shared 429 backoff, busy refusals — on a fake clock, no real sleeps."""
from __future__ import annotations

import threading

import pytest

from apps.octo.adapters.unifi.limiter import (
    PRIORITY_CLIENTS,
    PRIORITY_DISCOVERY,
    PRIORITY_FLEET,
    PRIORITY_SECURITY,
    LimiterAborted,
    LimiterBusy,
    UniFiRateLimiter,
    bounded_spacing,
    install_limiter,
    limiter_for,
    reset_limiters,
)
from apps.octo.adapters.unifi.tests.fake_unifi import FakeClock


def _limiter(clock: FakeClock, spacing: float = 1.0) -> UniFiRateLimiter:
    return UniFiRateLimiter(min_spacing_sec=spacing, clock=clock.monotonic, wait=clock.wait)


def test_spacing_is_never_below_one_second():
    assert bounded_spacing(0.1) == 1.0 and bounded_spacing("x") == 1.0
    assert bounded_spacing(float("nan")) == 1.0 and bounded_spacing(999) == 30.0
    clock = FakeClock()
    lim = _limiter(clock, spacing=0.01)
    at = [lim.acquire(PRIORITY_SECURITY).at for _ in range(5)]
    assert [b - a for a, b in zip(at, at[1:])] == [1.0] * 4


def test_strict_priority_with_aging():
    """The order the slot is granted in, decided deterministically (the
    limiter's own ordering on its own clock): security, clients, fleet,
    discovery — first come within a level — and a ticket that has waited
    `aging_slots` × spacing moves up a level, so discovery is never starved."""
    from apps.octo.adapters.unifi.limiter import _Ticket

    clock = FakeClock()
    lim = UniFiRateLimiter(min_spacing_sec=1.0, clock=clock.monotonic, wait=clock.wait,
                           aging_slots=4)
    tickets = [_Ticket(PRIORITY_DISCOVERY, 0, 0.0), _Ticket(PRIORITY_FLEET, 1, 0.0),
               _Ticket(PRIORITY_CLIENTS, 2, 0.0), _Ticket(PRIORITY_SECURITY, 3, 0.0),
               _Ticket(PRIORITY_SECURITY, 4, 0.0)]

    def order(now: float) -> list[int]:
        return [t.seq for t in sorted(tickets, key=lambda t: (lim._effective(t, now), t.seq))]  # noqa: SLF001

    assert order(0.0) == [3, 4, 2, 1, 0]
    # After 12 s of waiting discovery has climbed three levels: it is served
    # with security, by arrival.
    assert lim._effective(tickets[0], 12.0) == PRIORITY_SECURITY  # noqa: SLF001
    assert order(12.0) == [0, 1, 2, 3, 4]


def test_a_429_backs_every_caller_off_and_a_success_resets_the_ladder():
    clock = FakeClock()
    lim = _limiter(clock)
    assert lim.throttled() == 15.0
    assert lim.throttled() == 30.0
    assert lim.throttled(retry_after_sec=120) == 120.0
    grant = lim.acquire(PRIORITY_SECURITY)
    assert grant.at >= 120.0                              # waited the backoff out
    lim.success()
    assert lim.throttled() == 15.0
    assert lim.throttled(retry_after_sec=10_000) <= 600.0   # capped


def test_a_caller_that_cannot_wait_is_refused_at_once():
    clock = FakeClock()
    lim = _limiter(clock)
    lim.throttled()
    with pytest.raises(LimiterBusy) as e:
        lim.acquire(PRIORITY_DISCOVERY, max_wait_sec=5)
    assert e.value.throttled and e.value.retry_in_sec == pytest.approx(15.0)
    abort = threading.Event()
    abort.set()
    with pytest.raises(LimiterAborted):
        lim.acquire(PRIORITY_SECURITY, abort=abort)


def test_one_limiter_per_key_by_fingerprint():
    reset_limiters()
    a = limiter_for("fixture-key-one-" + "1" * 24)
    assert limiter_for("fixture-key-one-" + "1" * 24) is a
    assert limiter_for("fixture-key-two-" + "2" * 24) is not a
    mine = install_limiter("fixture-key-one-" + "1" * 24, _limiter(FakeClock()))
    assert limiter_for("fixture-key-one-" + "1" * 24) is mine
    reset_limiters()
