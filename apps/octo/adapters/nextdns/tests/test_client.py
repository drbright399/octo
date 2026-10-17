"""The REAL NextDNSClient against the fake transport (fake clock): the
request shapes, parsing, paging, the status → error mapping (403 as a
throttle only after the key worked), and that the key never leaks into an
error message."""
from __future__ import annotations

from datetime import timedelta

import pytest

from apps.octo.adapters.nextdns import limiter as lim
from apps.octo.adapters.nextdns.client import (
    NextDNSAuthError,
    NextDNSClientError,
    NextDNSConfig,
    NextDNSNotFoundError,
    NextDNSThrottledError,
    valid_profile_id,
)
from apps.octo.adapters.nextdns.limiter import PRIORITY_INVESTIGATION
from apps.octo.adapters.nextdns.tests.fake_nextdns import (
    API_KEY,
    T0,
    FakeClock,
    FakeNextDNSTransport,
    block_line,
    fake_limiter,
    real_client,
)


@pytest.fixture
def world():
    lim.reset_limiters()
    clock = FakeClock()
    transport = FakeNextDNSTransport(clock)
    limiter = fake_limiter(clock)
    client = real_client(transport, limiter=limiter)
    clock.advance(3600)
    yield clock, transport, client
    lim.reset_limiters()


def test_profiles_one_call_with_the_key_header(world):
    clock, transport, client = world
    profiles = client.list_profiles()
    assert [p.id for p in profiles] == ["abc123", "abc124", "def456", "tst001", "per001"]
    assert profiles[0].name == "Acme Corp Office" and profiles[4].role == "editor"
    assert transport.paths() == ["/profiles"]


def test_profile_ids_that_are_not_path_safe_are_dropped_and_never_requested(world):
    clock, transport, client = world
    transport.profiles.append({"id": "../x", "name": "bad"})
    transport.profiles.append({"id": "", "name": "blank"})
    assert "../x" not in {p.id for p in client.list_profiles()}
    with pytest.raises(NextDNSClientError):
        client.analytics_status("../../etc", from_=clock.now())
    assert valid_profile_id("abc123") == "abc123"
    assert valid_profile_id("a b") is None
    assert len(transport.calls) == 1


def test_status_and_reasons_windows(world):
    clock, transport, client = world
    transport.set_rate("abc123", default=900, blocked=40, allowed=2)
    transport.add_lines("abc123", block_line(clock.now() - timedelta(minutes=5)))
    status = client.analytics_status("abc123", from_=clock.now() - timedelta(hours=1),
                                     to=clock.now())
    assert status == {"default": 900, "blocked": 41, "allowed": 2}
    reasons = client.analytics_reasons("abc123", from_=clock.now() - timedelta(hours=1),
                                       to=clock.now())
    # Every reason of a multi-reason block counts (verified live): the 40
    # policy blocks are on two lists, so the reasons add up to more than
    # the 41 blocked queries.
    assert reasons == {"blocklist:oisd": ("OISD", 40),
                       "blocklist:nextdns-recommended": ("NextDNS Ads & Trackers Blocklist", 40),
                       "threat-intelligence-feeds": ("Threat Intelligence Feeds", 1)}
    assert sum(n for _name, n in reasons.values()) > status["blocked"]
    q = transport.calls[-1].query
    assert q["from"] == "2026-09-30T12:00:00.000Z" and q["to"] == "2026-09-30T13:00:00.000Z"
    # limit=500 is accepted live and the whole list comes in one page.
    assert q["limit"] == "500" and len(transport.calls) == 2


def test_reasons_without_the_limit_parameter_follow_the_cursor(world):
    """If NextDNS ever refuses `limit` (400), the client asks again without it
    and follows the cursor, so a rare signal reason beyond the default page
    is never cut off."""
    clock, transport, client = world
    transport.reasons_refuse_limit = True
    transport.reasons_page_size = 2
    for i, rid in enumerate(("blocklist:oisd", "tld:cn", "denylist", "nrd", "dga")):
        transport.add_lines("abc123", *[
            block_line(clock.now() - timedelta(minutes=10, seconds=n), reason=rid, reason_name=rid)
            for n in range(10 - i)
        ])
    reasons = client.analytics_reasons("abc123", from_=clock.now() - timedelta(hours=1),
                                       to=clock.now())
    assert set(reasons) == {"blocklist:oisd", "tld:cn", "denylist", "nrd", "dga"}
    assert reasons["dga"] == ("dga", 6)
    statuses = [c.status for c in transport.calls]
    assert statuses[0] == 400 and all(s == 200 for s in statuses[1:])


def test_the_history_series_is_one_call_and_a_malformed_one_is_refused(world):
    """analytics/status;series (from=-21d, hourly — verified live: 504 hour
    stamps): every status summed per bucket, oldest first; a series whose
    counts do not match its times is an error, never a guess."""
    clock, transport, client = world
    transport.set_rate("abc123", default=100, blocked=5, allowed=1)
    transport.silence("abc123", clock.now() - timedelta(hours=5))
    points = client.analytics_status_series("abc123")
    assert transport.paths() == ["/profiles/abc123/analytics/status;series"]
    assert transport.calls[0].query == {"from": "-21d", "interval": "3600"}
    assert len(points) == 504
    starts = [p[0] for p in points]
    assert starts == sorted(starts) and starts[-1] <= clock.now()
    by_hour = dict(points)
    assert by_hour[starts[-2]] == 106
    assert by_hour[clock.now().replace(minute=0, second=0, microsecond=0)
                   - timedelta(hours=5)] == 0
    transport.series_malformed = True
    with pytest.raises(NextDNSClientError, match="counts that do not match"):
        client.analytics_status_series("abc123")


def test_a_baseline_seed_keeps_two_bitmasks_of_closed_hours_not_the_series():
    from datetime import datetime, timezone

    from apps.octo.adapters.nextdns.poller import make_seed, unpack_hours

    now = datetime(2026, 9, 30, 12, 30, tzinfo=timezone.utc)
    first = now.replace(minute=0) - timedelta(hours=503)
    points = []
    for i in range(504):
        start = first + timedelta(hours=i)
        # Nothing for 3 days (not routing yet), then 5 an hour, 40 by day.
        q = 0 if i < 72 else (40 if 13 <= start.hour <= 20 else 5)
        points.append((start, q))
    seed = make_seed(points, now)
    assert seed["from"] == (first + timedelta(hours=72)).strftime("%Y-%m-%dT%H:00:00Z")
    # The current (partial) hour is not used.
    assert seed["to"] == (now.replace(minute=0) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:00:00Z")
    busy = unpack_hours(seed["busy"], 22 * 24)
    seen = unpack_hours(seed["seen"], 22 * 24)
    assert len(seen) == 504 - 72 - 1 and all(13 <= int(h[11:13]) <= 20 for h in busy)
    assert seed["peak24"] == 8 * 40 + 16 * 5
    assert not any(isinstance(v, list) for v in seed.values())
    assert make_seed([(first, 0), (first + timedelta(hours=1), 0)], now)["from"] is None


def test_logs_page_by_cursor_oldest_first(world):
    clock, transport, client = world
    base = clock.now() - timedelta(minutes=30)
    transport.add_lines("abc123", *[block_line(base + timedelta(seconds=i)) for i in range(25)])
    page = client.logs("abc123", from_=base, to=clock.now(), limit=10)
    assert len(page.lines) == 10 and page.cursor
    assert page.lines[0]["timestamp"] < page.lines[-1]["timestamp"]
    second = client.logs("abc123", from_=base, to=clock.now(), limit=10, cursor=page.cursor)
    third = client.logs("abc123", from_=base, to=clock.now(), limit=10, cursor=second.cursor)
    assert third.cursor is None and len(third.lines) == 5
    q = transport.calls[0].query
    assert q["status"] == "blocked" and q["sort"] == "asc"


def test_401_is_auth(world):
    clock, transport, client = world
    transport.key = "fixture-other-key"
    with pytest.raises(NextDNSAuthError) as exc:
        client.list_profiles()
    assert "401" in str(exc.value) and API_KEY not in str(exc.value)


def test_403_before_any_success_is_auth_after_a_success_a_throttle(world):
    clock, transport, client = world
    transport.throttle_next = 1
    with pytest.raises(NextDNSAuthError):
        client.list_profiles()
    client.list_profiles()                           # the key works
    transport.throttle_next = 1
    with pytest.raises(NextDNSThrottledError) as exc:
        client.list_profiles()
    assert exc.value.retry_in_sec == pytest.approx(15)
    # The next call waits the backoff out (fake clock) — no burst.
    before = clock.monotonic()
    client.list_profiles()
    assert transport.calls[-1].at >= before + 15 - 0.001


def test_a_request_thread_is_refused_during_the_backoff(world):
    clock, transport, client = world
    client.list_profiles()
    transport.throttle_next = 1
    with pytest.raises(NextDNSThrottledError):
        client.list_profiles()
    n = len(transport.calls)
    with pytest.raises(NextDNSThrottledError) as exc:
        client.logs("abc123", from_=clock.now() - timedelta(hours=1), to=clock.now(),
                    priority=PRIORITY_INVESTIGATION, max_wait_sec=5)
    assert "resume" in str(exc.value)
    assert len(transport.calls) == n                 # nothing was sent


def test_404_and_other_statuses(world):
    clock, transport, client = world
    with pytest.raises(NextDNSNotFoundError):
        client.analytics_status("zzz999", from_=clock.now() - timedelta(hours=1))
    transport.force_status = 500
    with pytest.raises(NextDNSClientError) as exc:
        client.list_profiles()
    assert "HTTP 500" in str(exc.value)
    transport.force_status = 302
    with pytest.raises(NextDNSClientError) as exc:
        client.list_profiles()
    assert "redirect" in str(exc.value)


def test_unreachable_never_carries_the_key(world):
    clock, transport, client = world
    transport.unreachable = True
    with pytest.raises(NextDNSClientError) as exc:
        client.list_profiles()
    assert API_KEY not in str(exc.value) and exc.value.__cause__ is None


def test_check_access_is_one_call(world):
    clock, transport, client = world
    ok, detail, count = client.check_access()
    assert ok and count == 5 and "5 profile(s)" in detail
    assert transport.paths() == ["/profiles"]
    transport.key = "fixture-other-key"
    ok, detail, _ = client.check_access()
    assert not ok and API_KEY not in detail


def test_a_burst_would_be_refused_but_the_client_never_bursts(world):
    """The fake answers >8 calls in 5 s with 403 like the real API; the
    client, spaced by the limiter, never triggers it."""
    clock, transport, client = world
    for _ in range(40):
        client.analytics_status("abc123", from_=T0)
    assert all(c.status == 200 for c in transport.calls)
    assert min(transport.gaps()) >= 2.0


def test_the_configured_spacing_is_shared_per_key():
    lim.reset_limiters()
    client_a = real_client(FakeNextDNSTransport(FakeClock()),
                           NextDNSConfig(api_key=API_KEY, min_spacing_sec=3.0))
    client_b = real_client(FakeNextDNSTransport(FakeClock()), NextDNSConfig(api_key=API_KEY))
    assert client_a.limiter is client_b.limiter
    lim.reset_limiters()
