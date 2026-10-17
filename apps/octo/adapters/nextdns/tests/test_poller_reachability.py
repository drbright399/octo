"""One endpoint of a profile refused, and NextDNS unreachable — the poller
never goes quiet about either. Real pieces, fake socket, one fake clock
(conftest.py).

Pinned (round 6, 2026-09-30 — the final verifier's probes, ported):
  * a LISTED profile whose history call (analytics/status;series) alone
    answers 403 while its other reads answer: the 403s are counted on that
    call alone (an answer on its security path never resets them), only
    that call backs off — its roll-ups and lapse detection go on — the key
    is never called rate limited for it, and after 3 such 403s it is a
    failed read (local learning, one retry a day): at most 3 + 1 a day,
    never one per cycle;
  * a LISTED, active profile whose hourly analytics/status alone answers
    403 while its security checks answer: its roll-up 403s keep their own
    streak (the security answers do not reset it), its roll-ups alone back
    off, and after 3 it shows its own problem — "NextDNS refuses this
    profile's hourly analytics — check sharing/permissions" — while the
    rest of the fleet stays current and the key's status clean; an answer
    clears it and its roll-ups catch up (the outage it hid then lapses);
  * a profile being classified whose history call keeps answering 403 is
    classified without it after 3 (never left NEW for good);
  * NextDNS unreachable for hours: the instance row says 'error' —
    "NextDNS unreachable since <time>" — within a bounded time whatever the
    fleet size (1, 2, 5, 20, 53 mapped profiles: the per-profile backoffs
    spread their failures over many cycles), stays so while it lasts, and
    the next successful call clears it; one failed call on a quiet fleet
    is not an outage.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
import requests

from apps.octo.adapters.nextdns.poller import REFUSED_BEFORE_PROBLEM
from apps.octo.adapters.nextdns.presentation import EVENT_LAPSED
from apps.octo.adapters.nextdns.tests.fake_nextdns import hour_of
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"
UTC = timezone.utc


def _setup(world, n: int) -> list[str]:
    ids = [f"r{i:05d}" for i in range(n)]
    world.transport.profiles = [{"id": p, "name": f"Site {p}", "fingerprint": "fp",
                                 "role": "owner"} for p in ids]
    for p in ids:
        world.transport.set_rate(p)
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(p, ACME if i % 2 else BAKERY, f"Site {p}", "manual")
        for i, p in enumerate(ids)])
    return ids


def _drive(world, poller, seconds: float) -> list[tuple[float, str, str]]:
    """Run the poller's loop for `seconds`; (clock, row status, row detail)
    after every cycle."""
    seen = []
    end = world.clock.monotonic() + seconds
    while world.clock.monotonic() < end:
        delay = poller.cycle_with_reporting()
        row = world.instance_row()
        seen.append((world.clock.monotonic(), row["status"], row["status_detail"] or ""))
        world.clock.advance(max(1.0, min(delay, end - world.clock.monotonic())))
    return seen


def _key(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


def _at(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00.000Z")


def _latest_closed(world) -> str:
    return _key(hour_of(world.clock.now() - timedelta(seconds=300)) - timedelta(hours=1))


def _lapses(world) -> list[dict]:
    return [p for s in (ACME, BAKERY) for p in world.payloads(s, EVENT_LAPSED)]


def _rate_limited(seen) -> int:
    """How many times the row turned to 'rate limiting' (episodes)."""
    flags = [False] + ["rate limiting" in d for _t, _s, d in seen]
    return sum(1 for a, b in zip(flags, flags[1:]) if b and not a)


# ---------------------------------------------------------------------------
# One endpoint of a listed profile refused
# ---------------------------------------------------------------------------

def test_a_history_call_refused_alone_is_a_failed_read_and_the_rollups_go_on(world):
    """The verifier's probe: the history series of one listed, active
    profile answers 403 (its other reads answer); 3 h later the site goes
    dark for 30 h. Before: each answer on its security path reset the
    streak, the 403 ended every cycle as 'rate limiting' and stopped its
    roll-ups (no lapse in 30 h dark, 198 history calls in 33 h)."""
    ids = _setup(world, 6)
    t = world.transport
    victim = ids[0]

    def refuse_history(path, query):
        if path == f"/profiles/{victim}/analytics/status;series":
            t.status_script = [403]
    t.before_request = refuse_history
    poller = world.poller()
    seen = _drive(world, poller, 3 * 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence(victim, *[first + timedelta(hours=h) for h in range(30)])
    seen += _drive(world, poller, 30 * 3600)
    # The key is never called rate limited for it.
    assert _rate_limited(seen) == 0
    assert all(s == "running" for _t, s, _d in seen)
    # Its roll-ups kept up with the fleet's…
    hd = {p: poller._profiles[p].hour_done for p in ids}
    assert set(hd.values()) == {_latest_closed(world)}
    # …so its 30 dark hours lapsed it (no history: the whole-day rule).
    [lapse] = _lapses(world)
    assert lapse["profile_id"] == victim
    assert lapse["since"] == _key(first)
    assert lapse["detected_at"] == _at(first + timedelta(hours=24))
    # 3 refusals, then a failed read: one retry a day — never one a cycle.
    series = [c for c in t.calls_for(victim) if c.path.endswith(";series")]
    assert [c.status for c in series] == [403] * len(series)
    assert REFUSED_BEFORE_PROBLEM <= len(series) <= REFUSED_BEFORE_PROBLEM + 2
    first_three = series[:REFUSED_BEFORE_PROBLEM]
    assert first_three[-1].at - first_three[0].at <= 3 * 3600      # with its roll-ups
    for a, b in zip(series[REFUSED_BEFORE_PROBLEM - 1:], series[REFUSED_BEFORE_PROBLEM:]):
        assert b.at - a.at >= 24 * 3600
    st = poller.snapshot()["states"][victim]
    assert st["problem"] is None and st["baseline_seeded"] is False
    assert not poller.snapshot()["throttled"]
    # Its security checks went on all along.
    reasons = [c for c in t.calls_for(victim) if c.path.endswith("/analytics/reasons")]
    assert len(reasons) >= 30 * 6


def test_rollups_refused_alone_show_the_profiles_own_problem_and_the_key_stays_clean(world):
    """The verifier's probe: one listed, ACTIVE profile's hourly
    analytics/status answers 403 while its security checks answer, and the
    site goes dark. Before: every security answer reset its 403 streak, so
    it was never shown refused — its roll-ups and lapse detection stopped
    silently and the key was called rate limited about once an hour."""
    ids = _setup(world, 6)
    t = world.transport
    victim = ids[0]
    on: list[int] = []

    def refuse_status(path, query):
        if on and path == f"/profiles/{victim}/analytics/status":
            t.status_script = [403]
    t.before_request = refuse_status
    poller = world.poller()
    _drive(world, poller, 3 * 3600)
    on.append(1)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence(victim, *[first + timedelta(hours=h) for h in range(30)])
    c0 = len(t.calls)
    early = _drive(world, poller, 2 * 3600)
    late = _drive(world, poller, 28 * 3600)
    snap = poller.snapshot()
    st = snap["states"][victim]
    # Its own problem, named for what is refused.
    assert st["problem_kind"] == "refused" and st["state"] == "active" and not st["missing"]
    assert "NextDNS refuses this profile's hourly analytics — check sharing/permissions" \
        in st["problem"]
    assert "its blocks are still read" in st["problem"]
    # Shown within the first hours; the key never blamed from then on.
    assert _rate_limited(early) <= REFUSED_BEFORE_PROBLEM
    assert _rate_limited(late) == 0
    assert world.instance_row()["status"] == "running"
    assert world.instance_row()["status_detail"].startswith("connected")
    # The rest of the fleet is current; the refused profile is not lag.
    assert {poller._profiles[p].hour_done for p in ids[1:]} == {_latest_closed(world)}
    assert snap["rollup_lag_hours"] == 0 and not snap["throttled"]
    # Its roll-ups are retried at most hourly; its security checks go on.
    calls = t.calls[c0:]
    refused = [c for c in calls if c.path.startswith(f"/profiles/{victim}/") and c.status == 403]
    assert len(refused) <= REFUSED_BEFORE_PROBLEM + 31
    reasons = [c for c in calls if c.path == f"/profiles/{victim}/analytics/reasons"
               and c.status == 200]
    assert len(reasons) >= 30 * 5
    # Whether it is dark cannot be seen: no lapse while refused.
    assert _lapses(world) == []
    # NextDNS answers again: the problem clears, its roll-ups catch up —
    # and the outage they hid is now seen.
    on.clear()
    _drive(world, poller, 2 * 3600)
    st = poller.snapshot()["states"][victim]
    assert st["problem"] is None
    assert poller._profiles[victim].hour_done == _latest_closed(world)
    assert [p["profile_id"] for p in _lapses(world)] == [victim]


def test_a_profile_classified_while_its_history_is_refused_is_never_left_new(world):
    """A weekday office mapped on a Sunday is judged with its history; its
    history call keeps answering 403 (the profile listed, the rest
    answering). After 3 it is a failed read: the profile is classified
    without it (the 7-day rule), once — not asked every cycle."""
    t = world.transport
    t.set_rate("abc123")
    t.of("abc123").rate_fn = lambda h: (
        {"default": 900, "blocked": 40, "allowed": 2} if h.weekday() < 5 else {})
    t.series_status["abc123"] = 403
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))           # Sunday
    world.map(abc123=ACME)
    poller = world.poller()
    _drive(world, poller, 3 * 3600)
    st = poller.snapshot()["states"]["abc123"]
    assert st["state"] != "new" and st["problem"] is None
    series = [c for c in t.calls_for("abc123") if c.path.endswith(";series")]
    assert len(series) == REFUSED_BEFORE_PROBLEM
    _drive(world, poller, 12 * 3600)
    assert len([c for c in t.calls_for("abc123") if c.path.endswith(";series")]) \
        == REFUSED_BEFORE_PROBLEM


# ---------------------------------------------------------------------------
# NextDNS unreachable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 5, 20, 53])
def test_nextdns_unreachable_for_hours_is_said_whatever_the_fleet_size(world, n):
    """The verifier's probe: NextDNS cannot be reached for 2 h. Before, a
    fleet of up to ~20 mapped profiles stayed "connected — last contact
    with the vendor succeeded" all along (3 failures in a row inside one
    cycle never happened: each profile backs off on its own)."""
    ids = _setup(world, n)
    poller = world.poller()
    world.run_for(poller, 3600)
    assert world.instance_row()["status"] == "running"
    world.transport.unreachable = True
    down_at = world.clock.monotonic()
    seen = _drive(world, poller, 2 * 3600)
    errors = [i for i, (_t, s, _d) in enumerate(seen) if s == "error"]
    assert errors, Counter(d[:40] for _t, _s, d in seen)
    # Said within 2 intervals of the first failed call (+ one cycle)…
    assert seen[errors[0]][0] - down_at <= 3 * poller.interval_sec + 120
    # …and said for as long as it lasts.
    assert all(s == "error" for _t, s, _d in seen[errors[0]:])
    detail = seen[-1][2]
    assert detail.startswith("NextDNS unreachable since ")
    assert "this clears with the next successful call" in detail
    assert poller.snapshot()["unreachable_since"] is not None
    # Reachable again: the next successful call clears it.
    world.transport.unreachable = False
    up_at = world.clock.monotonic()
    seen = _drive(world, poller, 3600)
    ok = [i for i, (_t, s, _d) in enumerate(seen) if s == "running"]
    assert ok and seen[ok[0]][0] - up_at <= 16 * 60 + 120
    assert seen[-1][1:] == ("running", "connected — last contact with the vendor succeeded")
    assert poller.snapshot()["unreachable_since"] is None
    assert len(ids) == n


def test_one_failed_call_on_a_quiet_fleet_is_not_an_outage(world):
    """One profile still PENDING (one read every 6 h): a single timeout,
    then an answer on the retry. Long without a call is not 'unreachable'."""
    t = world.transport
    t.set_rate("abc123", default=2, blocked=0, allowed=0)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 7 * 3600)
    assert poller.snapshot()["states"]["abc123"]["state"] == "pending"
    fired: list[str] = []

    def once(path, query):
        if path.startswith("/profiles/abc123") and not fired:
            fired.append(path)
            raise requests.Timeout("fixture: read timed out")
    t.before_request = once
    seen = _drive(world, poller, 6 * 3600)
    assert fired
    assert all(s == "running" for _t, s, _d in seen)
    assert poller.snapshot()["unreachable_since"] is None
