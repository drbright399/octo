"""The site's week — the owner's decisions of 2026-09-30. Real pieces, fake
socket, one fake clock (conftest.py).

  A. LEARN THE SITE'S WEEK: protection lapses only when a site is silent
     while it NORMALLY has traffic, judged against the same days / hours of
     the previous 3 weeks — the hourly rule AND the whole-day backstop (a
     weekend-closed or part-week office always silent then never lapses for
     it; a real outage on a normally-busy day still lapses once), and
     'dark before Athena watched' (mapping on a weekend raises nothing for a
     weekend-closed office; a truly dark site mapped any day raises one).
     A mass outage is still ONE fleet signal.
  B. SEEDED FROM NEXTDNS HISTORY: when a profile is first watched (and while
     its own roll-ups cover less than 3 weeks) its baseline is seeded from
     ONE analytics/status;series call (from=-21d, hourly), at health
     priority, at most once per profile per 24 h — stored compactly in its
     own state row, never as raw series. There is no first-weeks blind
     spot: the hourly rule works from the first day. A profile whose series
     call fails learns locally, as before, without breaking.

Round 5 (review of the round-4 build): the hours inside a profile's lapses
that it normally has queries in are UNKNOWN to its baseline (a site dark
again after a long outage, or the week after a two-week closure, lapses);
7 × 24 silent hours lapse an ever-active profile whatever its baseline; the
seed starts at sustained traffic (a stray test query is not the rollout); a
throttle on the history call is no answer (retried after the backoff, no
false 'dark before watched'); the budget is the profile id's (unmap +
re-map within a day = one call); a seed that no longer reaches the
profile's own roll-ups after a re-map is read again.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.adapters.nextdns import poller as poller_module
from apps.octo.adapters.nextdns.limiter import PRIORITY_HEALTH
from apps.octo.adapters.nextdns.presentation import EVENT_LAPSED, EVENT_RESTORED
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, hour_of
from apps.octo.client_provisioning import create_client
from apps.octo.instances import poller_state, tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"
OPS = "msp-ops"                                   # the operator's own tenant
EVENT_FLEET = "nextdns.fleet_dns_outage"
UTC = timezone.utc
Z = {"default": 0, "blocked": 0, "allowed": 0}
OPEN = {"default": 300, "blocked": 10, "allowed": 0}


def _payload(row) -> dict:
    return json.loads(row["payload"])


def _series_calls(world, pid: str) -> list:
    return [c for c in world.transport.calls_for(pid) if c.path.endswith("/analytics/status;series")]


def _key(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


# ---------------------------------------------------------------------------
# B. The baseline is seeded from NextDNS history
# ---------------------------------------------------------------------------

def test_a_busy_site_seeded_from_its_history_lapses_on_its_first_day(world):
    """Mapped today, never rolled up before: its NextDNS history says every
    hour is busy, so two silent busy hours on the FIRST day are a lapse —
    no week-long wait for a local baseline."""
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 3600)
    assert poller.snapshot()["states"]["abc123"]["baseline_seeded"] is True
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(6)])
    world.run_for(poller, 3 * 3600 + 600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = _payload(lapse)
    assert payload["cause"] == "no_queries" and payload["since"] == _key(first)
    assert payload["detected_at"] == (first + timedelta(hours=2)).strftime(
        "%Y-%m-%dT%H:00:00.000Z")


def test_the_history_is_read_once_per_watched_profile_at_health_priority(world):
    t = world.transport
    t.set_rate("abc123")
    t.set_rate("def456")
    t.set_rate("tst001", default=2, blocked=0, allowed=0)       # 48 a day: pending
    world.map(abc123=ACME, def456=BAKERY, tst001=BAKERY)
    poller = world.poller()
    world.run_for(poller, 26 * 3600)
    assert [len(_series_calls(world, p)) for p in ("abc123", "def456", "tst001")] == [1, 1, 0]
    # …through the ONE limiter, at health priority (grants and calls pair up).
    grants = world.limiter.grants()
    assert len(grants) == len(t.calls)
    for i, call in enumerate(t.calls):
        if call.path.endswith(";series"):
            assert grants[i].priority == PRIORITY_HEALTH
            assert call.query == {"from": "-21d", "interval": "3600"}
    # Stored compactly in its own row (the profile row never carries it).
    seed = poller_state.load(world.record.id, poller_module.seed_state_key("abc123"))
    assert set(seed) == {"v", "at", "from", "to", "busy", "seen", "peak24"}
    assert len(json.dumps(seed, separators=(",", ":"))) < 500          # 3 weeks, 2 bitmasks
    row = poller_state.load(world.record.id, poller_module.profile_state_key("abc123"))
    assert "seed" not in row and "seed_tried_at" not in row     # the seed carries its time
    # A restart reads it back — no second call — and three more days of
    # a local baseline under 3 weeks never ask again.
    restarted = world.poller()
    world.run_for(restarted, 3 * 86400)
    assert [len(_series_calls(world, p)) for p in ("abc123", "def456", "tst001")] == [1, 1, 0]
    assert restarted.snapshot()["states"]["abc123"]["baseline_seeded"] is True
    # Unmapped: its seed row goes with it.
    world.map(abc123=ACME)
    world.run_for(restarted, 600)
    assert poller_state.load(world.record.id, poller_module.seed_state_key("def456")) is None


def test_unreadable_seed_rows_at_a_restart_never_break_the_daily_budget(world, monkeypatch):
    """The registry cannot list the seed rows at a restart: a stored seed
    may exist, so no history call for a day — the budget holds."""
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    world.run_for(world.poller(), 3600)
    assert len(_series_calls(world, "abc123")) == 1
    real = poller_state.load_prefix

    def flaky(instance_id, prefix):
        return None if prefix == poller_module.SEED_KEY_PREFIX else real(instance_id, prefix)
    monkeypatch.setattr(poller_state, "load_prefix", flaky)
    restarted = world.poller()
    world.run_for(restarted, 20 * 3600)
    assert len(_series_calls(world, "abc123")) == 1
    assert restarted.snapshot()["states"]["abc123"]["state"] == "active"


def test_a_profile_with_three_weeks_of_its_own_rollups_is_not_seeded(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)                          # 21 days of own rows
    world.map(abc123=ACME)
    world.run_for(world.poller(), 2 * 86400)
    assert _series_calls(world, "abc123") == []


@pytest.mark.parametrize("failure", ["http500", "http404", "malformed"])
def test_a_profile_whose_history_read_fails_learns_locally(world, failure):
    """The series call fails (5xx, a 404 on the series alone, a malformed
    answer): not the profile's problem, nothing breaks — it is polled as
    before, its baseline is learnt from its own roll-ups (the first-week
    rules: only a whole silent day lapses it), and the history is asked
    again at most once a day."""
    t = world.transport
    t.set_rate("abc123")
    if failure == "malformed":
        t.series_malformed = True
    else:
        t.series_status["abc123"] = 500 if failure == "http500" else 404
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(40)])
    world.run_for(poller, 12 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == []                # no hourly rule yet
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "active" and snap["problem"] is None and not snap["missing"]
    assert snap["baseline_seeded"] is False
    world.run_for(poller, 14 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)                   # the whole-day backstop
    assert _payload(lapse)["since"] == _key(first)
    # Asked again after a day — never more often.
    calls = _series_calls(world, "abc123")
    assert len(calls) == 2 and calls[1].at - calls[0].at >= 24 * 3600
    assert world.instance_row()["status"] == "running"
    assert sum(1 for c in t.calls_for("abc123") if c.path.endswith("/analytics/reasons")) >= 100


# ---------------------------------------------------------------------------
# A. Learn the site's week (seeded from NextDNS history — from day one)
# ---------------------------------------------------------------------------

def _weekdays(hour: datetime) -> dict[str, int]:
    """Open Monday–Friday 13:00–22:59 UTC; nothing at all otherwise."""
    return dict(OPEN) if hour.weekday() < 5 and 13 <= hour.hour <= 22 else dict(Z)


def _mon_wed_fri(hour: datetime) -> dict[str, int]:
    """Open Monday, Wednesday and Friday 13:00–22:59 UTC; nothing otherwise."""
    return dict(OPEN) if hour.weekday() in (0, 2, 4) and 13 <= hour.hour <= 22 else dict(Z)


def _alerts(world, *slugs: str) -> list[dict]:
    return [_payload(r) for slug in (slugs or (ACME, BAKERY))
            for et in (EVENT_LAPSED, EVENT_RESTORED) for r in world.events(slug, et)]


def test_a_weekend_closed_office_never_lapses_for_its_weekends_from_day_one(world):
    """Fully silent every weekend (no NAS, nothing). Mapped on a Thursday
    with no roll-ups of its own: its history says Saturdays and Sundays are
    always silent, so two weekends pass without a lapse (the whole-day
    backstop used to lapse it every Saturday) — and a real outage on a
    normally-busy weekday still lapses, once."""
    world.transport.of("abc123").rate_fn = _weekdays
    world.clock.set(datetime(2026, 10, 1, 12, 0, tzinfo=UTC))           # Thursday
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 12 * 86400)                                    # → Tue 13 Oct
    assert _alerts(world) == []
    outage = datetime(2026, 10, 14, 13, 0, tzinfo=UTC)                   # Wednesday
    world.transport.silence("abc123", *[outage + timedelta(hours=h) for h in range(4)])
    world.run_for(poller, 35 * 3600)                                     # → Wed 23:00
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = _payload(lapse)
    assert payload["since"] == "2026-10-14T13:00:00Z" and payload["cause"] == "no_queries"
    assert payload["detected_at"] == "2026-10-14T15:00:00.000Z"
    assert len(world.events(ACME, EVENT_RESTORED)) == 1


def test_a_part_week_office_never_lapses_on_its_closed_days(world):
    """Open Monday / Wednesday / Friday only: its Tuesdays, Thursdays and
    weekends are always silent — two weeks without a lapse."""
    world.transport.of("abc123").rate_fn = _mon_wed_fri
    world.clock.set(datetime(2026, 10, 5, 12, 0, tzinfo=UTC))           # Monday
    world.map(abc123=ACME)
    world.run_for(world.poller(), 14 * 86400)
    assert _alerts(world) == []


def test_mapping_a_weekend_closed_office_on_a_sunday_is_no_dark_before_watch(world):
    """0 queries in 24 h and thousands in the week — by the 7-day rule
    alone 'dark before Athena watched'. Its history says Sundays are always
    silent: no alert, ACTIVE (it routes thousands a weekday), and Monday
    goes on normally. The history is read once, at mapping."""
    world.transport.of("abc123").rate_fn = _weekdays
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))           # Sunday
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "active" and snap["queries_24h"] == 0
    world.run_for(poller, 2 * 86400)                                     # → Tuesday
    assert _alerts(world) == []
    assert len(_series_calls(world, "abc123")) == 1


def test_a_weekend_office_dark_since_thursday_mapped_on_sunday_lapses_once_on_monday(world):
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    dark = datetime(2026, 10, 1, 23, 0, tzinfo=UTC)                     # after Thursday
    t.silence("abc123", *[dark + timedelta(hours=h) for h in range(5 * 24)])
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))           # Sunday
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 20 * 3600)                                     # → Monday 08:00
    assert _alerts(world) == []
    world.run_for(poller, 10 * 3600)                                     # → Monday 18:00
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = _payload(lapse)
    assert payload["since"] == "2026-10-05T13:00:00Z"
    assert payload["detected_at"] == "2026-10-05T15:00:00.000Z"


@pytest.mark.parametrize("mapped_at", [T0, datetime(2026, 10, 4, 12, 0, tzinfo=UTC)],
                         ids=["wednesday", "sunday"])
def test_a_truly_dark_site_mapped_any_day_is_one_dark_before_watch(world, mapped_at):
    """Busy every hour of every day in its history, silent for the last 30
    hours: mapped on a weekday or on a Sunday — ONE 'dark before Athena
    watched', nothing more while it stays dark."""
    t = world.transport
    t.set_rate("abc123")
    first = hour_of(mapped_at) - timedelta(hours=30)
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(4 * 24)])
    world.clock.set(mapped_at)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["cause"] == "before_watch"
    assert world.events(ACME, EVENT_RESTORED) == []
    assert poller.snapshot()["states"]["abc123"]["state"] == "lapsed"


def test_without_its_history_a_sunday_mapping_falls_back_to_the_seven_day_rule(world):
    """NextDNS would not give the history: nothing breaks — the 7-day rule
    decides alone (one 'before Athena watched' for a weekend-closed office
    mapped on a Sunday), and Monday's queries restore it."""
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    t.series_status["*"] = 502
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))           # Sunday
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["cause"] == "before_watch"
    assert len(world.events(ACME, EVENT_RESTORED)) == 1
    assert poller.snapshot()["states"]["abc123"]["state"] == "active"


def test_a_mass_outage_of_weekday_offices_is_one_fleet_signal_not_a_weekend_one(world):
    """Ten weekday offices, fully silent every weekend, mapped on a Friday.
    A DNS template pushed on Saturday morning breaks six of them. The quiet
    weekend raises nothing (it is every weekend); on Monday the six stay
    silent in their busy hours: six lapses, grouped under ONE fleet
    signal."""
    ids = [f"q{i:05d}" for i in range(10)]
    t = world.transport
    t.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"} for pid in ids]
    for pid in ids:
        t.of(pid).rate_fn = _weekdays
    push = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)                      # Saturday
    for pid in ids[:6]:
        t.silence(pid, *[push + timedelta(hours=h) for h in range(4 * 24)])
    world.clock.set(datetime(2026, 10, 2, 12, 0, tzinfo=UTC))           # Friday
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(pid, ACME if i % 2 else BAKERY, f"Site {pid}", "manual")
        for i, pid in enumerate(ids)])
    create_client(OPS, "MSP Operations", kind="internal")
    poller = world.poller()
    world.run_for(poller, 2 * 86400 + 20 * 3600)                         # → Monday 08:00
    assert _alerts(world) == [] and world.events(OPS, EVENT_FLEET) == []
    world.run_for(poller, 10 * 3600)                                     # → Monday 18:00
    lapses = [_payload(r) for slug in (ACME, BAKERY) for r in world.events(slug, EVENT_LAPSED)]
    assert sorted(p["profile_id"] for p in lapses) == ids[:6]
    assert {p["since"] for p in lapses} == {"2026-10-05T13:00:00Z"}
    [fleet] = world.events(OPS, EVENT_FLEET)
    assert fleet["severity"] == "high" and _payload(fleet)["sites"] == 6


# ---------------------------------------------------------------------------
# Round 5: an outage or a closure is never the site's normal week; a stray
# query is not its rollout; the history budget is the profile id's
# ---------------------------------------------------------------------------

def _at(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00.000Z")


def test_mark_span_and_the_sustained_start_of_a_history_series():
    k = lambda h: _key(T0 + timedelta(hours=h))                    # noqa: E731
    packed = poller_module.mark_span(None, k(0), k(2))
    packed = poller_module.mark_span(packed, k(5), k(5))
    assert poller_module.unpack_hours(packed, poller_module.SEED_SPAN_HOURS) == [
        k(0), k(1), k(2), k(5)]
    # Hours beyond the span fall off; a span older than it adds nothing.
    far = poller_module.mark_span(packed, k(600), k(600))
    assert poller_module.unpack_hours(far, poller_module.SEED_SPAN_HOURS) == [k(600)]
    assert poller_module.mark_span(far, k(0), k(1)) == far
    # One stray query 20 days before a rollout: the seed starts at the rollout.
    stray, rollout = T0 - timedelta(days=20), T0 - timedelta(days=5)
    points = [(T0 - timedelta(hours=h), 0) for h in range(1, 21 * 24)]
    points = [(s, 1 if s == stray else 900 if s >= rollout else q) for s, q in points]
    seed = poller_module.make_seed(points, T0)
    assert seed["from"] == _key(rollout)
    # A low-volume profile (never 100 in 24 h) keeps its first query.
    low = [(s, 3 if s.hour == 9 else 0) for s, _q in points]
    assert poller_module.make_seed(low, T0)["from"] == _key(min(s for s, q in low if q))


def test_a_site_dark_again_after_a_long_outage_lapses_again(world):
    """Busy every hour; dark for 15 days (one lapse), back for 2 days, then
    dark again. The first outage's hours are inside its lapse — UNKNOWN to
    the baseline, never learnt as the site's normal week — so the second
    outage lapses within 2 hours, like the first (it used to never lapse:
    ACTIVE at 0 queries for good)."""
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller(poll_interval_sec=3600)
    world.run_for(poller, 86400)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(15 * 24)])
    world.run_for(poller, 15 * 86400 + 3 * 3600)
    assert [p["since"] for p in world.payloads(ACME, EVENT_LAPSED)] == [_key(first)]
    assert len(world.events(ACME, EVENT_RESTORED)) == 1
    world.run_for(poller, 2 * 86400)
    second = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("abc123", *[second + timedelta(hours=h) for h in range(10 * 24)])
    world.run_for(poller, 4 * 3600)
    lapses = world.payloads(ACME, EVENT_LAPSED)
    assert [p["since"] for p in lapses] == [_key(first), _key(second)]
    assert lapses[1]["detected_at"] == _at(second + timedelta(hours=2))
    assert poller.snapshot()["states"]["abc123"]["state"] == "lapsed"


def test_dns_breaking_the_week_after_a_two_week_closure_lapses(world):
    """A weekday office closed over the holidays (Sat 19 Dec – Sun 3 Jan)
    lapses once on Monday 21 Dec (the accepted holiday lapse) and is
    restored on 4 Jan. Its DNS breaks on Thursday 7 Jan: the closure's
    hours are inside that lapse — unknown, not its normal week — so 7 Jan
    is judged on 17 Dec alone and lapses at 15:00 (it used to stay ACTIVE
    at 0 queries for weeks)."""
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    closed = datetime(2026, 12, 19, 0, 0, tzinfo=UTC)
    t.silence("abc123", *[closed + timedelta(hours=h) for h in range(16 * 24)])
    broken = datetime(2027, 1, 7, 0, 0, tzinfo=UTC)
    t.silence("abc123", *[broken + timedelta(hours=h) for h in range(7 * 24)])
    world.clock.set(datetime(2026, 12, 7, 12, 0, tzinfo=UTC))           # Monday
    world.map(abc123=ACME)
    poller = world.poller(poll_interval_sec=3600)
    world.run_for(poller, 31 * 86400 + 6 * 3600)                         # → Thu 7 Jan 18:00
    lapses = world.payloads(ACME, EVENT_LAPSED)
    assert [(p["since"], p["detected_at"]) for p in lapses] == [
        ("2026-12-21T13:00:00Z", "2026-12-21T15:00:00.000Z"),
        ("2027-01-07T13:00:00Z", "2027-01-07T15:00:00.000Z")]
    [restore] = world.payloads(ACME, EVENT_RESTORED)
    assert restore["restored_hour"] == "2027-01-04T13:00:00Z"


def test_a_site_silent_for_a_whole_week_lapses_whatever_its_baseline(world):
    """The floor under the whole-day backstop. A weekday office whose
    NextDNS history holds a two-week closure (before Athena watched it, so
    not one of its lapses) is back for two days, mapped, then dark. Its
    baseline learnt the closure — only 1 of the 3 previous weeks busy at any
    hour — so no rule sees an abnormal silence; after 7 × 24 silent
    rolled-up hours it lapses anyway (never a weekend or a long weekend)."""
    def office(hour):
        closure = datetime(2026, 10, 3, tzinfo=UTC) <= hour < datetime(2026, 10, 19, tzinfo=UTC)
        return dict(Z) if closure else _weekdays(hour)
    t = world.transport
    t.of("abc123").rate_fn = office
    dark = datetime(2026, 10, 21, 0, 0, tzinfo=UTC)                     # Wednesday
    t.silence("abc123", *[dark + timedelta(hours=h) for h in range(10 * 24)])
    world.clock.set(datetime(2026, 10, 21, 12, 0, tzinfo=UTC))
    world.map(abc123=ACME)
    poller = world.poller(poll_interval_sec=3600)
    world.run_for(poller, 3600)
    assert poller.snapshot()["states"]["abc123"]["state"] == "active"
    first = datetime.strptime(poller._profiles["abc123"].first_hour,      # its first roll-up
                              "%Y-%m-%dT%H:00:00Z").replace(tzinfo=UTC)
    assert dark < first < datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    floor = first + timedelta(hours=7 * 24)          # the 168th zero hour closes then
    world.run_for(poller, (floor - timedelta(minutes=30) - world.clock.now()).total_seconds())
    assert world.events(ACME, EVENT_LAPSED) == []                       # a whole week learnt
    world.run_for(poller, 3600)
    [lapse] = world.payloads(ACME, EVENT_LAPSED)
    assert lapse["since"] == _key(first) and lapse["cause"] == "no_queries"
    assert lapse["detected_at"] == _at(floor)


def test_a_stray_test_query_weeks_before_the_rollout_is_not_the_sites_week(world):
    """The profile was created and tested at NextDNS (one query) 20 days
    before the site's gateway rollout, 5 days before mapping. Its seed
    starts where the sustained traffic starts — the weeks before are
    unknown, not a quiet site — so when the site goes dark on its third day
    watched it lapses within 2 hours (it used to never lapse)."""
    from apps.octo.adapters.nextdns.tests.fake_nextdns import block_line

    t = world.transport
    now = world.clock.now()
    t.set_rate("abc123", active_from=now - timedelta(days=5))
    t.add_lines("abc123", block_line(now - timedelta(days=20), domain="probe.example.test"))
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)
    assert poller._profiles["abc123"].seed["from"] == _key(now - timedelta(days=5))
    dark = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("abc123", *[dark + timedelta(hours=h) for h in range(10 * 24)])
    world.run_for(poller, 4 * 3600)
    [lapse] = world.payloads(ACME, EVENT_LAPSED)
    assert lapse["since"] == _key(dark)
    assert lapse["detected_at"] == _at(dark + timedelta(hours=2))


def test_a_throttle_on_the_history_call_is_no_answer_and_is_asked_again_soon(world):
    """A weekday office mapped on a Sunday; another tool on the key trips a
    burst 403 exactly on its history call. No data was served: the call
    does not use up the day's budget, the profile is not judged without its
    history (no false 'dark before Athena watched'), and the history is
    read once the backoff is over — minutes later, not a day."""
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))           # Sunday
    fired = []

    def burst(path, query):
        if path.endswith(";series") and not fired:
            fired.append(path)
            t.throttle_next = 1
    t.before_request = burst
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)                                     # → Tuesday
    assert fired and _alerts(world) == []
    calls = _series_calls(world, "abc123")
    assert [c.status for c in calls] == [403, 200]
    assert calls[1].at - calls[0].at <= 3600
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "active" and snap["baseline_seeded"] is True
    assert snap["problem"] is None


def test_a_profile_remapped_weeks_after_its_history_was_read_reads_it_again(world):
    """Mapped on a Friday (its history read then), re-mapped to another
    client 17 days later. The new tenant has no roll-ups and the old
    history stops 17 days back, so for days none of the 3 previous weeks
    would be known (the plain rule: its weekend lapsed). The seed no longer
    reaches the profile's roll-ups: it is read again (once), and the
    weekend after passes in silence."""
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    world.clock.set(datetime(2026, 10, 2, 12, 0, tzinfo=UTC))           # Friday
    world.map(abc123=ACME)
    poller = world.poller(poll_interval_sec=3600)
    world.run_for(poller, 3600)
    world.clock.set(datetime(2026, 10, 19, 12, 0, tzinfo=UTC))          # Monday, 17 days on
    world.map(abc123=BAKERY)                                             # a correction
    world.run_for(poller, 7 * 86400)                                     # → Monday 26 Oct
    assert _alerts(world, ACME, BAKERY) == []
    calls = _series_calls(world, "abc123")
    assert len(calls) == 2
    seed = poller._profiles["abc123"].seed
    assert seed["to"] >= "2026-10-19T00:00:00Z"
    assert poller.snapshot()["states"]["abc123"]["state"] == "active"


def test_unmapping_and_remapping_within_a_day_reads_the_history_once(world):
    """The budget is the profile id's, not its mapping's: an operator
    fixing mappings (unmap, map again — twice within three hours) never
    makes a second history call, and the re-mapped profile keeps its seed
    (parked for the day). A day later the parked seed row is gone."""
    t = world.transport
    t.set_rate("abc123")
    t.set_rate("def456")
    world.map(abc123=ACME, def456=BAKERY)
    poller = world.poller()
    world.run_for(poller, 3600)
    for _ in range(2):
        world.map(def456=BAKERY)
        world.run_for(poller, 1200)
        world.map(abc123=ACME, def456=BAKERY)
        world.run_for(poller, 3600)
    assert len(_series_calls(world, "abc123")) == 1
    assert poller.snapshot()["states"]["abc123"]["baseline_seeded"] is True
    # …across a restart too (the attempt is in the global state row).
    world.map(def456=BAKERY)
    world.run_for(poller, 600)
    restarted = world.poller()
    world.run_for(restarted, 600)
    assert poller_state.load(world.record.id, poller_module.seed_state_key("abc123"))
    world.map(abc123=ACME, def456=BAKERY)
    world.run_for(restarted, 3600)
    assert len(_series_calls(world, "abc123")) == 1
    assert restarted.snapshot()["states"]["abc123"]["baseline_seeded"] is True
    # Unmapped for good: the parked seed row goes once it is a day old.
    world.map(def456=BAKERY)
    world.run_for(restarted, 26 * 3600)
    assert poller_state.load(world.record.id, poller_module.seed_state_key("abc123")) is None


def test_without_history_a_closed_weekend_lapsed_by_the_plain_rule_is_learnt_once(world):
    """No history (the series call keeps failing): a weekday office's first
    weekend is lapsed by the plain whole-day rule (the documented
    limitation) — but that lapse, decided WITHOUT a baseline, does not make
    the weekend unknown: the next weekends are judged by it (silent, as
    always) and never lapse."""
    t = world.transport
    t.of("abc123").rate_fn = _weekdays
    t.series_status["*"] = 502
    world.clock.set(datetime(2026, 9, 30, 12, 0, tzinfo=UTC))           # Wednesday
    world.map(abc123=ACME)
    poller = world.poller(poll_interval_sec=3600)
    world.run_for(poller, 19 * 86400)                                    # three weekends
    lapses = world.payloads(ACME, EVENT_LAPSED)
    assert [p["since"][:10] for p in lapses] == ["2026-10-02"]           # the first weekend
    assert len(world.events(ACME, EVENT_RESTORED)) == 1
    assert poller._profiles["abc123"].dark_hours is None
