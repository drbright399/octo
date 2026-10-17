"""Protection health — the verifier's second-round findings and the rules
that close them. Real pieces, fake socket, one fake clock (conftest.py);
coalescing is in test_poller_coalescing.py.

  * PENDING: 1–99 queries a day stay pending (no alert, never active); only
    a silent day after a busy week is "dark before Athena watched" (with
    NextDNS history: only when the site normally has queries then —
    test_poller_baseline.py);
  * the whole-day backstop: an ever-active site silent for 24 h is lapsed
    — once it has a baseline, only when it normally has queries in that
    day (test_poller_baseline.py: weekend-closed / part-week offices);
  * the hourly rule judges "normally busy" by the same HOUR OF THE WEEK over
    the previous 3 weeks, and only with at least 7 days of baseline (seeded
    from NextDNS history: from the first day — test_poller_baseline.py);
  * a vendor-side gap excuses at most 2 hours in a row; a real mass outage
    lapses the sites and raises ONE fleet-level signal in the operator's
    own (internal) tenant, the per-site lapses linked to it; only FAILED
    reads are NextDNS-side evidence (an empty data array is what a silent
    hour normally looks like — verified live);
  * (third round) only CONSECUTIVE normally-busy zero hours count; a
    'dark before Athena watched' profile that wakes up at 1-99 a day goes
    back to PENDING; a fleet of logs-off sites stays one open incident.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from apps.octo.adapters.nextdns import NextDNSSourceAdapter
from apps.octo.adapters.nextdns.presentation import EVENT_LAPSED, EVENT_RESTORED
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, hour_of
from apps.octo.client_provisioning import create_client
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"
OPS = "msp-ops"                                   # the operator's own tenant
EVENT_FLEET = "nextdns.fleet_dns_outage"
UTC = timezone.utc


def _payload(row) -> dict:
    return json.loads(row["payload"])


# ---------------------------------------------------------------------------
# PENDING vs dark before watch
# ---------------------------------------------------------------------------

def test_a_profile_with_1_to_99_queries_a_day_stays_pending_without_an_alert(world):
    world.transport.set_rate("abc123", default=2, blocked=0, allowed=0)     # 48 a day
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 13 * 3600)
    assert world.events(ACME) == []
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "pending" and 1 <= snap["queries_24h"] < 100


def test_a_silent_day_after_a_quiet_week_is_pending_not_dark(world):
    t = world.transport
    t.set_rate("abc123", default=1, blocked=0, allowed=0, active_from=T0 - timedelta(days=5))
    h = hour_of(T0 - timedelta(hours=30))
    while h < T0 + timedelta(hours=12):
        t.silence("abc123", h)
        h += timedelta(hours=1)
    world.map(abc123=ACME)                    # 0 in 24 h, 90 (< 100) in 7 days
    poller = world.poller()
    world.run_for(poller, 3600)
    assert world.events(ACME) == []
    assert poller.snapshot()["states"]["abc123"]["state"] == "pending"


# ---------------------------------------------------------------------------
# The whole-day backstop
# ---------------------------------------------------------------------------

def _silence_from(world, pid: str, first: datetime, hours: int) -> None:
    world.transport.silence(pid, *[first + timedelta(hours=h) for h in range(hours)])


def test_a_whole_silent_day_lapses_even_a_site_whose_hours_all_look_quiet(world):
    """150 queries a day (6 an hour, ACTIVE by the gate) — below the 'busy
    hour' mark in every hour, so the hourly rule never counts a zero hour.
    Its gateway's DNS is changed: silent for good. The backstop lapses it
    after a whole day."""
    t = world.transport
    t.set_rate("abc123", default=6, blocked=0, allowed=0)
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    _silence_from(world, "abc123", first, 48)
    world.run_for(poller, 23 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == []
    world.run_for(poller, 3 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = _payload(lapse)
    assert payload["cause"] == "no_queries"
    assert payload["since"] == first.strftime("%Y-%m-%dT%H:00:00Z")
    assert payload["zero_hours"] >= 24
    assert poller.snapshot()["states"]["abc123"]["state"] == "lapsed"


def test_without_its_history_and_a_week_of_baseline_only_a_whole_silent_day_lapses(world):
    """NextDNS would not give its history (the seed): the first-week rule
    of local learning — only the whole-day backstop."""
    t = world.transport
    t.set_rate("abc123")                                     # busy, freshly mapped
    t.series_status["abc123"] = 503
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    _silence_from(world, "abc123", first, 40)
    world.run_for(poller, 12 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == []            # no hourly rule yet
    world.run_for(poller, 14 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["since"] == first.strftime("%Y-%m-%dT%H:00:00Z")


# ---------------------------------------------------------------------------
# The hourly rule: the same hour of the week, and 7 days of baseline
# ---------------------------------------------------------------------------

def _quiet_nights(world, pid: str) -> None:
    t = world.transport
    t.set_rate(pid, default=900, blocked=40, allowed=2)
    for h in list(range(20, 24)) + list(range(0, 6)):
        t.of(pid).rate_by_hour_of_day[h] = {"default": 0, "blocked": 0, "allowed": 0}


def test_a_night_dark_office_never_lapses_on_its_first_nights(world):
    _quiet_nights(world, "abc123")
    world.map(abc123=ACME)
    world.run_for(world.poller(), 3 * 86400)
    assert world.events(ACME, EVENT_LAPSED) == []
    assert world.events(ACME, EVENT_RESTORED) == []


def test_a_night_dark_office_with_a_baseline_lapses_only_in_its_busy_hours(world):
    _quiet_nights(world, "abc123")
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)
    assert world.events(ACME, EVENT_LAPSED) == []
    day3 = hour_of(world.clock.now()).replace(hour=0) + timedelta(days=1)
    for h in range(9, 13):
        world.transport.silence("abc123", day3.replace(hour=h))
    world.clock.set(day3.replace(hour=8, minute=30))
    world.run_for(poller, 4 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["since"].endswith("T09:00:00Z")


def _weekend_office(hour: datetime) -> dict[str, int]:
    """Busy on weekdays 13:00-23:00 UTC; nights and weekends silent except a
    NAS that looks something up at 03:00 and 15:00 every day."""
    if hour.weekday() < 5 and 13 <= hour.hour <= 22:
        return {"default": 120, "blocked": 3, "allowed": 0}
    if hour.hour in (3, 15):
        return {"default": 3, "blocked": 0, "allowed": 0}
    return {"default": 0, "blocked": 0, "allowed": 0}


def test_a_weekend_closed_office_is_judged_by_the_same_hour_of_the_week(world):
    t = world.transport
    t.of("abc123").rate_fn = _weekend_office
    friday = datetime(2026, 10, 2, 20, 0, tzinfo=UTC)
    world.clock.set(friday)
    world.seed_baseline("abc123", ACME)                      # 3 weeks of the pattern
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 86400)                         # → Sunday 20:00
    assert world.events(ACME, EVENT_LAPSED) == []
    # Monday: a busy hour goes silent — a real outage still lapses.
    monday = datetime(2026, 10, 5, 13, 0, tzinfo=UTC)
    _silence_from(world, "abc123", monday, 3)
    world.run_for(poller, 21 * 3600)                         # → Monday 17:00
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["since"] == "2026-10-05T13:00:00Z"


# ---------------------------------------------------------------------------
# Hysteresis (with a baseline)
# ---------------------------------------------------------------------------

def test_a_relapse_within_a_day_is_the_same_episode(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)
    for h in (13, 14, 17, 18):
        t.silence("abc123", T0.replace(hour=h))
    world.map(abc123=ACME)
    world.run_for(world.poller(), 9 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    [restored] = world.events(ACME, EVENT_RESTORED)
    lapse_notes = [n["note_text"] for n in world.notes(ACME, lapse["id"])]
    assert any("Stopped reporting again from 2026-09-30 17:00 UTC" in n for n in lapse_notes)
    restored_notes = [n["note_text"] for n in world.notes(ACME, restored["id"])]
    assert any("Reporting again from 2026-09-30 19:00 UTC" in n for n in restored_notes)


def test_a_lone_wake_up_is_not_a_restore(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)
    for h in range(13, 22):
        if h != 16:
            t.silence("abc123", T0.replace(hour=h))
    t.of("abc123").rate_by_hour_of_day[16] = {"default": 3, "blocked": 0, "allowed": 0}
    world.map(abc123=ACME)
    world.run_for(world.poller(), 9 * 3600)
    assert len(world.events(ACME, EVENT_LAPSED)) == 1
    assert world.events(ACME, EVENT_RESTORED) == []


# ---------------------------------------------------------------------------
# Vendor-side gaps are bounded; a mass outage is ONE fleet signal
# ---------------------------------------------------------------------------

def _fleet(world, n: int = 10, *, internal: bool = True) -> list[str]:
    ids = [f"q{i:05d}" for i in range(n)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"}
                                for pid in ids]
    for i, pid in enumerate(ids):
        world.transport.set_rate(pid)
        world.seed_baseline(pid, ACME if i % 2 else BAKERY)
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(pid, ACME if i % 2 else BAKERY, f"Site {pid}", "manual")
        for i, pid in enumerate(ids)])
    if internal:
        create_client(OPS, "MSP Operations", kind="internal")
    return ids


def _lapses(world) -> list[dict]:
    return [_payload(r) for slug in (ACME, BAKERY) for r in world.events(slug, EVENT_LAPSED)]


def test_a_mass_outage_lapses_after_two_hours_with_one_fleet_signal(world):
    """A bad DNS template push silences 6 of 10 sites. NextDNS answers their
    hours normally — an EMPTY data array is what a silent hour looks like
    (verified live) — so nothing says it is NextDNS's fault: 60 % silent is
    under the 80 % no-evidence bar, the sites lapse after their two busy
    zero hours, and ONE fleet signal groups them."""
    from apps.octo.agent.worker import process_tenant_once

    ids = _fleet(world)
    for slug in (ACME, BAKERY, OPS):
        process_tenant_once(slug)                            # the triage watermark
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:6]:                                      # a bad DNS template push
        _silence_from(world, pid, first, 48)
    world.run_for(poller, 3 * 3600 + 600)                    # two silent hours read
    lapses = _lapses(world)
    assert sorted(p["profile_id"] for p in lapses) == ids[:6]
    assert {p["since"] for p in lapses} == {first.strftime("%Y-%m-%dT%H:00:00Z")}
    assert poller.snapshot()["analytics_gaps"] == []
    assert all(p["fleet"]["sites"] == 6 and p["fleet"]["watched"] == 10 for p in lapses)
    [fleet] = world.events(OPS, EVENT_FLEET)
    assert fleet["severity"] == "high"
    assert fleet["summary"] == ("6 sites stopped reporting to NextDNS — check NextDNS status "
                                "and the UniFi DNS template")
    fp = _payload(fleet)
    assert fp["sites"] == 6 and fp["watched"] == 10
    assert sorted(p["profile_id"] for p in fp["profiles"]) == ids[:6]
    # The per-site lapses are grouped under it — not 6 escalations.
    for slug in (ACME, BAKERY, OPS):
        process_tenant_once(slug)
    for slug in (ACME, BAKERY):
        for row in world.events(slug, EVENT_LAPSED):
            [l1] = [n for n in world.notes(slug, row["id"]) if n["query_kind"] == "auto_enrich"]
            assert l1["disposition"] == "pattern"
            assert "6 of 10 sites stopped reporting at the same time" in l1["note_text"]
    [l1] = [n for n in world.notes(OPS, fleet["id"]) if n["query_kind"] == "auto_enrich"]
    assert l1["disposition"] == "escalate"
    # It stays ONE incident.
    world.run_for(poller, 12 * 3600)
    assert len(world.events(OPS, EVENT_FLEET)) == 1 and len(_lapses(world)) == 6
    assert poller.snapshot()["analytics_gaps"] == []


def _fail_first_hour_reads(world, pids: list[str], first) -> None:
    """NextDNS fails (HTTP 502) the first read of every hour from `first` on
    for `pids` — the retry answers normally: the failed reads are the
    vendor-side evidence."""
    t = world.transport
    failed: set[tuple[str, str]] = set()

    def hook(path: str, query: dict) -> None:
        parts = path.split("/")
        if len(parts) < 5 or parts[2] not in pids or not path.endswith("/analytics/status"):
            return
        start = datetime.fromisoformat(query["from"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(query.get("to", query["from"]).replace("Z", "+00:00"))
        if end - start == timedelta(hours=1) and start >= first \
                and (parts[2], query["from"]) not in failed:
            failed.add((parts[2], query["from"]))
            t.status_script.append(502)
    t.before_request = hook


def test_failed_reads_are_vendor_evidence_and_excuse_at_most_two_hours(world):
    """The same 6 of 10 silent — but NextDNS FAILED the first read of each
    of their hours (HTTP 502) before answering them empty: that is evidence
    of a NextDNS-side gap, so ≥ half is enough and the first two hours are
    excused; the third expires the gap and the sites lapse since the first
    hour, grouped under ONE fleet signal."""
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:6]:
        _silence_from(world, pid, first, 48)
    _fail_first_hour_reads(world, ids[:6], first)
    world.run_for(poller, 3 * 3600 + 600)                    # two silent hours read
    assert _lapses(world) == []
    assert first.strftime("%Y-%m-%dT%H:00:00Z") in poller.snapshot()["analytics_gaps"]
    world.run_for(poller, 3600)                              # the third: past the bound
    lapses = _lapses(world)
    assert sorted(p["profile_id"] for p in lapses) == ids[:6]
    assert {p["since"] for p in lapses} == {first.strftime("%Y-%m-%dT%H:00:00Z")}
    assert len(world.events(OPS, EVENT_FLEET)) == 1


def test_empty_answers_alone_are_normal_silence_not_vendor_evidence(world):
    """Half of the sites silent for two hours, NextDNS answering every read
    (empty data arrays): no vendor gap is assumed — the silent sites lapse
    (the owner's rule: only FAILED reads are NextDNS-side evidence)."""
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:5]:
        _silence_from(world, pid, first, 2)
    world.run_for(poller, 3 * 3600 + 600)
    assert sorted(p["profile_id"] for p in _lapses(world)) == ids[:5]
    assert poller.snapshot()["analytics_gaps"] == []


def test_a_two_hour_vendor_side_gap_is_still_excused(world):
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids:
        _silence_from(world, pid, first, 2)
    world.run_for(poller, 6 * 3600)
    assert _lapses(world) == [] and world.events(OPS, EVENT_FLEET) == []
    gaps = poller.snapshot()["analytics_gaps"]
    assert first.strftime("%Y-%m-%dT%H:00:00Z") in gaps
    assert (first + timedelta(hours=1)).strftime("%Y-%m-%dT%H:00:00Z") in gaps


def test_three_silent_hours_everywhere_are_no_longer_a_vendor_gap(world):
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids:
        _silence_from(world, pid, first, 5)
    world.run_for(poller, 8 * 3600)
    assert len(_lapses(world)) == 10
    [fleet] = world.events(OPS, EVENT_FLEET)
    assert _payload(fleet)["sites"] == 10
    # Everything resumed: every site restored, the incident noted as over.
    assert sum(len(world.events(s, EVENT_RESTORED)) for s in (ACME, BAKERY)) == 10
    assert any("reporting again" in n["note_text"] for n in world.notes(OPS, fleet["id"]))


def test_many_zeros_without_vendor_evidence_are_site_outages(world):
    """NextDNS answers explicit zeros (no failed read): 6 of 10
    silent sites are not 'nearly all' — no gap is assumed; they lapse at
    once, and since half the fleet is dark, one fleet signal groups them."""
    ids = _fleet(world)
    world.transport.explicit_zero_rows = True
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:6]:
        _silence_from(world, pid, first, 2)
    world.run_for(poller, 3 * 3600 + 600)
    assert len(_lapses(world)) == 6
    assert poller.snapshot()["analytics_gaps"] == []
    assert len(world.events(OPS, EVENT_FLEET)) == 1


def test_without_an_internal_tenant_the_fleet_outage_is_shown_not_lost(world):
    ids = _fleet(world, internal=False)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:6]:
        _silence_from(world, pid, first, 48)
    world.run_for(poller, 5 * 3600)
    assert len(_lapses(world)) == 6
    outage = poller.snapshot()["fleet_outage"]
    assert outage["sites"] == 6 and outage["watched"] == 10 and outage["tenant"] is None
    adapter = NextDNSSourceAdapter()
    adapter._poller = poller
    assert adapter.card_summary(world.record.id)["fleet_outage_sites"] == 6


# ---------------------------------------------------------------------------
# Third-round findings: only CONSECUTIVE busy zero hours; trickle profiles
# stay pending; a logs-off fleet stays one open incident
# ---------------------------------------------------------------------------

Z = {"default": 0, "blocked": 0, "allowed": 0}


def test_busy_shoulder_hours_either_side_of_a_closed_night_are_not_a_lapse(world):
    """A shop open 13-21 UTC every day; its 12:00 and 22:00 hours are in use
    on 2 days of 3 (so both count as normally busy). One evening the 22:00
    hour is quiet and the next morning the 12:00 hour: filtering never
    stopped — the closed night between them breaks the run."""
    quiet = {(datetime(2026, 9, 16).date(), 22), (datetime(2026, 9, 17).date(), 12),
             (datetime(2026, 9, 30).date(), 22), (datetime(2026, 10, 1).date(), 12)}

    def shop(hour: datetime) -> dict[str, int]:
        if 13 <= hour.hour <= 21:
            return {"default": 400, "blocked": 10, "allowed": 0}
        if hour.hour in (12, 22) and (hour.date(), hour.hour) not in quiet:
            return {"default": 30, "blocked": 0, "allowed": 0}
        return dict(Z)

    world.transport.of("abc123").rate_fn = shop
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 30 * 3600)                     # Wed 12:00 → Thu 18:00
    assert world.events(ACME, EVENT_LAPSED) == []
    assert world.events(ACME, EVENT_RESTORED) == []
    # A real outage over the same night is still caught by the next
    # morning's busy hours — dated from its first normally-busy silent hour.
    t = world.transport
    first = datetime(2026, 10, 1, 22, 0, tzinfo=UTC)    # from Thursday's shoulder hour
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(20)])
    world.run_for(poller, 21 * 3600)                     # → Fri 15:00
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = _payload(lapse)
    assert payload["since"] == "2026-10-01T22:00:00Z"
    assert payload["detected_at"] == "2026-10-02T14:00:00.000Z"


def _trickle(hour: datetime) -> dict[str, int]:
    """24 queries a weekday (13:00-16:59 UTC), none at weekends."""
    if hour.weekday() < 5 and 13 <= hour.hour <= 16:
        return {"default": 6, "blocked": 0, "allowed": 0}
    return dict(Z)


def test_a_trickle_profile_mapped_on_its_quiet_day_is_pending_without_an_alert(world):
    """24 queries a weekday, none at weekends (1-99 a day), mapped on a
    Sunday: 0 in 24 h and ≥ 100 in 7 days — but its NextDNS history says
    Sundays are always silent, and its busiest day is far under 100: a
    low-volume profile, PENDING, no alert at all (owner decision A)."""
    world.transport.of("abc123").rate_fn = _trickle
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 14 * 86400)
    assert world.events(ACME) == []
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "pending" and snap["queries_24h"] < 100


def test_without_history_a_trickle_profile_mapped_on_its_quiet_day_goes_back_to_pending(world):
    """The same, NextDNS refusing its history: the 7-day rule alone gives
    one 'dark before Athena watched' alert — but when it wakes on Monday it
    is a 1-99-a-day profile: PENDING again (a note on that alert, no restore
    alert), never ACTIVE, never a weekly backstop lapse."""
    world.transport.of("abc123").rate_fn = _trickle
    world.transport.series_status["abc123"] = 500
    world.clock.set(datetime(2026, 10, 4, 12, 0, tzinfo=UTC))
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 14 * 86400)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["cause"] == "before_watch"
    assert world.events(ACME, EVENT_RESTORED) == []
    notes = [n["note_text"] for n in world.notes(ACME, lapse["id"])]
    assert any("fewer than 100 in 24 hours" in n and "pending" in n for n in notes)
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "pending" and snap["queries_24h"] < 100


def test_a_before_watch_site_that_really_routes_again_is_restored(world):
    t = world.transport
    t.set_rate("abc123")
    first = hour_of(T0 - timedelta(hours=30))
    t.silence("abc123", *[first + timedelta(hours=h) for h in range(33)])
    world.map(abc123=ACME)                               # dark since yesterday
    poller = world.poller()
    world.run_for(poller, 6 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert _payload(lapse)["cause"] == "before_watch"
    [restored] = world.events(ACME, EVENT_RESTORED)
    assert _payload(restored)["lapse_event_id"] == lapse["id"]
    assert poller.snapshot()["states"]["abc123"]["state"] == "active"


def test_logging_switched_off_on_most_sites_stays_one_open_fleet_incident(world):
    """Logging is turned off at NextDNS on 6 of 10 sites: their lapses are
    'logs_off', and they are still dark — the fleet incident stays open
    (shown on the card) and never says they are 'reporting again'. When
    they really report again, the closing note counts the restored ones."""
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    for pid in ids[:6]:
        _silence_from(world, pid, first, 30)
        world.transport.logs_settings[pid] = {"enabled": False, "retention": 0}
    opened = []
    for _ in range(24 * 6):
        world.run_for(poller, 600)
        opened.append(bool(poller.snapshot()["fleet_outage"]))
    lapses = _lapses(world)
    assert sorted(p["profile_id"] for p in lapses) == ids[:6]
    assert {p["cause"] for p in lapses} == {"logs_off"}
    [fleet] = world.events(OPS, EVENT_FLEET)
    assert True in opened
    assert all(opened[opened.index(True):])              # never closed while silent
    notes = [n["note_text"] for n in world.notes(OPS, fleet["id"])]
    assert not any("reporting again" in n for n in notes)
    for pid in ids[:6]:
        world.transport.logs_settings.pop(pid)
    world.run_for(poller, 12 * 3600)
    assert poller.snapshot()["fleet_outage"] is None
    notes = [n["note_text"] for n in world.notes(OPS, fleet["id"])]
    assert any(n.startswith("6 of the 6 sites are reporting again (0 still silent)")
               for n in notes)
