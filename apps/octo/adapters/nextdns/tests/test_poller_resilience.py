"""The NextDNS poller when things go wrong — failures stay with the profile
that has them, and nothing fails silently. Real pieces, fake socket, one
fake clock (conftest.py).

Pinned (fix round 2026-09-30):
  * a single 404 is re-checked, not permanent; two make the profile MISSING
    only if GET /profiles no longer lists it — shown (snapshot, protection
    rows, source health) with ONE lapse signal for a profile that was
    active — and a missing profile is re-probed on the pending cadence and
    at once when the profile list shows it again; a 404 on a profile the
    list still shows is a vendor-side failure (backoff, no lapse), and many
    profiles lost at once are ONE fleet incident; a restore after such a
    lapse is never dated before it;
    a missing profile (with or without a log backlog) never makes the
    poller spin;
  * one profile's timeouts, 403s or broken tenant store never stop the
    other profiles' security checks, and a local store fault is never
    reported as a NextDNS failure; a profile NextDNS keeps refusing (403)
    while still listing it has ALL its reads held back — the other
    profiles' roll-ups stay current and their lapses are detected on time —
    and after repeated 403s on it alone it shows its own problem ("NextDNS
    refuses this profile — check sharing/permissions"), never "rate
    limiting" for the whole key — also when 2 or 3 listed profiles are
    refused at once (round 5: each one's 403 no longer resets the others);
  * a long throttle stays a throttle — never "the key no longer works";
  * a failing hourly write backs off instead of re-reading every second;
  * a log cursor that never ends cannot hold the limiter;
  * a spent cycle page budget never skips a millisecond of lines;
  * a profile unmapped mid-cycle is dropped at once, and an unreadable
    tenant map polls nothing;
  * the card shows the new profiles as "checking" from the first call;
  * at 260 active profiles the stretch is detected and the roll-up lag shown.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import timedelta

import pytest

from apps.octo.adapters.nextdns import NextDNSSourceAdapter, store
from apps.octo.adapters.nextdns.poller import profile_state_key
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK, EVENT_LAPSED, EVENT_RESTORED
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line, hour_of
from apps.octo.client_provisioning import create_client
from apps.octo.instances import poller_state, tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"


def _reasons_calls(world, pid: str) -> int:
    return sum(1 for c in world.transport.calls_for(pid) if c.path.endswith("/analytics/reasons"))


def _protection(poller) -> dict:
    adapter = NextDNSSourceAdapter()
    adapter._poller = poller          # the running adapter's read side
    return adapter.protection(None)


# ---------------------------------------------------------------------------
# 404: recoverable, visible, never silent
# ---------------------------------------------------------------------------

def test_one_404_blip_does_not_stop_monitoring(world):
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 600)                          # active
    t.profile_status["abc123"] = 404                    # a vendor-side blip…
    world.run_for(poller, 600)
    assert poller.snapshot()["states"]["abc123"]["missing"] is False
    del t.profile_status["abc123"]                      # …over
    t.add_lines("abc123", block_line(T0 + timedelta(hours=2)))
    world.run_for(poller, 6 * 3600)
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    snap = poller.snapshot()["states"]["abc123"]
    assert snap["state"] == "active" and snap["missing"] is False and snap["problem"] is None
    assert world.events(ACME, EVENT_LAPSED) == []


def test_a_profile_gone_for_good_is_missing_shown_and_one_lapse_is_raised(world):
    t = world.transport
    t.set_rate("abc123")
    t.set_rate("abc124")
    world.map(abc123=ACME, abc124=ACME)
    poller = world.poller()
    world.run_for(poller, 600)
    t.profile_status["abc123"] = 404                    # deleted / un-shared:
    t.profiles = [p for p in t.profiles if p["id"] != "abc123"]   # …gone from the list too
    world.run_for(poller, 3 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = json.loads(lapse["payload"])
    assert payload["cause"] == "not_visible"
    shown = NextDNSSourceAdapter.present_event(payload)
    assert "no longer shows this profile to Athena's API key" in shown.detail
    snap = poller.snapshot()
    assert snap["missing"] == 1 and snap["states"]["abc123"]["missing"] is True
    assert snap["states"]["abc123"]["state"] == "lapsed"
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["abc123"]["missing"] is True and "HTTP 404" in rows["abc123"]["problem"]
    # No repeats, and only the 6-hourly re-probe — the other profile goes on.
    calls = len(t.calls_for("abc123"))
    world.run_for(poller, 5 * 3600)
    assert len(world.events(ACME, EVENT_LAPSED)) == 1
    assert len(t.calls_for("abc123")) - calls <= 1
    assert _reasons_calls(world, "abc124") >= 40


def test_a_missing_profile_comes_back_when_the_list_shows_it_or_on_the_reprobe(world):
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 600)
    listed = list(t.profiles)
    t.profile_status["abc123"] = 404
    t.profiles = [p for p in t.profiles if p["id"] != "abc123"]
    world.run_for(poller, 3600)
    assert poller.snapshot()["states"]["abc123"]["missing"] is True
    del t.profile_status["abc123"]
    t.profiles = listed
    # A restart: the first call is the profile list; it shows the profile
    # → re-probed in the same cycle, not 6 h later.
    fresh = world.poller()
    fresh.run_cycle()
    snap = fresh.snapshot()["states"]["abc123"]
    assert snap["missing"] is False and snap["problem"] is None
    # It was active when it vanished → LAPSED; queries resume → restored.
    world.run_for(fresh, 3 * 3600)
    assert fresh.snapshot()["states"]["abc123"]["state"] == "active"
    t.add_lines("abc123", block_line(world.clock.now() + timedelta(minutes=5)))
    world.run_for(fresh, 1800)
    assert len(world.events(ACME, EVENT_BLOCK)) == 1


def test_a_missing_profile_with_a_log_backlog_never_spins(world):
    t = world.transport
    t.set_rate("abc123")
    base = T0 - timedelta(hours=6)
    t.add_lines("abc123", *[block_line(base + timedelta(seconds=8 * i)) for i in range(2500)])
    world.map(abc123=ACME)
    poller = world.poller(max_log_pages_per_profile=1)
    poller.run_cycle()
    assert poller_state.load(world.record.id, profile_state_key("abc123"))["logs"]
    t.profile_status["abc123"] = 404
    t.profiles = [p for p in t.profiles if p["id"] != "abc123"]
    before = len(t.calls)
    cycles = world.run_for(poller, 3600)
    assert cycles < 30, cycles
    assert len(t.calls) - before <= 10
    # The backlog's /logs 404 at most twice (then MISSING) — never every cycle.
    assert sum(1 for c in t.calls[before:] if c.path.endswith("/logs")) <= 2
    assert "logs" not in poller_state.load(world.record.id, profile_state_key("abc123"))


# ---------------------------------------------------------------------------
# One profile's failure never stops the others
# ---------------------------------------------------------------------------

def test_one_profiles_timeouts_do_not_stop_the_fleet(world):
    t = world.transport
    for pid in ("abc123", "abc124", "def456"):
        t.set_rate(pid)
    world.map(abc123=ACME, abc124=ACME, def456=BAKERY)
    poller = world.poller()
    world.run_for(poller, 600)
    t.profile_timeout.add("abc124")
    t.add_lines("def456", block_line(T0 + timedelta(hours=1)))
    tried = len(t.calls_for("abc124"))
    world.run_for(poller, 4 * 3600)
    assert len(world.events(BAKERY, EVENT_BLOCK)) == 1
    assert _reasons_calls(world, "abc123") >= 20 and _reasons_calls(world, "def456") >= 20
    # Backed off (60 s doubling to 15 min), not every cycle.
    assert len(t.calls_for("abc124")) - tried <= 22
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert "timed out" in (rows["abc124"]["problem"] or "") or "Timeout" in (
        rows["abc124"]["problem"] or "")
    assert world.instance_row()["status"] == "running"


def test_one_tenants_broken_store_does_not_stop_the_fleet(world, monkeypatch):
    t = world.transport
    t.set_rate("abc123")
    t.set_rate("def456")
    world.map(abc123=ACME, def456=BAKERY)
    real = store.count_hits

    def broken(slug, *a, **k):
        if slug == BAKERY:
            raise sqlite3.DatabaseError("fixture: database disk image is malformed")
        return real(slug, *a, **k)
    monkeypatch.setattr(store, "count_hits", broken)
    t.add_lines("def456", *[block_line(T0 + timedelta(minutes=m)) for m in (1, 30, 90)])
    t.add_lines("abc123", block_line(T0 + timedelta(hours=2)))
    poller = world.poller()
    world.run_for(poller, 4 * 3600)
    assert len(world.events(ACME, EVENT_BLOCK)) == 1          # the other tenant alerted
    assert _reasons_calls(world, "abc123") >= 20
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["def456"]["problem_kind"] == "store"
    assert "local fault in Athena, not NextDNS" in rows["def456"]["problem"]
    row = world.instance_row()
    assert row["status"] == "running" and "Could not read from NextDNS" not in (
        row["status_detail"] or "")
    # Nothing lost: the store works again → the backlog is read and alerted.
    monkeypatch.setattr(store, "count_hits", real)
    world.run_for(poller, 2 * 3600)
    assert len(world.events(BAKERY, EVENT_BLOCK)) >= 1


def test_a_refused_profile_the_list_no_longer_shows_is_not_accessible(world):
    t = world.transport
    for pid in ("abc123", "abc124", "def456"):
        t.set_rate(pid)
    world.map(abc123=ACME, abc124=ACME, def456=BAKERY)
    poller = world.poller()
    world.run_for(poller, 600)                          # all three active
    t.profile_status["abc124"] = 403                    # un-shared from the account:
    t.profiles = [p for p in t.profiles if p["id"] != "abc124"]   # …and gone from the list
    t.add_lines("def456", block_line(T0 + timedelta(hours=1)))
    world.run_for(poller, 4 * 3600)
    assert len(world.events(BAKERY, EVENT_BLOCK)) == 1
    assert _reasons_calls(world, "abc123") >= 15 and _reasons_calls(world, "def456") >= 15
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["abc124"]["problem_kind"] == "access"
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert json.loads(lapse["payload"])["cause"] == "not_accessible"
    row = world.instance_row()
    assert row["status"] == "running"
    assert "Disable this integration" not in (row["status_detail"] or "")
    assert len(t.calls_for("abc124")) < 12              # re-probed rarely, never a loop


def test_a_refused_profile_still_on_the_list_is_throttling_not_a_lapse(world):
    """A 403 on one profile while NextDNS still LISTS it is read as rate
    limiting at first (partial throttling of a busy key): backoff, no
    'not accessible', no lapse — and the list is asked at most once per
    profile per 30 minutes. When it keeps coming back on that profile alone
    it is the profile's own problem ('refused'), still no lapse."""
    t = world.transport
    for pid in ("abc123", "abc124", "def456"):
        t.set_rate(pid)
    world.map(abc123=ACME, abc124=ACME, def456=BAKERY)
    poller = world.poller()
    world.run_for(poller, 600)
    t.profile_status["abc124"] = 403
    lists_before = t.paths().count("/profiles")
    world.run_for(poller, 4 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == []
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["abc124"]["problem_kind"] == "refused" and rows["abc124"]["state"] == "active"
    assert _reasons_calls(world, "abc123") >= 15 and _reasons_calls(world, "def456") >= 15
    assert t.paths().count("/profiles") - lists_before <= 4 * 2 + 1
    assert world.instance_row()["status"] == "running"


def test_a_profile_nextdns_keeps_refusing_never_stalls_the_fleets_rollups(world):
    """One LISTED profile answers HTTP 403 for hours (its data no longer
    shared with the account; the key itself is fine) while another site
    has a real outage. The refused profile's hourly reads are held back
    too, so every other profile's roll-ups stay current and the real
    outage lapses on time; after repeated 403s on that profile alone it
    shows its own problem — the whole key is not called rate limited."""
    t = world.transport
    sites = {"abc123": ACME, "abc124": ACME, "def456": BAKERY, "tst001": BAKERY}
    for pid, slug in sites.items():
        t.set_rate(pid)
        world.seed_baseline(pid, slug)
    world.map(**sites)
    poller = world.poller()
    world.run_for(poller, 3600)
    t.profile_status["abc124"] = 403                    # refused, still listed
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence("def456", *[first + timedelta(hours=h) for h in range(8)])
    c0 = len(t.calls)
    world.run_for(poller, 6 * 3600)
    latest = (hour_of(world.clock.now() - timedelta(minutes=5))
              - timedelta(hours=1)).strftime("%Y-%m-%dT%H:00:00Z")
    done = {}
    for slug in (ACME, BAKERY):
        for r in world.telemetry_rows(slug, "nextdns_hourly"):
            done[r["profile_id"]] = max(done.get(r["profile_id"], ""), r["hour"])
    # The OTHER profiles' roll-ups are current…
    assert {p: done[p] for p in ("abc123", "def456", "tst001")} == {
        "abc123": latest, "def456": latest, "tst001": latest}
    # …and the real outage elsewhere lapsed on time.
    [lapse] = world.events(BAKERY, EVENT_LAPSED)
    payload = json.loads(lapse["payload"])
    assert payload["profile_id"] == "def456"
    assert payload["since"] == first.strftime("%Y-%m-%dT%H:00:00Z")
    assert payload["detected_at"] == (first + timedelta(hours=2)).strftime(
        "%Y-%m-%dT%H:00:00.000Z")
    # The refused profile: its own problem, no lapse, retried rarely.
    snap = poller.snapshot()
    st = snap["states"]["abc124"]
    assert st["problem_kind"] == "refused" and st["state"] == "active" and not st["missing"]
    assert "NextDNS refuses this profile — check sharing/permissions" in st["problem"]
    assert world.events(ACME, EVENT_LAPSED) == []
    assert sum(1 for c in t.calls[c0:] if c.path.startswith("/profiles/abc124")) <= 9
    assert snap["rollup_lag_hours"] <= 1 and not snap["throttled"]
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["abc124"]["problem_kind"] == "refused"
    row = world.instance_row()
    assert row["status"] == "running" and "rate limiting" not in (row["status_detail"] or "")
    assert _reasons_calls(world, "abc123") >= 30 and _reasons_calls(world, "tst001") >= 30
    # NextDNS answers it again: the problem clears, its roll-ups catch up.
    del t.profile_status["abc124"]
    world.run_for(poller, 2 * 3600)
    st = poller.snapshot()["states"]["abc124"]
    assert st["problem"] is None and st["state"] == "active"
    assert world.events(ACME, EVENT_LAPSED) == []


def test_intermittent_403s_across_the_key_never_lapse_a_site(world):
    """Another tool on the same key keeps it near its limit for 40 minutes:
    every other call answers 403. No site is 'not accessible'."""
    t = world.transport
    for pid in ("abc123", "abc124", "def456", "tst001"):
        t.set_rate(pid)
    world.map(abc123=ACME, abc124=ACME, def456=BAKERY, tst001=BAKERY)
    poller = world.poller()
    world.run_for(poller, 2 * 3600)
    n = {"i": 0}
    start = world.clock.monotonic()

    def flaky(path, query):
        if world.clock.monotonic() - start < 40 * 60:
            n["i"] += 1
            if n["i"] % 2 == 0:
                t.throttle_next = 1
    t.before_request = flaky
    world.run_for(poller, 3 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == [] and world.events(BAKERY, EVENT_LAPSED) == []
    snap = poller.snapshot()["states"]
    assert all(v["problem_kind"] != "access" and v["state"] == "active" for v in snap.values())


def test_a_throttle_longer_than_an_hour_is_never_called_a_dead_key(world):
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 2 * 3600)                     # the key works
    t.force_status = 403                                # …then NextDNS refuses everything
    details, throttled = [], []
    end = world.clock.monotonic() + 3 * 3600
    while world.clock.monotonic() < end:
        wait = poller.cycle_with_reporting()
        details.append(world.instance_row()["status_detail"] or "")
        throttled.append(poller.snapshot()["throttled"])
        assert world.instance_row()["status"] == "running"
        world.clock.advance(max(1.0, wait))
    assert all("Disable this integration" not in d for d in details)
    assert "for over an hour" in details[-1]
    assert all(throttled[1:])
    # The limiter keeps backing off for every caller (at its 10-minute cap).
    gaps = world.transport.gaps()[-5:]
    assert min(gaps) >= 590
    t.force_status = None
    world.clock.advance(700)
    poller.cycle_with_reporting()
    assert not poller.snapshot()["throttled"]


def test_a_failing_hourly_write_backs_off(world, monkeypatch):
    t = world.transport
    t.set_rate("abc123")
    t.set_rate("def456")
    world.map(abc123=ACME, def456=BAKERY)
    real = store.upsert_hourly

    def broken(slug, *a, **k):
        if slug == BAKERY:
            raise sqlite3.OperationalError("fixture: unable to open database file")
        return real(slug, *a, **k)
    monkeypatch.setattr(store, "upsert_hourly", broken)
    poller = world.poller()
    cycles = world.run_for(poller, 3600)
    hourly_status = [c for c in t.calls_for("def456") if c.path.endswith("/analytics/status")
                     and c.query["to"][11:13] != c.query["from"][11:13]
                     and c.query["to"][:10] == c.query["from"][:10]]
    assert len(hourly_status) <= 6, len(hourly_status)
    assert cycles < 40, cycles
    assert world.telemetry_rows(ACME, "nextdns_hourly")
    rows = {r["profile_id"]: r for r in _protection(poller)["profiles"]}
    assert rows["def456"]["problem_kind"] == "store"


# ---------------------------------------------------------------------------
# Log pulls: bounded progress
# ---------------------------------------------------------------------------

def test_a_cursor_that_never_ends_cannot_hold_the_limiter(world, caplog):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", *[block_line(T0 - timedelta(minutes=50 - i)) for i in range(20)])
    t.stuck_cursor = "0"
    world.map(abc123=ACME)
    caplog.set_level(logging.WARNING, logger="apps.octo.adapters.nextdns.poller")
    poller = world.poller()
    before = world.clock.monotonic()
    world.run_for(poller, 3600)
    logs = [c for c in t.calls if c.path.endswith("/logs")]
    assert len(logs) <= 3, len(logs)
    assert len(t.calls) < 200                            # the limiter is not pinned
    assert any("same page cursor" in r.getMessage() for r in caplog.records)
    assert "logs" not in poller_state.load(world.record.id, profile_state_key("abc123"))
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    assert world.clock.monotonic() - before >= 3600


def test_a_spent_cycle_budget_never_skips_a_millisecond(world):
    t = world.transport
    for pid in ("abc123", "def456"):
        t.set_rate(pid)
        t.add_lines(pid, *[block_line(T0 - timedelta(minutes=40 - i)) for i in range(5)])
    world.map(abc123=ACME, def456=BAKERY)
    poller = world.poller(max_log_pages_per_cycle=1)
    poller.run_cycle()
    state = {pid: poller_state.load(world.record.id, profile_state_key(pid))
             for pid in ("abc123", "def456")}
    pulled = [pid for pid in ("abc123", "def456") if state[pid].get("logs") is None]
    starved = [pid for pid in ("abc123", "def456") if state[pid].get("logs") is not None]
    assert len(pulled) == 1 and len(starved) == 1
    window = state[starved[0]]["logs"]
    assert window["resume"] is None                     # no page read → nothing moved
    world.clock.advance(60)
    poller.run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 1 and len(world.events(BAKERY, EVENT_BLOCK)) == 1


# ---------------------------------------------------------------------------
# The mapping is re-read before every profile task
# ---------------------------------------------------------------------------

def test_a_profile_unmapped_mid_cycle_is_dropped_at_once(world):
    t = world.transport
    for pid in ("abc123", "per001"):
        t.set_rate(pid)
        t.add_lines(pid, *[block_line(T0 - timedelta(hours=h)) for h in (1, 3, 5)])
    world.map(abc123=ACME, per001=ACME)                 # a personal profile, by mistake
    seen: list[str] = []

    def unmap_on_first_per001_call(path, query):
        if path.startswith("/profiles/per001") and not seen:
            seen.append(path)
            world.map(abc123=ACME)                      # the admin fixes it
    t.before_request = unmap_on_first_per001_call
    poller = world.poller()
    poller.run_cycle()
    assert len(t.calls_for("per001")) == 1              # the call already in flight only
    assert all(json.loads(e["payload"])["profile_id"] == "abc123"
               for e in world.events(ACME, EVENT_BLOCK))
    assert not [r for r in world.telemetry_rows(ACME, "nextdns_hourly")
                if r["profile_id"] == "per001"]
    assert "per001" not in poller.snapshot()["states"]


def test_an_unreadable_tenant_map_polls_nothing(world, monkeypatch):
    world.transport.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    before = len(world.transport.calls)

    def locked(_instance_id):
        raise sqlite3.OperationalError("fixture: database is locked")
    monkeypatch.setattr(tenant_map, "get_mappings", locked)
    world.clock.advance(600)
    report = poller.run_cycle()
    assert report.held and len(world.transport.calls) == before


# ---------------------------------------------------------------------------
# The card during the first cycle; the stretch at 260 profiles
# ---------------------------------------------------------------------------

def test_the_card_shows_new_profiles_as_checking_from_the_first_call(world):
    ids = [f"p{n:05d}" for n in range(6)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"} for pid in ids]
    for pid in ids:
        world.transport.set_rate(pid)
    tenant_map.set_mappings(world.record.id, [TenantMapping(pid, ACME, None, "manual")
                                              for pid in ids])
    poller = world.poller()
    seen: list[dict] = []
    world.transport.before_request = lambda path, q: seen.append(poller.snapshot()["counts"])
    poller.run_cycle()
    assert seen[1]["new"] == 6                          # the first classification call
    assert seen[-1]["active"] + seen[-1]["new"] == 6
    assert seen[-1]["active"] >= 5


def test_260_active_profiles_are_flagged_as_stretched_with_the_rollup_lag(world, caplog):
    ids = [f"p{n:05d}" for n in range(260)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"} for pid in ids]
    for pid in ids:
        world.transport.set_rate(pid)
    create_client("globex", "Globex")
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(pid, (ACME, BAKERY, "globex")[i % 3], None, "manual")
        for i, pid in enumerate(ids)])
    caplog.set_level(logging.WARNING, logger="apps.octo.adapters.nextdns.poller")
    poller = world.poller()
    poller.run_cycle()                                   # classifies all 260
    report = poller.run_cycle()
    assert report.stretched
    assert poller.planned_calls_per_hour()["total"] * 2.0 > 3600 * 0.9
    assert [r for r in caplog.records if "the cycle stretches" in r.getMessage()]
    assert "rollup_lag_hours" in poller.snapshot()
    assert min(world.transport.gaps()) >= 2.0


@pytest.mark.parametrize("active,stretched", [(53, False), (200, False)])
def test_the_measured_fleet_sizes_fit(world, active, stretched):
    ids = [f"p{n:05d}" for n in range(active)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"} for pid in ids]
    for pid in ids:
        world.transport.set_rate(pid)
    tenant_map.set_mappings(world.record.id, [TenantMapping(pid, ACME, None, "manual")
                                              for pid in ids])
    poller = world.poller()
    poller.run_cycle()
    assert poller.run_cycle().stretched is stretched


def test_a_looping_searcher_never_holds_back_the_pollers_security_checks(world):
    """An analyst (or a script) searching as fast as the API allows, while
    the poller runs: the searches are refused once the hourly budget is
    used, and every profile's security check still runs every interval."""
    from apps.octo.adapters.nextdns.adapter import INVESTIGATION_CALLS_PER_HOUR
    from apps.octo.adapters.nextdns.client import NextDNSBusyError

    t = world.transport
    for pid in ("abc123", "def456"):
        t.set_rate(pid)
    world.map(abc123=ACME, def456=BAKERY)
    poller = world.poller()
    adapter = NextDNSSourceAdapter()
    adapter._client = poller._client          # the running adapter shares the client
    refused = 0
    end = world.clock.monotonic() + 2 * 3600
    while world.clock.monotonic() < end:
        delay = poller.cycle_with_reporting()
        for _ in range(5):
            try:
                now = world.clock.now()
                adapter.investigate([("abc123", "a"), ("def456", "b")],
                                    since=now - timedelta(days=7), until=now,
                                    domain="x.example.test", device=None, status=None,
                                    limit=100)
            except NextDNSBusyError:
                refused += 1
        world.clock.advance(max(1.0, delay))
    searched = [c for c in t.calls if "search" in c.query]
    assert len(searched) <= 2 * INVESTIGATION_CALLS_PER_HOUR + 2
    assert refused > 0
    for pid in ("abc123", "def456"):
        # Security checks (not the hourly roll-up's 1-hour reasons reads).
        checks = sorted(c.at for c in t.calls_for(pid) if c.path.endswith("/analytics/reasons")
                        and not (c.query["from"][14:] == c.query["to"][14:] == "00:00.000Z"))
        assert _reasons_calls(world, pid) >= 11, pid
        gaps = [b - a for a, b in zip(checks, checks[1:])]
        assert not gaps or max(gaps) <= 700, (pid, max(gaps))


# ---------------------------------------------------------------------------
# Third-round findings: a 404 on a listed profile is a vendor failure; a mass
# loss of visibility is ONE fleet incident; a restore is never back-dated
# ---------------------------------------------------------------------------

OPS = "msp-ops"
EVENT_FLEET = "nextdns.fleet_dns_outage"


def _fleet(world, n: int = 10) -> list[str]:
    ids = [f"q{i:05d}" for i in range(n)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"}
                                for pid in ids]
    for i, pid in enumerate(ids):
        world.transport.set_rate(pid)
        world.seed_baseline(pid, ACME if i % 2 else BAKERY)
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(pid, ACME if i % 2 else BAKERY, f"Site {pid}", "manual")
        for i, pid in enumerate(ids)])
    create_client(OPS, "MSP Operations", kind="internal")
    return ids


def _all(world, event_type: str) -> list[dict]:
    return [json.loads(r["payload"]) for s in (ACME, BAKERY) for r in world.events(s, event_type)]


def test_a_short_404_storm_on_profiles_nextdns_still_lists_is_no_lapse(world):
    ids = _fleet(world)
    poller = world.poller()
    world.run_for(poller, 3600)
    t = world.transport
    lists_before = t.paths().count("/profiles")
    for pid in ids:
        t.profile_status[pid] = 404                     # listed all along
    world.run_for(poller, 25 * 60)
    snap = poller.snapshot()["states"]
    assert not any(v["missing"] for v in snap.values())
    assert any(v["problem_kind"] == "not_found" for v in snap.values())
    t.profile_status.clear()
    world.run_for(poller, 8 * 3600)
    assert _all(world, EVENT_LAPSED) == [] and _all(world, EVENT_RESTORED) == []
    assert world.events(OPS, EVENT_FLEET) == []
    # The list is asked at most once per profile per 30 minutes.
    assert t.paths().count("/profiles") - lists_before <= len(ids)
    snap = poller.snapshot()["states"]
    assert all(v["state"] == "active" and v["problem"] is None for v in snap.values())


def test_losing_sight_of_most_profiles_at_once_is_one_fleet_incident(world):
    """The account stops sharing 6 of 10 profiles with the key (404, gone
    from GET /profiles): 6 'not visible' lapses grouped under ONE fleet
    signal (their L1 notes 'pattern', not 6 escalations)."""
    from apps.octo.agent.worker import process_tenant_once

    ids = _fleet(world)
    for slug in (ACME, BAKERY, OPS):
        process_tenant_once(slug)
    poller = world.poller()
    world.run_for(poller, 3600)
    t = world.transport
    for pid in ids[:6]:
        t.profile_status[pid] = 404
    t.profiles = [p for p in t.profiles if p["id"] not in ids[:6]]
    world.run_for(poller, 3600)
    lapses = _all(world, EVENT_LAPSED)
    assert sorted(p["profile_id"] for p in lapses) == ids[:6]
    assert {p["cause"] for p in lapses} == {"not_visible"}
    assert all(p["fleet"]["sites"] == 6 and p["fleet"]["watched"] == 10 for p in lapses)
    [fleet] = world.events(OPS, EVENT_FLEET)
    assert json.loads(fleet["payload"])["sites"] == 6
    for slug in (ACME, BAKERY, OPS):
        process_tenant_once(slug)
    for slug in (ACME, BAKERY):
        for row in world.events(slug, EVENT_LAPSED):
            [l1] = [n for n in world.notes(slug, row["id"]) if n["query_kind"] == "auto_enrich"]
            assert l1["disposition"] == "pattern"
    world.run_for(poller, 3 * 3600)
    assert poller.snapshot()["fleet_outage"]["sites"] == 6     # still open: still unseen


def test_a_restore_after_a_visibility_lapse_is_never_dated_before_it(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 3600)
    keep = list(t.profiles)
    t.profile_status["abc123"] = 404
    t.profiles = [p for p in t.profiles if p["id"] != "abc123"]
    world.run_for(poller, 3 * 3600)
    t.profile_status.clear()
    t.profiles = keep
    world.run_for(poller, 12 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    [restored] = world.events(ACME, EVENT_RESTORED)
    lp, rp = json.loads(lapse["payload"]), json.loads(restored["payload"])
    assert lp["cause"] == "not_visible"
    assert rp["detected_at"] > lp["detected_at"]
    assert rp["restored_hour"] > lp["detected_at"]
    notes = [n["note_text"] for n in world.notes(ACME, lapse["id"])]
    assert not any(f"from {lp['detected_at'][:10]} 12:00 UTC" in n for n in notes)


@pytest.mark.parametrize("refused", [2, 3])
def test_several_listed_profiles_refused_at_once_each_show_their_own_problem(world, refused):
    """Several LISTED profiles answer HTTP 403 at once (one owner account
    stopped sharing them). Each one's 403 is "another refusal on the key"
    for the others — yet each is refused alone in its own right: each shows
    'refused' (never the whole key rate limited), none is counted in the
    roll-up lag, the other profiles' roll-ups stay current and a real
    outage elsewhere lapses on time."""
    ids = _fleet(world)
    t = world.transport
    poller = world.poller()
    world.run_for(poller, 3600)
    bad = [ids[0], ids[3], ids[6]][:refused]
    for pid in bad:
        t.profile_status[pid] = 403
    first = hour_of(world.clock.now()) + timedelta(hours=1)
    t.silence(ids[5], *[first + timedelta(hours=h) for h in range(8)])
    world.run_for(poller, 6 * 3600)
    snap = poller.snapshot()
    assert [snap["states"][p]["problem_kind"] for p in bad] == ["refused"] * refused
    assert snap["rollup_lag_hours"] == 0 and not snap["throttled"]
    latest = (hour_of(world.clock.now() - timedelta(minutes=5))
              - timedelta(hours=1)).strftime("%Y-%m-%dT%H:00:00Z")
    assert {p: poller._profiles[p].hour_done for p in ids if p not in bad} == {
        p: latest for p in ids if p not in bad}
    [lapse] = _all(world, EVENT_LAPSED)
    assert lapse["profile_id"] == ids[5]
    assert lapse["since"] == first.strftime("%Y-%m-%dT%H:00:00Z")
    assert lapse["detected_at"] == (first + timedelta(hours=2)).strftime(
        "%Y-%m-%dT%H:00:00.000Z")
    # From then on the key is never called rate limited for them.
    details = set()
    end = world.clock.monotonic() + 2 * 3600
    while world.clock.monotonic() < end:
        delay = poller.cycle_with_reporting()
        details.add(world.instance_row()["status_detail"] or "")
        world.clock.advance(max(1.0, min(delay, end - world.clock.monotonic())))
    assert all("rate limiting" not in d for d in details), details
    assert world.instance_row()["status"] == "running"
    assert sum(1 for c in t.calls if c.status == 403
               and world.clock.monotonic() - c.at <= 2 * 3600) <= 3 * refused
