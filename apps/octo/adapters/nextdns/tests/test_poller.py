"""The NextDNS poller end to end on the real pieces (registry, tenant map,
sink, telemetry store, limiter, client) with only the socket fake, on one
fake clock.

Pinned: nothing polled before a mapping and never an unmapped / ignored /
inactive-tenant profile; the first import back-fills 24 h of SECURITY
blocks only; no log call without a signal reason; coalescing (one alert per
device / root / reason / hour, hits counted, one "seen N times" note);
analytics lag caught by the overlap without duplicates; restart safety (no
duplicate, no gap, a crash between claim and alert); hourly roll-ups that
replace rather than add; remapping routes NEW rows only.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta

import pytest

from apps.octo import paths
from apps.octo.adapters.nextdns import store
from apps.octo.adapters.nextdns.poller import NextDNSPoller, profile_state_key
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line, hour_of
from apps.octo.instances import ignored_tenants, poller_state

ACME = "acme-corp"
BAKERY = "example-bakery"


def _unpolled(world, *pids: str) -> None:
    for pid in pids:
        assert world.transport.calls_for(pid) == [], f"{pid} was polled"


# ---------------------------------------------------------------------------
# What is polled at all
# ---------------------------------------------------------------------------

def test_nothing_is_polled_until_a_profile_is_mapped(world):
    for pid in ("abc123", "def456"):
        world.transport.set_rate(pid)
        world.transport.add_lines(pid, block_line(T0 - timedelta(minutes=5)))
    poller = world.poller()
    report = poller.run_cycle()
    assert report.held and report.discovery
    assert world.transport.paths() == ["/profiles"]           # discovery only
    # Hours later: still only the profile list — once per interval while
    # nothing is mapped (it is the contact that says the key works).
    world.run_for(poller, 3 * 3600)
    assert set(world.transport.paths()) == {"/profiles"}
    assert 3 * 6 - 1 <= len(world.transport.paths()) <= 3 * 6 + 1   # every 10 min
    snap = poller.snapshot()
    assert snap["mapped"] == 0 and snap["known"] == 5
    assert world.events(ACME) == []


def test_unmapped_ignored_and_inactive_tenant_profiles_are_never_polled(world):
    for pid in ("abc123", "abc124", "def456", "tst001", "per001"):
        world.transport.set_rate(pid)
        world.transport.add_lines(pid, block_line(T0 - timedelta(minutes=5)))
    ignored_tenants.set_ignored(world.record.id, [("tst001", "Test Profile")])
    world.map(abc123=ACME, def456=BAKERY)
    reg = sqlite3.connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = ?", (BAKERY,))
    reg.commit()
    reg.close()
    poller = world.poller()
    world.run_for(poller, 3 * 3600)
    assert world.transport.calls_for("abc123")
    _unpolled(world, "abc124", "def456", "tst001", "per001")
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    assert world.events(BAKERY) == []


# ---------------------------------------------------------------------------
# First import
# ---------------------------------------------------------------------------

def test_first_import_backfills_24h_of_security_blocks_only(world):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines(
        "abc123",
        block_line(T0 - timedelta(hours=25), domain="old.bad-example.test"),     # too old
        block_line(T0 - timedelta(hours=23), domain="c2.bad-example.test"),      # high
        block_line(T0 - timedelta(hours=2), domain="ads.example.test",
                   reason="blocklist:oisd", reason_name="OISD"),                 # policy
        block_line(T0 - timedelta(hours=1), domain="vpn.example.test",
                   reason="bypass-methods", reason_name="Bypass Methods"),       # medium
    )
    world.map(abc123=ACME)
    report = world.poller().run_cycle()
    assert report.signals == 2
    rows = world.events(ACME, EVENT_BLOCK)
    assert {r["severity"] for r in rows} == {"high", "medium"}
    domains = {json.loads(r["payload"])["log"]["domain"] for r in rows}
    assert domains == {"c2.bad-example.test", "vpn.example.test"}
    # The headline names the reason and the device — never the domain.
    assert rows[0]["summary"] == "NextDNS blocked a threat-intelligence domain — alice-laptop"
    assert all("bad-example" not in r["summary"] for r in rows)
    # Security only: no hourly back-fill — the roll-up starts at the most
    # recent READABLE closed hour (11:00-12:00 is read from 12:05 on).
    hourly = world.telemetry_rows(ACME, "nextdns_hourly")
    assert [r["hour"] for r in hourly] == ["2026-09-30T10:00:00Z"]
    # The first window was the last 24 hours (the first call of a started
    # poller is the profile list, so the check runs a few seconds after T0).
    assert t.paths()[0] == "/profiles"
    first_reasons = next(c for c in t.calls if c.path.endswith("/analytics/reasons"))
    frm = datetime.fromisoformat(first_reasons.query["from"].replace("Z", "+00:00"))
    to = datetime.fromisoformat(first_reasons.query["to"].replace("Z", "+00:00"))
    assert to - frm == timedelta(hours=24) and to - T0 < timedelta(seconds=10)


def test_no_log_call_without_a_signal_reason(world):
    world.transport.set_rate("abc123", blocked=500)
    world.transport.add_lines("abc123", *[
        block_line(T0 - timedelta(minutes=m), reason="tld:cn", reason_name="CN")
        for m in range(1, 50)
    ])
    world.map(abc123=ACME)
    world.run_for(world.poller(), 2 * 3600)
    assert not any(p.endswith("/logs") for p in world.transport.paths())
    assert world.events(ACME) == []
    assert world.telemetry_rows(ACME, "nextdns_hourly")          # counted, not alerted


# ---------------------------------------------------------------------------
# Coalescing
# ---------------------------------------------------------------------------

def test_one_alert_per_device_domain_reason_and_hour(world):
    t = world.transport
    t.set_rate("abc123")
    h = T0 - timedelta(hours=2)                       # 10:00-11:00
    t.add_lines("abc123",
                *[block_line(h + timedelta(minutes=5 + i)) for i in range(5)],
                block_line(h + timedelta(minutes=20), device_id="D9", device_name="bob-pc"),
                block_line(h + timedelta(minutes=21), domain="x.other-example.test"),
                block_line(h + timedelta(minutes=22), reason="dga", reason_name="DGA"),
                block_line(h + timedelta(minutes=65)))          # next hour
    world.map(abc123=ACME)
    poller = world.poller()
    report = poller.run_cycle()
    assert report.signals == 5 and report.counted == 4
    rows = world.events(ACME, EVENT_BLOCK)
    assert len(rows) == 5
    buckets = list(store.iter_buckets(ACME))
    first = next(b for b in buckets if b["hits"] == 5)
    assert first["event_id"] == rows[0]["id"]
    # The stored alert is never rewritten by later hits.
    assert json.loads(rows[0]["payload"])["log"]["timestamp"] == "2026-09-30T10:05:00.000Z"
    # Hour over (+ interval + overlap): ONE note, once.
    world.clock.advance(1800)
    poller.run_cycle()
    poller.run_cycle()
    notes = world.notes(ACME, rows[0]["id"])
    assert len(notes) == 1 and notes[0]["query_kind"] == "vendor_update"
    assert "Seen 5 times in the hour from 2026-09-30 10:00 UTC" in notes[0]["note_text"]
    # A single-hit bucket gets no note.
    assert world.notes(ACME, rows[1]["id"]) == []
    # The alerts feed's live count.
    from apps.octo.adapters.nextdns import NextDNSSourceAdapter
    suffixes = NextDNSSourceAdapter.presentation_suffixes(
        ACME, [(r["id"], json.loads(r["payload"])) for r in rows])
    assert suffixes == {rows[0]["id"]: (
        "Seen 5 times in the hour from 10:00 UTC — every one blocked; only the first "
        "raised this alert.")}


def test_analytics_lag_is_caught_by_the_overlap_without_duplicates(world):
    t = world.transport
    t.set_rate("abc123")
    t.analytics_lag_sec = 240                         # analytics 4 min behind
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()                                # first import: nothing yet
    world.clock.advance(600)
    # A threat block one minute before the next check: in the logs, not yet
    # in the analytics.
    t.add_lines("abc123", block_line(world.clock.now() - timedelta(minutes=1)))
    report = poller.run_cycle()
    assert report.security_checks == 1 and report.log_pages == 0
    assert world.events(ACME) == []
    world.clock.advance(600)                          # the overlap window now sees it
    report = poller.run_cycle()
    assert report.signals == 1
    for _ in range(3):
        world.clock.advance(600)
        poller.run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    assert list(store.iter_buckets(ACME))[0]["hits"] == 1


# ---------------------------------------------------------------------------
# Restart safety
# ---------------------------------------------------------------------------

def test_a_restart_neither_duplicates_nor_leaves_a_gap(world):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", *[block_line(T0 - timedelta(minutes=30 - i)) for i in range(3)])
    world.map(abc123=ACME)
    first = world.poller()
    first.run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    state = poller_state.load(world.record.id, profile_state_key("abc123"))
    checked_to = state["checked_to"]
    assert checked_to.startswith("2026-09-30T12:00:0")

    # Down for three hours; blocks keep happening — including one inside
    # the overlap of the last check and one in the same bucket as before.
    t.add_lines(
        "abc123",
        block_line(T0 - timedelta(minutes=2)),                        # same bucket (11:xx)
        block_line(T0 + timedelta(minutes=40), domain="a.bad-example.test"),
        block_line(T0 + timedelta(hours=2, minutes=50), domain="b.bad-example.test"),
    )
    world.clock.advance(3 * 3600)
    second = world.poller()                           # a fresh process
    second.run_cycle()
    rows = world.events(ACME, EVENT_BLOCK)
    assert [json.loads(r["payload"])["log"]["domain"] for r in rows] == [
        "c2.bad-example.test", "a.bad-example.test", "b.bad-example.test"]
    hits = {b["hour"]: b["hits"] for b in store.iter_buckets(ACME)}
    assert hits["2026-09-30T11:00:00Z"] == 4
    # The gap was read in ONE window from the persisted mark minus the overlap.
    froms = [c.query["from"] for c in t.calls if c.path.endswith("/analytics/reasons")]
    mark = datetime.fromisoformat(checked_to.replace("Z", "+00:00"))
    assert (mark - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z") in froms
    # And again: nothing new, nothing doubled.
    world.poller().run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 3
    assert {b["hour"]: b["hits"] for b in store.iter_buckets(ACME)} == hits


def test_a_crash_between_the_claim_and_the_alert_is_finished_later(world, monkeypatch):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", block_line(T0 - timedelta(minutes=20)),
                block_line(T0 - timedelta(minutes=10)))
    world.map(abc123=ACME)
    crashing = world.poller()

    def boom(*a, **k):
        raise RuntimeError("fixture: process died")
    monkeypatch.setattr(crashing, "_ingest_block", boom)
    with pytest.raises(RuntimeError):
        crashing.run_cycle()
    [bucket] = list(store.iter_buckets(ACME))
    assert bucket["event_id"] is None                 # claimed, alert not written
    world.clock.advance(600)
    world.poller().run_cycle()
    rows = world.events(ACME, EVENT_BLOCK)
    assert len(rows) == 1
    [bucket] = list(store.iter_buckets(ACME))
    assert bucket["event_id"] == rows[0]["id"] and bucket["hits"] == 2


def test_hourly_rows_are_replaced_never_added(world):
    world.transport.set_rate("abc123", default=900, blocked=40, allowed=2)
    world.transport.add_lines("abc123", block_line(T0 - timedelta(minutes=90)))   # 10:30
    world.map(abc123=ACME)
    world.poller().run_cycle()
    [row] = world.telemetry_rows(ACME, "nextdns_hourly")
    assert (row["queries"], row["blocked"], row["allowed"], row["default_queries"]) == (
        943, 41, 2, 900)
    # Class counts are per REASON (the 40 policy blocks are on two lists).
    assert (row["signal_high"], row["policy_blocked"]) == (1, 80)
    assert json.loads(row["signal_reasons"]) == {"threat-intelligence-feeds": 1}
    # Forget the mark (as a restore of an old registry would) and read again.
    state = poller_state.load(world.record.id, profile_state_key("abc123"))
    state.pop("hour_done")
    poller_state.save(world.record.id, profile_state_key("abc123"), state)
    world.poller().run_cycle()
    [again] = world.telemetry_rows(ACME, "nextdns_hourly")
    assert again["queries"] == 943 and again["blocked"] == 41


def test_a_remapped_profile_sends_new_rows_to_its_new_tenant_only(world):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", block_line(T0 - timedelta(minutes=30)))
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    world.map(abc123=BAKERY)
    t.add_lines("abc123", block_line(T0 + timedelta(minutes=5), domain="new.bad-example.test"))
    world.clock.advance(600)
    poller.run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 1
    [moved] = world.payloads(BAKERY, EVENT_BLOCK)
    assert moved["log"]["domain"] == "new.bad-example.test"


def test_a_log_backlog_is_bounded_per_cycle_and_resumes(world):
    t = world.transport
    t.set_rate("abc123")
    base = T0 - timedelta(hours=6)
    # 2,500 signal lines (one device, one domain → coalesced per hour).
    t.add_lines("abc123", *[block_line(base + timedelta(seconds=8 * i)) for i in range(2500)])
    world.map(abc123=ACME)
    poller = world.poller(max_log_pages_per_profile=1)
    report = poller.run_cycle()
    assert report.log_pages == 1
    state = poller_state.load(world.record.id, profile_state_key("abc123"))
    assert state["logs"]["resume"] is not None
    for _ in range(4):
        world.clock.advance(60)
        poller.run_cycle()
    hours = {b["hour"]: b["hits"] for b in store.iter_buckets(ACME)}
    assert sum(hours.values()) == 2500
    assert len(world.events(ACME, EVENT_BLOCK)) == len(hours) == 6


def test_a_profile_nextdns_no_longer_knows_is_missing_shown_and_rechecked(world):
    """A mapped id NextDNS answers 404 for: one 404 is re-checked next
    interval, the second marks it MISSING (shown, never silent); a missing
    profile is re-probed every pending interval — never in a tight loop."""
    world.transport.set_rate("abc123")
    world.map(abc123=ACME, zzz999=ACME)
    poller = world.poller()
    poller.run_cycle()
    assert len(world.transport.calls_for("zzz999")) == 1       # the first 404
    assert poller.snapshot()["states"]["zzz999"]["missing"] is False
    cycles = world.run_for(poller, 3 * 3600)
    assert cycles < 60                                          # never a tight loop
    assert len(world.transport.calls_for("zzz999")) == 2       # the second 404
    snap = poller.snapshot()
    assert snap["states"]["zzz999"]["missing"] is True and snap["missing"] == 1
    assert "HTTP 404" in snap["states"]["zzz999"]["problem"]
    world.run_for(poller, 4 * 3600)                             # re-probed after 6 h
    assert len(world.transport.calls_for("zzz999")) == 3


def test_the_sink_identity_would_catch_a_replayed_record(world):
    """Belt and braces: the same record offered twice is one row."""
    from apps.octo.adapters.nextdns import NextDNSSourceAdapter
    from apps.octo.ingest import SqliteIngestSink

    world.map(abc123=ACME)
    poller = world.poller()
    payload = {
        "vendor_event_id": "x", "kind": "security_block", "profile_id": "abc123",
        "profile_name": "Acme Corp Office", "log": block_line(T0),
        "signal": {"level": "high", "reason_id": "threat-intelligence-feeds",
                   "reason_label": "a threat-intelligence domain",
                   "bucket_hour": "2026-09-30T12:00:00Z"},
    }
    event = NextDNSSourceAdapter().extract_event(payload)
    sink = SqliteIngestSink(publish_to_stream=False)
    assert not sink.ingest(ACME, "nextdns", event).duplicate
    assert sink.ingest(ACME, "nextdns", event).duplicate
    assert poller is not None
    _ = hour_of


def test_poller_never_waits_for_a_real_clock(world):
    """Sanity: the whole module runs on the fake clock — a 6-hour
    simulation completes instantly and every call is spaced."""
    world.transport.set_rate("abc123")
    world.map(abc123=ACME)
    world.run_for(world.poller(), 6 * 3600)
    assert min(world.transport.gaps()) >= 2.0
    assert all(c.status == 200 for c in world.transport.calls)
    assert isinstance(NextDNSPoller, type)
