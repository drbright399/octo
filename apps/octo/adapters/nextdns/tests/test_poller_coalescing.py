"""The owner's coalescing rule (Rick, 2026-09-30, "split by severity") and
the live fact it rests on — real pieces, fake socket, one fake clock.

  * HIGH = one alert per (profile, device, ROOT domain, reason) per clock
    hour; DGA = per (profile, device, reason) per hour across domains;
    MEDIUM / LOW = ONE alert per (profile, device, reason) per UTC DAY
    whatever the domain, the note counting lookups and distinct domains
    with masked samples — the busy AI-threat site ends up at about one
    alert per device per reason per day (it was 468 a day);
  * analytics/reasons counts EVERY reason of a multi-reason block (verified
    live), so a signal behind a blocklist still triggers the log pull.
"""
from __future__ import annotations

import json
import random
from datetime import timedelta

from apps.octo.adapters.nextdns import NextDNSSourceAdapter, store
from apps.octo.adapters.nextdns import poller as poller_module
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line

ACME = "acme-corp"


def _payload(row) -> dict:
    return json.loads(row["payload"])


# ---------------------------------------------------------------------------
# Coalescing: split by severity
# ---------------------------------------------------------------------------

def test_medium_reasons_are_one_alert_per_device_and_reason_per_day_whatever_the_domain(world):
    t = world.transport
    t.set_rate("abc123")
    start = T0.replace(hour=2)                               # today, 02:00 UTC
    t.add_lines("abc123", *[
        block_line(start + timedelta(minutes=10 * i), domain=f"w{i}.suspect{i}-example.test",
                   reason="ai-threat-detection", reason_name="AI-Driven Threat Detection")
        for i in range(30)
    ], *[
        block_line(start + timedelta(minutes=7 * i), domain=f"z{i}.suspect-example.test",
                   reason="ai-threat-detection", reason_name="AI-Driven Threat Detection",
                   device_id="D2B3C4", device_name="bob-pc")
        for i in range(5)
    ], *[
        block_line(start + timedelta(minutes=33 * i), domain=f"n{i}.fresh{i}-example.test",
                   reason="nrd", reason_name="Newly Registered Domains")
        for i in range(3)
    ])
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    alerts = world.events(ACME, EVENT_BLOCK)
    # alice × ai-threat, bob × ai-threat, alice × nrd — not 38.
    assert len(alerts) == 3
    for row in alerts:
        signal = _payload(row)["signal"]
        assert signal["bucket_span"] == "day" and signal["cross_domain"] is True
        assert signal["bucket_hour"] == "2026-09-30T00:00:00Z"
    ai = next(r for r in alerts if _payload(r)["signal"]["reason_id"] == "ai-threat-detection"
              and _payload(r)["log"]["device"]["name"] == "alice-laptop")
    bucket = next(b for b in store.iter_buckets(ACME) if b["event_id"] == ai["id"])
    assert bucket["hits"] == 30 and bucket["distinct_roots"] == 30 and bucket["root"] == "*"
    shown = NextDNSSourceAdapter.present_event(_payload(ai))
    assert "(any domain)" in shown.detail and "same day" in shown.detail
    # The day closes: ONE note with lookups, distinct domains, masked samples.
    world.run_for(poller, 12 * 3600 + 25 * 60)               # → 00:25 tomorrow
    [note] = world.notes(ACME, ai["id"])
    assert "30 lookups across 30 different domains on 2026-09-30 (UTC)" in note["note_text"]
    assert "suspect" not in note["note_text"]                # samples are masked
    suffix = NextDNSSourceAdapter.presentation_suffixes(ACME, [(ai["id"], _payload(ai))])
    assert suffix[ai["id"]].startswith("30 lookups across 30 domains on 2026-09-30 (UTC)")


def test_the_busy_ai_threat_site_is_about_one_alert_per_device_per_reason_per_day(world):
    """The verifier's site: ~290 AI-threat blocks a day over 60 domains and
    8 devices — 468 alerts a day before; now one per device per UTC day."""
    rng = random.Random(20260930)
    t = world.transport
    t.set_rate("abc123")
    lines = []
    at = T0 - timedelta(hours=24)
    while at < T0 + timedelta(hours=24):
        at += timedelta(seconds=rng.expovariate(290 / 86400))
        k = rng.randrange(60)
        lines.append(block_line(at, domain=f"w{k}.suspect{k}-example.test",
                                reason="ai-threat-detection",
                                reason_name="AI-Driven Threat Detection",
                                device_id=f"AI{rng.randrange(8):04d}", device_name="ws"))
    t.add_lines("abc123", *sorted(lines, key=lambda line: line["timestamp"]))
    world.map(abc123=ACME)
    world.run_for(world.poller(), 24 * 3600)
    alerts = [_payload(r) for r in world.events(ACME, EVENT_BLOCK)]
    keys = [(a["log"]["device"]["id"], a["signal"]["bucket_hour"]) for a in alerts]
    assert len(keys) == len(set(keys))                       # one per device per day
    per_day = {}
    for device, day in keys:
        per_day.setdefault(day, set()).add(device)
    assert set(per_day) <= {"2026-09-29T00:00:00Z", "2026-09-30T00:00:00Z",
                            "2026-10-01T00:00:00Z"}
    assert all(len(devices) <= 8 for devices in per_day.values())
    assert len(alerts) <= 3 * 8


def test_high_reasons_stay_per_root_domain_per_hour(world):
    t = world.transport
    t.set_rate("abc123")
    h = T0 - timedelta(hours=2)
    t.add_lines("abc123",
                block_line(h + timedelta(minutes=5), domain="a.c2-example.test"),
                block_line(h + timedelta(minutes=6), domain="b.c2-example.test"),     # same root
                block_line(h + timedelta(minutes=7), domain="x.other-c2-example.test"),
                block_line(h + timedelta(minutes=8), domain="y.dga-example1.test",
                           reason="dga", reason_name="DGA"),
                block_line(h + timedelta(minutes=9), domain="z.dga-example2.test",
                           reason="dga", reason_name="DGA"))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    alerts = [_payload(r) for r in world.events(ACME, EVENT_BLOCK)]
    assert len(alerts) == 3                    # two roots of threat intel + one DGA
    assert {a["signal"]["bucket_span"] for a in alerts} == {"hour"}
    assert sorted(a["signal"]["cross_domain"] for a in alerts) == [False, False, True]


def test_a_csam_lookup_never_rides_in_another_reasons_bucket(world):
    """v0.17.2 + v0.17.1: a line naming 'csam' among its reasons never rides
    in the threat-intelligence bucket of the same device and root (an ack or
    expected condition on THAT bucket must never hide it) — and it is no
    ordinary alert or bucket at all: rule B7's restricted evidence only."""
    t = world.transport
    t.set_rate("abc123")
    h = T0 - timedelta(hours=2)
    t.add_lines("abc123",
                block_line(h + timedelta(minutes=5), domain="a.mixed-example.test"),
                block_line(h + timedelta(minutes=6), domain="b.mixed-example.test",
                           extra_reasons=(("csam", "Child Sexual Abuse Material"),)))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    alerts = [_payload(r) for r in world.events(ACME, EVENT_BLOCK)]
    assert [a["signal"]["reason_id"] for a in alerts] == ["threat-intelligence-feeds"]
    buckets = {b["reason_id"]: b for b in store.iter_buckets(ACME)}
    assert "csam" not in buckets and buckets["threat-intelligence-feeds"]["hits"] == 1


# ---------------------------------------------------------------------------
# The live fact: every reason of a multi-reason block is counted
# ---------------------------------------------------------------------------

def test_a_signal_behind_a_blocklist_triggers_the_log_pull_and_every_reason_counts(world):
    t = world.transport
    t.set_rate("abc123", default=900, blocked=40, allowed=2)
    t.add_lines("abc123", block_line(
        T0 - timedelta(minutes=90), reason="blocklist:oisd", reason_name="OISD",
        extra_reasons=(("threat-intelligence-feeds", "Threat Intelligence Feeds"),)))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    [alert] = world.events(ACME, EVENT_BLOCK)
    assert alert["severity"] == "high"
    assert _payload(alert)["signal"]["reason_id"] == "threat-intelligence-feeds"
    [row] = world.telemetry_rows(ACME, "nextdns_hourly")
    classes = row["signal_high"] + row["signal_medium"] + row["signal_low"] + row["policy_blocked"]
    # 41 blocked queries; 82 reason counts (the 40 on two lists each, and
    # the line under both of its reasons).
    assert row["blocked"] == 41 and classes == 82 and classes > row["blocked"]


# ---------------------------------------------------------------------------
# The span's note: written once the span is fully read, samples distinct
# ---------------------------------------------------------------------------

def test_a_day_note_waits_until_the_log_backlog_of_that_day_is_read(world):
    """Athena was down from 12:00 to 00:30 the next day; one device had
    6000 NRD blocks between 18:00 and 23:50. The first cycle back reads
    only 5 pages: the day's note must wait until the whole backlog is read
    and then say 6000 (not the 5000 read by the first cycle)."""
    t = world.transport
    t.set_rate("abc123")
    first = T0.replace(hour=18)
    t.add_lines("abc123", *[
        block_line(first + timedelta(seconds=3.5 * i),
                   domain=f"n{i % 40}.fresh{i % 40}-example.test",
                   reason="nrd", reason_name="Newly Registered Domains")
        for i in range(6000)
    ])
    world.map(abc123=ACME)
    world.poller().run_cycle()                               # 12:00: nothing yet
    world.clock.set(T0 + timedelta(hours=12, minutes=30))  # 00:30 the next day
    poller = world.poller()                                  # the restart
    poller.run_cycle()
    [alert] = world.events(ACME, EVENT_BLOCK)
    assert world.notes(ACME, alert["id"]) == []              # 1000 lines still unread
    world.run_for(poller, 2 * 3600)
    [note] = world.notes(ACME, alert["id"])
    last = (first + timedelta(seconds=3.5 * 5999)).strftime("%H:%M:%S")
    assert "6000 lookups across 40 different domains on 2026-09-30 (UTC)" in note["note_text"]
    assert f"last {last} UTC" in note["note_text"]


def test_a_notes_masked_samples_are_distinct(world):
    """Masking keeps two letters and the TLD, so many roots mask alike: the
    note shows each masked form once, drawing on more of the roots."""
    t = world.transport
    t.set_rate("abc123")
    start = T0.replace(hour=2)
    roots = [f"fr{i}-example.test" for i in range(12)] + [
        "alpha-example.test", "bravo-example.test", "charlie-example.test",
        "delta-example.test", "echo-example.test", "foxtrot-example.test"]
    t.add_lines("abc123", *[
        block_line(start + timedelta(minutes=5 * i), domain=f"w.{root}",
                   reason="ai-threat-detection", reason_name="AI-Driven Threat Detection")
        for i, root in enumerate(roots)
    ])
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    world.run_for(poller, 12 * 3600 + 25 * 60)
    [alert] = world.events(ACME, EVENT_BLOCK)
    [note] = world.notes(ACME, alert["id"])
    samples = note["note_text"].split("(e.g. ")[1].split(")")[0].split(", ")
    assert len(samples) == 5 and len(set(samples)) == 5
    assert samples[0] == "fr*****.test" and "al*****.test" in samples
    # Roots that all mask alike: the one form, once.
    assert poller_module.masked_samples(["fr1-example.test", "fr2-example.test"]) == [
        "fr*****.test"]
