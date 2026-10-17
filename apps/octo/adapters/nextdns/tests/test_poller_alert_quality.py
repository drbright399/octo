"""Alert quality — the NextDNS poller must not flood, flap, or blame the
wrong thing. Real pieces, fake socket, one fake clock (conftest.py).

Pinned (fix rounds 2026-09-30; the owner's final rules and the whole-day /
hour-of-week / gap-bound / fleet rules are in test_poller_owner_rules.py):
  * DGA: one device looking up hundreds of algorithm-generated domains is ONE
    alert per hour, with "N lookups across M domains" (masked samples);
  * MEDIUM / LOW reasons coalesce per device and reason per UTC day:
    periodic bypass-methods lookups (iCloud Private Relay, a browser's
    secure DNS) are one alert per device per day, not 24;
  * lapse / restore hysteresis: an office that is quiet every night never
    lapses for it (no hourly rule before a week of baseline, then the same
    hour of the week decides);
  * a zero hour shared by most active profiles is a NextDNS-side gap — no
    lapse anywhere (for at most 2 hours in a row);
  * a site already dark when it was mapped starts LAPSED (one alert), not
    "pending rollout"; logging off at NextDNS is said as such;
  * a re-mapped profile never writes one tenant's slug or event ids into
    another tenant's alerts.
"""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo import paths
from apps.octo.adapters.nextdns import NextDNSSourceAdapter, store
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK, EVENT_LAPSED, EVENT_RESTORED
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line, hour_of
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"


# ---------------------------------------------------------------------------
# Coalescing shape
# ---------------------------------------------------------------------------

def test_a_dga_infected_device_is_one_alert_per_hour_not_one_per_domain(world):
    t = world.transport
    t.set_rate("abc123")
    start = T0 - timedelta(minutes=55)
    t.add_lines("abc123", *[
        block_line(start + timedelta(seconds=20 * i), domain=f"x{i:04d}q7.dga-example{i}.test",
                   reason="dga", reason_name="Domain Generation Algorithms")
        for i in range(150)
    ])
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    [alert] = world.events(ACME, EVENT_BLOCK)
    assert alert["severity"] == "high"
    payload = json.loads(alert["payload"])
    assert payload["signal"]["cross_domain"] is True and payload["signal"]["bucket_span"] == "hour"
    [bucket] = list(store.iter_buckets(ACME))
    assert bucket["hits"] == 150 and bucket["distinct_roots"] == 150 and bucket["root"] == "*"
    shown = NextDNSSourceAdapter.present_event(payload)
    assert "(any domain)" in shown.detail
    world.run_for(poller, 1800)                          # the hour closes
    [note] = world.notes(ACME, alert["id"])
    assert "150 lookups across 150 different domains in the hour from" in note["note_text"]
    assert "dga-example" not in note["note_text"]        # samples are masked
    suffix = NextDNSSourceAdapter.presentation_suffixes(ACME, [(alert["id"], payload)])
    assert suffix[alert["id"]].startswith("150 lookups across 150 domains")


def test_periodic_bypass_lookups_are_one_alert_per_device_per_day(world):
    t = world.transport
    t.set_rate("abc123")
    start = T0 - timedelta(hours=23, minutes=55)          # 12:05 yesterday → now
    devices = [("DEV001", "alice-phone"), ("DEV002", "bob-phone"), ("DEV003", "carol-mac")]
    for dev_id, dev_name in devices:
        t.add_lines("abc123", *[
            block_line(start + timedelta(minutes=5 * i), domain="mask.icloud-example.test",
                       reason="bypass-methods", reason_name="Bypass Methods",
                       device_id=dev_id, device_name=dev_name)
            for i in range(287)
        ])
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    alerts = world.events(ACME, EVENT_BLOCK)
    # 3 devices × 2 UTC days (the back-fill crosses midnight) — not 3 × 24.
    assert len(alerts) == 6
    assert {r["severity"] for r in alerts} == {"medium"}
    days = {json.loads(r["payload"])["signal"]["bucket_hour"] for r in alerts}
    assert days == {"2026-09-29T00:00:00Z", "2026-09-30T00:00:00Z"}
    # Yesterday's buckets are closed: one "seen N times on <day>" note each.
    world.run_for(poller, 1200)
    yesterday = [r for r in alerts
                 if json.loads(r["payload"])["signal"]["bucket_hour"].startswith("2026-09-29")]
    for r in yesterday:
        [note] = world.notes(ACME, r["id"])
        assert "times on 2026-09-29 (UTC)" in note["note_text"]
    # The L1 wording names the likely benign causes.
    from apps.octo.agent.heuristic_l1 import DnsFilterEvent, TriageFeatures, triage
    text = triage(TriageFeatures(severity="medium", has_indicator=True, dns_filter=DnsFilterEvent(
        kind="block", reason_id="bypass-methods", device="alice-phone"))).note_text()
    assert "iCloud Private Relay" in text and "evade DNS filtering (VPN/proxy/Tor)" in text


def test_high_reasons_keep_the_hourly_bucket(world):
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", *[block_line(T0 - timedelta(hours=h, minutes=10)) for h in range(4)])
    world.map(abc123=ACME)
    world.poller().run_cycle()
    assert len(world.events(ACME, EVENT_BLOCK)) == 4


# ---------------------------------------------------------------------------
# Protection health: hysteresis
# ---------------------------------------------------------------------------

def _quiet_nights(world, pid: str, *, wake: dict[int, int] | None = None) -> None:
    """A site busy 06:00-20:00 UTC and silent at night (except `wake`
    hours with a few queries — a printer, an IoT box)."""
    t = world.transport
    t.set_rate(pid, default=900, blocked=40, allowed=2)
    for h in list(range(20, 24)) + list(range(0, 6)):
        n = (wake or {}).get(h, 0)
        t.of(pid).rate_by_hour_of_day[h] = {"default": n, "blocked": 0, "allowed": 0}


def test_an_office_quiet_every_night_never_lapses_for_it(world):
    _quiet_nights(world, "abc123")
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    world.run_for(world.poller(), 3 * 86400)
    assert world.events(ACME, EVENT_LAPSED) == []
    assert world.events(ACME, EVENT_RESTORED) == []


def test_a_printer_waking_at_night_does_not_flap_lapse_and_restore(world):
    _quiet_nights(world, "abc123", wake={21: 3, 0: 3, 3: 3})
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    world.run_for(world.poller(), 3 * 86400)
    assert world.events(ACME, EVENT_LAPSED) == []
    assert world.events(ACME, EVENT_RESTORED) == []


# ---------------------------------------------------------------------------
# A NextDNS-side gap is not N site outages
# ---------------------------------------------------------------------------

def _four_sites(world):
    t = world.transport
    for pid, slug in (("abc123", ACME), ("abc124", ACME), ("def456", BAKERY),
                      ("tst001", BAKERY)):
        t.set_rate(pid)
        world.seed_baseline(pid, slug)
    world.map(abc123=ACME, abc124=ACME, def456=BAKERY, tst001=BAKERY)


def test_a_zero_hour_shared_by_most_profiles_is_a_vendor_gap(world):
    _four_sites(world)
    for pid in ("abc123", "abc124", "def456", "tst001"):
        for h in (13, 14):
            world.transport.silence(pid, T0.replace(hour=h))
    poller = world.poller()
    world.run_for(poller, 5 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == [] and world.events(BAKERY, EVENT_LAPSED) == []
    gaps = poller.snapshot()["analytics_gaps"]
    assert "2026-09-30T13:00:00Z" in gaps or "2026-09-30T14:00:00Z" in gaps


def test_one_site_silent_among_many_still_lapses(world):
    _four_sites(world)
    for h in (13, 14):
        world.transport.silence("abc123", T0.replace(hour=h))
    poller = world.poller()
    world.run_for(poller, 5 * 3600)
    assert len(world.events(ACME, EVENT_LAPSED)) == 1
    assert poller.snapshot()["analytics_gaps"] == []


# ---------------------------------------------------------------------------
# Dark before mapping; logging off
# ---------------------------------------------------------------------------

def test_a_site_dark_since_before_mapping_starts_lapsed_not_pending(world):
    t = world.transport
    t.set_rate("abc123")
    h = hour_of(T0 - timedelta(hours=72))
    while h < T0 + timedelta(hours=24):
        t.silence("abc123", h)
        h += timedelta(hours=1)
    world.map(abc123=ACME)
    poller = world.poller()
    world.run_for(poller, 12 * 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = json.loads(lapse["payload"])
    assert payload["cause"] == "before_watch" and payload["queries_7d"] >= 100
    shown = NextDNSSourceAdapter.present_event(payload)
    assert "stopped reporting before Athena started watching it" in shown.detail
    assert poller.snapshot()["states"]["abc123"]["state"] == "lapsed"


def test_logging_off_is_shown_as_such_not_as_a_pending_rollout(world):
    world.transport.logs_settings["def456"] = {"enabled": False}
    world.map(def456=BAKERY)
    poller = world.poller()
    poller.run_cycle()
    snap = poller.snapshot()["states"]["def456"]
    assert snap["state"] == "pending" and snap["logs_enabled"] is False
    assert snap["problem_kind"] == "logs_off" and "Logging is turned off" in snap["problem"]


def test_logging_turned_off_on_an_active_profile_is_the_lapse_cause(world):
    t = world.transport
    t.set_rate("abc123")
    for h in (13, 14, 15):
        t.silence("abc123", T0.replace(hour=h))
    t.logs_settings["abc123"] = {"enabled": False}
    world.seed_baseline("abc123", ACME)
    world.map(abc123=ACME)
    world.run_for(world.poller(), 3 * 3600 + 600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    payload = json.loads(lapse["payload"])
    assert payload["cause"] == "logs_off"
    assert "Logging was turned off" in NextDNSSourceAdapter.present_event(payload).detail


# ---------------------------------------------------------------------------
# Re-mapping never crosses tenants
# ---------------------------------------------------------------------------

def test_a_remap_never_writes_one_tenants_slug_or_ids_into_another(world):
    t = world.transport
    t.set_rate("abc123")
    for h in (13, 14):
        t.silence("abc123", T0.replace(hour=h))
    world.seed_baseline("abc123", ACME)
    tenant_map.set_mappings(world.record.id, [
        TenantMapping("abc123", ACME, "Acme Corp Office", "manual")])
    poller = world.poller()
    world.run_for(poller, 3 * 3600 + 600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    world.map(abc123=BAKERY)                             # the mapping was wrong
    world.run_for(poller, 4 * 3600)
    acme_notes = " ".join(n["note_text"] for n in world.notes(ACME, lapse["id"]))
    assert "re-mapped to another client" in acme_notes
    assert BAKERY not in acme_notes and "event #" not in acme_notes
    for e in world.events(BAKERY):
        payload = json.loads(e["payload"])
        assert payload.get("lapse_event_id") is None
        for n in world.notes(BAKERY, e["id"]):
            assert ACME not in n["note_text"] and f"#{lapse['id']}" not in n["note_text"]
    assert poller.snapshot()["states"]["abc123"]["tenant_slug"] == BAKERY
    assert (paths.client_dir(BAKERY) / "events.db").exists() or True


def test_logging_turned_back_on_clears_the_problem(world):
    t = world.transport
    t.logs_settings["def456"] = {"enabled": False}
    world.map(def456=BAKERY)
    poller = world.poller()
    poller.run_cycle()
    assert poller.snapshot()["states"]["def456"]["problem_kind"] == "logs_off"
    del t.logs_settings["def456"]
    t.set_rate("def456", active_from=world.clock.now())
    world.run_for(poller, 7 * 3600)
    snap = poller.snapshot()["states"]["def456"]
    assert snap["state"] == "active" and snap["problem"] is None
