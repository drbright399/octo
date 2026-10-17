"""Protection health, throttling / auth, the call budget and the key.

Pinned: the PENDING gate (a never-active profile is silent: one 24-h read
every 6 h, never a lapse); ACTIVE → 2 zero hours → ONE lapsed signal (no
repeats while lapsed, not after a restart either) → queries resume → ONE
restored signal with a deterministic L1 note linking the lapse; 403 after a
success = throttled (row stays 'running', never 'error'); 401 / 403 from a
key that never worked = auth error; the budget at 48 active + 24 pending
profiles (a synthetic mid-size fleet); a stretched cycle never bursts and still rolls hours up; the key
is in no log line, health detail, registry / audit row or error.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta

import pytest

from apps.octo import paths
from apps.octo.adapters.nextdns.limiter import NextDNSRateLimiter, install_limiter
from apps.octo.adapters.nextdns.poller import STATE_KEY
from apps.octo.adapters.nextdns.presentation import (
    EVENT_BLOCK,
    EVENT_LAPSED,
    EVENT_RESTORED,
    LAPSED_ACTION,
)
from apps.octo.adapters.nextdns.tests.fake_nextdns import API_KEY, T0, block_line
from apps.octo.client_provisioning import create_client
from apps.octo.instances import poller_state, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"
BAKERY = "example-bakery"


def _window(c) -> timedelta:
    frm = datetime.fromisoformat(c.query["from"].replace("Z", "+00:00"))
    to = datetime.fromisoformat(c.query["to"].replace("Z", "+00:00"))
    return to - frm


def _status_24h_calls(world, pid: str) -> int:
    return sum(
        1 for c in world.transport.calls_for(pid)
        if c.path.endswith("/analytics/status") and _window(c) == timedelta(hours=24)
    )


# ---------------------------------------------------------------------------
# The PENDING gate
# ---------------------------------------------------------------------------

def test_a_profile_that_never_routed_is_pending_and_silent(world):
    world.map(def456=BAKERY)                          # no traffic at all
    poller = world.poller()
    world.run_for(poller, 13 * 3600)
    assert poller.snapshot()["states"]["def456"]["state"] == "pending"
    assert world.events(BAKERY) == []                 # never a lapse
    calls = world.transport.calls_for("def456")
    # At mapping: the 24-hour read, the 7-day look (was it dark already?)
    # and its logging settings; then one 24-hour read every 6 h — nothing
    # else (the settings are re-read at most daily).
    status = "/profiles/def456/analytics/status"
    assert [c.path for c in calls] == [status, status, "/profiles/def456", status, status]
    assert _status_24h_calls(world, "def456") == 3
    assert _window(calls[1]) == timedelta(days=7)


def test_a_pending_profile_becomes_active_when_it_routes(world):
    world.map(def456=BAKERY)
    poller = world.poller()
    poller.run_cycle()
    world.transport.set_rate("def456", active_from=T0 + timedelta(hours=1))
    world.run_for(poller, 7 * 3600)
    snap = poller.snapshot()["states"]["def456"]
    assert snap["state"] == "active" and snap["queries_24h"] >= 100
    assert any(c.path.endswith("/analytics/reasons") for c in world.transport.calls_for("def456"))


# ---------------------------------------------------------------------------
# ACTIVE → LAPSED → restored
# ---------------------------------------------------------------------------

def _lapse_world(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)             # 3 weeks: busy at every hour
    for h in (13, 14, 15):
        t.silence("abc123", T0.replace(hour=h))
    world.map(abc123=ACME)
    tenant_map.set_mappings(world.record.id, [
        TenantMapping("abc123", ACME, "Acme Corp Office", "manual")])


def test_two_zero_hours_raise_one_lapse_and_resuming_one_restoration(world):
    _lapse_world(world)
    poller = world.poller()
    world.run_for(poller, 3 * 3600 + 600)             # to 15:10: hours 13 and 14 read
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert lapse["severity"] == "medium"
    assert lapse["summary"] == "NextDNS stopped reporting — Acme Corp Office (abc123)"
    payload = json.loads(lapse["payload"])
    assert payload["since"] == "2026-09-30T13:00:00Z" and payload["zero_hours"] == 2
    assert lapse["received_at"] == "2026-09-30T15:00:00.000Z"
    from apps.octo.adapters.nextdns import NextDNSSourceAdapter
    shown = NextDNSSourceAdapter.present_event(payload)
    assert shown.detail.startswith(LAPSED_ACTION)
    assert poller.snapshot()["states"]["abc123"]["state"] == "lapsed"

    # Hour 15 silent too: no repeat — not even after a restart.
    world.run_for(poller, 3600)
    world.run_for(world.poller(), 600)
    assert len(world.events(ACME, EVENT_LAPSED)) == 1

    # Hour 16 has queries → at 17:05 ONE restoration, linked.
    world.run_for(world.poller(), 2 * 3600)
    [restored] = world.events(ACME, EVENT_RESTORED)
    assert restored["severity"] == "low"
    rp = json.loads(restored["payload"])
    assert rp["lapse_event_id"] == lapse["id"] and rp["restored_hour"] == "2026-09-30T16:00:00Z"
    [l1] = world.notes(ACME, restored["id"])
    assert l1["agent_id"] == "octo" and l1["query_kind"] == "auto_enrich"
    assert l1["disposition"] == "noise"
    assert f"after the lapse recorded as event #{lapse['id']}" in l1["note_text"]
    [forward] = world.notes(ACME, lapse["id"])
    assert f"recorded as event #{restored['id']}" in forward["note_text"]
    assert len(world.events(ACME, EVENT_LAPSED)) == 1
    # Running on: nothing more.
    world.run_for(world.poller(), 3 * 3600)
    assert len(world.events(ACME, EVENT_RESTORED)) == 1
    assert len(world.notes(ACME, restored["id"])) == 1


def test_one_zero_hour_is_not_a_lapse(world):
    t = world.transport
    t.set_rate("abc123")
    world.seed_baseline("abc123", ACME)
    t.silence("abc123", T0.replace(hour=13))
    world.map(abc123=ACME)
    world.run_for(world.poller(), 5 * 3600)
    assert world.events(ACME, EVENT_LAPSED) == []


# ---------------------------------------------------------------------------
# Throttled vs auth
# ---------------------------------------------------------------------------

def test_403_after_working_calls_is_throttled_not_failed(world):
    world.transport.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    assert poller.cycle_with_reporting() > 0
    assert world.instance_row()["status"] == "running"
    world.clock.advance(600)
    world.transport.throttle_next = 1
    wait = poller.cycle_with_reporting()
    assert wait == pytest.approx(15, abs=1)
    row = world.instance_row()
    assert row["status"] == "running"                 # never 'error'
    assert "rate limiting" in row["status_detail"] and "Not a failure" in row["status_detail"]
    snap = poller.snapshot()
    assert snap["throttled"] and 0 < snap["throttled_for_sec"] <= 15
    assert vendor_contact.snapshot(world.record.id)["last_throttled_at"]
    world.clock.advance(wait)
    poller.cycle_with_reporting()
    assert world.instance_row()["status_detail"] == vendor_contact.OK_DETAIL
    assert not poller.snapshot()["throttled"]


def test_a_throttle_loses_nothing(world):
    t = world.transport
    t.set_rate("abc123")
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    t.add_lines("abc123", block_line(T0 + timedelta(minutes=3)))
    world.clock.advance(600)
    t.throttle_next = 3
    world.run_for(poller, 1800)
    assert len(world.events(ACME, EVENT_BLOCK)) == 1


def test_a_rejected_key_is_an_auth_error(world):
    world.transport.set_rate("abc123")
    world.map(abc123=ACME)
    world.transport.key = "fixture-rotated-key"
    poller = world.poller()
    poller.cycle_with_reporting()
    row = world.instance_row()
    assert row["status"] == "error" and "rejected the API key (HTTP 401" in row["status_detail"]
    assert vendor_contact.snapshot(world.record.id)["failure_kind"] == "auth"


def test_403_from_a_key_that_never_worked_is_an_auth_error(world):
    world.map(abc123=ACME)
    world.transport.throttle_next = 1
    world.poller().cycle_with_reporting()
    assert world.instance_row()["status"] == "error"
    assert vendor_contact.snapshot(world.record.id)["failure_kind"] == "auth"


def test_a_restart_inside_the_hour_still_reads_403_as_a_throttle(world):
    world.transport.set_rate("abc123")
    world.map(abc123=ACME)
    world.poller().run_cycle()                        # persists key_ok_at
    # A fresh process: a fresh limiter that never saw a success itself.
    install_limiter(API_KEY, NextDNSRateLimiter(
        min_spacing_sec=2.0, clock=world.clock.monotonic, wait=world.clock.wait))
    world.limiter = __import__(
        "apps.octo.adapters.nextdns.limiter", fromlist=["limiter_for"]).limiter_for(API_KEY)
    world.clock.advance(600)
    world.transport.throttle_next = 1
    world.poller().cycle_with_reporting()
    assert world.instance_row()["status"] == "running"


# ---------------------------------------------------------------------------
# Budget and stretch — 72 profiles (synthetic)
# ---------------------------------------------------------------------------

def _fleet(world, active: int = 48, pending: int = 24) -> list[str]:
    ids = [f"p{n:05d}" for n in range(active + pending)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"} for pid in ids]
    for pid in ids[:active]:
        world.transport.set_rate(pid, default=900, blocked=40, allowed=2)
    create_client("globex", "Globex")
    tenant_map.set_mappings(world.record.id, [
        TenantMapping(pid, (ACME, BAKERY, "globex")[i % 3], f"Site {pid}", "manual")
        for i, pid in enumerate(ids)
    ])
    return ids


def test_call_budget_at_48_active_and_24_pending_profiles(world):
    _fleet(world)
    poller = world.poller()
    world.run_for(poller, 2 * 3600)                   # first import + warm-up
    before = len(world.transport.calls)
    world.run_for(poller, 3600)                       # one steady-state hour
    per_hour = len(world.transport.calls) - before
    planned = poller.planned_calls_per_hour()
    assert 364 <= per_hour <= 424, per_hour            # planned ≈ 389 (−25 / +35)
    assert planned["total"] == pytest.approx(
        48 * 6 + 48 * 2 + 24 / 6 + 24 / 24 + 1 / 6, abs=0.5)
    assert min(world.transport.gaps()) >= 2.0
    assert all(c.status == 200 for c in world.transport.calls)
    counts = poller.snapshot()["counts"]
    assert counts["active"] == 48 and counts["pending"] == 24
    print(f"\nmeasured calls in a steady-state hour: {per_hour}; planned {planned}")


def test_a_budget_that_does_not_fit_stretches_once_and_never_bursts(world, caplog):
    _fleet(world)
    caplog.set_level(logging.WARNING, logger="apps.octo.adapters.nextdns.poller")
    poller = world.poller(poll_interval_sec=60)       # 48 × 2 s = 96 s > 60 s
    world.run_for(poller, 3 * 3600)
    stretch = [r for r in caplog.records if "cycle stretches" in r.getMessage()]
    assert len(stretch) == 1
    assert min(world.transport.gaps()) >= 2.0         # never a burst
    assert all(c.status == 200 for c in world.transport.calls)
    # Health still gets its share: every active profile rolled hours up.
    rows = sum(len(world.telemetry_rows(s, "nextdns_hourly")) for s in (ACME, BAKERY, "globex"))
    assert rows >= 48 * 2


# ---------------------------------------------------------------------------
# The key never leaks
# ---------------------------------------------------------------------------

def test_the_key_is_in_no_log_health_detail_registry_or_audit_row(world, caplog):
    caplog.set_level(logging.DEBUG)
    t = world.transport
    t.set_rate("abc123")
    t.add_lines("abc123", block_line(T0 - timedelta(minutes=5)))
    world.map(abc123=ACME)
    poller = world.poller()
    poller.cycle_with_reporting()                     # works
    world.clock.advance(600)
    t.throttle_next = 1
    poller.cycle_with_reporting()                     # throttled
    world.clock.advance(60)
    t.force_status = 500
    poller.cycle_with_reporting()                     # transport
    t.force_status = None
    t.unreachable = True
    world.clock.advance(120)
    poller.cycle_with_reporting()                     # unreachable
    t.unreachable = False
    t.key = "fixture-rotated-key"
    world.clock.advance(3 * 3600)
    poller.cycle_with_reporting()                     # auth
    assert API_KEY not in caplog.text
    assert API_KEY not in json.dumps(poller.snapshot())
    assert API_KEY not in json.dumps(poller_state.load(world.record.id, STATE_KEY))
    assert API_KEY not in json.dumps(poller_state.load_prefix(world.record.id, STATE_KEY))
    for db in (paths.registry_db_path(), paths.global_audit_db_path(),
               paths.client_dir(ACME) / "events.db", paths.client_dir(ACME) / "telemetry.db"):
        conn = sqlite3.connect(db)
        try:
            dump = "\n".join(conn.iterdump())
        finally:
            conn.close()
        assert API_KEY not in dump, db.name
    row = world.instance_row()
    assert API_KEY not in (row["status_detail"] or "")
