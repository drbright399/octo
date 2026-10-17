""""NextDNS stopped reporting from a PC that Datto says is online" — end to end
with the REAL NextDNS poller / client / limiter and the REAL Datto inventory
poller / client, only their sockets fake, and the real entity consumers.

The failure it exists for (2026-10-01): the NextDNS Windows app stopped
silently on all four PCs of one client between 09-19 and 09-29 and nothing
said so. Here: four PCs ("DESKTOP-0A1" …), each linked NextDNS device ↔ Datto
device by a UNIQUE name plus the same LAN address (auto), a baseline of
normal reporting, then the app dies on all four while Datto shows them
online → one alert per PC (and a restore when one comes back).

Call math (per TENANT, never per device): one analytics/devices read per
profile per closed hour, one analytics/ips read per profile per day."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.datto.inventory import InventoryPoller
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS as DATTO_CREDS,
    FakeDattoTransport,
    inventory_device,
    real_client as datto_client,
)
from apps.octo.adapters.nextdns import NextDNSSourceAdapter
from apps.octo.adapters.nextdns import feed as nd_feed
from apps.octo.adapters.nextdns import limiter as nd_lim
from apps.octo.adapters.nextdns.poller import NextDNSPoller
from apps.octo.adapters.nextdns.tests.fake_nextdns import (
    CREDS as NEXTDNS_CREDS,
    FakeClock,
    FakeNextDNSTransport,
    fake_limiter,
    real_client as nextdns_client,
)
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch, tokens
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.datto import DattoInventoryFeeder
from apps.octo.entity.feeders.nextdns import NextDNSDeviceFeeder
from apps.octo.ingest import SqliteIngestSink, telemetry
from apps.octo.instances import create_instance, freshness, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

A = "acme-corp"
PID = "abc123"
START = datetime(2026, 9, 28, 6, 0, tzinfo=timezone.utc)
# The LAN addresses only ever link a NextDNS device to a Datto device by
# equality (never classified), so documentation addresses stand in for them.
PCS = [("D0A1", "DESKTOP-0A1", "192.0.2.31"), ("D0A2", "DESKTOP-0A2", "192.0.2.32"),
       ("D0A3", "DESKTOP-0A3", "192.0.2.33"), ("D0A4", "DESKTOP-0A4", "192.0.2.34")]


class World:
    def __init__(self, root, clock, nd, datto, poller, inventory) -> None:
        self.root, self.clock, self.nd, self.datto = root, clock, nd, datto
        self.poller, self.inventory = poller, inventory

    def hour(self, n: int = 1) -> None:
        """n hours: per hour, a Datto round then the NextDNS cycles of that
        hour (every 10 minutes, as the poller would)."""
        for _ in range(n):
            for _step in range(6):
                self.clock.advance(600)
                if _step == 0:
                    self.inventory.run_once()
                self.poller.cycle_with_reporting()

    def events(self, event_type: str) -> list[dict]:
        db = paths.client_dir(A) / "events.db"
        conn = sqlite3.connect(db)
        try:
            return [json.loads(r[0]) for r in conn.execute(
                "SELECT payload FROM events WHERE event_type = ? ORDER BY id", (event_type,))]
        finally:
            conn.close()

    def rows(self, sql: str) -> list[dict]:
        with TenantDB.for_tenant(A).connect() as conn:
            return [dict(r) for r in conn.execute(sql)]

    def device_calls(self) -> list:
        return [c for c in self.nd.calls if c.path.endswith("/analytics/devices")]


@pytest.fixture
def world(bedrock_root):  # noqa: F811
    nd_lim.reset_limiters()
    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()
    tokens.reset_cache()
    switch.reset()
    vendor_contact.reset()
    freshness.reset()
    clock = FakeClock(START)
    nd = FakeNextDNSTransport(clock)
    nd.set_rate(PID, default=900, blocked=40, allowed=2)
    for did, name, ip in PCS:
        nd.of(PID).devices[did] = {"name": name, "model": "Windows 11", "localIp": ip,
                                   "per_hour": 60}
    nd.of(PID).ips_per_hour = {"203.0.113.129": 1000}
    limiter = fake_limiter(clock)
    nd_rec = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                             credentials_dict=dict(NEXTDNS_CREDS), instance_config={})
    dt_rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                             credentials_dict=dict(DATTO_CREDS), instance_config={})
    create_client(A, "Acme Corp", kind="client")
    tenant_map.set_mappings(nd_rec.id, [TenantMapping(PID, A, "Acme office", "manual")])
    tenant_map.set_mappings(dt_rec.id, [TenantMapping("site-a", A, "Acme", "manual")])
    switch.set_mode(A, "on")
    datto = FakeDattoTransport()
    datto.site_devices["site-a"] = [inventory_device(f"uid-{did}", name, site_uid="site-a",
                                                     int_ip=ip) for did, name, ip in PCS]
    nd_feed.register(NextDNSDeviceFeeder(now=clock.now))
    poller = NextDNSPoller(adapter=NextDNSSourceAdapter(),
                           client=nextdns_client(nd, limiter=limiter),
                           sink=SqliteIngestSink(publish_to_stream=False),
                           instance_id=nd_rec.id, now=clock.now)
    inventory = InventoryPoller(client=datto_client(datto), instance_id=dt_rec.id,
                                spacing_sec=0, now=clock.now, consumer=DattoInventoryFeeder())
    yield World(bedrock_root, clock, nd, datto, poller, inventory)
    nd_feed.register(None)
    nd_lim.reset_limiters()
    switch.reset()
    vendor_contact.reset()
    freshness.reset()


def test_the_app_dying_on_four_online_pcs_raises_one_alert_each_and_a_restore(world):
    world.hour(30)                                      # a baseline: ~30 reporting hours
    links = world.rows("SELECT * FROM device_link ORDER BY id")
    assert [(l["state"], l["rule_id"], l["score"]) for l in links] == \
        [("auto", "L-NDNS-DATTO", 80)] * 4               # unique name + the same LAN address
    assert world.events("nextdns.device_silent") == []
    # The app stops on all four PCs; Datto still shows them online.
    stop = world.clock.now().replace(minute=0, second=0) + timedelta(hours=1)
    for did, _n, _ip in PCS:
        world.nd.of(PID).devices[did]["silent_from"] = stop
    world.hour(3)
    assert world.events("nextdns.device_silent") == []  # 4 silent hours are needed
    world.hour(3)
    alerts = world.events("nextdns.device_silent")
    assert sorted(a["datto"]["hostname"] for a in alerts) == [n for _d, n, _i in PCS]
    a = alerts[0]
    assert a["silent_hours"] >= 4 and a["signal"]["level"] == "medium"
    assert a["ocsf"]["class_uid"] == 2004 and a["ocsf"]["finding_info"]["analytic"]["uid"] == \
        "athena.entity.E1"
    assert a["ocsf"]["device"]["hostname"] == a["datto"]["hostname"]
    world.hour(3)
    assert len(world.events("nextdns.device_silent")) == 4          # once per episode
    # One PC comes back.
    world.nd.of(PID).devices["D0A1"]["silent_until"] = world.clock.now().replace(
        minute=0, second=0)
    world.hour(2)
    restored = world.events("nextdns.device_restored")
    assert [r["datto"]["hostname"] for r in restored] == ["DESKTOP-0A1"]
    assert isinstance(restored[0]["silent_event_id"], int)


def _span_h(call) -> float:
    def at(v: str) -> datetime:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    return (at(call.query["to"]) - at(call.query["from"])).total_seconds() / 3600


def test_call_math_is_per_profile_not_per_device(world):
    world.hour(10)
    hourly = [c for c in world.device_calls() if _span_h(c) == 1]
    seed = [c for c in world.device_calls() if _span_h(c) == 24]
    hours = sorted({c.query["from"] for c in hourly})
    assert len(hourly) == len(hours)                     # ONE call per profile-hour, 4 devices
    # 10 hours watched + at most 6 caught up from before the start.
    assert 10 <= len(hours) <= 16
    # The 14-day seed: one call per profile and day, once.
    assert len(seed) == len({c.query["from"] for c in seed}) == 14
    assert len(world.device_calls()) == len(hourly) + len(seed)
    ips = [c for c in world.nd.calls if c.path.endswith("/analytics/ips")]
    assert len(ips) == 1                                 # one a day (yesterday)


def test_an_offline_pc_or_an_unknown_hour_never_alerts(world):
    world.hour(30)
    stop = world.clock.now().replace(minute=0, second=0) + timedelta(hours=1)
    world.nd.of(PID).devices["D0A1"]["silent_from"] = stop
    world.nd.of(PID).devices["D0A2"]["silent_from"] = stop
    # DESKTOP-0A1 is OFF in Datto (a PC switched off is not a silent app).
    world.datto.site_devices["site-a"][0]["online"] = False
    world.hour(7)
    hosts = [a["datto"]["hostname"] for a in world.events("nextdns.device_silent")]
    assert hosts == ["DESKTOP-0A2"]


def test_without_the_devices_endpoint_one_log_page_is_sampled(world):
    from apps.octo.adapters.nextdns.poller import ENTITY_DEVICES_REFUSALS

    world.nd.devices_status = 404
    world.hour(3)
    # Refused ENTITY_DEVICES_REFUSALS times in a row on this profile, then
    # sampled — and not asked again until the re-probe (6 h).
    assert len(world.device_calls()) == ENTITY_DEVICES_REFUSALS
    logs = [c for c in world.nd.calls if c.path.endswith("/logs") and "status" not in c.query]
    assert logs and all(c.query.get("limit") == "1000" for c in logs)
    rows = world.rows("SELECT * FROM ndns_presence_hour ORDER BY hour")
    assert rows and all(r["method"] == "logs" for r in rows)


def test_shadow_tracks_the_state_but_raises_nothing(world):
    switch.set_mode(A, "shadow")
    world.hour(30)
    stop = world.clock.now().replace(minute=0, second=0) + timedelta(hours=1)
    for did, _n, _ip in PCS:
        world.nd.of(PID).devices[did]["silent_from"] = stop
    world.hour(7)
    assert world.events("nextdns.device_silent") == []
    watch = world.rows("SELECT * FROM device_watch")
    assert watch and all(w["state"] == "silent" for w in watch)


def test_a_name_that_is_not_unique_links_nothing(world):
    world.datto.site_devices["site-a"].append(
        inventory_device("uid-dup", "DESKTOP-0A1", site_uid="site-a", int_ip="192.0.2.99"))
    world.hour(2)
    links = world.rows("SELECT a_value FROM device_link WHERE valid_to IS NULL")
    assert sorted(l["a_value"] for l in links) == [f"{PID}:D0A2", f"{PID}:D0A3", f"{PID}:D0A4"]


def test_a_name_without_the_same_lan_address_is_only_a_suggestion(world):
    for d in world.datto.site_devices["site-a"]:
        d["intIpAddress"] = "192.0.2.199"
    world.hour(2)
    links = world.rows("SELECT * FROM device_link")
    assert {(l["state"], l["rule_id"], l["score"]) for l in links} == {("suggested", "N-DEV", 45)}


# ---------------------------------------------------------------------------
# Review round 2: a silence that began in shadow; an app already dead at
# switch-on; the alert says when the device LAST reported
# ---------------------------------------------------------------------------

def test_a_silence_that_began_in_shadow_alerts_once_the_switch_is_on(world):
    switch.set_mode(A, "shadow")
    world.hour(30)
    stop = world.clock.now().replace(minute=0, second=0) + timedelta(hours=1)
    for did, _n, _ip in PCS:
        world.nd.of(PID).devices[did]["silent_from"] = stop
    world.hour(7)
    assert world.events("nextdns.device_silent") == []
    assert all(w["state"] == "silent" for w in world.rows("SELECT * FROM device_watch"))
    switch.set_mode(A, "on")
    on_at = world.clock.now()
    world.hour(1)
    alerts = world.events("nextdns.device_silent")
    assert sorted(a["datto"]["hostname"] for a in alerts) == [n for _d, n, _i in PCS]
    # The silence is dated from when it was verified (in shadow), the last
    # report from the device's own last hour.
    a = alerts[0]
    assert a["silent_since"] < format_hour(on_at)
    assert a["last_report_precision"] == "hour" and a["last_report"] < a["silent_since"]
    world.hour(2)
    assert len(world.events("nextdns.device_silent")) == 4          # once


def format_hour(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00.000Z")


def test_an_app_already_dead_at_switch_on_is_seeded_linked_and_alerted(world):
    """The motivating case: the app stopped two days BEFORE the client was
    switched on. The 14-day seed finds the devices (and their LAN address),
    links them to Datto, and the alert says when each last reported."""
    dead = START - timedelta(days=2)
    for did, _n, _ip in PCS:
        world.nd.of(PID).devices[did]["silent_from"] = dead
    world.hour(9)
    seeded = world.rows("SELECT DISTINCT day FROM ndns_seed_day ORDER BY day")
    assert len(seeded) == 14
    links = world.rows("SELECT * FROM device_link ORDER BY id")
    assert [(l["state"], l["rule_id"]) for l in links] == [("auto", "L-NDNS-DATTO")] * 4
    alerts = world.events("nextdns.device_silent")
    assert sorted(a["datto"]["hostname"] for a in alerts) == [n for _d, n, _i in PCS]
    a = alerts[0]
    assert (a["last_report"], a["last_report_precision"]) == (dead.strftime("%Y-%m-%d"), "day")
    assert a["ocsf"]["unmapped"]["nextdns"]["last_report"] == dead.strftime("%Y-%m-%d")
    from apps.octo.adapters.nextdns.presentation import present_device

    text = present_device(a, restored=False).detail
    assert f"last reported on {dead.strftime('%Y-%m-%d')}" in text
    assert "verified silent while online" in text and "4 hours in a row" not in text


def test_a_profile_whose_devices_endpoint_hiccups_once_keeps_analytics(world):
    """One 404 is not "the endpoint is unsupported": the next cycle asks
    analytics/devices again, and every hour read is an analytics hour."""
    calls = {"n": 0}
    original = world.nd._devices

    def flaky(pid, query):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("fixture: one bad answer")       # → HTTP 400 once
        return original(pid, query)

    world.nd._devices = flaky
    world.hour(3)
    rows = world.rows("SELECT * FROM ndns_presence_hour ORDER BY hour")
    assert rows and all(r["method"] == "analytics" for r in rows)
