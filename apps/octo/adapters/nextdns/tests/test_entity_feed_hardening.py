"""The NextDNS entity feed under refusal (review round 2) — the REAL poller /
client / limiter on the fake NextDNS (only the socket fake), feeding the real
entity consumer, on one fake clock:

  * a 403 on analytics/devices (or /ips) holds THAT read of THAT profile —
    the cycle goes on and the lapse decisions / bucket closes still run every
    cycle (the feed runs after them);
  * an analytics/ips read NextDNS refuses (400 / 403 / 404) is not asked
    again that day, and the device reads of every profile come first, from a
    start that rotates: no profile is starved by the others' retries;
  * analytics/devices refused on ONE profile switches only that profile to
    log sampling — after repeated refusals — and it is asked again later.
"""
from __future__ import annotations

import pytest

from apps.octo.adapters.nextdns import feed as nd_feed
from apps.octo.adapters.nextdns import poller as poller_mod
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch, tokens
from apps.octo.entity.feeders.nextdns import NextDNSDeviceFeeder
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping

A = "acme-corp"


@pytest.fixture
def ent(world):
    entity_db.reset_schema_cache()
    tokens.reset_cache()
    switch.reset()
    switch.set_mode(A, "on")
    nd_feed.register(NextDNSDeviceFeeder(now=world.clock.now))
    yield world
    nd_feed.register(None)
    switch.reset()


def _profiles(world, n: int) -> list[str]:
    pids = [f"zz{i:04d}" for i in range(n)]
    for i, pid in enumerate(pids):
        world.transport.profiles.append({"id": pid, "name": f"Acme site {i}",
                                         "fingerprint": f"fz{i:04d}", "role": "owner"})
        world.transport.set_rate(pid, default=900, blocked=40, allowed=2)
        world.transport.of(pid).devices["D1"] = {"name": f"DESKTOP-{i:02d}", "model": "Windows",
                                                 "localIp": f"10.20.0.{10 + i}", "per_hour": 30}
    tenant_map.set_mappings(world.record.id, [TenantMapping(p, A, None, "manual") for p in pids])
    return pids


def _calls(world, suffix: str, pid: str | None = None) -> list:
    return [c for c in world.transport.calls if c.path.endswith(suffix)
            and (pid is None or f"/profiles/{pid}/" in c.path)]


def test_a_403_on_the_device_read_never_ends_the_cycle_before_lapse_decisions(ent):
    world = ent
    _profiles(world, 1)
    world.transport.devices_status = 403
    p = world.poller()
    decided = {"n": 0}
    real = p._resolve_lapses

    def counting() -> None:
        decided["n"] += 1
        real()

    p._resolve_lapses = counting
    cycles = world.run_for(p, 6 * 3600)
    assert decided["n"] == cycles                     # every cycle decided its lapses
    device_calls = _calls(world, "/analytics/devices")
    # Held on its own, doubling from 15 minutes: a handful in 6 hours, not
    # one (and one key-wide throttle) every cycle.
    assert 1 <= len(device_calls) <= 6, len(device_calls)
    assert p._client.limiter.throttle_events <= len(device_calls)


def test_a_refused_ip_read_is_not_retried_that_day_and_starves_no_device_read(ent, monkeypatch):
    world = ent
    pids = _profiles(world, 6)
    world.transport.ips_status = 404
    monkeypatch.setattr(poller_mod, "ENTITY_CALLS_PER_CYCLE", 4)
    monkeypatch.setattr(poller_mod, "ENTITY_SEED_DAYS", 0)          # the seed is not under test
    p = world.poller()
    world.run_for(p, 2 * 3600)
    ips = _calls(world, "/analytics/ips")
    assert len(ips) <= len(pids)                      # at most once per profile and day
    for pid in pids:                                  # every profile got its device reads
        assert _calls(world, "/analytics/devices", pid), pid


def test_one_profiles_refused_device_read_samples_its_log_alone_and_is_reprobed(ent):
    world = ent
    bad, good = _profiles(world, 2)
    world.transport.devices_status_by_profile[bad] = 404
    p = world.poller()
    world.run_for(p, 3 * 3600)
    from apps.octo.entity.db import TenantDB

    with TenantDB.for_tenant(A).connect() as conn:
        methods = {(r["profile_id"], r["method"]) for r in conn.execute(
            "SELECT profile_id, method FROM ndns_presence_hour")}
    assert (good, "analytics") in methods and (good, "logs") not in methods
    assert (bad, "logs") in methods and (bad, "analytics") not in methods
    refused = len(_calls(world, "/analytics/devices", bad))
    assert refused == poller_mod.ENTITY_DEVICES_REFUSALS
    assert p.snapshot()["device_presence_sampled"] == [bad]          # shown, not silent
    # Six hours on, analytics/devices is asked again for that profile.
    del world.transport.devices_status_by_profile[bad]
    world.run_for(p, 6 * 3600)
    assert len(_calls(world, "/analytics/devices", bad)) > refused
    with TenantDB.for_tenant(A).connect() as conn:
        assert conn.execute("SELECT 1 FROM ndns_presence_hour WHERE profile_id = ? AND "
                            "method = 'analytics'", (bad,)).fetchone()
