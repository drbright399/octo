"""Entity resolution hardening (review round 2) — the real feeders, intervals,
link rules, resolver and worker on an injected clock (no vendor, no network):

  * a UniFi site's Athena site belongs to the SCOPE, never to the adapter
    instance reading it: a key rotation (disable, add a new instance, map the
    same site) keeps ONE site, its refs and its open lookups — in either
    order of the worker and the first new poll, and after a plain disable;
  * a registry read fault changes NOTHING (never "everything was unmapped");
  * an unmap closes lookups at their last observation, never at the moment
    it was noticed (an outage is never bridged into a confident answer);
  * the MAC-anomaly rule sees a join whose log line arrives AFTER the
    snapshot covering it, re-queues an answer that already picked the MAC,
    and catches a same-IP same-medium clone by its uplink flapping;
  * conflicts and anomalies are time-bounded (never carried by a rollover);
  * a ghost join counts only for the subject address, before T;
  * a network is filtered out of NextDNS candidates only on positive
    evidence of a bypass (a domain controller's DNS, a mixed list: kept);
  * a confirmed profile narrows an egress shared by two sites of a tenant;
  * a feed that stops inside the join window is not re-resolved every
    minute; a re-run that would store the same answer writes nothing;
  * the NextDNS-app exclusion uses T's OWN hour (waiting for it), matched by
    name, never by a LAN address seen anywhere;
  * subnets that arrive late fix the guest mark of open leases.
Every address is a documentation / private value; names are fixtures."""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

from apps.octo.entity import intervals as iv
from apps.octo.entity.tests.conftest import (
    A,
    EGRESS_A,
    PROFILE_A,
    SCOPE_A,
    SCOPE_B,
    T0,
    client,
    iso,
    join_event,
    lan,
    mac,
    office_and_guest,
)
from apps.octo.entity.tests.test_resolver import (
    EARLY,
    T_BLOCK,
    _answer,
    _block_event,
    _confirm_profile,
    _ips_event,
    _ips_world,
    site_a,
    site_a_clients,
)
from apps.octo.entity.worker import EntityWorker


def _worker(at):
    return EntityWorker(now=lambda: at)


def _open_unifi_refs(world):
    return world.rows("SELECT * FROM site_vendor_ref WHERE vendor = 'unifi' AND valid_to IS NULL "
                      "ORDER BY id")


def _active_sites(world):
    return world.rows("SELECT * FROM site WHERE status = 'active'")


def _new_unifi_instance(world):
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS
    from apps.octo.instances import create_instance
    from apps.octo.instances.manager import disable_instance

    disable_instance(world.unifi_id, disabled_by_operator_id=None, reason="key rotation")
    return create_instance(vendor_slug="unifi", display_name="UniFi (rotated key)",
                           credentials_dict=dict(CREDS), instance_config={})


# ---------------------------------------------------------------------------
# A key rotation never splits a tenant's site
# ---------------------------------------------------------------------------

def _rotation_answer(world, site_id):
    for minute in (25, 30):
        world.poll(T0.replace(minute=minute), site_a_clients())
    eid = _block_event(world, at=T0.replace(minute=27), vid="after-rotation")
    row = _answer(world, eid, T0.replace(minute=30, second=30))
    assert (row["site_id"], row["site_basis"], row["site_score"], row["tier"]) == \
        (site_id, "both", 99, "candidate"), row["flags"]
    assert row["n_candidates"] == 9
    assert world.rows("SELECT * FROM link_conflict") == []


def test_a_key_rotation_with_the_worker_first_keeps_one_site(world):
    site_id = site_a(world)
    new = _new_unifi_instance(world)
    world.map(new.id, {SCOPE_A: A})
    _worker(T0.replace(minute=21)).run_tenant(A)             # reconcile before the new poll
    refs = _open_unifi_refs(world)
    assert [(r["adapter_instance_id"], r["state"], r["site_id"]) for r in refs] == \
        [(new.id, "confirmed", site_id)]
    # Nothing closed: the scope never left the tenant.
    assert len(world.rows("SELECT * FROM lk_ip_lease WHERE valid_to IS NULL")) == 14
    assert world.rows("SELECT * FROM lk_site_egress WHERE close_reason = 'unmapped'") == []
    _rotation_answer(world, site_id)
    assert [s["site_id"] for s in _active_sites(world)] == [site_id]


def test_a_key_rotation_with_the_new_poll_first_keeps_one_site(world):
    site_id = site_a(world)
    new = _new_unifi_instance(world)
    world.map(new.id, {SCOPE_A: A})
    world.poll(T0.replace(minute=22), site_a_clients())      # the new instance reads first
    _worker(T0.replace(minute=23)).run_tenant(A)
    refs = _open_unifi_refs(world)
    assert [(r["adapter_instance_id"], r["site_id"]) for r in refs] == [(new.id, site_id)]
    _rotation_answer(world, site_id)
    assert [s["site_id"] for s in _active_sites(world)] == [site_id]


def test_a_plain_disable_then_a_new_instance_re_attaches_to_the_same_site(world):
    site_id = site_a(world)
    new = _new_unifi_instance(world)
    _worker(T0.replace(minute=21)).run_tenant(A)             # unmapped for a moment
    assert _open_unifi_refs(world) == []
    world.map(new.id, {SCOPE_A: A})
    world.networks()                       # the new instance's first cycle reads them
    _rotation_answer(world, site_id)
    assert [s["site_id"] for s in _active_sites(world)] == [site_id]


# ---------------------------------------------------------------------------
# A registry read fault changes nothing
# ---------------------------------------------------------------------------

def test_a_registry_read_fault_retires_and_closes_nothing(world, monkeypatch):
    from apps.octo.entity.feeders import mapping

    site_id = site_a(world)

    def locked(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    assert mapping.mapped_scopes("unifi", A) == [(world.unifi_id, SCOPE_A, "manual",
                                                  f"label {SCOPE_A}")]
    with monkeypatch.context() as m:
        m.setattr(mapping, "connect", locked)
        assert mapping.mapped_scopes("unifi", A) is None       # a fault, not "nothing mapped"
        _worker(T0.replace(minute=21)).run_tenant(A)
    refs = _open_unifi_refs(world)
    assert [(r["state"], r["decided_by"]) for r in refs] == [("confirmed", "operator:mapping")]
    assert len(world.rows("SELECT * FROM lk_ip_lease WHERE valid_to IS NULL")) == 14
    assert world.rows("SELECT * FROM lk_site_egress WHERE valid_to IS NOT NULL") == []
    world.poll(T0.replace(minute=25), site_a_clients())
    assert [s["site_id"] for s in _active_sites(world)] == [site_id]


# ---------------------------------------------------------------------------
# An unmap closes at the last observation
# ---------------------------------------------------------------------------

def test_an_unmap_after_an_outage_closes_at_the_last_good_poll_and_bridges_nothing(world):
    site_a(world)                                            # last good poll 14:20, day 1
    world.map(world.unifi_id, {})
    later = T0 + timedelta(hours=20)
    _worker(later).run_tenant(A)
    leases = world.rows("SELECT * FROM lk_ip_lease")
    assert leases and all(r["valid_to"] == iso(T0.replace(minute=20)) for r in leases)
    assert {(r["to_exact"], r["close_reason"]) for r in leases} == {(0, "gap")}
    (egress,) = world.rows("SELECT * FROM lk_site_egress")
    assert (egress["valid_to"], egress["close_reason"]) == (iso(T0.replace(minute=20)), "gap")
    # A block INSIDE the outage: the site holds by policy, but nothing says
    # the office was where it came from — no candidate list.
    eid = _block_event(world, at=T0 + timedelta(hours=14), vid="in-the-outage")
    row = _answer(world, eid, later + timedelta(minutes=1))
    assert row["site_basis"] == "policy" and row["n_candidates"] == 0
    assert "location_unknown" in json.loads(row["flags"])


def test_an_unmap_right_after_a_poll_is_unmapped_at_that_poll(world):
    site_a(world)
    world.map(world.unifi_id, {})
    _worker(T0.replace(minute=22)).run_tenant(A)
    leases = world.rows("SELECT * FROM lk_ip_lease")
    assert {(r["valid_to"], r["close_reason"]) for r in leases} == \
        {(iso(T0.replace(minute=20)), "unmapped")}


# ---------------------------------------------------------------------------
# The MAC-anomaly rule: late log lines, re-queued answers, uplink flapping
# ---------------------------------------------------------------------------

def test_a_join_logged_after_the_snapshot_that_covered_it_is_still_checked(world):
    _ips_world(world)                                        # 14:10: MAC1 on .37 since 08:00
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    # The 14:12 join ("MAC1 joined as .88") is applied at 14:20, after the
    # 14:15 snapshot that covered it.
    out = world.log([join_event(T0.replace(minute=12), 1, lan(88))])
    assert out and out["signals"][0]["anomaly"] == "two_ips"
    world.poll(T0.replace(minute=20), [client(1, lan(37), connected=EARLY)])
    row = _answer(world, _ips_event(world, T0.replace(minute=13)), T0.replace(minute=21))
    assert row["tier"] == "candidate" and "mac_anomaly" in json.loads(row["flags"])


def test_a_join_after_the_last_snapshot_is_checked_by_the_next_one(world):
    _ips_world(world)
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    assert world.log([join_event(T0.replace(minute=17), 1, lan(88))]) is None
    assert world.rows("SELECT * FROM lk_join WHERE checked = 0")
    out = world.poll(T0.replace(minute=20), [client(1, lan(37), connected=EARLY)])
    assert out and out["signals"][0]["anomaly"] == "two_ips"
    assert world.rows("SELECT * FROM lk_join WHERE checked = 0") == []


def test_an_answer_that_picked_the_mac_before_the_anomaly_was_known_is_redone(world):
    _ips_world(world)
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    eid = _ips_event(world, T0.replace(minute=13))
    first = _answer(world, eid, T0.replace(minute=16))
    assert (first["tier"], first["score"]) == ("medium", 85)
    world.log([join_event(T0.replace(minute=12), 1, lan(88))])        # late evidence
    assert world.one("SELECT status FROM resolution WHERE res_id = ?",
                     (first["res_id"],))["status"] == "stale"
    _worker(T0.replace(minute=17)).run_tenant(A)
    cur = world.one("SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'",
                    (eid,))
    assert cur["tier"] == "candidate" and "mac_anomaly" in json.loads(cur["flags"])


def test_a_legitimate_reconnect_logged_late_is_no_anomaly(world):
    _ips_world(world)
    back = T0.replace(minute=12)
    world.poll(T0.replace(minute=15), [client(1, lan(88), connected=back)])
    assert world.log([join_event(back, 1, lan(88))]) is None
    assert world.rows("SELECT * FROM lk_mac_anomaly") == []


def _wired(up: str, *, kind: str = "WIRED") -> dict:
    c = client(1, lan(37), connected=EARLY, kind=kind)
    c["uplink_device_id"] = up
    return c


def test_a_same_ip_same_medium_clone_is_caught_by_its_uplink_flapping(world):
    """S-8: a rogue on another switch port clones FRONT-DESK's wired MAC —
    same IP (DHCP is keyed on the MAC), same medium; the MAC keeps switching
    between the two switches."""
    world.networks()
    outs = [world.poll(T0.replace(minute=10 + 5 * i), [_wired(up)])
            for i, up in enumerate(["sw-a", "sw-b", "sw-a", "sw-b"])]
    assert outs[:3] == [None, None, None]                     # two changes: not yet
    assert outs[3]["signals"][0]["anomaly"] == "uplink_flap"
    (anomaly,) = world.rows("SELECT * FROM lk_mac_anomaly")
    assert anomaly["kind"] == "uplink_flap" and anomaly["mac"] == mac(1)
    row = _answer(world, _ips_event(world, T0.replace(minute=22)), T0.replace(minute=26))
    assert row["tier"] == "candidate" and "mac_anomaly" in json.loads(row["flags"])


def test_a_clone_flapping_in_wired_join_events_is_caught_too(world):
    world.networks()
    world.poll(T0.replace(minute=10), [_wired("sw-a")])
    events = []
    for i, up in enumerate(["sw-a", "sw-b", "sw-a", "sw-b"]):
        j = join_event(T0.replace(minute=11 + 2 * i), 1, lan(37))
        j["client"]["uplink"] = up
        events.append(j)
    out = world.log(events)
    assert out and [s["anomaly"] for s in out["signals"]] == ["uplink_flap"]


def test_one_desk_move_or_wireless_roaming_is_no_anomaly(world):
    world.networks()
    for i, up in enumerate(["sw-a", "sw-b", "sw-b", "sw-b"]):
        world.poll(T0.replace(minute=10 + 5 * i), [_wired(up)])
    for i, ap in enumerate(["ap-a", "ap-b", "ap-a", "ap-b", "ap-a"]):
        world.poll(T0.replace(minute=30 + 5 * i), [_wired(ap, kind="WIRELESS")])
    assert world.rows("SELECT * FROM lk_mac_anomaly") == []


# ---------------------------------------------------------------------------
# Time-bounded conflicts; ghosts of the subject address only
# ---------------------------------------------------------------------------

def test_an_ip_conflict_is_time_bounded_and_never_carried_by_a_rollover(world):
    _ips_world(world)
    at = T0.replace(minute=12)
    world.log([{"id": "conflict-1", "ts_ms": int(at.timestamp() * 1000), "time": iso(at),
                "event": "CLIENT_IP_CONFLICT", "client": {"ip": lan(37)}}])
    t = T0.replace(minute=15)
    end = T0.replace(hour=2, minute=0) + timedelta(days=1)
    while t <= end:
        world.poll(t, [client(1, lan(37), connected=EARLY)])
        t += timedelta(minutes=15)
    assert all(r["conflict"] == 0 for r in world.rows("SELECT * FROM lk_ip_lease"))
    near = _answer(world, _ips_event(world, T0.replace(minute=13)), T0.replace(minute=16))
    assert near["tier"] == "candidate" and "conflict" in json.loads(near["flags"])
    next_day = T0.replace(hour=1, minute=50) + timedelta(days=1)
    row = _answer(world, _ips_event(world, next_day), end + timedelta(minutes=1))
    assert (row["tier"], row["score"]) == ("medium", 85)


def test_a_guest_joining_after_the_alert_on_another_vlan_is_no_ghost_of_it(world):
    _ips_world(world)
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    world.log([join_event(T0.replace(minute=19, second=30), 50, lan(50, 30),
                          event="CLIENT_CONNECTED_WIRELESS")])
    world.poll(T0.replace(minute=20), [client(1, lan(37), connected=EARLY)])
    row = _answer(world, _ips_event(world, T0.replace(minute=16)), T0.replace(minute=21))
    assert (row["tier"], row["score"]) == ("medium", 85)
    assert "ghost_join" not in json.loads(row["flags"])


# ---------------------------------------------------------------------------
# DNS path: only positive evidence of a bypass filters
# ---------------------------------------------------------------------------

def _site_with(world, office_dns: list[str]) -> None:
    nets = office_and_guest()
    nets[0].update({"dhcpd_dns_enabled": True,
                    **{f"dhcpd_dns_{i + 1}": s for i, s in enumerate(office_dns)}})
    world.networks(nets)
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), site_a_clients())
    _confirm_profile(world)


def test_an_office_whose_dns_is_a_domain_controller_keeps_its_devices(world):
    """The usual domain-joined office: DHCP DNS = the DC on a server VLAN,
    which forwards to the gateway (and so to NextDNS)."""
    _site_with(world, [lan(5, 40)])
    paths_ = {r["name"]: r["dns_path"] for r in world.rows("SELECT * FROM lk_site_subnet")}
    assert paths_ == {"Office": "unknown", "Guest": "other"}
    row = _answer(world, _block_event(world), T0.replace(minute=20, second=30))
    assert (row["tier"], row["n_candidates"]) == ("candidate", 9)
    assert json.loads(row["chain"])[-1]["out"]["excluded"] == {"dns_bypasses_nextdns": 5}


def test_the_gateway_plus_a_public_fallback_is_unknown_never_filtered(world):
    _site_with(world, [lan(1), "198.51.100.53"])
    paths_ = {r["name"]: r["dns_path"] for r in world.rows("SELECT * FROM lk_site_subnet")}
    assert paths_["Office"] == "unknown"
    row = _answer(world, _block_event(world), T0.replace(minute=20, second=30))
    assert row["n_candidates"] == 9


def test_nextdns_resolvers_are_bundle_configuration_never_a_guess(world, monkeypatch):
    nets = office_and_guest()
    nets[0].update({"dhcpd_dns_enabled": True, "dhcpd_dns_1": "192.0.2.53"})   # "NextDNS"
    world.networks(nets)
    paths_ = {r["name"]: r["dns_path"] for r in world.rows("SELECT * FROM lk_site_subnet")}
    assert paths_ == {"Office": "nextdns", "Guest": "other"}
    monkeypatch.delenv("OCTO_NEXTDNS_RESOLVER_NETS")
    net = {"dhcpd_dns_enabled": True, "dhcpd_dns_1": "198.51.100.53"}
    import ipaddress

    assert iv._dns_path(net, ipaddress.ip_network(f"{lan(0, 30)}/24")) == "unknown"


def test_when_every_device_was_set_aside_the_note_never_says_none_was_connected(world):
    world.networks()
    guests = [client(20 + n, lan(10 + n, 30), kind="WIRELESS", connected=EARLY)
              for n in range(1, 4)]
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), guests)
    _confirm_profile(world)
    row = _answer(world, _block_event(world), T0.replace(minute=20, second=30))
    d7 = json.loads(row["chain"])[-1]
    assert d7["out"] == {"candidates": 0, "excluded": {"dns_bypasses_nextdns": 3}}
    assert "no device was connected" not in d7["note"] and "set aside" in d7["note"]


# ---------------------------------------------------------------------------
# A confirmed profile narrows an egress two sites of the tenant share
# ---------------------------------------------------------------------------

def test_a_confirmed_profile_narrows_an_egress_shared_by_two_sites(world):
    world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: A})
    world.networks()
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), site_a_clients())
    world.networks(scope=SCOPE_B)
    back_office = [client(60 + n, lan(60 + n), connected=EARLY) for n in range(3)]
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), back_office, scope=SCOPE_B)
    site1 = _confirm_profile(world)                           # the first site (SCOPE_A's)
    row = _answer(world, _block_event(world), T0.replace(minute=20, second=30))
    assert (row["site_id"], row["site_basis"], row["site_tier"]) == (site1, "both", "strong")
    assert "shared_in_tenant" in json.loads(row["flags"])
    assert (row["tier"], row["n_candidates"]) == ("candidate", 9)   # site 1's office only


# ---------------------------------------------------------------------------
# A feed that stops inside the join window is not redone every minute
# ---------------------------------------------------------------------------

def test_a_feed_that_stops_inside_the_join_window_is_not_redone_every_minute(world):
    world.networks()
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), site_a_clients())
    _confirm_profile(world)
    eid = _block_event(world, at=T0.replace(minute=19, second=50), vid="edge")
    _worker(T0.replace(minute=20, second=30)).run_tenant(A)       # provisional
    _worker(T0.replace(minute=51)).run_tenant(A)                  # finalised, lookup_stale
    stale = world.one("SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'",
                      (eid,))
    assert stale["status"] == "final" and "lookup_stale" in json.loads(stale["flags"])
    assert "|" in stale["lookup_watermark"]                       # each wait keeps its need
    n_res = len(world.rows("SELECT * FROM resolution"))
    n_run = len(world.rows("SELECT * FROM resolution_run"))
    for minute in (52, 53, 54, 55):
        counts = _worker(T0.replace(minute=minute)).run_tenant(A)
        assert counts["backfill"] == 0
    assert len(world.rows("SELECT * FROM resolution")) == n_res
    assert len(world.rows("SELECT * FROM resolution_run")) == n_run
    # When the console comes back past what the answer needed, it is redone once.
    world.poll(T0.replace(minute=56), site_a_clients())
    assert _worker(T0.replace(minute=57)).run_tenant(A)["backfill"] == 1
    assert _worker(T0.replace(minute=58)).run_tenant(A)["backfill"] == 0


def test_a_backfill_that_would_store_the_same_answer_writes_nothing(world):
    from apps.octo.entity import resolver as rv

    world.networks()
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), site_a_clients())
    _confirm_profile(world)
    eid = _block_event(world)
    r = rv.Resolver.for_tenant(A, now=lambda: T0.replace(minute=20, second=30))
    r.resolve_event(eid, mode="backfill", created_by="rule:backfill")
    n = len(world.rows("SELECT * FROM resolution"))
    again = r.resolve_event(eid, mode="backfill", created_by="rule:backfill")
    assert again["noop"] is True and len(world.rows("SELECT * FROM resolution")) == n


# ---------------------------------------------------------------------------
# The NextDNS-app exclusion: T's own hour, by name
# ---------------------------------------------------------------------------

def _app_site(world) -> None:
    world.networks()
    clients = site_a_clients() + [client(40, lan(40), name="DESKTOP-APP01", connected=EARLY)]
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), clients)
    _confirm_profile(world)


def _device_hour(world, hour: str, devices: list[dict], read_at) -> None:
    world.nextdns.on_device_hour(A, PROFILE_A, {
        "hour": hour, "complete": True, "method": "analytics", "devices": devices,
        "read_at": iso(read_at)})


APP = {"id": "D9F2A1", "name": "DESKTOP-APP01", "model": "Windows", "client": "nextdns-windows"}


def test_a_pc_whose_app_died_minutes_before_stays_a_candidate(world):
    _app_site(world)
    _device_hour(world, "2026-10-01T13:00:00Z", [{**APP, "queries": 180}], T0.replace(minute=5))
    _device_hour(world, "2026-10-01T14:00:00Z", [], T0.replace(hour=15, minute=5))   # dead
    row = _answer(world, _block_event(world), T0.replace(hour=15, minute=6))
    assert row["n_candidates"] == 10
    assert json.loads(row["chain"])[-1]["out"]["excluded"] == {"dns_bypasses_nextdns": 5}


def test_until_ts_hour_is_read_the_answer_waits_and_excludes_nothing(world):
    _app_site(world)
    _device_hour(world, "2026-10-01T13:00:00Z", [{**APP, "queries": 180}], T0.replace(minute=5))
    eid = _block_event(world)
    first = _answer(world, eid, T0.replace(minute=20, second=30))
    assert first["status"] == "provisional" and first["n_candidates"] == 10
    assert "app_presence_pending" in json.loads(first["flags"])
    assert "nextdns.presence:abc123=" in first["lookup_watermark"]
    # T's hour is read (the app reported in it): the worker redoes the answer.
    _device_hour(world, "2026-10-01T14:00:00Z", [{**APP, "queries": 120}],
                 T0.replace(minute=24))
    _worker(T0.replace(minute=25)).run_tenant(A)
    cur = world.one("SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'",
                    (eid,))
    assert cur["status"] == "final" and cur["n_candidates"] == 9
    assert json.loads(cur["chain"])[-1]["out"]["excluded"] == \
        {"dns_bypasses_nextdns": 5, "nextdns_app_device": 1}


def test_an_app_laptop_at_home_on_the_same_lan_address_excludes_no_office_pc(world):
    site_a(world)
    # PC-5 (no app) holds lan(15) in the office; a laptop running the app
    # is at home in the same hour, its home LAN address also lan(15).
    _device_hour(world, "2026-10-01T14:00:00Z",
                 [{"id": "L4P70P", "name": "LAPTOP-HOME", "model": "Windows",
                   "client": "nextdns-windows", "local_ip": lan(15), "queries": 50}],
                 T0.replace(minute=19))
    row = _answer(world, _block_event(world), T0.replace(minute=20, second=30))
    assert row["n_candidates"] == 9
    assert "nextdns_app_device" not in json.loads(row["chain"])[-1]["out"]["excluded"]


# ---------------------------------------------------------------------------
# Subnets that arrive late fix open leases' guest mark
# ---------------------------------------------------------------------------

def test_subnets_arriving_after_a_guest_lease_mark_it_guest(world):
    world.poll(T0, [client(21, lan(21, 30), kind="WIRELESS")])
    (row,) = world.rows("SELECT * FROM lk_ip_lease")
    assert (row["is_guest"], row["net_id"]) == (0, None)
    world.networks()
    (row,) = world.rows("SELECT * FROM lk_ip_lease")
    assert (row["is_guest"], row["net_id"]) == (1, "net-2")


def test_the_egress_used_above_is_a_documentation_address():
    assert EGRESS_A.startswith("203.0.113.") and T_BLOCK.minute == 17
