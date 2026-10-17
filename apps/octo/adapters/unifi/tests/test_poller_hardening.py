"""UniFi poller hardening (review round 2) — the real poller / client / limiter
on the fake cloud, one fake clock:

  * a site the console does not list is never read through the console's
    ONLY listed site (another tenant's leases); a fleet site without a valid
    internal reference is dropped, never guessed as 'default';
  * a mapped site that left the fleet list does not spin the cycle;
  * one console answering 3xx / 401 through the connector holds only its
    site (the other sites keep their security reads);
  * the system-log progress handed to entity resolution is what is
    GUARANTEED read whole (the window end minus the overlap);
  * a site UniFi calls "Default" takes its console's name;
  * the card's "consoles offline" counts only consoles that host a mapped
    site (an ignored, switched-off home console is nobody's problem).
"""
from __future__ import annotations

from datetime import timedelta

from apps.octo.adapters.unifi.poller import OVERLAP, build_fleet
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    HOST_B,
    HOST_C,
    SCOPE_A,
    SCOPE_B,
    SCOPE_C,
    FakeSite,
    ips_event,
    lan,
    mac,
)

A, B = "acme-corp", "example-bakery"
SITE_X = "f1x7517e00000000000000x1"


def _multi_site_console(world) -> str:
    """Console A hosts TWO sites: X ('sitex', mapped to acme-corp) and the
    default site Y (mapped to example-bakery). The cloud's fleet list shows
    both; the console's own integration list shows only Y."""
    console = world.transport.console(HOST_A)
    console.sites[0].desc = "Bakery front"
    console.sites[0].clients = [{"id": "c-pos", "name": "BAKERY-POS", "macAddress": mac(77),
                                 "ipAddress": lan(77), "type": "WIRED",
                                 "connectedAt": "2026-10-01T08:00:00Z"}]
    console.sites.append(FakeSite(site_id=SITE_X, ref="sitex", desc="Acme back office",
                                  integration_id="0f0f0f0f-0000-4000-8000-0000000000x1",
                                  listed=False))
    return f"{HOST_A}/{SITE_X}"


def test_a_site_the_console_does_not_list_is_never_read_through_its_only_site(world):
    scope_x = _multi_site_console(world)
    world.map_sites({scope_x: A, SCOPE_A: B})
    p = world.poller()
    p.run_cycle()
    snaps = world.consumer.of("client_snapshot")
    # Bakery's own snapshot arrives under bakery's scope …
    assert [(slug, scope) for slug, scope, _d in snaps] == [(B, SCOPE_A)]
    assert [c["name"] for c in snaps[0][2]["clients"]] == ["BAKERY-POS"]
    # … and acme-corp NEVER gets it under its scope: the read fails closed.
    failed = world.consumer.of("client_snapshot_failed")
    assert [(slug, scope) for slug, scope, _d in failed] == [(A, scope_x)]
    assert "not listed" in failed[0][2]["reason"]
    assert all(slug != A for slug, _s, _d in snaps)


def test_a_fleet_site_without_a_valid_internal_reference_is_dropped_not_defaulted():
    hosts = [{"id": HOST_A, "reportedState": {"hostname": "acme-udm", "state": "connected"}}]
    site = {"hostId": HOST_A, "siteId": SITE_X, "meta": {"desc": "Back office"},
            "statistics": {}}
    assert build_fleet(hosts, [site]) == {}
    site["meta"]["name"] = "../../etc"
    assert build_fleet(hosts, [site]) == {}
    site["meta"]["name"] = "sitex"
    assert list(build_fleet(hosts, [site])) == [f"{HOST_A}/{SITE_X}"]


def test_a_site_called_default_takes_its_consoles_name():
    hosts = [{"id": HOST_A, "reportedState": {"hostname": "acme-udm", "state": "connected"}},
             {"id": HOST_B, "reportedState": {"hostname": "bakery-ucg", "state": "connected"}}]
    sites = [
        {"hostId": HOST_A, "siteId": "f1x7517e0000000000000001",
         "meta": {"name": "default", "desc": "Default"}, "statistics": {}},
        {"hostId": HOST_B, "siteId": "f1x7517e0000000000000001",
         "meta": {"name": "default", "desc": "Default"}, "statistics": {}},
        {"hostId": HOST_B, "siteId": SITE_X, "meta": {"name": "sitex", "desc": "Warehouse"},
         "statistics": {}},
    ]
    fleet = build_fleet(hosts, sites)
    assert fleet[f"{HOST_A}/f1x7517e0000000000000001"].name == "acme-udm"
    # A console with several sites: its default site says whose it is.
    assert fleet[f"{HOST_B}/f1x7517e0000000000000001"].name == "bakery-ucg — Default"
    assert fleet[f"{HOST_B}/{SITE_X}"].name == "Warehouse"


def test_the_standard_home_console_called_default_is_listed_by_its_console_name(world):
    p = world.poller()
    p.run_cycle()
    assert p.fleet_view()[SCOPE_C]["name"] == "home-lab"


def test_a_mapped_site_that_left_the_fleet_list_does_not_spin_the_cycle(world):
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    p = world.poller()
    healthy = world.run_for(p, 10 * 60)
    world.transport.consoles = [c for c in world.transport.consoles if c.host_id != HOST_A]
    gone = world.run_for(p, 10 * 60)
    assert healthy <= 8 and gone <= 8, (healthy, gone)       # not one cycle a second
    assert p.site_states()[SCOPE_A]["problem_kind"] == "missing"


def test_one_console_answering_a_redirect_or_401_holds_only_its_site(world):
    for status in (302, 401):
        world.transport.console_status.clear()
        now = world.clock.now()
        world.transport.site(HOST_B).log.append(
            ips_event(now - timedelta(minutes=2), eid=f"b-{status}"))
        world.transport.console_status[HOST_A] = status
        world.map_sites({SCOPE_A: A, SCOPE_B: B})
        p = world.poller()
        before = len(world.transport.calls_to(f"{HOST_B}/proxy/network/v2/api/site"))
        world.run_for(p, 60 * 60)
        b_reads = len(world.transport.calls_to(f"{HOST_B}/proxy/network/v2/api/site")) - before
        assert b_reads >= 10, (status, b_reads)               # B keeps its security reads
        row = world.instance_row()
        assert row["status"] == "running", (status, row["status_detail"])
        assert p.site_states()[SCOPE_A]["problem_kind"] == "console"
        assert f"b-{status}" in [x["event"]["id"] for x in world.payloads(B)]


def test_log_progress_is_what_is_read_whole_the_overlap_excluded(world):
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    p.run_cycle()
    progress = world.consumer.of("log_progress")
    assert progress
    last = progress[-1][2]["scanned_to"]
    from apps.octo.adapters.unifi import catalogue

    now_ms = int(world.clock.now().timestamp() * 1000)
    # The last window ended at (about) now; the vouched-for end is OVERLAP
    # before it — a line written late can still land in that span.
    assert last <= catalogue.iso_ms(now_ms - int(OVERLAP.total_seconds() * 1000))
    assert last >= catalogue.iso_ms(now_ms - int(OVERLAP.total_seconds() * 1000) - 60_000)


def test_consoles_offline_counts_only_consoles_with_a_mapped_site(world):
    world.transport.console(HOST_C).state = "disconnected"        # the ignored home lab
    world.map_sites({SCOPE_A: A}, ignore=(SCOPE_C,))
    p = world.poller()
    p.run_cycle()
    assert p.snapshot()["consoles_offline"] == 0
    world.transport.console(HOST_A).state = "disconnected"
    world.clock.advance(6 * 60)
    p.run_cycle()
    assert p.snapshot()["consoles_offline"] == 1
