"""Review round 3, item 6: `shared_external` counts the OWNERS of an address
by TENANT, not by console. A landlord console with 'Suite 100' (client A)
and 'Suite 200' (client B) on one WAN gave both a plain 'direct' egress, so a
block from that address corroborated "both 99" in either client — the design
(R3.2) wanted it flagged. A site mapped to no tenant counts as its console
(an unknown owner); two sites of ONE client sharing an address are one."""
from __future__ import annotations

from apps.octo.adapters.unifi.poller import build_fleet
from apps.octo.adapters.unifi.tests.fake_unifi import HOST_A, SCOPE_A, FakeSite

A, B = "acme-corp", "example-bakery"



def _two_tenant_console(world) -> str:
    """One landlord console: 'Suite 100' (client A) and 'Suite 200' (client
    B) behind ONE WAN address."""
    console = world.transport.console(HOST_A)
    console.sites.append(FakeSite(site_id="f1x7517e0000000000000002", ref="suite200",
                                  desc="Suite 200", integration_id="0f0f0f0f-0000-4000-8000-000000000002",
                                  wans={"WAN": {"externalIp": "203.0.113.129", "asn": 64500,
                                                "isp": "Example ISP"}}))
    return f"{HOST_A}/f1x7517e0000000000000002"


def test_two_clients_on_one_console_sharing_a_wan_are_shared_external(world):
    suite200 = _two_tenant_console(world)
    world.map_sites({SCOPE_A: A, suite200: B})
    world.poller().run_cycle()
    reports = {slug: r for slug, _s, r in world.consumer.of("site_report")}
    assert reports[A]["wans"][0]["shared_external"] is True
    assert reports[B]["wans"][0]["shared_external"] is True


def test_two_sites_of_one_client_sharing_a_wan_are_not_shared_external(world):
    suite200 = _two_tenant_console(world)
    world.map_sites({SCOPE_A: A, suite200: A})
    world.poller().run_cycle()
    assert all(not w["shared_external"] for _slug, _s, r in world.consumer.of("site_report")
               for w in r["wans"])


def test_an_unmapped_site_sharing_the_address_still_flags_it(world):
    _two_tenant_console(world)
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    (report,) = [r for _slug, _s, r in world.consumer.of("site_report")]
    assert report["wans"][0]["shared_external"] is True       # another (unknown) owner


def test_without_an_owner_map_two_consoles_sharing_an_address_are_flagged():
    hosts = [{"id": "H1", "reportedState": {}}, {"id": "H2", "reportedState": {}}]
    sites = [{"hostId": h, "siteId": "s1", "meta": {"name": "default", "desc": h},
              "statistics": {"wans": {"WAN": {"externalIp": "203.0.113.9"}}}}
             for h in ("H1", "H2")]
    fleet = build_fleet(hosts, sites)
    assert all(info.wans[0]["shared_external"] for info in fleet.values())
    same = build_fleet(hosts, sites, owner_of=lambda scope: A)
    assert not any(info.wans[0]["shared_external"] for info in same.values())
