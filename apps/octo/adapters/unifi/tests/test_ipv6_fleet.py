"""Review round 3, item 3: the fleet report carries a dual-stack console's
IPv6 WAN address and the prefix delegated to its LAN (from /v1/hosts
reportedState.wans[]), as egress "WANs" "<WAN>/v6" and "<WAN>/pd" — on a
single-site console only (a multi-site console's own WAN is not each
site's). Before, only the IPv4 externalIp was reported."""
from __future__ import annotations

from apps.octo.adapters.unifi import poller as poller_mod
from apps.octo.adapters.unifi.tests.fake_unifi import HOST_A, SCOPE_A, FakeSite

A = "acme-corp"



def test_a_dual_stack_consoles_ipv6_wan_and_delegated_prefix_are_reported(world):
    console = world.transport.console(HOST_A)
    console.wan_ipv6 = "2001:db8:42::1"
    console.wan_pd = "2001:db8:4200::/56"
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    (report,) = [r for slug, _s, r in world.consumer.of("site_report") if slug == A]
    v6 = [w for w in report["wans"] if w["wan"].startswith("WAN/")]
    assert v6 == [
        {"wan": "WAN/v6", "external_ip": "2001:db8:42::1", "prefix_len": 128,
         "nat_kind": "direct", "family": 6, "shared_external": False},
        {"wan": "WAN/pd", "external_ip": "2001:db8:4200::", "prefix_len": 56,
         "nat_kind": "direct", "family": 6, "shared_external": False}]


def test_ipv6_facts_are_read_tolerantly_and_never_guessed():
    rs = {"wans": [
        {"type": "WAN", "ipv6": "fe80::1"},                              # link-local: no
        {"type": "WAN2", "ipv6": ["fd00::5", "2001:db8:77::2/64"],       # ULA skipped
         "prefixDelegation": {"prefix": "2001:db8:7700::", "length": 48}},
        {"type": "WAN3", "ipv6": "2001:db8:88::2", "enabled": False},     # disabled
        {"type": "WAN4", "delegatedPrefix": "2001:db8:99::/96"},          # not a LAN prefix
    ]}
    assert poller_mod.host_v6(rs) == [
        {"wan": "WAN2/v6", "external_ip": "2001:db8:77::2", "prefix_len": 128,
         "nat_kind": "direct", "family": 6},
        {"wan": "WAN2/pd", "external_ip": "2001:db8:7700::", "prefix_len": 48,
         "nat_kind": "direct", "family": 6}]


def test_a_multi_site_consoles_own_ipv6_is_no_sites_egress(world):
    console = world.transport.console(HOST_A)
    console.wan_ipv6 = "2001:db8:42::1"
    console.sites.append(FakeSite(site_id="f1x7517e0000000000000002", ref="branch",
                                  desc="Branch", integration_id="0f0f0f0f-0000-4000-8000-000000000002"))
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    (report,) = [r for slug, _s, r in world.consumer.of("site_report") if slug == A]
    assert [w["wan"] for w in report["wans"]] == ["WAN"]
