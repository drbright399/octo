"""Review round 3, item 3: IPv6 egress, tested with a DUAL-STACK office.

The UDM reaches NextDNS over IPv6, so a gateway-forwarded line carries the
gateway's IPv6 WAN address; a device using DoH / the app over IPv6 carries
its own address inside the prefix delegated to the LAN. Before: only the
IPv4 `externalIp` was an egress, so such a block read "not this client's
internet connection" and lost its device list. Now the console's IPv6 WAN
address (/128) and its delegated prefix are egress intervals, and an IPv6
address the site's known IPv6 space cannot place is location UNKNOWN."""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo.entity import explain, linkrules
from apps.octo.entity.tests.conftest import A, EGRESS_A, PROFILE_A, T0, iso, world  # noqa: F401
from apps.octo.entity.tests.test_resolver import (
    _answer,
    _block_event,
    _confirm_profile,
    site_a_clients,
)

WAN_V6 = "2001:db8:42::1"                 # the gateway's own IPv6 WAN address
PD = ("2001:db8:4200::", 56)              # the prefix delegated to the LAN
DEVICE_V6 = "2001:db8:4200:10::abcd"      # a PC's own address inside it
ELSEWHERE_V6 = "2001:db8:9999::7"         # another network's address


def dual_stack(*, pd: bool = True) -> list[dict]:
    wans = [{"wan": "WAN", "external_ip": EGRESS_A, "nat_kind": "direct", "asn": 64500,
             "isp": "Example ISP", "shared_external": False},
            {"wan": "WAN/v6", "external_ip": WAN_V6, "prefix_len": 128, "nat_kind": "direct",
             "family": 6}]
    if pd:
        wans.append({"wan": "WAN/pd", "external_ip": PD[0], "prefix_len": PD[1],
                     "nat_kind": "direct", "family": 6})
    return wans


def office(world, *, wans) -> str:  # noqa: F811
    world.networks()
    for minute in (10, 15, 20):
        at = T0.replace(minute=minute)
        world.site_report(at, wans=wans)
        world.log_progress(at)
        world.snapshot(at, site_a_clients())
    return _confirm_profile(world)


def test_a_dual_stack_offices_ipv6_egress_is_stored_as_intervals(world):  # noqa: F811
    office(world, wans=dual_stack())
    rows = world.rows("SELECT addr, prefix_len, wan, nat_kind, valid_to FROM lk_site_egress "
                      "ORDER BY id")
    assert [(r["addr"], r["prefix_len"], r["wan"], r["nat_kind"], r["valid_to"]) for r in rows] == [
        (EGRESS_A, 32, "WAN", "direct", None), (WAN_V6, 128, "WAN/v6", "direct", None),
        (PD[0], PD[1], "WAN/pd", "direct", None)]
    # A new delegated prefix closes the old interval and opens another.
    world.site_report(T0.replace(minute=25), wans=dual_stack()[:2] + [
        {"wan": "WAN/pd", "external_ip": "2001:db8:4300::", "prefix_len": 56,
         "nat_kind": "direct"}])
    rows = world.rows("SELECT addr, close_reason FROM lk_site_egress WHERE wan = 'WAN/pd' "
                      "ORDER BY id")
    assert [(r["addr"], r["close_reason"]) for r in rows] == [(PD[0], "changed"),
                                                              ("2001:db8:4300::", None)]


def test_a_gateway_block_over_ipv6_is_located_with_its_device_list(world):  # noqa: F811
    site_id = office(world, wans=dual_stack())
    row = _answer(world, _block_event(world, client_ip=WAN_V6), T0.replace(minute=20, second=30))
    assert (row["site_id"], row["site_basis"], row["site_score"]) == (site_id, "both", 99)
    assert (row["tier"], row["n_candidates"]) == ("candidate", 9)
    assert [h["rule"] for h in json.loads(row["chain"])][:3] == ["S1", "S2", "S-AGREE"]


def test_a_devices_own_ipv6_address_inside_the_delegated_prefix_is_located(world):  # noqa: F811
    site_id = office(world, wans=dual_stack())
    row = _answer(world, _block_event(world, client_ip=DEVICE_V6, client_kind="doh"),
                  T0.replace(minute=20, second=30))
    assert (row["site_id"], row["site_basis"], row["site_score"]) == (site_id, "both", 99)
    s2 = next(h for h in json.loads(row["chain"]) if h["rule"] == "S2")
    assert s2["lookup"][0]["prefix_len"] == PD[1]
    assert DEVICE_V6 not in json.dumps({k: row[k] for k in ("chain", "candidates")})


def test_an_ipv6_address_outside_the_known_ipv6_space_is_not_located(world):  # noqa: F811
    office(world, wans=dual_stack())
    row = _answer(world, _block_event(world, client_ip=ELSEWHERE_V6),
                  T0.replace(minute=20, second=30))
    assert (row["site_basis"], row["n_candidates"]) == ("not_located", 0)
    assert "ip_not_an_egress" in json.loads(row["flags"])


def test_without_a_known_ipv6_prefix_an_ipv6_block_is_location_unknown(world):  # noqa: F811
    """IPv4-only reports (or the WAN /128 without a delegated prefix): an IPv6
    line that matches nothing is UNKNOWN — never "not this client's internet
    connection" (the verifier's SX-v6 case)."""
    for wans in ([dual_stack()[0]], dual_stack(pd=False)):
        world.clock.set(T0)
        with world.db().write() as conn:
            conn.execute("DELETE FROM lk_site_egress")
            conn.execute("DELETE FROM lk_watermark WHERE source = 'unifi.sites'")
        office(world, wans=wans)
        row = _answer(world, _block_event(world, client_ip=DEVICE_V6, vid=f"v{len(wans)}"),
                      T0.replace(minute=20, second=30))
        flags = json.loads(row["flags"])
        assert row["site_basis"] == "policy" and row["n_candidates"] == 0
        assert {"location_unknown", "ipv6_unknown"} <= set(flags)
        assert "ip_not_an_egress" not in flags
        why = explain.explain(dict(row), None)["why"]
        assert any("IPv6" in w and "not ruled out" in w for w in why)
        assert not any("was not this client's internet connection" in w for w in why)


def test_ipv6_traffic_inside_the_prefix_counts_toward_the_profiles_site(world):  # noqa: F811
    office(world, wans=dual_stack())
    day = T0.strftime("%Y-%m-%d")
    world.nextdns.on_ip_day(A, PROFILE_A, {"day": day, "read_at": iso(T0 + timedelta(days=1)),
                                           "ips": [[EGRESS_A, 100], [WAN_V6, 300],
                                                   [DEVICE_V6, 50], ["2001:db8:4200:11::9", 50],
                                                   [ELSEWHERE_V6, 500]]})
    (row,) = world.rows("SELECT * FROM ndns_ip_day")
    kept = dict(json.loads(row["egress_ips"]))
    # Devices' own addresses are counted under the PREFIX, never one by one;
    # another network's address is only counted.
    assert kept == {EGRESS_A: 100, WAN_V6: 300, f"{PD[0]}/{PD[1]}": 100}
    assert (row["egress_queries"], row["total_queries"]) == (500, 1000)
    with world.db().connect() as conn:
        site_id = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
        cov = linkrules.coverage(conn, PROFILE_A, site_id, iso(T0 + timedelta(days=1)))
    assert (cov["queries_from_site"], cov["queries"], cov["share"]) == (500, 1000, 0.5)
