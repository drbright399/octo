"""The ISP-outage correlation end to end through the REAL UniFi poller (fake
socket, one fake clock): consoles of mapped sites going offline in the fleet
poll → ONE `fleet.isp_outage` signal in the internal tenant, only for the
ASN that has enough of them; back online → closed with a note. The fleet
health read (`fleet_health`) carries the network layer's statistics; the
entity feed's site report is unchanged by them."""
from __future__ import annotations

import json

from apps.octo.adapters.unifi.tests.fake_unifi import HOST_A, HOST_B, SCOPE_A, SCOPE_B, \
    SITE_DEFAULT
from apps.octo.client_provisioning import create_client
from apps.octo.fleet import isp_outage

A, B = "acme-corp", "example-bakery"
D, E = "example-dental", "example-diner"
INTERNAL = "msp-internal"
HOST_D = "F1X7D0000000000000000000000000000000000000000000000000D004:100000004"
HOST_E = "F1X7E0000000000000000000000000000000000000000000000000E005:100000005"
SCOPE_D, SCOPE_E = f"{HOST_D}/{SITE_DEFAULT}", f"{HOST_E}/{SITE_DEFAULT}"


def _setup(world):
    for slug, name, kind in ((D, "Example Dental", "client"), (E, "Example Diner", "client"),
                             (INTERNAL, "Example MSP", "internal")):
        create_client(slug, name, kind=kind)
    # D and E share Acme's ISP (AS64500); the bakery is on AS64501.
    world.transport.add_console(HOST_D, "dental-udm", desc="Example Dental")
    world.transport.add_console(HOST_E, "diner-ucg", desc="Example Diner")
    world.map_sites({SCOPE_A: A, SCOPE_B: B, SCOPE_D: D, SCOPE_E: E})


def _offline(world, *hosts: str, state: str = "disconnected") -> None:
    for h in hosts:
        world.transport.console(h).state = state


def test_three_mapped_sites_on_one_isp_offline_make_one_incident(world, monkeypatch):
    monkeypatch.delenv(isp_outage.MIN_SITES_ENV, raising=False)
    _setup(world)
    p = world.poller()
    world.run_for(p, 6 * 60)                                  # healthy fleet polls
    health = p.fleet_health()
    stats = health["sites"][SCOPE_A]["stats"]
    assert stats["isp_asn"] == 64500 and stats["isp_name"] == "Example ISP"
    assert stats["devices_total"] == 4 and stats["gateways_offline"] == 0
    assert "stats" not in [c for c in world.consumer.calls if c[0] == "site_report"][0][3]

    _offline(world, HOST_A, HOST_B, HOST_D)                  # 2 on AS64500 + 1 elsewhere
    world.run_for(p, 5 * 60)
    assert world.events(INTERNAL, "fleet.isp_outage") == []

    _offline(world, HOST_E)                                   # the third on AS64500
    world.run_for(p, 5 * 60)
    rows = world.events(INTERNAL, "fleet.isp_outage")
    assert len(rows) == 1 and rows[0]["severity"] == "high"
    payload = json.loads(rows[0]["payload"])
    assert payload["isp"]["asn"] == 64500 and payload["sites"] == 3
    assert {a["tenant"] for a in payload["affected"]} == {A, D, E}
    assert B not in rows[0]["payload"]                       # the other ISP is not in it
    (snap,) = [i for i in p.isp_outages() if i.get("vid")]
    assert snap["open"] is True and snap["sites"] == 3

    world.run_for(p, 10 * 60)                                 # still down: still one
    assert len(world.events(INTERNAL, "fleet.isp_outage")) == 1

    _offline(world, HOST_A, HOST_B, HOST_D, HOST_E, state="connected")
    world.run_for(p, 6 * 60)
    (snap,) = [i for i in p.isp_outages() if i.get("vid")]
    assert snap["open"] is False
    # A restart (a new poller over the stored state) raises nothing new.
    p2 = world.poller()
    world.run_for(p2, 6 * 60)
    assert len(world.events(INTERNAL, "fleet.isp_outage")) == 1
    # Nothing was written to the clients' own stores by the correlation.
    for slug in (A, D, E):
        assert world.events(slug, "fleet.isp_outage") == []
    assert SCOPE_B in p.fleet_health()["sites"]


def test_only_a_new_internet_issue_is_recent(world):
    """The issue lists may be histories: an entry already listed when the
    poller starts is not "now"; one that appears between two fresh fleet
    polls is recent for an hour (Fleet v2's network layer warns on that
    only; the count is data)."""
    world.map_sites({SCOPE_A: A})
    world.transport.site(HOST_A).internet_issues = [{"index": 1, "highLatency": True}]
    p = world.poller()
    world.run_for(p, 6 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["internet_issues"] == 1 and stats["issues_recent"] is False
    world.transport.site(HOST_A).internet_issues.append({"index": 2, "highLatency": True})
    world.run_for(p, 6 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["internet_issues"] == 2 and stats["issues_recent"] is True
    assert stats["issues_new_at"]
    world.run_for(p, 65 * 60)                                 # an hour with nothing new
    assert p.fleet_health()["sites"][SCOPE_A]["stats"]["issues_recent"] is False


def test_recurring_issues_are_counted_and_a_quiet_poll_ends_the_streak(world):
    """The quiet tier: a one-off blip is a notice; new entries on several
    polls (or several at once) within the hour warn — the poller counts the
    new entries of the last hour and the CONSECUTIVE polls that had some."""
    world.map_sites({SCOPE_A: A})
    site = world.transport.site(HOST_A)
    p = world.poller()
    world.run_for(p, 6 * 60)
    for i in range(1, 4):
        site.internet_issues.append({"index": i, "highLatency": True})
        world.run_for(p, 5 * 60)
        stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
        assert stats["issues_recent"] is True and stats["issues_streak"] == i
        assert stats["issues_recent_count"] == i
    world.run_for(p, 5 * 60)                                  # a poll with nothing new
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["issues_streak"] == 0 and stats["issues_recent_count"] == 3
    site.internet_issues.extend({"index": 10 + k} for k in range(2))   # two at once
    world.run_for(p, 5 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["issues_streak"] == 1 and stats["issues_recent_count"] == 5
    world.run_for(p, 65 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["issues_recent"] is False and stats["issues_recent_count"] == 0


def test_a_backup_wans_issues_are_never_the_sites(world):
    """A backup line is nice-to-have (owner decision 2026-10-02): trouble on
    WAN2 never makes the site's internet "recent issues"; the primary's does."""
    world.map_sites({SCOPE_A: A})
    site = world.transport.site(HOST_A)
    site.wans["WAN2"] = {"externalIp": "198.51.100.7", "asn": 64501, "isp": "Backup ISP"}
    p = world.poller()
    world.run_for(p, 6 * 60)
    site.wan_issues["WAN2"] = [{"index": 1, "wanDowntime": True}]
    world.run_for(p, 5 * 60)
    assert p.fleet_health()["sites"][SCOPE_A]["stats"]["issues_recent"] is False
    site.wan_issues["WAN"] = [{"index": 1, "highLatency": True}]
    world.run_for(p, 5 * 60)
    assert p.fleet_health()["sites"][SCOPE_A]["stats"]["issues_recent"] is True


def test_the_wired_wireless_offline_split_reaches_the_fleet(world):
    world.map_sites({SCOPE_A: A})
    site = world.transport.site(HOST_A)
    p = world.poller()
    world.run_for(p, 6 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert stats["devices_offline_wifi"] is None and stats["devices_offline_wired"] is None
    site.offline_wifi, site.offline_wired = 2, 0
    world.run_for(p, 5 * 60)
    stats = p.fleet_health()["sites"][SCOPE_A]["stats"]
    assert (stats["devices_offline"], stats["devices_offline_wifi"],
            stats["devices_offline_wired"]) == (2, 2, 0)
