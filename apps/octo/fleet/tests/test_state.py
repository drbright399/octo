"""The worst-state calculator — each layer, the site's worst, stale = unknown
(never ok), neutral (client) wording without vendor names; Tier Black
slice 1: black ranks first, the health layers never say Red or Black (the
re-tier table + HEALTH_CEILING), the threat layer reads incident records and
is never unknown while one is open, WAN coverage (WAN2 not configured /
backup line down), the IPS direction (N7) and DNS level (N8) splits."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from apps.octo.fleet import state as fs
from apps.octo.fleet.tests.fixtures import fleet_site

VENDORS = ("unifi", "nextdns", "datto", "rocketcyber", "ubiquiti", "kaseya")
NOW = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)


def _no_vendor(text: str) -> bool:
    return not any(v in text.lower() for v in VENDORS)


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------

def test_worst_ranks_bad_warn_unknown_notice_ok():
    assert fs.worst([fs.OK, fs.WARN, fs.UNKNOWN]) == fs.WARN
    assert fs.worst([fs.OK, fs.UNKNOWN]) == fs.UNKNOWN          # stale never reads ok
    assert fs.worst([fs.WARN, fs.BAD]) == fs.BAD
    assert fs.worst([fs.OK, fs.NOTICE]) == fs.NOTICE
    assert fs.worst([fs.NOTICE, fs.UNKNOWN]) == fs.UNKNOWN      # …nor a notice
    assert fs.worst([fs.NOTICE, fs.WARN]) == fs.WARN
    assert fs.worst([]) == fs.UNKNOWN
    assert fs.worst(["nonsense"]) == fs.UNKNOWN


def test_rank_order_including_black():
    assert fs.RANK == {fs.OK: 0, fs.NOTICE: 1, fs.UNKNOWN: 2, fs.WARN: 3, fs.BAD: 4,
                       fs.BLACK: 5}
    assert set(fs.STATES) == set(fs.RANK)
    assert fs.worst([fs.BAD, fs.BLACK, fs.WARN]) == fs.BLACK
    assert fs.worst([fs.BLACK, fs.UNKNOWN]) == fs.BLACK
    # Threat first: it wins the top-reason tie.
    assert fs.LAYERS[0] == "threat" and fs.HEALTH_CEILING == fs.WARN
    assert fs.HEALTH_LAYERS == ("network", "security", "endpoints", "buoy")


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw,state,text", [
    ({}, fs.OK, None),
    # Re-tier rows 2–4: outages are Yellow, never Red.
    ({"connected": False}, fs.WARN, "console offline"),
    ({"gateways_offline": 1}, fs.WARN, "gateway offline"),
    ({"port_up": False}, fs.WARN, "WAN down"),
    ({"devices_offline": 2}, fs.WARN, "2 devices offline"),
    # A listed issue that is not new (the list may be a history) is data only.
    ({"internet_issues": 3}, fs.OK, None),
])
def test_network_layer(kw, state, text):
    layer = fs.network_layer(fleet_site(1, **kw), fresh=True)
    assert layer.present and layer.state == state
    if text:
        assert layer.reasons[0].text == text and _no_vendor(layer.reasons[0].neutral)
    assert layer.data["pending_updates"] == 1                 # shown, never a verdict


def test_a_single_recent_internet_blip_is_a_notice():
    """Owner decision 2026-10-02: useful but noisy (rural, weather-prone
    links) — one new issue in the last hour is SEEN, not yellow."""
    site = fleet_site(1, internet_issues=3)
    assert fs.network_layer(site, fresh=True).data["internet_issues"] == 3
    site["stats"].update({"issues_recent": True, "issues_recent_count": 1, "issues_streak": 1})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.NOTICE
    assert layer.reasons[0].text == "internet blip in the last hour"
    assert _no_vendor(layer.reasons[0].neutral)
    assert layer.data["internet_issues_recent"] is True
    assert layer.data["internet_issues_level"] == fs.NOTICE


@pytest.mark.parametrize("count,streak", [(3, 1), (1, 3), (5, 2)])
def test_recurring_internet_issues_warn(count, streak):
    site = fleet_site(1)
    site["stats"].update({"issues_recent": True, "issues_recent_count": count,
                          "issues_streak": streak})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN
    assert layer.reasons[0].text == \
        f"internet issues keep recurring ({max(count, streak)} in the last hour)"
    assert layer.data["internet_issues_level"] == fs.WARN


def test_counts_without_a_recent_issue_are_nothing():
    site = fleet_site(1)
    site["stats"].update({"issues_recent": False, "issues_recent_count": 9, "issues_streak": 9})
    assert fs.network_layer(site, fresh=True).state == fs.OK


def test_an_access_point_offline_is_a_notice_a_switch_warns():
    site = fleet_site(1, devices_offline=3)
    site["stats"].update({"devices_offline_wifi": 2, "devices_offline_wired": 1})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN
    assert [(r.state, r.text) for r in layer.reasons] == [
        (fs.WARN, "1 wired device offline"), (fs.NOTICE, "2 access points offline")]
    site["stats"].update({"devices_offline": 1, "devices_offline_wifi": 1,
                          "devices_offline_wired": 0})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.NOTICE and layer.reasons[0].text == "1 access point offline"
    assert layer.reasons[0].neutral == "1 wireless access point offline"


def test_offline_devices_of_no_known_kind_warn():
    # Counts that do not add up: the remainder warns with the wired ones.
    site = fleet_site(1, devices_offline=3)
    site["stats"].update({"devices_offline_wifi": 1, "devices_offline_wired": 0})
    layer = fs.network_layer(site, fresh=True)
    assert [(r.state, r.text) for r in layer.reasons] == [
        (fs.WARN, "2 wired devices offline"), (fs.NOTICE, "1 access point offline")]
    # No split at all (a report without UniFi's wired / wireless counts):
    # every offline device warns, as before.
    assert fs.network_layer(fleet_site(1, devices_offline=2), fresh=True).state == fs.WARN


def test_stale_is_never_a_notice():
    site = fleet_site(1, devices_offline=1)
    site["stats"].update({"issues_recent": True, "issues_recent_count": 1,
                          "devices_offline_wifi": 1, "devices_offline_wired": 0})
    layer = fs.network_layer(site, fresh=False)
    assert layer.state == fs.UNKNOWN and [r.state for r in layer.reasons] == [fs.UNKNOWN]
    assert fs.cap_internet_issues(layer, "x", "y") is False


def test_the_regional_cap_holds_only_the_issue_reason():
    site = fleet_site(1, port_up=False)
    site["stats"].update({"issues_recent": True, "issues_recent_count": 4})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN
    assert fs.cap_internet_issues(layer, "likely regional", "likely regional") is True
    assert layer.state == fs.WARN                                 # WAN down stays
    assert [(r.state, r.text) for r in layer.reasons] == [
        (fs.WARN, "WAN down"), (fs.NOTICE, "likely regional")]
    recurring = fleet_site(2)
    recurring["stats"].update({"issues_recent": True, "issues_recent_count": 4})
    layer = fs.network_layer(recurring, fresh=True)
    assert layer.state == fs.WARN
    fs.cap_internet_issues(layer, "likely regional", "likely regional")
    assert layer.state == fs.NOTICE and layer.data["internet_issues_regional"] is True
    assert fs.cap_internet_issues(fs.network_layer(fleet_site(3), fresh=True), "x", "y") \
        is False                                                  # nothing to hold


def test_a_backup_wan_down_is_never_a_warning():
    """Owner decision 2026-10-02: WAN2 is nice-to-have. Many clients have no
    second line, and 'WAN2 down' was most of the Fleet's yellow. Whether it
    is configured is not known here (an older snapshot): data only."""
    site = fleet_site(1)
    site["wans"].append({"wan": "WAN2", "asn": 64501, "isp": "Backup ISP", "port_up": False})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.OK and layer.reasons == []
    assert layer.data["wan_up"] == ["WAN"] and layer.data["wan_down"] == ["WAN2"]
    assert layer.data["wan_primary"] == "WAN" and layer.data["backup_down"] == ["WAN2"]
    assert layer.data["has_backup"] is None


def test_the_primary_down_on_backup_is_a_warning():
    site = fleet_site(1)
    site["wans"][0]["port_up"] = False
    site["wans"].append({"wan": "WAN2", "asn": 64501, "isp": "Backup ISP", "port_up": True})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN
    assert layer.reasons[0].text == "WAN down — running on backup (WAN2)"
    assert layer.data["backup_down"] == []


def test_failover_priority_decides_which_line_is_primary():
    site = fleet_site(1)
    site["wans"][0]["failover_priority"] = 2                      # WAN is the BACKUP here
    site["wans"][0]["port_up"] = False
    site["wans"].append({"wan": "WAN2", "asn": 64501, "isp": "Fibre ISP", "port_up": True,
                         "failover_priority": 1})
    layer = fs.network_layer(site, fresh=True)
    assert layer.data["wan_primary"] == "WAN2"
    assert layer.state == fs.OK and layer.data["backup_down"] == ["WAN"]


def test_every_wan_down_is_yellow_not_red():
    site = fleet_site(1)
    site["wans"][0]["port_up"] = False
    site["wans"].append({"wan": "WAN2", "asn": 64501, "isp": "Backup ISP", "port_up": False})
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN and layer.reasons[0].text == "WAN down"


# ---------------------------------------------------------------------------
# WAN coverage (Rick, 2026-10-02 — most sites: WAN2 enabled but
# never plugged in; 6 single-port gateways; 4 real dual-WAN)
# ---------------------------------------------------------------------------

def _wan2(**kw):
    return {"wan": "WAN2", "asn": 64501, "isp": "Backup ISP", "port_up": False,
            "role": "backup", **kw}


def test_an_unplugged_never_addressed_wan2_is_an_operator_only_notice():
    site = fleet_site(1)
    site["wans"][0].update({"role": "primary", "configured": True})
    site["wans"].append(_wan2(configured=False, plugged=False, ipv4_present=False))
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.NOTICE
    (r,) = layer.reasons
    assert r.text == "WAN2 not configured" and r.operator_only
    assert r.neutral == "no backup internet line" and _no_vendor(r.neutral)
    assert layer.data["has_backup"] is False
    # A client user gets nothing of it: their layer is ok.
    assert fs.client_layer(layer).state == fs.OK and fs.client_layer(layer).reasons == []


def test_a_configured_backup_line_down_is_a_notice_naming_its_isp():
    site = fleet_site(1)
    site["wans"][0].update({"role": "primary", "configured": True})
    site["wans"].append(_wan2(configured=True, plugged=True, ipv4_present=True))
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.NOTICE
    assert layer.reasons[0].text == "backup line down (Backup ISP)"
    assert layer.reasons[0].neutral == "backup internet line down"
    assert not layer.reasons[0].operator_only
    assert layer.data["has_backup"] is True


def test_the_primary_down_on_a_configured_backup_still_warns():
    site = fleet_site(1, port_up=False)
    site["wans"][0].update({"role": "primary", "configured": True})
    site["wans"].append(_wan2(configured=True, port_up=True))
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN
    assert layer.reasons[0].text == "WAN down — running on backup (WAN2)"


def test_everything_down_with_an_unconfigured_backup_is_yellow():
    site = fleet_site(1, port_up=False)
    site["wans"][0].update({"role": "primary", "configured": True})
    site["wans"].append(_wan2(configured=False))
    layer = fs.network_layer(site, fresh=True)
    assert layer.state == fs.WARN and layer.reasons[0].text == "WAN down"


def test_a_single_port_gateway_has_no_backup_and_no_notice():
    layer = fs.network_layer(fleet_site(1), fresh=True)
    assert layer.state == fs.OK and layer.data["has_backup"] is False


def test_the_wan_edge_is_vendor_agnostic():
    edges = fs.wan_edges([
        {"wan": "X1", "role": "primary", "configured": True, "up": True, "asn": 64500,
         "isp": "Example ISP"},
        {"wan": "X2", "role": "backup", "configured": True, "up": False, "asn": 64501},
        {"wan": "X1/v6", "external_ip": "2001:db8::1"},
    ])
    assert edges == [
        {"name": "X1", "role": "primary", "configured": True, "up": True, "asn": 64500,
         "isp": "Example ISP"},
        {"name": "X2", "role": "backup", "configured": True, "up": False, "asn": 64501,
         "isp": None}]
    assert fs.backup_coverage(edges) is True
    assert fs.primary_wan([{"wan": "X2", "role": "primary"}, {"wan": "X1"}]) == "X2"


def test_network_stale_is_unknown_never_ok():
    layer = fs.network_layer(fleet_site(1), fresh=False)
    assert layer.state == fs.UNKNOWN
    assert "stale" in layer.reasons[0].text
    # A stale BAD site is unknown too: old data is not today's verdict.
    assert fs.network_layer(fleet_site(1, connected=False), fresh=False).state == fs.UNKNOWN


def test_network_absent_for_a_tenant_level_entry():
    assert fs.network_layer(None, fresh=True).present is False


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

def _dns(state="active", fresh=True, missing=False, threats=0, pid="abc123"):
    return fs.DnsProfile(pid, f"Profile {pid}", state, missing, fresh, threats)


def test_security_ips():
    blocked = fs.security_layer(ips=fs.IpsPart(0, 2, True), dns=[], rc=None)
    assert blocked.state == fs.WARN and blocked.reasons[0].text == "2 IPS blocks today"
    assert blocked.reasons[0].neutral == "2 intrusion attempts blocked today"
    # Re-tier row 13: detected-not-blocked is Yellow (one sensor's word).
    detected = fs.security_layer(ips=fs.IpsPart(1, 5, True), dns=[], rc=None)
    assert detected.state == fs.WARN
    assert detected.reasons[0].text == "1 IPS detection NOT blocked today"
    quiet = fs.security_layer(ips=fs.IpsPart(0, 0, True), dns=[], rc=None)
    assert quiet.state == fs.OK
    stale = fs.security_layer(ips=fs.IpsPart(0, 0, False), dns=[], rc=None)
    assert stale.state == fs.UNKNOWN


def test_n7_inbound_blocked_is_a_notice_outbound_stays_yellow():
    inbound = fs.security_layer(ips=fs.IpsPart(0, 3, True, blocked_inbound=3), dns=[], rc=None)
    assert inbound.state == fs.NOTICE
    assert inbound.reasons[0].text == "3 inbound IPS blocks today"
    assert _no_vendor(inbound.reasons[0].neutral)
    both = fs.security_layer(ips=fs.IpsPart(0, 5, True, blocked_inbound=2), dns=[], rc=None)
    assert both.state == fs.WARN
    assert [(r.state, r.text) for r in both.reasons] == [
        (fs.WARN, "3 IPS blocks today"), (fs.NOTICE, "2 inbound IPS blocks today")]
    # Tunable to Yellow, never above it.
    tuned = fs.security_layer(ips=fs.IpsPart(0, 1, True, blocked_inbound=1), dns=[], rc=None,
                              settings={"ips_inbound_blocked_level": "warn"})
    assert tuned.state == fs.WARN
    never = fs.security_layer(ips=fs.IpsPart(0, 1, True, blocked_inbound=1), dns=[], rc=None,
                              settings={"ips_inbound_blocked_level": "bad"})
    assert never.state == fs.NOTICE                  # a knob never names Red


def test_a1_dns_blocks_are_a_counted_notice_whatever_the_reason():
    """v0.17.1 (Rick, 2026-10-06), replacing N8's ">= 1 HIGH → WARN": "a
    block is NextDNS doing its job" — HIGH, MEDIUM or known-benign, the count
    is a NOTICE; only a device that looks wrong is Yellow."""
    def prof(**kw):
        return fs.DnsProfile("abc123", "Profile abc123", "active", False, True,
                             kw.pop("total", 0), **kw)

    high = fs.security_layer(ips=None, dns=[prof(total=3, threats_high=1, threats_medium=2)],
                             rc=None)
    assert high.state == fs.NOTICE
    assert [(r.state, r.text, r.neutral) for r in high.reasons] == [
        (fs.NOTICE, "3 threats blocked today", "3 threats blocked by DNS protection today")]
    medium = fs.security_layer(ips=None, dns=[prof(total=4, threats_high=0, threats_medium=4)],
                               rc=None)
    assert medium.state == fs.NOTICE
    # The Samsung probe (known-benign) is not a threat: an operator-only
    # notice when it is all there is; "not counted" beside real blocks.
    benign = fs.security_layer(ips=None, dns=[prof(total=2, threats_high=0, threats_benign=2)],
                               rc=None)
    assert benign.state == fs.NOTICE
    assert benign.reasons[0].text == "2 known-benign DNS blocks today"
    assert benign.reasons[0].operator_only
    both = fs.security_layer(ips=None, dns=[prof(total=3, threats_high=1, threats_benign=2)],
                             rc=None)
    assert both.reasons[0].text == "1 threat blocked today (+2 known-benign not counted)"
    # An unsplit count (an older caller): counted, still a notice.
    assert fs.security_layer(ips=None, dns=[prof(total=2)], rc=None).state == fs.NOTICE
    # A1 "no WARN merely because blocks happened": the v0.17 knob that could
    # raise the count is RETIRED (fixer) — a value stored under v0.17 is
    # ignored, never reinterpreted.
    assert "dns_medium_level" not in fs.KNOB_DEFAULTS
    for stale in ("warn", "black"):
        assert fs.security_layer(ips=None, dns=[prof(total=2, threats_high=2)], rc=None,
                                 settings={"dns_medium_level": stale}).state == fs.NOTICE


def test_a_newly_pending_profile_is_a_notice_then_yellow():
    young = fs.DnsProfile("abc123", "Profile abc123", "pending", False, True,
                          pending_since=NOW - timedelta(days=2))
    layer = fs.security_layer(ips=None, dns=[young], rc=None, now=NOW)
    assert layer.state == fs.NOTICE
    assert layer.reasons[0].text == "NextDNS pending (Profile abc123) — newly mapped"
    old = fs.DnsProfile("abc123", "Profile abc123", "pending", False, True,
                        pending_since=NOW - timedelta(days=8))
    assert fs.security_layer(ips=None, dns=[old], rc=None, now=NOW).state == fs.WARN
    tuned = fs.security_layer(ips=None, dns=[old], rc=None, now=NOW,
                              settings={"nextdns_pending_days": 14})
    assert tuned.state == fs.NOTICE
    # When it began is not known: Yellow (the safer reading).
    unknown = fs.DnsProfile("abc123", "Profile abc123", "pending", False, True)
    assert fs.security_layer(ips=None, dns=[unknown], rc=None, now=NOW).state == fs.WARN


@pytest.mark.parametrize("profile,state,text,neutral", [
    (_dns(), fs.OK, None, None),
    # Re-tier row 16: a protection gap is Yellow.
    (_dns("lapsed"), fs.WARN, "NextDNS lapsed (Profile abc123)", "DNS protection lapsed"),
    (_dns(missing=True), fs.WARN, "NextDNS profile missing (Profile abc123)",
     "DNS protection not found"),
    (_dns("pending"), fs.WARN, "NextDNS pending (Profile abc123)",
     "DNS protection not confirmed yet"),
    (_dns("new"), fs.WARN, "NextDNS pending (Profile abc123)",
     "DNS protection not confirmed yet"),
    (_dns(threats=4), fs.NOTICE, "4 threats blocked today",
     "4 threats blocked by DNS protection today"),
    (_dns("lapsed", fresh=False), fs.UNKNOWN, "NextDNS Profile abc123: not checked recently",
     "DNS protection data is out of date"),
    # An active profile NextDNS stopped showing lapses: lapsed AND missing is
    # still a problem, never downgraded to "missing".
    (_dns("lapsed", missing=True), fs.WARN, "NextDNS lapsed (Profile abc123)",
     "DNS protection lapsed"),
])
def test_security_nextdns(profile, state, text, neutral):
    layer = fs.security_layer(ips=None, dns=[profile], rc=None)
    assert layer.present and layer.state == state
    if text:
        assert layer.reasons[0].text == text
        assert layer.reasons[0].neutral == neutral and _no_vendor(neutral)
    assert layer.data["dns_profiles"][0]["profile_id"] == "abc123"


def test_security_rocketcyber():
    assert fs.security_layer(ips=None, dns=[], rc=fs.RcPart(0, True)).state == fs.OK
    # Re-tier row 21: tenant-wide, no device, one source — Yellow. The client
    # wording says "alert" (an "incident" is the Red / Black record).
    rc = fs.security_layer(ips=None, dns=[], rc=fs.RcPart(2, True))
    assert rc.state == fs.WARN and rc.reasons[0].text == "2 open RocketCyber incidents"
    assert rc.reasons[0].neutral == "2 open security alerts"
    assert fs.security_layer(ips=None, dns=[], rc=fs.RcPart(2, False)).state == fs.UNKNOWN


def test_security_is_the_worst_of_its_parts_and_absent_without_any():
    layer = fs.security_layer(ips=fs.IpsPart(0, 1, True), dns=[_dns("lapsed")],
                              rc=fs.RcPart(0, True))
    assert layer.state == fs.WARN
    assert [r.state for r in layer.reasons] == [fs.WARN, fs.WARN]
    assert fs.security_layer(ips=None, dns=[], rc=None).present is False
    # One fresh-ok part and one stale part: unknown, never ok.
    mixed = fs.security_layer(ips=fs.IpsPart(0, 0, True), dns=[], rc=fs.RcPart(0, False))
    assert mixed.state == fs.UNKNOWN


# ---------------------------------------------------------------------------
# Endpoints, buoy
# ---------------------------------------------------------------------------

def test_endpoints_layer():
    assert fs.endpoints_layer(None).present is False
    ok = fs.endpoints_layer(fs.Inventory(10, 6, 4, 0, True))
    assert ok.state == fs.OK and ok.data["agents_offline"] == 4     # PCs off at night: ok
    # Re-tier row 23: a server offline is an outage — Yellow.
    srv = fs.endpoints_layer(fs.Inventory(10, 8, 2, 1, True))
    assert srv.state == fs.WARN and srv.reasons[0].text == "1 server offline"
    assert fs.endpoints_layer(fs.Inventory(10, 10, 0, 0, False)).state == fs.UNKNOWN


@pytest.mark.parametrize("health,state", [
    # Re-tier row 25: the buoy down is a sensor outage — Yellow.
    ("green", fs.OK), ("yellow", fs.WARN), ("red", fs.WARN), ("stale", fs.UNKNOWN),
    ("unknown", fs.UNKNOWN),
])
def test_buoy_layer(health, state):
    layer = fs.buoy_layer(health)
    assert layer.present and layer.state == state and layer.scope == "tenant"
    for r in layer.reasons:
        assert _no_vendor(r.neutral) and "buoy" not in r.neutral.lower()
    assert fs.buoy_layer(None).present is False


def test_a_canary_port_touch_is_yellow():
    layer = fs.buoy_layer("green", canary_touches=2)
    assert layer.state == fs.WARN and layer.reasons[0].text == "decoy touched 2 times in 24 h"
    assert _no_vendor(layer.reasons[0].neutral)
    assert fs.buoy_layer("green", canary_touches=0).state == fs.OK


# ---------------------------------------------------------------------------
# P1 — the health layers are never Red or Black
# ---------------------------------------------------------------------------

def _health_layers_at_their_worst() -> list[fs.Layer]:
    """Every reason generator of every health layer, driven as hard as it
    goes (each outage, gap and alert on at once)."""
    site = fleet_site(1, connected=False, gateways_offline=1, port_up=False,
                      devices_offline=4)
    site["stats"].update({"issues_recent": True, "issues_recent_count": 9,
                          "devices_offline_wifi": 1, "devices_offline_wired": 1,
                          "critical_notifications": 3})
    site["wans"].append({"wan": "WAN2", "port_up": False, "configured": False})
    out = [fs.network_layer(site, fresh=True), fs.network_layer(site, fresh=False)]
    for dns in ([_dns("lapsed")], [_dns(missing=True)], [_dns("pending")],
                [_dns(threats=9)], [_dns("lapsed", missing=True, threats=5)]):
        out.append(fs.security_layer(ips=fs.IpsPart(7, 9, True, blocked_inbound=3), dns=dns,
                                     rc=fs.RcPart(4, True)))
    out.append(fs.endpoints_layer(fs.Inventory(10, 0, 10, 10, True)))
    for health in ("green", "yellow", "red", "stale"):
        out.append(fs.buoy_layer(health, canary_touches=5))
    return out


def test_health_layers_never_red_or_black():
    for layer in _health_layers_at_their_worst():
        assert layer.name in fs.HEALTH_LAYERS
        assert fs.RANK[layer.state] <= fs.RANK[fs.HEALTH_CEILING], (layer.name, layer.state)
        for r in layer.reasons:
            assert r.state not in (fs.BAD, fs.BLACK), (layer.name, r.text)
        assert "clamped" not in layer.data          # no generator needed the clamp


def test_the_ceiling_clamps_and_logs_a_reason_that_slips_past(caplog):
    layer = fs.Layer("security", present=True)
    layer.reasons.append(fs.Reason(fs.BAD, "a reason a future change got wrong", "x",
                                   "security"))
    with caplog.at_level(logging.WARNING, logger="apps.octo.fleet.state"):
        fs._finish(layer, [fs.OK, fs.BLACK])
    assert layer.state == fs.WARN and layer.reasons[0].state == fs.WARN
    assert layer.data["clamped"] is True
    assert "clamped" in caplog.text
    # The threat layer is NOT a health layer: never clamped.
    threat = fs.Layer("threat", present=True)
    fs._finish(threat, [fs.OK, fs.BLACK])
    assert threat.state == fs.BLACK


# ---------------------------------------------------------------------------
# The threat layer (incident records)
# ---------------------------------------------------------------------------

@dataclass
class Inc:
    """The incident fields the state calculator reads (threat.store.Incident's)."""
    id: int
    tier: str
    status: str = "open"
    summary: str = "credential tried on a decoy"
    detected_at: str = "2026-10-03T14:48:00.000Z"
    device_label: Optional[str] = "ws-01"
    device_ref: Optional[str] = "ws-01"
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    contained_at: Optional[str] = None
    closed_at: Optional[str] = None
    close_reason_code: Optional[str] = None
    rule_id: str = "B6"

    @property
    def is_open(self) -> bool:
        return self.status not in ("closed", "false_positive")

    @property
    def acked(self) -> bool:
        return self.acknowledged_at is not None

    @property
    def contained(self) -> bool:
        return self.contained_at is not None

    @property
    def true_positive(self) -> bool:
        return self.close_reason_code == "remediated"


def _closed(n: int, days: float, code: str) -> Inc:
    at = (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return Inc(n, "red", status="closed", closed_at=at, close_reason_code=code)


@pytest.mark.parametrize("incs,state,text", [
    ([], fs.OK, None),
    ([Inc(1, "black")], fs.BLACK,
     "BLACK: credential tried on a decoy on ws-01 (12 min, unacknowledged)"),
    ([Inc(1, "black", acknowledged_by="7", acknowledged_at="2026-10-03T14:50:00.000Z")],
     fs.BLACK, "BLACK: credential tried on a decoy on ws-01 (12 min, acknowledged by alice)"),
    ([Inc(1, "black", contained_at="2026-10-03T14:55:00.000Z")], fs.BLACK,
     "BLACK: credential tried on a decoy on ws-01 (12 min, contained)"),
    ([Inc(2, "red")], fs.BAD, "Red: credential tried on a decoy on ws-01 (12 min, "
                              "unacknowledged)"),
    ([_closed(3, 2, "remediated")], fs.WARN, None),               # post-incident watch
    ([_closed(3, 9, "remediated")], fs.NOTICE, "security incident closed 2026-09-24"),
    ([_closed(3, 2, "false_positive")], fs.NOTICE, None),         # no watch for an FP
    ([_closed(3, 31, "remediated")], fs.OK, None),                # past the 30-day tail
])
def test_threat_layer_states(incs, state, text):
    layer = fs.threat_layer(incs, now=NOW, names={"7": "alice"})
    assert layer.present and layer.name == "threat" and layer.state == state
    if text:
        assert layer.reasons[0].text == text


def test_the_watch_follows_the_watch_days_knob():
    layer = fs.threat_layer([_closed(3, 5, "remediated")], now=NOW, watch_days=3)
    assert layer.state == fs.NOTICE
    assert fs.threat_layer([_closed(3, 5, "remediated")], now=NOW, watch_days=7).state == fs.WARN


def test_threat_layer_is_never_unknown_while_an_incident_is_open():
    # The worker stale, the store unreadable (the last known set shown):
    # the open incident still decides.
    layer = fs.threat_layer([Inc(1, "black")], now=NOW, worker_fresh=False,
                            stale_since="2026-10-03T14:40:00.000Z", unreadable=True)
    assert layer.state == fs.BLACK
    assert layer.data["stale_since"] == "2026-10-03T14:40:00.000Z"
    assert any(r.text == "threat correlator not running" and r.state == fs.NOTICE
               for r in layer.reasons)
    red = fs.threat_layer([Inc(2, "red")], now=NOW, worker_fresh=False, unreadable=True)
    assert red.state == fs.BAD
    # Nothing open and the worker stale: unknown — never ok.
    idle = fs.threat_layer([], now=NOW, worker_fresh=False)
    assert idle.state == fs.UNKNOWN and idle.reasons[0].text == "threat correlator not running"
    assert _no_vendor(idle.reasons[0].neutral)
    # Nothing open and the store unreadable with no last-known set: unknown.
    assert fs.threat_layer([], now=NOW, unreadable=True).state == fs.UNKNOWN


def test_an_unreadable_store_with_nothing_open_known_is_unknown_for_the_client_too():
    """Stale never reads OK: the last good read held no open incident, the
    store is unreadable NOW (one opened since could be hiding) — unknown,
    with a reason a client user keeps (never their "all clear")."""
    layer = fs.threat_layer([], now=NOW, stale_since="2026-10-03T14:40:00.000Z",
                            unreadable=True)
    assert layer.state == fs.UNKNOWN
    client = fs.client_layer(layer)
    assert client.state == fs.UNKNOWN
    assert [r.neutral for r in client.reasons] == ["security monitoring status unknown"]
    # A closed incident's notice tail in the last-known set changes nothing:
    # still unknown (a true positive's watch, Yellow, would outrank it).
    closed = _closed(3, 2, "false_positive")
    assert fs.threat_layer([closed], now=NOW, stale_since="2026-10-03T14:40:00.000Z",
                           unreadable=True).state == fs.UNKNOWN


def test_fr2_blindness_is_yellow_for_the_tenant_notice_fleet_wide():
    @dataclass
    class B:
        label: str
        since: str
        fleet_wide: bool

    own = fs.threat_layer([], now=NOW, blind=[B("NextDNS", "2026-10-03T13:00:00.000Z", False)])
    assert own.state == fs.WARN
    assert own.reasons[0].text == "Athena is blind to NextDNS here since 13:00 UTC"
    fleet = fs.threat_layer([], now=NOW, blind=[B("Datto RMM", "2026-10-03T13:00:00.000Z",
                                                  True)])
    assert fleet.state == fs.NOTICE
    # An open incident is untouched by it.
    assert fs.threat_layer([Inc(1, "black")], now=NOW,
                           blind=[B("NextDNS", "2026-10-03T13:00:00.000Z", False)]).state \
        == fs.BLACK


def test_shadow_would_fires_are_an_operator_only_notice():
    layer = fs.threat_layer([], now=NOW, would_fire={"R6": 2})
    assert layer.state == fs.NOTICE
    assert layer.reasons[0].text == "would have been Red: R6 ×2 (shadow, 24 h)"
    assert layer.reasons[0].operator_only
    assert fs.client_layer(layer).state == fs.OK


def test_an_unknown_location_is_labelled():
    layer = fs.threat_layer([Inc(4, "red")], now=NOW, unknown_location={4})
    assert layer.reasons[0].text.endswith("— device location unknown")


# ---------------------------------------------------------------------------
# The site
# ---------------------------------------------------------------------------

def test_site_verdict_and_reason_line():
    layers = {
        "network": fs.network_layer(fleet_site(1), fresh=True),
        "security": fs.security_layer(ips=fs.IpsPart(0, 2, True), dns=[], rc=None),
        "endpoints": fs.endpoints_layer(None),
        "buoy": fs.buoy_layer(None),
    }
    v = fs.site_verdict(layers)
    assert v.state == fs.WARN and fs.reason_line(v) == "2 IPS blocks today"
    layers["security"] = fs.security_layer(ips=fs.IpsPart(0, 2, True), dns=[_dns("lapsed")],
                                           rc=None)
    v = fs.site_verdict(layers)
    assert v.state == fs.WARN
    assert fs.reason_line(v) == "2 IPS blocks today (+1 more)"
    assert fs.reason_line(v, neutral=True) == "2 intrusion attempts blocked today (+1 more)"
    layers["network"] = fs.network_layer(fleet_site(1, gateways_offline=1), fresh=True)
    v = fs.site_verdict(layers)
    assert fs.reason_line(v) == "gateway offline (+2 more)"            # layer order on a tie
    # An incident outranks every health reason; the threat layer wins the tie.
    layers["threat"] = fs.threat_layer([Inc(2, "red")], now=NOW)
    v = fs.site_verdict(layers)
    assert v.state == fs.BAD and fs.reason_line(v).startswith("Red: credential tried")
    assert fs.reason_line(v, neutral=True) == "security issue under investigation (+3 more)"


def test_reason_line_never_folds_a_black():
    layers = {"threat": fs.threat_layer([Inc(1, "black"), Inc(2, "black", summary="ransom note",
                                                                device_label="srv-01")],
                                        now=NOW),
              "security": fs.security_layer(ips=fs.IpsPart(0, 2, True), dns=[], rc=None)}
    v = fs.site_verdict(layers)
    assert v.state == fs.BLACK
    line = fs.reason_line(v)
    assert "BLACK: credential tried on a decoy on ws-01" in line
    assert "BLACK: ransom note on srv-01" in line
    assert line.endswith("(+1 more)")                 # only the Yellow is folded
    assert fs.reason_line(v, neutral=True) == "urgent security incident (+1 more)"


def test_stale_layer_turns_an_ok_site_unknown():
    layers = {"network": fs.network_layer(fleet_site(1), fresh=True),
              "security": fs.security_layer(ips=fs.IpsPart(0, 0, False), dns=[], rc=None)}
    v = fs.site_verdict(layers)
    assert v.state == fs.UNKNOWN and fs.reason_line(v).startswith("UniFi system log")


def test_a_notice_shows_only_when_nothing_is_worse():
    blip = fleet_site(1)
    blip["stats"].update({"issues_recent": True, "issues_recent_count": 1})
    layers = {"network": fs.network_layer(blip, fresh=True)}
    v = fs.site_verdict(layers)
    assert v.state == fs.NOTICE and fs.reason_line(v) == "internet blip in the last hour"
    layers["security"] = fs.security_layer(ips=fs.IpsPart(0, 2, True), dns=[], rc=None)
    v = fs.site_verdict(layers)
    assert v.state == fs.WARN and fs.reason_line(v) == "2 IPS blocks today"   # no "+1 more"
    layers["security"] = fs.security_layer(ips=fs.IpsPart(0, 0, False), dns=[], rc=None)
    assert fs.site_verdict(layers).state == fs.UNKNOWN                        # stale > notice


def test_no_present_layer_is_unknown():
    v = fs.site_verdict({"network": fs.network_layer(None, fresh=True)})
    assert v.state == fs.UNKNOWN and fs.reason_line(v) == "no data source reports on this site yet"
    ok = fs.site_verdict({"network": fs.network_layer(fleet_site(1), fresh=True)})
    assert ok.state == fs.OK and fs.reason_line(ok) == "all clear"


def test_the_threat_layer_never_stands_in_for_data():
    """The threat layer is always present (an incident can land anywhere): a
    site with NO health layer and a clean threat layer is unknown, never
    Green "all clear" (P8, re-tier row 27). Its notices do not outrank that;
    an open incident, a watch or blindness do."""
    absent = {"network": fs.network_layer(None, fresh=True)}
    clean = fs.site_verdict({**absent, "threat": fs.threat_layer([], now=NOW)})
    assert clean.state == fs.UNKNOWN
    assert fs.reason_line(clean) == "no data source reports on this site yet"
    assert fs.reason_line(clean, neutral=True) == "no data reported yet"
    tail = fs.site_verdict({**absent, "threat": fs.threat_layer([_closed(3, 9, "remediated")],
                                                                now=NOW)})
    assert tail.state == fs.UNKNOWN
    watch = fs.site_verdict({**absent, "threat": fs.threat_layer([_closed(3, 2, "remediated")],
                                                                 now=NOW)})
    assert watch.state == fs.WARN
    black = fs.site_verdict({**absent, "threat": fs.threat_layer([Inc(1, "black")], now=NOW)})
    assert black.state == fs.BLACK
    # One health layer present: the threat layer adds to it, nothing more.
    with_data = fs.site_verdict({"network": fs.network_layer(fleet_site(1), fresh=True),
                                 "threat": fs.threat_layer([], now=NOW)})
    assert with_data.state == fs.OK


def test_rows_5_and_11_are_yellow_tunable_to_notice():
    down = {**fleet_site(1), "wans": [
        {"wan": "WAN", "port_up": False, "failover_priority": 1},
        {"wan": "WAN2", "port_up": True, "failover_priority": 2}]}
    assert fs.network_layer(down, fresh=True).state == fs.WARN
    quiet = {"primary_on_backup_level": fs.NOTICE, "critical_notifications_level": fs.NOTICE}
    assert fs.network_layer(down, fresh=True, settings=quiet).state == fs.NOTICE
    site = fleet_site(1)
    loud = {**site, "stats": {**site["stats"], "critical_notifications": 2}}
    assert fs.network_layer(loud, fresh=True).state == fs.WARN
    assert fs.network_layer(loud, fresh=True, settings=quiet).state == fs.NOTICE
    # A knob never names Red or Black.
    assert fs.network_layer(down, fresh=True,
                            settings={"primary_on_backup_level": fs.BAD}).state == fs.WARN
