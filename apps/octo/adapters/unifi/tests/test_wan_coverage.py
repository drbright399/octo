"""WAN coverage (Rick, 2026-10-02 23:52; Tier Black slice 1): each site WAN
carries what the console says of its PORT — plugged in, holding an IPv4 —
from /v1/hosts reportedState.wans (matched by type 'WAN' / 'WAN2' to
statistics.wans), its role (primary / backup) and the vendor-agnostic
`configured` the Fleet reads. Calibrated on the three shapes a production
fleet shows: WAN2 enabled but never plugged in (most sites), a single WAN
port, a real dual-WAN. And N7: the IPS direction rides in the coalescing subject."""
from __future__ import annotations

from apps.octo.adapters.unifi import catalogue
from apps.octo.adapters.unifi import poller as poller_mod
from apps.octo.adapters.unifi.tests.fake_unifi import lan
from apps.octo.fleet import state as fs

HOST = "F1X70001000000000000000000000000000000000000000000000000:100000001"
SITE = "f1x7517e0000000000000001"


def _fleet(host_wans: list[dict], site_wans: dict) -> dict:
    hosts = [{"id": HOST, "reportedState": {"hostname": "console-1", "state": "connected",
                                            "wans": host_wans}}]
    sites = [{"hostId": HOST, "siteId": SITE, "meta": {"name": "default", "desc": "Default"},
              "statistics": {"counts": {"offlineGatewayDevice": 0},
                             "ispInfo": {"asn": 64500, "name": "Example ISP"},
                             "wans": site_wans}}]
    (info,) = poller_mod.build_fleet(hosts, sites).values()
    return {w["wan"]: w for w in info.wans}


def test_wan2_enabled_but_never_plugged_in_is_not_configured():
    wans = _fleet(
        [{"type": "WAN", "plugged": True, "enabled": True, "ipv4": "192.0.2.10"},
         {"type": "WAN2", "plugged": False, "enabled": True}],
        {"WAN": {"externalIp": "192.0.2.10", "portUp": True},
         "WAN2": {"portUp": False}})
    assert wans["WAN"]["role"] == "primary" and wans["WAN"]["configured"] is True
    # The site-level provider is BORROWED for a WAN with none of its own —
    # marked, so no text ever names it as this line's provider.
    assert wans["WAN2"] == {"wan": "WAN2", "port_up": False, "plugged": False,
                            "ipv4_present": False, "configured": False, "role": "backup",
                            "asn": 64500, "isp": "Example ISP", "isp_from": "site",
                            "shared_external": False}
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert [r.text for r in layer.reasons] == ["WAN2 not configured"]
    assert layer.data["has_backup"] is False
    # Not "down": a line nobody connected is coverage, not an outage.
    assert layer.data["wan_down"] == [] and layer.data["wan_unconfigured"] == ["WAN2"]


def test_a_single_wan_port_gateway_has_no_backup():
    wans = _fleet([{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"}],
                  {"WAN": {"externalIp": "192.0.2.10", "portUp": True}})
    assert list(wans) == ["WAN"] and wans["WAN"]["role"] == "primary"
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert layer.state == fs.OK and layer.data["has_backup"] is False


def test_an_unplugged_wan2_and_an_unknown_primary_are_not_every_wan_down():
    wans = _fleet(
        [{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"},
         {"type": "WAN2", "plugged": False, "enabled": True}],
        {"WAN": {"externalIp": "192.0.2.10"},                  # primary: portUp unknown
         "WAN2": {"portUp": False}})
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert "WAN down" not in [r.text for r in layer.reasons]
    assert layer.state == fs.NOTICE                            # WAN2 not configured only


def test_the_backup_line_text_names_only_its_own_provider():
    wans = _fleet(
        [{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"},
         {"type": "WAN2", "plugged": True, "ipv4": "198.51.100.7"}],
        {"WAN": {"externalIp": "192.0.2.10", "portUp": True, "failoverPriority": 1},
         "WAN2": {"externalIp": "198.51.100.7", "portUp": False, "failoverPriority": 2}})
    assert wans["WAN2"]["isp_from"] == "site"                  # the primary's provider
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert [r.text for r in layer.reasons] == ["backup line down"]
    assert "Example ISP" not in " ".join(r.text for r in layer.reasons)


def test_a_multi_site_console_never_lends_its_own_ports_to_its_sites():
    hosts = [{"id": HOST, "reportedState": {"hostname": "console-1", "state": "connected",
                                            "wans": [{"type": "WAN", "plugged": True,
                                                      "ipv4": "192.0.2.10"},
                                                     {"type": "WAN2", "plugged": False}]}}]
    sites = [{"hostId": HOST, "siteId": f"f1x7517e000000000000000{n}",
              "meta": {"name": f"site{n}", "desc": f"Site {n}"},
              "statistics": {"counts": {}, "wans": {"WAN": {"portUp": True},
                                                    "WAN2": {"portUp": False}}}}
             for n in (1, 2)]
    for info in poller_mod.build_fleet(hosts, sites).values():
        wan2 = next(w for w in info.wans if w["wan"] == "WAN2")
        # The console's own unplugged WAN2 is not this site's: unknown, so a
        # hosted site whose real WAN2 dropped is never "not configured".
        assert "configured" not in wan2 and "plugged" not in wan2
        layer = fs.network_layer({"wans": info.wans, "stats": {}}, fresh=True)
        assert "WAN2 not configured" not in [r.text for r in layer.reasons]
        assert layer.data["has_backup"] is None


def test_a_real_dual_wan_whose_backup_drops_is_a_notice():
    wans = _fleet(
        [{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"},
         {"type": "WAN2", "plugged": True, "ipv4": "198.51.100.7"}],
        {"WAN": {"externalIp": "192.0.2.10", "portUp": True, "failoverPriority": 1},
         "WAN2": {"externalIp": "198.51.100.7", "portUp": False, "failoverPriority": 2,
                  "ispInfo": {"asn": 64501, "name": "Backup ISP"}}})
    assert wans["WAN2"]["configured"] is True and wans["WAN2"]["role"] == "backup"
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert layer.state == fs.NOTICE
    assert [r.text for r in layer.reasons] == ["backup line down (Backup ISP)"]
    assert layer.data["has_backup"] is True


def test_a_backup_line_that_drops_is_down_not_never_configured(monkeypatch):
    """A real dual-WAN site whose backup modem dies (or whose cable is
    pulled): its port then reads unplugged with no address — exactly a WAN2
    nobody ever connected. The poller REMEMBERS it was configured (30 days,
    restart-safe): "backup line down", never "WAN2 not configured", and the
    site is not counted among those without a backup line."""
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    p = poller_mod.UniFiPoller(adapter=None, client=SimpleNamespace(), sink=None,
                               instance_id=None)
    t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    hosts = lambda wan2: [{"id": HOST, "reportedState": {  # noqa: E731
        "hostname": "console-1", "state": "connected",
        "wans": [{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"}, wan2]}}]
    sites = lambda up: [{"hostId": HOST, "siteId": SITE,  # noqa: E731
                         "meta": {"name": "default", "desc": "Default"},
                         "statistics": {"counts": {}, "wans": {
                             "WAN": {"portUp": True, "failoverPriority": 1},
                             "WAN2": {"portUp": up, "failoverPriority": 2,
                                      "ispInfo": {"name": "Backup ISP"}}}}}]

    def poll(wan2: dict, up: bool, at: datetime) -> dict:
        p._fleet = poller_mod.build_fleet(hosts(wan2), sites(up))
        p._remember_wans(at)
        (info,) = p._fleet.values()
        return next(w for w in info.wans if w["wan"] == "WAN2")

    # A working backup line, seen configured …
    assert poll({"type": "WAN2", "plugged": True, "ipv4": "198.51.100.7"}, True, t0)[
        "configured"] is True
    # … then its modem dies: unplugged, no address.
    wan2 = poll({"type": "WAN2", "plugged": False}, False, t0 + timedelta(hours=3))
    assert wan2["configured"] is True and wan2["configured_from"] == "history"
    layer = fs.network_layer({"wans": [w for w in next(iter(p._fleet.values())).wans],
                              "stats": {}}, fresh=True)
    assert [r.text for r in layer.reasons] == ["backup line down (Backup ISP)"]
    assert layer.data["has_backup"] is True
    # Restart-safe: the memory rides in the poller's saved state.
    saved: dict = {}
    p._instance_id = 7
    monkeypatch.setattr(poller_mod.poller_state, "save",
                        lambda _i, _k, v: saved.update(v) or True)
    p._save_state()
    (scope,) = saved["wan_seen"]
    assert scope.endswith(SITE) and "WAN2" in saved["wan_seen"][scope]
    fresh = poller_mod.UniFiPoller(adapter=None, client=SimpleNamespace(), sink=None,
                                   instance_id=7)
    monkeypatch.setattr(poller_mod.poller_state, "load", lambda _i, _k: saved)
    fresh._load_state()
    assert fresh._wan_seen == saved["wan_seen"]
    # Unplugged for longer than the memory: decommissioned → "not configured".
    late = poll({"type": "WAN2", "plugged": False}, False, t0 + timedelta(days=31))
    assert late["configured"] is False


def test_a_port_the_console_does_not_describe_is_never_guessed():
    wans = _fleet([{"type": "WAN", "plugged": True, "ipv4": "192.0.2.10"}],
                  {"WAN": {"externalIp": "192.0.2.10", "portUp": True},
                   "WAN2": {"portUp": False}})
    assert "configured" not in wans["WAN2"] and "plugged" not in wans["WAN2"]
    layer = fs.network_layer({"wans": list(wans.values()), "stats": {}}, fresh=True)
    assert layer.state == fs.OK and layer.data["has_backup"] is None


def test_an_ipv4_alone_or_a_disabled_port_decides():
    ports = poller_mod.host_wan_ports({"wans": [
        {"type": "WAN", "ipv4": "198.51.100.2"},              # no plugged flag, an address
        {"type": "WAN2", "plugged": True, "enabled": False},
        {"type": "WAN3", "enabled": False}]})
    assert poller_mod.wan_configured(ports["WAN"], None) is True
    assert poller_mod.wan_configured(ports["WAN2"], None) is True       # plugged wins
    assert poller_mod.wan_configured(ports["WAN3"], None) is False
    assert poller_mod.wan_configured(None, True) is True                # up = configured
    assert poller_mod.wan_configured(None, None) is None


# ---------------------------------------------------------------------------
# N7 — the IPS direction
# ---------------------------------------------------------------------------

def _ev(src: str, dst: str, event: str = "THREAT_BLOCKED") -> catalogue.LogEvent:
    return catalogue.LogEvent(
        id="e1", ts_ms=1_759_500_000_000, category="SECURITY",
        subcategory="SECURITY_INTRUSION_PREVENTION", event=event, vendor_severity="HIGH",
        title="Threat Blocked", message="", target="", title_raw="Threat Blocked",
        parameters={"SRC_IP": {"id": src}, "DST_IP": {"id": dst},
                    "SIGNATURE": {"id": "2010935", "name": "ET EXAMPLE"}})


def test_n7_direction_from_the_two_ends():
    # The site's own end is told by its (private) address space: lan(n).
    assert catalogue.ips_direction("203.0.113.9", lan(5)) == "inbound"
    assert catalogue.ips_direction(lan(5), "203.0.113.9") == "outbound"
    assert catalogue.ips_direction(lan(5), lan(6)) is None
    assert catalogue.ips_direction(None, lan(6)) is None


def test_n7_the_direction_sits_before_the_action_in_the_subject():
    inbound = _ev("203.0.113.9", lan(5))
    subj = catalogue.subject_of("ips_threat", inbound, catalogue.ips_fields(inbound))
    assert subj.endswith("|inbound|blocked") and subj.rsplit("|", 1)[-1] == "blocked"
    outbound = _ev(lan(5), "203.0.113.9", "THREAT_DETECTED")
    assert catalogue.subject_of("ips_threat", outbound,
                                catalogue.ips_fields(outbound)).endswith("|outbound|detected")
