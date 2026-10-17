"""The event catalogue and the OCSF mapping at the boundary: every event of the
fleet catalogue (2026-09-30) lands in its family and kind; an unknown event
the vendor rates HIGH is never only counted; every kind has one consistent
OCSF class; IPS fields are read tolerantly; a payload is a pure function of
the event."""
from __future__ import annotations

from datetime import timedelta

import pytest

from apps.octo.adapters.unifi import catalogue, ocsf
from apps.octo.adapters.unifi.catalogue import ROLLUP, SIGNAL, classify
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    SCOPE_A,
    SITE_DEFAULT,
    T0,
    client_event,
    ips_event,
    lan,
    legacy_ips_event,
    log_event,
    mac,
)

# (category, subcategory, event, vendor severity) → (family, kind, severity)
CATALOGUE = [
    ("CLIENT_DEVICES", "MONITORING_WIFI", "CLIENT_ROAMED", "LOW", ROLLUP, "client_roam", ""),
    ("CLIENT_DEVICES", "MONITORING_WIFI", "CLIENT_CONNECTED_WIRELESS", "LOW", ROLLUP, "client_connect", ""),
    ("CLIENT_DEVICES", "MONITORING_WIFI", "CLIENT_DISCONNECTED_WIRELESS", "LOW", ROLLUP, "client_disconnect", ""),
    ("CLIENT_DEVICES", "MONITORING_WIRED", "CLIENT_DISCONNECTED_WIRED", "LOW", ROLLUP, "client_disconnect", ""),
    ("CLIENT_DEVICES", "MONITORING_WIRED", "CLIENT_CONNECTED_WIRED", "LOW", ROLLUP, "client_connect", ""),
    ("SECURITY", "SECURITY_FIREWALL", "BLOCKED_BY_FIREWALL", "MEDIUM", ROLLUP, "firewall_block", ""),
    ("SECURITY", "SECURITY_INTRUSION_PREVENTION", "THREAT_BLOCKED", "HIGH", SIGNAL, "ips_threat", "high"),
    ("POWER", "POWER_CYCLE", "POWER_SUPERVISOR_POWER_CYCLE_TRIGGERED", "MEDIUM", ROLLUP, "device", ""),
    ("INTERNET_AND_WAN", "INTERNET_PERFORMANCE", "ISP_HIGH_LATENCY", "MEDIUM", ROLLUP, "isp_quality", ""),
    ("SECURITY", "SECURITY_INTRUSION_PREVENTION", "THREAT_DETECTED", "HIGH", SIGNAL, "ips_threat", "high"),
    ("INTERNET_AND_WAN", "INTERNET_PERFORMANCE", "ISP_PACKET_LOSS", "MEDIUM", ROLLUP, "isp_quality", ""),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_WAN_RESTORED", "MEDIUM", SIGNAL, "wan_restored", "low"),
    ("AUDIT", "SYSTEM_ADMIN", "ADMIN_ACCESS", "MEDIUM", SIGNAL, "admin_activity", "low"),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_WAN_FAILED", "VERY_HIGH", SIGNAL, "wan_down", "medium"),
    ("VPN", "SYSTEM_VPN", "VPN_SITE_TO_SITE_DISCONNECTED", "MEDIUM", SIGNAL, "vpn_down", "medium"),
    ("SOFTWARE_UPDATES", "SYSTEM_DEVICES", "FIRMWARE_UPDATED", "MEDIUM", ROLLUP, "device", ""),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_WAN_FAILED_TEMPORARY", "MEDIUM", ROLLUP, "wan_flap", ""),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_WAN_FAILED_MULTIPLE_TIMES", "VERY_HIGH", SIGNAL, "wan_down", "medium"),
    ("SOFTWARE_UPDATES", "SYSTEM_ADMIN", "NETWORK_UPDATED", "MEDIUM", ROLLUP, "device", ""),
    ("UNIFI_DEVICES", "SYSTEM_WIFI", "ROGUE_AP_DETECTED", "MEDIUM", SIGNAL, "rogue_ap", "medium"),
    ("UNIFI_DEVICES", "SYSTEM_DEVICES", "DEVICE_UNREACHABLE", "HIGH", SIGNAL, "system_event", "medium"),
    ("VPN", "SYSTEM_VPN", "TELEPORT_CLIENT_DISCONNECTED", "LOW", ROLLUP, "client_disconnect", ""),
    ("VPN", "SYSTEM_VPN", "TELEPORT_CLIENT_CONNECTED", "LOW", ROLLUP, "client_connect", ""),
    ("AUDIT", "SYSTEM_ADMIN", "MADE_CHANGES", "MEDIUM", SIGNAL, "config_change", "medium"),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_FAILED_OVER_TO_BACKUP_WAN", "VERY_HIGH", SIGNAL, "wan_failover", "medium"),
    ("UNIFI_ETHERNET_PORTS", "SYSTEM_NETWORK", "PORT_TRANSMISSION_ERRORS", "HIGH", SIGNAL, "system_event", "medium"),
    ("CLIENT_DEVICES", "MONITORING_GUEST_HOTSPOT", "HOTSPOT_GUEST_AUTHORIZED", "LOW", ROLLUP, "client_connect", ""),
    ("UNIFI_DEVICES", "SYSTEM_WIFI", "AP_CLIENT_PACKET_LOSS", "MEDIUM", ROLLUP, "device", ""),
    ("INTERNET_AND_WAN", "INTERNET_OUTAGE_AND_FAILOVER", "NETWORK_FAILED_OVER_TO_BACKUP_WAN_TEMPORARY", "MEDIUM", ROLLUP, "wan_flap", ""),
    ("AUDIT", "SYSTEM_ADMIN", "GENERATED", "MEDIUM", SIGNAL, "admin_activity", "low"),
    ("UNIFI_DEVICES", "SYSTEM_NETWORK", "CLIENT_IP_CONFLICT", "LOW", ROLLUP, "device", ""),
    ("SOMETHING_NEW", "X", "NEVER_SEEN", "LOW", ROLLUP, "other", ""),
    ("SOMETHING_NEW", "X", "NEVER_SEEN", "VERY_HIGH", SIGNAL, "system_event", "medium"),
]


@pytest.mark.parametrize("cat,sub,ev,sev,family,kind,level", CATALOGUE)
def test_every_catalogue_event_lands_where_the_plan_says(cat, sub, ev, sev, family, kind, level):
    c = classify(cat, sub, ev, sev)
    assert (c.family, c.kind, c.severity) == (family, kind, level)


def test_every_kind_has_one_consistent_ocsf_class():
    for kind in (*catalogue.SIGNAL_KINDS, *catalogue.ROLLUP_KINDS):
        class_uid, activity = ocsf.class_of(kind)
        name, category = ocsf.CLASSES[class_uid]
        assert activity in ocsf.ACTIVITIES[class_uid], kind
        assert category in ocsf.CATEGORIES, kind
    o = ocsf.project("wan_down", time_ms=1, severity="medium", event_uid="e", scope=SCOPE_A,
                     site_name="Acme Corp", console_name="acme-udm", title="WAN failed",
                     original_time="t", vendor={"event": "NETWORK_WAN_FAILED"})
    assert (o["class_uid"], o["category_uid"], o["activity_id"], o["type_uid"]) == (4001, 4, 4, 400104)
    assert o["severity_id"] == 3 and o["metadata"]["version"] == ocsf.OCSF_VERSION
    assert o["metadata"]["product"] == {"name": "UniFi Network", "vendor_name": "Ubiquiti"}


def test_the_ips_fields_and_the_detection_finding():
    """The LIVE shape (2026-10-01 20:00): no signature / category / CLIENT
    parameter; SRC_IP / DST_IP {id, name, not_actionable}; DEVICE = the
    reporting gateway. The threat is named from the text."""
    ev = catalogue.normalise(ips_event(T0, blocked=False, eid="ips-9"))
    assert ev is not None and ev.ts_ms == int(T0.timestamp() * 1000)
    assert ev.title == "Threat Detected"
    assert ev.message == f"ET MALWARE Example Beacon: {lan(37)} to 203.0.113.66"
    assert ev.message_raw == "ET MALWARE Example Beacon: {SRC_IP} to {DST_IP}"
    ips = catalogue.ips_fields(ev)
    assert ips == {
        "action": "detected", "src_ip": lan(37), "dst_ip": "203.0.113.66",
        "signature": "ET MALWARE Example Beacon", "gateway": "acme-gateway",
        "local_ip": lan(37), "remote_ip": "203.0.113.66",
        "direction": "outbound",                            # N7: LAN → internet
    }
    site = catalogue.SiteContext(SCOPE_A, HOST_A, SITE_DEFAULT, "default", "Acme Corp", "acme-udm")
    cls = classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity)
    payload = catalogue.signal_payload(cls, ev, site)
    o = payload["ocsf"]
    assert (o["class_uid"], o["activity_id"], o["disposition_id"], o["action_id"]) == (2004, 1, 15, 1)
    assert o["finding_info"]["analytic"] == {"name": "ET MALWARE Example Beacon",
                                             "type_id": 1, "type": "Rule"}
    assert o["evidences"][0]["src_endpoint"] == {"ip": lan(37)}
    assert o["evidences"][0]["dst_endpoint"] == {"ip": "203.0.113.66"}
    assert payload["vendor_event_id"] == f"{SCOPE_A}:ips-9"
    # A pure function of (event, site): the same event, the same payload.
    assert catalogue.signal_payload(cls, catalogue.normalise(ips_event(T0, blocked=False,
                                                                       eid="ips-9")), site) == payload


def test_an_older_shape_with_client_and_signature_parameters_is_still_read():
    ev = catalogue.normalise(legacy_ips_event(T0, eid="ips-8"))
    ips = catalogue.ips_fields(ev)
    assert ips["client"] == {"mac": mac(37), "ip": lan(37), "name": "FRONT-DESK-PC",
                             "hostname": "front-desk-pc"}
    assert (ips["signature"], ips["signature_id"], ips["category"], ips["dst_port"]) == \
        ("ET MALWARE Example Beacon", "2030001", "Malware", 443)


@pytest.mark.parametrize("title,message,name", [
    ("Threat Blocked", "ET POLICY Example Tor Exit: {SRC_IP} to {DST_IP}", "ET POLICY Example Tor Exit"),
    ("ET SCAN Example Probe", "{SRC_IP} → {DST_IP}", "ET SCAN Example Probe"),
    ("Threat Detected", "{SRC_IP} matched \"Example Malware C2\" to {DST_IP}", "Example Malware C2"),
    ("Threat Detected", "Intrusion attempt from {SRC_IP}: Example Exploit Kit", "Example Exploit Kit"),
    ("Example Botnet Callback", "", "Example Botnet Callback"),
    ("Threat Blocked", "{SRC_IP} to {DST_IP}", None),
    ("", "", None),
])
def test_the_threat_is_named_from_the_text_never_with_an_address(title, message, name):
    assert catalogue.threat_name(title, message) == name


def test_the_live_address_objects_are_read_tolerantly():
    raw = ips_event(T0, eid="tol-1")
    raw["parameters"]["SRC_IP"] = {"id": "fixture-uuid-1", "name": f"{lan(41)} (FRONT-DESK)",
                                   "not_actionable": True}
    raw["parameters"]["DST_IP"] = {"id": "198.51.100.7", "name": "example.net",
                                   "not_actionable": False}
    ips = catalogue.ips_fields(catalogue.normalise(raw))
    assert (ips["local_ip"], ips["remote_ip"]) == (lan(41), "198.51.100.7")
    # DEVICE (the gateway) is never taken for the LAN client.
    assert "client" not in ips and ips["gateway"] == "acme-gateway"


def test_an_inbound_attack_keeps_the_lan_device_as_the_local_side():
    ips = catalogue.ips_fields(catalogue.normalise(
        ips_event(T0, eid="in-1", remote_ip="198.51.100.99", inbound=True)))
    assert ips["local_ip"] == lan(37) and ips["remote_ip"] == "198.51.100.99"


def test_coalescing_subjects_and_bucket_keys():
    a = catalogue.normalise(ips_event(T0, eid="1"))
    # The same LAN device and threat from ANOTHER remote address: one bucket
    # (the name is read from the template, never the rendered text).
    b = catalogue.normalise(ips_event(T0 + timedelta(minutes=30), eid="2",
                                      remote_ip="198.51.100.31"))
    c = catalogue.normalise(ips_event(T0 + timedelta(minutes=30), eid="3", lan_ip=lan(38)))
    d = catalogue.normalise(ips_event(T0 + timedelta(minutes=30), eid="4",
                                      signature="ET SCAN Example Probe"))
    subj = [catalogue.subject_of("ips_threat", e, catalogue.ips_fields(e)) for e in (a, b, c, d)]
    assert subj[0] == subj[1] and len(set(subj)) == 3
    assert "203.0.113.66" not in subj[0] and "198.51.100.31" not in subj[1]
    # No name in the text at all: the TEMPLATE (never the rendered text).
    raw = ips_event(T0, eid="5")
    raw["message_raw"] = "{SRC_IP} to {DST_IP}"
    raw2 = ips_event(T0, eid="6", remote_ip="198.51.100.32")
    raw2["message_raw"] = "{SRC_IP} to {DST_IP}"
    e5, e6 = catalogue.normalise(raw), catalogue.normalise(raw2)
    assert catalogue.subject_of("ips_threat", e5, catalogue.ips_fields(e5)) == \
        catalogue.subject_of("ips_threat", e6, catalogue.ips_fields(e6))
    hour = catalogue.bucket_hour(a.ts_ms)
    assert hour == "2026-10-01T12:00:00Z"
    # The console is part of the key: the same subject on another console is
    # another bucket.
    assert catalogue.bucket_key(SCOPE_A, "ips_threat", subj[0], hour) != catalogue.bucket_key(
        f"OTHER:1/{SITE_DEFAULT}", "ips_threat", subj[0], hour)
    adm = catalogue.normalise(log_event(T0, "ADMIN_ACCESS", category="AUDIT",
                                        params={"ADMIN": {"id": "admin-1", "name": "alice"}}))
    assert "alice" not in catalogue.subject_of("admin_activity", adm)       # hashed


def test_boundaries_and_unusable_items():
    ev = catalogue.normalise(client_event(T0, "CLIENT_DISCONNECTED_WIRELESS", n=12,
                                          ip=lan(12), name="PHONE-12"))
    b = catalogue.boundary_event(ev)
    assert b["event"] == "CLIENT_DISCONNECTED_WIRELESS" and b["client"]["mac"] == mac(12)
    assert b["ocsf_class_uid"] == 4001
    fw = catalogue.normalise(log_event(T0, "BLOCKED_BY_FIREWALL", subcategory="SECURITY_FIREWALL"))
    assert catalogue.boundary_event(fw) is None
    assert catalogue.normalise({"event": "X"}) is None                     # no time
    assert catalogue.normalise("not a dict") is None
    # Seconds are read as seconds; an id-less item gets a stable digest id.
    item = log_event(T0, "ADMIN_ACCESS")
    item["timestamp"] = int(T0.timestamp())
    del item["id"]
    one, two = catalogue.normalise(item), catalogue.normalise(dict(item))
    assert one.ts_ms == int(T0.timestamp() * 1000) and one.id == two.id and one.id.startswith("h")
