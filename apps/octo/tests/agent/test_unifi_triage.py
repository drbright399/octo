"""Deterministic L1 notes for UniFi gateway records (rule 1d) — the pure
engine, and the feature gathering from a stored UniFi payload (the real
catalogue builds it)."""
from __future__ import annotations

import json
import sqlite3

from apps.octo.adapters.unifi import catalogue
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    SCOPE_A,
    SITE_DEFAULT,
    T0,
    ips_event,
    lan,
    log_event,
)
from apps.octo.agent.features import build_features
from apps.octo.agent.heuristic_l1 import NetworkEvent, TriageFeatures, triage

# The IPS event's LAN end: the fixture site's address (fake_unifi.lan, RFC 1918
# because catalogue.is_local tells the device from the remote end by it).
LAN_IP = lan(37)


def _f(severity="high", **net):
    return TriageFeatures(severity=severity, has_indicator=True, recurrence_count=10,
                          indicator_hits=3, network=NetworkEvent(**net))


def test_ips_detected_not_blocked_ranks_above_blocked():
    detected = triage(_f(kind="ips_threat", action="detected", site="Acme Corp",
                         device="FRONT-DESK-PC", signature="ET MALWARE Example",
                         remote="203.0.113.66"))
    blocked = triage(_f(kind="ips_threat", action="blocked", site="Acme Corp",
                        device="FRONT-DESK-PC", signature="ET MALWARE Example"))
    assert (detected.disposition, detected.suggested_severity) == ("escalate", "critical")
    assert "did NOT block it" in detected.rationale and "203.0.113.66" in detected.rationale
    assert (blocked.disposition, blocked.suggested_severity) == ("escalate", "high")
    assert blocked.rationale.startswith("Blocked by the UniFi IPS (ET MALWARE Example) at Acme Corp.")
    assert "FRONT-DESK-PC reached for it" in blocked.rationale
    # Recurrence never turns an IPS hit into noise (rule 1d comes first).
    assert detected.confidence > 0.8 and blocked.confidence > 0.8


def test_audit_rogue_and_availability_wording():
    rogue = triage(_f("medium", kind="rogue_ap", site="Acme Corp"))
    assert rogue.disposition == "pattern" and "evil twin" in rogue.rationale
    admin = triage(_f("low", kind="admin_activity", site="Acme Corp"))
    change = triage(_f("medium", kind="config_change", site="Acme Corp"))
    for d in (admin, change):
        assert d.disposition == "pattern" and d.rationale.startswith("Audit: ")
        assert "planned MSP work" in d.rationale
    wan = triage(_f("medium", kind="wan_down", site="Acme Corp"))
    assert wan.disposition == "escalate" and "one ISP outage" in wan.rationale
    vpn = triage(_f("medium", kind="vpn_down", site="Acme Corp"))
    assert vpn.disposition == "escalate" and "site-to-site VPN" in vpn.rationale
    back = triage(_f("low", kind="wan_restored", site="Acme Corp"))
    assert back.disposition == "noise" and "is back" in back.rationale


def test_an_unknown_kind_falls_through_to_the_generic_rules():
    d = triage(_f("medium", kind="system_event", site="Acme Corp"))
    assert d.disposition == "pattern" and "Recurring medium-severity pattern" in d.rationale


def test_features_are_read_from_the_stored_payload():
    site = catalogue.SiteContext(SCOPE_A, HOST_A, SITE_DEFAULT, "default", "Acme Corp", "acme-udm")
    ev = catalogue.normalise(ips_event(T0, blocked=False, lan_ip=LAN_IP))
    payload = catalogue.signal_payload(
        catalogue.classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity), ev, site)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, source TEXT, source_host TEXT, "
                 "event_type TEXT, severity TEXT, payload TEXT)")
    conn.execute("INSERT INTO events (source, source_host, event_type, severity, payload) "
                 "VALUES ('unifi', 'FRONT-DESK-PC', 'unifi.ips_threat', 'high', ?)",
                 (json.dumps(payload),))
    row = conn.execute("SELECT * FROM events").fetchone()
    f = build_features(row, events_conn=conn, indicators_conn=None)
    assert f.network == NetworkEvent(kind="ips_threat", site="Acme Corp (acme-udm)",
                                     device=LAN_IP, action="detected",
                                     signature="ET MALWARE Example Beacon", remote="203.0.113.66")
    assert triage(f).suggested_severity == "critical"
    # A non-UniFi row carries no network context.
    conn.execute("INSERT INTO events (source, source_host, event_type, severity, payload) "
                 "VALUES ('datto', 'x', 'datto.eventlog', 'medium', '{}')")
    other = conn.execute("SELECT * FROM events WHERE source = 'datto'").fetchone()
    assert build_features(other, events_conn=conn, indicators_conn=None).network is None
    wan = catalogue.normalise(log_event(T0, "NETWORK_WAN_FAILED", category="INTERNET_AND_WAN"))
    assert wan is not None


def test_an_isp_outage_escalates_once_from_its_stored_payload():
    view = {"vid": "isp:1:64500:2026-10-01T12:05:00.000Z", "asn": 64500, "isp": "Example ISP",
            "since": "2026-10-01T12:05:00.000Z", "opened_at": "2026-10-01T12:05:00.000Z",
            "min_sites": 3, "window_min": 10, "sites": 3,
            "affected": [{"scope": f"host-{n}/site", "site_name": f"Example Site {n}",
                          "tenant": f"tenant-{n}", "since": "2026-10-01T12:05:00.000Z",
                          "why": "console unreachable"} for n in (1, 2, 3)]}
    payload = catalogue.isp_outage_payload(view)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, source TEXT, source_host TEXT, "
                 "event_type TEXT, severity TEXT, payload TEXT)")
    conn.execute("INSERT INTO events (source, source_host, event_type, severity, payload) "
                 "VALUES ('unifi', NULL, 'fleet.isp_outage', 'high', ?)", (json.dumps(payload),))
    row = conn.execute("SELECT * FROM events").fetchone()
    f = build_features(row, events_conn=conn, indicators_conn=None)
    assert f.network == NetworkEvent(kind="isp_outage", site="", isp="Example ISP", asn=64500,
                                     sites=3)
    d = triage(f)
    assert (d.disposition, d.suggested_severity) == ("escalate", "high")
    assert d.rationale.startswith("ISP outage: 3 sites on Example ISP (AS64500)")
    assert "not N site problems" in d.rationale
