"""UniFi alerts as an operator reads them — and rows of the retired
local-controller adapter still read."""
from __future__ import annotations

from apps.octo.adapters.unifi import catalogue
from apps.octo.adapters.unifi.presentation import (
    EVENT_TYPES,
    LEGACY_EVENT,
    event_type_of,
    indicator_of,
    present,
)
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    SCOPE_A,
    SITE_DEFAULT,
    T0,
    ips_event,
    lan,
    legacy_ips_event,
    log_event,
)

SITE = catalogue.SiteContext(SCOPE_A, HOST_A, SITE_DEFAULT, "default", "Acme Corp", "acme-udm")


def _payload(raw):
    ev = catalogue.normalise(raw)
    cls = catalogue.classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity)
    return catalogue.signal_payload(cls, ev, SITE)


def test_ips_headlines_rank_detected_first_and_name_the_device():
    blocked = present(_payload(ips_event(T0)))
    detected = present(_payload(ips_event(T0, blocked=False)))
    # The live IPS event names no client: the device is its LAN address.
    assert blocked.headline == f"UniFi IPS blocked ET MALWARE Example Beacon — {lan(37)}"
    assert detected.headline == f"UniFi IPS detected (NOT blocked) ET MALWARE Example Beacon — {lan(37)}"
    assert blocked.event_type == "unifi.ips_threat" and blocked.device == lan(37)
    assert "Action: DETECTED, NOT BLOCKED" in detected.detail
    assert f"Traffic: {lan(37)} → 203.0.113.66" in blocked.detail
    assert "Reported by: acme-gateway (the gateway)" in blocked.detail
    # An older shape naming the client still names it.
    legacy = present(_payload(legacy_ips_event(T0)))
    assert legacy.headline == "UniFi IPS blocked ET MALWARE Example Beacon — FRONT-DESK-PC"
    assert f"Traffic: {lan(37)} → 203.0.113.66:443 (TCP)" in legacy.detail
    assert "Site: Acme Corp (acme-udm)" in blocked.detail
    assert indicator_of(_payload(ips_event(T0))) == "203.0.113.66"


def test_every_kind_has_a_headline():
    cases = {
        "ROGUE_AP_DETECTED": "UniFi rogue access point detected — Acme Corp (acme-udm)",
        "ADMIN_ACCESS": "UniFi administrator access on the console — Acme Corp (acme-udm)",
        "MADE_CHANGES": "UniFi configuration changed — Acme Corp (acme-udm)",
        "NETWORK_WAN_FAILED": "UniFi internet (WAN) connection failed — Acme Corp (acme-udm)",
        "NETWORK_FAILED_OVER_TO_BACKUP_WAN":
            "UniFi failed over to the backup internet connection — Acme Corp (acme-udm)",
        "NETWORK_WAN_RESTORED": "UniFi internet (WAN) connection restored — Acme Corp (acme-udm)",
        "VPN_SITE_TO_SITE_DISCONNECTED": "UniFi site-to-site VPN disconnected — Acme Corp (acme-udm)",
    }
    cats = {"ADMIN_ACCESS": "AUDIT", "MADE_CHANGES": "AUDIT", "ROGUE_AP_DETECTED": "UNIFI_DEVICES",
            "VPN_SITE_TO_SITE_DISCONNECTED": "VPN"}
    for event, headline in cases.items():
        p = present(_payload(log_event(T0, event, category=cats.get(event, "INTERNET_AND_WAN"))))
        assert p.headline == headline, event
        assert p.event_type in EVENT_TYPES and p.fallback is False
    unknown = present(_payload(log_event(T0, "NEVER_SEEN", category="X", severity="VERY_HIGH",
                                         title="Something serious")))
    assert unknown.headline == "UniFi Something serious — Acme Corp (acme-udm)"
    assert unknown.event_type == "unifi.system_event"


def test_vendor_text_is_cleaned():
    raw = legacy_ips_event(T0, client_name="EVIL\u202eNAME\nnext <b>x</b>")
    p = present(_payload(raw))
    assert "\u202e" not in p.headline and "\n" not in p.headline
    assert p.headline.endswith("EVIL NAME next <b>x</b>")         # text, never markup


def test_rows_of_the_retired_local_controller_adapter_still_read():
    legacy = {"key": "EVT_IPS_IpsAlert", "msg": "Suspicious DNS lookup", "hostname": "AP-01",
              "_octo_tenant_slug": "acme-corp"}
    p = present(legacy)
    assert p.headline == "UniFi event — Suspicious DNS lookup"
    assert p.event_type == LEGACY_EVENT == event_type_of(legacy) and p.device == "AP-01"
    assert present({}).fallback is True


def test_the_isp_outage_incident_reads_as_one_provider_problem():
    view = {"vid": "isp:1:64500:2026-10-01T12:05:00.000Z", "asn": 64500, "isp": "Example ISP",
            "since": "2026-10-01T12:05:00.000Z", "opened_at": "2026-10-01T12:05:00.000Z",
            "min_sites": 3, "window_min": 10, "sites": 3,
            "affected": [{"scope": f"host-{n}/site", "site_name": f"Example Site {n}",
                          "tenant": f"tenant-{n}", "since": "2026-10-01T12:05:00.000Z",
                          "why": "console unreachable"} for n in (1, 2, 3)]}
    payload = catalogue.isp_outage_payload(view)
    shown = present(payload)
    assert shown.event_type == "fleet.isp_outage" and shown.event_type in EVENT_TYPES
    assert shown.headline == "ISP outage: Example ISP — 3 sites"
    assert "Provider: Example ISP (AS64500)" in shown.detail
    assert "Example Site 2 (tenant-2) — console unreachable since 12:05 UTC" in shown.detail
    assert event_type_of(payload) == "fleet.isp_outage"
    assert payload["ocsf"]["class_uid"] == 2005 and payload["signal"]["level"] == "high"
    # A pure function of the view: the same payload twice (the sink's identity).
    assert catalogue.isp_outage_payload(view) == payload
