"""How a NextDNS alert reads: the title names the reason and the device,
never the domain; the detail shows the domain MASKED (the IOC rule); the
lapse says what to check."""
from __future__ import annotations

from apps.octo.adapters.nextdns.presentation import (
    EVENT_BLOCK,
    EVENT_FLEET,
    EVENT_LAPSED,
    EVENT_RESTORED,
    LAPSED_ACTION,
    indicator_of,
    present,
)
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line


def _block(**line_kw):
    return {
        "vendor_event_id": "id1", "kind": "security_block", "profile_id": "abc123",
        "profile_name": "Acme Corp Office", "log": block_line(T0, **line_kw),
        "signal": {"level": "high", "reason_id": "threat-intelligence-feeds",
                   "reason_label": "a threat-intelligence domain",
                   "bucket_hour": "2026-09-30T12:00:00Z"},
    }


def test_block_title_names_the_reason_and_device_not_the_domain():
    shown = present(_block(domain="c2.bad-example.test"))
    assert shown.event_type == EVENT_BLOCK
    assert shown.headline == "NextDNS blocked a threat-intelligence domain — alice-laptop"
    assert "c2.bad-example.test" not in shown.headline + shown.detail
    # Masked by the pulse's rule (api.indicator_mask): "c2" is too short a
    # first label to keep any of it.
    assert "before any connection: *****.test (masked" in shown.detail
    assert "Blocked by NextDNS before any connection" in shown.detail
    assert "Acme Corp Office (abc123)" in shown.detail
    assert shown.site == "Acme Corp Office" and shown.device == "alice-laptop"


def test_without_a_device_name_the_client_ip_is_the_label():
    shown = present(_block(device_id=None))
    assert shown.headline.endswith("— 192.0.2.10")


def test_vendor_text_is_cleaned():
    payload = _block(device_name="evil‮net\nname")
    shown = present(payload)
    assert "\n" not in shown.headline and "‮" not in shown.headline


def test_the_indicator_is_the_blocked_domain():
    assert indicator_of(_block(domain="C2.Bad-Example.TEST.")) == "c2.bad-example.test"
    assert indicator_of({"kind": "protection_lapsed"}) is None
    assert indicator_of(_block(domain="bad domain")) is None


def test_lapsed_and_restored():
    lapsed = present({"kind": "protection_lapsed", "profile_id": "abc123",
                      "profile_name": "Acme Corp Office", "since": "2026-09-30T13:00:00Z",
                      "zero_hours": 2})
    assert lapsed.event_type == EVENT_LAPSED
    assert lapsed.headline == "NextDNS stopped reporting — Acme Corp Office (abc123)"
    assert lapsed.detail.startswith(LAPSED_ACTION)
    assert "since 2026-09-30 13:00 UTC" in lapsed.detail
    restored = present({"kind": "protection_restored", "profile_id": "abc123",
                        "lapse_event_id": 7, "lapsed_since": "2026-09-30T13:00:00Z",
                        "restored_hour": "2026-09-30T16:00:00Z", "queries": 900})
    assert restored.event_type == EVENT_RESTORED
    assert restored.headline == "NextDNS reporting again — abc123"
    assert "the lapse recorded as event #7" in restored.detail


def test_the_fleet_outage_reads_as_one_incident_and_the_sites_say_they_are_grouped():
    fleet = present({"kind": "fleet_dns_outage", "sites": 12, "watched": 20,
                     "since": "2026-09-30T14:00:00Z",
                     "profiles": [{"profile_id": f"q{i:05d}", "profile_name": f"Site {i}"}
                                  for i in range(10)]})
    assert fleet.event_type == EVENT_FLEET
    assert fleet.headline == ("12 sites stopped reporting to NextDNS — check NextDNS status "
                              "and the UniFi DNS template")
    assert "12 of 20 watched sites" in fleet.detail and "since 2026-09-30 14:00 UTC" in fleet.detail
    assert "Site 0, Site 1" in fleet.detail and "(+2 more)" in fleet.detail
    lapsed = present({"kind": "protection_lapsed", "profile_id": "abc123",
                      "profile_name": "Acme Corp Office", "since": "2026-09-30T14:00:00Z",
                      "zero_hours": 3,
                      "fleet": {"sites": 12, "watched": 20, "since": "2026-09-30T14:00:00Z"}})
    assert lapsed.detail.startswith(LAPSED_ACTION)
    assert "Part of a fleet-wide outage: 12 of 20 sites stopped reporting" in lapsed.detail
    from apps.octo.adapters.nextdns.adapter import _severity
    assert _severity({"kind": "fleet_dns_outage"}) == "high"


def test_an_unreadable_payload_is_a_fallback_label():
    shown = present({"kind": "security_block"})
    assert shown.fallback and shown.headline == "NextDNS alert"
    assert present("nonsense").fallback
