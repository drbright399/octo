"""Deterministic L1 notes for NextDNS records (rule 1c) — the pure engine:
the owner's wording for a blocked threat and for filter evasion, the
disposition per level, a lapse escalates, a restoration is noise linked to
its lapse. (End to end through the real worker: adapters/nextdns/tests/
test_triage_notes.py.)"""
from __future__ import annotations

from apps.octo.agent.heuristic_l1 import DnsFilterEvent, TriageFeatures, triage


def _f(severity="medium", **dns):
    return TriageFeatures(severity=severity, has_indicator=True,
                          recurrence_count=10, indicator_hits=4,
                          dns_filter=DnsFilterEvent(**dns))


BLOCKED = ("Blocked by NextDNS before any connection. If this repeats or is "
           "C2/threat-intel, check alice-laptop for the source.")


def test_a_high_block_escalates_with_the_owner_wording():
    d = triage(_f("high", kind="block", level="high", reason_id="threat-intelligence-feeds",
                  device="alice-laptop"))
    assert d.disposition == "escalate" and d.rationale == BLOCKED
    assert d.suggested_severity == "high"


def test_a_medium_block_is_a_pattern_whatever_the_recurrence():
    d = triage(_f("medium", kind="block", level="medium", reason_id="typosquatting",
                  device="alice-laptop"))
    assert d.disposition == "pattern" and d.rationale == BLOCKED
    assert d.suggested_severity == "medium"


def test_filter_evasion_says_so():
    d = triage(_f("medium", kind="block", level="medium", reason_id="bypass-methods",
                  device="bob-pc"))
    assert d.disposition == "pattern"
    assert d.rationale.startswith(
        "A device is trying to evade DNS filtering (VPN/proxy/Tor) — bob-pc.")
    assert "Tor" in d.rationale and "application on bob-pc" in d.rationale
    # The usual benign causes come first (periodic OS / browser lookups).
    assert "iCloud Private Relay" in d.rationale and "DNS-over-HTTPS" in d.rationale


def test_dns_rebinding_is_noise_and_explains_why():
    d = triage(_f("low", kind="block", level="low", reason_id="drp", device="192.0.2.50"))
    assert d.disposition == "noise"
    assert "check 192.0.2.50 for the source" in d.rationale
    assert "benign local device" in d.rationale


def test_a_lapse_escalates_and_a_restoration_links_it():
    d = triage(_f("medium", kind="lapsed", profile="Acme Corp Office (abc123)"))
    assert d.disposition == "escalate"
    assert d.rationale.startswith("DNS filtering stopped reporting for Acme Corp Office (abc123) "
                                  "— check the site's UniFi DNS/NextDNS setup")
    for cause, needle in (("not_visible", "no longer lets Athena's API key see the profile"),
                          ("not_accessible", "no longer lets Athena's API key see the profile"),
                          ("logs_off", "Logging was turned off at NextDNS")):
        c = triage(_f("medium", kind="lapsed", profile="Acme Corp Office", cause=cause))
        assert c.disposition == "escalate" and needle in c.rationale, cause
        assert "UniFi" not in c.rationale
    r = triage(_f("low", kind="restored", profile="Acme Corp Office", lapse_event_id=41,
                  lapsed_since="2026-09-30T13:00:00Z", restored_hour="2026-09-30T16:00:00Z"))
    assert r.disposition == "noise"
    assert "after the lapse recorded as event #41" in r.rationale
    assert "no queries since 2026-09-30 13:00 UTC" in r.rationale


def test_a_fleet_outage_escalates_once_and_its_sites_are_a_pattern():
    fleet = triage(_f("high", kind="fleet_outage", fleet_sites=12, fleet_watched=20,
                      lapsed_since="2026-09-30T14:00:00Z"))
    assert fleet.disposition == "escalate"
    assert fleet.rationale.startswith("12 of 20 sites stopped reporting at the same time "
                                      "(since 2026-09-30 14:00 UTC)")
    assert "NextDNS status" in fleet.rationale and "UniFi DNS template" in fleet.rationale
    site = triage(_f("medium", kind="lapsed", profile="Acme Corp Office (abc123)",
                     fleet_sites=12, fleet_watched=20))
    assert site.disposition == "pattern"
    assert "12 of 20 sites stopped reporting at the same time" in site.rationale
    assert "No separate escalation" in site.rationale
    # Without the grouping a lapse still escalates.
    assert triage(_f("medium", kind="lapsed", profile="Acme")).disposition == "escalate"
