"""The block-reason table: every id the design names, one assertion each,
plus the fail-safe (an unknown non-list reason is a LOW signal) and the
line rule (any signal reason → a signal at the highest level)."""
from __future__ import annotations

import pytest

from apps.octo.adapters.nextdns import classification

from apps.octo.adapters.nextdns.classification import (
    HIGH,
    LOW,
    MEDIUM,
    class_counts,
    classify_line,
    classify_reason,
    signal_reason_counts,
)

HIGH_IDS = [
    "threat-intelligence-feeds", "googlesafebrowsing", "cryptojacking", "dga", "csam",
    "dns-data-exfiltration", "dns-payload-delivery", "tunneling-endpoints",
    "fast-flux-networks",
    # "any … id" of the four families, whatever surrounds it
    "security:dns-data-exfiltration", "dns-payload-delivery-v2",
    "threat:tunneling-endpoints", "fast-flux-networks:new",
]
MEDIUM_IDS = [
    "ai-threat-detection", "typosquatting", "idn-homographs", "nrd", "newly-active-domains",
    "ddns", "free-hosting", "parked-domains", "residential-hosting",
    "decentralized-web-gateways", "data-drop-services", "untrusted-certificates",
    "bypass-methods",
]
LOW_IDS = ["drp"]
NOT_SIGNAL_IDS = [
    "blocklist:adguard-dns-filter", "blocklist:nextdns-recommended", "blocklist:oisd",
    "denylist", "tld:cn", "tld:support", "tld:top", "tld:work", "disguised-trackers",
    "safesearch-not-supported", "native:apple", "native:windows",
    "parental-control:porn", "porn", "gambling", "social-networks",
]


@pytest.mark.parametrize("rid", HIGH_IDS)
def test_high(rid):
    rc = classify_reason(rid)
    assert rc.level == HIGH and rc.is_signal and rc.known


@pytest.mark.parametrize("rid", MEDIUM_IDS)
def test_medium(rid):
    rc = classify_reason(rid)
    assert rc.level == MEDIUM and rc.is_signal and rc.known


@pytest.mark.parametrize("rid", LOW_IDS)
def test_low(rid):
    rc = classify_reason(rid)
    assert rc.level == LOW and rc.known


@pytest.mark.parametrize("rid", NOT_SIGNAL_IDS)
def test_not_a_signal(rid):
    rc = classify_reason(rid)
    assert rc.level is None and not rc.is_signal


@pytest.mark.parametrize("rid", ["some-new-security-feature", "zero-day-thing", "Weird:ID"])
def test_an_unknown_non_list_reason_is_a_low_signal(rid):
    rc = classify_reason(rid, "Some New Feature")
    assert rc.level == LOW and not rc.known
    assert "Some New Feature" in rc.label


def test_ids_are_case_and_space_insensitive():
    assert classify_reason("  Threat-Intelligence-Feeds ").level == HIGH
    assert classify_reason("BLOCKLIST:OISD").level is None


def test_a_blank_reason_id_is_a_low_signal_but_a_line_without_reasons_is_not():
    assert classify_reason("").level == LOW
    assert classify_reason(None).level == LOW
    assert classify_line([]).level is None
    assert classify_line(None).level is None


def test_a_line_takes_the_highest_signal_reason():
    line = classify_line([
        {"id": "blocklist:oisd", "name": "OISD"},
        {"id": "nrd", "name": "Newly Registered Domains"},
        {"id": "threat-intelligence-feeds", "name": "Threat Intelligence Feeds"},
        {"id": "drp"},
    ])
    assert line.level == HIGH
    assert line.primary is not None and line.primary.id == "threat-intelligence-feeds"


def test_a_line_of_policy_reasons_only_is_not_a_signal():
    line = classify_line([{"id": "blocklist:oisd"}, {"id": "tld:cn"}, {"id": "denylist"}])
    assert line.level is None and line.primary is None


def test_the_first_reason_at_the_top_level_is_primary():
    line = classify_line([{"id": "typosquatting"}, {"id": "bypass-methods"}])
    assert line.level == MEDIUM and line.primary.id == "typosquatting"


@pytest.mark.parametrize("reasons", [
    [{"id": "threat-intelligence-feeds"}, {"id": "csam"}],
    [{"id": "dga"}, {"id": "blocklist:oisd"}, {"id": "csam"}],
    [{"id": "nrd"}, {"id": "csam"}],
    ["csam", "threat-intelligence-feeds"],
])
def test_csam_is_always_the_primary_reason(reasons):
    """v0.17.2: the primary reason keys the coalescing bucket — a CSAM lookup
    never rides in another reason's bucket (an ack / expected condition on
    that reason must never hide it)."""
    line = classify_line(reasons)
    assert line.level == HIGH and line.primary is not None and line.primary.id == "csam"


def test_counts_by_class():
    reasons = {
        "blocklist:oisd": ("OISD", 900), "tld:cn": ("CN", 10),
        "threat-intelligence-feeds": ("TIF", 3), "bypass-methods": ("Bypass", 7),
        "drp": ("DRP", 2), "mystery": ("Mystery", 1),
    }
    assert class_counts(reasons) == {HIGH: 3, MEDIUM: 7, LOW: 3, "policy": 910}
    assert signal_reason_counts(reasons) == {
        "threat-intelligence-feeds": 3, "bypass-methods": 7, "drp": 2, "mystery": 1,
    }
    assert signal_reason_counts({"blocklist:oisd": ("OISD", 5), "nrd": ("NRD", 0)}) == {}


@pytest.mark.parametrize("rid", ["tiktok", "roblox", "fortnite", "youtube", "discord",
                                 "snapchat", "instagram", "9gag", "xboxlive"])
def test_parental_control_services_are_policy_not_the_fail_safe(rid):
    """A school blocking TikTok must not raise "NextDNS blocked “TikTok”"
    alerts (nor trigger log pulls): service ids are content policy."""
    rc = classify_reason(rid, rid.title())
    assert rc.level is None and rc.known
    assert classification.signal_reason_counts({rid: (rid.title(), 40)}) == {}


def test_bucket_span_and_cross_domain():
    assert classification.bucket_span(classification.HIGH) == "hour"
    assert classification.bucket_span(classification.MEDIUM) == "day"
    assert classification.bucket_span(classification.LOW) == "day"
    assert classification.is_cross_domain("dga")
    assert classification.is_cross_domain("domain-generation-algorithms")
    assert not classification.is_cross_domain("threat-intelligence-feeds")
    assert not classification.is_cross_domain("cryptojacking", classification.HIGH)
    # Owner decision 2026-09-30: MEDIUM / LOW are per device and reason per
    # day, whatever the domain.
    for rid in ("bypass-methods", "ai-threat-detection", "nrd", "typosquatting", "drp",
                "some-new-feature"):
        assert classification.is_cross_domain(rid), rid
    assert classification.is_cross_domain("x", classification.MEDIUM)
