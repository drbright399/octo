"""The verdict evaluator in isolation (no store): acknowledge hides and
re-surfaces on a NEW occurrence, "repeats for 24 h" expires by itself, an
expected condition matches its tenant + device + signature (+ remote) only
while active — never after its review date, never once revoked, never for an
alert that may not be expected — and the keys are the same from a stored
alert and from the ledger the Fleet counts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.verdicts import keys
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import ACKED, EXPECTED, OPEN, RESURFACED, Occurrence, TenantVerdicts

NOW = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)
SCOPE = "F1X7HOST/f1x7site"


def iso(dt: datetime) -> str:
    return vstore.iso(dt)


def ack(event_id: int, key: keys.AlertKey, *, at: datetime, hits: int | None = None,
        last: datetime | None = None, repeat: bool = False, vid: int = 1) -> vstore.Verdict:
    return vstore.Verdict(vid, "acme-corp", event_id, key.source, key.device_key,
                          key.signature_key, vstore.ACK, 7, iso(at), "seen", hits,
                          iso(last) if last else None,
                          iso(at + timedelta(hours=24)) if repeat else None)


def rule(key: keys.AlertKey, *, remote: str | None = None, created: datetime = NOW,
         review: datetime | None = None, revoked: bool = False, rid: int = 5) -> vstore.ExpectedRule:
    return vstore.ExpectedRule(
        rid, "acme-corp", key.source, key.device_key, key.signature_key, remote, "label",
        "known backup traffic", 41, 7, iso(created - timedelta(days=1)),
        iso(review or created + timedelta(days=90)),
        revoked_at=iso(created) if revoked else None, revoked_by=7 if revoked else None,
        revoke_reason="no longer" if revoked else None)


def ips_key(client: str = "192.0.2.37", remote: str | None = "203.0.113.66") -> keys.AlertKey:
    return keys.unifi_key(SCOPE, "ips_threat", f"{client}|ET POLICY Example|outbound|blocked",
                          remote=remote)


def occ(key: keys.AlertKey, *, event_id: int = 41, first: datetime = NOW - timedelta(hours=1),
        last: datetime | None = None, hits: int | None = None,
        remotes: dict[str, int] | None = None, eligible: bool = True) -> Occurrence:
    return Occurrence(event_id, key, iso(first), iso(last or first), hits, remotes,
                      eligible=eligible)


# ---------------------------------------------------------------------------
# Acknowledge
# ---------------------------------------------------------------------------

def test_an_ack_hides_one_alert_and_a_new_alert_is_open():
    k = ips_key()
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=NOW - timedelta(minutes=30))], [], now=NOW)
    assert tv.state(occ(k)).status == ACKED and tv.state(occ(k)).hidden
    # Another occurrence (a new event) is not covered by a plain ack.
    assert tv.state(occ(k, event_id=42, first=NOW - timedelta(minutes=5))).status == OPEN


def test_a_coalesced_alert_re_surfaces_when_it_grows_past_the_ack():
    k = ips_key()
    seen = NOW - timedelta(minutes=40)
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=NOW - timedelta(minutes=30), hits=3,
                                          last=seen)], [], now=NOW)
    assert tv.state(occ(k, hits=3, last=seen)).status == ACKED
    grown = tv.state(occ(k, hits=5, last=NOW - timedelta(minutes=2)))
    assert grown.status == RESURFACED and not grown.hidden and grown.new_hits == 2
    # A newer last-seen alone (the count read the same) re-surfaces too.
    assert tv.state(occ(k, hits=3, last=NOW - timedelta(minutes=1))).status == RESURFACED


def test_acknowledge_repeats_for_24_hours_then_expires():
    k = ips_key()
    at = NOW - timedelta(hours=2)
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=at, hits=1, last=at, repeat=True)], [],
                        now=NOW)
    # The acked bucket grew inside the window: still acknowledged.
    assert tv.state(occ(k, hits=4, last=NOW)).status == ACKED
    # The next hour's bucket (a new event) of the same device + signature.
    later = occ(k, event_id=43, first=at + timedelta(hours=1), hits=2)
    st = tv.state(later)
    assert st.status == ACKED and st.by_repeat
    # Another device, another signature: never.
    assert tv.state(occ(ips_key("192.0.2.99"), event_id=44, first=NOW)).status == OPEN
    # Past the 24 hours: a new occurrence re-surfaces / is open again.
    after = at + timedelta(hours=25)
    assert tv.state(occ(k, event_id=45, first=after)).status == OPEN
    assert tv.state(occ(k, event_id=46, first=at + timedelta(hours=23),
                        last=after, hits=9)).status == RESURFACED
    # An occurrence from BEFORE the ack is not a repeat.
    assert tv.state(occ(k, event_id=47, first=at - timedelta(hours=1))).status == OPEN


def test_the_latest_ack_of_an_event_wins():
    k = ips_key()
    first = ack(41, k, at=NOW - timedelta(hours=3), hits=2, last=NOW - timedelta(hours=3), vid=1)
    second = ack(41, k, at=NOW - timedelta(minutes=5), hits=6, last=NOW - timedelta(minutes=6),
                 vid=2)
    tv = TenantVerdicts("acme-corp", [second, first], [], now=NOW)
    assert tv.state(occ(k, hits=6, last=NOW - timedelta(minutes=6))).status == ACKED


# ---------------------------------------------------------------------------
# Expected
# ---------------------------------------------------------------------------

def test_an_expected_condition_matches_its_device_and_signature_only():
    k = ips_key()
    tv = TenantVerdicts("acme-corp", [], [rule(k)], now=NOW)
    st = tv.state(occ(k, hits=3, remotes={"203.0.113.66": 3}))
    assert st.status == EXPECTED and st.hidden and st.rule is not None and st.rule.id == 5
    assert tv.state(occ(ips_key("192.0.2.99"))).status == OPEN               # other device
    other = keys.unifi_key(SCOPE, "ips_threat", "192.0.2.37|ET POLICY Example|outbound|detected")
    assert tv.state(occ(other)).status == OPEN               # blocked ≠ detected (NOT blocked)


def test_expiry_stops_matching_and_a_revoked_rule_never_matches():
    k = ips_key()
    review = NOW - timedelta(minutes=1)
    expired = TenantVerdicts("acme-corp", [], [rule(k, created=NOW - timedelta(days=89),
                                                    review=review)], now=NOW)
    assert expired.state(occ(k)).status == OPEN
    revoked = TenantVerdicts("acme-corp", [], [rule(k, revoked=True)], now=NOW)
    assert revoked.state(occ(k)).status == OPEN
    live = rule(k, created=NOW - timedelta(days=10), review=NOW + timedelta(days=1))
    assert live.status(NOW) == "active"
    assert live.status(NOW + timedelta(days=1)) == "expired"                 # no renewal
    assert TenantVerdicts("acme-corp", [], [live], now=NOW + timedelta(days=2)) \
        .state(occ(k)).status == OPEN


def test_an_alert_that_may_not_be_expected_is_never_labelled():
    k = ips_key()
    tv = TenantVerdicts("acme-corp", [], [rule(k)], now=NOW)
    assert tv.state(occ(k, eligible=False)).status == OPEN


def test_a_remote_limited_condition_needs_every_remote_under_it():
    k = ips_key()
    tv = TenantVerdicts("acme-corp", [], [rule(k, remote="198.51.100.0/24")], now=NOW)
    assert tv.state(occ(k, hits=2, remotes={"198.51.100.7": 1, "198.51.100.9": 1})).status \
        == EXPECTED
    assert tv.state(occ(k, hits=2, remotes={"198.51.100.7": 1, "203.0.113.5": 1})).status \
        == OPEN                                                        # one remote outside
    assert tv.state(occ(k, hits=3, remotes={"198.51.100.7": 1})).status == OPEN  # not all known
    assert tv.state(occ(k, hits=2, remotes=None)).status == OPEN        # before 046: unknown
    assert tv.state(occ(k, hits=2, remotes={"198.51.100.7": 1, "~": 1})).status == OPEN
    single = keys.unifi_key(SCOPE, "ips_threat", "192.0.2.37|ET POLICY Example|outbound|blocked",
                            remote="198.51.100.7")
    assert tv.state(occ(single)).status == EXPECTED                     # one event, its remote


def test_a_host_remote_needs_a_forward_confirmed_ptr():
    k = ips_key(remote="198.51.100.7")
    ptrs = {"198.51.100.7": {"ptr": "bdr-12.dattobackup.com", "ptr_confirmed": True},
            "198.51.100.8": {"ptr": "bdr-13.dattobackup.com", "ptr_confirmed": False}}
    tv = TenantVerdicts("acme-corp", [], [rule(k, remote="dattobackup.com")], now=NOW,
                        ptr_of=ptrs.get)
    assert tv.state(occ(k, hits=1, remotes={"198.51.100.7": 1})).status == EXPECTED
    assert tv.state(occ(k, hits=1, remotes={"198.51.100.8": 1})).status == OPEN   # unconfirmed
    assert tv.state(occ(k, hits=1, remotes={"198.51.100.9": 1})).status == OPEN   # no PTR


def test_remote_normalisation():
    assert vstore.normalize_remote(" 203.0.113.7 ") == "203.0.113.7"
    assert vstore.normalize_remote("198.51.100.0/24") == "198.51.100.0/24"
    assert vstore.normalize_remote("*.DattoBackup.com.") == "dattobackup.com"
    # A local address / network is refused: these must be private (generic values).
    # scan-sensitive: allow[ip-private] generic RFC 1918 values: the local refusal under test
    local = (("10.0.0.5", "local"), ("192.168.1.0/24", "local"))
    # Wider than /16: the RFC 2544 benchmarking block (a /15).
    for bad, why in (*local, ("198.18.0.0/15", "at most"), ("not a host", "not an address"),
                     ("", "required")):
        with pytest.raises(ValueError, match=why):
            vstore.normalize_remote(bad)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def test_unifi_keys_from_a_stored_alert_equal_the_ledger_buckets():
    payload = {"kind": "ips_threat", "scope": SCOPE,
               "signal": {"subject": "aa:bb:cc:00:00:01|2030001|inbound|blocked"},
               "ips": {"remote_ip": "203.0.113.9"}}
    from_event = keys.alert_key({"source": "unifi", "event_type": "unifi.ips_threat"}, payload)
    from_bucket = keys.unifi_key(SCOPE, "ips_threat", "aa:bb:cc:00:00:01|2030001|inbound|blocked")
    assert (from_event.device_key, from_event.signature_key) == \
        (from_bucket.device_key, from_bucket.signature_key)
    assert from_event.device_key == f"{SCOPE}|aa:bb:cc:00:00:01"
    assert from_event.signature_key == "unifi.ips_threat:2030001|inbound|blocked"
    assert from_event.family == "unifi_ips" and from_event.remote == "203.0.113.9"


def test_nextdns_keys_from_a_stored_alert_equal_the_ledger_buckets():
    base = {"kind": "security_block", "profile_id": "p-acme",
            "log": {"domain": "x.example.test", "root": "example.test", "device": {"id": "D1"}},
            "signal": {"reason_id": "dga"}}
    k = keys.alert_key({"source": "nextdns"}, base)
    assert k == keys.nextdns_key("p-acme", "D1", "example.test", "dga")
    benign = dict(base, signal={"reason_id": "dga", "known_benign": {"rule_id": 3}})
    assert keys.alert_key({"source": "nextdns"}, benign).signature_key == "nextdns:dga|kb:3"
    cross = dict(base, signal={"reason_id": "threat-intelligence-feeds", "cross_domain": True},
                 log={"clientIp": "198.51.100.4", "domain": "y.example.test"})
    assert keys.alert_key({"source": "nextdns"}, cross) == \
        keys.nextdns_key("p-acme", "198.51.100.4", "*", "threat-intelligence-feeds")


def test_a_datto_monitor_signature_names_the_monitor_never_the_value():
    def alert(code: str, text: str) -> dict:
        return {"alertUid": "u", "alertSourceInfo": {"deviceUid": "dev-1", "deviceName": "SRV"},
                "alertContext": {"@class": "eventlog_ctx", "logName": "System",
                                 "source": "Service Control Manager", "code": code,
                                 "description": text}}

    a, b = (keys.alert_key({"source": "datto"}, alert("7031", t))
            for t in ("crashed 1 time", "crashed 9 times"))
    assert a == b and a.device_key == "dev-1"
    assert a.signature_key == "datto:eventlog_ctx|system|service control manager|7031"
    assert keys.alert_key({"source": "datto"}, alert("7034", "x")) != a


def test_expected_is_refused_for_csam_canaries_malware_incidents_and_athena():
    csam = {"source": "nextdns", "event_type": "nextdns.security_block",
            "payload": {"kind": "security_block", "signal": {"reason_id": "csam"},
                        "log": {"reasons": [{"id": "csam"}]}}}
    assert "CSAM" in (keys.expected_refusal(csam) or "")
    hidden_csam = {"source": "nextdns", "payload": {"kind": "security_block",
                                                    "signal": {"reason_id": "dga"},
                                                    "log": {"reasons": ["dga", "csam"]}}}
    assert "CSAM" in (keys.expected_refusal(hidden_csam) or "")
    canary = {"source": "buoy", "event_type": "opencanary.ssh", "payload": {"src_host": "192.0.2.9"}}
    assert "R6" in (keys.expected_refusal(canary) or "")
    malware = {"id": 9, "source": "wazuh", "event_type": "wazuh.alert",
               "payload": {"rule": {"level": 13, "groups": ["yara"], "id": "554"},
                           "agent": {"name": "WS-1"}}}
    assert "R2-W" in (keys.expected_refusal(malware) or "")
    noisy = {"id": 10, "source": "wazuh", "event_type": "wazuh.alert",
             "payload": {"rule": {"level": 7, "groups": ["syslog"], "id": "5503"},
                         "agent": {"name": "WS-2"}}}
    assert keys.expected_refusal(noisy) is None
    # The same alert naming no device: a rule would cover the whole client.
    nameless = dict(noisy, payload={"rule": {"level": 7, "groups": ["syslog"], "id": "5503"}})
    assert keys.expected_refusal(nameless) == keys.NO_DEVICE
    ips = {"source": "unifi", "payload": {"kind": "ips_threat", "signal": {"subject": "a|b|c"}}}
    assert keys.expected_refusal(ips) is None
    assert "incident" in (keys.expected_refusal(ips, linked_incident=True) or "")
    assert keys.expected_refusal({"source": "athena", "payload": {}}) is not None
    assert not keys.expected_eligible_bucket(keys.nextdns_key("p", "d", "x.test", "csam"))
