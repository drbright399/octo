"""Ingest tiering — the classification table (`apps.octo.ingest.tiering`).

Pins, per the owner-approved design (2026-09-29):
  * every documented Pi-hole FTL query status code (0-18): BLOCKED codes and
    the unknown code are SIGNALS, answered codes are TELEMETRY — read from
    the payload's numeric `raw_query.status` (and the v6 API's names), never
    from the buoy forwarder's `status_label` / severity, which are shifted;
  * Suricata dns/tls/http/flow metadata is telemetry; a record that is (or
    carries) an alert, anomaly or anything else is a signal;
  * every other type — and anything unreadable — is a signal (fail-safe);
  * elevated severity always wins (signal);
  * the dimensions the roll-ups key on (domain, LAN device).
"""
from __future__ import annotations

import pytest

from apps.octo.ingest import tiering
from apps.octo.ingest.tiering import SIGNAL, TELEMETRY, classify, extract_dimensions

# The documented table, restated here independently of the module's copy:
# status → (FTL name, expected tier).
DOCUMENTED_PIHOLE: dict[int, tuple[str, str]] = {
    0: ("UNKNOWN", SIGNAL),                   # not (yet) known → fail-safe
    1: ("GRAVITY", SIGNAL),                   # blocked: gravity
    2: ("FORWARDED", TELEMETRY),
    3: ("CACHE", TELEMETRY),
    4: ("REGEX", SIGNAL),                     # blocked: regex deny
    5: ("DENYLIST", SIGNAL),                  # blocked: exact deny
    6: ("EXTERNAL_BLOCKED_IP", SIGNAL),
    7: ("EXTERNAL_BLOCKED_NULL", SIGNAL),
    8: ("EXTERNAL_BLOCKED_NXRA", SIGNAL),
    9: ("GRAVITY_CNAME", SIGNAL),
    10: ("REGEX_CNAME", SIGNAL),
    11: ("DENYLIST_CNAME", SIGNAL),
    12: ("RETRIED", TELEMETRY),
    13: ("RETRIED_DNSSEC", TELEMETRY),
    14: ("IN_PROGRESS", TELEMETRY),
    15: ("DBBUSY", SIGNAL),
    16: ("SPECIAL_DOMAIN", SIGNAL),
    17: ("CACHE_STALE", TELEMETRY),
    18: ("EXTERNAL_BLOCKED_EDE15", SIGNAL),
}


def _pihole(status, *, label: str | None = None, severity: str = "info") -> dict:
    """The stored payload shape: the ingest router's {event_type, severity,
    **data} with the buoy forwarder's pihole adapter data."""
    raw = {"id": 41, "timestamp": 1759140000, "type": 1, "status": status,
           "domain": "example.test", "client": "192.0.2.10",
           "client_name": "alice-laptop", "forward": "198.51.100.53",
           "reply_type": 4, "reply_time": 0.01}
    if label is not None:
        raw["status_label"] = label
    return {"event_type": "pihole.query", "severity": severity, "raw_query": raw,
            "_buoy": "buoy-acme-1", "_adapter": "pihole", "_adapter_version": "1.0"}


def test_the_module_table_is_the_documented_table():
    assert {k: v[0] for k, v in tiering.PIHOLE_STATUS.items()} == {
        k: v[0] for k, v in DOCUMENTED_PIHOLE.items()
    }


@pytest.mark.parametrize("status", sorted(DOCUMENTED_PIHOLE))
def test_every_documented_pihole_status_code(status):
    name, expected = DOCUMENTED_PIHOLE[status]
    got = classify("pihole.query", _pihole(status), "info")
    assert got.tier == expected, f"status {status} ({name})"


@pytest.mark.parametrize("status", sorted(DOCUMENTED_PIHOLE))
def test_v6_api_status_names_classify_like_their_codes(status):
    name, expected = DOCUMENTED_PIHOLE[status]
    assert classify("pihole.query", _pihole(name), "info").tier == expected
    assert classify("pihole.query", _pihole(name.lower()), "info").tier == expected


@pytest.mark.parametrize("status", ["2", " 3 ", "1"])
def test_numeric_strings_are_codes(status):
    expected = DOCUMENTED_PIHOLE[int(status)][1]
    assert classify("pihole.query", _pihole(status), "info").tier == expected


def test_v5_blacklist_names_are_blocks():
    assert classify("pihole.query", _pihole("BLACKLIST"), "info").tier == SIGNAL
    assert classify("pihole.query", _pihole("BLACKLIST_CNAME"), "info").tier == SIGNAL


@pytest.mark.parametrize("status", [19, 99, -1, None, True, "", "SOMETHING_NEW", 2.0, [2], {"s": 2}])
def test_unknown_or_unreadable_status_is_a_signal(status):
    got = classify("pihole.query", _pihole(status), "info")
    assert got.tier == SIGNAL
    assert got.reason == "pihole:status-unknown"


def test_missing_status_is_a_signal():
    payload = _pihole(2)
    del payload["raw_query"]["status"]
    assert classify("pihole.query", payload, "info").tier == SIGNAL


def test_the_forwarders_shifted_label_is_ignored():
    """The forwarder labels status 2 'blocked-gravity' (severity low) and
    status 1 'allowed' (info). The documented codes win: 2 is an answered
    lookup (telemetry), 1 a gravity block (signal)."""
    forwarded = _pihole(2, label="blocked-gravity", severity="low")
    assert classify("pihole.query", forwarded, "low").tier == TELEMETRY
    gravity = _pihole(1, label="allowed", severity="info")
    assert classify("pihole.query", gravity, "info").tier == SIGNAL


def test_top_level_status_shape_is_read_when_raw_query_is_absent():
    assert classify("pihole.query", {"status": 3, "domain": "example.test"}).tier == TELEMETRY
    assert classify("pihole.query", {"status": 1}).tier == SIGNAL


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

def _eve(event_type: str, **extra) -> dict:
    record = {"timestamp": "2026-09-29T10:00:00.000000+0000", "event_type": event_type,
              "src_ip": "192.0.2.10", "dest_ip": "198.51.100.53", **extra}
    return {"event_type": f"suricata.{event_type}", "severity": "info",
            "raw_eve": record, "_adapter": "suricata"}


@pytest.mark.parametrize("proto", ["dns", "tls", "http", "flow"])
def test_suricata_metadata_is_telemetry(proto):
    assert classify(f"suricata.{proto}", _eve(proto), "info").tier == TELEMETRY


@pytest.mark.parametrize("et", ["suricata.alert", "suricata.anomaly", "suricata.fileinfo",
                                "suricata.ssh", "suricata.netflow"])
def test_other_suricata_types_are_signals(et):
    proto = et.split(".", 1)[1]
    assert classify(et, _eve(proto), "info").tier == SIGNAL


def test_a_dns_record_that_carries_an_alert_is_a_signal():
    payload = _eve("dns", alert={"signature_id": 2027863, "severity": 3})
    assert classify("suricata.dns", payload, "info").reason == "suricata:alert-block"


def test_a_record_whose_eve_type_disagrees_is_a_signal():
    """Declared suricata.dns but the eve record is an alert (or a drop)."""
    payload = _eve("alert")
    payload["event_type"] = "suricata.dns"
    assert classify("suricata.dns", payload, "info").tier == SIGNAL
    assert classify("suricata.tls", _eve("drop"), "info").tier == SIGNAL


def test_a_top_level_alert_block_is_a_signal():
    assert classify("suricata.http", {"alert": {"signature": "x"}}, "info").tier == SIGNAL


def test_a_non_dict_eve_record_is_a_signal():
    assert classify("suricata.dns", {"raw_eve": "not-a-record"}, "info").tier == SIGNAL


def test_suricata_without_raw_eve_is_telemetry():
    """The generic shape (no eve envelope) the ingest contract allows."""
    assert classify("suricata.dns", {"_adapter": "suricata", "query": "example.test"},
                    "info").tier == TELEMETRY


# ---------------------------------------------------------------------------
# Signals by type, severity, fail-safe
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("et", [
    "wazuh.alert", "datto.alert", "datto.eventlog", "rocketcyber.incident",
    "rocketcyber.detection", "unifi.ips", "opencanary.ssh", "opencanary.telnet",
    "buoy.command", "buoy.heartbeat", "suricata.alert", "alert", "t.e",
    "brand-new.type", "", "PIHOLE.QUERY",
])
def test_everything_else_is_a_signal(et):
    got = classify(et, {"anything": 1}, "info")
    assert got.tier == SIGNAL
    assert got.reason == "type"


@pytest.mark.parametrize("sev", ["medium", "high", "critical", "HIGH"])
def test_elevated_severity_is_always_a_signal(sev):
    assert classify("pihole.query", _pihole(2), sev).reason == "severity"
    assert classify("suricata.dns", _eve("dns"), sev).tier == SIGNAL


@pytest.mark.parametrize("sev", ["info", "low", None])
def test_low_severity_does_not_change_the_tier(sev):
    assert classify("pihole.query", _pihole(3), sev).tier == TELEMETRY


@pytest.mark.parametrize("payload", [None, "text", 7, ["list"]])
def test_an_unreadable_payload_is_a_signal(payload):
    assert classify("pihole.query", payload, "info").tier == SIGNAL
    assert classify("suricata.dns", payload, "info").tier == SIGNAL


def test_non_string_event_type_is_a_signal():
    assert classify(None, _pihole(2)).tier == SIGNAL  # type: ignore[arg-type]


def test_candidate_registry():
    assert tiering.TELEMETRY_CANDIDATE_TYPES == {
        "pihole.query", "suricata.dns", "suricata.tls", "suricata.http", "suricata.flow",
    }


# ---------------------------------------------------------------------------
# Dimensions
# ---------------------------------------------------------------------------

def test_pihole_devices_are_keyed_by_address_with_the_name_beside_it():
    """v0.11 T5: a Pi-hole v6 client is keyed by its IP — the key Suricata
    has — so a search by IP finds its Pi-hole rows; the name is kept beside
    it (and a search by name finds them too)."""
    from apps.octo.ingest.tiering import extract_device_name

    assert extract_dimensions("pihole.query", _pihole(2)) == ("example.test", "192.0.2.10")
    assert extract_device_name("pihole.query", _pihole(2)) == "alice-laptop"
    p = _pihole(2)
    p["raw_query"]["client_name"] = None                      # v5, or v6 without a name
    assert extract_dimensions("pihole.query", p) == ("example.test", "192.0.2.10")
    assert extract_device_name("pihole.query", p) == ""
    p = _pihole(2)
    p["raw_query"]["client"] = None                           # a name only: it is the key
    assert extract_dimensions("pihole.query", p) == ("example.test", "alice-laptop")
    assert extract_device_name("pihole.query", p) == ""       # not repeated
    assert extract_device_name("suricata.dns", _eve("dns")) == ""


def test_suricata_dns_request_and_response_devices():
    req = _eve("dns", dns={"type": "query", "rrname": "WWW.Example.TEST.", "rrtype": "A"})
    assert extract_dimensions("suricata.dns", req) == ("www.example.test", "192.0.2.10")
    # A response travels server → client: the client is dest_ip.
    resp = _eve("dns", dns={"type": "answer", "rrname": "example.test"})
    resp["raw_eve"]["src_ip"], resp["raw_eve"]["dest_ip"] = "198.51.100.53", "192.0.2.11"
    assert extract_dimensions("suricata.dns", resp) == ("example.test", "192.0.2.11")
    # eve DNS v3 lists queries.
    v3 = _eve("dns", dns={"version": 3, "type": "request",
                          "queries": [{"rrname": "api.example.test", "rrtype": "AAAA"}]})
    assert extract_dimensions("suricata.dns", v3)[0] == "api.example.test"


def test_suricata_tls_http_flow_dimensions():
    assert extract_dimensions("suricata.tls", _eve("tls", tls={"sni": "login.example.test"})) \
        == ("login.example.test", "192.0.2.10")
    assert extract_dimensions("suricata.http", _eve("http", http={"hostname": "cdn.example.test"})) \
        == ("cdn.example.test", "192.0.2.10")
    assert extract_dimensions("suricata.flow", _eve("flow")) == ("", "192.0.2.10")


@pytest.mark.parametrize("bad", ["", "   ", "a b.test", "x" * 254, "ctl\x00.test", 42, None])
def test_unusable_domains_are_blank(bad):
    assert tiering.normalize_domain(bad) == ""


def test_generic_shape_dimensions():
    assert extract_dimensions("suricata.dns", {"query": "example.test"}) == ("example.test", "")


# ---------------------------------------------------------------------------
# Roll-up key: a Suricata DNS exchange is one lookup, not two
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dns_type,expected", [
    ("query", "suricata.dns"), ("request", "suricata.dns"), (None, "suricata.dns"),
    ("answer", tiering.SURICATA_DNS_ANSWER), ("response", tiering.SURICATA_DNS_ANSWER),
    ("ANSWER", tiering.SURICATA_DNS_ANSWER),
])
def test_suricata_dns_answers_roll_up_apart(dns_type, expected):
    dns = {"rrname": "example.test"}
    if dns_type is not None:
        dns["type"] = dns_type
    assert tiering.rollup_event_type("suricata.dns", _eve("dns", dns=dns)) == expected


@pytest.mark.parametrize("et,payload", [
    ("pihole.query", _pihole(2)), ("suricata.tls", _eve("tls")),
    ("suricata.dns", None), ("suricata.dns", {"raw_eve": "x"}),
])
def test_other_rollup_keys_are_the_event_type(et, payload):
    assert tiering.rollup_event_type(et, payload) == et


# ---------------------------------------------------------------------------
# First-seen eligibility: names that can be "new"
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "224.2.0.192.in-addr.arpa", "8.b.d.0.1.0.0.2.ip6.arpa", "router.home.arpa", "arpa",
    "printer.local", "local", "localhost",
    "qwhzkcdmrb", "alice-laptop",          # single-label: Chrome's probes, bare hosts
    "",
])
def test_names_that_never_enter_the_first_seen_ledger(name):
    assert tiering.first_seen_eligible(name) is False


@pytest.mark.parametrize("name", [
    "example.test", "login.example.test", "xk2j9q7wp.example.test",   # DGA-like: kept
    "localhost.example.test", "arpa.example.test",
])
def test_names_that_do(name):
    assert tiering.first_seen_eligible(name) is True


# ---------------------------------------------------------------------------
# classify_stored: the SQL path gives classify()'s answer for every fixture
# ---------------------------------------------------------------------------

def _parity_cases() -> list[tuple[str, object, str]]:
    cases: list[tuple[str, object, str]] = []
    for status in sorted(DOCUMENTED_PIHOLE):
        cases.append(("pihole.query", _pihole(status), "info"))
        cases.append(("pihole.query", _pihole(DOCUMENTED_PIHOLE[status][0]), "info"))
    for status in [19, -1, None, True, False, "", " 3 ", "2", "SOMETHING_NEW", 2.0, [2], {"s": 2}]:
        cases.append(("pihole.query", _pihole(status), "info"))
    raw_null = _pihole(2)
    raw_null["raw_query"]["status"] = None
    raw_null["status"] = 2                       # raw_query.status present (null) wins
    cases += [
        ("pihole.query", raw_null, "info"),
        ("pihole.query", {"status": 2}, "info"),
        ("pihole.query", {"status": 1}, "info"),
        ("pihole.query", {"raw_query": "text", "status": 3}, "info"),
        ("pihole.query", {"raw_query": {}, "status": 2}, "info"),
        ("pihole.query", {}, "info"),
        ("pihole.query", _pihole(2), "high"),
        ("pihole.query", _pihole(2), "low"),
        ("pihole.query", ["list"], "info"),
        ("pihole.query", "text", "info"),
        ("pihole.query", 7, "info"),
    ]
    for proto in ("dns", "tls", "http", "flow"):
        et = f"suricata.{proto}"
        cases += [
            (et, _eve(proto), "info"),
            (et, _eve(proto, alert={"signature_id": 1}), "info"),
            (et, _eve(proto, alert=None), "info"),
            (et, _eve("alert"), "info"),
            (et, {**_eve(proto), "alert": {"x": 1}}, "info"),
            (et, {"raw_eve": "not-a-record"}, "info"),
            (et, {"raw_eve": None}, "info"),
            (et, {"raw_eve": [1]}, "info"),
            (et, {"raw_eve": 5}, "info"),
            (et, {"raw_eve": {"event_type": None}}, "info"),
            (et, {"raw_eve": {"event_type": 7}}, "info"),
            (et, {"raw_eve": {"event_type": {"x": 1}}}, "info"),
            (et, {"query": "example.test"}, "info"),
            (et, _eve(proto), "medium"),
        ]
    cases += [("wazuh.alert", {"rule": {"level": 3}}, "info"), ("suricata.alert", _eve("alert"), "info")]
    return cases


def test_the_sql_classifier_matches_classify_on_every_fixture():
    import json
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, event_type TEXT, "
                 "severity TEXT, payload TEXT)")
    cases = _parity_cases()
    for et, payload, sev in cases:
        conn.execute("INSERT INTO events (event_type, severity, payload) VALUES (?, ?, ?)",
                     (et, sev, json.dumps(payload)))
    conn.execute("INSERT INTO events (event_type, severity, payload) VALUES "
                 "('pihole.query', 'info', '{not json')")
    cases.append(("pihole.query", None, "info"))
    got = [
        tiering.classify_stored(et, sev, tuple(features)).tier
        for et, sev, *features in conn.execute(
            f"SELECT event_type, severity, {tiering.STORED_FEATURES_SQL} FROM events ORDER BY id")
    ]
    want = [classify(et, payload, sev).tier for et, payload, sev in cases]
    mismatches = [(c, g, w) for c, g, w in zip(cases, got, want) if g != w]
    assert not mismatches
    assert len(got) == len(cases) > 100
