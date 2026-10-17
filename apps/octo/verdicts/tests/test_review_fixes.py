"""v0.17.2 review fixes, in isolation (no store):

  * an alert that names no device (a RocketCyber incident) is never covered
    by an expected rule or a repeat-ack — even a row written past the API;
  * the rows of ONE vendor alert share an ack: a Datto raise and its
    resolution; a RocketCyber incident's earlier versions (a later version
    re-surfaces it);
  * Datto signature keys name the monitor precisely enough: AV status,
    a component monitor's message shape, an unknown class's message shape;
    a ransomware / endpoint-threat DETECTION is never expected;
  * "repeats for 24 h" is never offered for a device-less alert or a CSAM
    lookup.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apps.octo.verdicts import keys
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import ACKED, OPEN, RESURFACED, Occurrence, TenantVerdicts

NOW = datetime(2026, 10, 6, 15, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return vstore.iso(dt)


def _ack(event_id: int, key: keys.AlertKey, *, at: datetime, last: datetime | None = None,
         repeat: bool = False, vid: int = 1) -> vstore.Verdict:
    return vstore.Verdict(vid, "acme-corp", event_id, key.source, key.device_key,
                          key.signature_key, vstore.ACK, 7, iso(at), None, None,
                          iso(last) if last else None,
                          iso(at + timedelta(hours=24)) if repeat else None,
                          alert_ref=key.ref)


def _rule(key: keys.AlertKey) -> vstore.ExpectedRule:
    return vstore.ExpectedRule(5, "acme-corp", key.source, key.device_key, key.signature_key,
                               None, "label", "a reason long enough", 41, 7,
                               iso(NOW - timedelta(days=1)), iso(NOW + timedelta(days=30)))


def _row_occ(event_id: int, key: keys.AlertKey, at: datetime) -> Occurrence:
    return Occurrence(event_id, key, iso(at), iso(at))


def _rc(iid: int, title: str = "Suspicious PowerShell Detected") -> keys.AlertKey:
    return keys.alert_key({"source": "rocketcyber", "event_type": "rocketcyber.incident"},
                          {"id": iid, "title": title})


def _datto(uid: str, *, resolved: bool = False, ctx: dict | None = None,
           device: str = "dev-1", **extra) -> dict:
    return {"alertUid": uid, "resolved": resolved,
            "alertSourceInfo": {"deviceUid": device, "deviceName": "EXAMPLE-SRV"},
            "alertContext": ctx if ctx is not None else {
                "@class": "srvc_status_ctx", "serviceName": "Spooler", "status": "Stopped"},
            **extra}


# ---------------------------------------------------------------------------
# No device: never client-wide
# ---------------------------------------------------------------------------

def test_a_rocketcyber_incident_names_no_device_and_is_never_expected_or_repeat_acked():
    k = _rc(101)
    assert k.device_key == "" and k.ref == "rocketcyber:101"
    row = {"id": 9, "source": "rocketcyber", "event_type": "rocketcyber.incident",
           "payload": {"id": 101, "title": "Suspicious PowerShell Detected"}}
    # v0.17.3: the SOURCE rule answers first (Rick, 2026-10-07).
    assert keys.expected_refusal(row) == keys.ROCKETCYBER_REFUSAL
    assert keys.repeat_refusal(k) == keys.ROCKETCYBER_REPEAT
    assert not keys.expected_eligible_bucket(k)


def test_a_device_less_rule_or_repeat_ack_written_past_the_api_never_matches():
    k = _rc(101)
    other = _rc(202)                         # another incident, same title, any device
    tv = TenantVerdicts("acme-corp", [_ack(1, k, at=NOW - timedelta(hours=1), repeat=True)],
                        [_rule(k)], now=NOW)
    assert tv.rules == []                    # a device-less rule is never applied
    st = tv.state(_row_occ(2, other, NOW - timedelta(minutes=5)))
    assert st.status == OPEN                 # nor a device-less "repeats for 24 h"


def test_csam_is_never_repeat_acked():
    k = keys.nextdns_key("p1", "D1", "bad.example.test", "csam")
    assert keys.repeat_refusal(k) == keys.CSAM_REPEAT
    tif = keys.nextdns_key("p1", "D1", "bad.example.test", "threat-intelligence-feeds")
    assert keys.repeat_refusal(tif) is None
    assert keys.repeat_refusal(tif, csam=True) == keys.CSAM_REPEAT


# ---------------------------------------------------------------------------
# One vendor alert, several rows
# ---------------------------------------------------------------------------

def test_an_ack_of_a_datto_raise_covers_its_resolution_row():
    raise_key = keys.alert_key({"source": "datto"}, _datto("uid-1"))
    resolved_key = keys.alert_key({"source": "datto"}, _datto("uid-1", resolved=True))
    other_key = keys.alert_key({"source": "datto"}, _datto("uid-2"))
    assert raise_key.ref == resolved_key.ref == "datto:uid-1" != other_key.ref
    tv = TenantVerdicts("acme-corp", [_ack(10, raise_key, at=NOW - timedelta(minutes=30),
                                           last=NOW - timedelta(minutes=40))], [], now=NOW)
    assert tv.state(_row_occ(10, raise_key, NOW - timedelta(minutes=40))).status == ACKED
    # The resolution arrived AFTER the ack: the same alert, not a new one.
    assert tv.state(_row_occ(11, resolved_key, NOW - timedelta(minutes=5))).status == ACKED
    assert tv.state(_row_occ(12, other_key, NOW - timedelta(minutes=5))).status == OPEN


def test_a_rocketcyber_ack_covers_earlier_versions_and_a_later_one_re_surfaces():
    k = _rc(101)
    v1, v2, v3 = NOW - timedelta(hours=3), NOW - timedelta(hours=2), NOW - timedelta(minutes=5)
    tv = TenantVerdicts("acme-corp", [_ack(20, k, at=NOW - timedelta(hours=1), last=v2)], [],
                        now=NOW)
    assert tv.state(_row_occ(19, k, v1)).status == ACKED       # an earlier version
    assert tv.state(_row_occ(20, k, v2)).status == ACKED       # the version acked
    st = tv.state(_row_occ(21, k, v3))                         # changed since: re-surfaced
    assert st.status == RESURFACED and st.ack is not None and not st.hidden
    # An ack that does not say which version was acked covers no other one.
    blind = TenantVerdicts("acme-corp", [_ack(20, k, at=NOW - timedelta(hours=1))], [],
                           now=NOW)
    assert blind.state(_row_occ(19, k, v1)).status == RESURFACED


def test_acks_of_the_alerts_judged_are_read_whatever_their_age():
    k = _rc(101)
    old = _ack(20, k, at=NOW - timedelta(days=5), last=NOW - timedelta(days=5, minutes=1))
    asked: list[dict] = []

    def loader(slug, **kw):
        asked.append(kw)
        return [old] if kw.get("refs") == ["rocketcyber:101"] else []

    tv = TenantVerdicts("acme-corp", [], [], now=NOW, loader=loader)
    assert tv.empty
    tv.ensure(refs=["rocketcyber:101"])
    assert not tv.empty
    assert tv.state(_row_occ(20, k, NOW - timedelta(days=5, minutes=1))).status == ACKED
    tv.ensure(refs=["rocketcyber:101"])                        # asked once only
    assert [a.get("refs") for a in asked] == [["rocketcyber:101"]]


# ---------------------------------------------------------------------------
# Datto signature keys
# ---------------------------------------------------------------------------

def _sig(ctx: dict, **extra) -> str:
    return keys.alert_key({"source": "datto"}, _datto("u", ctx=ctx, **extra)).signature_key


def test_antivirus_not_running_is_not_antivirus_out_of_date():
    running = _sig({"@class": "antivirus_ctx", "productName": "Example AV", "status": "Not Running"})
    stale = _sig({"@class": "antivirus_ctx", "productName": "Example AV",
                  "status": "Not Up To Date"})
    assert running != stale and "not running" in running


def test_two_component_monitors_with_the_same_samples_do_not_share_a_key():
    def comp(diag: str) -> str:
        return _sig({"@class": "comp_script_ctx", "samples": {"Status": "FAIL", "DIAG": diag}})

    backup = comp("Backup job Nightly failed after 37 minutes")
    assert backup == comp("Backup job Nightly failed after 112 minutes")   # numbers masked
    assert backup != comp("Certificate expires in 12 days")
    assert backup.startswith("datto:comp_script_ctx|diag,status|backup job nightly failed")


def test_an_unknown_class_keys_by_alert_type_and_message_shape():
    a = _sig({"@class": "endpoint_security_windows_defender_ctx",
              "description": "Real-time protection is off"})
    b = _sig({"@class": "endpoint_security_windows_defender_ctx",
              "description": "Definitions are 9 days old"})
    assert a != b


def test_a_ransomware_or_threat_detection_is_never_expected_and_keys_by_what_it_saw():
    ctx = {"@class": "ransomware_ctx", "state": "Detected", "rwextension": ".locked",
           "affectedDirectories": "C:\\Shares"}
    row = {"id": 5, "source": "datto", "event_type": "datto.ransomware",
           "payload": _datto("u", ctx=ctx)}
    assert "ransomware" in (keys.expected_refusal(row) or "")
    assert _sig(ctx) != _sig(dict(ctx, rwextension=".crypt"))
    threat = {"id": 6, "source": "datto", "event_type": "datto.alert",
              "payload": _datto("u", ctx={"@class": "endpoint_security_threat_ctx",
                                          "description": "Trojan found"})}
    assert "threat detection" in (keys.expected_refusal(threat) or "")
    # A service monitor stays eligible (the reference cases are monitors).
    svc = {"id": 7, "source": "datto", "event_type": "datto.srvc", "payload": _datto("u")}
    assert keys.expected_refusal(svc) is None
