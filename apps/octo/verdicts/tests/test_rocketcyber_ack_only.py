"""RocketCyber = ACKNOWLEDGE ONLY, by SOURCE (v0.17.3; Rick, 2026-10-07:
"They are too vague to just do a sweeping expected tag on").

Until v0.17.2 a RocketCyber alert was acknowledge-only because its key names
no device. Now it is the source's rule, whatever the payload names:

  * `keys.expected_refusal` / `keys.repeat_refusal` answer with the
    RocketCyber wording — for an incident that DOES name a host too;
  * the evaluator ignores a RocketCyber expected rule or "repeats for 24 h"
    ack even when one is in the registry (an older release's, a row written
    past the API) — even one that names a device;
  * the store refuses to write either;
  * the alert's own ack still acknowledges it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.verdicts import keys
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import ACKED, OPEN, RESURFACED, Occurrence, TenantVerdicts

NOW = datetime(2026, 10, 7, 15, 0, tzinfo=timezone.utc)
HOSTED = {"id": 303, "status": "open", "title": "Suspicious PowerShell Detected",
          "hostname": "EXAMPLE-PC", "deviceName": "EXAMPLE-PC",
          "agent": {"hostname": "EXAMPLE-PC", "id": "agent-0001"},
          "device": {"hostname": "EXAMPLE-PC", "ip": "192.0.2.37"}}


def iso(dt: datetime) -> str:
    return vstore.iso(dt)


def _row(payload: dict, *, host: str | None = "EXAMPLE-PC") -> dict:
    return {"id": 9, "source": "rocketcyber", "event_type": "rocketcyber.incident",
            "source_host": host, "payload": payload}


# A key AS IF a release keyed RocketCyber by its host: the source rule must
# hold even then (today's key names no device).
WITH_DEVICE = keys.AlertKey("rocketcyber", "EXAMPLE-PC",
                            "rocketcyber:suspicious powershell detected", "rocketcyber",
                            ref="rocketcyber:303")


def _rule(key: keys.AlertKey, source: str | None = None) -> vstore.ExpectedRule:
    return vstore.ExpectedRule(5, "acme-corp", source or key.source, key.device_key,
                               key.signature_key, None, "label", "a reason long enough", 41, 7,
                               iso(NOW - timedelta(days=1)), iso(NOW + timedelta(days=30)))


def _ack(event_id: int, key: keys.AlertKey, *, at: datetime, repeat: bool = False,
         hits: int | None = None, last: datetime | None = None, vid: int = 1) -> vstore.Verdict:
    return vstore.Verdict(vid, "acme-corp", event_id, key.source, key.device_key,
                          key.signature_key, vstore.ACK, 7, iso(at), None, hits,
                          iso(last) if last else None,
                          iso(at + timedelta(hours=24)) if repeat else None,
                          alert_ref=key.ref)


def test_an_incident_that_names_a_host_is_refused_by_source():
    row = _row(HOSTED)
    k = keys.alert_key(row)
    assert keys.expected_refusal(row) == keys.ROCKETCYBER_REFUSAL
    assert keys.repeat_refusal(k) == keys.ROCKETCYBER_REPEAT
    assert keys.repeat_refusal(WITH_DEVICE) == keys.ROCKETCYBER_REPEAT
    assert not keys.expected_eligible_bucket(WITH_DEVICE)
    assert keys.ROCKETCYBER_REFUSAL == ("RocketCyber alerts are acknowledged one at a time — "
                                        "too vague for an expected condition (Rick, 2026-10-07)")
    # Another source with the same host stays as it was.
    assert keys.expected_refusal({"source": "datto", "payload": {
        "alertSourceInfo": {"deviceUid": "dev-1"},
        "alertContext": {"@class": "srvc_status_ctx", "serviceName": "Spooler"}}}) is None
    # The incident's own record and its being evidence still answer first.
    assert "evidence of an incident" in keys.expected_refusal(row, linked_incident=True)


def test_an_rc_rule_or_repeat_ack_in_the_registry_is_ignored_even_with_a_device():
    other = Occurrence(2, WITH_DEVICE, iso(NOW - timedelta(minutes=5)),
                       iso(NOW - timedelta(minutes=5)))
    tv = TenantVerdicts("acme-corp", [_ack(1, WITH_DEVICE, at=NOW - timedelta(hours=1),
                                           repeat=True)],
                        [_rule(WITH_DEVICE)], now=NOW)
    assert tv.rules == []
    assert tv.rule_for(other) is None
    # A different incident (another ref) that "repeats" the same key: OPEN.
    assert tv.state(Occurrence(2, keys.AlertKey(
        "rocketcyber", "EXAMPLE-PC", WITH_DEVICE.signature_key, "rocketcyber",
        ref="rocketcyber:404"), iso(NOW - timedelta(minutes=5)),
        iso(NOW - timedelta(minutes=5)))).status == OPEN
    # A rule stored under another source name but a RocketCyber signature: ignored too.
    assert TenantVerdicts("acme-corp", [], [_rule(WITH_DEVICE, source="other")],
                          now=NOW).rules == []


def test_its_own_ack_still_counts_and_growth_resurfaces_despite_a_repeat_window():
    own = Occurrence(1, WITH_DEVICE, iso(NOW - timedelta(minutes=50)),
                     iso(NOW - timedelta(minutes=50)))
    tv = TenantVerdicts("acme-corp", [_ack(1, WITH_DEVICE, at=NOW - timedelta(minutes=40))],
                        [], now=NOW)
    assert tv.state(own).status == ACKED
    # A coalesced row that GREW after an ack carrying repeat_until (written
    # past the API): the repeat window never covers the growth.
    grown = Occurrence(1, WITH_DEVICE, iso(NOW - timedelta(minutes=50)),
                       iso(NOW - timedelta(minutes=5)), hits=4)
    tv = TenantVerdicts("acme-corp", [_ack(1, WITH_DEVICE, at=NOW - timedelta(minutes=40),
                                           repeat=True, hits=2,
                                           last=NOW - timedelta(minutes=45))], [], now=NOW)
    st = tv.state(grown)
    assert st.status == RESURFACED and not st.by_repeat


def test_a_non_rc_repeat_ack_still_works():
    k = keys.AlertKey("datto", "dev-1", "datto:srvc_status_ctx|spooler", "datto")
    tv = TenantVerdicts("acme-corp", [_ack(1, k, at=NOW - timedelta(hours=1), repeat=True)],
                        [], now=NOW)
    later = Occurrence(2, k, iso(NOW - timedelta(minutes=5)), iso(NOW - timedelta(minutes=5)))
    st = tv.state(later)
    assert st.status == ACKED and st.by_repeat


def test_the_store_refuses_an_rc_rule_or_repeat_ack():
    import sqlite3

    conn = sqlite3.connect(":memory:")
    with pytest.raises(ValueError, match="RocketCyber alerts are acknowledged one at a time"):
        vstore.add_expected(conn, slug="acme-corp", key=WITH_DEVICE, remote=None, label="x",
                            reason="a reason long enough", origin_event_id=1, by=7, now=NOW,
                            review_at=NOW + timedelta(days=30))
    with pytest.raises(ValueError, match="repeats for 24 h"):
        vstore.record(conn, slug="acme-corp", event_id=1, key=WITH_DEVICE, verdict=vstore.ACK,
                      actor=7, at=NOW, repeat_until=NOW + timedelta(hours=24))
