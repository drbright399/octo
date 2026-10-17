"""The client (viewer) view of an incident (design 6.9 + Rick's 9.2): hidden
until an operator acknowledges it or it is 60 minutes old; neutral strings
only — never a vendor, a device, an indicator, a rule or a pulse; exactly two
actions; FR-rule incidents never shown; a closed one only as the
true-positive watch."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from apps.octo.threat import client_view, lockdown, store
from apps.octo.threat.tests.conftest import A

NOW = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)
FORBIDDEN = ("ws-01", "198.51.100.23", "relay-young.example.test", "b6", "r8", "rule",
             "unifi", "nextdns", "datto", "rocketcyber", "wazuh", "opencanary", "alice",
             "pulse", "acknowledged_by", "device")


def _inc(tier: str = "black", *, at: datetime = NOW, key: str = "k1",
         rule: str = "B6") -> store.Incident:
    return store.open_incident(
        A, tier=tier, rule_id=rule, rule_version=1, key=key,
        summary="ws-01 beaconing to relay-young.example.test (198.51.100.23)",
        scope="device", opened_by="7", reason="seen by alice on ws-01", device_ref="ws-01",
        device_label="WS-01", now=at).incident


def _clean(payload) -> None:
    if isinstance(payload, dict):
        payload = {k: v for k, v in payload.items() if k != "ref"}   # opaque hex
    text = json.dumps(payload).lower()
    for word in FORBIDDEN:
        assert word not in text, word


def test_hidden_before_an_ack_or_60_minutes(troot):
    inc = _inc()
    assert client_view.visible(inc, NOW + timedelta(minutes=59)) is False
    assert client_view.payload(inc, NOW + timedelta(minutes=59)) is None
    assert client_view.visible(inc, NOW + timedelta(minutes=60)) is True
    acked = store.ack(A, inc.id, by="7", now=NOW + timedelta(minutes=2))
    assert client_view.visible(acked, NOW + timedelta(minutes=3)) is True
    assert acked.client_visible_at == "2026-10-03T15:02:00.000Z"


def test_the_neutral_lines(troot):
    black = _inc()
    later = NOW + timedelta(hours=2)
    assert client_view.line(black, later) == client_view.LINE_BLACK
    acked = store.ack(A, black.id, by="7", now=NOW + timedelta(minutes=5))
    assert client_view.line(acked, later) == client_view.LINE_BLACK_ACKED
    contained = store.contain(A, black.id, by="7", receipt="both services stopped",
                              now=NOW + timedelta(minutes=10))
    assert client_view.line(contained, later) == client_view.LINE_CONTAINED
    red = _inc("red", key="k2", rule="R8")
    assert client_view.line(red, later) == client_view.LINE_RED
    closed = store.close(A, red.id, by="7", code="remediated", text="cleaned",
                         now=NOW + timedelta(hours=1))
    assert client_view.line(closed, later) == client_view.LINE_WATCH
    assert client_view.line(closed, NOW + timedelta(days=9)) is None     # past the watch
    fp = _inc("red", key="k3", rule="R8")
    fp = store.close(A, fp.id, by="7", code="false_positive", text="ours",
                     now=NOW + timedelta(hours=1))
    assert client_view.line(fp, later) is None                             # never shown
    for line in (client_view.LINE_BLACK, client_view.LINE_BLACK_ACKED,
                 client_view.LINE_CONTAINED, client_view.LINE_RED, client_view.LINE_WATCH):
        _clean(line)


def test_the_payload_carries_nothing_but_the_neutral_view(troot):
    inc = _inc()
    payload = client_view.payload(inc, NOW + timedelta(hours=1))
    assert set(payload) == {"ref", "tier", "status_neutral", "opened_at", "actions",
                            "decisions"}
    assert payload["ref"] == client_view.ref(A, inc.id) and A not in payload["ref"]
    assert [a["kind"] for a in payload["actions"]] == ["lockdown", "allow"]
    assert [a["label"] for a in payload["actions"]] == [
        "Lock down my network and contact my analyst", "Allow this traffic"]
    _clean(payload)


def test_exactly_two_actions_and_none_once_closed(troot):
    assert [k for k, _ in client_view.ACTIONS] == ["lockdown", "allow"]
    inc = _inc("red", rule="R8")
    closed = store.close(A, inc.id, by="7", code="remediated", text="cleaned",
                         now=NOW + timedelta(hours=1))
    assert client_view.payload(closed, NOW + timedelta(hours=2))["actions"] == []


def test_a_black_allow_is_a_pending_request_a_red_allow_the_clients_decision():
    assert client_view.decision_status("allow", "black") == "pending_analyst"
    assert client_view.decision_status("allow", "red") == "recorded"
    assert client_view.decision_status("lockdown", "black") == "recorded"
    assert "analyst must confirm" in client_view.confirmation("allow", "black")
    assert lockdown.LIFE_SAFETY_NOTICE.lower() in client_view.confirmation("lockdown",
                                                                            "red").lower()


def test_fr_rule_incidents_are_internal(troot):
    inc = _inc("red", key="k-fr", rule="FR1")
    assert client_view.visible(inc, NOW + timedelta(hours=3)) is False


def test_a_reopened_incident_waits_for_triage_again(troot):
    """Reopening clears the acknowledgement AND the visibility stamp, and the
    60-minute clock restarts at the reopen — a record once closed (even as a
    false positive) never reaches the client before someone looked again."""
    inc = _inc("red", key="k-re", rule="R8")
    acked = store.ack(A, inc.id, by="7", now=NOW + timedelta(minutes=2))
    assert acked.client_visible_at is not None
    store.close(A, inc.id, by="7", code="false_positive", text="the vendor's scan",
                now=NOW + timedelta(hours=1))
    reopen_at = NOW + timedelta(days=2)
    back = _inc("red", key="k-re", rule="R8", at=reopen_at)
    assert back.id == inc.id and back.reopened_count == 1
    assert back.client_visible_at is None and not back.acked
    assert client_view.clock_start(back) == reopen_at
    assert client_view.visible(back, reopen_at + timedelta(minutes=30)) is False
    assert client_view.visible(back, reopen_at + timedelta(minutes=60)) is True


def test_the_worst_line_of_several(troot):
    items = [{"status_neutral": client_view.LINE_RED},
             {"status_neutral": client_view.LINE_BLACK_ACKED},
             {"status_neutral": client_view.LINE_CONTAINED}]
    assert client_view.worst_line(items) == client_view.LINE_BLACK_ACKED
    worst = client_view.worst_line(items + [{"status_neutral": client_view.LINE_BLACK}])
    assert worst == client_view.LINE_BLACK
    assert client_view.worst_line([]) is None
