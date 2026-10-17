"""The doorbell's parts on their own: `DattoClient.get_alert` (real client,
fake socket), the body reader (`adapters.datto.doorbell`) and the bounded
fetch memory (`instances.doorbell`)."""
from __future__ import annotations

import pytest

from apps.octo.adapters.datto import doorbell as reader
from apps.octo.adapters.datto.client import (
    DattoClientError,
    DattoForbiddenError,
    DattoNotFoundError,
)
from apps.octo.adapters.datto.fields import is_alert_uid
from apps.octo.adapters.datto.tests.fake_datto import (
    FORBIDDEN_TEXT,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
    real_client,
)
from apps.octo.adapters.datto.tests.test_presentation import EVENTLOG, api_alert
from apps.octo.instances import doorbell as memory

UID = "0a1b2c3d-aaaa-bbbb-cccc-000000000001"


@pytest.fixture(autouse=True)
def _clean_memory():
    memory.reset()
    yield
    memory.reset()


# ---------------------------------------------------------------------------
# DattoClient.get_alert
# ---------------------------------------------------------------------------

def test_get_alert_returns_the_vendors_object_verbatim_with_the_doorbell_timeout():
    transport = FakeDattoTransport()
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    client = real_client(transport)
    assert client.get_alert(UID, timeout_seconds=8.0) == api_alert(EVENTLOG)
    assert transport.calls[-1] == ("GET", f"/api/v2/alert/{UID}")
    # The token exchange keeps the configured timeout; the read gets the
    # shorter one — and never a LONGER one than configured.
    assert transport.timeouts[-1] == 8.0
    assert client.get_alert(UID, timeout_seconds=99.0) and transport.timeouts[-1] == 15.0
    assert client.get_alert(UID) and transport.timeouts[-1] == 15.0


@pytest.mark.parametrize("bad", [
    "", "a-1", "[alert_uid]", UID + "x", UID[:-1], "../account", UID.replace("-", ""),
    UID + "/../../account", "0a1b2c3d-aaaa-bbbb-cccc-00000000000g", None, 7, [UID],
])
def test_get_alert_refuses_anything_that_is_not_a_uid_before_sending(bad):
    transport = FakeDattoTransport()
    client = real_client(transport)
    with pytest.raises(ValueError):
        client.get_alert(bad)
    assert transport.calls == []
    assert not is_alert_uid(bad)


def test_get_alert_checks_the_answer_names_the_alert_asked_for():
    transport = FakeDattoTransport()
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG, alertUid=UID.replace("1", "2"))
    with pytest.raises(DattoClientError, match="different alert"):
        real_client(transport).get_alert(UID)
    transport.alerts_by_uid[UID] = {"unrelated": True}
    with pytest.raises(DattoClientError, match="different alert"):
        real_client(transport).get_alert(UID)
    # Case does not make it a different alert.
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG, alertUid=UID.upper())
    assert real_client(transport).get_alert(UID)["alertUid"] == UID.upper()


def test_get_alert_failure_classes_and_operator_safe_messages():
    transport = FakeDattoTransport()
    client = real_client(transport)
    with pytest.raises(DattoNotFoundError):
        client.get_alert(UID)                       # the fake does not know it
    transport.alert_fetch_status = 403
    with pytest.raises(DattoForbiddenError) as forbidden:
        client.get_alert(UID)
    assert forbidden.value.vendor_error == FORBIDDEN_TEXT.replace("'", "’")
    transport.alert_fetch_status = 500
    with pytest.raises(DattoClientError, match="HTTP 500"):
        client.get_alert(UID)
    transport.alert_fetch_status = None
    transport.alert_fetch_times_out = True
    with pytest.raises(DattoClientError, match="ReadTimeout") as timed_out:
        client.get_alert(UID)
    for exc in (forbidden.value, timed_out.value):
        for secret in SECRETS:
            assert secret not in str(exc)


def test_adapter_fetch_alert_maps_every_failure_and_needs_a_running_instance():
    from apps.octo.adapters.datto.tests.fake_datto import CREDS

    transport = FakeDattoTransport()
    adapter = datto_adapter_class(transport)()
    with pytest.raises(memory.AlertFetchError) as not_running:
        adapter.fetch_alert(UID)
    assert not_running.value.kind == "not_running"
    assert transport.calls == []

    adapter.start(dict(CREDS))          # no running loop: poller deferred, client live
    try:
        for status, kind in ((None, "not_found"), (403, "forbidden"), (500, "transport")):
            transport.alert_fetch_status = status
            with pytest.raises(memory.AlertFetchError) as failed:
                adapter.fetch_alert(UID, timeout_seconds=8.0)
            assert failed.value.kind == kind
            for secret in SECRETS:
                assert secret not in failed.value.message
        with pytest.raises(memory.AlertFetchError) as invalid:
            adapter.fetch_alert("not-a-uid")
        assert invalid.value.kind == "invalid"
        transport.alert_fetch_status = None
        transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
        assert adapter.fetch_alert(UID, timeout_seconds=8.0) == api_alert(EVENTLOG)
        assert transport.timeouts[-1] == 8.0
    finally:
        adapter.stop()


# ---------------------------------------------------------------------------
# Reading the bell
# ---------------------------------------------------------------------------

def test_read_envelope_takes_only_a_uuid_and_a_known_event():
    bell = reader.read_envelope({"alertUid": UID, "event": "alert_resolved"})
    assert bell == reader.Doorbell(UID, "alert_resolved") and bell.resolved
    assert reader.read_envelope({"alertUid": UID.upper()}).alert_uid == UID
    # The shared field reader strips whitespace, as for every other field.
    assert reader.read_envelope({"alertUid": " " + UID + "\n"}).alert_uid == UID
    for uid in ("a-1", "[alert_uid]", UID + " x", 5, None, {"x": UID}, [UID]):
        assert reader.read_envelope({"alertUid": uid, "event": "alert_raised"}).alert_uid is None
    for event in ("deleted", "ALERT_RAISED", "", None, 1, ["alert_raised"]):
        assert reader.read_envelope({"alertUid": UID, "event": event}).event is None
    assert reader.read_envelope({}) == reader.Doorbell()


def test_read_raw_scans_a_broken_body_strictly():
    body = (
        b'{"event": "alert_resolved", "alertUid": "' + UID.upper().encode()
        + b'", "alertContext": {"message": "line one\r\n"quoted"\tline two"}'
    )
    assert reader.read_raw(body) == reader.Doorbell(UID, "alert_resolved")
    assert reader.read_raw(b'{ "alertUid" : "' + UID.encode() + b'"').alert_uid == UID
    for body in (
        b"",
        b"not json at all",
        b'{"alertUid": "not-a-uuid"',
        b'{"alertUid": "' + UID.encode()[:-1] + b'"',           # 35 chars
        b'{"alertUid": "' + UID.encode() + b'x"',               # 37 chars
        b'{"alertUid": ' + UID.encode() + b'',                  # unquoted
        b"{'alertUid': '" + UID.encode() + b"'",                # single quotes
        b'{"deviceUid": "' + UID.encode() + b'"',               # another key
        b'{"alertuid": "' + UID.encode() + b'"',                # wrong case key
        b'{"alertUid": "\xff' + UID.encode() + b'"',            # not UTF-8, not a uid
        b'{"alertUid": "' + UID.encode() + b'", "alertUid": "' + UID.encode() + b'"',
    ):
        bell = reader.read_raw(body)
        assert bell.alert_uid in (None, UID), body
        if bell.alert_uid == UID:
            assert body.count(UID.encode()) == 2     # the duplicate-key case only
    for body in (b'"event": "alert_deleted"', b'"event": "raised"', b"event: alert_raised"):
        assert reader.read_raw(body).event is None
    assert reader.read_raw(b'"event":"alert_raised"').event == "alert_raised"
    # Bounded work: a large body is one linear scan.
    assert reader.read_raw(b"x" * 1_000_000 + b'"alertUid": "' + UID.encode() + b'"').alert_uid == UID


def test_as_delivered_marks_resolved_only_when_the_bell_says_so():
    alert = api_alert(EVENTLOG)
    raised = reader.Doorbell(UID, "alert_raised")
    resolved = reader.Doorbell(UID, "alert_resolved")
    assert reader.as_delivered(alert, raised) is alert          # untouched: the poller's copy
    assert reader.as_delivered(alert, reader.Doorbell(UID, None)) is alert
    stamped = reader.as_delivered(alert, resolved)
    assert stamped == {**alert, "resolved": True} and alert["resolved"] is False
    already = {**alert, "resolved": True, "resolvedOn": 1}
    assert reader.as_delivered(already, resolved) is already   # the API's own flag stands


# ---------------------------------------------------------------------------
# The memory: per-uid window, instance budget, bounds, reset
# ---------------------------------------------------------------------------

def test_memory_remembers_per_uid_for_the_window_and_is_bounded(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(memory, "_monotonic", lambda: now[0])
    assert memory.recent(1, UID) is None
    memory.remember(1, UID, alert={"alertUid": UID})
    assert memory.recent(1, UID) == memory.Remembered({"alertUid": UID}, None)
    assert memory.recent(2, UID) is None                    # per instance
    memory.remember(1, "other", failure="forbidden")
    assert memory.recent(1, "other") == memory.Remembered(None, "forbidden")
    now[0] += memory.PER_ID_WINDOW_SEC + 0.1
    assert memory.recent(1, UID) is None and memory.recent(1, "other") is None
    # No instance id: nothing is kept, nothing is found.
    memory.remember(None, UID, alert={})
    assert memory.recent(None, UID) is None

    for i in range(memory.MAX_REMEMBERED_PER_INSTANCE + 10):
        memory.remember(3, f"uid-{i}", failure="not_found")
    assert memory.recent(3, "uid-0") is None                # oldest out
    assert memory.recent(3, f"uid-{memory.MAX_REMEMBERED_PER_INSTANCE + 9}") is not None


def test_memory_budget_is_a_sliding_minute_per_instance(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(memory, "_monotonic", lambda: now[0])
    monkeypatch.setattr(memory, "FETCHES_PER_MINUTE", 3)
    assert [memory.take_fetch(1) for _ in range(3)] == [0, 0, 0]
    assert memory.take_fetch(1) == 60 and memory.fetches_in_window(1) == 3
    assert memory.take_fetch(2) == 0                        # another instance's budget
    assert memory.take_fetch(None) == 0                     # nothing to attribute to
    now[0] += 30
    assert memory.take_fetch(1) == 30
    now[0] += 30.5
    assert memory.take_fetch(1) == 0                        # the first one aged out
    memory.reset(1)
    assert memory.fetches_in_window(1) == 0 and memory.fetches_in_window(2) == 1
    memory.reset()
    assert memory.fetches_in_window(2) == 0


def test_alert_fetch_error_kinds_are_closed():
    assert memory.AlertFetchError("not_found", "x").kind == "not_found"
    assert memory.AlertFetchError("something-new", "x").kind == "transport"
    assert str(memory.AlertFetchError("auth", "static text")) == "static text"
