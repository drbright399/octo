"""The Datto webhook as a DOORBELL — through the real HTTP route with the REAL
Datto adapter, client, instance manager, tenant map, receipt recorder and
SQLite sink; only the vendor socket is fake (adapters/datto/tests/fake_datto.py).

What production showed, and what this therefore pins:
  * Datto substitutes [alert_message] (multi-line Windows event text, with
    quotes) into the operator's JSON template WITHOUT escaping it — 4 of 9
    real webhooks in one night were 422 'malformed';
  * the ones that parsed produced a different payload than the polled copy
    of the same alert (severity 'info', no context class).
So: the body is read for the alertUid (a UUID — from the JSON, or from the
raw text when the JSON is broken), the alert is fetched from Datto's API
through the running instance and stored in the poller's shape, the sink
collapses the poll copy, and every fetch is bounded (one per uid per minute,
an instance budget, a deadline) — the vendor is waiting for its 2xx.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.tests.fake_datto import (
    ALERTS_PATH,
    CREDS,
    FORBIDDEN_TEXT,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
)
from apps.octo.adapters.datto.tests.test_presentation import (
    EVENTLOG,
    WINDOWS_4625,
    api_alert,
)
from apps.octo.instances import (
    doorbell, quarantine, tenant_map, unmapped, vendor_contact, webhook_receipt,
)
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"
_HOOK = "/api/v1/webhooks/datto"
_INGEST = "https://ingest.example.test"
_CARD = "/api/v1/integrations"

UID = "0a1b2c3d-aaaa-bbbb-cccc-000000000001"
UID_2 = "0a1b2c3d-aaaa-bbbb-cccc-000000000002"
UID_3 = "0a1b2c3d-aaaa-bbbb-cccc-000000000003"
SITE = "site-uid-0001"
ALERT_CALL = ("GET", f"/api/v2/alert/{UID}")


@pytest.fixture
def bell(instance_endpoint_client, monkeypatch):  # noqa: F811
    """(client, transport, token, instance id): a running Datto instance on a
    fake vendor, its site mapped to the provisioned client 'acme', its
    generated webhook token in hand, and clean process-local state."""
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", _INGEST)
    for module in (webhook_receipt, doorbell, unmapped, vendor_contact):
        module.reset()
    quarantine.reset_schema_cache()   # a fresh data root per test
    webhook_receipt.stop_flusher()
    client = instance_endpoint_client
    transport = FakeDattoTransport()
    client.app.state.adapter_registry.register_adapter_class(datto_adapter_class(transport))
    client_provisioning.create_client("acme", "Acme")
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    client.cookies_ = cookies
    yield client, transport
    client.app.state.instance_manager.stop_all_running()
    for module in (webhook_receipt, doorbell, unmapped, vendor_contact):
        module.reset()
    quarantine.reset_schema_cache()


def _create(client, transport, **config) -> tuple[int, str]:
    r = client.post(_CREATE, json={
        "credentials": {**CREDS, "DATTO_WEBHOOK_SECRET": ""},
        "enable_webhook": True,
        "instance_config": config,
    }, cookies=client.cookies_)
    assert r.status_code == 200, r.text
    iid = r.json()["instance"]["id"]
    tenant_map.set_mappings(iid, [tenant_map.TenantMapping(SITE, "acme")])
    return iid, r.json()["generated_webhook_secret"]["header_value"]


def _ring(client, token: str, body, **headers):
    """One webhook POST. `body` may be a dict (sent as JSON) or raw bytes."""
    hdrs = {"X-Webhook-Token": token, "Content-Type": "application/json", **headers}
    if isinstance(body, (bytes, bytearray)):
        return client.post(_HOOK, content=bytes(body), headers=hdrs)
    return client.post(_HOOK, json=body, headers=hdrs)


def _id_only(uid: str = UID, event: str = "alert_raised", **over) -> dict:
    """The ID-only template from the setup guide, as Datto would send it."""
    body = {
        "event": event, "alertUid": uid, "siteUid": SITE, "siteName": "Example Site",
        "device": {"hostname": "WS-EXAMPLE-01", "uid": "dev-uid-0001"},
        "alertCategory": "Event Log", "alertType": "Event Log Monitor",
    }
    if event == "alert_resolved":
        body["resolved"] = True
    body.update(over)
    return body


def _broken_rich_body(uid: str = UID, event: str = "alert_raised") -> bytes:
    """The OLD rich template after Datto substituted a real Windows event
    into [alert_message] unescaped: raw CR/LF and tabs inside the string,
    and a quote in the failure reason. Not JSON — exactly what arrived."""
    message = WINDOWS_4625.replace(
        "Unknown user name or bad password.", 'Unknown user name or "bad" password.',
    )
    return (
        b'{\n  "event": "' + event.encode() + b'",\n  "alertUid": "' + uid.encode()
        + b'",\n  "alertCategory": "Event Log",\n  "alertType": "Event Log Monitor",\n'
        + b'  "alertContext": {"message": "' + message.encode() + b'"},\n'
        + b'  "device": {"hostname": "WS-EXAMPLE-01", "uid": "dev-uid-0001"},\n'
        + b'  "siteUid": "' + SITE.encode() + b'",\n  "siteName": "Example Site"\n}'
    )


def _rows(slug: str = "acme") -> list[tuple]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return conn.execute(
            "SELECT event_type, summary, severity, source_host, payload, payload_sha256 "
            "FROM events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def _alert_fetches(transport: FakeDattoTransport, uid: str = UID) -> int:
    return transport.count(f"/api/v2/alert/{uid}")


def _wait_for(predicate, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached in time"
        time.sleep(0.01)


def _receipt(client) -> dict:
    r = client.get(_CARD, cookies=client.cookies_)
    assert r.status_code == 200, r.text
    return r.json()["instances"]["datto"]["webhook_receipt"]


# ---------------------------------------------------------------------------
# The doorbell: fetched from the API, stored in the poller's shape
# ---------------------------------------------------------------------------

def test_a_parsed_doorbell_stores_the_api_alert_exactly_as_the_poller_would(bell, caplog):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)

    with caplog.at_level(logging.INFO):
        r = _ring(client, token, _id_only())
    assert r.status_code == 200, r.text
    assert r.json() == {
        "status": "accepted", "ingested": True, "tenant": "acme", "event_id": UID,
        "idempotent": False, "routing": "mapped", "via": "api",
    }
    assert _alert_fetches(transport) == 1

    # Byte for byte what the poller stores for this alert.
    polled = DattoSourceAdapter().extract_event(api_alert(EVENTLOG))
    ((event_type, summary, severity, host, payload, sha),) = _rows()
    assert event_type == polled.event_type == "datto.eventlog"
    assert summary == polled.summary == "Event log · Security 4625 — An account failed to log on"
    assert severity == polled.severity == "high"      # from the API's `priority`
    assert host == "WS-EXAMPLE-01" and sha == polled.payload_sha256
    assert json.loads(payload) == api_alert(EVENTLOG)   # NOT the templated body
    # Not the poller's 15 s: the vendor is waiting for its 2xx.
    fetch_index = transport.calls.index(ALERT_CALL)
    assert transport.timeouts[fetch_index] == doorbell.FETCH_TIMEOUT_SEC

    receipt = _receipt(client)
    assert receipt["accepted_since_start"] == 1 and receipt["rejected_since_start"] == 0
    assert f"alert {UID} fetched from Datto" in caplog.text
    for secret in SECRETS:
        assert secret not in caplog.text and secret not in r.text


def test_a_malformed_body_naming_the_alert_is_still_stored_via_the_api(bell, caplog):
    """THE production case: the rich template, broken by an unescaped Windows
    event. The uid is read from the raw text and the alert fetched."""
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)

    body = _broken_rich_body()
    with pytest.raises(ValueError):
        json.loads(body)                    # it really is not JSON
    with caplog.at_level(logging.INFO):
        r = _ring(client, token, body)
    assert r.status_code == 200, r.text
    assert r.json()["ingested"] is True and r.json()["via"] == "api"
    ((event_type, summary, severity, _host, payload, _sha),) = _rows()
    assert (event_type, severity) == ("datto.eventlog", "high")
    assert summary == "Event log · Security 4625 — An account failed to log on"
    assert json.loads(payload) == api_alert(EVENTLOG)
    assert "not valid JSON but names alert" in caplog.text
    assert "ID-only template" in caplog.text
    receipt = _receipt(client)
    assert receipt["accepted_since_start"] == 1 and receipt["rejected_since_start"] == 0


def test_a_malformed_body_without_a_uid_is_the_422_malformed_it_always_was(bell):
    client, transport = bell
    iid, token = _create(client, transport)

    for body in (
        b"{not json",
        b"[1, 2]",
        b'{"event": "alert_raised", "alertContext": {"message": "no id\r\nhere"}',
        b'{"alertUid": "not-a-uuid", "siteUid": "' + SITE.encode() + b'"',    # not a uid
        b'{"deviceUid": "' + UID.encode() + b'", "alertContext": {"m": "x"}',  # wrong key
        b'{"alertUid": "' + UID.encode()[:-1] + b'"',                          # 35 chars
    ):
        r = _ring(client, token, body)
        assert r.status_code == 422, (body, r.text)
        assert r.json()["code"] == "VALIDATION_FAILED"
        assert "names no alertUid" in r.json()["message"]
        assert "ID-only template" in r.json()["message"]
        assert body[:8].decode(errors="replace") not in r.json()["message"]
    assert not [c for c in transport.calls if "/api/v2/alert/" in c[1]]
    assert _rows() == []

    receipt = _receipt(client)
    assert receipt["rejected_recent_by_reason"] == {"malformed": 6}
    (line,) = receipt["recent_rejections"]
    assert "not a JSON object" in line and "named no alert id" in line
    assert "[alert_message]" in line and "ID-only template from the Setup guide" in line


def test_a_uid_that_is_not_a_uuid_is_never_fetched(bell):
    """A parsed body with a hand-typed id is the templated event it always
    was — nothing that is not a UUID is ever put into a request path. Datto's
    own 'Test Webhook' (the template, unsubstituted) keeps its 2xx."""
    client, transport = bell
    iid, token = _create(client, transport)

    r = _ring(client, token, _id_only(uid="a-1"))
    assert r.status_code == 200 and r.json()["via"] == "template", r.text
    assert r.json()["ingested"] is True and r.json()["event_id"] == "a-1"
    literal = json.loads(DattoSourceAdapter().onboarding(_INGEST).steps[3].code_sample)
    r = _ring(client, token, literal)
    assert r.status_code == 200 and r.json()["via"] == "template", r.text
    # No siteUid was substituted and there is no instance default: HELD, not
    # dropped — the same quarantine any unattributable delivery lands in.
    assert r.json()["ingested"] is False and r.json()["reason"] == "quarantined"
    assert r.json()["quarantine_reason"] == "no-tenant-id"
    for uid in ("../account", "%2e%2e/account", UID + "x", "'" + UID, UID.upper() + "0"):
        r = _ring(client, token, _id_only(uid=uid))
        assert r.status_code == 200 and r.json()["via"] == "template", (uid, r.text)
    assert not [c for c in transport.calls if "/api/v2/alert/" in c[1]]
    ((event_type, summary, _sev, host, _payload, _sha),) = _rows()[:1]
    # The fallback row from the ID-only template still agrees on the class.
    assert event_type == "datto.eventlog" and host == "WS-EXAMPLE-01"
    assert summary == "Event Log alert on WS-EXAMPLE-01"


def test_uppercase_hex_in_a_uid_is_still_that_uid(bell):
    """UUIDs are case-insensitive: one spelling on the wire (Datto's own,
    lowercase) and one throttle key per alert."""
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)
    r = _ring(client, token, _id_only(uid=UID.upper()))
    assert r.status_code == 200 and r.json()["via"] == "api", r.text
    assert transport.calls[-1] == ("GET", f"/api/v2/alert/{UID}")
    assert _ring(client, token, _id_only()).json()["idempotent"] is True
    assert _alert_fetches(transport) == 1


# ---------------------------------------------------------------------------
# Fallbacks — the API fetch fails: never a 5xx for Athena's own lookup
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("failure,kind", [
    ("not_found", "not_found"), (403, "forbidden"), (500, "transport"), ("read_timeout", "transport"),
])
def test_when_the_fetch_fails_a_parsed_body_is_stored_as_sent(bell, caplog, failure, kind):
    client, transport = bell
    if failure == 403 or failure == 500:
        transport.alert_fetch_status = failure
    elif failure == "read_timeout":
        transport.alert_fetch_times_out = True
    # "not_found": the fake simply does not know UID
    iid, token = _create(client, transport)

    with caplog.at_level(logging.INFO):
        r = _ring(client, token, _id_only())
    assert r.status_code == 200, r.text
    assert r.json()["ingested"] is True and r.json()["via"] == "template"
    assert _alert_fetches(transport) == 1
    ((event_type, summary, severity, host, payload, _sha),) = _rows()
    assert event_type == "datto.eventlog" and host == "WS-EXAMPLE-01"
    assert summary == "Event Log alert on WS-EXAMPLE-01" and severity == "info"
    assert json.loads(payload) == _id_only()
    assert f"alert {UID} not fetched ({kind})" in caplog.text
    # Accepted — the fallback IS a stored event, not a rejection.
    receipt = _receipt(client)
    assert receipt["accepted_since_start"] == 1 and receipt["rejected_since_start"] == 0

    # The failure is remembered for the window: a retry burst costs no read.
    r = _ring(client, token, _id_only())
    assert r.status_code == 200 and r.json()["via"] == "template"
    assert r.json()["idempotent"] is True
    assert _alert_fetches(transport) == 1
    for secret in SECRETS:
        assert secret not in caplog.text and secret not in r.text
        assert secret not in client.get(_CARD, cookies=client.cookies_).text


@pytest.mark.parametrize("failure", ["not_found", 403, "read_timeout"])
def test_when_the_fetch_fails_a_malformed_body_is_accepted_but_unresolvable(bell, caplog, failure):
    client, transport = bell
    if failure == 403:
        transport.alert_fetch_status = 403
    elif failure == "read_timeout":
        transport.alert_fetch_times_out = True
    iid, token = _create(client, transport)

    with caplog.at_level(logging.INFO):
        r = _ring(client, token, _broken_rich_body())
    assert r.status_code == 200, r.text          # a 2xx: the vendor must not retry
    assert r.json() == {"status": "accepted", "ingested": False, "reason": "unresolvable"}
    assert _rows() == []
    assert "DROPPED doorbell" in caplog.text and "ID-only template" in caplog.text

    receipt = _receipt(client)
    assert receipt["rejected_recent_by_reason"] == {"unresolvable": 1}
    assert receipt["last_reject_reason"] == "unresolvable"
    (line,) = receipt["recent_rejections"]
    assert line.startswith("1 rejected since the service last started: ")
    assert "could not be fetched" in line and "DROPPED" in line
    assert "ID-only template from the Setup guide" in line
    assert "must be running and able to read alerts" in line
    # Vendor text (a 403 body) never reaches the card, nor does a secret.
    text = client.get(_CARD, cookies=client.cookies_).text
    assert FORBIDDEN_TEXT not in text
    for secret in SECRETS:
        assert secret not in text and secret not in caplog.text


def test_the_forbidden_message_is_the_operator_safe_one(bell, caplog):
    client, transport = bell
    transport.alert_fetch_status = 403
    iid, token = _create(client, transport)
    with caplog.at_level(logging.INFO):
        _ring(client, token, _id_only())
    assert f"alert {UID} not fetched (forbidden)" in caplog.text
    assert "HTTP 403" in caplog.text and "security level" in caplog.text


def test_a_slow_vendor_never_holds_the_request_past_the_deadline(bell, caplog, monkeypatch):
    """The client's own read timeout is the first line; this is the second:
    a vendor that answers slowly (not a socket timeout) still gets its 2xx
    within the deadline, and the alert is not asked for again in the window.

    Measured where a server measures it — when the app SENDS the response
    (`http.response.start`): Starlette's TestClient itself only returns to
    the caller once the abandoned worker thread has finished, which a real
    ASGI server does not wait for."""
    from fastapi.testclient import TestClient

    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    transport.alert_fetch_delay_sec = 0.6
    monkeypatch.setattr(doorbell, "FETCH_DEADLINE_SEC", 0.05)
    iid, token = _create(client, transport)

    answered_after: list[float] = []
    app = client.app

    async def timed_app(scope, receive, send):
        started = time.monotonic()

        async def timed_send(message):
            if message["type"] == "http.response.start":
                answered_after.append(time.monotonic() - started)
            await send(message)

        await app(scope, receive, timed_send)

    timed = TestClient(timed_app, base_url="https://athena.test")
    with caplog.at_level(logging.INFO):
        r = timed.post(_HOOK, json=_id_only(), headers={"X-Webhook-Token": token})
    assert r.status_code == 200 and r.json()["via"] == "template", r.text
    (elapsed,) = answered_after
    assert elapsed < 0.4, elapsed
    assert "did not answer within" in caplog.text
    assert doorbell.recent(iid, UID).failure == "timeout"
    r = _ring(client, token, _broken_rich_body())
    assert r.json()["reason"] == "unresolvable"
    assert _alert_fetches(transport) == 1          # the slow one; no second ask


def test_an_instance_that_is_not_running_uses_the_body_as_sent(bell, caplog):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)
    client.app.state.instance_manager.stop_instance(iid)   # e.g. start failed

    with caplog.at_level(logging.INFO):
        r = _ring(client, token, _id_only())
    assert r.status_code == 200 and r.json()["via"] == "template", r.text
    assert "not running in this process" in caplog.text
    assert _alert_fetches(transport) == 0
    assert _ring(client, token, _broken_rich_body()).json()["reason"] == "unresolvable"


# ---------------------------------------------------------------------------
# Resolved doorbells
# ---------------------------------------------------------------------------

def test_a_resolved_doorbell_stores_the_fetched_alert_as_resolved(bell):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)

    assert _ring(client, token, _id_only()).json()["via"] == "api"
    r = _ring(client, token, _id_only(event="alert_resolved"))
    assert r.status_code == 200 and r.json()["via"] == "api", r.text
    assert r.json()["ingested"] is True and r.json()["idempotent"] is False
    raised, resolved = _rows()
    assert raised[1] == "Event log · Security 4625 — An account failed to log on"
    assert resolved[1] == "[resolved] Event log · Security 4625 — An account failed to log on"
    assert resolved[0] == raised[0] == "datto.eventlog"
    # The API's own flag, on the API's own object — no templated fields.
    assert json.loads(resolved[4]) == {**api_alert(EVENTLOG), "resolved": True}
    # Raised then resolved for one alert = ONE fetch (the window covers it).
    assert _alert_fetches(transport) == 1
    # A vendor retry of the resolved bell: nothing new.
    assert _ring(client, token, _id_only(event="alert_resolved")).json()["idempotent"] is True
    assert len(_rows()) == 2


def test_a_resolved_doorbell_from_a_broken_body_is_still_marked_resolved(bell):
    client, transport = bell
    transport.alerts_by_uid[UID] = {**api_alert(EVENTLOG), "resolved": True, "resolvedOn": 1_790_000_100_000}
    iid, token = _create(client, transport)

    r = _ring(client, token, _broken_rich_body(event="alert_resolved"))
    assert r.status_code == 200 and r.json()["via"] == "api", r.text
    ((_type, summary, _sev, _host, payload, _sha),) = _rows()
    assert summary.startswith("[resolved] Event log · Security 4625")
    # The API copy already said so: stored verbatim, nothing stamped on it.
    assert json.loads(payload) == transport.alerts_by_uid[UID]


# ---------------------------------------------------------------------------
# One alert, two doors: the sink collapses the copies
# ---------------------------------------------------------------------------

def _poll_once(client, iid: int) -> None:
    """One drain of the REAL poller of the running instance (its client, its
    mapping sink) — driven by hand, because the test client has no loop
    that outlives a request for the background task to live on."""
    poller = client.app.state.instance_manager.running_adapter(iid)._poller
    asyncio.run(poller._drain_once())


def test_a_doorbell_for_an_alert_the_poller_already_stored_is_idempotent(bell):
    client, transport = bell
    transport.alerts = [api_alert(EVENTLOG)]        # listed as open
    iid, token = _create(client, transport)
    _poll_once(client, iid)
    assert len(_rows()) == 1

    r = _ring(client, token, _id_only())
    assert r.status_code == 200 and r.json()["via"] == "api", r.text
    assert r.json()["ingested"] is True and r.json()["idempotent"] is True
    assert len(_rows()) == 1
    r = _ring(client, token, _broken_rich_body())
    assert r.json()["idempotent"] is True and len(_rows()) == 1
    # And the same alert, fetched by the doorbell, is the same event row the
    # poller wrote — not a second copy in another shape.
    ((event_type, summary, severity, _host, payload, _sha),) = _rows()
    assert (event_type, severity) == ("datto.eventlog", "high")
    assert json.loads(payload) == api_alert(EVENTLOG)


def test_a_poll_after_the_doorbell_stores_nothing_new(bell):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)
    assert _ring(client, token, _id_only()).json()["idempotent"] is False
    assert len(_rows()) == 1

    transport.alerts = [api_alert(EVENTLOG)]        # now listed as open
    polls_before = transport.count(ALERTS_PATH)
    _poll_once(client, iid)
    assert transport.count(ALERTS_PATH) == polls_before + 1
    assert len(_rows()) == 1
    assert _alert_fetches(transport) == 1


# ---------------------------------------------------------------------------
# Bounds: one fetch per uid per minute, an instance budget
# ---------------------------------------------------------------------------

def test_a_burst_of_doorbells_for_one_alert_is_one_fetch(bell):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)

    answers = [_ring(client, token, _id_only()).json() for _ in range(5)]
    answers += [_ring(client, token, _broken_rich_body()).json() for _ in range(3)]
    assert all(a["ingested"] is True and a["via"] == "api" for a in answers)
    assert [a["idempotent"] for a in answers] == [False] + [True] * 7
    assert _alert_fetches(transport) == 1 and len(_rows()) == 1

    # After the window the alert is fetched afresh (a re-raised alert).
    now = [time.monotonic()]
    original = doorbell._monotonic
    doorbell._monotonic = lambda: now[0]
    try:
        now[0] += doorbell.PER_ID_WINDOW_SEC + 1
        assert _ring(client, token, _id_only()).json()["idempotent"] is True
    finally:
        doorbell._monotonic = original
    assert _alert_fetches(transport) == 2


def test_the_instance_budget_bounds_fetches_and_the_rest_fall_back(bell, caplog, monkeypatch):
    client, transport = bell
    for uid in (UID, UID_2, UID_3):
        transport.alerts_by_uid[uid] = api_alert(EVENTLOG, alertUid=uid)
    monkeypatch.setattr(doorbell, "FETCHES_PER_MINUTE", 2)
    iid, token = _create(client, transport)

    with caplog.at_level(logging.INFO):
        first = _ring(client, token, _id_only(uid=UID)).json()
        second = _ring(client, token, _id_only(uid=UID_2)).json()
        third = _ring(client, token, _id_only(uid=UID_3)).json()
        broken = _ring(client, token, _broken_rich_body(uid=UID_3)).json()
    assert (first["via"], second["via"], third["via"]) == ("api", "api", "template")
    assert broken == {"status": "accepted", "ingested": False, "reason": "unresolvable"}
    assert [c for c in transport.calls if "/api/v2/alert/" in c[1]] == [
        ("GET", f"/api/v2/alert/{UID}"), ("GET", f"/api/v2/alert/{UID_2}"),
    ]
    assert "fetch budget (2/min) is spent" in caplog.text
    # Budget exhaustion is NOT remembered per uid: when it frees up, the
    # next ring for that alert fetches.
    now = [time.monotonic()]
    monkeypatch.setattr(doorbell, "_monotonic", lambda: now[0])
    now[0] += 61
    assert _ring(client, token, _id_only(uid=UID_3)).json()["via"] == "api"
    assert transport.calls[-1] == ("GET", f"/api/v2/alert/{UID_3}")
    types = [row[0] for row in _rows()]
    assert types == ["datto.eventlog"] * 4     # the fallback row agrees on the class
    # …but only the fetched ones carry the API's severity.
    assert [row[2] for row in _rows()] == ["high", "high", "info", "high"]


def test_disable_forgets_the_doorbell_memory(bell):
    client, transport = bell
    transport.alerts_by_uid[UID] = api_alert(EVENTLOG)
    iid, token = _create(client, transport)
    _ring(client, token, _id_only())
    assert doorbell.recent(iid, UID) is not None and doorbell.fetches_in_window(iid) == 1
    d = client.post(f"/api/v1/admin/adapters/instances/{iid}/disable",
                    json={"reason": "fixture"}, cookies=client.cookies_)
    assert d.status_code == 200, d.text
    assert doorbell.recent(iid, UID) is None and doorbell.fetches_in_window(iid) == 0


# ---------------------------------------------------------------------------
# Unmapped sites: the fetched object routes by ITS siteUid, through the same
# tenant lifecycle as a polled one (auto-link → auto-create → quarantine) —
# never dropped, never stored under the site the BODY claimed
# ---------------------------------------------------------------------------

def _tenant_card(client) -> dict:
    r = client.get(_CARD, cookies=client.cookies_)
    assert r.status_code == 200, r.text
    return r.json()["instances"]["datto"]


def test_a_fetched_alert_from_an_unmapped_named_site_auto_creates_its_tenant(bell):
    client, transport = bell
    stray = api_alert(EVENTLOG)
    stray["alertSourceInfo"] = {
        **stray["alertSourceInfo"], "siteUid": "site-uid-stray", "siteName": "Stray Site",
    }
    transport.alerts_by_uid[UID] = stray
    iid, token = _create(client, transport)

    # The body claims the mapped site; the API says otherwise — the API wins,
    # and the API's site (unmapped, named) becomes a pending tenant.
    r = _ring(client, token, _id_only())
    assert r.status_code == 200, r.text
    assert r.json() == {
        "status": "accepted", "ingested": True, "tenant": "stray-site", "event_id": UID,
        "idempotent": False, "routing": "auto-created", "via": "api",
    }
    assert _rows("acme") == []                      # not where the body pointed
    ((event_type, _s, severity, _h, _p, _sha),) = _rows("stray-site")
    assert event_type == "datto.eventlog" and severity == "high"   # the API copy
    assert tenant_map.resolve(iid, "site-uid-stray") == "stray-site"
    assert unmapped.snapshot(iid)["dropped"] == 0
    assert quarantine.counts(iid)["held"] == 0

    # Rung again (vendor retry): now mapped, idempotent, nothing new.
    again = _ring(client, token, _id_only()).json()
    assert again["routing"] == "mapped" and again["idempotent"] is True
    assert len(_rows("stray-site")) == 1 and _alert_fetches(transport) == 1

    card = _tenant_card(client)
    assert card["auto_created_pending"] == 1 and card["quarantined"] == 0
    assert card["webhook_receipt"]["accepted_since_start"] == 2
    tenants = client.get("/api/v1/admin/tenants", cookies=client.cookies_).json()["tenants"]
    (t,) = [t for t in tenants if t["slug"] != "acme"]
    assert t["slug"] == "stray-site" and t["origin"] == "auto"
    assert t["review_state"] == "pending"
    assert t["created_by_instance"]["instance_id"] == iid


def test_a_fetched_alert_from_an_unmapped_nameless_site_is_held_not_dropped(bell):
    client, transport = bell
    stray = api_alert(EVENTLOG)
    stray["alertSourceInfo"] = {
        k: v for k, v in {**stray["alertSourceInfo"], "siteUid": "site-uid-stray"}.items()
        if k != "siteName"
    }
    transport.alerts_by_uid[UID] = stray
    iid, token = _create(client, transport)

    r = _ring(client, token, _id_only())
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "accepted", "ingested": False, "reason": "quarantined",
                        "quarantine_reason": "name-unknown", "via": "api"}
    assert _rows("acme") == []
    assert unmapped.snapshot(iid)["dropped"] == 0       # held, not dropped
    (held,), total = quarantine.list_rows(instance_id=iid)
    assert total == 1 and held.source == "webhook"
    assert held.vendor_tenant_id == "site-uid-stray" and held.reason == "name-unknown"
    # Held = received and stored; the card's quarantine line counts it, once.
    assert _receipt(client)["rejected_recent_by_reason"] == {}
    assert _receipt(client)["accepted_since_start"] == 1
    card = _tenant_card(client)
    assert card["quarantined"] == 1 and card["auto_created_pending"] == 0
    tenants = client.get("/api/v1/admin/tenants", cookies=client.cookies_).json()["tenants"]
    assert [t["slug"] for t in tenants] == ["acme"]      # nothing was created
