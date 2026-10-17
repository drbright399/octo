"""Datto RMM through the real HTTP routes with the REAL adapter and client
(only the vendor socket is fake — see adapters/datto/tests/fake_datto.py).

The production defect: Datto issues a token to an API user whose security
level grants nothing, then answers every data endpoint 403. The wizard saved
that key as "connected".

  - test-connection reports it, with a message the operator can act on
  - create REFUSES it: no row, nothing vaulted, NO webhook token minted or
    shown, vendor slot left free so the retry after the fix just works
  - a create that passes is born with `last_test_at`
  - poller-observed state reaches the Integrations payload
  - no credential, token or key in any response or log line
"""
from __future__ import annotations

import logging
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FORBIDDEN_QUOTED,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
)
from apps.octo.instances import vendor_contact
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

_SMOKE = "/api/v1/admin/adapters/datto/smoke-test"
_CREATE = "/api/v1/admin/adapters/datto/instances"


@pytest.fixture
def datto(instance_endpoint_client):  # noqa: F811
    """(client, cookies, transport) with the real Datto adapter registered."""
    vendor_contact.reset()
    client = instance_endpoint_client
    transport = FakeDattoTransport()
    client.app.state.adapter_registry.register_adapter_class(
        datto_adapter_class(transport)
    )
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    yield client, cookies, transport
    manager = client.app.state.instance_manager
    manager.stop_all_running()
    vendor_contact.reset()


def _rows() -> list[tuple]:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        return reg.execute(
            "SELECT id, status, last_test_at FROM adapter_instances"
        ).fetchall()
    finally:
        reg.close()


def _assert_no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

def test_test_connection_reports_authenticated_but_forbidden(datto, caplog):
    client, cookies, transport = datto
    transport.forbid_data = True
    with caplog.at_level(logging.DEBUG):
        r = client.post(_SMOKE, json={"credentials": CREDS}, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is False
    assert body["message"].startswith("Datto accepted the API key, but this API user")
    assert "(HTTP 403)" in body["message"] and body["message"].endswith(FORBIDDEN_QUOTED)
    assert "Setup > Users" in body["message"] and "API Security Level" in body["message"]
    _assert_no_secret(r.text, caplog.text)
    assert _rows() == []          # a test never persists anything


def test_test_connection_passes_only_after_real_reads(datto):
    client, cookies, transport = datto
    r = client.post(_SMOKE, json={"credentials": CREDS}, cookies=cookies)
    assert r.json()["ok"] is True
    assert transport.count("/api/v2/account") == 1
    assert transport.count("/api/v2/account/sites") == 1
    assert transport.count("/api/v2/account/alerts/open") == 1


# ---------------------------------------------------------------------------
# Create — refused, and nothing is left half-done
# ---------------------------------------------------------------------------

def test_create_with_a_forbidden_key_is_refused_and_mints_no_webhook_token(
    datto, caplog, monkeypatch,
):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    client, cookies, transport = datto
    transport.forbid_data = True

    minted: list[str] = []
    from apps.octo.instances import webhook_auth
    real_generate = webhook_auth.generate_token
    monkeypatch.setattr(
        webhook_auth, "generate_token",
        lambda: minted.append("x") or real_generate(),
    )

    with caplog.at_level(logging.DEBUG):
        r = client.post(
            _CREATE,
            json={"credentials": {**CREDS, "DATTO_WEBHOOK_SECRET": ""}, "enable_webhook": True},
            cookies=cookies,
        )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["code"] == "SMOKE_TEST_FAILED"
    # The adapter's message stands alone: "rejected the credentials: Datto
    # accepted the API key…" contradicted itself and sent operators off to
    # regenerate a key pair that was fine. Same text as Test connection.
    assert body["message"].startswith("Not saved — Datto accepted the API key, but")
    assert "rejected the credentials" not in body["message"]
    assert "smoke test" not in body["message"].lower()
    assert "Setup > Users" in body["message"]
    assert "do not regenerate" in body["message"]
    # No orphaned one-time secret: none generated, none in the response.
    assert minted == []
    assert "generated_webhook_secret" not in body
    assert "header_value" not in r.text
    # No instance, healthy or otherwise; the vendor slot is free.
    assert _rows() == []
    listed = client.get("/api/v1/integrations", cookies=cookies).json()
    assert listed["instances"] == {}
    _assert_no_secret(r.text, caplog.text)

    # The operator fixes the security level in Datto RMM and saves again.
    transport.forbid_data = False
    again = client.post(
        _CREATE,
        json={"credentials": {**CREDS, "DATTO_WEBHOOK_SECRET": ""}, "enable_webhook": True},
        cookies=cookies,
    )
    assert again.status_code == 200, again.text
    assert again.json()["generated_webhook_secret"]["header_value"]
    assert len(minted) == 1


def test_create_with_rejected_credentials_is_refused(datto):
    client, cookies, transport = datto
    transport.token_status = 401
    r = client.post(_CREATE, json={"credentials": CREDS}, cookies=cookies)
    assert r.status_code == 400
    assert r.json()["code"] == "SMOKE_TEST_FAILED"
    assert "rejected credentials" in r.json()["message"]
    assert _rows() == []
    _assert_no_secret(r.text)


# ---------------------------------------------------------------------------
# Create — passes → last_test_at; observed health reaches the payload
# ---------------------------------------------------------------------------

def test_successful_create_is_born_with_last_test_at(datto):
    client, cookies, _transport = datto
    r = client.post(_CREATE, json={"credentials": CREDS}, cookies=cookies)
    assert r.status_code == 200, r.text
    instance = r.json()["instance"]
    assert instance["status"] == "running"
    assert instance["last_test_at"]
    assert "can read the account" in r.json()["smoke_test_message"]

    (row,) = _rows()
    assert row[2] == instance["last_test_at"]
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["last_test_at"] == instance["last_test_at"]
    _assert_no_secret(r.text)


def test_observed_failure_and_last_good_contact_reach_both_payloads(datto):
    """What the poller wrote (see test_poller_status) is what the card gets."""
    from apps.octo.instances.manager import set_contact_status

    client, cookies, _transport = datto
    # Webhooks ON with a platform-generated token: "receives webhooks" is only
    # ever true for an instance that can verify one (test_webhook_reachability
    # covers the instance saved without a secret).
    iid = client.post(
        _CREATE, json={"credentials": CREDS, "enable_webhook": True}, cookies=cookies,
    ).json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()

    reporter = vendor_contact.ContactReporter(iid, what="fixture")
    reporter.ok()
    good_at = vendor_contact.snapshot(iid)["last_ok_at"]
    reporter.failed("forbidden", "Datto accepted the API key but — fixture detail")

    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["status"] == "error"
    assert card["status_detail"] == "Datto accepted the API key but — fixture detail"
    assert card["last_contact_ok_at"] == good_at
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()["instances"][0]
    assert listed["status"] == "error" and listed["last_contact_ok_at"] == good_at
    # WHY it is in error reaches the card (it words the headline by it), and
    # so does the fact that inbound webhooks are a separate path that CAN
    # deliver (a usable token is stored).
    assert card["contact_failure_kind"] == listed["contact_failure_kind"] == "forbidden"
    assert card["receives_webhooks"] is listed["receives_webhooks"] is True
    # The analyst dashboard agrees: not 'ok' — and analysts get a FIXED
    # sentence, never the admin detail (it can quote the vendor's own text).
    health = client.get("/api/v1/dashboard/integrations", cookies=cookies).json()["items"]
    (row,) = [h for h in health if h["slug"] == "datto"]
    assert row["health"] == "down"
    assert row["detail"] == vendor_contact.analyst_summary(iid)
    assert "refuses access" in row["detail"] and "fixture detail" not in row["detail"]

    # Disable forgets the in-memory contact state with the instance.
    d = client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "fixture: replace"}, cookies=cookies,
    )
    assert d.status_code == 200, d.text
    assert vendor_contact.snapshot(iid)["last_ok_at"] is None
    assert set_contact_status(iid, status="running", status_detail="late") is False
