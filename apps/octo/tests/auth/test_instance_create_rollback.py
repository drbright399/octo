"""Create must never strand an instance, and a 422 must never echo a body.

1. A failure AFTER the row is inserted (audit DB locked, an unexpected error
   starting the poller, a response that cannot be built) used to leave an
   ACTIVE instance whose generated webhook token nobody ever saw — and a vendor
   slot that answered the retry with 409. Now the row is switched off again and
   the operator gets a clean "try again" error.
2. The global RequestValidationError handler no longer returns pydantic's
   `input` / `ctx`: for a missing key `input` is the WHOLE body, so a malformed
   create bounced operator-typed secrets straight back.
"""
from __future__ import annotations

import logging
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.api.routers import adapters as adapters_router
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    _StubDatto,
    _register_stub_datto,
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"
_GENERATE = {"credentials": {"DATTO_API_KEY": "k"}, "enable_webhook": True}


def _admin(client) -> dict:
    _register_stub_datto(client)
    return client.login(client.provision_operator("admin1", "password1234567"))


def _rows() -> list[sqlite3.Row]:
    reg = sqlite3.connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        return reg.execute(
            "SELECT id, status, disabled_at, disabled_reason FROM adapter_instances"
        ).fetchall()
    finally:
        reg.close()


def _spy_on_tokens(monkeypatch) -> list[str]:
    from apps.octo.instances import webhook_auth

    minted: list[str] = []
    real = webhook_auth.generate_token
    monkeypatch.setattr(
        webhook_auth, "generate_token", lambda: minted.append(real()) or minted[-1],
    )
    return minted


def _break_audit(monkeypatch):
    def _locked(**_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(adapters_router, "_audit_instance_create", _locked)


def _break_start(monkeypatch, client):
    def _boom(record):
        raise RuntimeError("poller thread could not be created")

    monkeypatch.setattr(client.app.state.instance_manager, "start_instance", _boom)


def _break_response(monkeypatch, client):
    """The LAST step before the response exists — and an error whose text
    carries the token, like a pydantic validation error would."""
    def _boom(rec, *, vendor_display_name):
        from apps.octo import credentials
        raise ValueError(f"cannot serialise {credentials.load(rec.cred_ref)!r}")

    monkeypatch.setattr(adapters_router, "_instance_to_out", _boom)


@pytest.mark.parametrize("breaker", ["audit", "start", "response"])
def test_failure_after_insert_frees_the_vendor_slot_and_says_try_again(
    instance_endpoint_client, monkeypatch, caplog, breaker,
):
    client = instance_endpoint_client
    cookies = _admin(client)
    minted = _spy_on_tokens(monkeypatch)
    stopped: list[int] = []
    real_stop = client.app.state.instance_manager.stop_instance
    monkeypatch.setattr(
        client.app.state.instance_manager, "stop_instance",
        lambda iid: stopped.append(iid) or real_stop(iid),
    )

    with monkeypatch.context() as broken:
        if breaker == "audit":
            _break_audit(broken)
        elif breaker == "start":
            _break_start(broken, client)
        else:
            _break_response(broken, client)
        with caplog.at_level(logging.DEBUG):
            r = client.post(_CREATE, json=_GENERATE, cookies=cookies)

    # A clean, structured error — not a bare 500 — that says what to do.
    assert r.status_code == 500, r.text
    body = r.json()
    assert body["code"] == "INSTANCE_CREATE_INCOMPLETE"
    assert "try again" in body["message"].lower()
    assert "Stub Datto" in body["message"]

    # The token WAS minted (the row was written) and is nowhere to be seen.
    (token,) = minted
    assert token not in r.text and token not in caplog.text
    assert "generated_webhook_secret" not in r.text

    # The row is switched off: poller stopped, slot free, reason recorded.
    (row,) = _rows()
    assert row["status"] == "disabled" and row["disabled_at"] is not None
    assert "rolled back" in row["disabled_reason"]
    assert stopped == [row["id"]]
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed == {"instances": []}
    # …and the dead token no longer authenticates the public receiver.
    dead = client.post(
        "/api/v1/webhooks/datto", json={"alertUid": "a-1"},
        headers={"X-Webhook-Token": token},
    )
    assert dead.status_code == 401

    # "Try again" works — no 409 — and yields a fresh token, shown once.
    again = client.post(_CREATE, json=_GENERATE, cookies=cookies)
    assert again.status_code == 200, again.text
    fresh = again.json()["generated_webhook_secret"]["header_value"]
    assert fresh and fresh != token


def test_rollback_is_audited_without_credentials(instance_endpoint_client, monkeypatch):
    client = instance_endpoint_client
    cookies = _admin(client)
    minted = _spy_on_tokens(monkeypatch)
    with monkeypatch.context() as broken:
        _break_start(broken, client)
        r = client.post(_CREATE, json=_GENERATE, cookies=cookies)
    assert r.status_code == 500, r.text

    audit_db = sqlite3.connect(paths.global_audit_db_path())
    try:
        rows = audit_db.execute("SELECT * FROM audit_log ORDER BY rowid").fetchall()
    finally:
        audit_db.close()
    text = repr(rows)
    assert "adapter_instance_create" in text and "adapter_instance_disable" in text
    assert "rolled back automatically" in text
    assert minted[0] not in text


def test_rollback_that_cannot_disable_names_the_manual_path(
    instance_endpoint_client, monkeypatch,
):
    from apps.octo.instances import manager as manager_module

    client = instance_endpoint_client
    cookies = _admin(client)

    def _locked(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    with monkeypatch.context() as broken:
        _break_start(broken, client)
        broken.setattr(manager_module, "disable_instance", _locked)
        r = client.post(_CREATE, json=_GENERATE, cookies=cookies)
    assert r.status_code == 500, r.text
    message = r.json()["message"]
    assert r.json()["code"] == "INSTANCE_CREATE_INCOMPLETE"
    assert "could not be switched off automatically" in message
    assert "Settings → Integrations → Stub Datto → Disable, then Add integration again" in message


def test_duplicate_instance_message_names_the_exact_recovery_path(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    assert client.post(_CREATE, json=_GENERATE, cookies=cookies).status_code == 200
    r = client.post(_CREATE, json=_GENERATE, cookies=cookies)
    assert r.status_code == 409 and r.json()["code"] == "INSTANCE_ALREADY_EXISTS"
    message = r.json()["message"]
    assert "Settings → Integrations → Stub Datto → Disable, then Add integration again" in message
    assert "/api/v1/" not in message


# ---------------------------------------------------------------------------
# 422 bodies never echo the request
# ---------------------------------------------------------------------------

_SECRET = "fixture-secret-value-" + "9f8e7d6c5b4a" * 3


@pytest.mark.parametrize("payload", [
    # `credentials` is the wrong type → pydantic's `input` is the value itself.
    {"credentials": [{"DATTO_WEBHOOK_SECRET": _SECRET}]},
    # Wrong type one level down → `input` is the secret-bearing string.
    {"credentials": {"DATTO_API_KEY": "k"}, "enable_webhook": _SECRET},
    {"credentials": {}, "display_name": {"DATTO_API_SECRET_KEY": _SECRET}},
])
def test_malformed_body_is_not_echoed_in_the_422(instance_endpoint_client, payload):
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(_CREATE, json=payload, cookies=cookies)
    assert r.status_code == 422, r.text
    assert _SECRET not in r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["code"] == "VALIDATION_FAILED"
    # Still useful: where, what kind, and the human sentence — nothing else.
    assert body["errors"]
    for err in body["errors"]:
        assert set(err) <= {"type", "loc", "msg"}
        assert err["loc"][0] == "body" and err["msg"]
    assert client.get(
        "/api/v1/admin/adapters/instances", cookies=cookies,
    ).json() == {"instances": []}


def test_missing_required_key_does_not_return_the_whole_body(instance_endpoint_client):
    """For a MISSING key pydantic reports the enclosing object as `input` —
    on the disable route that is the entire body."""
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(
        "/api/v1/admin/adapters/instances/1/disable",
        json={"note": f"rotating, old value was {_SECRET}"},
        cookies=cookies,
    )
    assert r.status_code == 422, r.text
    assert _SECRET not in r.text and "input" not in r.text
    assert r.json()["errors"][0]["loc"] == ["body", "reason"]
