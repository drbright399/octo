"""Adapter instance-create endpoint — POST /admin/adapters/{slug}/instances.

Covers:
  - Happy path: smoke_test passes → cred persisted → manager starts adapter
    → response carries status=running and the smoke message
  - Smoke-test failure prevents persistence (no row, no cred_ref, no audit)
  - Unknown vendor → 404 ADAPTER_NOT_FOUND
  - Duplicate active instance → 409-style INSTANCE_ALREADY_EXISTS
  - Audit row is written without leaking credentials
  - Admin tier gate (analyst rejected)
  - GET /instances surfaces persisted rows with vendor_display_name
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

import pyotp
import pytest
from cryptography.fernet import Fernet

from apps.octo import paths


# ---------------------------------------------------------------------------
# Stub adapter the endpoint tests exercise. Same shape we used in the
# instance-manager tests; the smoke_test() result is parameterizable per-test
# via class attributes.
# ---------------------------------------------------------------------------

class _StubResult:
    def __init__(self, ok: bool, message: str) -> None:
        self.ok = ok
        self.message = message


class _StubAdapter:
    vendor_slug = "stub-adapter"
    vendor_display_name = "Stub Adapter"
    vendor_logo_path = ""
    vendor_category = "other"
    auth_model = "api-key"
    delivery_mode = "poll"
    availability = "available"
    compliance_categories: list[str] = []
    contract_version = "1.0.0"

    # Per-class knobs the tests flip
    smoke_ok = True
    smoke_message = "ok"
    starts = 0
    stops = 0

    def __init__(self) -> None:
        pass

    def credential_shape(self) -> list:
        return []

    def tenant_mapping_shape(self) -> None:
        return None

    def smoke_test(self, credentials: dict[str, Any]) -> _StubResult:
        return _StubResult(type(self).smoke_ok, type(self).smoke_message)

    def start(self, instance_config: dict[str, Any]) -> None:
        type(self).starts += 1
        type(self).last_start_config = dict(instance_config)

    def stop(self) -> None:
        type(self).stops += 1


def _reset_stub() -> None:
    _StubAdapter.smoke_ok = True
    _StubAdapter.smoke_message = "ok"
    _StubAdapter.starts = 0
    _StubAdapter.stops = 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def instance_endpoint_client(monkeypatch, tmp_path):
    """Auth client + an isolated bedrock layer:
      - tmp data root with registry.db at user_version 7
      - tmp adapter-credentials-key.env
      - AdapterRegistry seeded with the stub adapter
      - InstanceManager bound to that registry
    """
    from fastapi.testclient import TestClient
    from apps.octo.auth import bootstrap
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.framework.registry import (
        AdapterRegistry,
        InMemoryRegistryBackend,
    )
    from apps.octo.instances import InstanceManager

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    pepper_file = secrets_dir / "pepper.env"
    pepper_file.write_text(
        "PEPPER_VERSION=pepper_v1\n"
        "PEPPER_HEX=" + "ab" * 32 + "\n"
    )
    os.chmod(pepper_file, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper_file))

    mfa_file = secrets_dir / "mfa-key.env"
    mfa_file.write_text(
        "MFA_KEY_VERSION=v1\n"
        f"MFA_KEY_BASE64={Fernet.generate_key().decode()}\n"
    )
    os.chmod(mfa_file, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa_file))

    cred_key_file = secrets_dir / "adapter-credentials-key.env"
    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(cred_key_file))

    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")

    from apps.octo.credentials import ensure_key_file
    ensure_key_file()
    bootstrap.init_data_root()

    _reset_stub()

    reset_limiter()
    app = create_app()
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(_StubAdapter)
    app.state.adapter_registry = registry
    app.state.instance_manager = InstanceManager(adapter_registry=registry)

    client = TestClient(app, base_url="https://athena.test")

    # provision_operator + login helpers (copied from conftest pattern)
    def provision_operator(username: str, password: str, *, athena_role: str = "admin"):
        import json
        from apps.octo.auth import core as core_auth, crypto, operators
        from apps.octo.db import connect, transaction
        # create_operator inserts ONE row in operator_roles using `role` arg.
        # Pass athena_role for both so the tier check sees only the intended role.
        op = operators.create_operator(
            username=username,
            email=f"{username}@example.test",
            role=athena_role,
            scope_slugs=["*"],
            actor="system",
            reason="instance endpoint fixture",
        )
        pw_hash = core_auth.hash_token(password)
        totp_secret = pyotp.random_base32()
        totp_secret_enc = crypto.encrypt_at_rest(totp_secret.encode())
        op_id = op["operator_id"]
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    "UPDATE operators SET password_hash = ?, mfa_enabled = 1, "
                    "mfa_secret_enc = ? WHERE id = ?",
                    (pw_hash, totp_secret_enc, op_id),
                )
        finally:
            reg.close()
        return {
            "id": op_id, "username": username, "password": password,
            "totp_secret_b32": totp_secret,
        }

    def login(op):
        r = client.post("/api/v1/auth/password/begin", json={
            "username": op["username"], "password": op["password"],
        })
        challenge = r.json()["challenge_id"]
        code = pyotp.TOTP(op["totp_secret_b32"]).now()
        r2 = client.post("/api/v1/auth/password/totp", json={
            "challenge_id": challenge, "totp_code": code,
        })
        assert r2.status_code == 200, r2.text
        return dict(r2.cookies)

    client.provision_operator = provision_operator
    client.login = login
    yield client


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_create_instance_persists_and_starts_adapter(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)

    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={
            "credentials": {"API_KEY": "sample-fixture-key"},
            "instance_config": {"poll_interval_sec": 30},
            "default_tenant_slug": "_unmapped",
        },
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["instance"]["vendor_slug"] == "stub-adapter"
    assert body["instance"]["vendor_display_name"] == "Stub Adapter"
    assert body["instance"]["status"] == "running"
    assert _StubAdapter.starts == 1
    # smoke message echoed for the UI's success toast
    assert body["smoke_test_message"] == "ok"


def test_create_never_carries_the_psa_writes_switch(instance_endpoint_client):
    """Slice 0: an instance is always born with PSA writes OFF. The switch is
    server-owned (super_admin + step-up, audited — admin_psa.py): a create
    body cannot set it, neither in instance_config nor smuggled into the
    credential blob (which would win the start-config merge)."""
    import json

    from apps.octo import credentials

    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={
            "credentials": {"API_KEY": "sample-fixture-key", "writes_enabled": True},
            "instance_config": {"poll_interval_sec": 30, "writes_enabled": True},
        },
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        cfg_json, cred_ref = reg.execute(
            "SELECT instance_config_json, cred_ref FROM adapter_instances",
        ).fetchone()
    finally:
        reg.close()
    assert json.loads(cfg_json) == {"poll_interval_sec": 30}
    assert "writes_enabled" not in credentials.load(cred_ref)
    assert "writes_enabled" not in _StubAdapter.last_start_config


# ---------------------------------------------------------------------------
# Smoke-test failure path
# ---------------------------------------------------------------------------

def test_smoke_test_failure_prevents_persistence(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)

    _StubAdapter.smoke_ok = False
    _StubAdapter.smoke_message = "bad-creds-message"

    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"API_KEY": "wrong"}},
        cookies=cookies,
    )
    assert r.status_code == 400, r.text
    assert r.json()["code"] == "SMOKE_TEST_FAILED"
    assert "bad-creds-message" in r.json()["message"]

    # Nothing persisted
    reg = sqlite3.connect(paths.registry_db_path())
    count = reg.execute("SELECT COUNT(*) FROM adapter_instances").fetchone()[0]
    reg.close()
    assert count == 0
    # Adapter.start() never called
    assert _StubAdapter.starts == 0


# ---------------------------------------------------------------------------
# Unknown vendor
# ---------------------------------------------------------------------------

def test_unknown_vendor_returns_404(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    r = client.post(
        "/api/v1/admin/adapters/no-such-vendor/instances",
        json={"credentials": {}},
        cookies=cookies,
    )
    assert r.status_code == 404
    assert r.json()["code"] == "ADAPTER_NOT_FOUND"


# ---------------------------------------------------------------------------
# Duplicate active instance
# ---------------------------------------------------------------------------

def test_duplicate_active_instance_is_rejected(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)

    r1 = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r1.status_code == 200

    r2 = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v2"}},
        cookies=cookies,
    )
    assert r2.status_code == 409, r2.text
    assert r2.json()["code"] == "INSTANCE_ALREADY_EXISTS"


# ---------------------------------------------------------------------------
# Audit row hygiene
# ---------------------------------------------------------------------------

def test_audit_row_does_not_leak_credentials(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    secret_marker = "PLEASE-DO-NOT-LEAK-INTO-AUDIT"
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"API_KEY": secret_marker}},
        cookies=cookies,
    )
    assert r.status_code == 200

    conn = sqlite3.connect(paths.global_audit_db_path())
    rows = conn.execute(
        "SELECT action, target_id, after_state "
        "FROM audit_log WHERE action = 'adapter_instance_create' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    action, target_id, after_state = rows[0]
    assert action == "adapter_instance_create"
    assert secret_marker not in (after_state or "")
    assert "API_KEY" not in (after_state or "")


# ---------------------------------------------------------------------------
# Admin tier gate
# ---------------------------------------------------------------------------

def test_analyst_cannot_create_instance(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("anlst1", "password1234567", athena_role="analyst")
    cookies = client.login(op)
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Read-back / list endpoint
# ---------------------------------------------------------------------------

def test_list_instances_returns_persisted_rows_with_display_name(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    r = client.get("/api/v1/admin/adapters/instances", cookies=cookies)
    assert r.status_code == 200
    body = r.json()
    assert len(body["instances"]) == 1
    inst = body["instances"][0]
    assert inst["vendor_slug"] == "stub-adapter"
    assert inst["vendor_display_name"] == "Stub Adapter"
    assert inst["status"] == "running"


def test_list_instances_empty_when_nothing_persisted(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    r = client.get("/api/v1/admin/adapters/instances", cookies=cookies)
    assert r.status_code == 200
    assert r.json() == {"instances": []}


def test_list_instances_requires_admin(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("anlst1", "password1234567", athena_role="analyst")
    cookies = client.login(op)
    r = client.get("/api/v1/admin/adapters/instances", cookies=cookies)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Webhook secret not set → the operator is told (receiver fails closed)
# ---------------------------------------------------------------------------

class _StubDatto(_StubAdapter):
    """Stub registered under the real `datto` slug — the slug is what ties an
    instance to a webhook route, so that's all the warning logic keys on."""
    vendor_slug = "datto"
    vendor_display_name = "Stub Datto"
    delivery_mode = "hybrid"


def _register_stub_datto(client) -> None:
    client.app.state.adapter_registry.register_adapter_class(_StubDatto)


def test_create_without_webhook_secret_warns_everywhere(instance_endpoint_client):
    client = instance_endpoint_client
    _register_stub_datto(client)
    cookies = client.login(client.provision_operator("admin1", "password1234567"))

    r = client.post(
        "/api/v1/admin/adapters/datto/instances",
        json={"credentials": {"DATTO_API_KEY": "k", "DATTO_WEBHOOK_SECRET": "  "}},
        cookies=cookies,
    )
    # Still created — polling works without the webhook — but never silently.
    assert r.status_code == 200, r.text
    warnings = r.json()["instance"]["warnings"]
    assert len(warnings) == 1
    assert "Webhook Token" in warnings[0] and "rejected" in warnings[0]
    assert "DATTO_WEBHOOK_SECRET" not in warnings[0]

    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed["instances"][0]["warnings"] == warnings

    agg = client.get("/api/v1/integrations", cookies=cookies).json()
    assert agg["instances"]["datto"]["warnings"] == warnings


def test_create_with_webhook_secret_has_no_warning(instance_endpoint_client, monkeypatch):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    client = instance_endpoint_client
    _register_stub_datto(client)
    cookies = client.login(client.provision_operator("admin1", "password1234567"))

    token = "sample-fixture-token-" + "0123456789ab"  # 32 chars: meets the floor
    r = client.post(
        "/api/v1/admin/adapters/datto/instances",
        json={"credentials": {"DATTO_API_KEY": "k", "DATTO_WEBHOOK_SECRET": token}},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.json()["instance"]["warnings"] == []
    # The secret value itself never appears in any read-back surface.
    assert token not in r.text
    agg = client.get("/api/v1/integrations", cookies=cookies)
    assert agg.json()["instances"]["datto"]["warnings"] == []
    assert token not in agg.text


def test_create_refuses_a_short_webhook_token(instance_endpoint_client):
    """It guards a public endpoint and can't be edited later — refuse it now,
    before anything is persisted, and never echo it back."""
    client = instance_endpoint_client
    _register_stub_datto(client)
    cookies = client.login(client.provision_operator("admin1", "password1234567"))

    r = client.post(
        "/api/v1/admin/adapters/datto/instances",
        json={"credentials": {"DATTO_API_KEY": "k", "DATTO_WEBHOOK_SECRET": "weak-token-31"}},
        cookies=cookies,
    )
    assert r.status_code == 422, r.text
    assert "Webhook Token is too short" in r.text and "at least 32" in r.text
    assert "weak-token-31" not in r.text
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed == {"instances": []}


def test_create_refuses_an_unusable_svix_secret(instance_endpoint_client):
    class _StubResend(_StubAdapter):
        vendor_slug = "resend"
        vendor_display_name = "Stub Resend"
        delivery_mode = "push"

    client = instance_endpoint_client
    client.app.state.adapter_registry.register_adapter_class(_StubResend)
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    r = client.post(
        "/api/v1/admin/adapters/resend/instances",
        json={"credentials": {"RESEND_WEBHOOK_SECRET": "whsec_"}},
        cookies=cookies,
    )
    assert r.status_code == 422, r.text
    assert "Webhook Signing Secret is set but unusable" in r.text


def test_vendor_without_webhook_route_never_warns(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.json()["instance"]["warnings"] == []


# ---------------------------------------------------------------------------
# Disable — the supported way to replace an integration
# ---------------------------------------------------------------------------

_DISABLE = "/api/v1/admin/adapters/instances/{id}/disable"


def _create_stub(client, cookies, creds=None) -> dict:
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": creds or {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    return r.json()["instance"]


def test_create_disable_create_again_works(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    first = _create_stub(client, cookies)
    assert client.app.state.instance_manager.is_running(first["id"])

    r = client.post(_DISABLE.format(id=first["id"]),
                    json={"reason": "webhook secret was left blank"}, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "disabled" and body["disabled_at"]
    assert body["already_disabled"] is False
    # Poller stopped, row out of the active list, vendor slot free.
    assert _StubAdapter.stops == 1
    assert not client.app.state.instance_manager.is_running(first["id"])
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed == {"instances": []}

    second = _create_stub(client, cookies, {"k": "corrected"})
    assert second["id"] != first["id"] and second["status"] == "running"


def test_disable_is_idempotent_and_unknown_id_is_404(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    inst = _create_stub(client, cookies)
    url = _DISABLE.format(id=inst["id"])

    assert client.post(url, json={"reason": "first"}, cookies=cookies).status_code == 200
    again = client.post(url, json={"reason": "second"}, cookies=cookies)
    assert again.status_code == 200 and again.json()["already_disabled"] is True
    assert _StubAdapter.stops == 1

    conn = sqlite3.connect(paths.global_audit_db_path())
    n = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'adapter_instance_disable'"
    ).fetchone()[0]
    conn.close()
    assert n == 1  # the no-op did not write a second row

    missing = client.post(_DISABLE.format(id=99999), json={"reason": "nope"}, cookies=cookies)
    assert missing.status_code == 404


def test_disable_requires_a_reason(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    inst = _create_stub(client, cookies)
    r = client.post(_DISABLE.format(id=inst["id"]), json={}, cookies=cookies)
    assert r.status_code == 422
    assert client.app.state.instance_manager.is_running(inst["id"])


@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_below_admin_cannot_disable_instance(instance_endpoint_client, role):
    client = instance_endpoint_client
    admin = client.login(client.provision_operator("admin1", "password1234567"))
    inst = _create_stub(client, admin)

    client.cookies.clear()
    low = client.login(client.provision_operator("lowtier1", "password1234567", athena_role=role))
    r = client.post(_DISABLE.format(id=inst["id"]), json={"reason": "should not work"}, cookies=low)
    assert r.status_code == 403
    assert client.app.state.instance_manager.is_running(inst["id"])
    assert _StubAdapter.stops == 0


def test_disable_writes_audit_row_without_credentials(instance_endpoint_client):
    client = instance_endpoint_client
    op = client.provision_operator("admin1", "password1234567")
    cookies = client.login(op)
    secret_marker = "PLEASE-DO-NOT-LEAK-INTO-AUDIT"
    inst = _create_stub(client, cookies, {"API_KEY": secret_marker})

    r = client.post(_DISABLE.format(id=inst["id"]),
                    json={"reason": "rotating the vendor API key"}, cookies=cookies)
    assert r.status_code == 200
    assert secret_marker not in r.text

    conn = sqlite3.connect(paths.global_audit_db_path())
    row = conn.execute(
        "SELECT actor, target_kind, target_id, before_state, after_state, reason "
        "FROM audit_log WHERE action = 'adapter_instance_disable'"
    ).fetchone()
    conn.close()
    assert row is not None
    actor, target_kind, target_id, before, after, reason = row
    assert actor == str(op["id"]) and target_kind == "adapter_instance"
    assert target_id == str(inst["id"])
    assert '"status":"running"' in before and '"status":"disabled"' in after
    assert reason == "rotating the vendor API key"
    assert secret_marker not in (before + after + reason)

    # The row records who/why as well.
    reg = sqlite3.connect(paths.registry_db_path())
    disabled_by, disabled_reason = reg.execute(
        "SELECT disabled_by_operator_id, disabled_reason FROM adapter_instances WHERE id = ?",
        (inst["id"],),
    ).fetchone()
    reg.close()
    assert disabled_by == op["id"] and disabled_reason == "rotating the vendor API key"


def test_disable_never_decrypts_credentials(instance_endpoint_client, monkeypatch):
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    inst = _create_stub(client, cookies)

    from apps.octo import credentials

    def _boom(ref):
        raise AssertionError("disable must not decrypt stored credentials")

    monkeypatch.setattr(credentials, "load", _boom)
    r = client.post(_DISABLE.format(id=inst["id"]), json={"reason": "no read-back"}, cookies=cookies)
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Dropped-unmapped events are visible on the health payload
# ---------------------------------------------------------------------------

def test_integrations_payload_surfaces_dropped_unmapped_events(instance_endpoint_client):
    from apps.octo.instances import unmapped

    unmapped.reset()
    client = instance_endpoint_client
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    created = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    ).json()["instance"]

    clean = client.get("/api/v1/integrations", cookies=cookies).json()
    assert clean["instances"]["stub-adapter"]["unmapped_dropped"] == 0

    unmapped.record_drop(created["id"], "site-not-mapped")
    unmapped.record_drop(created["id"], "site-not-mapped")

    inst = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["stub-adapter"]
    assert inst["unmapped_dropped"] == 2
    assert inst["unmapped_vendor_tenant_ids"] == ["site-not-mapped"]
    assert inst["unmapped_last_dropped_at"]
    assert any("2 event(s) DROPPED" in w for w in inst["warnings"])

    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert any("DROPPED" in w for w in listed["instances"][0]["warnings"])
    unmapped.reset()
