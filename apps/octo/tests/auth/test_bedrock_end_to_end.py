"""End-to-end through the bedrock layer.

Single flow exercising every piece together:
  1. /admin/adapters/catalog returns the stub adapter
  2. /admin/adapters/{slug}/smoke-test passes
  3. /admin/adapters/{slug}/instances persists + starts
  4. /integrations surfaces the configured row
  5. /admin/adapters/instances lists the same row

If any layer is broken the chain stops where the rot is.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pyotp
import pytest
from cryptography.fernet import Fernet

from apps.octo import paths


class _StubResult:
    def __init__(self, ok: bool, message: str) -> None:
        self.ok = ok
        self.message = message


class _E2EAdapter:
    vendor_slug = "bedrock-e2e"
    vendor_display_name = "Bedrock E2E Adapter"
    vendor_logo_path = ""
    vendor_category = "siem"
    auth_model = "api-key"
    delivery_mode = "poll"
    availability = "available"
    compliance_categories: list[str] = []
    contract_version = "1.0.0"

    def __init__(self) -> None:
        pass

    def credential_shape(self) -> list:
        return []

    def tenant_mapping_shape(self) -> None:
        return None

    def onboarding(self, webhook_url: str | None = None) -> None:
        # Contract grew onboarding() with the 06-05 wizard work; the double
        # opts out (no guided onboarding for the e2e stub vendor).
        return None

    def smoke_test(self, credentials: dict[str, Any]) -> _StubResult:
        return _StubResult(True, "bedrock-ok")

    def start(self, instance_config: dict[str, Any]) -> None:
        pass

    def stop(self) -> None:
        pass


@pytest.fixture
def e2e_client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.auth import bootstrap
    from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.instances import InstanceManager

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))

    sd = tmp_path / "secrets"
    sd.mkdir()
    p = sd / "pepper.env"
    p.write_text("PEPPER_VERSION=pepper_v1\nPEPPER_HEX=" + "ab" * 32 + "\n")
    os.chmod(p, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(p))

    m = sd / "mfa-key.env"
    m.write_text(f"MFA_KEY_VERSION=v1\nMFA_KEY_BASE64={Fernet.generate_key().decode()}\n")
    os.chmod(m, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(m))

    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH",
        str(sd / "adapter-credentials-key.env"),
    )
    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")

    from apps.octo.credentials import ensure_key_file
    ensure_key_file()
    bootstrap.init_data_root()

    reset_limiter()
    app = create_app()
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(_E2EAdapter)
    app.state.adapter_registry = registry
    app.state.instance_manager = InstanceManager(adapter_registry=registry)

    c = TestClient(app, base_url="https://athena.test")

    def provision_operator(username: str, password: str, *, athena_role: str = "admin"):
        from apps.octo.auth import core as core_auth, crypto, operators
        from apps.octo.db import connect, transaction
        op = operators.create_operator(
            username=username,
            email=f"{username}@example.test",
            role=athena_role,
            scope_slugs=["*"],
            actor="system",
            reason="e2e fixture",
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
        r = c.post("/api/v1/auth/password/begin", json={
            "username": op["username"], "password": op["password"],
        })
        challenge = r.json()["challenge_id"]
        code = pyotp.TOTP(op["totp_secret_b32"]).now()
        r2 = c.post("/api/v1/auth/password/totp", json={
            "challenge_id": challenge, "totp_code": code,
        })
        assert r2.status_code == 200, r2.text
        return dict(r2.cookies)

    c.provision_operator = provision_operator
    c.login = login
    yield c


def test_full_pipe_catalog_smoke_create_listback(e2e_client):
    """The whole bedrock chain in one test."""
    op = e2e_client.provision_operator("admin1", "password1234567")
    cookies = e2e_client.login(op)

    # 1. Catalog includes the stub
    r = e2e_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 200
    slugs = {a["vendor_slug"] for a in r.json()["adapters"]}
    assert "bedrock-e2e" in slugs

    # 2. Smoke-test passes
    r = e2e_client.post(
        "/api/v1/admin/adapters/bedrock-e2e/smoke-test",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["message"] == "bedrock-ok"

    # 3. Create-instance persists + starts
    r = e2e_client.post(
        "/api/v1/admin/adapters/bedrock-e2e/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["instance"]["status"] == "running"
    assert body["smoke_test_message"] == "bedrock-ok"

    # 4. /integrations aggregator surfaces the configured row
    r = e2e_client.get("/api/v1/integrations", cookies=cookies)
    assert r.status_code == 200
    body = r.json()
    assert body["instances"]["bedrock-e2e"]["status"] == "running"
    defs = {d["slug"]: d for d in body["definitions"]}
    assert defs["bedrock-e2e"]["name"] == "Bedrock E2E Adapter"
    assert defs["bedrock-e2e"]["category"] == "siem"

    # 5. /admin/adapters/instances lists the same row
    r = e2e_client.get("/api/v1/admin/adapters/instances", cookies=cookies)
    assert r.status_code == 200
    rows = r.json()["instances"]
    assert len(rows) == 1
    assert rows[0]["vendor_slug"] == "bedrock-e2e"
    assert rows[0]["vendor_display_name"] == "Bedrock E2E Adapter"
    assert rows[0]["status"] == "running"
