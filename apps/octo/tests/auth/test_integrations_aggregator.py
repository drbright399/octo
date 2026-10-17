"""Combined /api/v1/integrations aggregator endpoint.

Verifies the read-back layer the Integrations settings UI consumes:
  - empty list when nothing is configured
  - configured row surfaces via definitions + instances joined by slug
  - admin-tier gated
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


class _StubAdapter:
    """Stub adapter for the aggregator test. Distinct from
    test_adapter_instance_endpoint's stub because tests run in separate
    fixtures and the unique-index constraint on vendor_slug demands a
    different slug if we ever want to combine."""
    vendor_slug = "stub-aggregator"
    vendor_display_name = "Stub Aggregator"
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

    def smoke_test(self, credentials: dict[str, Any]) -> _StubResult:
        return _StubResult(True, "ok")

    def start(self, instance_config: dict[str, Any]) -> None:
        pass

    def stop(self) -> None:
        pass


@pytest.fixture
def aggregator_client(monkeypatch, tmp_path):
    """Auth-ready app with the stub adapter pre-registered."""
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.auth import bootstrap
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

    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH",
        str(secrets_dir / "adapter-credentials-key.env"),
    )
    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")

    from apps.octo.credentials import ensure_key_file
    ensure_key_file()
    bootstrap.init_data_root()

    reset_limiter()
    app = create_app()
    # Override the auto-discovered registry so this test exercises ONLY
    # the stub adapter (avoids depending on the real Wazuh/Datto/etc.
    # being correctly importable in every test env).
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(_StubAdapter)
    app.state.adapter_registry = registry
    app.state.instance_manager = InstanceManager(adapter_registry=registry)

    client = TestClient(app, base_url="https://athena.test")

    def provision_operator(username: str, password: str, *, athena_role: str = "admin"):
        from apps.octo.auth import core as core_auth, crypto, operators
        from apps.octo.db import connect, transaction
        op = operators.create_operator(
            username=username,
            email=f"{username}@example.test",
            role=athena_role,
            scope_slugs=["*"],
            actor="system",
            reason="aggregator fixture",
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


def test_aggregator_returns_empty_when_nothing_configured(aggregator_client):
    op = aggregator_client.provision_operator("admin1", "password1234567")
    cookies = aggregator_client.login(op)
    r = aggregator_client.get("/api/v1/integrations", cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"definitions": [], "instances": {}}


def test_aggregator_surfaces_configured_instance(aggregator_client):
    op = aggregator_client.provision_operator("admin1", "password1234567")
    cookies = aggregator_client.login(op)
    # Configure one instance via the create endpoint
    r = aggregator_client.post(
        "/api/v1/admin/adapters/stub-aggregator/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text

    r = aggregator_client.get("/api/v1/integrations", cookies=cookies)
    assert r.status_code == 200
    body = r.json()
    # definitions carries the vendor metadata for the configured row
    defs = {d["slug"]: d for d in body["definitions"]}
    assert "stub-aggregator" in defs
    assert defs["stub-aggregator"]["name"] == "Stub Aggregator"
    assert defs["stub-aggregator"]["category"] == "siem"
    # instances maps slug → live status
    assert body["instances"]["stub-aggregator"]["status"] == "running"


def test_both_payload_routers_agree_on_supports_vendor_links(aggregator_client, monkeypatch):
    """The Integrations card reads /integrations, the admin list reads
    /admin/adapters/instances: both carry `supports_vendor_links`, and it is
    derived from the adapter class the same way on both."""
    op = aggregator_client.provision_operator("admin1", "password1234567")
    cookies = aggregator_client.login(op)
    r = aggregator_client.post(
        "/api/v1/admin/adapters/stub-aggregator/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text

    def both() -> tuple[bool, bool]:
        card = aggregator_client.get("/api/v1/integrations", cookies=cookies)
        listed = aggregator_client.get("/api/v1/admin/adapters/instances", cookies=cookies)
        assert card.status_code == 200 and listed.status_code == 200
        (row,) = [i for i in listed.json()["instances"] if i["vendor_slug"] == "stub-aggregator"]
        return (
            card.json()["instances"]["stub-aggregator"]["supports_vendor_links"],
            row["supports_vendor_links"],
        )

    # The stub cannot build "Open in <vendor>" links.
    assert both() == (False, False)

    # Give the SAME registered class the link capability: both flip together.
    monkeypatch.setattr(_StubAdapter, "vendor_link_spec", classmethod(lambda cls: None), raising=False)
    monkeypatch.setattr(_StubAdapter, "vendor_link_ids", staticmethod(lambda payload: {}), raising=False)
    assert both() == (True, True)


def test_aggregator_requires_admin(aggregator_client):
    op = aggregator_client.provision_operator(
        "anlst1", "password1234567", athena_role="analyst",
    )
    cookies = aggregator_client.login(op)
    r = aggregator_client.get("/api/v1/integrations", cookies=cookies)
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# W1: GET /api/v1/dashboard/integrations — analyst-visible health view
# ---------------------------------------------------------------------------

def test_dashboard_integrations_empty_when_nothing_configured(aggregator_client):
    op = aggregator_client.provision_operator("admin1", "password1234567")
    cookies = aggregator_client.login(op)
    r = aggregator_client.get("/api/v1/dashboard/integrations", cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"items": []}


def test_dashboard_integrations_returns_compact_health(aggregator_client):
    op = aggregator_client.provision_operator("admin1", "password1234567")
    cookies = aggregator_client.login(op)
    aggregator_client.post(
        "/api/v1/admin/adapters/stub-aggregator/instances",
        json={"credentials": {"k": "v"}},
        cookies=cookies,
    )

    r = aggregator_client.get("/api/v1/dashboard/integrations", cookies=cookies)
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    row = items[0]
    assert row["slug"] == "stub-aggregator"
    assert row["name"] == "Stub Aggregator"
    assert row["category"] == "siem"
    assert row["health"] == "ok"


def test_dashboard_integrations_analyst_allowed(aggregator_client):
    """Distinguishes the dashboard endpoint from the admin aggregator
    — analyst-tier callers can read health but not the full config."""
    op = aggregator_client.provision_operator(
        "anlst1", "password1234567", athena_role="analyst",
    )
    cookies = aggregator_client.login(op)
    r = aggregator_client.get("/api/v1/dashboard/integrations", cookies=cookies)
    assert r.status_code == 200
    assert r.json() == {"items": []}
