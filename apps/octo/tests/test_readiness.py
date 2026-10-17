"""/readyz: green only when the bundle can actually serve."""
from __future__ import annotations

import pytest

from apps.octo import bundle_bootstrap


@pytest.fixture
def bundle(monkeypatch, tmp_path):
    secrets_dir = tmp_path / "secrets"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(secrets_dir / "pepper.env"))
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(secrets_dir / "mfa-key.env"))
    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH",
        str(secrets_dir / "adapter-credentials-key.env"),
    )
    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")
    monkeypatch.setenv("OCTO_TRIAGE_WORKER", "0")
    return secrets_dir


def _client():
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    return TestClient(create_app())


def test_ready_after_bootstrap(bundle):
    assert bundle_bootstrap.main(["--skip-factory-admin"]) == 0
    r = _client().get("/readyz")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_not_ready_when_secrets_mount_is_lost(bundle):
    bundle_bootstrap.main(["--skip-factory-admin"])
    (bundle / "mfa-key.env").unlink()

    c = _client()
    r = c.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["checks"]["mfa_key"] is False
    assert body["checks"]["registry_schema"] is True
    # names only — never paths or values
    assert "mfa-key.env" not in r.text
    # liveness is unaffected
    assert c.get("/healthz").status_code == 200


def test_not_ready_on_unbootstrapped_bundle(bundle):
    r = _client().get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["mfa_key"] is False
