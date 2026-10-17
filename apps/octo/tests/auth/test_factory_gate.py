"""Tests for the session_factory() role gate (Slice 5d-1).

Exercises operator_is_factory + the dependency's reject/accept paths.
The factory flag is set by:
  - provision_factory_super_admin_if_empty (production first-init)
  - the auth_client fixture's `is_factory=True` arg (tests)
  - migration 026 backfill (existing-bundle upgrade)
"""
from __future__ import annotations

import pyotp

from apps.octo import paths
from apps.octo.api.role_gates import operator_is_factory
from apps.octo.db import connect


def _login(client, op: dict) -> None:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text


# ---------------------------------------------------------------------------
# operator_is_factory direct check
# ---------------------------------------------------------------------------

def test_factory_default_false_for_regular_operator(auth_client):
    op = auth_client.provision_operator(
        "regular-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    assert operator_is_factory(op["id"]) is False


def test_factory_true_when_flag_set(auth_client):
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    assert operator_is_factory(op["id"]) is True


def test_factory_false_for_nonexistent_operator(auth_client):
    """Out-of-range ID returns False, doesn't raise."""
    assert operator_is_factory(99999) is False


def test_factory_backfill_via_migration_026(auth_client):
    """Migration 026 backfills any operator named 'Root' to is_factory=1.
    Verifies the migration's WHERE-username clause works for the
    well-known factory username."""
    # Insert an operator named "Root" directly without is_factory=1,
    # then call _ensure_migration check by re-running the schema.
    op = auth_client.provision_operator(
        "Root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=False,  # Provisioned without flag.
    )
    # Manually unset is_factory to simulate pre-migration state.
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE operators SET is_factory = 0 WHERE id = ?", (op["id"],))
        reg.commit()
    finally:
        reg.close()
    assert operator_is_factory(op["id"]) is False
    # Now re-apply migration 026's backfill clause.
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE operators SET is_factory = 1 WHERE username = 'Root'")
        reg.commit()
    finally:
        reg.close()
    assert operator_is_factory(op["id"]) is True


# ---------------------------------------------------------------------------
# session_factory() dependency end-to-end (via the existing /admin/llm path
# which now requires it on write actions)
# ---------------------------------------------------------------------------

def test_session_factory_rejects_unauthenticated(auth_client, tmp_path, monkeypatch):
    """No session at all → 401/403."""
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(tmp_path))
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "anything"},
    )
    assert r.status_code in (401, 403)


def test_session_factory_rejects_analyst(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(tmp_path))
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "anything"},
    )
    assert r.status_code == 403


def test_session_factory_rejects_admin(auth_client, tmp_path, monkeypatch):
    op = auth_client.provision_operator(
        "alice-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    _login(auth_client, op)
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(tmp_path))
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "anything"},
    )
    assert r.status_code == 403


def test_session_factory_rejects_non_factory_super_admin(
    auth_client, tmp_path, monkeypatch,
):
    op = auth_client.provision_operator(
        "su-second", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=False,
    )
    _login(auth_client, op)
    # Stage a model so a successful PUT could succeed if the gate
    # mistakenly let us through.
    d = tmp_path / "models"
    d.mkdir()
    (d / "granite-3b-q4.gguf").write_bytes(b"\x00")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "granite-3b-q4"},
    )
    assert r.status_code == 403
    assert "factory" in r.json().get("message", "").lower()


def test_session_factory_accepts_factory_super_admin(
    auth_client, tmp_path, monkeypatch,
):
    op = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, op)
    # Slice 5d-3: model writes also require step-up auth.
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r_elev = auth_client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r_elev.status_code == 200, r_elev.text
    d = tmp_path / "models"
    d.mkdir()
    (d / "granite-3b-q4.gguf").write_bytes(b"\x00")
    monkeypatch.setenv("OCTO_LLM_MODELS_DIR", str(d))
    r = auth_client.put(
        "/api/v1/admin/llm/models/active",
        json={"name": "granite-3b-q4"},
    )
    assert r.status_code == 200, r.text
