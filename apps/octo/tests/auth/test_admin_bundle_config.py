"""Tests for /api/v1/admin/bundle-config/llm (Slice 7a).

Super_admin-gated bundle-wide LLM toggle.
"""
from __future__ import annotations

import pyotp


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


def test_unauthenticated_rejected(auth_client):
    r = auth_client.get("/api/v1/admin/bundle-config/llm")
    assert r.status_code in (401, 403)


def test_analyst_forbidden(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/bundle-config/llm")
    assert r.status_code == 403
    r2 = auth_client.put(
        "/api/v1/admin/bundle-config/llm", json={"l2_llm_enabled": True},
    )
    assert r2.status_code == 403


def test_admin_forbidden(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        "/api/v1/admin/bundle-config/llm", json={"l2_llm_enabled": True},
    )
    assert r.status_code == 403


def test_super_admin_get_returns_defaults(auth_client):
    """No prior state → defaults: enabled=false, model=granite-3b-q4."""
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/admin/bundle-config/llm")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["l2_llm_enabled"] is False
    assert body["l2_llm_active_model"] == "granite-3b-q4"


def test_super_admin_can_toggle(auth_client):
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        "/api/v1/admin/bundle-config/llm", json={"l2_llm_enabled": True},
    )
    assert r.status_code == 200
    assert r.json()["l2_llm_enabled"] is True

    # GET reflects the change.
    r2 = auth_client.get("/api/v1/admin/bundle-config/llm")
    assert r2.json()["l2_llm_enabled"] is True

    # And toggle back.
    r3 = auth_client.put(
        "/api/v1/admin/bundle-config/llm", json={"l2_llm_enabled": False},
    )
    assert r3.json()["l2_llm_enabled"] is False


def test_partial_update_omitting_field_no_change(auth_client):
    """A PUT with no fields should be a no-op."""
    op = auth_client.provision_operator(
        "su-alice", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, op)
    # Set to true first.
    auth_client.put(
        "/api/v1/admin/bundle-config/llm", json={"l2_llm_enabled": True},
    )
    # Empty PUT.
    r = auth_client.put("/api/v1/admin/bundle-config/llm", json={})
    assert r.status_code == 200
    # Still true.
    assert r.json()["l2_llm_enabled"] is True
