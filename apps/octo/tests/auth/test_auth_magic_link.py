"""Phase G.1 — magic-link issue + verify flow.

Exercises:
  - super_admin can issue magic-link for another operator
  - Non-super_admin caller is refused (ISOLATION_VIOLATION)
  - Verify happy path issues a session
  - Re-presenting a used magic link → AUTH_MAGIC_LINK_INVALID (single-use)
  - Verifying an unknown token → AUTH_MAGIC_LINK_INVALID
  - Verifying an expired token → AUTH_MAGIC_LINK_INVALID
  - 'initial-setup' purpose refused via API (bootstrap-only)
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths


def _login_session(client, op: dict) -> dict:
    """Helper: log in as `op` via password+TOTP, return the cookies dict."""
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


# ---------------------------------------------------------------------------
# Issue
# ---------------------------------------------------------------------------

def test_super_admin_issues_magic_link(auth_client):
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    target = auth_client.provision_operator(
        "zack", "pw2", athena_role="super_admin",
    )
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "test issuance"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target_username"] == "zack"
    assert body["target_operator_id"] == target["id"]
    assert body["purpose"] == "re-auth"
    assert len(body["token"]) >= 30
    assert body["expires_at"]


def test_non_super_admin_refused_to_issue(auth_client):
    issuer = auth_client.provision_operator(
        "viewer-jane", "pw", athena_role="viewer",
    )
    auth_client.provision_operator("zack", "pw2", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "should fail"},
        cookies=cookies,
    )
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_initial_setup_purpose_refused_via_api(auth_client):
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    auth_client.provision_operator("zack", "pw2", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "initial-setup",
              "reason": "should be refused"},
        cookies=cookies,
    )
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_target_unknown_returns_operator_not_found(auth_client):
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "ghost", "purpose": "re-auth",
              "reason": "should 404"},
        cookies=cookies,
    )
    assert r.status_code == 404
    assert r.json()["code"] == "AUTH_OPERATOR_NOT_FOUND"


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def test_verify_happy_path_issues_session(auth_client):
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    target = auth_client.provision_operator("zack", "pw2", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "verify happy path"},
        cookies=cookies,
    )
    token = r.json()["token"]

    # Use a fresh client (no cookies) to verify — simulates the target user
    auth_client.cookies.clear()
    r2 = auth_client.post("/api/v1/auth/magic-link/verify",
                            json={"token": token})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["operator_id"] == target["id"]
    assert body["username"] == "zack"
    assert "athena_session" in r2.cookies


def test_used_magic_link_cannot_be_replayed(auth_client):
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    auth_client.provision_operator("zack", "pw2", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "single-use test"},
        cookies=cookies,
    )
    token = r.json()["token"]

    auth_client.cookies.clear()
    r1 = auth_client.post("/api/v1/auth/magic-link/verify", json={"token": token})
    assert r1.status_code == 200

    auth_client.cookies.clear()
    r2 = auth_client.post("/api/v1/auth/magic-link/verify", json={"token": token})
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_MAGIC_LINK_INVALID"


def test_unknown_token_returns_invalid(auth_client):
    auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/magic-link/verify",
                         json={"token": "X" * 43})  # plausible-shape but not real
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_MAGIC_LINK_INVALID"


def test_expired_token_returns_invalid(auth_client):
    """Expire the row in DB to past time, then verify — must reject as expired."""
    issuer = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    auth_client.provision_operator("zack", "pw2", athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "expiry test"},
        cookies=cookies,
    )
    token = r.json()["token"]

    # Force the row's expires_at into the past
    past = (datetime.now(timezone.utc) - timedelta(minutes=1))
    past_iso = past.strftime("%Y-%m-%dT%H:%M:%S.") + f"{past.microsecond // 1000:03d}Z"
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute("UPDATE magic_link_tokens SET expires_at = ?", (past_iso,))
    conn.commit()
    conn.close()

    auth_client.cookies.clear()
    r2 = auth_client.post("/api/v1/auth/magic-link/verify", json={"token": token})
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_MAGIC_LINK_INVALID"
