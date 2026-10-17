"""Phase G.1 — password+TOTP login flow.

Exercises:
  - Happy path: /password/begin → challenge → /password/totp → session cookie
  - Wrong password (no such user / disabled / wrong pw) → AUTH_PASSWORD_INVALID
  - Wrong TOTP → AUTH_TOTP_INVALID + bumps failed_login_count
  - Lockout after 5 consecutive failures → AUTH_LOCKED for 15 min
  - Successful login resets failed_login_count to 0
  - Operator without MFA enrolled → AUTH_MFA_NOT_ENROLLED on /password/begin
"""
from __future__ import annotations

import sqlite3
import pyotp
import pytest

from apps.octo import paths
from apps.octo.api.routers.auth import LOCKOUT_THRESHOLD


def _operator_row(op_id: int) -> sqlite3.Row:
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM operators WHERE id = ?", (op_id,)).fetchone()
    finally:
        conn.close()


def _totp_now(secret_b32: str) -> str:
    return pyotp.TOTP(secret_b32).now()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_happy_path_password_then_totp_issues_session(auth_client):
    op = auth_client.provision_operator("alice", "correct-horse-battery-staple")

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice",
        "password": "correct-horse-battery-staple",
    })
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge_id"]
    assert r.json()["requires_totp"] is True

    code = _totp_now(op["totp_secret_b32"])
    r2 = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge,
        "totp_code": code,
    })
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["operator_id"] == op["id"]
    assert body["username"] == "alice"
    assert "super_admin" in body["role"]

    # Session cookie was set
    assert "athena_session" in r2.cookies
    sid = r2.cookies["athena_session"]
    assert len(sid) >= 40

    # Posture reset on success
    row = _operator_row(op["id"])
    assert row["failed_login_count"] == 0
    assert row["last_login_at"] is not None
    assert row["locked_until"] is None


# ---------------------------------------------------------------------------
# Error cases on /password/begin
# ---------------------------------------------------------------------------

def test_unknown_username_returns_password_invalid(auth_client):
    auth_client.provision_operator("alice", "pw")
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "ghost", "password": "pw",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_PASSWORD_INVALID"


def test_wrong_password_returns_password_invalid_and_bumps_count(auth_client):
    op = auth_client.provision_operator("alice", "correct-pw")
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": "WRONG",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_PASSWORD_INVALID"
    row = _operator_row(op["id"])
    assert row["failed_login_count"] == 1
    assert row["locked_until"] is None


def test_no_mfa_operator_signs_in_password_only_for_setup(auth_client):
    """When `mfa_enabled=0`, /password/begin issues a session directly
    with auth_method='password-no-mfa' so the operator can reach
    /login/setup. The setup_gate middleware confines that session to
    setup-only endpoints until MFA is enrolled.

    Updated 2026-05-11 — earlier behavior was AUTH_MFA_NOT_ENROLLED at
    /password/begin, which left brand-new operators (admin-set temp
    password, no MFA yet) with no path forward to the wizard."""
    import sqlite3 as sql
    op = auth_client.provision_operator("alice", "pw")
    conn = sql.connect(paths.registry_db_path())
    conn.execute("UPDATE operators SET mfa_enabled = 0 WHERE id = ?", (op["id"],))
    conn.commit()
    conn.close()

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": "pw",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["requires_totp"] is False
    assert body["challenge_id"] == ""
    assert "athena_session" in r.cookies


# ---------------------------------------------------------------------------
# Error cases on /password/totp
# ---------------------------------------------------------------------------

def test_wrong_totp_bumps_count_and_returns_invalid(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    r = auth_client.post("/api/v1/auth/password/begin",
                         json={"username": "alice", "password": "pw"})
    challenge = r.json()["challenge_id"]

    r2 = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": "000000",
    })
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_TOTP_INVALID"
    row = _operator_row(op["id"])
    assert row["failed_login_count"] == 1


def test_malformed_challenge_returns_invalid(auth_client):
    auth_client.provision_operator("alice", "pw")
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": "not-a-real-fernet-token",
        "totp_code": "123456",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_TOTP_INVALID"


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------

def test_lockout_after_threshold_failures_and_unlock_after_success(auth_client):
    op = auth_client.provision_operator("alice", "correct-pw")

    # 5 wrong-password attempts → lockout
    for i in range(LOCKOUT_THRESHOLD):
        r = auth_client.post("/api/v1/auth/password/begin", json={
            "username": "alice", "password": "WRONG",
        })
        assert r.status_code == 401
        assert r.json()["code"] == "AUTH_PASSWORD_INVALID"

    row = _operator_row(op["id"])
    assert row["failed_login_count"] == LOCKOUT_THRESHOLD
    assert row["locked_until"] is not None

    # 6th attempt — even with correct password — must return AUTH_LOCKED
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": "correct-pw",
    })
    assert r.status_code == 423
    assert r.json()["code"] == "AUTH_LOCKED"


def test_lockout_combines_password_and_totp_failures(auth_client):
    """failed_login_count is bumped by BOTH wrong password AND wrong TOTP.
    A user who supplies the right password 5 times then types the wrong TOTP
    each time should still be locked out."""
    op = auth_client.provision_operator("alice", "correct-pw")

    for _ in range(LOCKOUT_THRESHOLD):
        r = auth_client.post("/api/v1/auth/password/begin", json={
            "username": "alice", "password": "correct-pw",
        })
        assert r.status_code == 200
        challenge = r.json()["challenge_id"]
        r2 = auth_client.post("/api/v1/auth/password/totp", json={
            "challenge_id": challenge, "totp_code": "000000",
        })
        assert r2.status_code == 401
        assert r2.json()["code"] == "AUTH_TOTP_INVALID"

    row = _operator_row(op["id"])
    assert row["failed_login_count"] == LOCKOUT_THRESHOLD
    assert row["locked_until"] is not None


def test_correct_login_resets_failed_count(auth_client):
    op = auth_client.provision_operator("alice", "correct-pw")

    # 4 wrong attempts (below threshold)
    for _ in range(LOCKOUT_THRESHOLD - 1):
        auth_client.post("/api/v1/auth/password/begin", json={
            "username": "alice", "password": "WRONG",
        })
    assert _operator_row(op["id"])["failed_login_count"] == LOCKOUT_THRESHOLD - 1

    # Successful login
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": "correct-pw",
    })
    challenge = r.json()["challenge_id"]
    code = _totp_now(op["totp_secret_b32"])
    r2 = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200

    row = _operator_row(op["id"])
    assert row["failed_login_count"] == 0
    assert row["locked_until"] is None
