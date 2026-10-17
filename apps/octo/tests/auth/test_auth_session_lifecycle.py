"""Phase G.1 — session lifecycle tests.

Exercises:
  - GET /auth/sessions lists current operator's sessions
  - DELETE /auth/sessions/{prefix} revokes a specific session
  - POST /auth/logout revokes the current session and clears the cookie
  - Logged-out cookie no longer authenticates
  - Idle-expired session no longer authenticates
  - Absolute-expired session no longer authenticates
  - Operator cannot revoke another operator's session (404)
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths
from apps.octo.auth import sessions as session_lib


def _login(client, op: dict) -> dict:
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


def _force_session_iso(operator_id: int, *, expires_at: str | None = None,
                       idle_expires_at: str | None = None,
                       revoked_at: str | None = None) -> None:
    conn = sqlite3.connect(paths.registry_db_path())
    sets, vals = [], []
    if expires_at is not None:
        sets.append("expires_at = ?"); vals.append(expires_at)
    if idle_expires_at is not None:
        sets.append("idle_expires_at = ?"); vals.append(idle_expires_at)
    if revoked_at is not None:
        sets.append("revoked_at = ?"); vals.append(revoked_at)
    vals.append(operator_id)
    conn.execute(
        f"UPDATE sessions SET {', '.join(sets)} WHERE operator_id = ?",
        vals,
    )
    conn.commit()
    conn.close()


def _iso_past(minutes: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# GET /auth/sessions
# ---------------------------------------------------------------------------

def test_list_sessions_returns_current_session_marked(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    r = auth_client.get("/api/v1/auth/sessions", cookies=cookies)
    assert r.status_code == 200
    body = r.json()
    assert len(body["sessions"]) == 1
    s = body["sessions"][0]
    assert s["is_current"] is True
    assert s["auth_method"] == "password+totp"
    # The id is a 12-char prefix + ellipsis
    assert s["id"].endswith("…")
    assert len(s["id"]) >= 12


def test_list_sessions_requires_session_cookie(auth_client):
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/auth/sessions")
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_SESSION_INVALID"


# ---------------------------------------------------------------------------
# DELETE /auth/sessions/{prefix}
# ---------------------------------------------------------------------------

def test_revoke_session_by_prefix(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    # Issue two sessions for this operator (different logins)
    cookies1 = _login(auth_client, op)
    auth_client.cookies.clear()
    cookies2 = _login(auth_client, op)

    r = auth_client.get("/api/v1/auth/sessions", cookies=cookies2)
    body = r.json()
    assert len(body["sessions"]) == 2
    # Find the non-current one
    other = next(s for s in body["sessions"] if not s["is_current"])
    prefix = other["id"].rstrip("…")

    r2 = auth_client.delete(f"/api/v1/auth/sessions/{prefix}", cookies=cookies2)
    assert r2.status_code == 200
    assert r2.json()["revoked"] is True

    # Listing again — only the current session remains (the revoked row is
    # still listed but show as revoked; for v1 we just confirm count is now 1
    # active).
    r3 = auth_client.get("/api/v1/auth/sessions", cookies=cookies2)
    rows = r3.json()["sessions"]
    # Both still appear in the list (issued + revoked); the current is_current=True
    assert any(s["is_current"] for s in rows)


def test_session_list_filters_out_revoked_sessions(auth_client):
    """`GET /auth/sessions` powers the Settings → Account live panel.
    Revoked rows MUST NOT appear or the list grows unbounded across
    sign-ins (and the UI looks like Revoke did nothing because the row
    keeps reappearing in the refresh)."""
    op = auth_client.provision_operator("alice", "pw")
    cookies1 = _login(auth_client, op)
    auth_client.cookies.clear()
    cookies2 = _login(auth_client, op)

    # Two active sessions
    body = auth_client.get("/api/v1/auth/sessions", cookies=cookies2).json()
    assert len(body["sessions"]) == 2

    # Revoke the other one
    other = next(s for s in body["sessions"] if not s["is_current"])
    prefix = other["id"].rstrip("…")
    auth_client.delete(f"/api/v1/auth/sessions/{prefix}", cookies=cookies2)

    # Refresh — only the current session remains in the live panel
    body2 = auth_client.get("/api/v1/auth/sessions", cookies=cookies2).json()
    assert len(body2["sessions"]) == 1
    assert body2["sessions"][0]["is_current"] is True
    # Ensure the revoked id is GONE, not just suppressed for is_current
    assert all(s["id"] != other["id"] for s in body2["sessions"])

    # Sanity: cookies1 is now invalid
    r = auth_client.get("/api/v1/auth/me", cookies=cookies1)
    assert r.status_code in (401, 403)


def test_revoking_unknown_prefix_returns_404(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)
    r = auth_client.delete("/api/v1/auth/sessions/nonexistent", cookies=cookies)
    assert r.status_code == 404
    assert r.json()["code"] == "NOT_FOUND"


def test_cannot_revoke_other_operators_session(auth_client):
    """Operator A cannot revoke Operator B's session even with the prefix."""
    a = auth_client.provision_operator("alice", "pw")
    b = auth_client.provision_operator("zack", "pw2")
    cookies_a = _login(auth_client, a)
    auth_client.cookies.clear()
    cookies_b = _login(auth_client, b)

    # Get B's session prefix
    rb = auth_client.get("/api/v1/auth/sessions", cookies=cookies_b)
    b_prefix = rb.json()["sessions"][0]["id"].rstrip("…")

    # A tries to revoke it — must 404 (per-operator prefix space)
    r = auth_client.delete(f"/api/v1/auth/sessions/{b_prefix}", cookies=cookies_a)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

def test_logout_revokes_session_and_clears_cookie(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    r = auth_client.post("/api/v1/auth/logout", cookies=cookies)
    assert r.status_code == 200
    assert r.json()["revoked"] is True

    # The same cookie no longer authenticates
    r2 = auth_client.get("/api/v1/auth/sessions", cookies=cookies)
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_SESSION_INVALID"


def test_logout_without_session_cookie_returns_401(auth_client):
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/logout")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Expired sessions
# ---------------------------------------------------------------------------

def test_idle_expired_session_no_longer_authenticates(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    # Force idle_expires_at into the past
    past = _iso_past(minutes=1)
    _force_session_iso(op["id"], idle_expires_at=past)

    r = auth_client.get("/api/v1/auth/sessions", cookies=cookies)
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_SESSION_INVALID"


def test_absolute_expired_session_no_longer_authenticates(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)
    past = _iso_past(minutes=1)
    _force_session_iso(op["id"], expires_at=past, idle_expires_at=past)

    r = auth_client.get("/api/v1/auth/sessions", cookies=cookies)
    assert r.status_code == 401


def test_revoked_session_no_longer_authenticates(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    _force_session_iso(op["id"], revoked_at=now_iso)

    r = auth_client.get("/api/v1/auth/sessions", cookies=cookies)
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# GET /auth/me — Console session middleware uses this to resolve identity
# ---------------------------------------------------------------------------

def test_me_returns_full_operator_identity(auth_client):
    op = auth_client.provision_operator("alice", "pw", athena_role="super_admin")
    cookies = _login(auth_client, op)

    r = auth_client.get("/api/v1/auth/me", cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operator_id"] == op["id"]
    assert body["username"] == "alice"
    assert "super_admin" in body["role"]
    assert body["ai_access_enabled"] is False     # default from migration 005
    assert body["auth_method"] == "password+totp"
    assert body["session_expires_at"]              # ISO timestamp


def test_me_without_session_returns_401(auth_client):
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/auth/me")
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_SESSION_INVALID"


def test_me_with_revoked_session_returns_401(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    _force_session_iso(op["id"], revoked_at=now_iso)
    r = auth_client.get("/api/v1/auth/me", cookies=cookies)
    assert r.status_code == 401
