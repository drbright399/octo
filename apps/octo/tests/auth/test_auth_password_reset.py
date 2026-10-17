"""Self-service password-reset flow (forgot + reset endpoints).

Exercises:
  Forgot:
    - hit by username → token row created, email send attempted
    - hit by email (case-insensitive)
    - miss → identical 202 body (anti-enumeration)
    - disabled operator → identical 202 body
    - email-send failure does not change response or block audit
  Reset:
    - happy path: returns operator, clears lockout, revokes sessions,
      new password works for login
    - wrong token → AUTH_MAGIC_LINK_INVALID
    - expired token → AUTH_MAGIC_LINK_INVALID
    - replayed (used) token → AUTH_MAGIC_LINK_USED
    - wrong-purpose token (re-auth) → AUTH_MAGIC_LINK_INVALID
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths
from apps.octo.api.routers import auth as auth_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login_session(client, op: dict) -> dict:
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


def _capture_emails(monkeypatch) -> list[dict]:
    """Replace email_sender.send_email with a capture-only stub.

    Returns a list that tests can inspect after the request. Stub always
    returns True (delivered). Tests that need to simulate a relay failure
    install their own monkeypatch instead of using this helper.
    """
    sent: list[dict] = []

    def fake_send_email(to, subject, body_text, *, body_html=None,
                       from_addr=None):
        sent.append({
            "to": to, "subject": subject, "body_text": body_text,
            "body_html": body_html, "from_addr": from_addr,
        })
        return True

    monkeypatch.setattr(auth_router.email_sender, "send_email", fake_send_email)
    return sent


def _count_reset_tokens(operator_id: int) -> int:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM magic_link_tokens "
            "WHERE operator_id = ? AND purpose = 'password-reset'",
            (operator_id,),
        ).fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Forgot
# ---------------------------------------------------------------------------

def test_forgot_by_username_issues_token_and_emails(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    sent = _capture_emails(monkeypatch)

    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice"})
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] is True
    assert "If an account matches" in body["message"]

    assert _count_reset_tokens(op["id"]) == 1
    assert len(sent) == 1
    assert sent[0]["to"] == op["email"]
    assert "password reset" in sent[0]["subject"].lower()
    assert "/login/reset?token=" in sent[0]["body_text"]


def test_forgot_by_email_case_insensitive(auth_client, monkeypatch):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", email="Alice@Example.Test",
    )
    sent = _capture_emails(monkeypatch)

    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice@example.test"})
    assert r.status_code == 200
    assert _count_reset_tokens(op["id"]) == 1
    assert sent[0]["to"] == "Alice@Example.Test"


def test_forgot_miss_returns_identical_body(auth_client, monkeypatch):
    auth_client.provision_operator("alice", "pw1234567890")
    sent = _capture_emails(monkeypatch)

    hit = auth_client.post("/api/v1/auth/password/forgot",
                            json={"identifier": "alice"}).json()
    miss = auth_client.post("/api/v1/auth/password/forgot",
                             json={"identifier": "nobody"}).json()

    assert hit == miss
    # Only one email was sent (the hit), miss did not trigger email.
    assert len(sent) == 1


def test_forgot_disabled_operator_treated_as_miss(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute(
        "UPDATE operators SET disabled_at = ? WHERE id = ?",
        ("2026-05-07T00:00:00.000Z", op["id"]),
    )
    conn.commit()
    conn.close()

    sent = _capture_emails(monkeypatch)
    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice"})
    assert r.status_code == 200
    assert _count_reset_tokens(op["id"]) == 0
    assert sent == []


def test_forgot_never_activated_operator_treated_as_miss(auth_client, monkeypatch):
    """No password AND no MFA = nothing to have forgotten. Minting a reset
    token here would let its holder set a password and walk in through
    /password/begin's no-MFA branch — the only door is the setup link."""
    op = auth_client.provision_operator("alice", "pw1234567890")
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute(
        "UPDATE operators SET password_hash = NULL, mfa_enabled = 0, "
        "mfa_secret_enc = NULL WHERE id = ?",
        (op["id"],),
    )
    conn.commit()
    conn.close()

    sent = _capture_emails(monkeypatch)
    for ident in ("alice", op["email"]):
        r = auth_client.post("/api/v1/auth/password/forgot",
                              json={"identifier": ident})
        assert r.status_code == 200
        assert r.json()["accepted"] is True
    assert _count_reset_tokens(op["id"]) == 0
    assert sent == []


def test_forgot_passwordless_but_mfa_enrolled_still_issues(auth_client, monkeypatch):
    """An ACTIVATED operator who simply never set a password (invite flow)
    keeps self-service reset — only never-activated accounts are refused."""
    op = auth_client.provision_operator("alice", "pw1234567890")
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute("UPDATE operators SET password_hash = NULL WHERE id = ?",
                 (op["id"],))
    conn.commit()
    conn.close()

    sent = _capture_emails(monkeypatch)
    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice"})
    assert r.status_code == 200
    assert _count_reset_tokens(op["id"]) == 1
    assert len(sent) == 1


def test_forgot_factory_placeholder_email_treated_as_miss(auth_client, monkeypatch):
    """The factory placeholder address is undeliverable by design; it never
    gets a reset token, even for a fully set-up account."""
    from apps.octo.auth import bootstrap
    op = auth_client.provision_operator(
        "alice", "pw1234567890", email=bootstrap.FACTORY_SUPER_ADMIN_EMAIL,
    )
    sent = _capture_emails(monkeypatch)
    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice"})
    assert r.status_code == 200
    assert _count_reset_tokens(op["id"]) == 0
    assert sent == []


def test_forgot_email_send_failure_still_returns_202(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    sent: list[dict] = []

    def failing_send_email(to, subject, body_text, *, body_html=None,
                            from_addr=None):
        sent.append({"to": to})
        return False  # relay down

    monkeypatch.setattr(auth_router.email_sender, "send_email",
                         failing_send_email)

    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": "alice"})
    assert r.status_code == 200
    # Token was still issued; email failure is logged + audited but does not
    # change the user-facing response (anti-enumeration).
    assert _count_reset_tokens(op["id"]) == 1
    assert len(sent) == 1


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def _request_reset_token(auth_client, monkeypatch, op: dict) -> str:
    """Drive the forgot endpoint, capture the plaintext token from the
    captured email body."""
    sent = _capture_emails(monkeypatch)
    r = auth_client.post("/api/v1/auth/password/forgot",
                          json={"identifier": op["username"]})
    assert r.status_code == 200
    body_text = sent[0]["body_text"]
    marker = "/login/reset?token="
    idx = body_text.index(marker) + len(marker)
    end = body_text.index("\n", idx)
    return body_text[idx:end].strip()


def test_reset_happy_path_changes_password(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    token = _request_reset_token(auth_client, monkeypatch, op)
    new_pw = "Brand-New-Pw-987654"

    r = auth_client.post("/api/v1/auth/password/reset",
                          json={"token": token, "new_password": new_pw})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operator_id"] == op["id"]
    assert body["username"] == "alice"

    # Old password must no longer work
    r_old = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": op["password"],
    })
    assert r_old.status_code == 401

    # New password must work
    r_new = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "alice", "password": new_pw,
    })
    assert r_new.status_code == 200, r_new.text


def test_reset_clears_lockout(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    # Force lockout state
    conn = sqlite3.connect(paths.registry_db_path())
    future = (datetime.now(timezone.utc) + timedelta(hours=1))
    future_iso = future.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{future.microsecond // 1000:03d}Z"
    conn.execute(
        "UPDATE operators SET failed_login_count = 9, locked_until = ? "
        "WHERE id = ?",
        (future_iso, op["id"]),
    )
    conn.commit()
    conn.close()

    token = _request_reset_token(auth_client, monkeypatch, op)
    r = auth_client.post("/api/v1/auth/password/reset",
                          json={"token": token,
                                "new_password": "Brand-New-Pw-987654"})
    assert r.status_code == 200, r.text

    conn = sqlite3.connect(paths.registry_db_path())
    row = conn.execute(
        "SELECT failed_login_count, locked_until FROM operators WHERE id = ?",
        (op["id"],),
    ).fetchone()
    conn.close()
    assert row[0] == 0
    assert row[1] is None


def test_reset_revokes_all_active_sessions(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    # Create an active session via password+TOTP login
    _login_session(auth_client, op)

    conn = sqlite3.connect(paths.registry_db_path())
    active_before = conn.execute(
        "SELECT COUNT(*) FROM sessions "
        "WHERE operator_id = ? AND revoked_at IS NULL",
        (op["id"],),
    ).fetchone()[0]
    conn.close()
    assert active_before >= 1

    auth_client.cookies.clear()
    token = _request_reset_token(auth_client, monkeypatch, op)
    r = auth_client.post("/api/v1/auth/password/reset",
                          json={"token": token,
                                "new_password": "Brand-New-Pw-987654"})
    assert r.status_code == 200, r.text

    conn = sqlite3.connect(paths.registry_db_path())
    active_after = conn.execute(
        "SELECT COUNT(*) FROM sessions "
        "WHERE operator_id = ? AND revoked_at IS NULL",
        (op["id"],),
    ).fetchone()[0]
    conn.close()
    assert active_after == 0


def test_reset_unknown_token_invalid(auth_client):
    auth_client.provision_operator("alice", "pw1234567890")
    r = auth_client.post("/api/v1/auth/password/reset",
                          json={"token": "X" * 43,
                                "new_password": "Brand-New-Pw-987654"})
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_MAGIC_LINK_INVALID"


def test_reset_expired_token_invalid(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    token = _request_reset_token(auth_client, monkeypatch, op)

    # Force expiry into the past
    past = (datetime.now(timezone.utc) - timedelta(minutes=1))
    past_iso = past.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{past.microsecond // 1000:03d}Z"
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute(
        "UPDATE magic_link_tokens SET expires_at = ? "
        "WHERE operator_id = ? AND purpose = 'password-reset'",
        (past_iso, op["id"]),
    )
    conn.commit()
    conn.close()

    r = auth_client.post("/api/v1/auth/password/reset",
                          json={"token": token,
                                "new_password": "Brand-New-Pw-987654"})
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_MAGIC_LINK_INVALID"


def test_reset_used_token_cannot_be_replayed(auth_client, monkeypatch):
    op = auth_client.provision_operator("alice", "pw1234567890")
    token = _request_reset_token(auth_client, monkeypatch, op)

    r1 = auth_client.post("/api/v1/auth/password/reset",
                           json={"token": token,
                                 "new_password": "Brand-New-Pw-987654"})
    assert r1.status_code == 200, r1.text

    r2 = auth_client.post("/api/v1/auth/password/reset",
                           json={"token": token,
                                 "new_password": "Some-Other-Pw-12345"})
    # Replay returns INVALID (not USED): the lookup query filters
    # `used_at IS NULL`, so a consumed token is indistinguishable from
    # an unknown one — same convention as /magic-link/verify. The
    # AUTH_MAGIC_LINK_USED path is only reachable on a concurrent-replay
    # race where two threads both pass the lookup before either UPDATE.
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_MAGIC_LINK_INVALID"


def test_reset_rejects_wrong_purpose_token(auth_client):
    """A re-auth magic link must not be usable as a password-reset token."""
    issuer = auth_client.provision_operator("alice", "pw1234567890",
                                              athena_role="super_admin")
    target = auth_client.provision_operator("zack", "pw0987654321",
                                              athena_role="super_admin")
    cookies = _login_session(auth_client, issuer)

    r = auth_client.post("/api/v1/auth/magic-link/request",
        json={"target_username": "zack", "purpose": "re-auth",
              "reason": "wrong-purpose test"},
        cookies=cookies,
    )
    token = r.json()["token"]

    auth_client.cookies.clear()
    r2 = auth_client.post("/api/v1/auth/password/reset",
                           json={"token": token,
                                 "new_password": "Brand-New-Pw-987654"})
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_MAGIC_LINK_INVALID"
