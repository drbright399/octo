"""Factory super_admin (Option 2 / per-MSP-bundle architecture).

The factory account is MAGIC-LINK-ONLY: no default password, no
pre-generated TOTP secret, no backup codes.

Exercises:
  - First-init: empty operators table → factory provisioned, returns dict
  - Subsequent: any operator exists → returns None, no duplicates, and an
    already-deployed (password + TOTP) factory row is left untouched
  - Factory account state: super_admin role, password_hash NULL,
    must_change_password=1, mfa_enabled=0, one initial-setup magic link
  - Printed block: username + link + expiry + next steps, no other secret
  - No way in without the link: /password/begin (old default, empty,
    random) and /password/forgot yield no session, challenge or token
  - Magic link → session gated by SETUP_REQUIRED until BOTH a password
    is set AND TOTP is enrolled
  - reset_factory_super_admin: back to pre-setup state, sessions revoked,
    old link dead, new link re-enters the wizard; raises if no factory
  - audit row written for factory_recovery_initiated
"""
from __future__ import annotations

import io
import sqlite3
import urllib.parse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo.auth import bootstrap
from apps.octo import paths
from apps.octo.api.routers import auth as auth_router


_OLD_DEFAULT_PASSWORD = "Octopus"   # the retired well-known default
_NEW_PASSWORD = "correct-horse-battery-staple"
_GATED_PATH = "/api/v1/admin/operators"


def _token_from(url: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["token"][0]


def _factory_row() -> sqlite3.Row:
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM operators WHERE username = ?",
            (bootstrap.FACTORY_SUPER_ADMIN_USERNAME,),
        ).fetchone()
    finally:
        conn.close()


def _count(sql: str, params: tuple = ()) -> int:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def _verify_link(client, url: str):
    return client.post("/api/v1/auth/magic-link/verify",
                       json={"token": _token_from(url)})


def _complete_wizard(client) -> list[str]:
    """Set password + enrol TOTP on the client's current session. Returns
    the backup codes issued by enrolment."""
    r = client.post("/api/v1/auth/password/change",
                    json={"new_password": _NEW_PASSWORD})
    assert r.status_code == 200, r.text
    r = client.post("/api/v1/auth/totp/enroll/begin")
    assert r.status_code == 200, r.text
    begin = r.json()
    r = client.post("/api/v1/auth/totp/enroll/complete", json={
        "pending_token": begin["pending_token"],
        "totp_code": pyotp.TOTP(begin["secret_b32"]).now(),
    })
    assert r.status_code == 200, r.text
    return r.json()["backup_codes"]


# ---------------------------------------------------------------------------
# provision_factory_super_admin_if_empty
# ---------------------------------------------------------------------------

def test_factory_provisioned_when_operators_empty(auth_data_root):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert creds is not None
    assert creds["username"] == bootstrap.FACTORY_SUPER_ADMIN_USERNAME == "Root"
    assert creds["email"] == bootstrap.FACTORY_SUPER_ADMIN_EMAIL
    assert creds["is_factory_super_admin"] is True
    assert creds["must_change_password"] is True
    assert "/login/magic?token=" in creds["magic_link_url"]
    assert creds["magic_link_expires_at"]
    # Magic-link-only: nothing else that could authenticate is returned.
    for key in ("initial_password", "totp_secret_b32", "totp_uri",
                "backup_codes", "admin_bearer_token"):
        assert key not in creds, key


def test_factory_skipped_when_operator_exists(auth_client):
    # auth_client fixture provisions an operator, so operators is non-empty.
    auth_client.provision_operator("alice", "pw1234567890")
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert creds is None


def test_factory_provisioning_is_idempotent(auth_data_root):
    first = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    second = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert first is not None
    assert second is None
    # Only one factory operator row, even though we tried to call twice
    conn = sqlite3.connect(paths.registry_db_path())
    n = conn.execute(
        "SELECT COUNT(*) FROM operators WHERE username = ?",
        (bootstrap.FACTORY_SUPER_ADMIN_USERNAME,),
    ).fetchone()[0]
    conn.close()
    assert n == 1


def test_factory_has_super_admin_role(auth_data_root):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    conn = sqlite3.connect(paths.registry_db_path())
    roles = conn.execute(
        "SELECT r.role_name FROM operator_roles r "
        "JOIN operators o ON o.id = r.operator_id "
        "WHERE o.username = ?",
        (bootstrap.FACTORY_SUPER_ADMIN_USERNAME,),
    ).fetchall()
    conn.close()
    assert ("super_admin",) in roles


def test_factory_has_initial_setup_magic_link(auth_data_root):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    conn = sqlite3.connect(paths.registry_db_path())
    rows = conn.execute(
        "SELECT m.purpose, m.expires_at, m.used_at FROM magic_link_tokens m "
        "JOIN operators o ON o.id = m.operator_id "
        "WHERE o.username = ?",
        (bootstrap.FACTORY_SUPER_ADMIN_USERNAME,),
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    purpose, expires_at, used_at = rows[0]
    assert purpose == "initial-setup"
    assert used_at is None
    assert expires_at == creds["magic_link_expires_at"]
    # 24h TTL — should expire within 23-25 hours from now
    exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    delta = exp - datetime.now(timezone.utc)
    assert timedelta(hours=23) < delta < timedelta(hours=25)


def test_factory_row_is_pre_setup_state(auth_data_root):
    """No password, no MFA, no backup codes — nothing to log in with."""
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    row = _factory_row()
    assert row["password_hash"] is None
    assert row["password_changed_at"] is None
    assert row["must_change_password"] == 1
    assert row["mfa_enabled"] == 0
    assert row["mfa_secret_enc"] is None
    assert row["is_factory"] == 1
    assert _count(
        "SELECT COUNT(*) FROM backup_code_sets WHERE operator_id = ?",
        (row["id"],),
    ) == 0


def test_no_well_known_default_password_exists():
    assert not hasattr(bootstrap, "FACTORY_SUPER_ADMIN_PASSWORD")
    import inspect
    sig = inspect.signature(bootstrap.provision_super_admin)
    assert "initial_password" not in sig.parameters


def test_print_credentials_writes_recognizable_block(auth_data_root):
    buf = io.StringIO()
    with redirect_stdout(buf):
        creds = bootstrap.provision_factory_super_admin_if_empty(
            print_credentials=True,
        )
    out = buf.getvalue()
    assert "FACTORY SUPER_ADMIN PROVISIONED" in out
    assert "Username:" in out
    assert bootstrap.FACTORY_SUPER_ADMIN_USERNAME in out
    assert "Setup link:" in out
    assert creds["magic_link_url"] in out
    assert creds["magic_link_expires_at"] in out
    # Next steps: open link -> set password -> scan QR
    assert "Open the link" in out
    assert "Set a password" in out
    assert "Scan the QR" in out
    assert "--reset-factory-admin" in out
    # Nothing else secret
    for forbidden in ("Initial password", "TOTP secret", "TOTP setup URI",
                      "otpauth://", "Backup codes (", "calvin",
                      _OLD_DEFAULT_PASSWORD):
        assert forbidden not in out, forbidden


def test_recovery_note_matches_behaviour(auth_data_root):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    note = creds["recovery_note"]
    assert "magic link" in note
    assert "--reset-factory-admin" in note
    assert "Default credentials" not in note
    assert _OLD_DEFAULT_PASSWORD not in note


# ---------------------------------------------------------------------------
# No way in without the link
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("password", [
    _OLD_DEFAULT_PASSWORD, "", " ", "Root", "x" * 40,
])
def test_password_begin_never_yields_session_or_challenge(auth_client, password):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "password": password,
    })
    # Empty string is refused by request validation; the rest by the
    # no-password-hash reject. Either way: no session, no challenge.
    assert r.status_code in (401, 422), r.text
    if r.status_code == 401:
        assert r.json()["code"] == "AUTH_PASSWORD_INVALID"
    assert "challenge_id" not in r.json()
    assert "athena_session" not in r.cookies
    assert "athena_session" not in auth_client.cookies
    row = _factory_row()
    assert row["failed_login_count"] == 0      # no lockout DoS pre-setup
    assert row["locked_until"] is None
    assert _count("SELECT COUNT(*) FROM sessions") == 0


@pytest.mark.parametrize("identifier", [
    bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
    bootstrap.FACTORY_SUPER_ADMIN_EMAIL,
    bootstrap.FACTORY_SUPER_ADMIN_EMAIL.upper(),
])
def test_forgot_password_mints_nothing_for_factory(
    auth_client, monkeypatch, identifier,
):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    sent: list = []
    monkeypatch.setattr(auth_router.email_sender, "send_email",
                        lambda *a, **kw: sent.append((a, kw)) or True)

    r = auth_client.post("/api/v1/auth/password/forgot",
                         json={"identifier": identifier})
    assert r.status_code == 200, r.text
    miss = auth_client.post("/api/v1/auth/password/forgot",
                            json={"identifier": "nobody@example.test"})
    assert r.json() == miss.json()             # indistinguishable from a miss

    assert sent == []
    assert _count("SELECT COUNT(*) FROM magic_link_tokens "
                  "WHERE purpose = 'password-reset'") == 0


def test_forgot_password_stays_off_while_placeholder_email(
    auth_client, monkeypatch,
):
    """Even after setup (password + MFA set), the undeliverable placeholder
    address never gets a reset token."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    sent: list = []
    monkeypatch.setattr(auth_router.email_sender, "send_email",
                        lambda *a, **kw: sent.append((a, kw)) or True)

    r = auth_client.post(
        "/api/v1/auth/password/forgot",
        json={"identifier": bootstrap.FACTORY_SUPER_ADMIN_USERNAME},
    )
    assert r.status_code == 200, r.text
    assert sent == []
    assert _count("SELECT COUNT(*) FROM magic_link_tokens "
                  "WHERE purpose = 'password-reset'") == 0


def test_magic_link_request_needs_a_session(auth_client):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    r = auth_client.post("/api/v1/auth/magic-link/request", json={
        "target_username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "purpose": "re-auth", "reason": "anonymous caller",
    })
    assert r.status_code == 401, r.text
    assert _count("SELECT COUNT(*) FROM magic_link_tokens") == 1  # bootstrap's


# ---------------------------------------------------------------------------
# Magic link → setup wizard (password THEN TOTP), gated throughout
# ---------------------------------------------------------------------------

def test_magic_link_session_gated_until_password_and_totp(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )

    r = _verify_link(auth_client, creds["magic_link_url"])
    assert r.status_code == 200, r.text
    assert "athena_session" in r.cookies

    me = auth_client.get("/api/v1/auth/me").json()
    assert me["needs_setup"] is True
    assert me["must_change_password"] is True
    assert me["mfa_enabled"] is False

    r = auth_client.get(_GATED_PATH)
    assert r.status_code == 403
    assert r.json()["code"] == "SETUP_REQUIRED"

    # Step 1 — set the initial password (no current_password: none exists).
    r = auth_client.post("/api/v1/auth/password/change",
                         json={"new_password": _NEW_PASSWORD})
    assert r.status_code == 200, r.text

    # Password alone is NOT enough — still gated until TOTP is enrolled.
    me = auth_client.get("/api/v1/auth/me").json()
    assert me["must_change_password"] is False
    assert me["mfa_enabled"] is False
    assert me["needs_setup"] is True
    r = auth_client.get(_GATED_PATH)
    assert r.status_code == 403
    assert r.json()["code"] == "SETUP_REQUIRED"

    # Step 2 — enrol TOTP (the QR wizard); backup codes issued here.
    r = auth_client.post("/api/v1/auth/totp/enroll/begin")
    assert r.status_code == 200, r.text
    begin = r.json()
    assert begin["otpauth_uri"].startswith("otpauth://")
    r = auth_client.post("/api/v1/auth/totp/enroll/complete", json={
        "pending_token": begin["pending_token"],
        "totp_code": pyotp.TOTP(begin["secret_b32"]).now(),
    })
    assert r.status_code == 200, r.text
    assert len(r.json()["backup_codes"]) == 8

    me = auth_client.get("/api/v1/auth/me").json()
    assert me["needs_setup"] is False
    assert me["mfa_enabled"] is True
    assert auth_client.get(_GATED_PATH).status_code == 200

    # Single use — the printed link is dead now.
    auth_client.cookies.clear()
    r = _verify_link(auth_client, creds["magic_link_url"])
    assert r.status_code == 401
    assert "athena_session" not in r.cookies


def test_totp_enrolment_is_refused_until_a_password_is_set(auth_client):
    """Password first. TOTP-then-lost-session on a password-less account has
    no way back except a destructive reset; password-then-lost-session
    resumes via /password/begin. So the half-way state that cannot resume
    must be unreachable — even for a direct API caller."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200

    r = auth_client.post("/api/v1/auth/totp/enroll/begin")
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "AUTH_PASSWORD_REQUIRED_FIRST"
    assert _factory_row()["mfa_enabled"] == 0


def test_password_set_then_lost_session_resumes_the_wizard(auth_client):
    """Close the browser after the password step: signing in with the new
    password yields a setup-confined session that can finish TOTP."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    r = auth_client.post("/api/v1/auth/password/change",
                         json={"new_password": _NEW_PASSWORD})
    assert r.status_code == 200, r.text
    auth_client.cookies.clear()

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "password": _NEW_PASSWORD,
    })
    assert r.status_code == 200, r.text
    assert r.json()["requires_totp"] is False          # setup-bound session
    assert auth_client.get(_GATED_PATH).status_code == 403

    begin = auth_client.post("/api/v1/auth/totp/enroll/begin")
    assert begin.status_code == 200, begin.text
    r = auth_client.post("/api/v1/auth/totp/enroll/complete", json={
        "pending_token": begin.json()["pending_token"],
        "totp_code": pyotp.TOTP(begin.json()["secret_b32"]).now(),
    })
    assert r.status_code == 200, r.text
    assert auth_client.get(_GATED_PATH).status_code == 200


def test_setup_session_cannot_register_a_passkey(auth_client):
    """The setup gate's passkey bypass covers SIGN-IN only; a setup-confined
    session must not be able to plant a passkey before finishing setup."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    r = auth_client.post("/api/v1/auth/passkey/register/begin")
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "SETUP_REQUIRED"


def test_after_setup_login_is_password_plus_totp(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    auth_client.cookies.clear()

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "password": _NEW_PASSWORD,
    })
    assert r.status_code == 200, r.text
    assert r.json()["requires_totp"] is True
    assert "athena_session" not in r.cookies


# ---------------------------------------------------------------------------
# Already-deployed factory accounts are untouched
# ---------------------------------------------------------------------------

def test_existing_factory_account_untouched_and_still_logs_in(auth_client):
    """A bundle deployed before this change has a factory row WITH a
    password hash + mfa_enabled=1. App start / migrations / a bootstrap
    re-run must not alter it, and password+TOTP sign-in keeps working."""
    op = auth_client.provision_operator(
        bootstrap.FACTORY_SUPER_ADMIN_USERNAME, "legacy-rotated-password",
        email=bootstrap.FACTORY_SUPER_ADMIN_EMAIL, is_factory=True,
    )
    before = dict(_factory_row())

    assert bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    ) is None
    bootstrap.init_data_root()
    bootstrap.ensure_registry_migrations_applied(paths.registry_db_path())
    from apps.octo.api import create_app
    create_app()

    assert dict(_factory_row()) == before
    assert before["password_hash"] and before["mfa_enabled"] == 1

    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["requires_totp"] is True
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": r.json()["challenge_id"],
        "totp_code": pyotp.TOTP(op["totp_secret_b32"]).now(),
    })
    assert r.status_code == 200, r.text
    assert auth_client.get(_GATED_PATH).status_code == 200


# ---------------------------------------------------------------------------
# reset_factory_super_admin
# ---------------------------------------------------------------------------

def test_reset_factory_raises_when_missing(auth_data_root):
    with pytest.raises(RuntimeError, match="does not exist"):
        bootstrap.reset_factory_super_admin()


def test_reset_factory_reissues_magic_link_and_clears_lockout(auth_data_root):
    # Provision first
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    # Force lockout state on the factory account
    conn = sqlite3.connect(paths.registry_db_path())
    future = (datetime.now(timezone.utc) + timedelta(hours=1))
    future_iso = future.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{future.microsecond // 1000:03d}Z"
    conn.execute(
        "UPDATE operators SET failed_login_count = 9, locked_until = ?, "
        "must_change_password = 0 WHERE username = ?",
        (future_iso, bootstrap.FACTORY_SUPER_ADMIN_USERNAME),
    )
    conn.commit()
    conn.close()

    result = bootstrap.reset_factory_super_admin()
    assert result["username"] == bootstrap.FACTORY_SUPER_ADMIN_USERNAME
    assert "/login/magic?token=" in result["magic_link_url"]

    # Lockout cleared, must_change_password forced back on
    row = _factory_row()
    assert row["failed_login_count"] == 0
    assert row["locked_until"] is None
    assert row["must_change_password"] == 1
    # Exactly one live link: the new one (the bootstrap link was burned)
    assert _count(
        "SELECT COUNT(*) FROM magic_link_tokens "
        "WHERE operator_id = ? AND purpose = 'initial-setup' "
        "AND used_at IS NULL",
        (row["id"],),
    ) == 1


def test_reset_returns_fully_set_up_account_to_factory_state(auth_client):
    """Password, MFA, backup codes, sessions and stale links all go; the
    new link leads back into the same wizard."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    assert auth_client.get(_GATED_PATH).status_code == 200
    op_id = _factory_row()["id"]
    # A stale, still-unused link from an earlier reset.
    stale = bootstrap.reset_factory_super_admin()
    # reset revoked the session — sign back in and finish setup again so
    # there is real state to clear.
    auth_client.cookies.clear()
    assert _verify_link(auth_client, stale["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    live_cookie = auth_client.cookies.get("athena_session")
    assert live_cookie
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute(
        "INSERT INTO magic_link_tokens "
        "(token_hash, operator_id, issued_at, expires_at, purpose) "
        "SELECT 'x' || token_hash, operator_id, issued_at, expires_at, "
        "'re-auth' FROM magic_link_tokens WHERE operator_id = ? LIMIT 1",
        (op_id,),
    )
    conn.commit()
    conn.close()

    result = bootstrap.reset_factory_super_admin()

    row = _factory_row()
    assert row["password_hash"] is None
    assert row["password_changed_at"] is None
    assert row["must_change_password"] == 1
    assert row["mfa_enabled"] == 0
    assert row["mfa_secret_enc"] is None
    assert row["is_factory"] == 1
    assert _count(
        "SELECT COUNT(*) FROM backup_code_sets "
        "WHERE operator_id = ? AND revoked_at IS NULL", (op_id,),
    ) == 0
    assert _count(
        "SELECT COUNT(*) FROM backup_code_sets WHERE operator_id = ? "
        "AND revoke_reason = 'admin-revoke'", (op_id,),
    ) >= 1
    assert _count(
        "SELECT COUNT(*) FROM sessions "
        "WHERE operator_id = ? AND revoked_at IS NULL", (op_id,),
    ) == 0
    assert _count(
        "SELECT COUNT(*) FROM magic_link_tokens "
        "WHERE operator_id = ? AND used_at IS NULL", (op_id,),
    ) == 1

    # The old session is dead.
    assert auth_client.get("/api/v1/auth/me").status_code == 401
    auth_client.cookies.clear()
    # The old password is dead.
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "password": _NEW_PASSWORD,
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_PASSWORD_INVALID"
    assert "athena_session" not in r.cookies
    # Old links are dead (the consumed ones and the never-used one alike).
    for old in (creds["magic_link_url"], stale["magic_link_url"]):
        r = _verify_link(auth_client, old)
        assert r.status_code == 401, r.text
        assert "athena_session" not in r.cookies

    # The new link re-enters the wizard: gated until password AND TOTP.
    assert _verify_link(auth_client, result["magic_link_url"]).status_code == 200
    me = auth_client.get("/api/v1/auth/me").json()
    assert me["needs_setup"] is True
    assert me["must_change_password"] is True
    assert me["mfa_enabled"] is False
    assert auth_client.get(_GATED_PATH).status_code == 403
    _complete_wizard(auth_client)
    assert auth_client.get(_GATED_PATH).status_code == 200


def test_reset_burns_unused_bootstrap_link(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    bootstrap.reset_factory_super_admin()
    r = _verify_link(auth_client, creds["magic_link_url"])
    assert r.status_code == 401
    assert "athena_session" not in r.cookies


def test_reset_finds_renamed_factory_by_flag(auth_data_root):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute("UPDATE operators SET username = 'alice' WHERE is_factory = 1")
    conn.commit()
    conn.close()
    assert bootstrap.reset_factory_super_admin()["username"] == "alice"


def test_reset_factory_writes_audit_row(auth_data_root):
    bootstrap.provision_factory_super_admin_if_empty(print_credentials=False)
    bootstrap.reset_factory_super_admin()

    conn = sqlite3.connect(paths.global_audit_db_path())
    rows = conn.execute(
        "SELECT action, actor, json_extract(after_state, '$.lockout_cleared'), "
        "json_extract(after_state, '$.mfa_cleared'), "
        "json_extract(after_state, '$.password_cleared') "
        "FROM audit_log WHERE action = 'factory_recovery_initiated' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "factory_recovery_initiated"
    assert rows[0][1] == "system"
    assert rows[0][2] == 1
    assert rows[0][3] == 1
    assert rows[0][4] == 1



# ---------------------------------------------------------------------------
# Backup codes are a real fallback; an expired challenge says so
# ---------------------------------------------------------------------------

def _password_challenge(client) -> str:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": bootstrap.FACTORY_SUPER_ADMIN_USERNAME,
        "password": _NEW_PASSWORD,
    })
    assert r.status_code == 200, r.text
    return r.json()["challenge_id"]


def test_backup_code_signs_in_once_and_only_once(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    codes = _complete_wizard(auth_client)
    assert len(codes) == 8
    auth_client.cookies.clear()

    # lower-case and without dashes: what a person actually types
    typed = codes[0].replace("-", "").lower()
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": _password_challenge(auth_client), "totp_code": typed,
    })
    assert r.status_code == 200, r.text
    assert auth_client.get("/api/v1/auth/me").json()["backup_codes_remaining"] == 7
    auth_client.cookies.clear()

    # single-use
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": _password_challenge(auth_client), "totp_code": codes[0],
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_TOTP_INVALID"
    assert _factory_row()["failed_login_count"] == 1     # counts toward lockout


def test_unknown_backup_code_is_rejected_and_counted(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": _password_challenge(auth_client),
        "totp_code": "AAAA-BBBB-CCCC",
    })
    assert r.status_code == 401
    assert "athena_session" not in r.cookies
    assert _factory_row()["failed_login_count"] == 1


def test_expired_challenge_says_timed_out_not_wrong_code(auth_client, monkeypatch):
    """>5 min between password and code used to answer AUTH_TOTP_INVALID
    ('that code didn't match') forever, for a CORRECT code, without counting
    a failure — indistinguishable from a broken authenticator."""
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    auth_client.cookies.clear()
    challenge = _password_challenge(auth_client)

    monkeypatch.setattr(auth_router, "CHALLENGE_TTL_SECONDS", -1)
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": "000000",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_CHALLENGE_EXPIRED"
    assert _factory_row()["failed_login_count"] == 0

    # a forged / garbage challenge is still the generic error
    r = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": "not-a-real-challenge", "totp_code": "000000",
    })
    assert r.json()["code"] == "AUTH_TOTP_INVALID"


# ---------------------------------------------------------------------------
# Break-glass must work on a disabled / demoted factory account
# ---------------------------------------------------------------------------

def test_reset_reenables_and_regrants_super_admin(auth_client):
    creds = bootstrap.provision_factory_super_admin_if_empty(
        print_credentials=False,
    )
    assert _verify_link(auth_client, creds["magic_link_url"]).status_code == 200
    _complete_wizard(auth_client)
    auth_client.cookies.clear()

    # another super_admin disabled + demoted Root, then left
    reg = sqlite3.connect(paths.registry_db_path())
    op_id = _factory_row()["id"]
    reg.execute("UPDATE operators SET disabled_at = ? WHERE id = ?",
                ("2026-01-01T00:00:00.000Z", op_id))
    reg.execute("DELETE FROM operator_roles WHERE operator_id = ? "
                "AND role_name = 'super_admin'", (op_id,))
    reg.commit(); reg.close()

    new = bootstrap.reset_factory_super_admin()

    assert _factory_row()["disabled_at"] is None
    r = _verify_link(auth_client, new["magic_link_url"])
    assert r.status_code == 200, r.text                  # was 423 + burned link
    assert "super_admin" in r.json()["role"]
    assert auth_client.get(_GATED_PATH).status_code == 403   # wizard, not console


# ---------------------------------------------------------------------------
# Terminal QR of the setup link
# ---------------------------------------------------------------------------

_DEMO_LINK = "https://console.example.com/login/magic?token=" + "A" * 43


def test_link_qr_on_a_tty_uses_full_cells_and_a_spec_quiet_zone(monkeypatch, capsys):
    import sys
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    bootstrap._print_link_qr(_DEMO_LINK)
    rows = [l for l in capsys.readouterr().out.splitlines() if "\x1b[4" in l]
    assert len(rows) >= 21 + 8                      # smallest QR + 4+4 quiet rows
    assert all("\u2580" not in r and "\u2584" not in r for r in rows)   # no half blocks
    # first 4 rows are pure quiet zone: white cells only
    assert all("\x1b[40m" not in r for r in rows[:4])
    assert all(r.endswith("\x1b[0m") for r in rows)  # never leak colour into the terminal


def test_link_qr_never_raises(monkeypatch, capsys):
    import builtins
    real_import = builtins.__import__
    def no_qrcode(name, *a, **k):
        if name == "qrcode":
            raise ImportError("not installed")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_qrcode)
    bootstrap._print_link_qr(_DEMO_LINK)            # must not raise
    assert "use the link above" in capsys.readouterr().out

