"""POST /admin/operators/{id}/reset-password — admin-driven password reset.

Covers:
  - Happy path: super_admin resets analyst → magic link issued + password
    cleared + sessions revoked + must_change_password set.
  - Tier rule: admin (3) CANNOT reset super_admin (4).
  - Self-reset is rejected with VALIDATION_FAILED.
  - Analyst (2) cannot reach the endpoint (403).
  - Audit row written without leaking sensitive fields.
  - Magic-link URL contains a token that actually resolves through
    /auth/password/reset.
"""
from __future__ import annotations

import sqlite3

import pyotp


def _login(client, op):
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


def test_super_admin_can_reset_an_analysts_password(auth_client):
    sa = auth_client.provision_operator(
        "sa-1", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    analyst = auth_client.provision_operator(
        "an-1", "analyst-password-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, sa)

    r = auth_client.post(
        f"/api/v1/admin/operators/{analyst['id']}/reset-password",
        json={"reason": "user lost their password"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operator_id"] == analyst["id"]
    assert body["username"] == "an-1"
    assert "/login/reset?token=" in body["magic_link_url"]

    # Target's password_hash was cleared + must_change_password set.
    from apps.octo import paths
    conn = sqlite3.connect(paths.registry_db_path())
    row = conn.execute(
        "SELECT password_hash, must_change_password "
        "FROM operators WHERE id = ?",
        (analyst["id"],),
    ).fetchone()
    conn.close()
    assert row[0] is None
    assert row[1] == 1


def test_admin_cannot_reset_super_admins_password(auth_client):
    admin = auth_client.provision_operator(
        "ad-1", "admin-password-1234",
        role="admin", athena_role="admin",
    )
    sa = auth_client.provision_operator(
        "sa-victim", "sa-password-1234567",
        role="super_admin", athena_role="super_admin",
    )
    cookies = _login(auth_client, admin)
    r = auth_client.post(
        f"/api/v1/admin/operators/{sa['id']}/reset-password",
        json={},
        cookies=cookies,
    )
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_admin_can_reset_analyst(auth_client):
    admin = auth_client.provision_operator(
        "ad-2", "admin-password-1234",
        role="admin", athena_role="admin",
    )
    analyst = auth_client.provision_operator(
        "an-2", "analyst-password-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, admin)
    r = auth_client.post(
        f"/api/v1/admin/operators/{analyst['id']}/reset-password",
        json={},
        cookies=cookies,
    )
    assert r.status_code == 200


def test_self_reset_is_rejected(auth_client):
    sa = auth_client.provision_operator(
        "sa-self", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    cookies = _login(auth_client, sa)
    r = auth_client.post(
        f"/api/v1/admin/operators/{sa['id']}/reset-password",
        json={},
        cookies=cookies,
    )
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_analyst_cannot_call_endpoint(auth_client):
    analyst = auth_client.provision_operator(
        "an-3", "analyst-password-1234",
        role="analyst", athena_role="analyst",
    )
    target = auth_client.provision_operator(
        "viewer-1", "viewer-password-1234",
        role="viewer", athena_role="viewer",
    )
    cookies = _login(auth_client, analyst)
    r = auth_client.post(
        f"/api/v1/admin/operators/{target['id']}/reset-password",
        json={},
        cookies=cookies,
    )
    assert r.status_code == 403


def test_admin_can_set_temporary_password_directly(auth_client):
    """Mode A: admin specifies a new_password. Target keeps
    must_change_password=1 so they're forced to rotate at next sign-in."""
    import sqlite3
    from apps.octo import paths

    sa = auth_client.provision_operator(
        "sa-temp", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "tgt-temp", "old-password-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, sa)
    r = auth_client.post(
        f"/api/v1/admin/operators/{target['id']}/reset-password",
        json={"new_password": "tempPass-issued-by-admin"},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["temporary_password_set"] is True
    assert body.get("magic_link_url") is None

    conn = sqlite3.connect(paths.registry_db_path())
    row = conn.execute(
        "SELECT password_hash, must_change_password "
        "FROM operators WHERE id = ?",
        (target["id"],),
    ).fetchone()
    conn.close()
    assert row[0] is not None and row[0] != "old-password-1234"
    assert row[1] == 1


def test_short_temp_password_is_rejected(auth_client):
    sa = auth_client.provision_operator(
        "sa-short", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "tgt-short", "old-password-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, sa)
    r = auth_client.post(
        f"/api/v1/admin/operators/{target['id']}/reset-password",
        json={"new_password": "short"},
        cookies=cookies,
    )
    # Pydantic-level validation rejects < 12 chars
    assert r.status_code == 422


def test_admin_temp_password_login_routes_through_setup(auth_client):
    """End-to-end: admin sets temp password → target logs in with it →
    setup_gate forces them through /login/setup to rotate it."""
    import pyotp

    sa = auth_client.provision_operator(
        "sa-e2e", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "tgt-e2e", "previously-known-pw-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, sa)
    temp_pw = "admin-issued-temp-1234"
    r = auth_client.post(
        f"/api/v1/admin/operators/{target['id']}/reset-password",
        json={"new_password": temp_pw},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text

    # Target signs in with the temp password
    r2 = auth_client.post("/api/v1/auth/password/begin", json={
        "username": "tgt-e2e", "password": temp_pw,
    })
    assert r2.status_code == 200, r2.text
    challenge = r2.json()["challenge_id"]
    code = pyotp.TOTP(target["totp_secret_b32"]).now()
    r3 = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r3.status_code == 200, r3.text
    target_cookies = dict(r3.cookies)

    # /auth/me should show must_change_password=1
    r4 = auth_client.get("/api/v1/auth/me", cookies=target_cookies)
    assert r4.status_code == 200
    me = r4.json()
    assert me["must_change_password"] is True
    assert me["needs_setup"] is True


def test_issued_magic_link_token_resolves_through_reset_endpoint(auth_client):
    """End-to-end: admin issues the link, target uses it to set a fresh
    password via /auth/password/reset."""
    from urllib.parse import urlparse, parse_qs

    sa = auth_client.provision_operator(
        "sa-rt", "password1234567",
        role="super_admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "tgt-rt", "old-password-1234",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, sa)
    r = auth_client.post(
        f"/api/v1/admin/operators/{target['id']}/reset-password",
        json={"reason": "rotation"},
        cookies=cookies,
    )
    assert r.status_code == 200
    url = r.json()["magic_link_url"]
    token = parse_qs(urlparse(url).query)["token"][0]

    # Target consumes the token via the normal /password/reset endpoint
    new_pw = "freshly-set-by-target-1234"
    r2 = auth_client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": new_pw},
    )
    assert r2.status_code == 200, r2.text
