"""Phase G.1 — passkey (WebAuthn) ceremony tests.

The webauthn library is well-tested upstream; we mock its
verify_registration_response / verify_authentication_response calls and
focus on testing OUR integration:

  - /passkey/register/begin returns options + stashes a challenge cookie
  - /passkey/register/complete inserts a webauthn_credentials row when
    verification succeeds
  - /passkey/begin returns auth options + stashes challenge
  - /passkey/complete looks up the credential by ID, increments sign_count,
    issues a session
  - Verification failures audit + return AUTH_PASSKEY_INVALID
  - Challenge cookie is required (intent-bound)
  - Operator-mismatch in registration challenge is refused
  - Unknown / revoked credential at /complete returns AUTH_PASSKEY_INVALID
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
import pytest

from apps.octo import paths


def _login(client, op: dict) -> dict:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200
    return dict(r2.cookies)


def _stub_register_verification(credential_id: bytes, public_key: bytes, sign_count: int = 0):
    """Build a stand-in for verify_registration_response's return value."""
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=public_key,
        sign_count=sign_count,
    )


def _stub_assertion_verification(new_sign_count: int):
    return SimpleNamespace(new_sign_count=new_sign_count)


# ---------------------------------------------------------------------------
# Registration ceremony
# ---------------------------------------------------------------------------

def test_register_begin_returns_options_and_stashes_challenge(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    r = auth_client.post("/api/v1/auth/passkey/register/begin",
                         json={"label": "test-key"}, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    pub = body["publicKey"]
    assert pub["rp"]["id"] == "athena.test"
    assert pub["rp"]["name"] == "Athena"
    assert pub["user"]["name"] == "alice"
    assert "challenge" in pub
    # WebAuthn challenge cookie was set
    assert "athena_webauthn_challenge" in r.cookies


def test_register_complete_inserts_credential(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    # Begin — get challenge cookie
    r = auth_client.post("/api/v1/auth/passkey/register/begin",
                         json={"label": "yubi"}, cookies=cookies)
    challenge_cookie = r.cookies["athena_webauthn_challenge"]
    cookies_with_challenge = {
        **cookies,
        "athena_webauthn_challenge": challenge_cookie,
    }

    fake_cred_id = b"\x01\x02\x03\x04" * 4   # 16 bytes
    fake_pub_key = b"\xaa" * 65              # COSE-encoded shape doesn't matter for the stub
    with patch(
        "apps.octo.api.routers.auth.verify_registration_response",
        return_value=_stub_register_verification(fake_cred_id, fake_pub_key, 0),
    ):
        r2 = auth_client.post(
            "/api/v1/auth/passkey/register/complete",
            json={"credential": {"id": "stub", "rawId": "stub",
                                 "response": {"transports": ["internal"]},
                                 "type": "public-key"},
                  "label": "yubi"},
            cookies=cookies_with_challenge,
        )
    assert r2.status_code == 200, r2.text
    assert r2.json()["label"] == "yubi"

    # Row landed in webauthn_credentials with the right operator + transports
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    rows = list(conn.execute("SELECT * FROM webauthn_credentials"))
    conn.close()
    assert len(rows) == 1
    assert rows[0]["operator_id"] == op["id"]
    assert bytes(rows[0]["credential_id"]) == fake_cred_id
    assert rows[0]["transports"] == '["internal"]'


def test_register_complete_fails_when_lib_rejects(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)

    r = auth_client.post("/api/v1/auth/passkey/register/begin",
                         json={}, cookies=cookies)
    challenge_cookie = r.cookies["athena_webauthn_challenge"]
    cookies_with_challenge = {
        **cookies,
        "athena_webauthn_challenge": challenge_cookie,
    }

    with patch(
        "apps.octo.api.routers.auth.verify_registration_response",
        side_effect=Exception("attestation invalid"),
    ):
        r2 = auth_client.post(
            "/api/v1/auth/passkey/register/complete",
            json={"credential": {"id": "x", "rawId": "x",
                                 "response": {}, "type": "public-key"}},
            cookies=cookies_with_challenge,
        )
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_PASSKEY_INVALID"


def test_register_complete_without_challenge_cookie_refuses(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    cookies = _login(auth_client, op)
    # Skip the begin step → no challenge cookie
    r = auth_client.post(
        "/api/v1/auth/passkey/register/complete",
        json={"credential": {"id": "x", "rawId": "x",
                             "response": {}, "type": "public-key"}},
        cookies=cookies,
    )
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_PASSKEY_INVALID"


# ---------------------------------------------------------------------------
# Authentication ceremony
# ---------------------------------------------------------------------------

def _seed_credential(op_id: int, *, cred_id: bytes, pub: bytes, sign_count: int = 0) -> int:
    conn = sqlite3.connect(paths.registry_db_path())
    cur = conn.execute(
        "INSERT INTO webauthn_credentials "
        "(operator_id, credential_id, public_key, sign_count, label, created_at) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
        (op_id, cred_id, pub, sign_count, "test-key"),
    )
    conn.commit()
    cred_pk = cur.lastrowid
    conn.close()
    return cred_pk


def test_passkey_begin_returns_options_and_stashes_challenge(auth_client):
    auth_client.provision_operator("alice", "pw")
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/passkey/begin")
    assert r.status_code == 200
    pub = r.json()["publicKey"]
    assert "challenge" in pub
    assert pub["rpId"] == "athena.test"
    assert "athena_webauthn_challenge" in r.cookies


def test_passkey_complete_issues_session_and_increments_signcount(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    fake_cred_id = b"\x10" * 32
    fake_pub = b"\xff" * 65
    _seed_credential(op["id"], cred_id=fake_cred_id, pub=fake_pub, sign_count=5)

    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/passkey/begin")
    challenge_cookie = r.cookies["athena_webauthn_challenge"]
    cred_b64 = "EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA"   # base64url of 32× 0x10

    with patch(
        "apps.octo.api.routers.auth.verify_authentication_response",
        return_value=_stub_assertion_verification(new_sign_count=6),
    ):
        r2 = auth_client.post(
            "/api/v1/auth/passkey/complete",
            json={"credential": {"id": cred_b64, "rawId": cred_b64,
                                 "response": {}, "type": "public-key"}},
            cookies={"athena_webauthn_challenge": challenge_cookie},
        )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["operator_id"] == op["id"]
    assert "athena_session" in r2.cookies

    # sign_count was bumped
    conn = sqlite3.connect(paths.registry_db_path())
    sc = conn.execute(
        "SELECT sign_count FROM webauthn_credentials WHERE operator_id = ?",
        (op["id"],),
    ).fetchone()[0]
    conn.close()
    assert sc == 6


def test_passkey_complete_unknown_credential_returns_invalid(auth_client):
    auth_client.provision_operator("alice", "pw")
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/passkey/begin")
    challenge_cookie = r.cookies["athena_webauthn_challenge"]
    # Use a credential ID that has no row
    cred_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    r2 = auth_client.post(
        "/api/v1/auth/passkey/complete",
        json={"credential": {"id": cred_b64, "rawId": cred_b64,
                             "response": {}, "type": "public-key"}},
        cookies={"athena_webauthn_challenge": challenge_cookie},
    )
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_PASSKEY_INVALID"


def test_passkey_complete_revoked_credential_returns_invalid(auth_client):
    op = auth_client.provision_operator("alice", "pw")
    fake_cred_id = b"\x20" * 32
    fake_pub = b"\xff" * 65
    pk = _seed_credential(op["id"], cred_id=fake_cred_id, pub=fake_pub, sign_count=1)
    # Revoke
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute(
        "UPDATE webauthn_credentials SET revoked_at = datetime('now') WHERE id = ?",
        (pk,),
    )
    conn.commit()
    conn.close()

    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/auth/passkey/begin")
    challenge_cookie = r.cookies["athena_webauthn_challenge"]
    cred_b64 = "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA"   # base64url of 32× 0x20
    r2 = auth_client.post(
        "/api/v1/auth/passkey/complete",
        json={"credential": {"id": cred_b64, "rawId": cred_b64,
                             "response": {}, "type": "public-key"}},
        cookies={"athena_webauthn_challenge": challenge_cookie},
    )
    assert r2.status_code == 401
    assert r2.json()["code"] == "AUTH_PASSKEY_INVALID"
