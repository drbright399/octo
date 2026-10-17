"""The login-challenge and pending-TOTP-enrolment Fernet keys are derived from
the MFA master key exactly as before the `_mfa_subkey_fernet` refactor:

    SHA-256(base64url-decoded 32-byte master key || label)

with the labels b"auth-challenge-v1" and b"totp-enroll-v1". The derivation is
spelled out independently here (not via the code under test), so:

  * a token issued by the previous release still verifies after a deploy
    (in-flight sign-ins and enrolments are not broken), and the other way round;
  * any change to the derivation or a label fails here, loudly;
  * the two labels still give two different keys (no cross-replay).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

import pytest
from cryptography.fernet import Fernet

from apps.octo.api.errors import APIError
from apps.octo.api.routers import auth

CHALLENGE_LABEL = b"auth-challenge-v1"
ENROLL_LABEL = b"totp-enroll-v1"


@pytest.fixture
def master_key(monkeypatch, tmp_path) -> bytes:
    """A fresh MFA key file (minted at runtime); returns the raw 32 bytes."""
    key_b64 = Fernet.generate_key()
    path = tmp_path / "mfa-key.env"
    path.write_text(f"MFA_KEY_VERSION=v1\nMFA_KEY_BASE64={key_b64.decode()}\n")
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(path))
    raw = base64.urlsafe_b64decode(key_b64)
    assert len(raw) == 32
    return raw


def _expected_subkey(master: bytes, label: bytes) -> bytes:
    return hashlib.sha256(master + label).digest()


def _previous_release_fernet(master: bytes, label: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_expected_subkey(master, label)))


def _key_bytes(f: Fernet) -> bytes:
    # Fernet splits its 32-byte key: signing key (first 16) + encryption key.
    return f._signing_key + f._encryption_key


@pytest.mark.parametrize("builder,label", [
    ("_challenge_fernet", CHALLENGE_LABEL),
    ("_totp_pending_fernet", ENROLL_LABEL),
])
def test_subkey_is_byte_identical_to_the_previous_derivation(master_key, builder, label):
    derived = _key_bytes(getattr(auth, builder)())
    assert derived == _expected_subkey(master_key, label)
    assert derived == _key_bytes(auth._mfa_subkey_fernet(label))


def test_the_two_labels_give_different_keys(master_key):
    assert _key_bytes(auth._challenge_fernet()) != _key_bytes(auth._totp_pending_fernet())


def test_a_login_challenge_issued_by_the_previous_release_still_verifies(master_key):
    old = _previous_release_fernet(master_key, CHALLENGE_LABEL)
    token = old.encrypt(json.dumps({"op": 7, "iat": int(time.time())}).encode()).decode()
    assert auth._verify_challenge(token) == 7


def test_a_login_challenge_issued_now_opens_under_the_previous_key(master_key):
    token = auth._issue_challenge(7)
    old = _previous_release_fernet(master_key, CHALLENGE_LABEL)
    assert json.loads(old.decrypt(token.encode()))["op"] == 7


def test_a_pending_enrolment_token_issued_by_the_previous_release_still_verifies(master_key):
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
    old = _previous_release_fernet(master_key, ENROLL_LABEL)
    token = old.encrypt(json.dumps({
        "op": 7, "secret": totp_secret, "iat": int(time.time()),
    }).encode()).decode()
    assert auth._verify_totp_pending_token(token, 7) == totp_secret


def test_a_pending_enrolment_token_issued_now_opens_under_the_previous_key(master_key):
    totp_secret = base64.b32encode(secrets.token_bytes(20)).decode()
    token = auth._issue_totp_pending_token(7, totp_secret)
    old = _previous_release_fernet(master_key, ENROLL_LABEL)
    assert json.loads(old.decrypt(token.encode()))["secret"] == totp_secret


def test_a_login_challenge_is_not_accepted_as_an_enrolment_token(master_key):
    with pytest.raises(APIError):
        auth._verify_totp_pending_token(auth._issue_challenge(7), 7)
