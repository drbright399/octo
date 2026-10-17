"""Adapter-credentials vault — round-trip + key-file hygiene."""
from __future__ import annotations

import os
import re
import stat

import pytest
from cryptography.fernet import Fernet

from apps.octo import credentials
from apps.octo.credentials import vault


@pytest.fixture
def isolated_key(monkeypatch, tmp_path):
    """Point the vault at a tmp key file. Auto-cleans on teardown."""
    key_path = tmp_path / "adapter-credentials-key.env"
    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(key_path))
    return key_path


def test_ensure_key_file_creates_when_missing(isolated_key):
    """First boot: file doesn't exist → create it with the expected
    contents + mode 600."""
    assert not isolated_key.exists()
    path = credentials.ensure_key_file()
    assert path == isolated_key
    assert isolated_key.exists()

    body = isolated_key.read_text()
    assert "ADAPTER_CREDENTIALS_KEY_VERSION=v1" in body
    assert re.search(r"ADAPTER_CREDENTIALS_KEY_BASE64=\S+", body)

    mode = stat.S_IMODE(isolated_key.stat().st_mode)
    assert mode == 0o600, f"expected mode 0o600, got {oct(mode)}"


def test_ensure_key_file_is_idempotent(isolated_key):
    """Calling it twice doesn't rotate the key — second call is a no-op."""
    credentials.ensure_key_file()
    original_body = isolated_key.read_text()
    credentials.ensure_key_file()
    assert isolated_key.read_text() == original_body


def test_round_trip_recovers_exact_dict(isolated_key):
    credentials.ensure_key_file()
    payload = {
        "DATTO_API_URL": "https://exampleplat-api.centrastage.net",
        "DATTO_API_KEY": "pub-key-fixture",
        "DATTO_API_SECRET_KEY": "sec-key-fixture-with-=padding=",
    }
    ref = credentials.store(payload)
    assert isinstance(ref, str) and ref.startswith("v1:")
    assert credentials.load(ref) == payload


def test_ciphertext_is_versioned(isolated_key):
    """Ref always carries the key version so future rotations can route
    decryption to the right key."""
    credentials.ensure_key_file()
    ref = credentials.store({"k": "v"})
    assert re.match(r"^v\d+:[A-Za-z0-9_=\-]+$", ref), ref


def test_load_rejects_malformed_ref(isolated_key):
    credentials.ensure_key_file()
    with pytest.raises(ValueError):
        credentials.load("not-a-versioned-token")


def test_load_rejects_tampered_ciphertext(isolated_key):
    credentials.ensure_key_file()
    ref = credentials.store({"k": "v"})
    # Flip a character in the token body — Fernet's MAC should reject it.
    head, _, tail = ref.partition(":")
    tampered = f"{head}:{tail[:-1]}{'A' if tail[-1] != 'A' else 'B'}"
    with pytest.raises(Exception):
        credentials.load(tampered)


def test_store_rejects_non_dict(isolated_key):
    credentials.ensure_key_file()
    with pytest.raises(TypeError):
        credentials.store("not-a-dict")  # type: ignore[arg-type]


def test_load_hard_fails_when_key_missing(isolated_key):
    """Hard-fail (not silent fallback) is the intended posture per the
    auth crypto module's documented stance."""
    # Don't call ensure_key_file
    with pytest.raises(FileNotFoundError):
        credentials.load("v1:anything")


def test_key_file_path_respects_env_override(monkeypatch, tmp_path):
    override = tmp_path / "elsewhere.env"
    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(override))
    assert vault.key_file_path() == override.resolve()


def test_ensure_key_file_does_not_overwrite_existing(isolated_key):
    """Operator-provisioned key (mode 600, valid content) survives an
    accidental ensure_key_file() call."""
    isolated_key.parent.mkdir(parents=True, exist_ok=True)
    pre_written = (
        "ADAPTER_CREDENTIALS_KEY_VERSION=v1\n"
        f"ADAPTER_CREDENTIALS_KEY_BASE64={Fernet.generate_key().decode()}\n"
    )
    isolated_key.write_text(pre_written)
    os.chmod(isolated_key, 0o600)
    credentials.ensure_key_file()
    assert isolated_key.read_text() == pre_written
