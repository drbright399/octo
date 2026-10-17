"""Tests for sanitized_pool.identity (M2 control).

Covers:
  - provision_hmac_secret() writes a file with mode 600
  - load_hmac_secret() round-trips
  - tenant_hmac() is deterministic + produces a 64-char hex string
  - Different slugs produce different HMACs
  - Same slug under DIFFERENT secrets produces different HMACs
    (the own-tenant pre-image attack is defeated)
  - reset_cache() forces re-load
  - Refuses to overwrite without force=True
"""
from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

import pytest

from apps.octo.sanitized_pool import identity


@pytest.fixture
def secret_path(monkeypatch, tmp_path) -> Path:
    """Point the module at a tmp secrets file + clear the module cache."""
    path = tmp_path / "secrets" / "sanitized-pool-hmac.env"
    monkeypatch.setenv("OCTO_SANITIZED_POOL_HMAC_PATH", str(path))
    identity.reset_cache()
    yield path
    identity.reset_cache()


def test_provision_writes_file_with_mode_600(secret_path: Path) -> None:
    info = identity.provision_hmac_secret()
    assert info["version"] == "v1"
    assert int(info["bytes_written"]) > 0
    assert secret_path.exists()
    # Mode 600 — owner read+write only.
    mode = stat.S_IMODE(secret_path.stat().st_mode)
    assert mode == 0o600, f"expected 0o600 mode, got {oct(mode)}"


def test_provision_refuses_to_overwrite(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    with pytest.raises(FileExistsError):
        identity.provision_hmac_secret()


def test_provision_force_overwrites(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    first_content = secret_path.read_text()
    identity.reset_cache()
    identity.provision_hmac_secret(force=True)
    second_content = secret_path.read_text()
    # New random secret → file content differs.
    assert first_content != second_content


def test_load_round_trip(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    version, secret = identity.load_hmac_secret()
    assert version == "v1"
    assert len(secret) == identity.SECRET_BYTES
    assert isinstance(secret, bytes)


def test_load_fails_when_missing(secret_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        identity.load_hmac_secret()


def test_load_fails_on_malformed_file(secret_path: Path) -> None:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_text("SOME_GARBAGE\n")
    with pytest.raises(ValueError, match="must set"):
        identity.load_hmac_secret()


def test_load_fails_on_wrong_length(secret_path: Path) -> None:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    short = base64.urlsafe_b64encode(b"short").decode()
    secret_path.write_text(
        f"SANITIZED_POOL_HMAC_VERSION=v1\n"
        f"SANITIZED_POOL_HMAC_BASE64={short}\n",
    )
    with pytest.raises(ValueError, match="32 bytes"):
        identity.load_hmac_secret()


def test_tenant_hmac_is_deterministic(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    a1 = identity.tenant_hmac("acme")
    a2 = identity.tenant_hmac("acme")
    assert a1 == a2


def test_tenant_hmac_is_64_hex_chars(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    h = identity.tenant_hmac("acme")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_different_slugs_produce_different_hmacs(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    a = identity.tenant_hmac("acme")
    b = identity.tenant_hmac("globex")
    assert a != b


def test_different_secrets_produce_different_hmacs_for_same_slug(
    secret_path: Path,
) -> None:
    """The own-tenant pre-image attack is defeated: rotating the secret
    invalidates every previously-computed tenant_hmac."""
    identity.provision_hmac_secret()
    h_before = identity.tenant_hmac("acme")
    # Rotate secret.
    identity.reset_cache()
    identity.provision_hmac_secret(force=True)
    h_after = identity.tenant_hmac("acme")
    assert h_before != h_after


def test_tenant_hmac_rejects_empty_or_non_string(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    with pytest.raises(ValueError):
        identity.tenant_hmac("")
    with pytest.raises(ValueError):
        identity.tenant_hmac(None)  # type: ignore[arg-type]


def test_hmac_version_returns_current_version(secret_path: Path) -> None:
    identity.provision_hmac_secret()
    assert identity.hmac_version() == "v1"


def test_reset_cache_forces_reload(secret_path: Path, monkeypatch) -> None:
    identity.provision_hmac_secret()
    h1 = identity.tenant_hmac("acme")
    # Rewrite the file with a different secret (simulating out-of-band rotation).
    new_secret = identity.generate_hmac_secret()
    new_b64 = base64.urlsafe_b64encode(new_secret).decode()
    secret_path.write_text(
        f"SANITIZED_POOL_HMAC_VERSION=v2\n"
        f"SANITIZED_POOL_HMAC_BASE64={new_b64}\n",
    )
    # Without resetting, we still see the old cached value.
    assert identity.tenant_hmac("acme") == h1
    # After reset, the new secret loads.
    identity.reset_cache()
    h2 = identity.tenant_hmac("acme")
    assert h2 != h1
    assert identity.hmac_version() == "v2"
