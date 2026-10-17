"""Shared pytest fixtures."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap


# ---------------------------------------------------------------------------
# Phase G.1 — auth-test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_data_root(monkeypatch, tmp_path):
    """fresh_data_root + MFA key file + Athena test RP config.

    Use this fixture (not `fresh_data_root`) for auth-router tests that need
    Fernet at-rest encryption (TOTP secrets, challenges) and a deterministic
    RP-ID for WebAuthn ceremonies.
    """
    from cryptography.fernet import Fernet

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    pepper_file = secrets_dir / "pepper.env"
    pepper_file.write_text(
        "PEPPER_VERSION=pepper_v1\n"
        "PEPPER_HEX=" + "ab" * 32 + "\n"
    )
    os.chmod(pepper_file, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper_file))

    mfa_file = secrets_dir / "mfa-key.env"
    mfa_file.write_text(
        "MFA_KEY_VERSION=v1\n"
        f"MFA_KEY_BASE64={Fernet.generate_key().decode()}\n"
    )
    os.chmod(mfa_file, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa_file))

    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")

    info = bootstrap.init_data_root()
    yield Path(info["data_root"])


@pytest.fixture
def auth_client(auth_data_root):
    """A FastAPI TestClient bound to the auth-ready data root.

    Exposes helper `client.provision_operator(...)` that creates an operator
    with password + TOTP secret already encrypted-at-rest, optionally with
    a Console role (super_admin / analyst / viewer).
    """
    import json
    import pyotp
    from fastapi.testclient import TestClient
    from apps.octo import paths
    from apps.octo.auth import core as core_auth, crypto, operators
    from apps.octo.db import connect, transaction
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter

    reset_limiter()
    app = create_app()
    client = TestClient(app, base_url="https://athena.test")

    def provision_operator(
        username: str,
        password: str,
        *,
        email: str | None = None,
        role: str = "admin",         # OCTO API role (existing)
        athena_role: str | None = "super_admin",   # Console role (G.1)
        scope_slugs: list[str] | None = None,
        is_factory: bool = False,    # Slice 5d-1 — factory super_admin
        l2_llm_granted: bool = False,  # Slice 5d-2 — LLM access grant
    ) -> dict:
        """Returns dict with: id, username, email, password, totp_secret_b32,
        admin_bearer_token (plaintext), admin_headers."""
        op = operators.create_operator(
            username=username,
            email=email or f"{username}@example.test",
            role=role,
            scope_slugs=scope_slugs or ["*"],
            actor="system",
            reason="auth_client fixture",
        )
        # Set password_hash + TOTP secret + assign Athena Console role
        pw_hash = core_auth.hash_token(password)
        totp_secret = pyotp.random_base32()
        totp_secret_enc = crypto.encrypt_at_rest(totp_secret.encode())
        op_id = op["operator_id"]
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    "UPDATE operators SET password_hash = ?, "
                    "mfa_enabled = 1, mfa_secret_enc = ? WHERE id = ?",
                    (pw_hash, totp_secret_enc, op_id),
                )
                if athena_role is not None:
                    reg.execute(
                        "INSERT OR IGNORE INTO operator_roles "
                        "(operator_id, role_name, scope_slugs) VALUES (?, ?, ?)",
                        (op_id, athena_role, json.dumps(scope_slugs or ["*"])),
                    )
                if is_factory:
                    reg.execute(
                        "UPDATE operators SET is_factory = 1 WHERE id = ?",
                        (op_id,),
                    )
                if l2_llm_granted or is_factory:
                    # Factory implicit grant (matches migration 027 backfill).
                    reg.execute(
                        "UPDATE operators SET l2_llm_granted = 1 WHERE id = ?",
                        (op_id,),
                    )
        finally:
            reg.close()
        return {
            "id": op_id,
            "username": username,
            "email": email or f"{username}@example.test",
            "password": password,
            "totp_secret_b32": totp_secret,
            "admin_bearer_token": op["plaintext"],
            "admin_headers": {"Authorization": f"Bearer {op['plaintext']}"},
        }

    client.provision_operator = provision_operator
    yield client


@pytest.fixture
def fresh_data_root(monkeypatch, tmp_path):
    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    # Provide a stub pepper for sanitizer tests.
    pepper_dir = tmp_path / "secrets"
    pepper_dir.mkdir()
    pepper_file = pepper_dir / "pepper.env"
    pepper_file.write_text(
        "PEPPER_VERSION=pepper_v1\n"
        "PEPPER_HEX=" + "ab" * 32 + "\n"
    )
    os.chmod(pepper_file, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper_file))
    info = bootstrap.init_data_root()
    yield Path(info["data_root"])


@pytest.fixture
def api_client(fresh_data_root):
    """A FastAPI TestClient bound to a fresh data root, with a pre-provisioned
    admin operator whose plaintext token is returned as `client.admin_token`."""
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.auth import operators

    reset_limiter()
    app = create_app()
    client = TestClient(app)

    admin = operators.create_operator(
        username="admin",
        email="admin@example.test",
        role="admin",
        scope_slugs=["*"],
        actor="system",
        reason="test fixture",
    )
    client.admin_token = admin["plaintext"]
    client.admin_headers = {"Authorization": f"Bearer {admin['plaintext']}"}
    yield client
