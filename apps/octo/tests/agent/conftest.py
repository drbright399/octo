"""Fixtures for autonomous-agent tests (Task #119).

A minimal data-root fixture (registry + secrets) so the triage worker can
resolve per-tenant DBs via apps.octo.paths, mirroring the auth suite's
auth_data_root without the WebAuthn bits the worker doesn't need.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap


@pytest.fixture
def triage_data_root(monkeypatch, tmp_path):
    from cryptography.fernet import Fernet

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    pepper_file = secrets_dir / "pepper.env"
    pepper_file.write_text("PEPPER_VERSION=pepper_v1\nPEPPER_HEX=" + "ab" * 32 + "\n")
    os.chmod(pepper_file, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper_file))

    mfa_file = secrets_dir / "mfa-key.env"
    mfa_file.write_text(
        "MFA_KEY_VERSION=v1\n"
        f"MFA_KEY_BASE64={Fernet.generate_key().decode()}\n"
    )
    os.chmod(mfa_file, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa_file))

    info = bootstrap.init_data_root()
    yield Path(info["data_root"])
