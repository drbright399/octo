"""First-run bundle bootstrap: provisions secrets + data root + factory
super_admin exactly once, and never overwrites on re-run."""
from __future__ import annotations

import stat

import pytest

from apps.octo import bundle_bootstrap, paths
from apps.octo.db import connect


@pytest.fixture
def empty_bundle(monkeypatch, tmp_path):
    secrets_dir = tmp_path / "secrets"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(secrets_dir / "pepper.env"))
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(secrets_dir / "mfa-key.env"))
    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH",
        str(secrets_dir / "adapter-credentials-key.env"),
    )
    monkeypatch.setenv("ATHENA_RP_ID", "athena.test")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://athena.test")
    return secrets_dir


def _operator_count() -> int:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return reg.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
    finally:
        reg.close()


def test_first_run_provisions_everything(empty_bundle, capsys):
    assert bundle_bootstrap.main([]) == 0

    for name in ("pepper.env", "mfa-key.env", "adapter-credentials-key.env"):
        f = empty_bundle / name
        assert f.exists(), name
        assert stat.S_IMODE(f.stat().st_mode) == 0o600, name
    assert paths.registry_db_path().exists()
    assert _operator_count() == 1
    out = capsys.readouterr().out
    assert "FACTORY SUPER_ADMIN PROVISIONED" in out
    # Magic-link-only: the link is the single secret in the block.
    assert "https://athena.test/login/magic?token=" in out
    for forbidden in ("Initial password", "TOTP secret", "otpauth://",
                      "Backup codes ("):
        assert forbidden not in out, forbidden


def test_rerun_is_idempotent_and_never_overwrites(empty_bundle, capsys):
    bundle_bootstrap.main([])
    before = {f.name: f.read_bytes() for f in empty_bundle.iterdir()}
    capsys.readouterr()

    assert bundle_bootstrap.main([]) == 0

    after = {f.name: f.read_bytes() for f in empty_bundle.iterdir()}
    assert after == before
    assert _operator_count() == 1
    assert "FACTORY SUPER_ADMIN PROVISIONED" not in capsys.readouterr().out


def test_skip_factory_admin(empty_bundle):
    assert bundle_bootstrap.main(["--skip-factory-admin"]) == 0
    assert (empty_bundle / "pepper.env").exists()
    assert _operator_count() == 0


def test_preflight_refuses_unset_public_host(empty_bundle, monkeypatch, capsys):
    # envsubst renders an unset BUNDLE_PUBLIC_HOST as "" / "https://"
    monkeypatch.setenv("ATHENA_RP_ID", "")
    monkeypatch.setenv("ATHENA_ORIGIN", "https://")

    assert bundle_bootstrap.main([]) == 2

    assert not empty_bundle.exists()              # nothing minted
    assert not paths.registry_db_path().exists()
    assert "nothing was created" in capsys.readouterr().out


def test_preflight_refuses_origin_rp_mismatch(empty_bundle, monkeypatch):
    monkeypatch.setenv("ATHENA_ORIGIN", "https://elsewhere.example")
    assert bundle_bootstrap.main([]) == 2
    assert not empty_bundle.exists()



def test_reset_factory_admin_prints_fresh_link(empty_bundle, capsys):
    bundle_bootstrap.main([])
    first = capsys.readouterr().out

    assert bundle_bootstrap.main(["--reset-factory-admin"]) == 0

    out = capsys.readouterr().out
    assert "FACTORY SUPER_ADMIN RESET" in out
    assert "https://athena.test/login/magic?token=" in out
    link = next(l for l in out.splitlines() if "Setup link:" in l)
    assert link not in first                      # a NEW link
    assert _operator_count() == 1
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        live = reg.execute(
            "SELECT COUNT(*) FROM magic_link_tokens WHERE used_at IS NULL"
        ).fetchone()[0]
    finally:
        reg.close()
    assert live == 1                              # first-run link burned


def test_reset_factory_admin_on_empty_bundle_creates_nothing(empty_bundle, capsys):
    assert bundle_bootstrap.main(["--reset-factory-admin"]) == 1
    assert not empty_bundle.exists()
    assert not paths.registry_db_path().exists()


def test_reset_factory_admin_without_factory_account(empty_bundle, capsys):
    bundle_bootstrap.main(["--skip-factory-admin"])
    capsys.readouterr()
    assert bundle_bootstrap.main(["--reset-factory-admin"]) == 1
    assert "does not exist" in capsys.readouterr().out
    assert _operator_count() == 0


def test_rerun_never_rewinds_a_live_schema(empty_bundle):
    """Re-running bootstrap on a LIVE root (or after a restore) used to re-apply
    migration 003 and rewind patterns.db's user_version 24 → 3; the next app
    start then failed migration 023 with 'duplicate column name'."""
    import sqlite3
    from apps.octo.auth import bootstrap

    def version(p):
        c = sqlite3.connect(p)
        try:
            return c.execute("PRAGMA user_version").fetchone()[0]
        finally:
            c.close()

    assert bundle_bootstrap.main(["--skip-factory-admin"]) == 0
    bootstrap.ensure_patterns_migrations_applied(paths.patterns_db_path())   # an app start
    live = version(paths.patterns_db_path())
    assert live > 3

    assert bundle_bootstrap.main(["--skip-factory-admin"]) == 0              # the re-run

    assert version(paths.patterns_db_path()) == live
    assert bootstrap.ensure_patterns_migrations_applied(paths.patterns_db_path()) == []   # next start: clean

