"""Key files (the MFA master key, the sanitized-pool HMAC secret, the bundle's
pepper) are created owner-only and published atomically —
`auth.bootstrap.write_secret_file`.

These keys must sit on disk in usable form, so how the file comes into
existence is the protection:

  * never readable by another local user, not even while being written:
    the mode comes from the call that creates the file, not a chmod after
    (proved with a 0 umask and every chmod disabled);
  * a key that appears while one is being provisioned is never overwritten
    (losing the MFA key destroys every TOTP secret; losing the HMAC secret
    orphans every tenant_hmac in the pool);
  * a new secrets directory is 0700; no temp file is left behind;
  * a fresh install still provisions, and the key still loads.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from apps.octo import bundle_bootstrap
from apps.octo.auth import bootstrap, config, crypto
from apps.octo.sanitized_pool import identity


@dataclass
class KeyFile:
    path: Path
    provision: Callable[..., dict]
    load: Callable[[], object]
    # (module, attribute) of the generator provision() calls for the key.
    generator: tuple[object, str]


@pytest.fixture(params=["mfa-key", "pool-hmac"])
def key_file(request, monkeypatch, tmp_path) -> KeyFile:
    secrets_dir = tmp_path / "secrets"
    if request.param == "mfa-key":
        path = secrets_dir / "mfa-key.env"
        monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(path))
        yield KeyFile(path, bootstrap.provision_mfa_key, crypto.load_mfa_key,
                      (crypto, "generate_mfa_key"))
    else:
        path = secrets_dir / "sanitized-pool-hmac.env"
        monkeypatch.setenv("OCTO_SANITIZED_POOL_HMAC_PATH", str(path))
        identity.reset_cache()
        yield KeyFile(path, identity.provision_hmac_secret, identity.load_hmac_secret,
                      (identity, "generate_hmac_secret"))
        identity.reset_cache()


@pytest.fixture
def no_umask():
    old = os.umask(0)
    yield
    os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def test_fresh_install_provisions_a_loadable_owner_only_key(key_file: KeyFile):
    info = key_file.provision()
    assert info["path"] == str(key_file.path) and info["version"] == "v1"
    assert _mode(key_file.path) == 0o600
    version, _ = key_file.load()
    assert version == "v1"
    # Only the key itself: no temp file left beside it.
    assert sorted(p.name for p in key_file.path.parent.iterdir()) == [key_file.path.name]


def test_the_key_is_never_readable_by_others_even_while_it_is_written(
    key_file: KeyFile, monkeypatch, no_umask,
):
    """With a 0 umask and every chmod / fchmod disabled, only the mode given
    to the call that CREATES the file is left. write-then-chmod would leave
    0666 here — the window in which another user could open the key."""
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)
    monkeypatch.setattr(os, "fchmod", lambda *a, **k: None)
    key_file.provision()
    assert _mode(key_file.path) == 0o600


def test_a_new_secrets_directory_is_owner_only(key_file: KeyFile, no_umask):
    assert not key_file.path.parent.exists()
    key_file.provision()
    assert _mode(key_file.path.parent) == 0o700


def test_an_existing_directory_keeps_its_mode(key_file: KeyFile):
    key_file.path.parent.mkdir(mode=0o750)
    os.chmod(key_file.path.parent, 0o750)
    key_file.provision()
    assert _mode(key_file.path.parent) == 0o750


def test_a_key_that_appears_meanwhile_is_never_overwritten(key_file: KeyFile, monkeypatch):
    """Another provisioner wins the race between the exists() check and the
    publish: its key stands, this one refuses (FileExistsError, as before)."""
    module, name = key_file.generator
    real = getattr(module, name)

    def racing_generator():
        key_file.path.parent.mkdir(parents=True, exist_ok=True)
        key_file.path.write_text("THEIRS\n")
        return real()

    monkeypatch.setattr(module, name, racing_generator)
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        key_file.provision()
    assert key_file.path.read_text() == "THEIRS\n"
    assert sorted(p.name for p in key_file.path.parent.iterdir()) == [key_file.path.name]


def test_an_existing_key_is_refused_without_force(key_file: KeyFile):
    key_file.provision()
    before = key_file.path.read_bytes()
    with pytest.raises(FileExistsError):
        key_file.provision()
    assert key_file.path.read_bytes() == before


def test_forced_rotation_replaces_the_key_owner_only_and_leaves_no_temp_file(
    key_file: KeyFile, no_umask,
):
    key_file.provision()
    before = key_file.path.read_bytes()
    key_file.provision(force=True)
    assert key_file.path.read_bytes() != before
    assert _mode(key_file.path) == 0o600
    assert sorted(p.name for p in key_file.path.parent.iterdir()) == [key_file.path.name]
    if key_file.generator[0] is identity:
        identity.reset_cache()
    version, _ = key_file.load()
    assert version == "v1"


def test_write_secret_file_cleans_up_when_the_write_fails(tmp_path, monkeypatch):
    target = tmp_path / "secrets" / "x.env"

    def failing_fsync(fd):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError, match="disk full"):
        bootstrap.write_secret_file(target, "K=V\n")
    assert not target.exists()
    assert list(target.parent.iterdir()) == []


def test_a_file_where_the_secrets_dir_should_be_is_not_reported_as_an_existing_key(
    key_file: KeyFile,
):
    """Only a key at the path itself is "already exists": any other
    FileExistsError keeps its own message instead of a false 'refusing to
    overwrite'."""
    key_file.path.parent.write_text("not a directory\n")
    with pytest.raises(FileExistsError) as ei:
        key_file.provision()
    assert "Refusing to overwrite" not in str(ei.value)


def test_write_secret_file_syncs_the_content_then_the_directory(tmp_path, monkeypatch):
    real_fsync = os.fsync
    synced: list[str] = []

    def recording_fsync(fd):
        synced.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    target = tmp_path / "secrets" / "x.env"
    bootstrap.write_secret_file(target, "K=V\n")
    assert synced == ["file", "dir"]
    assert target.read_text() == "K=V\n"
    assert sorted(p.name for p in target.parent.iterdir()) == ["x.env"]


# ---------------------------------------------------------------------------
# pepper.env — the bundle's first run writes it through the same helper
# ---------------------------------------------------------------------------

_PEPPER_FORMAT = re.compile(r"PEPPER_VERSION=pepper_v1\nPEPPER_HEX=[0-9a-f]{64}\n")


@pytest.fixture
def pepper_file(monkeypatch, tmp_path) -> Path:
    path = tmp_path / "secrets" / "pepper.env"
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(path))
    return path


def test_pepper_is_owner_only_from_creation_and_keeps_its_format_and_path(
    pepper_file: Path, monkeypatch, no_umask,
):
    """0 umask and every chmod disabled: only the creation mode is left.
    write_text() then chmod() would leave 0666 here."""
    monkeypatch.setattr(os, "chmod", lambda *a, **k: None)
    monkeypatch.setattr(os, "fchmod", lambda *a, **k: None)
    assert bundle_bootstrap.provision_pepper() is True
    assert config.pepper_path().resolve() == pepper_file.resolve()
    assert _mode(pepper_file) == 0o600
    assert _mode(pepper_file.parent) == 0o700
    assert _PEPPER_FORMAT.fullmatch(pepper_file.read_text())
    version, pepper = config.load_pepper()
    assert version == "pepper_v1" and len(pepper) == 32
    assert sorted(p.name for p in pepper_file.parent.iterdir()) == ["pepper.env"]


def test_an_existing_pepper_is_never_overwritten(pepper_file: Path):
    pepper_file.parent.mkdir()
    pepper_file.write_text("PEPPER_VERSION=pepper_v1\nPEPPER_HEX=" + "ab" * 32 + "\n")
    before = pepper_file.read_bytes()
    assert bundle_bootstrap.provision_pepper() is False
    assert pepper_file.read_bytes() == before


def test_a_pepper_that_appears_meanwhile_is_never_overwritten(pepper_file: Path, monkeypatch):
    """Another first run wins the race between the exists() check and the
    publish: its pepper stands (replacing it would invalidate every hash
    keyed by it) and this run reports 'exists'."""
    real_secrets = bundle_bootstrap.secrets

    class _RacingSecrets:
        @staticmethod
        def token_hex(nbytes):
            pepper_file.parent.mkdir(parents=True, exist_ok=True)
            pepper_file.write_text("THEIRS\n")
            return real_secrets.token_hex(nbytes)

    monkeypatch.setattr(bundle_bootstrap, "secrets", _RacingSecrets)
    assert bundle_bootstrap.provision_pepper() is False
    assert pepper_file.read_text() == "THEIRS\n"
    assert sorted(p.name for p in pepper_file.parent.iterdir()) == ["pepper.env"]
