"""scripts/unseal_backup_run.py: open one sealed backup run safely on the
operator workstation (the backup-vault design 2026-10-12, sections 7 and 11:
a compromised bundle host can seal well-formed forgeries, so a sealed run is
never given to `tar -x`).

Pins: a real sealed run unseals byte for byte (run files, its report, the
bundle files) and the temporary tar is gone; the checksum is checked BEFORE
decrypting; a forged tar (symlink, hard link, device, `..`, absolute path,
nested directory, unknown top directory, duplicate, no run directory, the
wrong stamp) is refused WHOLE, nothing extracted; wrong key, truncated
ciphertext, an identity file others can read, a non-empty --out, a missing
checksum file and a badly named file are refused.

Every key pair is made by the test (pyrage); fixture tenants are fictional.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

pyrage = pytest.importorskip("pyrage")

import scripts.seal_backup_runs as seal  # noqa: E402

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
STAMP = "20261012T060001Z"
TENANT = "acme-corp"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


unseal = _load("unseal_backup_run")


@pytest.fixture
def keys(tmp_path):
    ident = pyrage.x25519.Identity.generate()
    shm = tmp_path / "shm"
    shm.mkdir(mode=0o700)
    identity = shm / "identity.txt"
    identity.write_text(f"# test key\n{ident}\n")
    os.chmod(identity, 0o600)
    return ident, identity, shm


def _write_sealed(where: Path, plaintext: bytes, ident, stamp: str = STAMP) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    path = where / f"{stamp}.tar.age"
    cipher = pyrage.encrypt(plaintext, [ident.to_public()])
    path.write_bytes(cipher)
    (where / f"{stamp}.tar.age.sha256").write_text(
        f"{hashlib.sha256(cipher).hexdigest()}  {path.name}\n")
    return path


def _tar(*members: tuple[tarfile.TarInfo, bytes | None]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def _dir(name: str) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type, info.mode = tarfile.DIRTYPE, 0o700
    return info, None


def _file(name: str, data: bytes = b"x") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), 0o600
    return info, data


def _link(name: str, target: str, kind=tarfile.SYMTYPE) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, target
    return info, None


def run_unseal(sealed: Path, identity: Path, out: Path, *extra: str) -> int:
    return unseal.main(["--sealed", str(sealed), "--identity", str(identity),
                        "--out", str(out), *extra])


def test_a_sealed_run_unseals_byte_for_byte(tmp_path, keys, capsys):
    ident, identity, shm = keys
    backups, sealed_root = tmp_path / "backups", tmp_path / "sealed"
    backups.mkdir()
    sealed_root.mkdir(mode=0o700)
    run = backups / STAMP
    run.mkdir()
    files = {"registry.db.gz": os.urandom(3000), f"tenant_{TENANT}_events.db.gz": os.urandom(900),
             seal.RUN_REPORT_NAME: b'{"dest_dir": "/backup/' + STAMP.encode() + b'"}\n'}
    for name, data in files.items():
        (run / name).write_bytes(data)
    report = json.dumps({"dest_dir": f"/backup/{STAMP}"}).encode()
    (backups / "last-report.json").write_bytes(report)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}\n")
    recipients = tmp_path / "r.txt"
    recipients.write_text(f"{ident.to_public()}\n")
    os.chmod(recipients, 0o600)
    assert seal.main(["--backups-root", str(backups), "--sealed-root", str(sealed_root),
                      "--recipients", str(recipients), "--config-file", str(compose),
                      "--backfill"]) == 0
    out = shm / "unsealed"
    capsys.readouterr()

    assert run_unseal(sealed_root / f"{STAMP}.tar.age", identity, out) == 0

    for name, data in files.items():
        assert (out / STAMP / name).read_bytes() == data
    assert (out / "report" / "last-report.json").read_bytes() == report
    assert (out / "bundle" / "docker-compose.yml").read_text() == "services: {}\n"
    assert sorted(p.name for p in out.iterdir()) == [STAMP, "bundle", "report"]   # no temp tar
    text = capsys.readouterr()
    assert "checksum OK" in text.out and "3 run file(s)" in text.out
    assert str(ident) not in text.out + text.err


@pytest.mark.parametrize("forged", [
    "symlink", "hardlink", "device", "dotdot", "absolute", "nested", "unknown-top",
    "duplicate", "no-run-dir", "other-stamp", "report-dotdot", "dir-in-bundle",
])
def test_a_forged_tar_is_refused_whole(tmp_path, keys, forged, capsys):
    ident, identity, shm = keys
    good = [_dir(STAMP), _file(f"{STAMP}/registry.db.gz", b"real")]
    bad = {
        "symlink": [_link(f"{STAMP}/tenant_x_events.db.gz", "/etc/passwd")],
        "hardlink": [_link(f"{STAMP}/tenant_x_events.db.gz", f"{STAMP}/registry.db.gz",
                           tarfile.LNKTYPE)],
        "device": [(lambda i: (setattr(i, "type", tarfile.CHRTYPE), (i, None))[1])(
            tarfile.TarInfo(f"{STAMP}/null"))],
        "dotdot": [_file(f"{STAMP}/../../evil.sh")],
        "absolute": [_file(str(tmp_path / "abs-evil.sh"))],
        "nested": [_file(f"{STAMP}/sub/registry.db.gz")],
        "unknown-top": [_file("etc/cron.d/evil")],
        "duplicate": [_file(f"{STAMP}/registry.db.gz", b"overwritten")],
        "no-run-dir": None,
        "other-stamp": [_dir("20261011T060001Z"), _file("20261011T060001Z/registry.db.gz")],
        "report-dotdot": [_file("report/..")],
        "dir-in-bundle": [_dir("bundle/sub")],
    }[forged]
    members = [_file(f"{STAMP}/registry.db.gz")] if bad is None else good + bad
    sealed = _write_sealed(tmp_path / "pull", _tar(*members), ident)
    out = shm / "unsealed"

    assert run_unseal(sealed, identity, out) == 1

    assert list(out.iterdir()) == []                         # nothing extracted, no temp tar
    assert not (shm / "evil.sh").exists() and not (tmp_path / "abs-evil.sh").exists()
    assert "unseal: refused:" in capsys.readouterr().err


def test_the_checksum_is_checked_before_decrypting(tmp_path, keys, monkeypatch, capsys):
    ident, identity, shm = keys
    sealed = _write_sealed(tmp_path / "pull", _tar(_dir(STAMP), _file(f"{STAMP}/a.db.gz")), ident)
    (tmp_path / "pull" / f"{STAMP}.tar.age.sha256").write_text(f"{'0' * 64}  {sealed.name}\n")
    called = []
    monkeypatch.setattr(unseal, "unseal", lambda *a: called.append(a))
    assert run_unseal(sealed, identity, shm / "out") == 1
    assert called == []
    assert "checksum mismatch" in capsys.readouterr().err


def test_wrong_key_and_truncated_ciphertext_are_refused_without_leftovers(tmp_path, keys, capsys):
    ident, identity, shm = keys
    stranger = pyrage.x25519.Identity.generate()
    plain = _tar(_dir(STAMP), _file(f"{STAMP}/a.db.gz", os.urandom(200_000)))
    sealed = _write_sealed(tmp_path / "pull", plain, stranger)
    assert run_unseal(sealed, identity, shm / "a") == 1
    assert "none of the identities given can decrypt it" in capsys.readouterr().err
    assert list((shm / "a").iterdir()) == []

    sealed = _write_sealed(tmp_path / "pull2", plain, ident)
    sealed.write_bytes(sealed.read_bytes()[:-100])                       # cut short
    assert run_unseal(sealed, identity, shm / "b", "--no-verify") == 1
    assert list((shm / "b").iterdir()) == []                             # partial plaintext gone


@pytest.mark.parametrize("problem", ["identity-readable", "out-not-empty", "no-sidecar",
                                     "bad-name", "sidecar-other-file"])
def test_setup_refusals(tmp_path, keys, problem, capsys):
    ident, identity, shm = keys
    sealed = _write_sealed(tmp_path / "pull", _tar(_dir(STAMP), _file(f"{STAMP}/a.db.gz")), ident)
    out = shm / "out"
    if problem == "identity-readable":
        os.chmod(identity, 0o644)
    elif problem == "out-not-empty":
        out.mkdir()
        (out / "keep.txt").write_text("someone's file")
    elif problem == "no-sidecar":
        (tmp_path / "pull" / f"{STAMP}.tar.age.sha256").unlink()
    elif problem == "bad-name":
        sealed = sealed.rename(tmp_path / "pull" / "run.tar.age")
    else:
        digest = hashlib.sha256(sealed.read_bytes()).hexdigest()
        (tmp_path / "pull" / f"{STAMP}.tar.age.sha256").write_text(
            f"{digest}  20261011T060001Z.tar.age\n")
    assert run_unseal(sealed, identity, out) == 2
    err = capsys.readouterr().err
    assert "unseal: setup error:" in err and str(ident) not in err
    if problem == "out-not-empty":
        assert sorted(p.name for p in out.iterdir()) == ["keep.txt"]
    else:
        assert not out.exists() or list(out.iterdir()) == []


def test_a_full_out_dir_is_reported_as_such_and_leaves_nothing(tmp_path, keys, monkeypatch, capsys):
    ident, identity, shm = keys
    plain = _tar(_dir(STAMP), _file(f"{STAMP}/a.db.gz", os.urandom(300_000)))
    sealed = _write_sealed(tmp_path / "pull", plain, ident)
    real_write = os.write

    def full(fd, data):
        if os.readlink(f"/proc/self/fd/{fd}").endswith(".tar.partial"):
            raise OSError(28, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", full)
    assert run_unseal(sealed, identity, shm / "out") == 1
    assert "writing the decrypted tar into --out failed (No space left on device)" \
        in capsys.readouterr().err
    assert list((shm / "out").iterdir()) == []
