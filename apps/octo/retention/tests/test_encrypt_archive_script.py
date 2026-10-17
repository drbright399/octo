"""scripts/encrypt_archive.py — converting the plaintext archive of
2026-10-07 to age, with Rick's rule: nothing is shredded until verified.

Pins: the dry run writes nothing and says what each step would do; --apply
encrypts each plaintext day file (+ sidecar, ledger, manifest entry with the
plaintext's sha256) and KEEPS the plaintext; --verify needs the operator's
identity, records a decrypt round trip, and a wrong key records nothing;
--delete-plaintext unlinks only a plaintext whose copy was verified as both
files are now (never before; never after the plaintext changed) and says it
is not a secure erase; the dedupe survives the deletion; the run lock; no
key material printed.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat

import pytest

from apps.octo.retention import archive_crypto as crypto
from apps.octo.retention.archive import ColdArchive
from apps.octo.retention.tests._crypto_fixtures import (
    A, B, keypair, leaked, recipients_file, row,
)

pytest.importorskip("pyrage")

D1, D2 = "2026-10-06", "2026-10-07"


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A plaintext archive (two days of acme-corp, one of globex), the
    operator's key pair, the recipients file configured, a data root for the
    run lock."""
    arch_root = tmp_path / "archive"
    arch_root.mkdir(mode=0o700)
    plain = ColdArchive(arch_root)
    plain.append(A, D1, [row(1, D1), row(2, D1)])
    plain.append(A, D2, [row(3, D2)])
    plain.append(B, D2, [row(1, D2)])
    key = keypair(tmp_path)
    monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(arch_root))
    monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(recipients_file(tmp_path, key.public)))
    monkeypatch.delenv(crypto.POLICY_ENV, raising=False)
    data_root = tmp_path / "octo-data"
    data_root.mkdir()
    monkeypatch.setenv("OCTO_DATA_ROOT", str(data_root))
    return {"root": arch_root, "key": key, "data_root": data_root, "arch": plain}


def _run(world, *argv: str) -> int:
    import scripts.encrypt_archive as script

    return script.main(["--archive-root", str(world["root"]),
                        "--data-root", str(world["data_root"]), *argv])


def _digests(root) -> dict:
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_dry_run_writes_nothing_and_says_what_comes_next(world, capsys):
    before = _digests(world["root"])
    assert _run(world) == 0
    out = capsys.readouterr().out
    assert f"{A} {D1}: plaintext only — --apply would encrypt it" in out
    assert "plaintext day files: 3 not yet encrypted" in out
    assert "recipients: " + crypto.recipient_short(world["key"].public) in out
    assert "dry run — nothing was written" in out
    assert _digests(world["root"]) == before


def test_apply_verify_delete(world, capsys):
    arch, key = world["arch"], world["key"]
    plain1 = arch.day_file(A, D1)
    psha = hashlib.sha256(plain1.read_bytes()).hexdigest()
    # --apply: an encrypted copy beside each plaintext; the plaintext kept.
    assert _run(world, "--apply", "--tenant", A) == 0
    out = capsys.readouterr().out
    assert f"{A} {D1}: encrypted → {A}-telemetry-{D1}.jsonl.gz.age" in out
    conv = arch.converted_file(A, D1)
    assert plain1.exists() and conv.exists() and not arch.converted_file(B, D2).exists()
    ct = conv.read_bytes()
    assert ct.startswith(b"age-encryption.org/v1\n")
    assert arch.sidecar(conv).read_text().split()[0] == hashlib.sha256(ct).hexdigest()
    for p in (conv, arch.sidecar(conv), arch.ledger_file(A, D1)):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p
    entry = arch.manifest(A)["files"][f"2026/{A}-telemetry-{D1}.jsonl.gz.age"]
    assert entry["encrypted"] is True and entry["scheme"] == "age-x25519"
    assert entry["plaintext_sha256"] == psha and entry["rows"] == 2 and entry["part"] is None
    assert entry["recipients"] == [key.public] and "verified" not in entry
    assert arch._read_ledger(A, D1) == {conv.name: {1, 2}}
    # Re-running finds nothing to do.
    assert _run(world, "--apply", "--tenant", A) == 0
    assert f"{A} {D1}: already" in capsys.readouterr().out
    # --delete-plaintext before any verify: refused, kept.
    assert _run(world, "--delete-plaintext", "--tenant", A) == 1
    out = capsys.readouterr().out
    assert f"{A} {D1}: plaintext KEPT — its encrypted copy has never been verified" in out
    assert plain1.exists()
    # --verify needs an identity; a wrong one records nothing.
    assert _run(world, "--verify") == 2
    capsys.readouterr()
    stranger = keypair(world["root"].parent, "stranger")
    assert _run(world, "--verify", "--tenant", A, "--identity",
                str(stranger.identity_path)) == 1
    assert "FAILED — none of the identities given can decrypt it" in capsys.readouterr().out
    assert "verified" not in arch.manifest(A)["files"][f"2026/{A}-telemetry-{D1}.jsonl.gz.age"]
    # The operator's identity: verified, recorded.
    assert _run(world, "--verify", "--tenant", A, "--identity", str(key.identity_path)) == 0
    out = capsys.readouterr().out
    assert f"{A} {D1}: {conv.name}: verified (2 rows)" in out
    rec = arch.manifest(A)["files"][f"2026/{A}-telemetry-{D1}.jsonl.gz.age"]["verified"]
    assert rec["ciphertext_sha256"] == hashlib.sha256(ct).hexdigest()
    assert rec["plaintext_sha256"] == psha and rec["rows"] == 2
    assert rec["identities"] == [crypto.recipient_fingerprint(key.public)]
    # The dry run now says it is deletable.
    assert _run(world, "--tenant", A) == 0
    assert "plaintext + VERIFIED encrypted copy" in capsys.readouterr().out
    # --delete-plaintext: unlinked, said not to be a secure erase.
    assert _run(world, "--delete-plaintext", "--tenant", A) == 0
    out = capsys.readouterr().out
    assert f"{A} {D1}: plaintext unlinked" in out and "UNLINK, not a secure erase" in out
    assert "parity array" in out
    assert not plain1.exists() and not arch.sidecar(plain1).exists()
    m = arch.manifest(A)
    assert m["files"][f"2026/{A}-telemetry-{D1}.jsonl.gz"]["deleted_at"]
    assert m["days"][D1]["files"] == [f"2026/{A}-telemetry-{D1}.jsonl.gz.age"]
    assert "file" not in m["days"][D1]
    # globex was never touched.
    assert arch.day_file(B, D2).exists()
    # The rows are still archived — read with the identity — and still
    # deduped (a later run writes only what is new).
    ids = crypto.load_identities(key.identity_path)
    assert [r["id"] for r in arch.read_day(A, D1, identities=ids)] == [1, 2]
    with pytest.raises(Exception, match="--identity"):
        arch.read_day(A, D1)
    enc = ColdArchive(world["root"], encryption=crypto.with_recipients((key.public,)))
    assert enc.append(A, D1, [row(1, D1), row(2, D1), row(4, D1)]).rows_added == 1
    assert ColdArchive(world["root"]).append(A, D1, [row(1, D1), row(4, D1)]).rows_added == 0
    out_all = capsys.readouterr()
    assert not leaked(key.secret, out_all.out, out_all.err)


def test_a_plaintext_that_changed_after_its_verify_is_never_deleted(world, capsys):
    arch, key = world["arch"], world["key"]
    assert _run(world, "--apply", "--tenant", A, "--day", D2) == 0
    assert _run(world, "--verify", "--tenant", A, "--day", D2,
                "--identity", str(key.identity_path)) == 0
    # A late row reaches the plaintext (encryption was off for that run).
    assert arch.append(A, D2, [row(9, D2)]).rows_added == 1
    capsys.readouterr()
    assert _run(world, "--delete-plaintext", "--tenant", A, "--day", D2) == 1
    assert "the plaintext changed since its copy was made" in capsys.readouterr().out
    assert arch.day_file(A, D2).exists()
    # The covered-by-plaintext shortcut no longer applies either.
    assert arch.covered_by_plaintext(A, D2) is None
    assert _run(world, "--tenant", A, "--day", D2) == 0
    assert "plaintext changed since its encrypted copy" in capsys.readouterr().out
    # apply → verify → delete again: fine.
    assert _run(world, "--apply", "--tenant", A, "--day", D2) == 0
    assert "re-encrypted" in capsys.readouterr().out
    assert _run(world, "--delete-plaintext", "--tenant", A, "--day", D2) == 1   # not verified
    assert _run(world, "--verify", "--tenant", A, "--day", D2,
                "--identity", str(key.identity_path)) == 0
    assert _run(world, "--delete-plaintext", "--tenant", A, "--day", D2) == 0
    ids = crypto.load_identities(key.identity_path)
    assert [r["id"] for r in arch.read_day(A, D2, identities=ids)] == [3, 9]


def test_a_plaintext_reborn_after_its_deletion_never_overwrites_the_copy(world, capsys):
    """apply → verify → delete; then a late row reaches a NEW plaintext file
    (encryption off that night). Converting it must not replace the only
    copy of the deleted plaintext's rows: it becomes a part of its own."""
    arch, key = world["arch"], world["key"]
    for step in (["--apply"], ["--verify", "--identity", str(key.identity_path)],
                 ["--delete-plaintext"]):
        assert _run(world, *step, "--tenant", A, "--day", D1) == 0, step
    conv = arch.converted_file(A, D1)
    before = conv.read_bytes()
    assert arch.append(A, D1, [row(1, D1), row(7, D1)]).rows_added == 1   # 1 is deduped
    capsys.readouterr()
    assert _run(world, "--tenant", A, "--day", D1) == 0
    assert "plaintext changed since its encrypted copy" in capsys.readouterr().out
    assert _run(world, "--apply", "--tenant", A, "--day", D1) == 0
    assert f"encrypted → {A}-telemetry-{D1}.p001.jsonl.gz.age" in capsys.readouterr().out
    assert conv.read_bytes() == before                          # untouched
    ids = crypto.load_identities(key.identity_path)
    assert sorted(r["id"] for r in arch.read_day(A, D1, identities=ids)) == [1, 2, 7]
    assert arch.known_ids(A, D1) == {1, 2, 7}
    # The new plaintext goes the same way: verify, then delete.
    assert _run(world, "--delete-plaintext", "--tenant", A, "--day", D1) == 1
    assert _run(world, "--verify", "--tenant", A, "--day", D1,
                "--identity", str(key.identity_path)) == 0
    assert _run(world, "--delete-plaintext", "--tenant", A, "--day", D1) == 0
    assert not arch.day_file(A, D1).exists()
    assert sorted(r["id"] for r in arch.read_day(A, D1, identities=ids)) == [1, 2, 7]


def test_a_tampered_copy_is_never_the_reason_to_delete(world, capsys):
    arch, key = world["arch"], world["key"]
    assert _run(world, "--apply", "--tenant", B) == 0
    assert _run(world, "--verify", "--tenant", B, "--identity", str(key.identity_path)) == 0
    conv = arch.converted_file(B, D2)
    conv.write_bytes(conv.read_bytes() + b"x")
    capsys.readouterr()
    assert _run(world, "--delete-plaintext", "--tenant", B) == 1
    assert "does not match its .sha256 sidecar" in capsys.readouterr().out
    assert arch.day_file(B, D2).exists()


def test_setup_refusals_and_the_lock(world, tmp_path, capsys, monkeypatch):
    from apps.octo.retention import job as job_module

    key = world["key"]
    # --identity belongs to --verify only.
    assert _run(world, "--apply", "--identity", str(key.identity_path)) == 2
    # An identity file others can read.
    os.chmod(key.identity_path, 0o644)
    assert _run(world, "--verify", "--identity", str(key.identity_path)) == 2
    assert "chmod 600" in capsys.readouterr().err
    os.chmod(key.identity_path, 0o600)
    # No usable recipients: --apply refused, nothing written.
    before = _digests(world["root"])
    monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(recipients_file(
        tmp_path, key.public, key.secret, name="bad.txt")))
    assert _run(world, "--apply") == 2
    err = capsys.readouterr().err
    assert "must never be on this machine" in err and not leaked(key.secret, err)
    assert _digests(world["root"]) == before
    # Another retention run holds the lock: nothing done.
    monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(recipients_file(tmp_path, key.public)))
    held = job_module._Lock(world["data_root"] / job_module.LOCK_NAME)
    assert held.acquire()
    try:
        assert _run(world, "--apply") == 3
    finally:
        held.release()
    assert _digests(world["root"]) == before
    assert _run(world, "--apply", "--json") == 0
    out = capsys.readouterr().out
    report = json.loads(out[out.index("\n{") + 1:])
    assert report["mode"] == "apply"
    assert sorted((f["tenant"], f["day"], f["status"]) for f in report["files"]) == [
        (A, D1, "encrypted"), (A, D2, "encrypted"), (B, D2, "encrypted")]


# A plaintext append KILLED between its temp file and the rename (SIGKILL on
# a container recreate, the OOM killer): run in a child process that kills
# itself exactly there, as the real thing would.
_KILLED_APPEND = """
import os, signal, sys
from pathlib import Path
from apps.octo.retention import archive
from apps.octo.retention.tests._crypto_fixtures import row
def killed(src, dst):
    os.kill(os.getpid(), signal.SIGKILL)
archive.os.replace = killed
day = sys.argv[3]
archive.ColdArchive(Path(sys.argv[1])).append(sys.argv[2], day, [row(int(sys.argv[4]), day)])
"""


def _killed_append(root, slug: str, day: str, row_id: int) -> None:
    import signal
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parents[4]
    env = dict(os.environ, PYTHONPATH=str(repo))
    proc = subprocess.run([sys.executable, "-c", _KILLED_APPEND, str(root), slug, day,
                           str(row_id)], env=env, cwd=repo, capture_output=True)
    assert proc.returncode == -signal.SIGKILL, proc.stderr.decode()


def test_leftover_plaintext_temps_are_counted_listed_and_removed(world, capsys):
    """A killed plaintext append leaves `.<day file>.tmp-<hex>`: a full
    PLAINTEXT copy of the day plus the chunk. Settings → System counts it as
    plaintext, the dry run lists it, --delete-plaintext removes it (under
    the run lock) — its rows were never counted as archived."""
    import gzip

    from apps.octo.retention import archive as archive_module
    from apps.octo.retention import job as job_module

    arch = world["arch"]
    _killed_append(world["root"], A, D1, 5)               # the day file holds 1, 2
    _killed_append(world["root"], A, "2026-10-05", 6)     # a day with no file yet
    year = arch.day_file(A, D1).parent
    temps = sorted(p.name for p in year.iterdir() if p.name.startswith("."))
    assert len(temps) == 2 and all(archive_module.is_plaintext_temp(t) for t in temps)
    day_temp = next(year / t for t in temps if D1 in t)
    assert stat.S_IMODE(day_temp.stat().st_mode) == 0o600
    body = gzip.decompress(day_temp.read_bytes()).decode()
    assert [json.loads(x)["id"] for x in body.splitlines()] == [1, 2, 5]   # plaintext rows
    assert arch.known_ids(A, D1) == {1, 2}                # never counted as archived
    assert arch.days(A) == [D1, D2]
    # An encrypted part's temp too (ciphertext; removed alongside).
    (year / f".{A}-telemetry-{D1}.p001.jsonl.gz.age.tmp-0123abcd").write_bytes(b"age")
    # Counted: Settings → System and the scripts' status lines.
    counts = arch.file_counts()
    assert counts == {"plaintext": 5, "encrypted": 0, "plaintext_temp": 2, "complete": True}
    status = job_module.archive_status()
    assert status["files"]["plaintext_temp"] == 2
    assert any("2 of the plaintext file(s) are temp files" in line
               for line in job_module.archive_encryption_lines(status))
    # The dry run lists them and writes nothing.
    before = _digests(world["root"])
    assert _run(world, "--tenant", A) == 0
    out = capsys.readouterr().out
    assert f"{A} 2026-10-05: leftover temp file of an interrupted write" in out
    assert out.count("PLAINTEXT rows inside") == 2
    assert "leftover temp files: 3 (2 with plaintext rows)" in out
    assert _digests(world["root"]) == before
    # Another run holds the lock: nothing removed.
    held = job_module._Lock(world["data_root"] / job_module.LOCK_NAME)
    assert held.acquire()
    try:
        assert _run(world, "--delete-plaintext", "--tenant", A) == 3
    finally:
        held.release()
    assert _digests(world["root"]) == before
    # --delete-plaintext: the temps go; the day files (never verified) stay.
    assert _run(world, "--delete-plaintext", "--tenant", A) == 1
    out = capsys.readouterr().out
    assert out.count("removed (it held plaintext rows)") == 2
    assert "0 plaintext day file(s) unlinked, 3 leftover temp file(s) removed" in out
    assert "not a secure erase" in out
    assert not [p for p in year.iterdir() if p.name.startswith(".")]
    assert arch.day_file(A, D1).exists() and arch.day_file(A, D2).exists()
    assert arch.file_counts() == {"plaintext": 3, "encrypted": 0, "plaintext_temp": 0,
                                  "complete": True}
