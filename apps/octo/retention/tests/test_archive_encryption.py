"""Cold-archive encryption (`apps.octo.retention.archive_crypto` + the
encrypted parts / row-id ledger of `archive.py`) — Rick 2026-10-07: "make
sure encryption is built in for future archives"; custody (b): the operator
holds the private key off the machine, Athena gets public keys only.

Pins:
  * the format is standard age v1 / X25519 (round trip with a test-made
    identity; interop with the `age` CLI when it is on PATH — never
    installed);
  * one encrypted PART per run per day (0600 in 0700 folders, sha256 sidecar
    over the ciphertext), a plaintext row-id ledger (ids only) as the dedupe
    source, the manifest's per-file record;
  * dedupe across the plaintext file of 2026-10-07 and encrypted parts, in
    either mode; a mixed day restores as one day;
  * recipients validation: malformed / non-age1 lines by number (never
    echoed), a private key anywhere = hard refusal, writable by others =
    refused, the policy's defaults;
  * required + unusable = FAIL CLOSED: nothing pruned, the reason shown by
    the job, the scripts' dry runs and the API; "off" says "archive NOT
    encrypted" on every run;
  * crash points: a ledger entry for a part that never landed is not
    counted, a part the ledger does not name fails the day closed, a lost
    sidecar is repaired from the manifest;
  * no key material in any log line, output or exception text.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
from datetime import timedelta

import pytest

from apps.octo.retention import archive as archive_module
from apps.octo.retention import archive_crypto as crypto
from apps.octo.retention.archive import ArchiveError, ColdArchive
from apps.octo.retention.job import RetentionJob, archive_status
from apps.octo.retention.tests._crypto_fixtures import (
    A, B, keypair, leaked, recipients_file, row,
)
from apps.octo.tests._tiering_fixtures import (
    NOW, audit_rows, db, iso, make_root, rows, write_telemetry,
)

pytest.importorskip("pyrage")

DAY = "2026-09-20"


@pytest.fixture
def root(tmp_path, monkeypatch):
    return make_root(tmp_path, monkeypatch, tenants=(A, B))


@pytest.fixture
def key(tmp_path):
    return keypair(tmp_path)


@pytest.fixture
def arch_root(tmp_path):
    p = tmp_path / "archive"
    p.mkdir(mode=0o700)
    os.chmod(p, 0o700)
    return p


def _enc(*publics: str) -> crypto.ArchiveEncryption:
    return crypto.with_recipients(tuple(publics))


def _job(root, **kw) -> RetentionJob:
    kw.setdefault("archive_from_env", False)
    return RetentionJob(data_root=root, now=lambda: NOW, **kw)


def _seed(root, slug=A) -> dict:
    """Raw telemetry: three rows on 2026-09-20 and one on 09-21 (expired —
    the cutoff is 2026-09-22), one kept."""
    old = [write_telemetry(root, slug, received_at=iso(NOW - timedelta(days=9, hours=h)),
                           domain="nas.acme.example", n=h) for h in range(3)]
    edge = write_telemetry(root, slug, received_at="2026-09-21T23:59:59.000Z",
                           domain="edge.acme.example", n=9)
    kept = write_telemetry(root, slug, received_at="2026-09-22T00:00:00.000Z",
                           domain="kept.acme.example", n=10)
    return {"old": old, "edge": edge, "kept": kept}


def _env(monkeypatch, *, recipients=None, mode=None, archive_root=None):
    if archive_root is not None:
        monkeypatch.setenv("OCTO_ARCHIVE_ROOT", str(archive_root))
    if recipients is not None:
        monkeypatch.setenv(crypto.RECIPIENTS_ENV, str(recipients))
    if mode is not None:
        monkeypatch.setenv(crypto.POLICY_ENV, mode)


def _raw_ids(root, slug=A) -> set:
    return {r[0] for r in rows(db(root, slug, "telemetry"), "SELECT id FROM telemetry_raw")}


# ---------------------------------------------------------------------------
# The format: round trip, interop, one part per run per day
# ---------------------------------------------------------------------------

def test_round_trip_one_part_per_run_per_day(arch_root, key):
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    old_umask = os.umask(0o022)
    try:
        w = arch.day_writer(A, DAY)
        for chunk in ([row(1, DAY), row(2, DAY)], [row(3, DAY)], [row(4, DAY), row(1, DAY)]):
            w.add(chunk)
        out = w.finish()
    finally:
        os.umask(old_umask)
    assert (out.rows_added, out.rows_already, out.rows_total, out.encrypted) == (4, 1, 4, True)
    part = arch.part_file(A, DAY, 1)
    assert out.file == str(part) and part.name == f"{A}-telemetry-{DAY}.p001.jsonl.gz.age"
    assert not arch.day_file(A, DAY).exists()           # no plaintext written
    ct = part.read_bytes()
    assert ct.startswith(b"age-encryption.org/v1\n-> X25519 ")
    assert b"acme.example" not in ct and b"acme-laptop" not in ct
    # The sidecar covers the CIPHERTEXT (sha256sum -c format).
    assert arch.sidecar(part).read_text() == f"{hashlib.sha256(ct).hexdigest()}  {part.name}\n"
    assert arch.verify_day(A, DAY)
    # Readable with the operator's identity — never without.
    ids = crypto.load_identities(key.identity_path)
    got = arch.read_day(A, DAY, identities=ids)
    assert [r["id"] for r in got] == [1, 2, 3, 4]
    assert got[0]["domain"] == "printer.acme.example" and got[0]["tenant"] == A
    with pytest.raises(ArchiveError, match="needs the operator's age identity file"):
        arch.read_day(A, DAY)
    # The ledger: ids only, as ranges — no payload, no names.
    ledger = arch.ledger_file(A, DAY).read_text()
    assert f"{part.name} 1-4\n" in ledger and "acme.example" not in ledger
    # 0700 folders, 0600 files (umask 022 notwithstanding).
    for p in [arch_root / "telemetry", *(arch_root / "telemetry").rglob("*")]:
        assert stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600), p
    # A later run: a new part with only what is new.
    out2 = arch.append(A, DAY, [row(3, DAY), row(5, DAY)])
    assert (out2.rows_added, out2.rows_already) == (1, 1)
    assert [p.name for p in arch.encrypted_files(A, DAY)] == [
        part.name, f"{A}-telemetry-{DAY}.p002.jsonl.gz.age"]
    assert [r["id"] for r in arch.read_day(A, DAY, identities=ids)] == [1, 2, 3, 4, 5]
    # Nothing new: no part at all.
    assert arch.append(A, DAY, [row(5, DAY)]).rows_added == 0
    assert len(arch.encrypted_files(A, DAY)) == 2


def test_the_manifest_records_every_file(arch_root, key, tmp_path):
    escrow = keypair(tmp_path, "escrow")
    arch = ColdArchive(arch_root, encryption=_enc(key.public, escrow.public))
    arch.append(A, DAY, [row(1, DAY), row(2, DAY)])
    arch.append(A, DAY, [row(3, DAY)])
    m = arch.manifest(A)
    assert m["version"] == 2 and m["tenant"] == A and m["kind"] == "telemetry"
    p1 = f"2026/{A}-telemetry-{DAY}.p001.jsonl.gz.age"
    p2 = f"2026/{A}-telemetry-{DAY}.p002.jsonl.gz.age"
    for rel, part, n in ((p1, 1, 2), (p2, 2, 1)):
        e = m["files"][rel]
        data = (arch.tenant_dir(A) / rel).read_bytes()
        assert e["encrypted"] is True and e["scheme"] == "age-x25519"
        assert e["recipients"] == [key.public, escrow.public]      # public keys only
        assert (e["part"], e["rows"], e["day"]) == (part, n, DAY)
        assert e["sha256"] == hashlib.sha256(data).hexdigest() and e["bytes"] == len(data)
    assert m["days"][DAY]["rows"] == 3
    assert m["days"][DAY]["files"] == [p1, p2] == m["days"][DAY]["encrypted_files"]
    assert "AGE-SECRET-KEY" not in json.dumps(m)
    # Either recipient decrypts (primary + escrow).
    for kp in (key, escrow):
        got = arch.read_day(A, DAY, identities=crypto.load_identities(kp.identity_path))
        assert [r["id"] for r in got] == [1, 2, 3]


def test_a_large_day_rolls_over_into_several_parts(arch_root, key):
    arch = ColdArchive(arch_root, encryption=_enc(key.public), part_max_bytes=1)
    w = arch.day_writer(A, DAY)
    for i in range(1, 4):
        w.add([row(i, DAY)])
    assert w.finish().rows_added == 3
    assert len(arch.encrypted_files(A, DAY)) == 3
    got = arch.read_day(A, DAY, identities=crypto.load_identities(key.identity_path))
    assert [r["id"] for r in got] == [1, 2, 3]


@pytest.mark.skipif(shutil.which("age") is None, reason="the age CLI is not on PATH")
def test_interop_with_the_age_cli(arch_root, key, tmp_path):
    """What Athena writes, the stock CLI decrypts — and the other way round."""
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    arch.append(A, DAY, [row(1, DAY), row(2, DAY)])
    out = subprocess.run(["age", "-d", "-i", str(key.identity_path),
                          str(arch.part_file(A, DAY, 1))], capture_output=True, check=True)
    lines = gzip.decompress(out.stdout).decode().splitlines()
    assert [json.loads(x)["id"] for x in lines] == [1, 2]
    plain = gzip.compress(b'{"id":7}\n')
    enc = subprocess.run(["age", "-r", key.public], input=plain, capture_output=True,
                         check=True).stdout
    ids = crypto.load_identities(key.identity_path)
    assert ids.decrypt(enc) == plain


# ---------------------------------------------------------------------------
# Dedupe across plaintext and encrypted; a mixed day restores as one day
# ---------------------------------------------------------------------------

def test_dedupe_across_plaintext_and_encrypted_parts(arch_root, key):
    plain = ColdArchive(arch_root)                                   # the 2026-10-07 archive
    plain.append(A, DAY, [row(1, DAY), row(2, DAY), row(3, DAY)])
    enc = ColdArchive(arch_root, encryption=_enc(key.public))
    out = enc.append(A, DAY, [row(2, DAY), row(3, DAY), row(4, DAY), row(5, DAY)])
    assert (out.rows_added, out.rows_already) == (2, 2)
    assert enc._read_ledger(A, DAY) == {enc.part_file(A, DAY, 1).name: {4, 5}}
    # Encryption switched off again: the ledger still dedupes (the plaintext
    # file gets only what no file holds).
    out = plain.append(A, DAY, [row(4, DAY), row(5, DAY), row(6, DAY)])
    assert (out.rows_added, out.rows_already) == (1, 2)
    assert {r["id"] for r in archive_module._parse(
        plain.day_file(A, DAY).read_bytes(), "x")} == {1, 2, 3, 6}
    assert enc.known_ids(A, DAY) == {1, 2, 3, 4, 5, 6}
    m = enc.manifest(A)
    assert m["days"][DAY]["rows"] == 6
    assert m["days"][DAY]["file"] == f"2026/{A}-telemetry-{DAY}.jsonl.gz"   # 10-07 keys kept
    assert m["files"][f"2026/{A}-telemetry-{DAY}.jsonl.gz"]["encrypted"] is False
    assert m["files"][f"2026/{A}-telemetry-{DAY}.jsonl.gz"]["rows"] == 4
    got = enc.read_day(A, DAY, identities=crypto.load_identities(key.identity_path))
    assert sorted(r["id"] for r in got) == [1, 2, 3, 4, 5, 6] and len(got) == 6


def test_a_mixed_day_restores_as_one_day(arch_root, key, tmp_path, capsys, caplog):
    import scripts.restore_telemetry_archive as restore_script

    ColdArchive(arch_root).append(A, DAY, [row(1, DAY), row(2, DAY)])
    ColdArchive(arch_root, encryption=_enc(key.public)).append(
        A, DAY, [row(2, DAY), row(3, DAY), row(4, DAY)])
    out = tmp_path / "scratch" / "acme-dns.db"
    caplog.set_level(logging.DEBUG)
    # Without the identity the day is not loaded (and says why).
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(out)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert "--identity" in report["days"][DAY]["error"]
    other = tmp_path / "scratch" / "acme-dns-2.db"
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(other),
                                "--identity", str(key.identity_path)]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["days"][DAY] == {"ok": True, "rows": 4, "loaded": 4, "verified": True,
                                   "files": 2, "encrypted_files": 1}
    assert rows(other, "SELECT id, domain, device_name FROM telemetry_raw ORDER BY id") == [
        (i, "printer.acme.example", "acme-laptop-07") for i in (1, 2, 3, 4)]
    assert rows(other, "SELECT day, rows FROM restored_telemetry_archive") == [(DAY, 4)]
    assert stat.S_IMODE(other.stat().st_mode) == 0o600
    assert key.public[:12] in captured.err                     # the public key's short form
    assert not leaked(key.secret, captured.out, captured.err, caplog.text)


def test_restore_refuses_an_identity_others_can_read_and_never_echoes_it(
        arch_root, key, tmp_path, capsys):
    import scripts.restore_telemetry_archive as restore_script

    ColdArchive(arch_root, encryption=_enc(key.public)).append(A, DAY, [row(1, DAY)])
    out = tmp_path / "scratch" / "x.db"
    os.chmod(key.identity_path, 0o640)
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(out),
                                "--identity", str(key.identity_path)]) == 2
    err = capsys.readouterr().err
    assert "chmod 600" in err and not out.exists()
    os.chmod(key.identity_path, 0o600)
    # A garbled identity line: named by number, never shown.
    bad = tmp_path / "bad-identity.txt"
    bad.write_text("# a comment\n" + key.secret[:-3] + "zzz\n")
    os.chmod(bad, 0o600)
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(out), "--identity", str(bad)]) == 2
    captured = capsys.readouterr()
    assert "line 2 is not an age X25519 identity" in captured.err
    assert not leaked(key.secret, captured.out, captured.err)
    # The wrong key: the day fails, the message says so (and nothing more).
    stranger = keypair(tmp_path, "stranger")
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(tmp_path / "scratch" / "y.db"),
                                "--identity", str(stranger.identity_path)]) == 1
    captured = capsys.readouterr()
    assert "none of the identities given can decrypt it" in captured.out
    assert not leaked(stranger.secret, captured.out, captured.err)


def test_the_checksum_is_verified_before_decrypting(arch_root, key, monkeypatch):
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    arch.append(A, DAY, [row(1, DAY)])
    part = arch.part_file(A, DAY, 1)
    part.write_bytes(part.read_bytes() + b"x")
    ids = crypto.load_identities(key.identity_path)
    calls = []
    monkeypatch.setattr(crypto.AgeIdentities, "decrypt",
                        lambda self, data, where="": calls.append(where) or b"")
    with pytest.raises(ArchiveError, match="checksum does not match"):
        arch.read_day(A, DAY, identities=ids)
    assert calls == []


# ---------------------------------------------------------------------------
# Recipients validation and the policy
# ---------------------------------------------------------------------------

def test_recipients_validation(tmp_path, key):
    escrow = keypair(tmp_path, "escrow")
    ok = recipients_file(tmp_path, "# primary (operator's vault)", key.public, "",
                         "# escrow", escrow.public, key.public, mode=0o644)
    assert crypto.load_recipients(ok) == (key.public, escrow.public)   # 0644 is fine: public
    cases = {
        "malformed": (["# ok", key.public, key.public[:-4] + "qqqq"], "line 3 is not a valid"),
        "not-age1": (["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnly alice@example.test"],
                     "line 1 is not an age public key"),
        "empty": (["# nothing here", ""], "holds no public key"),
    }
    for name, (lines, msg) in cases.items():
        p = recipients_file(tmp_path, *lines, name=f"{name}.txt")
        with pytest.raises(crypto.EncryptionConfigError) as exc:
            crypto.load_recipients(p)
        assert msg in str(exc.value), name
        for line in lines:
            if line and not line.startswith("#"):
                assert line not in str(exc.value), name          # never echoed


@pytest.mark.parametrize("where", ["line", "comment", "pem"])
def test_a_private_key_in_the_recipients_file_is_a_hard_refusal(tmp_path, key, where):
    # A fake PEM block (no key in it), its marker assembled here so the
    # repository's pre-commit credential scan does not read it as a key.
    marker = "OPENSSH " + "PRIVATE KEY"
    lines = {
        "line": [key.public, key.secret],
        "comment": [f"# backup: {key.secret}", key.public],
        "pem": [key.public, f"-----BEGIN {marker}-----", "b3BlbnNzaC1rZXk=",
                f"-----END {marker}-----"],
    }[where]
    p = recipients_file(tmp_path, *lines)
    with pytest.raises(crypto.EncryptionConfigError) as exc:
        crypto.load_recipients(p)
    msg = str(exc.value)
    assert "PRIVATE key" in msg and "must never be on this machine" in msg
    assert not leaked(key.secret, msg) and "b3BlbnNzaC1rZXk" not in msg


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_a_recipients_file_others_can_write_is_refused(tmp_path, key, mode):
    p = recipients_file(tmp_path, key.public, mode=mode)
    with pytest.raises(crypto.EncryptionConfigError, match="writable by group or other"):
        crypto.load_recipients(p)


def test_the_policy(tmp_path, key, monkeypatch):
    default = tmp_path / "secrets" / "archive-recipients.txt"
    monkeypatch.setattr(crypto, "DEFAULT_RECIPIENTS_PATH", default)
    # Nothing configured: off, said.
    pol = crypto.load_policy({})
    assert (pol.mode, pol.source, pol.active) == ("off", "default", False)
    assert pol.note().startswith("archive NOT encrypted — no recipients configured")
    # The default file exists: required by default.
    recipients_file(tmp_path, key.public)
    pol = crypto.load_policy({})
    assert (pol.mode, pol.source, pol.active, pol.recipients) == (
        "required", "default", True, (key.public,))
    assert pol.note() is None
    st = pol.status()
    assert st["recipients"] == [{"short": crypto.recipient_short(key.public),
                                 "fingerprint": crypto.recipient_fingerprint(key.public)}]
    assert key.public not in json.dumps(st)                    # short forms only
    # Explicit off: plaintext, said — the recipients still listed.
    pol = crypto.load_policy({crypto.POLICY_ENV: "off"})
    assert (pol.mode, pol.active, pol.recipients) == ("off", False, (key.public,))
    assert "OCTO_ARCHIVE_ENCRYPTION=off" in pol.note()
    # An explicit path that does not exist: required (the operator meant it), unusable.
    pol = crypto.load_policy({crypto.RECIPIENTS_ENV: str(tmp_path / "missing.txt")})
    assert pol.mode == "required" and not pol.active and "does not exist" in pol.error
    # Required, nothing configured: unusable.
    monkeypatch.setattr(crypto, "DEFAULT_RECIPIENTS_PATH", tmp_path / "none.txt")
    pol = crypto.load_policy({crypto.POLICY_ENV: "required"})
    assert not pol.active and "no recipients file" in pol.error
    # A value that is neither: unusable, the value never echoed.
    pol = crypto.load_policy({crypto.POLICY_ENV: "AGE-SECRET-KEY-1NOTAREALKEY"})
    assert not pol.active and pol.error == "OCTO_ARCHIVE_ENCRYPTION must be 'required' or 'off'"


# ---------------------------------------------------------------------------
# The job: encrypted end to end, fail closed, "NOT encrypted"
# ---------------------------------------------------------------------------

def test_the_job_archives_encrypted_and_prunes(root, arch_root, key, tmp_path, monkeypatch,
                                               caplog):
    import scripts.restore_telemetry_archive as restore_script

    s = _seed(root)
    originals = rows(db(root, A, "telemetry"),
                     "SELECT id, received_at, payload, payload_sha256 FROM telemetry_raw "
                     "WHERE id != ? ORDER BY id", (s["kept"],))
    _env(monkeypatch, recipients=recipients_file(tmp_path, key.public), archive_root=arch_root)
    caplog.set_level(logging.DEBUG)
    report = RetentionJob(data_root=root, now=lambda: NOW).run(trigger="script")
    t = next(t for t in report.tenants if t.slug == A)
    assert t.classes["telemetry_raw"].deleted == 4 and report.status == "ok"
    assert report.archive["encrypted"] is True and report.archive["encryption_note"] is None
    assert t.archive["encrypted"] is True and t.archive["days"] == [DAY, "2026-09-21"]
    assert _raw_ids(root) == {s["kept"]}
    arch = ColdArchive(arch_root)
    assert not arch.day_file(A, DAY).exists()
    assert [p.name for p in arch.encrypted_files(A, DAY)] == [
        f"{A}-telemetry-{DAY}.p001.jsonl.gz.age"]
    plan = json.loads(audit_rows(root, "retention_enforce")[0]["after_state"])
    assert plan["archive"]["encrypted"] is True
    summary = json.loads(audit_rows(root, "retention_run")[0]["after_state"])
    assert summary["archive"]["encrypted"] is True
    # Restored through the script with the operator's identity.
    out = tmp_path / "scratch" / "acme.db"
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--from", DAY, "--to", "2026-09-21", "--out", str(out),
                                "--identity", str(key.identity_path)]) == 0
    assert rows(out, "SELECT id, received_at, payload, payload_sha256 FROM telemetry_raw "
                     "ORDER BY id") == originals
    assert not leaked(key.secret, caplog.text)


def test_required_but_unusable_prunes_nothing_and_says_why_everywhere(
        root, arch_root, tmp_path, monkeypatch, capsys):
    import scripts.enforce_retention as enforce_script
    import scripts.move_telemetry_out_of_events as move_script

    s = _seed(root)
    _env(monkeypatch, mode="required", archive_root=arch_root)     # no recipients anywhere
    status = archive_status()
    assert status["usable"] is False and status["encrypted"] is False
    assert "archive encryption is required but unusable" in status["reason"]
    assert "no recipients file" in status["reason"]
    report = _job(root, archive=ColdArchive.from_env()).run(trigger="script")
    raw = next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"]
    assert (raw.status, raw.deleted, raw.held) == ("blocked", 0, 4)
    assert "archive unusable" in raw.note and report.status == "partial"
    assert set(s["old"]) | {s["edge"]} <= _raw_ids(root)
    assert list(arch_root.iterdir()) == []                      # nothing written either
    # The scripts' dry runs show the reason.
    assert enforce_script.main(["--data-root", str(root), "--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "UNUSABLE: archive encryption is required but unusable" in out
    assert "encryption REQUIRED but UNUSABLE" in out
    assert move_script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "UNUSABLE: archive encryption is required but unusable" in out
    assert "would prune nothing (archive unusable)" in out
    # A bad recipients file: the same, with the file's problem.
    bad = recipients_file(tmp_path, "age1notakey")
    _env(monkeypatch, recipients=bad)
    status = archive_status()
    assert status["usable"] is False and "line 1 is not a valid" in status["reason"]
    assert "age1notakey" not in status["reason"]


def test_encryption_off_says_not_encrypted_on_every_run(root, arch_root, tmp_path, key,
                                                       monkeypatch, capsys, caplog):
    import scripts.enforce_retention as enforce_script

    _seed(root)
    _env(monkeypatch, recipients=recipients_file(tmp_path, key.public), mode="off",
         archive_root=arch_root)
    caplog.set_level(logging.WARNING, logger="apps.octo.retention.job")
    report = RetentionJob(data_root=root, now=lambda: NOW).run(trigger="script")
    assert report.status == "ok"
    assert report.archive["encrypted"] is False
    assert report.archive["encryption_note"].startswith(
        "archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off")
    assert "archive NOT encrypted" in caplog.text
    assert ColdArchive(arch_root).day_file(A, DAY).exists()   # plaintext, as before
    plan = json.loads(audit_rows(root, "retention_enforce")[0]["after_state"])
    assert plan["archive"]["encrypted"] is False
    assert "archive NOT encrypted" in plan["archive"]["note"]
    summary = json.loads(audit_rows(root, "retention_run")[0]["after_state"])
    assert summary["archive"]["encryption_note"].startswith("archive NOT encrypted")
    assert enforce_script.main(["--data-root", str(root), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "archive: archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off" in out
    assert "archive: files: 2 plaintext · 0 encrypted" in out


def test_status_counts_and_short_forms(arch_root, tmp_path, key, monkeypatch):
    from apps.octo.retention import job as job_module

    ColdArchive(arch_root).append(A, DAY, [row(1, DAY)])
    ColdArchive(arch_root).append(B, DAY, [row(1, DAY)])
    ColdArchive(arch_root, encryption=_enc(key.public)).append(A, DAY, [row(2, DAY)])
    _env(monkeypatch, recipients=recipients_file(tmp_path, key.public), archive_root=arch_root)
    st = archive_status()
    assert st["files"] == {"plaintext": 2, "encrypted": 1, "plaintext_temp": 0,
                          "complete": True}
    assert st["encrypted"] is True and st["encryption"]["mode"] == "required"
    assert st["encryption"]["recipients"][0]["short"].startswith(key.public[:12])
    assert key.public not in json.dumps(st)
    lines = job_module.archive_encryption_lines(st)
    assert lines[0].startswith("archive: ENCRYPTED (age X25519) to 1 recipient(s)")
    # The API's count is cached (a walk of array disks every 30 s is not).
    ColdArchive(arch_root, encryption=_enc(key.public)).append(B, DAY, [row(2, DAY)])
    assert archive_status(cached_counts=True)["files"]["encrypted"] == 1
    assert archive_status()["files"]["encrypted"] == 2


# ---------------------------------------------------------------------------
# Crash points
# ---------------------------------------------------------------------------

def test_a_part_that_never_landed_is_not_counted(arch_root, key, monkeypatch):
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    real = archive_module._atomic_write

    def no_parts(path, data):
        if path.name.endswith(".p001.jsonl.gz.age"):
            raise OSError(28, "No space left on device")
        return real(path, data)

    monkeypatch.setattr(archive_module, "_atomic_write", no_parts)
    with pytest.raises(ArchiveError, match="No space left"):
        arch.append(A, DAY, [row(1, DAY), row(2, DAY)])
    monkeypatch.setattr(archive_module, "_atomic_write", real)
    # The ledger named p001 before it failed — its ids are NOT archived.
    assert arch.known_ids(A, DAY) == set()
    out = arch.append(A, DAY, [row(1, DAY), row(2, DAY)])
    assert out.rows_added == 2 and out.file.endswith(".p002.jsonl.gz.age")
    # The stale entry is gone from the ledger and the manifest.
    assert set(arch._read_ledger(A, DAY)) == {arch.part_file(A, DAY, 2).name}
    assert list(arch.manifest(A)["files"]) == [f"2026/{A}-telemetry-{DAY}.p002.jsonl.gz.age"]


def test_a_part_the_ledger_does_not_name_fails_the_day_closed(root, arch_root, key):
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    arch.append(A, DAY, [row(1, DAY)])
    arch.ledger_file(A, DAY).unlink()
    with pytest.raises(ArchiveError, match="not in the day's row-id ledger"):
        arch.append(A, DAY, [row(2, DAY)])
    # Through the job: those rows stay in telemetry.db.
    s = _seed(root)
    report = _job(root, archive=arch).run(slugs=[A])
    raw = next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"]
    assert raw.status == "blocked" and raw.held == 3 and raw.deleted == 1
    assert set(s["old"]) <= _raw_ids(root)


def test_a_lost_sidecar_is_repaired_from_the_manifest(arch_root, key):
    arch = ColdArchive(arch_root, encryption=_enc(key.public))
    arch.append(A, DAY, [row(1, DAY)])
    side = arch.sidecar(arch.part_file(A, DAY, 1))
    want = side.read_text()
    side.unlink()
    arch.append(A, DAY, [row(2, DAY)])
    assert side.read_text() == want
    # A part that no longer matches its manifest entry is not "repaired".
    p1 = arch.part_file(A, DAY, 1)
    p1.write_bytes(p1.read_bytes() + b"x")
    side.unlink()
    with pytest.raises(ArchiveError, match="does not match the manifest"):
        arch.append(A, DAY, [row(3, DAY)])


# ---------------------------------------------------------------------------
# No key material anywhere
# ---------------------------------------------------------------------------

def test_no_key_material_in_any_log_line_or_exception(root, arch_root, key, tmp_path,
                                                      monkeypatch, capsys, caplog):
    import scripts.encrypt_archive as encrypt_script
    import scripts.enforce_retention as enforce_script
    import scripts.restore_telemetry_archive as restore_script

    caplog.set_level(logging.DEBUG)
    texts: list[str] = []
    # Every refusal / error text the module can produce around this key.
    for lines in ([key.secret], [f"#{key.secret}"], [key.public, key.secret.lower()]):
        try:
            crypto.load_recipients(recipients_file(tmp_path, *lines, name="r.txt"))
        except crypto.EncryptionConfigError as exc:
            texts.append(str(exc))
            texts.append(repr(exc))
    bad_ident = tmp_path / "bad-ident.txt"
    bad_ident.write_text(key.secret[:-2] + "zz\n")
    os.chmod(bad_ident, 0o600)
    try:
        crypto.load_identities(bad_ident)
    except crypto.EncryptionConfigError as exc:
        texts.append(str(exc))
    ids = crypto.load_identities(key.identity_path)
    texts += [repr(ids), str(ids)]
    try:
        crypto.load_identities(keypair(tmp_path, "other").identity_path).decrypt(
            _enc(key.public).encrypt(b"x"), "f")
    except crypto.DecryptionError as exc:
        texts.append(str(exc))
    # A full flow: job → restore → convert → verify → delete.
    _seed(root)
    ColdArchive(arch_root).append(A, "2026-09-01", [row(1, "2026-09-01")])
    _env(monkeypatch, recipients=recipients_file(tmp_path, key.public), archive_root=arch_root)
    assert enforce_script.main(["--data-root", str(root), "--reason", "test run"]) == 0
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A,
                                "--day", DAY, "--out", str(tmp_path / "s" / "a.db"),
                                "--identity", str(key.identity_path)]) == 0
    for argv in ([], ["--apply"], ["--verify", "--identity", str(key.identity_path)],
                 ["--delete-plaintext"]):
        assert encrypt_script.main(["--data-root", str(root), *argv]) == 0, argv
    captured = capsys.readouterr()
    texts += [captured.out, captured.err, caplog.text]
    assert not leaked(key.secret, *texts)
    # Nor anywhere in the archive.
    for p in arch_root.rglob("*"):
        if p.is_file() and not p.name.endswith(".age"):
            assert not leaked(key.secret, p.read_text(errors="replace")), p


# ---------------------------------------------------------------------------
# Review fixes (2026-10-07)
# ---------------------------------------------------------------------------

def test_an_encrypted_archive_never_falls_back_to_plaintext_when_its_recipients_go(
        root, arch_root, tmp_path, key, monkeypatch):
    """Mode unset, encryption on by the default recipients file; the file
    goes missing later (moved aside in a key rotation, a secrets dir
    restored without it). The archive already holds encrypted files: fail
    closed — never plaintext unless OCTO_ARCHIVE_ENCRYPTION=off says so."""
    default = tmp_path / "secrets" / "archive-recipients.txt"
    monkeypatch.setattr(crypto, "DEFAULT_RECIPIENTS_PATH", default)
    monkeypatch.delenv(crypto.POLICY_ENV, raising=False)
    monkeypatch.delenv(crypto.RECIPIENTS_ENV, raising=False)
    _env(monkeypatch, archive_root=arch_root)
    # A fresh archive, nothing configured: off, as before.
    arch = ColdArchive.from_env()
    assert arch.encryption.mode == "off" and not arch.encryption_in_use()
    # The operator drops the recipients file in: required by default.
    recipients_file(tmp_path, key.public)
    _seed(root)
    report = RetentionJob(data_root=root, now=lambda: NOW).run(trigger="script")
    assert report.status == "ok" and report.archive["encrypted"] is True
    marker = arch_root / "telemetry" / archive_module.ENCRYPTED_MARKER
    assert marker.is_file() and stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert ColdArchive.from_env().encryption_in_use()
    # The recipients file goes missing: required, UNUSABLE — not plaintext.
    default.unlink()
    enc = ColdArchive.from_env().encryption
    assert (enc.mode, enc.source, enc.active) == ("required", "archive", False)
    assert "already holds encrypted files" in enc.error
    status = archive_status()
    assert status["usable"] is False and "already holds encrypted files" in status["reason"]
    assert status["encryption"]["source"] == "archive"
    late = write_telemetry(root, A, received_at=iso(NOW - timedelta(days=9)),
                           domain="late.acme.example", n=20)
    report = RetentionJob(data_root=root, now=lambda: NOW).run(trigger="script")
    raw = next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"]
    assert (raw.status, raw.deleted) == ("blocked", 0) and late in _raw_ids(root)
    assert ColdArchive(arch_root).file_counts()["plaintext"] == 0     # nothing plaintext
    # The same through load_policy directly.
    pol = crypto.load_policy({}, in_use=True)
    assert pol.mode == "required" and not pol.active
    # Plaintext again only when said: OCTO_ARCHIVE_ENCRYPTION=off.
    monkeypatch.setenv(crypto.POLICY_ENV, "off")
    arch = ColdArchive.from_env()
    assert arch.encryption.mode == "off" and arch.unusable_reason() is None
    assert arch.encryption.note().startswith("archive NOT encrypted — OCTO_ARCHIVE_ENCRYPTION=off")
    # The recipients file back (mode unset again): encrypted, usable.
    monkeypatch.delenv(crypto.POLICY_ENV)
    recipients_file(tmp_path, key.public)
    arch = ColdArchive.from_env()
    assert arch.encryption.active and arch.unusable_reason() is None


def test_a_private_key_given_as_a_path_is_refused_and_never_echoed(
        arch_root, key, tmp_path, monkeypatch, capsys, caplog):
    """The identity line pasted into OCTO_ARCHIVE_RECIPIENTS_PATH (or given
    as --identity): refused, and the value appears nowhere — not in the
    status, the scripts' output, the logs or an exception."""
    import scripts.encrypt_archive as encrypt_script
    import scripts.restore_telemetry_archive as restore_script
    from apps.octo.retention import job as job_module

    caplog.set_level(logging.DEBUG)
    monkeypatch.delenv(crypto.POLICY_ENV, raising=False)
    _env(monkeypatch, recipients=key.secret, archive_root=arch_root)
    pol = crypto.load_policy()
    assert (pol.mode, pol.active, pol.recipients_path) == ("required", False, None)
    assert "is a PRIVATE key, not a file path" in pol.error
    status = archive_status()
    assert status["usable"] is False and "is a PRIVATE key" in status["reason"]
    assert status["encryption"]["recipients_path"] is None
    texts = [json.dumps(status), pol.error, repr(pol), json.dumps(pol.status()),
             *job_module.archive_encryption_lines(status)]
    # Off: plaintext — the problem still said, never the value.
    monkeypatch.setenv(crypto.POLICY_ENV, "off")
    pol = crypto.load_policy()
    assert pol.mode == "off" and "is a PRIVATE key" in pol.recipients_error
    status = archive_status()
    texts += [json.dumps(status), *job_module.archive_encryption_lines(status)]
    # The key itself as --identity: refused before anything is read.
    with pytest.raises(crypto.EncryptionConfigError) as exc:
        crypto.load_identities(key.secret)
    texts += [str(exc.value), repr(exc.value)]
    ColdArchive(arch_root, encryption=_enc(key.public)).append(A, DAY, [row(1, DAY)])
    assert restore_script.main(["--archive-root", str(arch_root), "--tenant", A, "--day", DAY,
                                "--out", str(tmp_path / "s" / "x.db"),
                                "--identity", key.secret]) == 2
    assert encrypt_script.main(["--archive-root", str(arch_root), "--data-root",
                                str(tmp_path), "--verify", "--identity", key.secret]) == 2
    captured = capsys.readouterr()
    assert captured.err.count("is a PRIVATE key, not a file path") == 2
    assert not (tmp_path / "s" / "x.db").exists()
    texts += [captured.out, captured.err, caplog.text]
    assert not leaked(key.secret, *texts)


def test_a_stale_plaintext_sidecar_is_healed_by_an_encrypted_run(arch_root, key, monkeypatch):
    """The last plaintext run crashed between the data file's rename and its
    sidecar's; the next run is encrypted. The sidecar is rewritten (the
    plaintext path's rule), so restore and encrypt_archive.py still take
    the day."""
    plain = ColdArchive(arch_root)
    plain.append(A, DAY, [row(1, DAY)])
    real = archive_module._atomic_write

    def no_sidecar(path, data):
        if path.name.endswith(".jsonl.gz.sha256"):
            raise OSError(5, "Input/output error")
        return real(path, data)

    monkeypatch.setattr(archive_module, "_atomic_write", no_sidecar)
    with pytest.raises(ArchiveError):
        plain.append(A, DAY, [row(2, DAY)])
    monkeypatch.setattr(archive_module, "_atomic_write", real)
    day_file = plain.day_file(A, DAY)
    assert not plain.verify_file(day_file)          # rows 1-2, the sidecar of row 1
    enc = ColdArchive(arch_root, encryption=_enc(key.public))
    out = enc.append(A, DAY, [row(1, DAY), row(2, DAY), row(3, DAY)])
    assert out.rows_added == 1 and out.file == str(enc.part_file(A, DAY, 1))
    assert enc.verify_file(day_file) and enc.verify_day(A, DAY)
    entry = enc.manifest(A)["files"][f"2026/{A}-telemetry-{DAY}.jsonl.gz"]
    assert entry["sha256"] == hashlib.sha256(day_file.read_bytes()).hexdigest()
    assert entry["rows"] == 2 and enc.manifest(A)["days"][DAY]["rows"] == 3
    # A run with nothing new heals it too (and writes no part).
    side = enc.sidecar(day_file)
    side.write_text(f"{'0' * 64}  {day_file.name}\n")
    out = enc.append(A, DAY, [row(2, DAY)])
    assert out.rows_added == 0 and enc.verify_file(day_file)
    assert len(enc.encrypted_files(A, DAY)) == 1
    # Restore and conversion take the day.
    ids = crypto.load_identities(key.identity_path)
    assert [r["id"] for r in enc.read_day(A, DAY, identities=ids)] == [1, 2, 3]
    assert enc.convert_day(A, DAY, _enc(key.public))["status"] == "encrypted"


def test_a_missing_mount_with_encryption_fine_is_not_called_unencrypted(
        root, tmp_path, key, caplog):
    """The root is unusable (mount missing) but the encryption policy is
    required and usable: the run reports the missing mount — it does not
    log "archive NOT encrypted" nor record encrypted=false."""
    from apps.octo.retention import job as job_module

    arch = ColdArchive(tmp_path / "not-mounted", encryption=_enc(key.public))
    st = archive_status(arch, from_env=False)
    assert (st["usable"], st["encrypted"], st["encryption_note"]) == (False, True, None)
    assert "does not exist" in st["reason"]
    assert job_module.archive_encryption_lines(st)[0].startswith("archive: ENCRYPTED")
    s = _seed(root)
    caplog.set_level(logging.WARNING, logger="apps.octo.retention.job")
    report = _job(root, archive=arch).run(trigger="script")
    assert report.archive["encrypted"] is True and report.archive["usable"] is False
    assert "archive NOT encrypted" not in caplog.text
    raw = next(t for t in report.tenants if t.slug == A).classes["telemetry_raw"]
    assert (raw.status, raw.deleted) == ("blocked", 0)
    assert set(s["old"]) <= _raw_ids(root)
    summary = json.loads(audit_rows(root, "retention_run")[0]["after_state"])
    assert summary["archive"]["encrypted"] is True and summary["archive"]["usable"] is False


def test_the_deploy_guide_keeps_the_key_and_the_decrypted_copy_off_the_array():
    """docs/operations/bundle.md: the identity is placed on tmpfs right
    before the one command that needs it and removed right after; the
    decrypted scratch DB goes to tmpfs (never an array share) and is
    removed in the same block."""
    import re
    from pathlib import Path

    path = Path(__file__).resolve().parents[4] / "docs" / "operations" / "bundle.md"
    readme = path.read_text()
    section = readme[readme.index("**Archive encryption"):readme.index("**Upgrade order**")]
    blocks = re.findall(r"```bash\n(.*?)```", section, re.S)
    restore = next(b for b in blocks if "restore_telemetry_archive.py" in b)
    convert = next(b for b in blocks if "encrypt_archive.py --verify" in b)
    for block in (restore, convert):
        placed = block.index("install -m 600")
        used = block.index("--identity /run/archive-identity.txt")
        removed = block.index("rm /dev/shm/archive-identity.txt")
        assert placed < used < removed, block
        assert "/dev/shm/archive-identity.txt" in block[placed:block.index("\n", placed)]
    assert "/mnt/" not in restore      # no array share (or any other mount): tmpfs only
    assert "R=/dev/shm/" in restore and 'rm -rf "$R"' in restore
    assert convert.index("rm /dev/shm/archive-identity.txt") < convert.index("--delete-plaintext")
