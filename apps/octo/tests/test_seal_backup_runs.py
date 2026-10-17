"""scripts/seal_backup_runs.py: the seal-at-source step for the backup vault
(the backup-vault design 2026-10-12, section 3; Rick's decision 2: seal at
source).

Pins:
  * a sealed run DECRYPTS (test-made age identity) to a tar holding the run
    byte for byte, its own backup report and the bundle config under
    bundle/; the .sha256 is over the ciphertext (sha256sum format); the meta
    has exactly the agreed keys and no tenant name or path; .complete is
    written LAST; a real backup_databases.py run seals, unseals
    (unseal_backup_run.py) and restores with restore_databases.py;
  * idempotent; --backfill (return codes "unknown"); catch-up of an older
    unsealed run; the return codes go only to the run the backup report
    names when it was made since --current-since, never to a neighbour (a
    backup that failed before making its run, overlapping runs, a refused
    run); a run is sealed only once FINISHED (its backup-report.json, or the
    report names it, or old and quiet: sealed as found); an empty run is a
    warning, not a nightly failure;
  * retention prunes only sealed outputs, only past N days by the run's
    stamp, .complete first, BEFORE anything is sealed; the backups root is
    never written;
  * --kind auto: 20 minutes after 23:00 America/Los_Angeles, DST-aware;
  * refusals: recipients (none, a bad line, a private key, writable by
    others, missing), nested roots, a sealed root others can write, a
    symlinked run, a run holding a symlink / subdirectory, non-stamp
    directories (warned, skipped), config files, --current-since;
  * a stray / planted / broken .complete is not "sealed"; the lock is
    waited for (then exit 3); no flock = exit 2; an unsupported directory
    fsync is tolerated;
  * Ctrl-C stops the whole tool; disk full stops the loop; the run made now
    goes first, then newest first; the free-space check;
  * two recipients can each decrypt; the dry run writes nothing; an
    interrupted seal (.tmp left, or a crash mid-stream) is redone;
    plaintext never appears in the sealed root, not even mid-stream; no key
    material in any output.

Every key pair is made by the test (pyrage); fixture tenants are fictional.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import stat
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pyrage = pytest.importorskip("pyrage")

import scripts.seal_backup_runs as seal  # noqa: E402
from apps.octo.retention import archive_crypto  # noqa: E402

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

NOW = datetime(2026, 10, 12, 6, 20, tzinfo=timezone.utc)
CURRENT = "20261012T060001Z"                    # 23:00 PDT = 01:00 CDT, the nightly
SINCE = "20261012T060000Z"                      # the host's clock just before the backup
MARKER = b"PLAINTEXT-MARKER-5e1f0c7a"           # in every plaintext input
TENANT = "acme-corp"
OTHER = "globex"
DONE = seal.RUN_REPORT_NAME                     # the run's "finished" marker


@pytest.fixture(autouse=True)
def _small_reserve(monkeypatch):
    """The real free-space check, with a reserve any test machine has."""
    monkeypatch.setattr(seal, "FREE_SPACE_RESERVE", 1024 * 1024)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod        # dataclasses resolve their module
    spec.loader.exec_module(mod)
    return mod


def _stamp(when: datetime) -> str:
    return when.strftime(seal.RUN_STAMP_FORMAT)


def _when(stamp: str) -> datetime:
    return seal.parse_stamp(stamp)


def _identity():
    ident = pyrage.x25519.Identity.generate()
    return ident, str(ident.to_public())


def _recipients(path: Path, *lines: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines))
    os.chmod(path, mode)
    return path


def make_run(backups: Path, stamp: str, *, mtime: datetime | None = None,
             big: bool = False, done: bool = True) -> dict[str, bytes]:
    """A run directory as backup_databases.py lays it out (contents need not
    be gzip: the seal never opens them); `done` = it holds its own report
    (the backup's last step). Files and the directory get an mtime (default:
    two minutes after the stamp)."""
    run = backups / stamp
    run.mkdir()
    files = {
        "registry.db.gz": MARKER + b"registry" + os.urandom(64),
        "global_audit.db.gz": MARKER + b"audit" + os.urandom(700),
        f"tenant_{TENANT}_events.db.gz": MARKER + os.urandom(1500),
        f"tenant_{OTHER}_telemetry.db.gz":
            MARKER + os.urandom((3 * 1024 * 1024 + 123) if big else 2048) + MARKER,
    }
    if done:
        files[DONE] = json.dumps({"dest_dir": f"/backup/{stamp}",
                                  "note": MARKER.decode()}).encode() + b"\n"
    for name, data in files.items():
        (run / name).write_bytes(data)
    ts = (mtime or (_when(stamp) + timedelta(minutes=2))).timestamp()
    for name in files:
        os.utime(run / name, (ts, ts))
    os.utime(run, (ts, ts))
    return files


def write_report(backups: Path, stamp: str) -> bytes:
    data = json.dumps({
        "data_root": "/var/lib/octo/state", "dest_dir": f"/backup/{stamp}",
        "databases_total": 4, "databases_failed": 0,
        "results": [{"label": f"tenant:{TENANT}:events", "note": MARKER.decode()}],
    }, indent=2).encode() + b"\n"
    (backups / "last-report.json").write_bytes(data)
    return data


def make_backup(backups: Path, stamp: str, **kw) -> dict[str, bytes]:
    """What one finished backup leaves: the run (marked) + the report naming it."""
    files = make_run(backups, stamp, **kw)
    write_report(backups, stamp)
    return files


@pytest.fixture
def world(tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    sealed = tmp_path / "sealed"
    sealed.mkdir(mode=0o700)
    ident, public = _identity()
    rec = _recipients(tmp_path / "secrets" / "archive-recipients.txt",
                      "# operator key", public)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    compose = bundle / "docker-compose.yml"
    compose.write_bytes(b"services:\n  octo-core: {}\n# " + MARKER + b"\n")
    host_script = bundle / "nightly-backup.sh"
    host_script.write_bytes(b"#!/bin/bash\n# " + MARKER + b"\n")
    return SimpleNamespace(tmp=tmp_path, backups=backups, sealed=sealed, ident=ident,
                           public=public, rec=rec, compose=compose, host_script=host_script)


def run_seal(w, *extra: str, now: datetime | None = NOW, configs: bool = True) -> int:
    argv = ["--backups-root", str(w.backups), "--sealed-root", str(w.sealed),
            "--recipients", str(w.rec)]
    if configs:
        argv += ["--config-file", str(w.compose), "--config-file", str(w.host_script)]
    return seal.main(argv + list(extra), now=now)


def nightly(w, *extra: str, backup_rc: int = 0, chain_rc: int = 0, since: str = SINCE,
            **kw) -> int:
    return run_seal(w, "--backup-rc", str(backup_rc), "--chain-rc", str(chain_rc),
                    "--current-since", since, *extra, **kw)


def decrypt(w, stamp: str, ident=None) -> bytes:
    data = (w.sealed / f"{stamp}.tar.age").read_bytes()
    return pyrage.decrypt(data, [ident or w.ident])


def members(plaintext: bytes) -> dict[str, tuple[tarfile.TarInfo, bytes | None]]:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:") as tar:
        for m in tar.getmembers():
            f = tar.extractfile(m) if m.isfile() else None
            out[m.name] = (m, f.read() if f else None)
    return out


def meta(w, stamp: str) -> dict:
    return json.loads((w.sealed / f"{stamp}.meta.json").read_text())


def outputs(w) -> set[str]:
    return {p.name for p in w.sealed.iterdir()}


def snapshot(root: Path) -> dict:
    """Every entry under `root`: type, bytes and mtime (symlinks not followed)."""
    out = {}
    for p in sorted(root.rglob("*")):
        st = os.lstat(p)
        if p.is_symlink():
            out[str(p.relative_to(root))] = ("link", os.readlink(p), st.st_mtime_ns)
        elif p.is_dir():
            out[str(p.relative_to(root))] = ("dir", None, st.st_mtime_ns)
        else:
            out[str(p.relative_to(root))] = ("file", hashlib.sha256(p.read_bytes()).hexdigest(),
                                             st.st_mtime_ns, st.st_mode)
    return out


def sealed_set(stamp: str) -> set[str]:
    return {f"{stamp}{s}" for s in seal.OUTPUT_SUFFIXES}


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


def hold_lock(w) -> int:
    fd = os.open(w.sealed / seal.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


# ---------------------------------------------------------------------------
# The sealed run
# ---------------------------------------------------------------------------

def test_a_sealed_run_decrypts_to_the_run_report_and_bundle_byte_for_byte(world, capsys):
    files = make_run(world.backups, CURRENT, big=True)
    report = write_report(world.backups, CURRENT)

    assert nightly(world, chain_rc=1) == 0

    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}
    plaintext = decrypt(world, CURRENT)
    got = members(plaintext)
    expected = {f"{CURRENT}/{n}" for n in files} | {
        f"{CURRENT}", "report/last-report.json",
        "bundle/docker-compose.yml", "bundle/nightly-backup.sh"}
    assert set(got) == expected
    assert f"{CURRENT}/{DONE}" in got                    # the run's own report travels too
    for name, data in files.items():
        info, body = got[f"{CURRENT}/{name}"]
        assert body == data
        assert info.mode == 0o600 and info.uid == 0 and info.gid == 0 and info.uname == ""
    assert got[CURRENT][0].isdir() and got[CURRENT][0].mode == 0o700
    assert got["report/last-report.json"][1] == report
    assert got["bundle/docker-compose.yml"][1] == world.compose.read_bytes()
    assert got["bundle/nightly-backup.sh"][1] == world.host_script.read_bytes()
    assert len(plaintext) % tarfile.RECORDSIZE == 0

    cipher = (world.sealed / f"{CURRENT}.tar.age").read_bytes()
    assert cipher.startswith(b"age-encryption.org/v1\n")
    digest = hashlib.sha256(cipher).hexdigest()
    line = f"{digest}  {CURRENT}.tar.age\n"
    assert (world.sealed / f"{CURRENT}.tar.age.sha256").read_text() == line
    assert (world.sealed / f"{CURRENT}.complete").read_text() == line

    m = meta(world, CURRENT)
    assert set(m) == set(seal.META_KEYS)
    assert m == {
        "run_stamp": CURRENT, "kind": "nightly", "backup_rc": 0, "chain_rc": 1,
        "db_files": 4, "plaintext_bytes": len(plaintext), "ciphertext_bytes": len(cipher),
        "recipients_count": 1, "sealed_at_utc": "2026-10-12T06:20:00Z",
        "tool_version": seal.TOOL_VERSION,
    }
    text = (world.sealed / f"{CURRENT}.meta.json").read_text()
    assert TENANT not in text and OTHER not in text and "/" not in text

    for name in outputs(world):
        assert stat_mode(world.sealed / name) == 0o600
    out = capsys.readouterr()
    assert f"{CURRENT}: sealed (nightly, this run, backup_rc=0, chain_rc=1" in out.out


def test_the_age_header_holds_one_x25519_stanza_per_recipient_plus_grease(world):
    """For the backup vault's side (patch doc section 6): pyrage adds one
    random "grease" stanza to every header, so the vault counts only
    `-> X25519 ` lines against meta.recipients_count."""
    make_backup(world.backups, CURRENT)
    _, escrow_public = _identity()
    _recipients(world.rec, world.public, escrow_public)
    assert nightly(world) == 0
    header = (world.sealed / f"{CURRENT}.tar.age").read_bytes().split(b"\n---", 1)[0]
    stanzas = [ln for ln in header.split(b"\n") if ln.startswith(b"-> ")]
    x25519 = [ln for ln in stanzas if ln.startswith(b"-> X25519 ")]
    assert len(x25519) == meta(world, CURRENT)["recipients_count"] == 2
    assert len(stanzas) >= len(x25519)


def test_the_complete_marker_is_written_last(world, monkeypatch):
    make_backup(world.backups, CURRENT)
    order: list[str] = []
    real_replace = os.replace

    def spy(src, dst, *a, **kw):
        order.append(Path(dst).name)
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", spy)
    assert nightly(world) == 0
    assert order == [f"{CURRENT}.tar.age", f"{CURRENT}.tar.age.sha256",
                     f"{CURRENT}.meta.json", f"{CURRENT}.complete"]


def test_a_crash_before_the_marker_leaves_the_run_unsealed_then_it_is_redone(world, monkeypatch,
                                                                              capsys):
    make_backup(world.backups, CURRENT)
    real = seal._write_atomic

    def broken(directory, name, text):
        if name.endswith(".meta.json"):
            raise OSError(errno.EIO, "Input/output error")
        return real(directory, name, text)

    monkeypatch.setattr(seal, "_write_atomic", broken)
    assert nightly(world) == 1
    err = capsys.readouterr().err
    assert f"seal: error: {CURRENT}: Input/output error" in err
    assert not (world.sealed / f"{CURRENT}.complete").exists()

    monkeypatch.setattr(seal, "_write_atomic", real)
    assert nightly(world) == 0
    assert "redone after an interrupted seal" in capsys.readouterr().out
    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}
    assert members(decrypt(world, CURRENT))


def test_a_real_backup_run_seals_unseals_and_restores(tmp_path):
    backup = _load("backup_databases")
    restore = _load("restore_databases")
    unseal = _load("unseal_backup_run")
    assert backup.RUN_STAMP_FORMAT == seal.RUN_STAMP_FORMAT
    assert backup.RUN_REPORT_NAME == seal.RUN_REPORT_NAME
    data_root = tmp_path / "state"
    (data_root / "clients" / TENANT).mkdir(parents=True)
    for path, rows in ((data_root / "registry.db", 3),
                       (data_root / "clients" / TENANT / "events.db", 11)):
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (n INTEGER)")
        conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(rows)])
        conn.commit()
        conn.close()
    backups, sealed = tmp_path / "backups", tmp_path / "sealed"
    sealed.mkdir(mode=0o700)
    since = datetime.now(timezone.utc).strftime(seal.RUN_STAMP_FORMAT)
    assert backup.main(["--data-root", str(data_root), "--backups-root", str(backups),
                        "--report-out", str(backups / "last-report.json"), "--quiet"]) == 0
    (stamp,) = [p.name for p in backups.iterdir() if p.is_dir()]
    assert (backups / stamp / seal.RUN_REPORT_NAME).is_file()
    ident, public = _identity()
    rec = _recipients(tmp_path / "secrets" / "r.txt", public)

    assert seal.main(["--backups-root", str(backups), "--sealed-root", str(sealed),
                      "--recipients", str(rec), "--backup-rc", "0", "--chain-rc", "0",
                      "--current-since", since]) == 0

    m = json.loads((sealed / f"{stamp}.meta.json").read_text())
    assert (m["backup_rc"], m["chain_rc"], m["db_files"]) == (0, 0, 2)
    identity = tmp_path / "shm" / "identity.txt"
    identity.parent.mkdir()
    identity.write_text(str(ident) + "\n")
    os.chmod(identity, 0o600)
    out = tmp_path / "shm" / "unsealed"
    assert unseal.main(["--sealed", str(sealed / f"{stamp}.tar.age"),
                        "--identity", str(identity), "--out", str(out)]) == 0
    assert (out / "report" / "last-report.json").is_file()
    assert (out / stamp / seal.RUN_REPORT_NAME).is_file()
    target = tmp_path / "restored"
    assert restore.main(["--backup-run", str(out / stamp), "--data-root", str(target)]) == 0
    events = sqlite3.connect(target / "clients" / TENANT / "events.db")
    assert events.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 11
    events.close()


# ---------------------------------------------------------------------------
# Idempotence, backfill, which run gets the return codes
# ---------------------------------------------------------------------------

def test_running_again_seals_nothing_twice(world, capsys):
    make_backup(world.backups, CURRENT)
    assert nightly(world) == 0
    before = snapshot(world.sealed)
    capsys.readouterr()
    assert nightly(world, backup_rc=1) == 0
    assert snapshot(world.sealed) == before
    out = capsys.readouterr().out
    assert "sealed 0, already sealed 1" in out
    assert "not recorded again" in out
    assert meta(world, CURRENT)["backup_rc"] == 0          # never re-attributed


def test_backfill_seals_every_unsealed_run_with_unknown_codes(world, capsys):
    stamps = ["20261001T060000Z", "20261005T151200Z", CURRENT]
    make_run(world.backups, stamps[0], done=False)          # a legacy run: no marker
    make_run(world.backups, stamps[1])
    make_backup(world.backups, CURRENT)

    assert run_seal(world, "--backfill") == 0

    for s, kind in zip(stamps, ("nightly", "adhoc", "nightly")):
        m = meta(world, s)
        assert (m["kind"], m["backup_rc"], m["chain_rc"]) == (kind, "unknown", "unknown")
        assert members(decrypt(world, s))
    assert "report/last-report.json" in members(decrypt(world, CURRENT))
    assert "report/last-report.json" not in members(decrypt(world, stamps[0]))
    out = capsys.readouterr().out
    assert f"{stamps[0]}: sealed (nightly, backfill, backup_rc=unknown, chain_rc=unknown; " \
           "as found: the backup never marked it finished" in out
    assert run_seal(world, "--backfill") == 0
    assert "sealed 0, already sealed 3" in capsys.readouterr().out


@pytest.mark.parametrize("extra", [("--backup-rc", "0"), ("--chain-rc", "0"),
                                   ("--current-since", SINCE), ("--kind", "nightly")])
def test_backfill_refuses_return_codes_and_an_explicit_kind(world, extra):
    make_backup(world.backups, CURRENT)
    assert run_seal(world, "--backfill", *extra) == 2
    assert outputs(world) == set()


@pytest.mark.parametrize("argv", [
    ("--backup-rc", "0"),
    ("--backup-rc", "0", "--chain-rc", "0"),                             # no --current-since
    ("--chain-rc", "0", "--current-since", SINCE),
    ("--backup-rc", "0", "--chain-rc", "0",
     "--current-since", _stamp(NOW + timedelta(hours=1))),                # in the future
])
def test_a_normal_run_needs_the_codes_and_a_sane_current_since(world, argv, capsys):
    make_backup(world.backups, CURRENT)
    assert run_seal(world, *argv) == 2
    assert outputs(world) == set()


def test_current_since_must_be_a_run_stamp_time(world):
    with pytest.raises(SystemExit) as exc:
        nightly(world, since="2026-10-12 06:00")
    assert exc.value.code == 2


def test_an_older_unsealed_run_is_caught_up_with_unknown_codes(world, capsys):
    older = "20261011T201500Z"
    make_run(world.backups, older)
    make_backup(world.backups, CURRENT)
    assert nightly(world, "--kind", "adhoc", backup_rc=1, chain_rc=0) == 0
    assert (meta(world, CURRENT)["kind"], meta(world, CURRENT)["backup_rc"]) == ("adhoc", 1)
    assert meta(world, older) | {"sealed_at_utc": None} == meta(world, older) | {
        "kind": "adhoc", "backup_rc": "unknown", "chain_rc": "unknown", "sealed_at_utc": None}
    assert f"{older}: sealed (adhoc, catch-up" in capsys.readouterr().out


def test_codes_are_not_given_to_a_stale_run(world, capsys):
    stale = _stamp(NOW - timedelta(hours=26))
    make_backup(world.backups, stale)
    assert nightly(world, backup_rc=2) == 0
    assert meta(world, stale)["backup_rc"] == "unknown"
    assert "not recorded for any run" in capsys.readouterr().out


def test_codes_go_nowhere_when_the_backup_failed_before_making_its_run(world, capsys):
    """Review case D: a good pre-deploy run made 2 h earlier whose own seal
    failed; tonight's backup exits 2 before creating its run, so the report
    still names that run. It must NOT be labelled with tonight's failure."""
    predeploy = _stamp(NOW - timedelta(hours=2))            # 21:20 PDT, by hand
    make_backup(world.backups, predeploy)
    assert nightly(world, "--kind", "nightly", backup_rc=2) == 0
    m = meta(world, predeploy)
    assert (m["kind"], m["backup_rc"], m["chain_rc"]) == ("adhoc", "unknown", "unknown")
    out = capsys.readouterr().out
    assert "the backup report names no run made since 20261012T060000Z" in out
    assert f"{predeploy}: sealed (adhoc, catch-up" in out


def test_overlapping_runs_the_codes_go_to_the_run_the_report_names(world, capsys):
    """Review case C: the cron run (backup_rc=1, the report names it)
    overlaps a hand backup still being written: the codes go to the cron
    run, the other is deferred and never takes them."""
    make_backup(world.backups, CURRENT)
    hand = _stamp(NOW - timedelta(minutes=5))
    make_run(world.backups, hand, mtime=NOW - timedelta(minutes=1), done=False)
    assert nightly(world, "--kind", "nightly", backup_rc=1) == 0
    assert (meta(world, CURRENT)["kind"], meta(world, CURRENT)["backup_rc"]) == ("nightly", 1)
    assert not (world.sealed / f"{hand}.complete").exists()
    assert f"{hand}: not marked finished" in capsys.readouterr().out


def test_codes_do_not_slide_onto_an_older_run_when_the_named_run_is_refused(world, capsys):
    earlier = _stamp(NOW - timedelta(hours=1))
    make_run(world.backups, earlier)
    elsewhere = world.tmp / "elsewhere"
    elsewhere.mkdir()
    make_run(elsewhere, CURRENT)
    (world.backups / CURRENT).symlink_to(elsewhere / CURRENT)
    write_report(world.backups, CURRENT)
    assert nightly(world, backup_rc=0, chain_rc=0) == 1
    assert meta(world, earlier)["backup_rc"] == "unknown"
    assert not (world.sealed / f"{CURRENT}.complete").exists()
    assert "is refused or missing" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Finished or not
# ---------------------------------------------------------------------------

def test_a_run_still_being_written_is_deferred_unless_the_report_names_it(world, capsys):
    young = _stamp(NOW - timedelta(minutes=2))
    make_run(world.backups, young, mtime=NOW - timedelta(minutes=1), done=False)
    assert nightly(world) == 0
    assert outputs(world) == {seal.LOCK_NAME}
    assert "deferred to a later seal" in capsys.readouterr().out

    write_report(world.backups, young)       # the backup finished: it wrote its report
    assert nightly(world) == 0
    assert meta(world, young)["backup_rc"] == 0


def test_a_paused_backup_is_not_sealed_as_complete(world, capsys):
    """Review case: a run stamped 25 min ago holding half its files, last
    written 11 min ago (a backup paused on a long integrity_check), not
    named by the report. The old mtime guess sealed it, for good; it is
    deferred until the backup marks it finished."""
    make_backup(world.backups, "20261011T060001Z")          # the report names another run
    paused = _stamp(NOW - timedelta(minutes=25))
    make_run(world.backups, paused, mtime=NOW - timedelta(minutes=11), done=False)
    assert nightly(world) == 0
    assert not (world.sealed / f"{paused}.complete").exists()
    assert f"{paused}: not marked finished" in capsys.readouterr().out

    (world.backups / paused / DONE).write_text('{"dest_dir": "/backup/x"}\n')   # its last step
    assert nightly(world) == 0
    assert seal.is_sealed(world.sealed, paused)
    assert f"{paused}/{DONE}" in members(decrypt(world, paused))


def test_a_run_never_marked_finished_is_sealed_as_found_once_old_and_quiet(world, capsys):
    dead = _stamp(NOW - timedelta(hours=7))                 # a backup that died
    make_run(world.backups, dead, mtime=NOW - timedelta(hours=6, minutes=50), done=False)
    assert nightly(world) == 0
    assert meta(world, dead)["backup_rc"] == "unknown"
    assert "as found: the backup never marked it finished" in capsys.readouterr().out


def test_an_empty_run_directory_is_a_warning_not_a_failure_every_night(world, capsys):
    empty = _stamp(NOW - timedelta(days=1))
    (world.backups / empty).mkdir()
    make_backup(world.backups, CURRENT)
    for _ in range(2):
        assert nightly(world) == 0
        err = capsys.readouterr().err
        assert f"seal: warning: {empty}: the run directory holds no files" in err
    assert not any(n.startswith(empty) for n in outputs(world))


# ---------------------------------------------------------------------------
# Retention, disk space, order
# ---------------------------------------------------------------------------

def test_retention_prunes_only_sealed_outputs_past_n_days(world, monkeypatch, capsys):
    old = _stamp(NOW - timedelta(days=20))
    edge_out = _stamp(NOW - timedelta(days=14, seconds=1))
    edge_in = _stamp(NOW - timedelta(days=14))
    recent = _stamp(NOW - timedelta(days=13))
    for s in (old, edge_out, edge_in, recent):
        make_run(world.backups, s)
    # sealed back then (each by a backfill on its own day)
    for s in (old, edge_out, edge_in, recent):
        assert run_seal(world, "--backfill", now=_when(s) + timedelta(hours=1)) == 0
    keep = {"notes.txt", f"{old}.tar.age.bak", "20250101T000000Z.complete"}
    (world.sealed / "notes.txt").write_text("operator notes")
    (world.sealed / f"{old}.tar.age.bak").write_text("not ours")
    (world.sealed / "20250101T000000Z.complete").mkdir()          # a directory: not ours
    backups_before = snapshot(world.backups)
    unlinked: list[str] = []
    real_unlink = os.unlink

    def spy(path, *a, **kw):
        unlinked.append(Path(path).name)
        return real_unlink(path, *a, **kw)

    monkeypatch.setattr(os, "unlink", spy)
    capsys.readouterr()
    assert nightly(world, "--retention-days", "14") == 0

    names = outputs(world)
    assert not names & (sealed_set(old) | sealed_set(edge_out))
    assert sealed_set(edge_in) | sealed_set(recent) | keep <= names
    assert snapshot(world.backups) == backups_before                # never touched
    for s in (old, edge_out):
        mine = [n for n in unlinked if n.startswith(s)]
        assert mine[0] == f"{s}.complete" and set(mine) == sealed_set(s)
    assert f"{old}: pruned (older than 14 days)" in capsys.readouterr().out

    assert nightly(world, "--retention-days", "14") == 0            # no churn:
    assert not outputs(world) & sealed_set(old)                     # never sealed again
    assert (f"{old}: older than 14 days, past the sealed retention: not sealed"
            in capsys.readouterr().out)
    assert snapshot(world.backups) == backups_before


def test_retention_days_must_be_at_least_one(world):
    with pytest.raises(SystemExit) as exc:
        nightly(world, "--retention-days", "0")
    assert exc.value.code == 2


def test_expired_outputs_are_pruned_before_anything_is_sealed(world, monkeypatch):
    old = _stamp(NOW - timedelta(days=20))
    make_run(world.backups, old)
    assert run_seal(world, "--backfill", now=_when(old) + timedelta(hours=1)) == 0
    make_backup(world.backups, CURRENT)
    events: list[str] = []
    real_unlink, real_seal = os.unlink, seal.seal_run

    def unlink_spy(path, *a, **kw):
        events.append(f"unlink {Path(path).name}")
        return real_unlink(path, *a, **kw)

    def seal_spy(**kw):
        events.append(f"seal {kw['run'].stamp}")
        return real_seal(**kw)

    monkeypatch.setattr(os, "unlink", unlink_spy)
    monkeypatch.setattr(seal, "seal_run", seal_spy)
    assert nightly(world) == 0
    first_seal = events.index(f"seal {CURRENT}")
    assert {e for e in events[:first_seal]} == {f"unlink {n}" for n in sealed_set(old)}


def test_the_run_made_now_goes_first_then_newest_first(world, monkeypatch):
    oldest, older = "20261009T201500Z", "20261011T201500Z"
    newer = _stamp(NOW - timedelta(minutes=4))              # a finished hand run, newer
    for s in (oldest, older, newer):
        make_run(world.backups, s)
    make_backup(world.backups, CURRENT)
    tried: list[str] = []
    real = seal.seal_run

    def spy(**kw):
        tried.append(kw["run"].stamp)
        return real(**kw)

    monkeypatch.setattr(seal, "seal_run", spy)
    assert nightly(world) == 0
    assert tried == [CURRENT, newer, older, oldest]


def test_a_short_disk_stops_sealing_with_the_newest_run_done(world, monkeypatch, capsys):
    for s in ("20261009T201500Z", "20261011T201500Z"):
        make_run(world.backups, s)
    make_backup(world.backups, CURRENT)
    tried: list[str] = []
    real = seal.seal_run

    def spy(**kw):
        tried.append(kw["run"].stamp)
        return real(**kw)

    monkeypatch.setattr(seal, "seal_run", spy)
    # room for one run, then only the reserve is left
    monkeypatch.setattr(seal, "free_bytes",
                        lambda path: 10 ** 12 if not tried else seal.FREE_SPACE_RESERVE + 4096)
    assert nightly(world) == 1
    assert tried == [CURRENT]
    assert seal.is_sealed(world.sealed, CURRENT)
    err = capsys.readouterr().err.strip().splitlines()
    assert len(err) == 1
    assert err[0].startswith("seal: error: 20261011T201500Z: not enough free space in the "
                             "sealed root")
    assert err[0].endswith("sealing stops here (1 more run(s) left for a later seal)")
    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}


def test_a_full_disk_mid_stream_stops_the_loop_then_it_is_redone(world, monkeypatch, capsys):
    for s in ("20261009T201500Z", "20261011T201500Z"):
        make_run(world.backups, s)
    make_backup(world.backups, CURRENT, big=True)
    real_write = os.write
    calls = {"n": 0}

    def full_disk(fd, data):                  # the disk fills while the ciphertext is written
        if os.readlink(f"/proc/self/fd/{fd}").endswith(".tar.age.tmp"):
            calls["n"] += 1
            if calls["n"] > 3:
                raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", full_disk)
    assert nightly(world) == 1
    err = capsys.readouterr().err
    assert err.strip().splitlines() == [
        f"seal: error: {CURRENT}: No space left on device: sealing stops here "
        "(2 more run(s) left for a later seal)"]
    assert outputs(world) == {seal.LOCK_NAME}                       # no .tmp, nothing else tried

    monkeypatch.setattr(os, "write", real_write)
    assert nightly(world) == 0
    assert members(decrypt(world, CURRENT))
    assert meta(world, CURRENT)["backup_rc"] == 0


# ---------------------------------------------------------------------------
# Ctrl-C
# ---------------------------------------------------------------------------

def test_ctrl_c_stops_the_whole_tool_not_just_the_run_being_sealed(world, monkeypatch):
    """A SIGINT lands in a Python callback of the encryptor (pyrage wraps it
    into its own error): it must stop the tool, not fail one run and go on
    sealing and pruning the rest."""
    older = "20261011T201500Z"
    make_run(world.backups, older)
    make_backup(world.backups, CURRENT)
    real = seal.tar_chunks

    def interrupted(opened, stamp, extras):
        gen = real(opened, stamp, extras)
        yield next(gen)
        raise KeyboardInterrupt

    monkeypatch.setattr(seal, "tar_chunks", interrupted)
    with pytest.raises(KeyboardInterrupt):
        nightly(world)
    assert outputs(world) == {seal.LOCK_NAME}           # the next run was NOT sealed; no .tmp

    monkeypatch.setattr(seal, "tar_chunks", real)
    assert nightly(world) == 0                          # the lock was released
    assert seal.is_sealed(world.sealed, older) and seal.is_sealed(world.sealed, CURRENT)


def test_a_callback_failure_the_encryptor_did_not_report_still_fails_the_run(world, monkeypatch,
                                                                           capsys):
    make_backup(world.backups, CURRENT)

    def chunks_then_eio(opened, stamp, extras):
        yield b"\0" * 512
        raise OSError(errno.EIO, "Input/output error")

    def swallowing(self, reader, writer):
        try:
            reader.read()
        except Exception:  # noqa: BLE001 — an encryptor that says "done" anyway
            pass

    monkeypatch.setattr(seal, "tar_chunks", chunks_then_eio)
    monkeypatch.setattr(archive_crypto.ArchiveEncryption, "encrypt_stream", swallowing)
    assert nightly(world) == 1
    assert f"seal: error: {CURRENT}: Input/output error" in capsys.readouterr().err
    assert outputs(world) == {seal.LOCK_NAME}


# ---------------------------------------------------------------------------
# Kind
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stamp,kind", [
    ("20261012T055959Z", "adhoc"),         # 22:59:59 PDT
    ("20261012T060000Z", "nightly"),       # 23:00 PDT = 01:00 CDT
    ("20261012T060001Z", "nightly"),
    ("20261012T061959Z", "nightly"),
    ("20261012T062000Z", "adhoc"),         # 20 minutes later
    ("20261012T070001Z", "adhoc"),         # 00:00 PDT: in summer 07:00Z is not the nightly
    ("20261012T050500Z", "adhoc"),         # a pre-deploy run at 00:05 CDT
    ("20260112T070001Z", "nightly"),       # 23:00 PST = 01:00 CST
    ("20260112T060500Z", "adhoc"),         # a pre-deploy run at 00:05 CST (the UTC window said nightly)
    ("20260112T060001Z", "adhoc"),         # 22:00 PST
    ("20260309T060000Z", "nightly"),       # 2026-03-08 23:00 PDT, the day DST starts
    ("20260308T070000Z", "nightly"),       # 2026-03-07 23:00 PST
    ("20261102T070000Z", "nightly"),       # 2026-11-01 23:00 PST, the day DST ends
    ("20261101T060000Z", "nightly"),       # 2026-10-31 23:00 PDT
    ("20261012T201500Z", "adhoc"),         # a pre-deploy run in the afternoon
])
def test_kind_auto_window(stamp, kind):
    assert seal.classify_kind(seal.parse_stamp(stamp)) == kind


def test_kind_auto_end_to_end(world):
    cases = {"20261011T055959Z": "adhoc", "20261011T060000Z": "nightly",
             "20261011T061959Z": "nightly", "20261011T062000Z": "adhoc"}
    for s in cases:
        make_run(world.backups, s)
    assert run_seal(world, "--backfill") == 0
    assert {s: meta(world, s)["kind"] for s in cases} == cases


@pytest.mark.parametrize("name,ok", [
    ("20261012T060001Z", True), ("20261012T060001", False), ("20261340T000000Z", False),
    ("2026-10-12T06:00:01Z", False), (" 20261012T060001Z", False), ("20261012T060001Z ", False),
    ("2026112T060001Z", False), ("tmp", False), ("", False),
])
def test_run_names_are_exactly_the_backup_stamp(name, ok):
    assert (seal.parse_stamp(name) is not None) is ok


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_refuses_a_recipients_file_without_a_key(world, capsys):
    make_backup(world.backups, CURRENT)
    _recipients(world.rec, "# no key yet", "")
    assert nightly(world) == 2
    assert outputs(world) == set()
    assert "holds no public key" in capsys.readouterr().err


def test_refuses_a_bad_recipient_line_without_echoing_it(world, capsys):
    make_backup(world.backups, CURRENT)
    _recipients(world.rec, world.public, "zz-not-a-key-qq")
    assert nightly(world) == 2
    out = capsys.readouterr()
    assert "line 2" in out.err and "zz-not-a-key-qq" not in out.out + out.err
    assert outputs(world) == set()


def test_refuses_a_private_key_in_the_recipients_file_and_never_prints_it(world, capsys):
    make_backup(world.backups, CURRENT)
    ident, public = _identity()
    secret = str(ident)
    _recipients(world.rec, public, secret)
    assert nightly(world) == 2
    out = capsys.readouterr()
    assert "PRIVATE key" in out.err
    body = secret.split("1", 1)[1]
    for text in (out.out, out.err):
        assert secret not in text and body[:20] not in text and body[-20:] not in text
    assert outputs(world) == set()


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_refuses_a_recipients_file_others_can_write(world, mode, capsys):
    make_backup(world.backups, CURRENT)
    os.chmod(world.rec, mode)
    assert nightly(world) == 2
    assert "writable by group or other" in capsys.readouterr().err
    assert outputs(world) == set()


def test_refuses_a_missing_recipients_file(world):
    make_backup(world.backups, CURRENT)
    world.rec.unlink()
    assert nightly(world) == 2
    assert outputs(world) == set()


@pytest.mark.parametrize("layout", ["sealed-in-backups", "backups-in-sealed", "same"])
def test_refuses_nested_roots(world, layout, capsys):
    make_backup(world.backups, CURRENT)
    if layout == "sealed-in-backups":
        world.sealed = world.backups / "sealed"
        world.sealed.mkdir()
    elif layout == "backups-in-sealed":
        inner = world.sealed / "backups"
        inner.mkdir()
        make_run(inner, CURRENT)
        world.backups = inner
    else:
        world.sealed = world.backups
    before = snapshot(world.tmp)
    assert nightly(world) == 2
    assert "separate trees" in capsys.readouterr().err
    assert snapshot(world.tmp) == before


def test_refuses_a_missing_sealed_root(world):
    make_backup(world.backups, CURRENT)
    world.sealed = world.tmp / "nope"
    assert nightly(world) == 2
    assert not world.sealed.exists()


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777])
@pytest.mark.parametrize("dry", [False, True])
def test_refuses_a_sealed_root_others_can_write(world, mode, dry, capsys):
    make_backup(world.backups, CURRENT)
    os.chmod(world.sealed, mode)
    try:
        assert nightly(world, *(["--dry-run"] if dry else [])) == 2
    finally:
        os.chmod(world.sealed, 0o700)
    assert "chmod 700 it" in capsys.readouterr().err
    assert outputs(world) == set()


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_refuses_a_sealed_root_this_user_cannot_write(world, capsys):
    make_backup(world.backups, CURRENT)
    os.chmod(world.sealed, 0o500)
    try:
        assert nightly(world) == 2
    finally:
        os.chmod(world.sealed, 0o700)
    assert "not writable by this user" in capsys.readouterr().err
    assert outputs(world) == set()


def test_refuses_a_symlinked_run_and_still_seals_the_others(world, capsys):
    elsewhere = world.tmp / "elsewhere"
    elsewhere.mkdir()
    make_run(elsewhere, "20261011T060000Z")
    (world.backups / "20261011T060000Z").symlink_to(elsewhere / "20261011T060000Z")
    make_backup(world.backups, CURRENT)
    assert nightly(world) == 1
    err = capsys.readouterr().err
    assert "seal: error: 20261011T060000Z: refused: the run directory is a symlink" in err
    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}


@pytest.mark.parametrize("what", ["symlink", "subdir"])
def test_refuses_a_run_holding_a_symlink_or_a_subdirectory(world, what, capsys):
    make_backup(world.backups, CURRENT)
    outside = world.tmp / "secret-elsewhere.env"
    outside.write_bytes(b"SECRET-OUTSIDE-THE-RUN-9d2b")
    if what == "symlink":
        (world.backups / CURRENT / "tenant_globex_audit.db.gz").symlink_to(outside)
    else:
        (world.backups / CURRENT / "nested").mkdir()
    assert nightly(world) == 1
    assert f"seal: error: {CURRENT}: refused: the run holds" in capsys.readouterr().err
    assert outputs(world) == {seal.LOCK_NAME}


def test_skips_non_stamp_directories_with_a_warning(world, capsys):
    make_backup(world.backups, CURRENT)
    for name in ("tmp", "20261012T060001", "20261340T000000Z", "2026-10-12T06:00:01Z"):
        (world.backups / name).mkdir()
        (world.backups / name / "registry.db.gz").write_bytes(MARKER)
    (world.backups / "last-status.txt").write_text("ok\n")
    assert nightly(world) == 0
    err = capsys.readouterr().err
    for name in ("tmp", "20261012T060001", "20261340T000000Z", "2026-10-12T06:00:01Z"):
        assert f"seal: warning: skipped '{name}': not a backup run name" in err
    assert "last-status" not in err and "last-report" not in err
    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}


def test_refuses_bad_config_files(world, capsys):
    make_backup(world.backups, CURRENT)
    assert nightly(world, "--config-file", str(world.tmp / "missing.yml")) == 2
    twin = world.tmp / "other" / "docker-compose.yml"
    twin.parent.mkdir()
    twin.write_text("x")
    assert nightly(world, "--config-file", str(twin)) == 2
    link = world.tmp / "link.yml"
    link.symlink_to(world.compose)
    assert nightly(world, "--config-file", str(link)) == 2
    err = capsys.readouterr().err
    assert "does not exist" in err and "must differ" in err and "is a symlink" in err
    assert outputs(world) == set()


# ---------------------------------------------------------------------------
# What counts as sealed; the lock; directory fsync
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("damage", ["lone-complete", "age-deleted", "complete-mismatch",
                                    "meta-deleted"])
def test_a_stray_or_broken_complete_is_not_sealed_and_the_run_is_sealed_again(world, damage,
                                                                              capsys):
    make_backup(world.backups, CURRENT)
    complete = world.sealed / f"{CURRENT}.complete"
    if damage == "lone-complete":                   # planted / stray marker, no seal ever ran
        complete.write_text(f"{'0' * 64}  {CURRENT}.tar.age\n")
    else:
        assert nightly(world) == 0
        if damage == "age-deleted":
            (world.sealed / f"{CURRENT}.tar.age").unlink()
        elif damage == "meta-deleted":
            (world.sealed / f"{CURRENT}.meta.json").unlink()
        else:
            complete.write_text(f"{'0' * 64}  {CURRENT}.tar.age\n")
    assert not seal.is_sealed(world.sealed, CURRENT)
    capsys.readouterr()

    assert nightly(world) == 0

    assert seal.is_sealed(world.sealed, CURRENT)
    assert "redone after an interrupted seal" in capsys.readouterr().out
    cipher = (world.sealed / f"{CURRENT}.tar.age").read_bytes()
    assert complete.read_text() == f"{hashlib.sha256(cipher).hexdigest()}  {CURRENT}.tar.age\n"
    assert members(decrypt(world, CURRENT))


def test_a_second_seal_waits_for_the_lock_then_seals(world, monkeypatch, capsys):
    make_backup(world.backups, CURRENT)
    fd = hold_lock(world)
    waits: list[float] = []

    def other_seal_finishes(seconds):
        waits.append(seconds)
        os.close(fd)

    monkeypatch.setattr(seal, "_sleep", other_seal_finishes)
    assert nightly(world) == 0
    assert waits == [seal.LOCK_POLL_SECONDS]
    assert "another seal holds the lock: waiting for it" in capsys.readouterr().out
    assert seal.is_sealed(world.sealed, CURRENT)


def test_a_seal_gives_up_after_waiting_an_hour_for_the_lock(world, monkeypatch, capsys):
    make_backup(world.backups, CURRENT)
    fd = hold_lock(world)
    clock = {"t": 1000.0}
    monkeypatch.setattr(seal, "_monotonic", lambda: clock["t"])
    monkeypatch.setattr(seal, "_sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    try:
        assert nightly(world) == 3
    finally:
        os.close(fd)
    assert clock["t"] - 1000.0 >= seal.LOCK_WAIT_SECONDS
    assert "held the lock for 60 minutes" in capsys.readouterr().err
    assert outputs(world) == {seal.LOCK_NAME}


def test_a_filesystem_without_flock_is_refused(world, monkeypatch, capsys):
    make_backup(world.backups, CURRENT)

    def no_flock(fd, op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(seal.fcntl, "flock", no_flock)
    assert nightly(world) == 2
    assert "does not support flock" in capsys.readouterr().err
    assert outputs(world) <= {seal.LOCK_NAME}


def test_a_directory_fsync_that_is_not_supported_is_tolerated(world, monkeypatch):
    make_backup(world.backups, CURRENT)
    real = os.fsync

    def picky(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "Invalid argument")
        return real(fd)

    monkeypatch.setattr(os, "fsync", picky)
    assert nightly(world) == 0
    assert seal.is_sealed(world.sealed, CURRENT)


# ---------------------------------------------------------------------------
# Two recipients, dry run, interruptions, no plaintext
# ---------------------------------------------------------------------------

def test_two_recipients_can_each_decrypt(world):
    make_backup(world.backups, CURRENT)
    escrow, escrow_public = _identity()
    stranger, _ = _identity()
    _recipients(world.rec, "# operator", world.public, "# break-glass", escrow_public)
    assert nightly(world) == 0
    assert decrypt(world, CURRENT) == decrypt(world, CURRENT, escrow)
    assert meta(world, CURRENT)["recipients_count"] == 2
    with pytest.raises(pyrage.DecryptError):
        decrypt(world, CURRENT, stranger)


def test_the_dry_run_writes_nothing(world, capsys):
    old = _stamp(NOW - timedelta(days=20))
    make_run(world.backups, old)
    assert run_seal(world, "--backfill", now=_when(old) + timedelta(hours=1)) == 0
    (world.sealed / seal.LOCK_NAME).unlink()
    make_backup(world.backups, CURRENT)
    (world.sealed / f"{CURRENT}.tar.age.tmp").write_bytes(b"stale")
    before_sealed, before_backups = snapshot(world.sealed), snapshot(world.backups)
    capsys.readouterr()

    assert nightly(world, "--dry-run") == 0

    assert snapshot(world.sealed) == before_sealed
    assert snapshot(world.backups) == before_backups
    out = capsys.readouterr().out
    assert (f"{CURRENT}: would seal (nightly, this run, backup_rc=0, chain_rc=0; 5 files, "
            "with its backup report)") in out
    assert f"{old}: would prune" in out
    assert "dry run: the runs to seal take about" in out and "free in the sealed root" in out
    assert "dry run — nothing was written; would seal 1" in out


def test_an_interrupted_seal_is_removed_and_redone(world, capsys):
    make_backup(world.backups, CURRENT)
    for suffix in (".tar.age.tmp", ".tar.age", ".meta.json", ".complete.tmp"):
        (world.sealed / f"{CURRENT}{suffix}").write_bytes(b"left by a killed seal")
    assert nightly(world) == 0
    assert outputs(world) == sealed_set(CURRENT) | {seal.LOCK_NAME}
    assert members(decrypt(world, CURRENT))
    assert "redone after an interrupted seal" in capsys.readouterr().out


def test_a_run_file_that_changes_while_sealing_fails_the_run(world, monkeypatch, capsys):
    make_backup(world.backups, CURRENT)
    real = seal.tar_chunks

    def shrinking(opened, stamp, extras):
        gen = real(opened, stamp, extras)
        yield next(gen)                       # the directory header
        yield next(gen)                       # the first file's header: it is open now
        with open(world.backups / CURRENT / opened.names[0], "r+b") as fh:
            fh.truncate(1)                    # same inode, shorter
        yield from gen

    monkeypatch.setattr(seal, "tar_chunks", shrinking)
    assert nightly(world) == 1
    assert "while it was being sealed" in capsys.readouterr().err
    assert outputs(world) == {seal.LOCK_NAME}


def _holds_plaintext(root: Path) -> list[str]:
    hits = []
    for p in root.rglob("*"):
        if p.is_file():
            data = p.read_bytes()
            if MARKER in data or TENANT.encode() in data or OTHER.encode() in data:
                hits.append(p.name)
    return hits


def test_plaintext_never_lands_in_the_sealed_root(world, monkeypatch):
    make_run(world.backups, "20261011T060000Z", big=True)
    make_backup(world.backups, CURRENT, big=True)
    real = seal.tar_chunks
    seen: list[list[str]] = []

    def watching(*a, **kw):
        for i, chunk in enumerate(real(*a, **kw)):
            if i % 2:
                seen.append(_holds_plaintext(world.sealed))
            yield chunk

    monkeypatch.setattr(seal, "tar_chunks", watching)
    assert nightly(world) == 0
    assert len(seen) > 4 and not any(seen)              # mid-stream: ciphertext only
    assert _holds_plaintext(world.sealed) == []
    assert MARKER in decrypt(world, CURRENT)            # ... yet it is all in there


def test_archive_crypto_streams_to_every_recipient():
    ident, public = _identity()
    enc = archive_crypto.with_recipients((public,))
    sink = io.BytesIO()
    enc.encrypt_stream(io.BytesIO(b"abc" * 100_000), sink)
    assert pyrage.decrypt(sink.getvalue(), [ident]) == b"abc" * 100_000
    with pytest.raises(archive_crypto.EncryptionConfigError):
        archive_crypto.ArchiveEncryption().encrypt_stream(io.BytesIO(b"x"), io.BytesIO())
