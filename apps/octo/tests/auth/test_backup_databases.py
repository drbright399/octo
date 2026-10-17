"""Backup CLI smoke tests — confirm `scripts/backup_databases.py`
produces restorable backups + proper exit codes.

These tests don't re-test SQLite's online backup API (that's a
load-bearing standard-library function); they test the file walk,
multi-DB aggregation, integrity verification, rotation, and exit-code
semantics specific to the wrapper.
"""
from __future__ import annotations

import gzip
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "backup_databases.py"


def _mk_db(path: Path, *, rows: int = 5) -> None:
    """Make a synthetic SQLite DB with `rows` rows in `t`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, v TEXT);
        """)
        for i in range(rows):
            conn.execute("INSERT INTO t (v) VALUES (?)", (f"row-{i}",))
        conn.commit()
    finally:
        conn.close()


def _mk_minimal_data_root(root: Path) -> None:
    """Build the minimal directory shape the discovery walks.
    registry.db + global/audit.db + clients/acme/events.db.
    """
    _mk_db(root / "registry.db", rows=3)
    _mk_db(root / "global" / "audit.db", rows=7)
    _mk_db(root / "clients" / "acme" / "events.db", rows=11)


def _run(*args: str) -> tuple[int, dict | None, str]:
    """Invoke the script, return (exit, parsed_json, stderr)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--quiet", *args],
        capture_output=True, text=True,
    )
    parsed = None
    if result.stdout.strip():
        parsed = json.loads(result.stdout)
    return result.returncode, parsed, result.stderr


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def test_happy_path_three_dbs(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    backups_root = tmp_path / "bk"
    _mk_minimal_data_root(data_root)

    code, report, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(backups_root),
        "--retention-days", "30",
    )
    assert code == 0
    assert report is not None
    assert report["databases_total"] == 3
    assert report["databases_failed"] == 0
    labels = sorted(r["label"] for r in report["results"])
    assert labels == ["global:audit", "registry", "tenant:acme:events"]

    # Backup files exist + are gzipped + non-empty.
    runs = list(backups_root.iterdir())
    assert len(runs) == 1
    run_dir = runs[0]
    files = sorted(p.name for p in run_dir.iterdir())
    assert set(files) == {
        "registry.db.gz",
        "global_audit.db.gz",
        "tenant_acme_events.db.gz",
        "backup-report.json",           # the run's own report: its "finished" marker
    }
    for f in run_dir.iterdir():
        assert f.stat().st_size > 0
    own = json.loads((run_dir / "backup-report.json").read_text())
    assert own == report and own["dest_dir"] == str(run_dir)


def test_the_finished_marker_is_the_last_write_into_the_run(tmp_path: Path) -> None:
    """scripts/seal_backup_runs.py seals a run once it holds
    backup-report.json: nothing may be written into the run after it, and it
    is written even when a database failed (finished is not succeeded)."""
    data_root = tmp_path / "data"
    _mk_minimal_data_root(data_root)
    with (data_root / "registry.db").open("r+b") as f:
        f.truncate(64)                                  # one database fails
    code, report, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(tmp_path / "bk"),
        "--retention-days", "30",
    )
    assert code == 1
    run_dir = next((tmp_path / "bk").iterdir())
    marker = run_dir / "backup-report.json"
    assert json.loads(marker.read_text()) == report
    newest_other = max(p.stat().st_mtime_ns for p in run_dir.iterdir() if p != marker)
    assert marker.stat().st_mtime_ns >= newest_other
    assert not [p.name for p in run_dir.iterdir() if p.name.endswith(".tmp")]


def test_backup_is_restorable(tmp_path: Path) -> None:
    """The backed-up DB, after gunzip, opens + has the original rows."""
    data_root = tmp_path / "data"
    backups_root = tmp_path / "bk"
    _mk_minimal_data_root(data_root)

    code, _, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(backups_root),
        "--retention-days", "30",
    )
    assert code == 0
    run_dir = next(backups_root.iterdir())
    bk_gz = run_dir / "tenant_acme_events.db.gz"

    # Restore.
    restored = tmp_path / "restored.db"
    with gzip.open(bk_gz, "rb") as fin, restored.open("wb") as fout:
        shutil.copyfileobj(fin, fout)
    conn = sqlite3.connect(str(restored))
    try:
        count = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    finally:
        conn.close()
    assert count == 11


def test_no_compress_flag(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    backups_root = tmp_path / "bk"
    _mk_minimal_data_root(data_root)

    code, _, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(backups_root),
        "--no-compress",
        "--retention-days", "30",
    )
    assert code == 0
    run_dir = next(backups_root.iterdir())
    files = sorted(p.name for p in run_dir.iterdir())
    # Should be .db not .db.gz.
    assert "registry.db" in files
    assert all(not f.endswith(".gz") for f in files)


def test_missing_data_root_exits_two(tmp_path: Path) -> None:
    """No DBs found → exit 2."""
    code, parsed, stderr = _run(
        "--data-root", str(tmp_path / "missing"),
        "--backups-root", str(tmp_path / "bk"),
    )
    assert code == 2
    assert parsed is None  # early-exit before any report is built
    assert "no databases found" in stderr.lower()


def test_rotation_drops_old_runs(tmp_path: Path) -> None:
    """Backup runs older than --retention-days get removed."""
    data_root = tmp_path / "data"
    backups_root = tmp_path / "bk"
    _mk_minimal_data_root(data_root)

    # Plant 3 fake old run directories with stamped names.
    backups_root.mkdir()
    now = datetime.now(timezone.utc)
    for days_ago in (1, 8, 30):
        stamp = (now - timedelta(days=days_ago)).strftime("%Y%m%dT%H%M%SZ")
        (backups_root / stamp).mkdir()
        (backups_root / stamp / "dummy").write_text("old")

    code, report, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(backups_root),
        "--retention-days", "7",
    )
    assert code == 0
    # 8-day-old + 30-day-old → removed (2). 1-day-old kept. New run kept.
    assert report["rotation_removed"] == 2
    remaining = sorted(p.name for p in backups_root.iterdir())
    # 2 kept-olds (1-day) + 1 new + 0 = check at-least-2-kept.
    assert len(remaining) == 2  # 1-day kept + this run


def test_corrupted_source_caught_by_integrity_check(tmp_path: Path) -> None:
    """A source DB whose pages are partially corrupted causes the
    backup to fail integrity_check, which produces a per-DB FAIL +
    overall exit code 1.

    Simulating real corruption is invasive; instead we point the
    discovery at a file that's well-formed SQLite but has its row data
    truncated to provoke integrity_check noise.
    """
    data_root = tmp_path / "data"
    _mk_minimal_data_root(data_root)
    # Corrupt registry.db by truncating to ~64 bytes (header survives,
    # data pages don't).
    target = data_root / "registry.db"
    with target.open("r+b") as f:
        f.truncate(64)

    code, report, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(tmp_path / "bk"),
        "--retention-days", "30",
    )
    # The corrupted DB will fail either at .backup() or integrity_check.
    # Either way: exit 1, that DB marked FAIL, the other two OK.
    assert code == 1
    failed = [r for r in report["results"] if not r["ok"]]
    assert any(r["label"] == "registry" for r in failed)
    ok_results = [r for r in report["results"] if r["ok"]]
    assert {r["label"] for r in ok_results} == {
        "global:audit", "tenant:acme:events",
    }


def test_no_verify_flag(tmp_path: Path) -> None:
    """--no-verify skips PRAGMA integrity_check; report records that
    integrity is None."""
    data_root = tmp_path / "data"
    _mk_minimal_data_root(data_root)
    code, report, _ = _run(
        "--data-root", str(data_root),
        "--backups-root", str(tmp_path / "bk"),
        "--no-verify",
        "--retention-days", "30",
    )
    assert code == 0
    for r in report["results"]:
        assert r["integrity"] is None
