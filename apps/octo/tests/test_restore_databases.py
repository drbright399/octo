"""restore_databases.py: reverse of the backup flattening, into an empty root."""
from __future__ import annotations

import gzip
import importlib.util
import sqlite3
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "restore_databases",
    Path(__file__).resolve().parents[3] / "scripts" / "restore_databases.py",
)
restore = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(restore)


def _gz_db(path: Path, rows: int) -> None:
    raw = path.with_suffix("")                      # strip .gz
    conn = sqlite3.connect(raw)
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(rows)])
    conn.commit(); conn.close()
    path.write_bytes(gzip.compress(raw.read_bytes()))
    raw.unlink()


@pytest.fixture
def run_dir(tmp_path):
    run = tmp_path / "20260101T000000Z"
    run.mkdir()
    _gz_db(run / "registry.db.gz", 3)
    _gz_db(run / "global_audit.db.gz", 5)
    _gz_db(run / "tenant_acme-west_events.db.gz", 7)
    (run / "registry.db-wal").write_bytes(b"")      # sidecar junk is ignored
    (run / "last-report.json").write_text("{}")
    return run


def test_restores_the_live_layout_and_checks_integrity(run_dir, tmp_path, capsys):
    root = tmp_path / "restored"
    assert restore.main(["--backup-run", str(run_dir), "--data-root", str(root)]) == 0
    assert (root / "registry.db").exists()
    assert (root / "global" / "audit.db").exists()
    events = root / "clients" / "acme-west" / "events.db"
    assert sqlite3.connect(events).execute("SELECT COUNT(*) FROM t").fetchone()[0] == 7
    assert '"restored": 3' in capsys.readouterr().out


def test_refuses_a_root_that_already_has_a_registry(run_dir, tmp_path):
    root = tmp_path / "live"
    root.mkdir()
    (root / "registry.db").write_bytes(b"live data")
    assert restore.main(["--backup-run", str(run_dir), "--data-root", str(root)]) == 2
    assert (root / "registry.db").read_bytes() == b"live data"      # untouched


def test_corrupt_backup_fails_loudly(run_dir, tmp_path):
    (run_dir / "tenant_acme-west_events.db.gz").write_bytes(gzip.compress(b"not a database"))
    root = tmp_path / "restored"
    assert restore.main(["--backup-run", str(run_dir), "--data-root", str(root)]) == 1
