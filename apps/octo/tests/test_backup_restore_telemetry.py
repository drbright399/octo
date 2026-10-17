"""Backups carry the telemetry store (migration 036) — and tickets.db — and a
restore puts every per-tenant database back where it lives.

Real backup + restore scripts on a real data root (provisioned tenant with a
telemetry.db written by the store and a tickets.db). Pins:
  * discovery lists clients/<slug>/{events,indicators,audit,tickets,
    telemetry}.db;
  * the round trip: backup_databases.py → restore_databases.py into an empty
    root → the same rows in clients/<slug>/telemetry.db and tickets.db;
  * the restore mapping knows exactly the names the backup writes (a stray
    "tenant_x_junk.db" is not restored into the live layout).
"""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
from pathlib import Path

from apps.octo.tests._tiering_fixtures import make_root, rows, write_telemetry

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod        # dataclasses resolve their module
    spec.loader.exec_module(mod)
    return mod


backup = _load("backup_databases")
restore = _load("restore_databases")
SLUG = "acme-corp"


def test_backup_discovers_telemetry_and_tickets(tmp_path, monkeypatch):
    root = make_root(tmp_path, monkeypatch, tenants=(SLUG,))
    (root / "clients" / SLUG / "tickets.db").write_bytes(b"")
    labels = {label for _p, label in backup.discover_databases(root)}
    assert {f"tenant:{SLUG}:{n}" for n in ("events", "indicators", "telemetry", "tickets")} <= labels


def test_round_trip_restores_the_telemetry_store(tmp_path, monkeypatch):
    root = make_root(tmp_path, monkeypatch, tenants=(SLUG,))
    for i in range(3):
        write_telemetry(root, SLUG, received_at=f"2026-09-29T10:0{i}:00.000Z",
                        domain=f"d{i}.example.test", n=i)
    tickets = root / "clients" / SLUG / "tickets.db"
    conn = sqlite3.connect(tickets)
    conn.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, title TEXT)")
    conn.execute("INSERT INTO tickets (title) VALUES ('printer on fire')")
    conn.commit()
    conn.close()
    want = rows(root / "clients" / SLUG / "telemetry.db",
                "SELECT id, received_at, domain, payload_sha256 FROM telemetry_raw ORDER BY id")

    backups = tmp_path / "backups"
    assert backup.main(["--data-root", str(root), "--backups-root", str(backups),
                        "--quiet", "--report-out", str(tmp_path / "r.json")]) == 0
    [run] = [p for p in backups.iterdir() if p.is_dir()]
    assert (run / f"tenant_{SLUG}_telemetry.db.gz").exists()
    assert (run / f"tenant_{SLUG}_tickets.db.gz").exists()

    target = tmp_path / "restored"
    assert restore.main(["--backup-run", str(run), "--data-root", str(target)]) == 0
    got = rows(target / "clients" / SLUG / "telemetry.db",
               "SELECT id, received_at, domain, payload_sha256 FROM telemetry_raw ORDER BY id")
    assert got == want
    assert rows(target / "clients" / SLUG / "telemetry.db",
                "SELECT SUM(count) FROM telemetry_hourly") == [(3,)]
    assert rows(target / "clients" / SLUG / "tickets.db", "SELECT title FROM tickets") == [
        ("printer on fire",)]


def test_restore_mapping_is_the_backup_naming():
    base = Path("/r")
    for name in restore.TENANT_DBS:
        assert restore._target_for(f"tenant_{SLUG}_{name}.db.gz", base) == \
            base / "clients" / SLUG / f"{name}.db"
    for name in restore.GLOBAL_DBS:
        assert restore._target_for(f"global_{name}.db.gz", base) == base / "global" / f"{name}.db"
    assert restore._target_for(f"tenant_{SLUG}_junk.db.gz", base) is None
    assert restore._target_for("global_junk.db", base) is None
    # Every per-tenant file the backup walks has a restore target.
    assert {f.removesuffix(".db") for f in backup.TENANT_DB_FILES} == set(restore.TENANT_DBS)
