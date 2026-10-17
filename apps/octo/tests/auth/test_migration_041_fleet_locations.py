"""Migration 041 (Fleet v2: the manual tenant location) — forward, rollback,
forward again — and scripts/rollback_v014.py, its one-command rollback.

Pins:
  - tenant_locations: one row per slug; latitude / longitude bounded, the
    (0, 0) "unset" value refused, a 1..120-character label;
  - the rollback keeps every row under tenant_locations_rolled_back_041
    (appended to on a second rollback), drops the table, version back to 40;
  - re-applying restores the newest kept row of each tenant that still
    exists, and spends the kept rows (a later rollback keeps the state of
    THEN);
  - rollback_v014: dry run by default, one step (041, registry), a root
    newer than 41 refused, nothing to do on a 40 root.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations

SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v014.py"


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _script():
    spec = importlib.util.spec_from_file_location("rollback_v014", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def reg(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    conn = connect(tmp_path / "root" / "registry.db")
    # v0.17.5 (048), v0.17.3 (047), v0.17.2 (046), v0.17 (044), v0.16 (043)
    # and v0.15 (042), independent of 041, sit on top: roll them back first,
    # newest first, the way rollback_v0175 → rollback_v0173 → rollback_v0172
    # → rollback_v017 → rollback_v016 → rollback_v015 → rollback_v014 run.
    apply_migration(conn, _migration(48, "rollback"), target="registry")
    apply_migration(conn, _migration(47, "rollback"), target="registry")
    apply_migration(conn, _migration(46, "rollback"), target="registry")
    apply_migration(conn, _migration(44, "rollback"), target="registry")
    apply_migration(conn, _migration(43, "rollback"), target="registry")
    apply_migration(conn, _migration(42, "rollback"), target="registry")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES "
                 "('acme-corp', 'Acme Corp', 'client'), "
                 "('example-bakery', 'Example Bakery', 'client')")
    conn.commit()
    yield conn
    conn.close()


def test_041_is_registry_only():
    for kind in ("forward", "rollback"):
        sql = _migration(41, kind).sql
        assert "-- @target: registry" in sql
        assert "-- @target: telemetry" not in sql and "-- @target: entities" not in sql


def test_constraints(reg):
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 41
    reg.execute("INSERT INTO tenant_locations (slug, lat, lng, label, set_by) VALUES "
                "('acme-corp', 37.512, -91.204, 'Main office', 1)")
    for bad in ((91.0, 1.0, "x"), (1.0, -181.0, "x"), (0.0, 0.0, "x"), (1.0, 1.0, ""),
                (1.0, 1.0, "y" * 121)):
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO tenant_locations (slug, lat, lng, label) VALUES "
                        "('example-bakery', ?, ?, ?)", bad)
    with pytest.raises(sqlite3.IntegrityError):                 # one row per tenant
        reg.execute("INSERT INTO tenant_locations (slug, lat, lng, label) VALUES "
                    "('acme-corp', 1.0, 1.0, 'again')")


def test_forward_rollback_forward_keeps_and_restores(reg):
    reg.execute("INSERT INTO tenant_locations (slug, lat, lng, label, set_by) VALUES "
                "('acme-corp', 37.512, -91.204, 'Main office', 1), "
                "('example-bakery', 37.601, -91.33, 'Bakery', 2)")
    reg.commit()
    fwd, back = _migration(41), _migration(41, "rollback")

    apply_migration(reg, back, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 40
    assert "tenant_locations" not in _tables(reg)
    kept = reg.execute("SELECT slug, lat, label FROM tenant_locations_rolled_back_041 "
                       "ORDER BY slug").fetchall()
    assert [tuple(r) for r in kept] == [("acme-corp", 37.512, "Main office"),
                                         ("example-bakery", 37.601, "Bakery")]

    reg.execute("DELETE FROM clients WHERE slug = 'example-bakery'")   # gone meanwhile
    reg.commit()
    apply_migration(reg, fwd, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 41
    rows = reg.execute("SELECT slug, lat, lng, label, set_by FROM tenant_locations").fetchall()
    assert [tuple(r) for r in rows] == [("acme-corp", 37.512, -91.204, "Main office", 1)]
    assert reg.execute("SELECT COUNT(*) FROM tenant_locations_rolled_back_041"
                       ).fetchone()[0] == 0                              # spent

    # An edit after the re-upgrade is what a SECOND rollback keeps.
    reg.execute("UPDATE tenant_locations SET label = 'HQ (moved)', lat = 37.7")
    reg.commit()
    apply_migration(reg, back, target="registry")
    apply_migration(reg, fwd, target="registry")
    row = reg.execute("SELECT lat, label FROM tenant_locations").fetchone()
    assert tuple(row) == (37.7, "HQ (moved)")


def test_rollback_v014_script(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    bootstrap.init_data_root()
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', "
                 "'Acme Corp', 'client')")
    conn.execute("INSERT INTO tenant_locations (slug, lat, lng, label) VALUES "
                 "('acme-corp', 37.512, -91.204, 'Main office')")
    conn.commit()
    conn.close()
    mod = _script()
    assert mod.main(["--data-root", str(root)]) == 1                    # v0.17.5 root: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    conn = sqlite3.connect(root / "registry.db", isolation_level=None)
    try:
        apply_migration(conn, _migration(48, "rollback"), target="registry")
        apply_migration(conn, _migration(47, "rollback"), target="registry")
        apply_migration(conn, _migration(46, "rollback"), target="registry")
        apply_migration(conn, _migration(44, "rollback"), target="registry")
        apply_migration(conn, _migration(43, "rollback"), target="registry")
        apply_migration(conn, _migration(42, "rollback"), target="registry")
    finally:
        conn.close()

    assert mod.main(["--data-root", str(root)]) == 0                    # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False
    assert [(s["migration"], s["target"]) for s in out["steps"]] == [(41, "registry")]

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and out["done"][0]["integrity"] == "ok"
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 40
        assert conn.execute("SELECT label FROM tenant_locations_rolled_back_041"
                            ).fetchall() == [("Main office",)]
    finally:
        conn.close()

    assert mod.main(["--data-root", str(root), "--apply"]) == 0         # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []

    bootstrap.init_data_root()                                           # re-upgrade
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("SELECT label FROM tenant_locations").fetchall() == \
            [("Main office",)]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 48
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root)]) == 1                    # newer: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(tmp_path / "missing")]) == 2
