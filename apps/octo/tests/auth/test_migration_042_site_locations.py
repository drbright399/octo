"""Migration 042 (Fleet v2: the manual SITE location, locked pins) — forward,
rollback, forward again — and scripts/rollback_v015.py, its one-command
rollback.

Pins:
  - site_locations: one row per Fleet site key, the tenant it was set for,
    latitude / longitude bounded, the (0, 0) "unset" value refused, a
    1..120-character label;
  - the rollback keeps every row under site_locations_rolled_back_042
    (appended to on a second rollback), drops the table, version back to 41;
  - re-applying restores the newest kept row of each site whose tenant still
    exists, and spends the kept rows;
  - rollback_v015: dry run by default, one step (042, registry), a root
    newer than 42 refused (a v0.17 / v0.16 root until rollback_v017 /
    rollback_v016 ran), nothing to
    do on a 41 root; rollback_v014 refuses a 42 root until this ran.
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

SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
HQ, ANNEX = "u-0123456789abcdef0123", "u-fedcba9876543210fedc"


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def reg(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    conn = connect(tmp_path / "root" / "registry.db")
    # v0.17.5 (048), v0.17.3 (047), v0.17.2 (046), v0.17 (044) and v0.16
    # (043 — it adds site_locations' provenance columns) sit on top: roll
    # them back first, newest first, the way rollback_v0175 → rollback_v0173
    # → rollback_v0172 → rollback_v017 → rollback_v016 → rollback_v015 run.
    apply_migration(conn, _migration(48, "rollback"), target="registry")
    apply_migration(conn, _migration(47, "rollback"), target="registry")
    apply_migration(conn, _migration(46, "rollback"), target="registry")
    apply_migration(conn, _migration(44, "rollback"), target="registry")
    apply_migration(conn, _migration(43, "rollback"), target="registry")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES "
                 "('acme-corp', 'Acme Corp', 'client'), "
                 "('example-bakery', 'Example Bakery', 'client')")
    conn.commit()
    yield conn
    conn.close()


def test_042_is_registry_only():
    for kind in ("forward", "rollback"):
        sql = _migration(42, kind).sql
        assert "-- @target: registry" in sql
        assert "-- @target: telemetry" not in sql and "-- @target: entities" not in sql


def test_constraints(reg):
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 42
    assert "tenant_locations" in _tables(reg)                    # 041 untouched
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by) "
                "VALUES (?, 'acme-corp', 37.512, -91.204, 'Main office', 1)", (HQ,))
    for bad in ((91.0, 1.0, "x"), (1.0, -181.0, "x"), (0.0, 0.0, "x"), (1.0, 1.0, ""),
                (1.0, 1.0, "y" * 121)):
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label) "
                        "VALUES (?, 'acme-corp', ?, ?, ?)", (ANNEX, *bad))
    with pytest.raises(sqlite3.IntegrityError):                 # one row per site
        reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label) "
                    "VALUES (?, 'example-bakery', 1.0, 1.0, 'again')", (HQ,))
    with pytest.raises(sqlite3.IntegrityError):                 # a key, not a blank
        reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label) "
                    "VALUES ('', 'acme-corp', 1.0, 1.0, 'x')")


def test_forward_rollback_forward_keeps_and_restores(reg):
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by) "
                "VALUES (?, 'acme-corp', 37.512, -91.204, 'Main office', 1), "
                "(?, 'example-bakery', 37.601, -91.33, 'Bakery', 2)", (HQ, ANNEX))
    reg.commit()
    fwd, back = _migration(42), _migration(42, "rollback")

    apply_migration(reg, back, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 41
    assert "site_locations" not in _tables(reg)
    kept = reg.execute("SELECT site_key, lat, label FROM site_locations_rolled_back_042 "
                       "ORDER BY label").fetchall()
    assert [tuple(r) for r in kept] == [(ANNEX, 37.601, "Bakery"), (HQ, 37.512, "Main office")]

    reg.execute("DELETE FROM clients WHERE slug = 'example-bakery'")   # gone meanwhile
    reg.commit()
    apply_migration(reg, fwd, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 42
    rows = reg.execute("SELECT site_key, tenant_slug, lat, lng, label, set_by "
                       "FROM site_locations").fetchall()
    assert [tuple(r) for r in rows] == [(HQ, "acme-corp", 37.512, -91.204, "Main office", 1)]
    assert reg.execute("SELECT COUNT(*) FROM site_locations_rolled_back_042"
                       ).fetchone()[0] == 0                              # spent

    # An edit after the re-upgrade is what a SECOND rollback keeps.
    reg.execute("UPDATE site_locations SET label = 'HQ (moved)', lat = 37.7")
    reg.commit()
    apply_migration(reg, back, target="registry")
    apply_migration(reg, fwd, target="registry")
    row = reg.execute("SELECT lat, label FROM site_locations").fetchone()
    assert tuple(row) == (37.7, "HQ (moved)")


def test_rollback_v015_script(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    bootstrap.init_data_root()
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', "
                 "'Acme Corp', 'client')")
    conn.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label) VALUES "
                 "(?, 'acme-corp', 37.512, -91.204, 'Main office')", (HQ,))
    conn.commit()
    conn.close()
    mod = _script("rollback_v015")

    # A v0.17.5 / v0.17.3 / v0.17.2 / v0.17 / v0.16 root is refused until
    # rollback_v0175, rollback_v0173, rollback_v0172, rollback_v017 and
    # rollback_v016 ran; v0.14's rollback refuses a v0.15 root until this one
    # ran.
    assert mod.main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0173").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0172").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v017").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v016").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    assert _script("rollback_v014").main(["--data-root", str(root)]) == 1
    assert "42" in json.loads(capsys.readouterr().out)["error"]

    assert mod.main(["--data-root", str(root)]) == 0                    # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False
    assert [(s["migration"], s["target"]) for s in out["steps"]] == [(42, "registry")]

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and out["done"][0]["integrity"] == "ok"
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 41
        assert conn.execute("SELECT label FROM site_locations_rolled_back_042"
                            ).fetchall() == [("Main office",)]
    finally:
        conn.close()

    assert mod.main(["--data-root", str(root), "--apply"]) == 0         # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []

    bootstrap.init_data_root()                                           # re-upgrade
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("SELECT label FROM site_locations").fetchall() == \
            [("Main office",)]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 48
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root)]) == 1                    # newer: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(tmp_path / "missing")]) == 2
