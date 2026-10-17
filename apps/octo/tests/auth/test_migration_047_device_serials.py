"""Migration 047 (v0.17.3 — the Datto device's serial number, manufacturer
and model from its audit) — forward, rollback, forward again — and
scripts/rollback_v0173.py.

Pins:
  - entities: inv_device.serial / manufacturer / model / audit_at (nullable;
    a file at 46 gets them lazily); registry: the version only (47);
  - the rollback returns each file to the newest migration before 047 that
    has its section (registry → 46, entities → 46), keeps the four columns'
    values aside and drops them; a re-upgrade puts them back and spends what
    was kept;
  - rollback_v0173: dry run by default, the tenant files then the registry,
    a newer root (v0.17.5's 48) refused until rollback_v0175 ran, nothing to
    do after it ran; rollback_v0172 refuses a 47 root until this ran.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.migration import apply_migration, list_migrations

SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
COLUMNS = ("serial", "manufacturer", "model", "audit_at")
AUDITED = "2026-10-07T12:00:00.000Z"


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _cols(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _v(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    create_client("acme-corp", "Acme Corp", kind="client")
    entity_db.reset_schema_cache()
    yield tmp_path / "root"
    entity_db.reset_schema_cache()


def test_047_targets_the_registry_and_entities_only():
    for kind in ("forward", "rollback"):
        sql = _migration(47, kind).sql
        for target in ("registry", "entities"):
            assert f"-- @target: {target}" in sql
        for target in ("telemetry", "events", "patterns", "audit"):
            assert f"-- @target: {target}" not in sql
    assert 47 in entity_db.migration_numbers()


def test_the_rollback_returns_each_file_to_the_newest_migration_before_047():
    back = _migration(47, "rollback").sql
    chunks = re.split(r"^-- @target: (\w+)\s*$", back, flags=re.MULTILINE)
    sections = dict(zip(chunks[1::2], chunks[2::2]))
    assert set(sections) == {"registry", "entities"}
    for target, versions in sections.items():
        before = max(m.number for m in list_migrations() if m.number < 47 and (
            f"-- @target: {target}" in m.sql or (target == "registry" and m.number == 1)))
        assert re.findall(r"PRAGMA user_version = (\d+)", versions) == [str(before)], target


def _entities(root: Path) -> Path:
    ent = root / "clients" / "acme-corp" / "entities.db"
    entity_db.ensure_db(ent)
    conn = sqlite3.connect(ent)
    conn.execute("INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
                 "first_seen_at, updated_at, ext_ip, serial, manufacturer, model, audit_at) "
                 "VALUES (1, 'dev-1', 'site-a', 'WS-1', 'a', 'b', '203.0.113.129', "
                 "'EXAMPLE-SN-0001', 'Example Computers', 'Model 7', ?)", (AUDITED,))
    conn.execute("INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
                 "first_seen_at, updated_at) VALUES (1, 'dev-2', 'site-a', 'WS-2', 'a', 'b')")
    conn.commit()
    conn.close()
    return ent


def test_a_file_at_46_gets_the_columns_lazily_and_they_are_nullable(root):
    ent = root / "clients" / "acme-corp" / "entities.db"
    for f in ent.parent.glob("entities.db*"):          # provisioning made a current one
        f.unlink()
    conn = sqlite3.connect(ent)
    try:
        for num in (40, 46):                       # an entities.db v0.17.2 left behind
            apply_migration(conn, _migration(num), target="entities")
        assert _v(ent) == 46 and not set(COLUMNS) & set(_cols(conn, "inv_device"))
    finally:
        conn.close()
    entity_db.reset_schema_cache()
    assert entity_db.ensure_db(ent) == [47]
    conn = sqlite3.connect(ent)
    try:
        assert set(COLUMNS) <= set(_cols(conn, "inv_device"))
        conn.execute("INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, "
                     "first_seen_at, updated_at) VALUES (1, 'dev-x', 's', 'a', 'b')")
        assert conn.execute("SELECT serial, manufacturer, model, audit_at FROM inv_device"
                            ).fetchone() == (None, None, None, None)
    finally:
        conn.close()


def test_rollback_v0173_script_keeps_everything_and_a_reupgrade_takes_it_back(root, capsys):
    ent = _entities(root)
    reg = root / "registry.db"
    mod = _script("rollback_v0173")
    # v0.17.5 (048) sits on top: refused until rollback_v0175 ran.
    assert (_v(ent), _v(reg)) == (47, 48)
    assert mod.main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    assert (_v(ent), _v(reg)) == (47, 47)
    # v0.17.2's rollback refuses a 47 root: run alone it would roll 046 back
    # on an entities.db that still holds 047's columns.
    assert _script("rollback_v0172").main(["--data-root", str(root)]) == 1
    assert "47" in json.loads(capsys.readouterr().out)["error"]

    assert mod.main(["--data-root", str(root)]) == 0                      # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False
    assert [(Path(s["file"]).name, s["target"]) for s in out["steps"]] == [
        ("entities.db", "entities"), ("registry.db", "registry")]
    assert (_v(ent), _v(reg)) == (47, 47)                                 # nothing written

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and all(d["integrity"] == "ok" for d in out["done"])
    assert (_v(ent), _v(reg)) == (46, 46)
    conn = sqlite3.connect(ent)
    try:
        assert not set(COLUMNS) & set(_cols(conn, "inv_device"))
        assert "ext_ip" in _cols(conn, "inv_device")                     # 046's: untouched
        assert conn.execute("SELECT device_uid, serial, manufacturer, model, audit_at FROM "
                            "inv_device_audit_rolled_back_047").fetchall() == \
            [("dev-1", "EXAMPLE-SN-0001", "Example Computers", "Model 7", AUDITED)]
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root), "--apply"]) == 0           # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []
    # Now v0.17.2's rollback may run (it is not run here: 046 is its test).
    assert _script("rollback_v0172").main(["--data-root", str(root)]) == 0
    capsys.readouterr()

    # Re-upgrade: the registry on start, the entities file lazily.
    bootstrap.init_data_root()
    entity_db.reset_schema_cache()
    assert entity_db.ensure_db(ent) == [47]
    conn = sqlite3.connect(ent)
    try:
        rows = conn.execute("SELECT device_uid, serial, manufacturer, model, audit_at FROM "
                            "inv_device ORDER BY device_uid").fetchall()
        assert rows == [("dev-1", "EXAMPLE-SN-0001", "Example Computers", "Model 7", AUDITED),
                        ("dev-2", None, None, None, None)]
        assert conn.execute("SELECT COUNT(*) FROM inv_device_audit_rolled_back_047"
                            ).fetchone()[0] == 0                          # spent
    finally:
        conn.close()
    assert _v(reg) == 48                                                  # 047 + 048 again
    assert mod.main(["--data-root", str(root)]) == 1                      # newer: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(root.parent / "missing")]) == 2


def test_an_empty_or_pre_040_entities_file_is_left_alone(root, capsys):
    """A tenant whose entities.db was never written (empty, or still at the
    version an older release left it) is not a step."""
    empty = root / "clients" / "acme-corp" / "entities.db"
    empty.write_bytes(b"")
    create_client("example-bakery", "Example Bakery", kind="client")
    old = root / "clients" / "example-bakery" / "entities.db"
    conn = sqlite3.connect(old)
    apply_migration(conn, _migration(40), target="entities")
    conn.close()
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    out = _script("rollback_v0173").plan(root)
    assert out["ok"] and [Path(s["file"]).name for s in out["steps"]] == ["registry.db"]
