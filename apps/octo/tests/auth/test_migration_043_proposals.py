"""Migration 043 (PROPOSALS — an integration proposes, an operator confirms —
and the site pins' provenance) — forward, rollback, forward again — and
scripts/rollback_v016.py, its one-command rollback.

Pins:
  - proposals: a status in proposed / confirmed / rejected / superseded; a
    closed one says when; an operator's decision names the operator and
    carries a 3..500-character reason; one LIVE row per (kind, source,
    source_ref, target, source hash) — NULL targets included; a superseded
    row never blocks the same data;
  - site_locations gains origin ('manual' default | 'autotask') and
    proposal_id; existing pins read 'manual'; a hand edit by code before
    043 (it never names the two columns) is 'manual' again (a trigger the
    rollback drops);
  - the rollback keeps every proposal (proposals_rolled_back_043) and the
    provenance of every non-manual pin, drops the table and the two columns
    (site_locations is 042's again, its pins untouched), version back to 42;
  - re-applying restores the newest kept proposal of each id whose tenant
    still exists and the provenance of each pin that is unchanged — a pin
    edited during the downgrade stays 'manual'; the kept rows are spent;
  - rollback_v016: dry run by default, one step (043, registry), a root
    newer than 43 refused (a v0.17 root until rollback_v017 ran), nothing to
    do on a 42 root; rollback_v015 refuses a 43 root until this ran.
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
H1, H2 = "a" * 32, "b" * 32


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _cols(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _triggers(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger' "
                                       "AND tbl_name = 'site_locations'")}


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _propose(conn, ref: str, *, target=None, h: str = H1, slug: str = "acme-corp") -> int:
    cur = conn.execute(
        "INSERT INTO proposals (kind, source, tenant_slug, target_key, source_ref, payload_json, "
        "source_hash) VALUES ('site_location', 'autotask', ?, ?, ?, '{\"label\": \"x\"}', ?)",
        (slug, target, ref, h))
    return int(cur.lastrowid)


@pytest.fixture
def reg(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    conn = connect(tmp_path / "root" / "registry.db")
    # v0.17.5 (048), v0.17.3 (047), v0.17.2 (046) and v0.17 (044),
    # independent of 043, sit on top: roll them back first, the way
    # rollback_v0175 → rollback_v0173 → rollback_v0172 → rollback_v017 →
    # rollback_v016 run.
    apply_migration(conn, _migration(48, "rollback"), target="registry")
    apply_migration(conn, _migration(47, "rollback"), target="registry")
    apply_migration(conn, _migration(46, "rollback"), target="registry")
    apply_migration(conn, _migration(44, "rollback"), target="registry")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES "
                 "('acme-corp', 'Acme Corp', 'client'), "
                 "('example-bakery', 'Example Bakery', 'client')")
    yield conn
    conn.close()


def test_043_is_registry_only():
    for kind in ("forward", "rollback"):
        sql = _migration(43, kind).sql
        assert "-- @target: registry" in sql
        assert "-- @target: telemetry" not in sql and "-- @target: entities" not in sql


def test_constraints(reg):
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 43
    assert {"proposals", "site_locations", "tenant_locations"} <= _tables(reg)
    assert _cols(reg, "site_locations")[-2:] == ["origin", "proposal_id"]
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label) "
                "VALUES (?, 'acme-corp', 37.5, -91.2, 'Main office')", (HQ,))
    assert reg.execute("SELECT origin FROM site_locations").fetchone()[0] == "manual"
    with pytest.raises(sqlite3.IntegrityError):
        reg.execute("UPDATE site_locations SET origin = 'guessed'")

    pid = _propose(reg, "company:1")
    assert reg.execute("SELECT status FROM proposals WHERE id = ?", (pid,)).fetchone()[0] \
        == "proposed"
    with pytest.raises(sqlite3.IntegrityError):                 # the same data twice
        _propose(reg, "company:1")
    _propose(reg, "company:1", target=HQ)                        # another target: allowed
    _propose(reg, "company:1", h=H2)                             # changed data: allowed
    with pytest.raises(sqlite3.IntegrityError):                  # NULL targets compare equal
        _propose(reg, "company:1", h=H2)
    for bad in ("UPDATE proposals SET status = 'maybe' WHERE id = ?",
                # closed without saying when
                "UPDATE proposals SET status = 'superseded' WHERE id = ?",
                # an operator's decision without who / why
                "UPDATE proposals SET status = 'rejected', decided_at = 'x' WHERE id = ?",
                "UPDATE proposals SET status = 'confirmed', decided_at = 'x', decided_by = 1, "
                "decision_reason = 'ok' WHERE id = ?",
                "UPDATE proposals SET source_hash = 'short' WHERE id = ?"):
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute(bad, (pid,))
    reg.execute("UPDATE proposals SET status = 'rejected', decided_at = 'x', decided_by = 1, "
                "decision_reason = 'not this client' WHERE id = ?", (pid,))
    reg.execute("UPDATE proposals SET status = 'superseded', decided_at = 'x' "
                "WHERE source_hash = ?", (H2,))


def test_a_superseded_row_never_blocks_the_same_data(reg):
    old = _propose(reg, "company:1", target=HQ)
    reg.execute("UPDATE proposals SET status = 'superseded', decided_at = 'x' WHERE id = ?",
                (old,))
    again = _propose(reg, "company:1", target=HQ)             # the same data, back
    assert again > old
    with pytest.raises(sqlite3.IntegrityError):              # … but never twice live
        _propose(reg, "company:1", target=HQ)
    reg.execute("UPDATE proposals SET status = 'rejected', decided_at = 'x', decided_by = 1, "
                "decision_reason = 'not this client' WHERE id = ?", (again,))
    with pytest.raises(sqlite3.IntegrityError):              # a rejection holds the data
        _propose(reg, "company:1", target=HQ)


def test_a_hand_edit_by_pre_043_code_is_manual_again(reg):
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by, "
                "origin, proposal_id) VALUES (?, 'acme-corp', 37.5, -91.2, '1 Example Rd', 7, "
                "'autotask', 5)", (HQ,))
    # 042's upsert (the v0.15 image on this schema): it never names origin /
    # proposal_id — the pin must not read "from Autotask, confirmed by" its
    # hand editor.
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by, "
                "set_at) VALUES (?, 'acme-corp', 37.6, -91.3, 'Front door', 9, 'now') "
                "ON CONFLICT (site_key) DO UPDATE SET tenant_slug = excluded.tenant_slug, "
                "lat = excluded.lat, lng = excluded.lng, label = excluded.label, "
                "set_by = excluded.set_by, set_at = excluded.set_at", (HQ,))
    row = reg.execute("SELECT origin, proposal_id, set_by FROM site_locations").fetchone()
    assert tuple(row) == ("manual", None, 9)
    # 043's own writes: a confirm (a NEW proposal id) keeps its provenance;
    # a hand edit says 'manual' itself.
    for origin, pid in (("autotask", 6), ("autotask", 8), ("manual", None)):
        reg.execute("UPDATE site_locations SET lat = lat + 0.01, origin = ?, proposal_id = ?",
                    (origin, pid))
        assert tuple(reg.execute("SELECT origin, proposal_id FROM site_locations"
                                 ).fetchone()) == (origin, pid)


def test_forward_rollback_forward_keeps_and_restores(reg):
    p1 = _propose(reg, "company:1", target=HQ)
    p2 = _propose(reg, "company:2", slug="example-bakery")
    reg.execute("UPDATE proposals SET status = 'confirmed', decided_at = 'x', decided_by = 7, "
                "decision_reason = 'verified on site' WHERE id = ?", (p1,))
    reg.execute("INSERT INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by, "
                "origin, proposal_id) VALUES (?, 'acme-corp', 37.5, -91.2, '1 Example Rd', 7, "
                "'autotask', ?), (?, 'acme-corp', 37.6, -91.3, 'Annex', 7, 'autotask', ?)",
                (HQ, p1, ANNEX, p1))
    fwd, back = _migration(43), _migration(43, "rollback")

    apply_migration(reg, back, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 42
    assert "proposals" not in _tables(reg)
    assert _cols(reg, "site_locations") == ["site_key", "tenant_slug", "lat", "lng", "label",
                                            "set_by", "set_at"]
    assert reg.execute("SELECT COUNT(*) FROM site_locations").fetchone()[0] == 2   # pins stay
    assert _triggers(reg) == set()                                 # 042's table again
    kept = reg.execute("SELECT id, status FROM proposals_rolled_back_043 ORDER BY id").fetchall()
    assert [tuple(r) for r in kept] == [(p1, "confirmed"), (p2, "proposed")]

    # During the downgrade: the annex pin is edited by hand, the bakery leaves.
    reg.execute("UPDATE site_locations SET label = 'Annex (moved)' WHERE site_key = ?", (ANNEX,))
    reg.execute("DELETE FROM clients WHERE slug = 'example-bakery'")
    apply_migration(reg, fwd, target="registry")
    assert reg.execute("PRAGMA user_version").fetchone()[0] == 43
    assert _triggers(reg) == {"site_locations_hand_edit_is_manual"}
    rows = reg.execute("SELECT id, status, decided_by, decision_reason FROM proposals"
                       ).fetchall()
    assert [tuple(r) for r in rows] == [(p1, "confirmed", 7, "verified on site")]
    pins = dict(reg.execute("SELECT site_key, origin FROM site_locations").fetchall())
    assert pins == {HQ: "autotask", ANNEX: "manual"}
    assert reg.execute("SELECT proposal_id FROM site_locations WHERE site_key = ?",
                       (HQ,)).fetchone()[0] == p1
    for table in ("proposals_rolled_back_043", "site_locations_origin_rolled_back_043"):
        assert reg.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0   # spent

    # A later rollback keeps the state of THEN.
    reg.execute("UPDATE proposals SET decision_reason = 'checked twice'")
    apply_migration(reg, back, target="registry")
    apply_migration(reg, fwd, target="registry")
    assert reg.execute("SELECT decision_reason FROM proposals").fetchone()[0] == "checked twice"
    # And the ids keep counting on (a restored id is never handed out again).
    assert _propose(reg, "company:9") > p2


def test_rollback_v016_script(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    bootstrap.init_data_root()
    conn = sqlite3.connect(root / "registry.db")
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', "
                 "'Acme Corp', 'client')")
    _propose(conn, "company:1")
    conn.commit()
    conn.close()
    mod = _script("rollback_v016")

    # A v0.17.5 root (48) is refused until rollback_v0175, rollback_v0173,
    # rollback_v0172 and rollback_v017 ran.
    assert mod.main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0173").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0172").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v017").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    assert _script("rollback_v015").main(["--data-root", str(root)]) == 1   # 43: not its own
    assert "43" in json.loads(capsys.readouterr().out)["error"]

    assert mod.main(["--data-root", str(root)]) == 0                    # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False
    assert [(s["migration"], s["target"]) for s in out["steps"]] == [(43, "registry")]

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and out["done"][0]["integrity"] == "ok"
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 42
        assert conn.execute("SELECT source_ref FROM proposals_rolled_back_043").fetchall() == \
            [("company:1",)]
    finally:
        conn.close()

    assert mod.main(["--data-root", str(root), "--apply"]) == 0         # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []

    bootstrap.init_data_root()                                           # re-upgrade
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("SELECT source_ref FROM proposals").fetchall() == [("company:1",)]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 48  # 043…048 again
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root)]) == 1                    # newer: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(tmp_path / "missing")]) == 2
