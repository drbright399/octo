"""scripts/rollback_v013.py — the SQL rollback of v0.13 as ONE command (the
review found the runbook said "roll back 040, 039, 038" with no command to
do it): dry run by default, newest first, every registry / telemetry file,
entities.db left in place, nothing destroyed, a re-upgrade takes it back."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

from apps.octo.auth import bootstrap
from apps.octo.ingest import telemetry

SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v013.py"
SCRIPT_V014 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v014.py"
SCRIPT_V015 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v015.py"
SCRIPT_V016 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v016.py"
SCRIPT_V017 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v017.py"
SCRIPT_V0175 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v0175.py"
SCRIPT_V0173 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v0173.py"
SCRIPT_V0172 = Path(__file__).resolve().parents[4] / "scripts" / "rollback_v0172.py"


def _script(path: Path = SCRIPT):
    spec = importlib.util.spec_from_file_location(path.stem, path)
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


def test_dry_run_then_apply_then_reupgrade(tmp_path, monkeypatch, capsys):
    root = tmp_path / "root"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    bootstrap.init_data_root()
    reg = root / "registry.db"
    conn = sqlite3.connect(reg)
    conn.execute("INSERT INTO clients (slug, display_name, kind) VALUES ('acme-corp', 'Acme Corp', "
                 "'client')")
    conn.execute("UPDATE clients SET entity_resolution = 'shadow'")
    conn.commit()
    conn.close()
    tel = root / "clients" / "acme-corp" / "telemetry.db"
    tel.parent.mkdir(parents=True, exist_ok=True)
    telemetry.reset_schema_cache()
    telemetry.ensure_db(tel)
    (root / "clients" / "acme-corp" / "entities.db").write_bytes(b"")
    mod = _script()
    # A v0.17.5 root (registry 48) is refused until v0.17.5, v0.17.3,
    # v0.17.2, v0.17, v0.16, v0.15 and v0.14 are rolled back first, newest
    # first.
    assert _v(reg) == 48
    assert mod.main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert _script(SCRIPT_V0175).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V0173).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V0172).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V017).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V016).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V015).main(["--data-root", str(root), "--apply"]) == 0
    assert _script(SCRIPT_V014).main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()

    assert mod.main(["--data-root", str(root)]) == 0                 # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False and out["entities_left_in_place"] == 1
    assert [(s["migration"], s["target"]) for s in out["steps"]] == \
        [(40, "registry"), (39, "telemetry"), (38, "registry")]
    assert (_v(reg), _v(tel)) == (40, 39)                             # nothing written

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and all(d["integrity"] == "ok" for d in out["done"])
    assert (_v(reg), _v(tel)) == (37, 37)
    conn = sqlite3.connect(reg)
    try:
        kept = conn.execute("SELECT slug, entity_resolution FROM "
                            "clients_entity_resolution_rolled_back_040").fetchall()
    finally:
        conn.close()
    assert kept == [("acme-corp", "shadow")]                         # nothing destroyed

    assert mod.main(["--data-root", str(root), "--apply"]) == 0      # nothing left to do
    assert json.loads(capsys.readouterr().out)["steps"] == []

    bootstrap.init_data_root()                                        # re-upgrade
    conn = sqlite3.connect(reg)
    try:
        assert conn.execute("SELECT entity_resolution FROM clients").fetchone()[0] == "shadow"
    finally:
        conn.close()
    assert _v(reg) == 48


def test_refuses_a_root_it_does_not_know(tmp_path, capsys):
    mod = _script()
    assert mod.main(["--data-root", str(tmp_path / "missing")]) == 2
    (tmp_path / "empty").mkdir()
    assert mod.main(["--data-root", str(tmp_path / "empty")]) == 1
    assert "no registry" in capsys.readouterr().out
