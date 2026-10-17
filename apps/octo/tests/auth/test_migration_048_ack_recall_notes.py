"""Migration 048 (v0.17.5 — RECALL an acknowledgement, NOTES on it) —
forward, rollback, forward again — and scripts/rollback_v0175.py.

Pins:
  - registry only: alert_verdict_followup (note / recall), append-only (no
    update, no delete, no REPLACE of an existing id — nor on 046's
    alert_verdict / expected_condition), text 1..500, a recall's reason
    ≥ 10, ONE recall per ack, always on an ACK of the same tenant;
    user_version 48;
  - the rollback LEAVES the table (version → the newest registry migration
    before 048: 47); a re-upgrade finds it current;
  - rollback_v0175: dry run by default (it counts the recalled acks — they
    cover their alerts again on a rolled-back bundle), the registry only, a
    newer root refused, nothing to do after it ran; rollback_v0173 refuses a
    48 root until this ran.
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
from apps.octo.db import connect
from apps.octo.migration import list_migrations

SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
NOW = "2026-10-08T12:00:00.000Z"
REASON = "a partner removed the DNS agents on purpose"


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
    yield tmp_path / "root"


def _verdict(reg, verdict: str = "ack", slug: str = "acme-corp", event_id: int = 7) -> int:
    return int(reg.execute(
        "INSERT INTO alert_verdict (tenant_slug, event_id, source, device_key, signature_key, "
        "verdict, actor, at) VALUES (?, ?, 'unifi', 'd', 's', ?, 1, ?)",
        (slug, event_id, verdict, NOW)).lastrowid)


INS = ("INSERT INTO alert_verdict_followup (verdict_id, tenant_slug, kind, actor, at, text) "
       "VALUES (?, ?, ?, 2, ?, ?)")


def test_048_targets_the_registry_only():
    for kind in ("forward", "rollback"):
        sql = _migration(48, kind).sql
        assert "-- @target: registry" in sql
        for target in ("telemetry", "entities", "events", "patterns", "audit"):
            assert f"-- @target: {target}" not in sql


def test_the_rollback_returns_the_registry_to_the_newest_migration_before_048():
    back = _migration(48, "rollback").sql
    chunks = re.split(r"^-- @target: (\w+)\s*$", back, flags=re.MULTILINE)
    sections = dict(zip(chunks[1::2], chunks[2::2]))
    assert set(sections) == {"registry"}
    before = max(m.number for m in list_migrations() if m.number < 48 and (
        "-- @target: registry" in m.sql or m.number == 1))
    assert re.findall(r"PRAGMA user_version = (\d+)", sections["registry"]) == [str(before)]
    assert "DROP" not in sections["registry"].upper()                  # the table is kept


def test_registry_constraints(root):
    reg = connect(root / "registry.db")
    try:
        assert reg.execute("PRAGMA user_version").fetchone()[0] == 48
        assert "alert_verdict_followup" in _tables(reg)
        ack = _verdict(reg)
        note = reg.execute(INS, (ack, "acme-corp", "note", NOW, "the partner did it")).lastrowid
        for bad in ((ack, "acme-corp", "recall", NOW, "too short"),        # reason < 10
                    (ack, "acme-corp", "recall", NOW, "         x         "),
                    (ack, "acme-corp", "note", NOW, "   "),                 # says nothing
                    (ack, "acme-corp", "note", NOW, "x" * 501),
                    (ack, "acme-corp", "dismiss", NOW, "a long enough text"),
                    (ack, "acme-corp", "note", "today", "short at")):
            with pytest.raises(sqlite3.IntegrityError):
                reg.execute(INS, bad)
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO alert_verdict_followup (verdict_id, tenant_slug, kind, "
                        "actor, at) VALUES (?, 'acme-corp', 'note', 2, ?)", (ack, NOW))
        # Always on an ACK of the same tenant.
        confirmed = _verdict(reg, "confirmed", event_id=8)
        with pytest.raises(sqlite3.IntegrityError, match="acknowledgement of the same tenant"):
            reg.execute(INS, (confirmed, "acme-corp", "note", NOW, "context"))
        with pytest.raises(sqlite3.IntegrityError, match="acknowledgement of the same tenant"):
            reg.execute(INS, (ack, "example-bakery", "note", NOW, "context"))
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute(INS, (ack + 999, "acme-corp", "note", NOW, "context"))
        # ONE recall per ack: final.
        reg.execute(INS, (ack, "acme-corp", "recall", NOW, REASON))
        with pytest.raises(sqlite3.IntegrityError, match="already recalled"):
            reg.execute(INS, (ack, "acme-corp", "recall", NOW, "and once more, to be sure"))
        reg.execute("DROP TRIGGER alert_verdict_followup_recall_final")   # the index holds too
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            reg.execute(INS, (ack, "acme-corp", "recall", NOW, "and once more, to be sure"))
        reg.execute(INS, (ack, "acme-corp", "note", NOW, "a note after the recall"))
        # Append-only; the ack row is untouched by any of it.
        with pytest.raises(sqlite3.IntegrityError, match="never changed"):
            reg.execute("UPDATE alert_verdict_followup SET text = 'rewritten' WHERE id = ?",
                        (note,))
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            reg.execute("DELETE FROM alert_verdict_followup")
        assert reg.execute("SELECT COUNT(*) FROM alert_verdict_followup").fetchone()[0] == 3
    finally:
        reg.close()


def test_a_follow_up_is_never_replaced_nor_the_verdict_it_hangs_on(root):
    """Review fix: SQLite's REPLACE on an existing id removes the old row
    WITHOUT the delete trigger — a recall overwritten by a note would let
    its ack cover the alert again. Every insert naming an existing id is
    refused (an upsert too), on the follow-ups and on 046's verdict rows and
    expected conditions; the recall survives and still reads as a recall."""
    reg = connect(root / "registry.db")
    try:
        ack = _verdict(reg)
        recall = reg.execute(INS, (ack, "acme-corp", "recall", NOW, REASON)).lastrowid
        for stmt in ("REPLACE INTO", "INSERT OR REPLACE INTO", "INSERT OR IGNORE INTO"):
            with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
                reg.execute(f"{stmt} alert_verdict_followup (id, verdict_id, tenant_slug, kind, "
                            "actor, at, text) VALUES (?, ?, 'acme-corp', 'note', 2, ?, 'x')",
                            (recall, ack, NOW))
        with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
            reg.execute("INSERT INTO alert_verdict_followup (id, verdict_id, tenant_slug, kind, "
                        "actor, at, text) VALUES (?, ?, 'acme-corp', 'note', 2, ?, 'x') "
                        "ON CONFLICT(id) DO NOTHING", (recall, ack, NOW))
        assert [tuple(r) for r in reg.execute(
            "SELECT id, kind, text FROM alert_verdict_followup")] == [(recall, "recall", REASON)]
        assert reg.execute(
            "SELECT COUNT(*) FROM alert_verdict_followup WHERE verdict_id = ? AND kind = 'recall'",
            (ack,)).fetchone()[0] == 1
        # 046's ack row (the one the recall hangs on) is never replaced either.
        with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
            reg.execute("REPLACE INTO alert_verdict (id, tenant_slug, event_id, source, "
                        "device_key, signature_key, verdict, actor, at) "
                        "VALUES (?, 'acme-corp', 99, 'unifi', 'd', 's', 'ack', 1, ?)", (ack, NOW))
        assert reg.execute("SELECT event_id FROM alert_verdict WHERE id = ?",
                           (ack,)).fetchone()[0] == 7
        # Nor a revoked expected condition (a REPLACE would un-revoke it).
        cols = ("tenant_slug, source, device_key, signature_key, label, reason, "
                "origin_event_id, created_by, created_at, review_at")
        vals = ("'acme-corp', 'unifi', 'd', 's', 'backup', 'known backup traffic', 7, 1, "
                "'2026-10-08T12:00:00.000Z', '2026-11-08T12:00:00.000Z'")
        rule = reg.execute(f"INSERT INTO expected_condition ({cols}) VALUES ({vals})").lastrowid
        reg.execute("UPDATE expected_condition SET revoked_at = ?, revoked_by = 1, "
                    "revoke_reason = 'not expected after all' WHERE id = ?", (NOW, rule))
        with pytest.raises(sqlite3.IntegrityError, match="never replaced"):
            reg.execute(f"REPLACE INTO expected_condition (id, {cols}) VALUES (?, {vals})",
                        (rule,))
        assert reg.execute("SELECT revoked_at FROM expected_condition WHERE id = ?",
                           (rule,)).fetchone()[0] == NOW
        # A writer that names no id is unaffected.
        assert reg.execute(INS, (ack, "acme-corp", "note", NOW, "context")).lastrowid > recall
        assert _verdict(reg, event_id=9) > ack
    finally:
        reg.close()


def test_rollback_v0175_script_keeps_everything_and_a_reupgrade_takes_it_back(root, capsys):
    reg_path = root / "registry.db"
    reg = connect(reg_path)
    ack = _verdict(reg)
    reg.execute(INS, (ack, "acme-corp", "recall", NOW, REASON))
    reg.execute(INS, (ack, "acme-corp", "note", NOW, "confirmed by phone"))
    reg.close()
    mod = _script("rollback_v0175")
    # v0.17.3's rollback refuses a 48 root: it rolls back 047 only.
    assert _script("rollback_v0173").main(["--data-root", str(root)]) == 1
    assert "48" in json.loads(capsys.readouterr().out)["error"]

    assert mod.main(["--data-root", str(root)]) == 0                       # dry run
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False and out["recalled_acks"] == 1
    assert [(Path(s["file"]).name, s["target"]) for s in out["steps"]] == [
        ("registry.db", "registry")]
    assert _v(reg_path) == 48                                              # nothing written

    assert mod.main(["--data-root", str(root), "--apply"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and out["done"][0]["integrity"] == "ok"
    assert _v(reg_path) == 47
    conn = sqlite3.connect(reg_path)
    try:                                                         # the table is LEFT, whole
        assert conn.execute("SELECT kind, text FROM alert_verdict_followup ORDER BY id"
                            ).fetchall() == [("recall", REASON), ("note", "confirmed by phone")]
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root), "--apply"]) == 0            # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []
    # Now v0.17.3's rollback may run (it is not run here: 047 is its test).
    assert _script("rollback_v0173").main(["--data-root", str(root)]) == 0
    capsys.readouterr()

    # Re-upgrade: the registry on start finds the table current.
    bootstrap.init_data_root()
    assert _v(reg_path) == 48
    conn = connect(reg_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM alert_verdict_followup").fetchone()[0] == 2
        with pytest.raises(sqlite3.IntegrityError, match="already recalled"):
            conn.execute(INS, (ack, "acme-corp", "recall", NOW, "after the re-upgrade too"))
        conn.execute("PRAGMA user_version = 49")
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root)]) == 1                       # newer: refused
    assert "49" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(root.parent / "missing")]) == 2
    (root / "registry.db").rename(root / "registry.db.moved")
    assert mod.main(["--data-root", str(root)]) == 1                       # no registry
    assert "no registry" in json.loads(capsys.readouterr().out)["error"]
