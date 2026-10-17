"""rotate_audit_chain.py: rotates a race-forked chain, REFUSES a tampered one."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from apps.octo.auth import audit
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations

_SPEC = importlib.util.spec_from_file_location(
    "rotate_audit_chain",
    Path(__file__).resolve().parents[3] / "scripts" / "rotate_audit_chain.py",
)
rotate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rotate)

_FIX = "a" * 40


def _entry(i: int) -> audit.AuditEntry:
    return audit.AuditEntry(actor="operator:1", actor_kind="human",
                            action="tickets.list", target_kind="ticket",
                            target_id=str(i), client_slug="global",
                            after_state={"i": i})


def _fork(conn: sqlite3.Connection, parent_id: int) -> None:
    """Insert a row the way the OLD racy append() did: correct id, correct
    self-hash, but prev_hash = an EARLIER row's hash (stale tip)."""
    parent = conn.execute("SELECT row_hash FROM audit_log WHERE id = ?",
                          (parent_id,)).fetchone()[0]
    next_id = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0] + 1
    rid, ts = str(uuid.uuid4()), "2026-01-01T00:00:00.000Z"
    h = audit._row_hash(prev_hash=parent, row_id=next_id, ts=ts, actor="operator:1",
                        action="tickets.list", target_kind="ticket", target_id="f",
                        before_state=None, after_state=None, reason=None,
                        request_id=rid)
    conn.execute(
        "INSERT INTO audit_log (id, ts, actor, actor_kind, action, target_kind, "
        "target_id, before_state, after_state, reason, request_id, client_slug, "
        "prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (next_id, ts, "operator:1", "human", "tickets.list", "ticket", "f",
         None, None, None, rid, "global", parent, h))
    conn.commit()


@pytest.fixture
def forked_root(tmp_path, monkeypatch):
    root = tmp_path / "state"
    (root / "global").mkdir(parents=True)
    (root / "clients").mkdir()
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    conn = connect(root / "global" / "audit.db")
    for mig in list_migrations(kind="forward"):
        if mig.number == 3:
            apply_migration(conn, mig, target="audit")
    for i in range(5):
        audit.append(conn, _entry(i))
    _fork(conn, parent_id=4)          # row 6 chains to row 4 instead of 5
    audit.append(conn, _entry(99))    # chain continues from the fork
    _fork(conn, parent_id=6)          # row 8 chains to row 6 instead of 7
    ok, _, _ = audit.verify(conn)
    conn.close()
    assert ok is False
    return root


def _run(root: Path, out: Path) -> int:
    return rotate.main(["--data-root", str(root), "--out", str(out),
                        "--fix-commit", _FIX, "--image-tag", "v-test",
                        "--operator", "alice",
                        "--archived-location", "compliance-archive-test"])


def test_rotates_a_race_forked_chain_and_links_it_by_hash(forked_root, tmp_path, capsys):
    out = tmp_path / "rotation"
    assert _run(forked_root, out) == 0

    live = forked_root / "global" / "audit.db"
    conn = connect(live, read_only=True)
    try:
        assert audit.verify(conn) == (True, 1, None)
        row = conn.execute("SELECT action, actor, after_state, row_hash FROM audit_log").fetchone()
    finally:
        conn.close()
    assert row["action"] == "audit_chain_rotated" and row["actor"] == "alice"
    state = json.loads(row["after_state"])
    archived = out / "audit-global-forked.db"
    assert state["archived_sha256"] == rotate._sha256_file(archived)
    assert state["archived_row_count"] == 8
    assert state["fork_row_ids_count"] == 2 and state["first_fork_row_id"] == 6
    assert state["fix_commit"] == _FIX

    manifest = json.loads((out / "rotation-manifest.json").read_text())
    assert manifest["fork_row_ids"] == [6, 8]
    assert manifest["new_genesis_row_hash"] == row["row_hash"]

    # archive: single file, not WAL, opens immutable, history untouched
    assert not Path(str(archived) + "-wal").exists()
    ro = sqlite3.connect(f"file:{archived}?mode=ro&immutable=1", uri=True)
    assert ro.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    assert ro.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 8
    ro.close()

    # the fixed append() continues the new chain cleanly
    conn = connect(live)
    audit.append(conn, _entry(1))
    assert audit.verify(conn) == (True, 2, None)
    conn.close()


def test_refuses_a_tampered_chain_and_touches_nothing(forked_root, tmp_path, capsys):
    live = forked_root / "global" / "audit.db"
    conn = sqlite3.connect(live)
    conn.execute("DROP TRIGGER IF EXISTS global_audit_no_update")
    conn.execute("UPDATE audit_log SET actor = 'mallory' WHERE id = 3")   # an EDIT
    conn.commit(); conn.close()
    before = live.read_bytes()

    assert _run(forked_root, tmp_path / "rotation") == 3
    assert "NOT explained by the append race" in capsys.readouterr().err
    assert sqlite3.connect(live).execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 8
    assert live.exists()


def test_refuses_a_deleted_row(forked_root, tmp_path):
    live = forked_root / "global" / "audit.db"
    conn = sqlite3.connect(live)
    conn.execute("DROP TRIGGER IF EXISTS global_audit_no_delete")
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    conn.commit(); conn.close()
    assert _run(forked_root, tmp_path / "rotation") == 3


def test_label_must_not_be_a_path_or_host(forked_root, tmp_path):
    rc = rotate.main(["--data-root", str(forked_root), "--out", str(tmp_path / "o"),
                      "--fix-commit", _FIX, "--image-tag", "t", "--operator", "alice",
                      "--archived-location", "/srv/archive/host.example.net"])
    assert rc == 2
