"""Migration 038 (the same-name fix) on a registry at 037 that already holds
operators, a single-person change and its notices: forward, rollback,
forward again — no notice is lost, every id and foreign key still resolves.

Pins:
  - operator_notices is rebuilt with the new kind 'mapping_review' (a
    platform notice: actor 0, no change request); every existing row keeps
    its id, acknowledgement and e-mail record; the other CHECKs hold;
  - the rollback keeps every mapping_review notice under
    operator_notices_rolled_back_038 (appended to on a second rollback),
    rebuilds 035's constraint (the new kind refused again) with every other
    row intact, version back to 37;
  - re-applying restores the kept notices whose recipient still exists.
"""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _build_v37(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 38:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 37
    return conn


def _seed(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO operators (username, email, token_hash, token_prefix) VALUES "
        "('alice', 'alice@example.test', 'h1', 'p1'), ('bob', 'bob@example.test', 'h2', 'p2'), "
        "('carol', 'carol@example.test', 'h3', 'p3')",
    )
    conn.execute(
        "INSERT INTO clients (slug, display_name, kind, review_state) VALUES "
        "('acme-corp', 'Acme Corp', 'client', 'confirmed'), "
        "('acme-dup', 'Acme Dup', 'client', 'confirmed')",
    )
    conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, target_slug, requested_by, "
        "reason, state, request_id, approval_mode, attestation, subject_confirmation, "
        "post_review_state) VALUES ('merge', 'acme-dup', 'acme-corp', 1, 'same customer', "
        "'applied', 'r-1', 'single_attested', "
        "'Duplicate created by the integration; checked both tenants today.', 'acme-dup', "
        "'pending')",
    )
    conn.commit()


def _merge_notice(conn: sqlite3.Connection, recipient: int) -> int:
    cur = conn.execute(
        "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, target_slug, "
        "change_request_id, title, body, request_id) VALUES (?, 'single_attested_merge', 1, "
        "'acme-dup', 'acme-corp', 1, 'Single-person merge: acme-dup → acme-corp', "
        "'alice merged acme-dup into acme-corp alone.', 'r-1')", (recipient,),
    )
    return int(cur.lastrowid)


def _review_notice(conn: sqlite3.Connection, recipient: int, digest: str = "d1") -> int:
    cur = conn.execute(
        "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, target_slug, "
        "change_request_id, title, body, request_id, email_state) VALUES (?, 'mapping_review', 0, "
        "'global', NULL, NULL, '1 tenant mapping made from a name match — please re-review', "
        "'These vendor sites were mapped to a client by NAME alone…', ?, 'not_configured')",
        (recipient, f"mapping-review:{digest}"),
    )
    return int(cur.lastrowid)


def _rows(conn, table="operator_notices") -> list[tuple]:
    return [tuple(r) for r in conn.execute(
        f"SELECT id, recipient_id, kind, change_request_id, acknowledged_at, email_state "
        f"FROM {table} ORDER BY id")]


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_forward_rollback_forward_keeps_every_notice(tmp_path):
    conn = _build_v37(tmp_path / "registry.db")
    _seed(conn)
    n_bob = _merge_notice(conn, 2)
    n_carol = _merge_notice(conn, 3)
    conn.execute("UPDATE operator_notices SET acknowledged_at = '2026-09-30T10:00:00.000Z', "
                 "email_state = 'sent' WHERE id = ?", (n_bob,))
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):              # 037 refuses the new kind
        _review_notice(conn, 1)
    before = _rows(conn)
    forward, rollback = _migration(38), _migration(38, "rollback")

    # ---- forward ---------------------------------------------------------
    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 38
    assert _rows(conn) == before                             # ids, acks, e-mail kept
    r_alice = _review_notice(conn, 1)
    r_bob = _review_notice(conn, 2)
    assert r_alice > n_carol                                 # AUTOINCREMENT carried on
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):              # other kinds still refused
        conn.execute("UPDATE operator_notices SET kind = 'something_else' WHERE id = ?", (r_bob,))
    with pytest.raises(sqlite3.IntegrityError):              # one per recipient per change
        _merge_notice(conn, 2)
    with pytest.raises(sqlite3.IntegrityError):              # no such operator
        _review_notice(conn, 99, "d2")
    indexes = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'operator_notices'")}
    assert {"idx_operator_notices_open", "idx_operator_notices_change",
            "idx_operator_notices_request"} <= indexes
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    # ---- rollback --------------------------------------------------------
    apply_migration(conn, rollback, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 37
    assert _rows(conn) == before                             # the merge notices, untouched
    assert [r[0] for r in _rows(conn, "operator_notices_rolled_back_038")] == [r_alice, r_bob]
    with pytest.raises(sqlite3.IntegrityError):              # 035's constraint is back
        _review_notice(conn, 1, "d3")
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    # ---- forward again: the kept notices come back -----------------------
    conn.execute("DELETE FROM operators WHERE id = 2")       # bob is gone meanwhile
    conn.commit()
    apply_migration(conn, forward, target="registry")
    kinds = {r[0]: r[2] for r in _rows(conn)}
    assert kinds.get(r_alice) == "mapping_review" and r_bob not in kinds
    assert kinds[n_carol] == "single_attested_merge"
    # A second rollback appends to the kept copy.
    apply_migration(conn, rollback, target="registry")
    assert conn.execute(
        "SELECT COUNT(*) FROM operator_notices_rolled_back_038").fetchone()[0] == 3
    assert "operator_notices" in _tables(conn)
    conn.close()
