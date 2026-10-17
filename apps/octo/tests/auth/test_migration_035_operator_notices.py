"""Migration 035 (v0.10) on a registry at 034 that already holds operators and
a single-person change: forward, rollback, forward again — no notice is lost,
every foreign key still resolves.

Pins:
  - operator_notices exists with its CHECKs (kind, email_state, one notice
    per recipient per change) and cascades with a DELETED operator (a
    never-used account's removal must not be blocked by a notice);
  - the rollback keeps every notice under operator_notices_rolled_back_035
    (appending on a second rollback) and sets the version back to 34;
  - re-applying starts an empty table.
"""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations


def _build_v34(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 35:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 34
    return conn


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


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


def _notice(conn: sqlite3.Connection, recipient: int, request_id: str = "r-1") -> int:
    cur = conn.execute(
        "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, target_slug, "
        "change_request_id, title, body, request_id) VALUES (?, 'single_attested_merge', 1, "
        "'acme-dup', 'acme-corp', 1, 'Single-person merge: acme-dup → acme-corp', "
        "'alice merged acme-dup into acme-corp alone.', ?)", (recipient, request_id),
    )
    return int(cur.lastrowid)


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_forward_rollback_forward_keeps_every_notice(tmp_path):
    conn = _build_v34(tmp_path / "registry.db")
    _seed(conn)
    forward, rollback = _migration(35), _migration(35, "rollback")

    # ---- forward ---------------------------------------------------------
    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 35
    assert "operator_notices" in _tables(conn)
    n_bob = _notice(conn, 2)
    n_carol = _notice(conn, 3)
    conn.execute(
        "UPDATE operator_notices SET email_state = 'sent', "
        "email_attempted_at = '2026-09-28T12:00:00.000Z' WHERE id = ?", (n_bob,),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM operator_notices WHERE id = ?", (n_carol,)).fetchone()
    assert (row["email_state"], row["acknowledged_at"], row["created_at"] is not None) == (
        "pending", None, True)
    # The CHECKs and the one-notice-per-recipient-per-change rule.
    with pytest.raises(sqlite3.IntegrityError):
        _notice(conn, 2)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE operator_notices SET kind = 'something_else' WHERE id = ?", (n_bob,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE operator_notices SET email_state = 'maybe' WHERE id = ?", (n_bob,))
    with pytest.raises(sqlite3.IntegrityError):              # no such operator
        _notice(conn, 99, "r-2")
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    # ---- rollback --------------------------------------------------------
    apply_migration(conn, rollback, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 34
    tables = _tables(conn)
    assert "operator_notices" not in tables and "operator_notices_rolled_back_035" in tables
    kept = conn.execute(
        "SELECT id, recipient_id, kind, change_request_id, email_state "
        "FROM operator_notices_rolled_back_035 ORDER BY id").fetchall()
    assert [tuple(r) for r in kept] == [
        (n_bob, 2, "single_attested_merge", 1, "sent"),
        (n_carol, 3, "single_attested_merge", 1, "pending"),
    ]
    # The change record itself is untouched (034's columns and all).
    assert tuple(conn.execute(
        "SELECT approval_mode, subject_confirmation FROM tenant_change_requests").fetchone()) == (
        "single_attested", "acme-dup")
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []

    # ---- forward again ---------------------------------------------------
    apply_migration(conn, forward, target="registry")
    assert conn.execute("SELECT COUNT(*) FROM operator_notices").fetchone()[0] == 0
    _notice(conn, 2)
    conn.commit()
    # A second rollback appends to the preserved copy.
    apply_migration(conn, rollback, target="registry")
    assert conn.execute(
        "SELECT COUNT(*) FROM operator_notices_rolled_back_035").fetchone()[0] == 3
    conn.close()


def test_a_deleted_operator_takes_their_notices_with_them(tmp_path):
    """Migration 031 hard-deletes a never-used account; a notice addressed to
    it must not block that (it cascades), and the change record stays."""
    conn = _build_v34(tmp_path / "registry.db")
    _seed(conn)
    apply_migration(conn, _migration(35), target="registry")
    _notice(conn, 3)
    conn.commit()
    conn.execute("DELETE FROM operators WHERE id = 3")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM operator_notices").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM tenant_change_requests").fetchone()[0] == 1
    conn.close()
