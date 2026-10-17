"""Migration 033 on a registry that already holds tenants: existing rows
become 'pending' (none is classified), origin is 'bootstrap' only for rows
onboarded alongside the first operator, everything else 'manual'; AI policy
is 'none' for all; the rollback restores the 032 shape and the quarantine
target builds its own DB.

033 is no longer the newest registry migration (034 — v0.10 — builds on
it), so these tests apply exactly 033 on a v32 registry rather than "every
pending migration": what they pin is 033's own behaviour."""
from __future__ import annotations

import sqlite3

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations


def _build_v32(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 33:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 32
    return conn


def _apply_033(conn: sqlite3.Connection) -> None:
    forward = next(m for m in list_migrations() if m.number == 33)
    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 33


def test_existing_rows_are_pending_and_origin_is_inferred(tmp_path):
    conn = _build_v32(tmp_path / "registry.db")
    conn.execute(
        "INSERT INTO operators (username, email, token_hash, token_prefix, created_at) "
        "VALUES ('factory', 'factory@example.test', 'h', 'p', '2026-09-19T10:00:00.000Z')",
    )
    rows = [
        ("boot-one", "2026-09-19T10:00:30.000Z"),   # minted by the same bootstrap run
        ("boot-two", "2026-09-19T10:40:00.000Z"),   # within the hour
        ("typed-one", "2026-09-21T15:00:00.000Z"),  # typed by hand two days later
    ]
    for slug, when in rows:
        conn.execute(
            "INSERT INTO clients (slug, display_name, onboarded_at) VALUES (?, ?, ?)",
            (slug, slug, when),
        )
    conn.commit()

    _apply_033(conn)
    got = {
        r[0]: tuple(r)[1:] for r in conn.execute(
            "SELECT slug, origin, kind, review_state, ai_policy, created_by_instance_id "
            "FROM clients",
        )
    }
    assert got["boot-one"] == ("bootstrap", "unclassified", "pending", "none", None)
    assert got["boot-two"] == ("bootstrap", "unclassified", "pending", "none", None)
    assert got["typed-one"] == ("manual", "unclassified", "pending", "none", None)
    # New rows take 033's defaults: manual, unclassified, CONFIRMED (the admin
    # API decides pending/confirmed explicitly), no AI. (Migration 034 then
    # moves such rows back to pending and refuses the combination.)
    conn.execute("INSERT INTO clients (slug, display_name) VALUES ('fresh', 'Fresh')")
    assert tuple(conn.execute(
        "SELECT origin, kind, review_state, ai_policy FROM clients WHERE slug = 'fresh'",
    ).fetchone()) == ("manual", "unclassified", "confirmed", "none")
    # The request table exists and enforces its vocabularies.
    conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, requested_by, reason, request_id) "
        "VALUES ('offboard', 'typed-one', 1, 'bye', 'r-1')",
    )
    try:
        conn.execute(
            "INSERT INTO tenant_change_requests (kind, subject_slug, requested_by, reason, request_id) "
            "VALUES ('delete', 'typed-one', 1, 'bye', 'r-2')",
        )
        raise AssertionError("CHECK on kind not enforced")
    except sqlite3.IntegrityError:
        pass
    conn.close()


def test_no_operators_means_nothing_is_tagged_bootstrap(tmp_path):
    conn = _build_v32(tmp_path / "registry.db")
    conn.execute("INSERT INTO clients (slug, display_name) VALUES ('acme-corp', 'Acme')")
    conn.commit()
    _apply_033(conn)
    assert tuple(conn.execute("SELECT origin, review_state FROM clients").fetchone()) == ("manual", "pending")
    conn.close()


def test_rollback_restores_the_032_shape_and_preserves_what_a_human_has_not_decided(tmp_path):
    """A downgrade must not destroy evidence: in-flight change requests and
    held quarantine payloads (the only copies, for webhook-only vendors)
    are kept under `*_rolled_back_033`; auto-created clients survive as
    ordinary rows. Re-applying 033 starts fresh next to the preserved copy."""
    conn = _build_v32(tmp_path / "registry.db")
    before = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    _apply_033(conn)
    conn.execute(
        "INSERT INTO clients (slug, display_name, origin, review_state) "
        "VALUES ('auto-co', 'Auto Co', 'auto', 'pending')",
    )
    conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, requested_by, reason, request_id) "
        "VALUES ('offboard', 'auto-co', 1, 'bye', 'r-1')",
    )
    conn.commit()
    rollback = next(m for m in list_migrations(kind="rollback") if m.number == 33)
    apply_migration(conn, rollback, target="registry")
    assert {r[1] for r in conn.execute("PRAGMA table_info(clients)")} == before
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 32
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "tenant_change_requests" not in tables
    assert "tenant_change_requests_rolled_back_033" in tables
    assert [tuple(r) for r in conn.execute(
        "SELECT kind, subject_slug, state FROM tenant_change_requests_rolled_back_033",
    )] == [("offboard", "auto-co", "pending")]
    assert [tuple(r) for r in conn.execute("SELECT slug FROM clients")] == [("auto-co",)]
    # Forward again: a fresh, empty request table; the preserved copy stays.
    _apply_033(conn)
    assert conn.execute("SELECT COUNT(*) FROM tenant_change_requests").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM tenant_change_requests_rolled_back_033").fetchone()[0] == 1
    conn.close()

    forward = next(m for m in list_migrations() if m.number == 33)
    q = sqlite3.connect(tmp_path / "quarantine.db")
    apply_migration(q, forward, target="quarantine")
    q.execute(
        "INSERT INTO quarantine (adapter_instance_id, vendor_slug, source, reason, payload, "
        "payload_sha256) VALUES (1, 'datto', 'webhook', 'name-unknown', '{}', 'abc')",
    )
    q.commit()
    apply_migration(q, rollback, target="quarantine")
    tables = {r[0] for r in q.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "quarantine" not in tables and "quarantine_rolled_back_033" in tables
    assert q.execute("SELECT reason, payload FROM quarantine_rolled_back_033").fetchall() == [
        ("name-unknown", "{}")]
    assert q.execute("PRAGMA user_version").fetchone()[0] == 0
    # A second rollback later appends to the same preserved table.
    apply_migration(q, forward, target="quarantine")
    q.execute(
        "INSERT INTO quarantine (adapter_instance_id, vendor_slug, source, reason, payload, "
        "payload_sha256) VALUES (1, 'datto', 'webhook', 'no-tenant-id', '{}', 'def')",
    )
    q.commit()
    apply_migration(q, rollback, target="quarantine")
    assert q.execute("SELECT COUNT(*) FROM quarantine_rolled_back_033").fetchone()[0] == 2
    q.close()


def test_quarantine_target_is_its_own_db_and_never_touches_the_registry(tmp_path):
    forward = next(m for m in list_migrations() if m.number == 33)
    q = sqlite3.connect(tmp_path / "quarantine.db")
    apply_migration(q, forward, target="quarantine")
    tables = {r[0] for r in q.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "quarantine" in tables and "clients" not in tables
    assert q.execute("PRAGMA user_version").fetchone()[0] == 33
    q.close()
    reg = _build_v32(tmp_path / "registry.db")
    _apply_033(reg)
    tables = {r[0] for r in reg.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "quarantine" not in tables
    reg.close()
