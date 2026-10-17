"""Migration 034 (v0.10) on a registry that already holds realistic data:
forward, rollback, forward again — nothing a human recorded is lost, every
foreign key still resolves, and the whole registry section is one
transaction (a refused guard leaves the DB exactly at 033).

Pins:
  - tenant_compliance_signoffs exists, append-only (triggers), one
    unrevoked row per tenant;
  - tenant_change_requests gains approval_mode / attestation /
    subject_confirmation / post-review columns with safe defaults;
  - confirmed + unclassified rows are backfilled to pending, then refused on
    INSERT and UPDATE; every other row, rowid and FK is untouched;
  - clients_history is dropped — and a NON-empty one stops the migration;
  - the rollback keeps sign-offs and the new columns' values under
    *_rolled_back_034 (appending on a second rollback, each row labelled
    with its rollback generation) and recreates an empty clients_history;
  - re-applying 034 restores each change record's v0.10 values from that
    archive (a single-person change never comes back labelled two-person),
    starts the sign-off table empty, and continues its ids after the
    archived ones (no id is ever reused).
"""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations

SHA = "b" * 64
TEXT = "I have checked this tenant's tags today; the BAA on file covers cloud processing."


def _build_v33(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 34:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 33
    return conn


def _apply_034(conn: sqlite3.Connection) -> list[int]:
    """Exactly 034 — later migrations (035 …) are pinned by their own tests,
    and 034's rollback belongs to a registry AT 034."""
    forward = next(m for m in list_migrations() if m.number == 34)
    apply_migration(conn, forward, target="registry")
    return [34]


def _seed(conn: sqlite3.Connection) -> None:
    """What a v0.9 registry looks like: confirmed tenants with a kind, pending
    auto-created ones, a bare-SQL row that took 033's defaults (confirmed +
    unclassified) — one of them offboarded — tokens pointing at them (FK),
    site mappings, and change requests in several states."""
    conn.execute(
        "INSERT INTO operators (username, email, token_hash, token_prefix) "
        "VALUES ('alice', 'alice@example.test', 'h1', 'p1'), ('bob', 'bob@example.test', 'h2', 'p2')",
    )
    rows = [
        # slug, kind, review_state, status, ai_policy, flags
        ("acme-corp", "client", "confirmed", "active", "cloud", '["hipaa"]'),
        ("globex-inc", "client", "confirmed", "active", "local", '["none"]'),
        ("auto-site", "unclassified", "pending", "active", "none", "[]"),
        ("seeded-lab", "unclassified", "confirmed", "active", "none", "[]"),     # bare-SQL defaults
        ("old-co", "unclassified", "confirmed", "offboarded", "none", '["pci"]'),
    ]
    for slug, kind, review, status, policy, flags in rows:
        conn.execute(
            "INSERT INTO clients (slug, display_name, kind, review_state, status, ai_policy, "
            "compliance_flags) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (slug, slug.replace("-", " ").title(), kind, review, status, policy, flags),
        )
    conn.execute(
        "INSERT INTO client_tokens (slug, token_hash, token_prefix, kind, label, created_by) "
        "VALUES ('seeded-lab', 'th1', 'tp1', 'buoy', 'lab buoy', 'alice'), "
        "('acme-corp', 'th2', 'tp2', 'service', 'shim', 'alice')",
    )
    conn.execute(
        "INSERT INTO adapter_instances (vendor_slug, display_name, cred_ref) "
        "VALUES ('datto', 'Datto RMM', 'cred')",
    )
    conn.execute(
        "INSERT INTO adapter_tenant_map (adapter_instance_id, vendor_tenant_id, octo_client_slug, "
        "match_source) VALUES (1, 'site-uid-0001', 'seeded-lab', 'manual')",
    )
    conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, target_slug, requested_by, reason, "
        "state, request_id) VALUES ('merge', 'auto-site', 'acme-corp', 1, 'same customer', "
        "'pending', 'r-1'), ('offboard', 'old-co', NULL, 1, 'contract ended', 'applied', 'r-2')",
    )
    conn.commit()


def _snapshot(conn: sqlite3.Connection) -> dict:
    return {
        "clients": [tuple(r) for r in conn.execute(
            "SELECT rowid, slug, display_name, kind, status, ai_policy, compliance_flags, origin "
            "FROM clients ORDER BY rowid")],
        "tokens": [tuple(r) for r in conn.execute(
            "SELECT id, slug, token_hash, kind FROM client_tokens ORDER BY id")],
        "mappings": [tuple(r) for r in conn.execute(
            "SELECT adapter_instance_id, vendor_tenant_id, octo_client_slug FROM adapter_tenant_map")],
        "requests": [tuple(r) for r in conn.execute(
            "SELECT id, kind, subject_slug, target_slug, state, request_id "
            "FROM tenant_change_requests ORDER BY id")],
    }


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _triggers(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}


def _review(conn: sqlite3.Connection) -> dict[str, str]:
    return {r[0]: r[1] for r in conn.execute("SELECT slug, review_state FROM clients")}


def _insert_signoff(conn, slug: str, flags: str, request_id: str) -> int:
    cur = conn.execute(
        "INSERT INTO tenant_compliance_signoffs (slug, flags_covered, baa_reference, "
        "attestation_text, attestation_sha256, attestation_version, signed_by, expires_at, "
        "request_id) VALUES (?, ?, 'BAA-2026-001', ?, ?, '2026-09-28.v1', 1, "
        "'2099-01-01T00:00:00.000Z', ?)", (slug, flags, TEXT, SHA, request_id),
    )
    return int(cur.lastrowid)


def test_forward_rollback_forward_keeps_every_row_and_foreign_key(tmp_path):
    conn = _build_v33(tmp_path / "registry.db")
    _seed(conn)
    before = _snapshot(conn)

    # ---- forward ---------------------------------------------------------
    assert _apply_034(conn) == [34]
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 34
    assert _snapshot(conn) == before                      # data, rowids, FKs' targets
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    # Backfill: ONLY confirmed + unclassified rows went back to pending.
    assert _review(conn) == {
        "acme-corp": "confirmed", "globex-inc": "confirmed", "auto-site": "pending",
        "seeded-lab": "pending", "old-co": "pending",
    }
    tables = _tables(conn)
    assert "tenant_compliance_signoffs" in tables and "clients_history" not in tables
    # The rollback's archives exist from the start, empty (the re-apply
    # path reads them unconditionally).
    for archive in ("tenant_compliance_signoffs_rolled_back_034",
                    "tenant_change_requests_rolled_back_034"):
        assert conn.execute(f"SELECT COUNT(*) FROM {archive}").fetchone()[0] == 0
    assert {
        "tenant_compliance_signoffs_no_delete", "tenant_compliance_signoffs_revoke_once",
        "clients_confirmed_needs_kind_insert", "clients_confirmed_needs_kind_update",
    } <= _triggers(conn)
    # New change-request columns, with safe defaults on existing rows.
    assert [tuple(r) for r in conn.execute(
        "SELECT approval_mode, attestation, subject_confirmation, post_review_state, "
        "post_reviewed_by FROM tenant_change_requests ORDER BY id")] == [
        ("two_person", None, None, "not_requested", None)] * 2
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE tenant_change_requests SET approval_mode = 'solo' WHERE id = 1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE tenant_change_requests SET post_review_state = 'maybe' WHERE id = 1")
    # The rule holds from now on, on INSERT and on UPDATE.
    with pytest.raises(sqlite3.IntegrityError, match="needs a kind"):
        conn.execute("INSERT INTO clients (slug, display_name) VALUES ('bare-co', 'Bare')")
    with pytest.raises(sqlite3.IntegrityError, match="needs a kind"):
        conn.execute("UPDATE clients SET review_state = 'confirmed' WHERE slug = 'seeded-lab'")
    with pytest.raises(sqlite3.IntegrityError, match="needs a kind"):
        conn.execute("UPDATE clients SET kind = 'unclassified' WHERE slug = 'acme-corp'")
    conn.execute("UPDATE clients SET kind = 'dev', review_state = 'confirmed' WHERE slug = 'seeded-lab'")

    # What v0.10 records on top.
    s1 = _insert_signoff(conn, "acme-corp", '["hipaa"]', "r-s1")
    conn.execute(
        "UPDATE tenant_compliance_signoffs SET revoked_at = '2026-09-28T12:00:00.000Z', "
        "revoked_by = 2, revoked_kind = 'operator', revoke_reason = 'BAA lapsed' WHERE id = ?",
        (s1,),
    )
    s2 = _insert_signoff(conn, "acme-corp", '["hipaa"]', "r-s2")
    conn.execute(
        "UPDATE tenant_change_requests SET approval_mode = 'single_attested', "
        "attestation = 'duplicate created by the integration; same customer', "
        "subject_confirmation = 'auto-site', post_review_state = 'pending' WHERE id = 1",
    )
    conn.commit()

    # ---- rollback --------------------------------------------------------
    rollback = next(m for m in list_migrations(kind="rollback") if m.number == 34)
    apply_migration(conn, rollback, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 33
    tables = _tables(conn)
    assert "tenant_compliance_signoffs" not in tables
    assert {"tenant_compliance_signoffs_rolled_back_034",
            "tenant_change_requests_rolled_back_034", "clients_history"} <= tables
    assert conn.execute("SELECT COUNT(*) FROM clients_history").fetchone()[0] == 0
    assert not {t for t in _triggers(conn) if "compliance" in t or "needs_kind" in t}
    # Sign-offs kept whole — revoked and live alike.
    kept = conn.execute(
        "SELECT id, slug, flags_covered, attestation_text, attestation_sha256, revoked_kind "
        "FROM tenant_compliance_signoffs_rolled_back_034 ORDER BY id").fetchall()
    assert [tuple(r) for r in kept] == [
        (s1, "acme-corp", '["hipaa"]', TEXT, SHA, "operator"),
        (s2, "acme-corp", '["hipaa"]', TEXT, SHA, None),
    ]
    # The change-request columns are gone from the table, their values kept by id.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(tenant_change_requests)")}
    assert not cols & {"approval_mode", "attestation", "subject_confirmation", "post_review_state",
                       "post_reviewed_by", "post_reviewed_at", "post_review_note"}
    assert tuple(conn.execute(
        "SELECT id, request_id, approval_mode, attestation, subject_confirmation, post_review_state "
        "FROM tenant_change_requests_rolled_back_034 WHERE id = 1").fetchone()) == (
        1, "r-1", "single_attested", "duplicate created by the integration; same customer",
        "auto-site", "pending")
    assert conn.execute(
        "SELECT COUNT(*) FROM tenant_change_requests_rolled_back_034").fetchone()[0] == 2
    assert {r[0] for r in conn.execute(
        "SELECT rolled_back_generation FROM tenant_change_requests_rolled_back_034 "
        "UNION SELECT rolled_back_generation FROM tenant_compliance_signoffs_rolled_back_034")} == {1}
    # Every tenant, token, mapping and request survived; FKs resolve.
    after_rollback = _snapshot(conn)
    assert after_rollback["tokens"] == before["tokens"]
    assert after_rollback["mappings"] == before["mappings"]
    assert after_rollback["requests"] == before["requests"]
    assert [c[1] for c in after_rollback["clients"]] == [c[1] for c in before["clients"]]
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    # 033's rules are back: the bare-SQL default is accepted again.
    conn.execute("INSERT INTO clients (slug, display_name) VALUES ('bare-co', 'Bare')")
    conn.commit()

    # ---- forward again ---------------------------------------------------
    assert _apply_034(conn) == [34]
    assert _review(conn)["bare-co"] == "pending"          # backfilled again
    # A fresh, empty sign-off table: no cloud sign-off comes back without a human.
    assert conn.execute("SELECT COUNT(*) FROM tenant_compliance_signoffs").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM tenant_compliance_signoffs_rolled_back_034").fetchone()[0] == 2
    # The single-person change is still one — attestation, typed slug and
    # post-review state restored by id; the two-person one is still that.
    assert [tuple(r) for r in conn.execute(
        "SELECT id, approval_mode, attestation, subject_confirmation, post_review_state "
        "FROM tenant_change_requests ORDER BY id")] == [
        (1, "single_attested", "duplicate created by the integration; same customer",
         "auto-site", "pending"),
        (2, "two_person", None, None, "not_requested")]
    assert "clients_history" not in _tables(conn)
    # A new sign-off never reuses an archived id (nor the audit chain's).
    s3 = _insert_signoff(conn, "globex-inc", '["none"]', "r-s3")
    assert s3 > max(s1, s2)
    conn.commit()
    # A second rollback appends to the preserved copies — as generation 2.
    apply_migration(conn, rollback, target="registry")
    assert conn.execute(
        "SELECT COUNT(*) FROM tenant_compliance_signoffs_rolled_back_034").fetchone()[0] == 3
    assert conn.execute(
        "SELECT COUNT(*) FROM tenant_change_requests_rolled_back_034").fetchone()[0] == 4
    assert [tuple(r) for r in conn.execute(
        "SELECT id, rolled_back_generation, approval_mode FROM "
        "tenant_change_requests_rolled_back_034 WHERE id = 1 ORDER BY rolled_back_generation")] == [
        (1, 1, "single_attested"), (1, 2, "single_attested")]
    assert conn.execute(
        "SELECT rolled_back_generation FROM tenant_compliance_signoffs_rolled_back_034 "
        "WHERE id = ?", (s3,)).fetchone()[0] == 2
    assert all(r[0] for r in conn.execute(
        "SELECT rolled_back_at FROM tenant_change_requests_rolled_back_034"))
    # … and a third apply restores from the LATEST generation.
    assert _apply_034(conn) == [34]
    assert conn.execute(
        "SELECT approval_mode FROM tenant_change_requests WHERE id = 1").fetchone()[0] == (
        "single_attested")
    conn.close()


def test_a_non_empty_clients_history_stops_the_whole_migration(tmp_path):
    """clients_history never held a row; if one ever does, 034 refuses to
    drop it — and, being one transaction, changes NOTHING else either."""
    conn = _build_v33(tmp_path / "registry.db")
    _seed(conn)
    conn.execute(
        "INSERT INTO clients_history (slug, actor, action, request_id, prev_hash, row_hash) "
        "VALUES ('acme-corp', 'alice', 'note', 'r-h', 'p', 'h')",
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="clients_history_must_be_empty"):
        _apply_034(conn)
    conn.close()
    conn = connect(tmp_path / "registry.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 33
        assert conn.execute("SELECT COUNT(*) FROM clients_history").fetchone()[0] == 1
        assert "tenant_compliance_signoffs" not in _tables(conn)
        assert not {t for t in _triggers(conn) if "needs_kind" in t}
        assert _review(conn)["seeded-lab"] == "confirmed"   # backfill rolled back too
        cols = {r[1] for r in conn.execute("PRAGMA table_info(tenant_change_requests)")}
        assert "approval_mode" not in cols
    finally:
        conn.close()
