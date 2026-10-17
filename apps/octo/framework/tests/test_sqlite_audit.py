"""Tests for SQLite-backed AuditLogBackend with hash chain.

Covers AuditLogBackend Protocol parity with InMemoryAuditLogBackend,
chain semantics (GENESIS root, prev_hash linkage, tamper detection),
durability across reopens, and integration with BridgeServerImpl.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from shared_bridge import (
    AuditLogEntry,
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
)

from apps.octo.framework.bridge_server import BridgeServerImpl
from apps.octo.framework.sqlite_audit import (
    GENESIS_PREV_HASH,
    SCHEMA_VERSION,
    SqliteAuditLogBackend,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(
    *,
    template_id: str = "recent_findings",
    operator_id: int = 10,
    operator_role: str = "viewer",
    session_id: str = "sess-1",
    tenant: str = "client_a",
    accepted: bool = True,
    rejection_reason: str | None = None,
    rows: int = 1,
    timestamp: str = "2026-05-04T15:00:00.000Z",
) -> AuditLogEntry:
    return AuditLogEntry(
        timestamp=timestamp,
        operator_id=operator_id,
        operator_role=operator_role,
        session_id=session_id,
        session_tenant=tenant,
        template_id=template_id,
        params_hash="a" * 64,
        result_row_count=rows,
        elapsed_ms=1.0,
        accepted=accepted,
        rejection_reason=rejection_reason,
        cross_tenant_access=False,
        extra={"k": "v"},
    )


# ---------------------------------------------------------------------------
# CRUD parity
# ---------------------------------------------------------------------------

def test_append_returns_first_id_as_one(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    audit_id = backend.append(_entry())
    assert audit_id == 1
    backend.close()


def test_append_increments_ids(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    ids = [backend.append(_entry(template_id=f"t{i}")) for i in range(5)]
    assert ids == [1, 2, 3, 4, 5]
    backend.close()


def test_query_no_filter_returns_all(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    for i in range(3):
        backend.append(_entry(template_id=f"t{i}"))
    results = backend.query()
    assert len(results) == 3
    backend.close()


def test_query_filter_by_session(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(session_id="sess-a"))
    backend.append(_entry(session_id="sess-b"))
    backend.append(_entry(session_id="sess-a"))
    results = backend.query(session_id="sess-a")
    assert len(results) == 2
    assert all(r.session_id == "sess-a" for r in results)
    backend.close()


def test_query_filter_by_operator(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(operator_id=10))
    backend.append(_entry(operator_id=20))
    results = backend.query(operator_id=10)
    assert len(results) == 1
    backend.close()


def test_query_filter_by_tenant(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(tenant="client_a"))
    backend.append(_entry(tenant="client_b"))
    results = backend.query(tenant="client_b")
    assert len(results) == 1
    assert results[0].session_tenant == "client_b"
    backend.close()


def test_query_filter_by_since(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(timestamp="2026-05-04T14:00:00.000Z"))
    backend.append(_entry(timestamp="2026-05-04T15:00:00.000Z"))
    backend.append(_entry(timestamp="2026-05-04T16:00:00.000Z"))
    results = backend.query(since="2026-05-04T15:00:00.000Z")
    assert len(results) == 2
    backend.close()


def test_query_limit(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    for _ in range(10):
        backend.append(_entry())
    results = backend.query(limit=3)
    assert len(results) == 3
    backend.close()


# ---------------------------------------------------------------------------
# Round-trip + nullable rejection_reason
# ---------------------------------------------------------------------------

def test_rejection_reason_round_trips(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(accepted=False, rejection_reason="role_below_min"))
    results = backend.query()
    assert results[0].accepted is False
    assert results[0].rejection_reason == "role_below_min"
    backend.close()


def test_extra_dict_round_trips(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    entry = AuditLogEntry(
        timestamp="2026-05-04T15:00:00.000Z",
        operator_id=10,
        operator_role="viewer",
        session_id="sess-1",
        session_tenant="client_a",
        template_id="t",
        params_hash="b" * 64,
        result_row_count=0,
        elapsed_ms=0.0,
        accepted=True,
        rejection_reason=None,
        cross_tenant_access=True,
        extra={"correlation_id": "abc-123", "source": "wizard"},
    )
    backend.append(entry)
    results = backend.query()
    assert results[0].extra == {"correlation_id": "abc-123", "source": "wizard"}
    assert results[0].cross_tenant_access is True
    backend.close()


# ---------------------------------------------------------------------------
# Hash chain semantics
# ---------------------------------------------------------------------------

def test_first_row_prev_hash_is_genesis(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry())
    import sqlite3
    conn = sqlite3.connect(tmp_path / "audit.db")
    try:
        row = conn.execute(
            "SELECT prev_hash FROM bridge_audit_log WHERE audit_entry_id = 1"
        ).fetchone()
        assert row[0] == GENESIS_PREV_HASH
    finally:
        conn.close()
        backend.close()


def test_subsequent_prev_hash_links_to_previous_row_hash(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(template_id="t1"))
    backend.append(_entry(template_id="t2"))
    import sqlite3
    conn = sqlite3.connect(tmp_path / "audit.db")
    try:
        row1 = conn.execute(
            "SELECT row_hash FROM bridge_audit_log WHERE audit_entry_id = 1"
        ).fetchone()
        row2 = conn.execute(
            "SELECT prev_hash FROM bridge_audit_log WHERE audit_entry_id = 2"
        ).fetchone()
        assert row1[0] == row2[0]
    finally:
        conn.close()
        backend.close()


def test_verify_chain_passes_on_clean_log(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    for i in range(10):
        backend.append(_entry(template_id=f"t{i}"))
    assert backend.verify_chain() is True
    backend.close()


def test_verify_chain_passes_on_empty_log(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    assert backend.verify_chain() is True
    backend.close()


def test_verify_chain_detects_row_tampering(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry(template_id="t1"))
    backend.append(_entry(template_id="t2"))
    backend.append(_entry(template_id="t3"))
    backend.close()  # close the backend before tampering

    # Out-of-band tamper: rewrite a column value, leaving row_hash stale
    import sqlite3
    conn = sqlite3.connect(tmp_path / "audit.db")
    try:
        conn.execute(
            "UPDATE bridge_audit_log SET template_id = 'TAMPERED' "
            "WHERE audit_entry_id = 2"
        )
        conn.commit()
    finally:
        conn.close()

    backend2 = SqliteAuditLogBackend(tmp_path / "audit.db")
    assert backend2.verify_chain() is False
    backend2.close()


def test_chain_tip_returns_latest(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    assert backend.chain_tip() is None
    backend.append(_entry(template_id="t1"))
    backend.append(_entry(template_id="t2"))
    tip = backend.chain_tip()
    assert tip is not None
    audit_id, row_hash = tip
    assert audit_id == 2
    assert len(row_hash) == 64  # sha256 hex
    backend.close()


# ---------------------------------------------------------------------------
# Durability
# ---------------------------------------------------------------------------

def test_data_survives_close_and_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    b1 = SqliteAuditLogBackend(db_path)
    b1.append(_entry(template_id="t1"))
    b1.append(_entry(template_id="t2"))
    b1.close()

    b2 = SqliteAuditLogBackend(db_path)
    results = b2.query()
    assert len(results) == 2
    # Chain still verifies after reopen
    assert b2.verify_chain() is True
    b2.close()


def test_chain_continues_correctly_after_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    b1 = SqliteAuditLogBackend(db_path)
    b1.append(_entry(template_id="t1"))
    b1.append(_entry(template_id="t2"))
    b1.close()

    # New process / container — append more
    b2 = SqliteAuditLogBackend(db_path)
    b2.append(_entry(template_id="t3"))
    b2.append(_entry(template_id="t4"))
    assert b2.verify_chain() is True
    # IDs continue from where the prior session left off
    all_results = b2.query()
    assert [r.template_id for r in all_results] == ["t1", "t2", "t3", "t4"]
    b2.close()


def test_schema_version_stamped(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.append(_entry())
    import sqlite3
    conn = sqlite3.connect(tmp_path / "audit.db")
    try:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v == SCHEMA_VERSION
    finally:
        conn.close()
        backend.close()


def test_close_idempotent(tmp_path: Path) -> None:
    backend = SqliteAuditLogBackend(tmp_path / "audit.db")
    backend.close()
    backend.close()


# ---------------------------------------------------------------------------
# Integration: BridgeServerImpl end-to-end with SQLite audit
# ---------------------------------------------------------------------------

class _StubExecutor:
    def execute(self, template, params, session):  # noqa: ARG002
        return [{"id": 1}]


def test_bridge_server_with_sqlite_audit_records_acceptance(tmp_path: Path) -> None:
    template = QueryTemplate(
        template_id="recent_findings",
        description="t",
        parameters={},
        response_schema={"id": "int"},
        requires_tenant_scope=True,
        min_role="viewer",
    )
    reg = TemplateRegistry()
    reg.register(template)

    audit = SqliteAuditLogBackend(tmp_path / "audit.db")
    server = BridgeServerImpl(templates=reg, executor=_StubExecutor(), audit=audit)
    session = SessionContext(
        operator_id=10, operator_role="viewer",
        session_tenant="client_a", session_id="sess-1",
    )
    result = server.execute_template(session, "recent_findings", {})
    assert result.audit_entry_id == 1

    entries = audit.query()
    assert len(entries) == 1
    assert entries[0].accepted is True
    assert audit.verify_chain() is True
    audit.close()


def test_bridge_server_with_sqlite_audit_records_rejection(tmp_path: Path) -> None:
    audit = SqliteAuditLogBackend(tmp_path / "audit.db")
    server = BridgeServerImpl(
        templates=TemplateRegistry(), executor=_StubExecutor(), audit=audit,
    )
    session = SessionContext(
        operator_id=10, operator_role="viewer",
        session_tenant="client_a", session_id="sess-1",
    )
    with pytest.raises(Exception):
        server.execute_template(session, "no_such_template", {})

    entries = audit.query()
    assert len(entries) == 1
    assert entries[0].accepted is False
    # Chain still consistent — rejections are part of the chain
    assert audit.verify_chain() is True
    audit.close()
