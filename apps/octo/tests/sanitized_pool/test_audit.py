"""Tests for sanitized_pool.audit (M4 — dual-write wrapper).

Covers:
  - Happy path: both writes succeed, returns (global_id, tenant_id),
    both chains contain the row.
  - Global write fails: raises PoolAuditError(stage="global"), no
    tenant write performed.
  - Tenant write fails after global success: raises
    PoolAuditError(stage="tenant", compensation_appended=True), and
    the global chain has BOTH the original row AND the compensating
    orphan-marker row.
  - Compensation itself fails (extreme path): raises with
    compensation_appended=False; original error still propagates.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import audit
from apps.octo.db import connect
from apps.octo.sanitized_pool.audit import PoolAuditError, append as pool_append


def _init_audit_db(p: Path) -> None:
    """Create an audit.db with the standard schema."""
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(p)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              TEXT    NOT NULL,
                actor           TEXT    NOT NULL,
                actor_kind      TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                target_kind     TEXT    NOT NULL,
                target_id       TEXT    NOT NULL,
                client_slug     TEXT    NOT NULL,
                before_state    TEXT,
                after_state     TEXT,
                reason          TEXT,
                request_id      TEXT    NOT NULL,
                prev_hash       TEXT    NOT NULL,
                row_hash        TEXT    NOT NULL
            );
        """)
    finally:
        conn.close()


def _entry(action: str = "pool_pattern_added") -> audit.AuditEntry:
    return audit.AuditEntry(
        actor="extractor",
        actor_kind="service",
        action=action,
        target_kind="pattern",
        target_id="42",
        client_slug="acme",
        after_state={"ioc_type": "domain", "ioc_value": "evil.com"},
        reason="test",
        request_id="req-test-1",
    )


def _row_count(p: Path) -> int:
    """Return audit_log row count, or 0 if the table doesn't exist
    (e.g. an uninitialized tenant DB used in the failure-mode tests)."""
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM audit_log",
            ).fetchone()[0]
        except sqlite3.OperationalError:
            return 0
    finally:
        conn.close()


def _chain_actions(p: Path) -> list[str]:
    """Return the action column of every row in order — useful for
    asserting compensation rows landed."""
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        return [r[0] for r in conn.execute(
            "SELECT action FROM audit_log ORDER BY id ASC"
        ).fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_happy_path_both_writes_succeed(tmp_path: Path) -> None:
    global_p = tmp_path / "global.db"
    tenant_p = tmp_path / "tenant.db"
    _init_audit_db(global_p)
    _init_audit_db(tenant_p)

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    try:
        gid, tid = pool_append(global_conn, tenant_conn, _entry())
    finally:
        global_conn.close()
        tenant_conn.close()

    assert gid > 0
    assert tid > 0
    assert _row_count(global_p) == 1
    assert _row_count(tenant_p) == 1
    assert _chain_actions(global_p) == ["pool_pattern_added"]
    assert _chain_actions(tenant_p) == ["pool_pattern_added"]


def test_happy_path_chain_integrity_preserved(tmp_path: Path) -> None:
    """Verify the chain-link math still holds across multiple
    dual-writes (regression guard against a bug where the wrapper
    accidentally writes the same row twice or skips the prev_hash
    chaining)."""
    global_p = tmp_path / "global.db"
    tenant_p = tmp_path / "tenant.db"
    _init_audit_db(global_p)
    _init_audit_db(tenant_p)

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    try:
        for i in range(5):
            pool_append(
                global_conn, tenant_conn,
                _entry(action=f"pool_op_{i}"),
            )
    finally:
        global_conn.close()
        tenant_conn.close()

    # Both chains intact via the existing verifier.
    g = connect(global_p, read_only=True)
    t = connect(tenant_p, read_only=True)
    try:
        ok_g, count_g, err_g = audit.verify(g)
        ok_t, count_t, err_t = audit.verify(t)
    finally:
        g.close()
        t.close()
    assert ok_g, f"global chain broken: {err_g}"
    assert ok_t, f"tenant chain broken: {err_t}"
    assert count_g == count_t == 5


# ---------------------------------------------------------------------------
# Global write fails first
# ---------------------------------------------------------------------------

def test_global_write_failure_aborts_everything(tmp_path: Path) -> None:
    """Global side fails → tenant side is never written → raise."""
    tenant_p = tmp_path / "tenant.db"
    _init_audit_db(tenant_p)
    # No audit_log table on the global side — first audit.append() call
    # will fail with OperationalError.
    global_p = tmp_path / "global.db"
    # Create empty file (not a valid audit DB).
    global_p.touch()

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    try:
        with pytest.raises(PoolAuditError) as exc_info:
            pool_append(global_conn, tenant_conn, _entry())
    finally:
        global_conn.close()
        tenant_conn.close()

    err = exc_info.value
    assert err.stage == "global"
    assert isinstance(err.cause, Exception)
    # Tenant chain stays empty — no orphaned writes there.
    assert _row_count(tenant_p) == 0


# ---------------------------------------------------------------------------
# Tenant write fails after global success — compensation appended
# ---------------------------------------------------------------------------

def test_tenant_write_failure_appends_compensation_to_global(
    tmp_path: Path,
) -> None:
    global_p = tmp_path / "global.db"
    _init_audit_db(global_p)
    # Tenant side intentionally NOT initialized → first write fails.
    tenant_p = tmp_path / "tenant.db"
    tenant_p.touch()  # empty file, no audit_log table

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    try:
        with pytest.raises(PoolAuditError) as exc_info:
            pool_append(global_conn, tenant_conn, _entry())
    finally:
        global_conn.close()
        tenant_conn.close()

    err = exc_info.value
    assert err.stage == "tenant"
    assert err.global_id_orphaned is not None
    assert err.compensation_appended is True

    # Global chain now has 2 rows: the original + the orphan marker.
    actions = _chain_actions(global_p)
    assert actions == ["pool_pattern_added", "pool_audit_tenant_failed"]
    # Global chain integrity is intact.
    g = connect(global_p, read_only=True)
    try:
        ok, count, _ = audit.verify(g)
    finally:
        g.close()
    assert ok
    assert count == 2

    # Tenant chain stays empty.
    assert _row_count(tenant_p) == 0


def test_orphan_marker_carries_global_id_in_after_state(tmp_path: Path) -> None:
    """The compensation row's after_state JSON must include the
    orphaned global id so a reconciliation job can join across."""
    import json

    global_p = tmp_path / "global.db"
    _init_audit_db(global_p)
    tenant_p = tmp_path / "tenant.db"
    tenant_p.touch()

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    try:
        with pytest.raises(PoolAuditError):
            pool_append(global_conn, tenant_conn, _entry())
    finally:
        global_conn.close()
        tenant_conn.close()

    g = connect(global_p, read_only=True)
    try:
        row = g.execute(
            "SELECT after_state FROM audit_log WHERE action = "
            "'pool_audit_tenant_failed'"
        ).fetchone()
    finally:
        g.close()
    payload = json.loads(row["after_state"])
    assert "orphaned_global_id" in payload
    assert payload["orphaned_global_id"] == 1
    assert "tenant_error_type" in payload


# ---------------------------------------------------------------------------
# Compensation itself fails (extreme case)
# ---------------------------------------------------------------------------

def test_compensation_failure_still_raises_with_flag(tmp_path: Path) -> None:
    """If even the compensating write fails (e.g. the global conn is
    closed mid-flight), the wrapper still raises but flags
    compensation_appended=False so callers know the chain may have a
    silent orphan."""
    global_p = tmp_path / "global.db"
    _init_audit_db(global_p)
    tenant_p = tmp_path / "tenant.db"
    tenant_p.touch()  # uninitialized → tenant.append fails

    global_conn = connect(global_p)
    tenant_conn = connect(tenant_p)
    # After the first global write succeeds, close the global conn so
    # the compensation attempt fails too.
    try:
        # Use a custom audit.append spy that closes the global conn
        # AFTER the successful initial write to simulate the
        # compensation-failure path.
        original_append = audit.append
        call_count = {"n": 0}

        def patched_append(conn, entry):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call — the initial global write. Let it through.
                return original_append(conn, entry)
            # Second call — either the tenant write (which fails anyway
            # because tenant_p is uninitialized) or the compensation
            # write. We don't reach compensation in this test path
            # because the tenant call raises first.
            return original_append(conn, entry)

        # Just close the global_conn right before the compensation
        # would fire. We do this by intercepting via a context.
        # Simpler approach: monkeypatch audit.append to fail on the
        # third call (the compensation).
        import apps.octo.sanitized_pool.audit as pool_audit_mod
        original = pool_audit_mod.audit.append

        def failing_third(conn, entry):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return original(conn, entry)  # initial global succeeds
            if call_count["n"] == 2:
                raise sqlite3.OperationalError("simulated tenant failure")
            raise sqlite3.OperationalError("simulated compensation failure")

        pool_audit_mod.audit.append = failing_third
        try:
            with pytest.raises(PoolAuditError) as exc_info:
                pool_append(global_conn, tenant_conn, _entry())
        finally:
            pool_audit_mod.audit.append = original
    finally:
        global_conn.close()
        tenant_conn.close()

    err = exc_info.value
    assert err.stage == "tenant"
    assert err.compensation_appended is False
