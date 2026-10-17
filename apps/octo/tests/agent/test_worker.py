"""Integration tests for the autonomous triage worker (Task #119b).

Exercises process_tenant_once against a real per-tenant events.db built by
the shared migration helper, covering disposition writes, watermark
advance/resume, idempotency, batching, and cross-tenant isolation.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from apps.octo.agent import triage_state
from apps.octo.agent.heuristic_l1 import RECUR_PATTERN_THRESHOLD
from apps.octo.agent.worker import process_tenant_once
from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _register_client,
)


def _insert_event(
    client_dir: Path, *, severity: str = "info", source: str = "test-source",
    source_host: str = "host-1", event_type: str = "test.event",
    payload: str = "{}",
) -> None:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary) "
            "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, ?, ?, ?, ?, '')",
            (source, source_host, event_type, severity, payload, "a" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def _notes(client_dir: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(client_dir / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT ref_id, agent_id, note_text, confidence, query_kind, "
            "       disposition FROM agent_notes ORDER BY ref_id"
        ).fetchall()
    finally:
        conn.close()


def _note_count(client_dir: Path) -> int:
    """Row count without referencing the lazily-added columns — safe to
    call on a tenant the worker has never touched."""
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM agent_notes").fetchone()[0]
    finally:
        conn.close()


def test_worker_writes_disposition_notes(triage_data_root):
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event(cdir, severity="critical")        # → escalate
    _insert_event(cdir, severity="info")            # below floor → SKIPPED (no note)
    _insert_event(cdir, severity="medium")          # single medium → uncertain

    result = process_tenant_once("acme", backfill=True)

    assert result.processed == 3            # all 3 examined
    assert result.last_event_id == 3        # watermark past the whole batch
    notes = _notes(cdir)
    # Only medium+ get notes; the info event is skipped (the floor).
    assert [n["disposition"] for n in notes] == ["escalate", "uncertain"]
    for n in notes:
        assert n["agent_id"] == "octo"
        assert n["query_kind"] == "auto_enrich"
        assert n["note_text"].startswith(f"[{n['disposition']}]")


def test_worker_skips_below_severity_floor(triage_data_root):
    # info/low are noise → skipped (no note); medium+ triaged. Watermark
    # still advances past the skipped events so they're never re-read.
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    for sev in ("info", "low", "medium", "high"):
        _insert_event(cdir, severity=sev)

    result = process_tenant_once("acme", backfill=True)

    assert result.processed == 4            # examined all 4
    assert result.last_event_id == 4        # watermark advanced past skipped too
    notes = _notes(cdir)
    assert len(notes) == 2                  # only medium + high noted
    assert {n["disposition"] for n in notes} == {"uncertain", "escalate"}
    # the skipped low-sev events leave no note behind
    assert _note_count(cdir) == 2


def test_ensure_agent_schema_creates_missing_tables(tmp_path):
    # Self-heal: a tenant events.db that predates migration 011 (no
    # agent_notes table) must get the full schema, not silently no-op.
    import sqlite3 as _sql
    from apps.octo.agent.notes import ensure_agent_schema
    db = tmp_path / "events.db"
    conn = _sql.connect(db)
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name='agent_notes'").fetchone() is None
    ensure_agent_schema(conn)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"agent_notes", "agent_pattern_links"} <= names
    cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_notes)")}
    assert {"query_kind", "disposition"} <= cols
    ensure_agent_schema(conn)  # idempotent — second call is a no-op, no error
    conn.close()


def test_worker_is_idempotent(triage_data_root):
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event(cdir, severity="critical")

    first = process_tenant_once("acme", backfill=True)
    assert first.processed == 1
    second = process_tenant_once("acme")
    assert second.processed == 0
    assert len(_notes(cdir)) == 1  # no duplicate note on the same event


def test_worker_resumes_from_watermark(triage_data_root):
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event(cdir, severity="info")
    process_tenant_once("acme", backfill=True)
    # New event arrives after the first pass.
    _insert_event(cdir, severity="high")
    result = process_tenant_once("acme")
    assert result.processed == 1
    assert result.last_event_id == 2
    assert _notes(cdir)[-1]["disposition"] == "escalate"


def test_worker_respects_batch_size(triage_data_root):
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    for _ in range(5):
        _insert_event(cdir, severity="info")

    r1 = process_tenant_once("acme", batch_size=2, backfill=True)
    assert r1.processed == 2 and r1.last_event_id == 2
    r2 = process_tenant_once("acme", batch_size=2)
    assert r2.processed == 2 and r2.last_event_id == 4
    r3 = process_tenant_once("acme", batch_size=2)
    assert r3.processed == 1 and r3.last_event_id == 5


def test_recurring_medium_becomes_pattern(triage_data_root):
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    # Same host + event_type repeated; once recurrence reaches the pattern
    # threshold, the later events flip from uncertain → pattern.
    for _ in range(RECUR_PATTERN_THRESHOLD + 1):
        _insert_event(cdir, severity="medium", source_host="h", event_type="t")

    process_tenant_once("acme", backfill=True)
    dispositions = [n["disposition"] for n in _notes(cdir)]
    # The last event (with >= threshold priors) must be a recognized pattern.
    assert dispositions[-1] == "pattern"
    # The first one (no priors) is uncertain.
    assert dispositions[0] == "uncertain"


def test_cross_tenant_isolation(triage_data_root):
    _register_client("acme")
    _register_client("globex")
    acme = triage_data_root / "clients" / "acme"
    globex = triage_data_root / "clients" / "globex"
    _apply_events_db_migration(acme)
    _apply_events_db_migration(globex)
    _insert_event(acme, severity="critical")
    _insert_event(globex, severity="critical")

    process_tenant_once("acme", backfill=True)  # only acme

    assert _note_count(acme) == 1
    assert _note_count(globex) == 0  # globex untouched (pristine — no lazy cols)

    # globex watermark never advanced
    gconn = sqlite3.connect(globex / "events.db")
    gconn.row_factory = sqlite3.Row
    try:
        assert triage_state.get_watermark(gconn) == 0
    finally:
        gconn.close()


def test_missing_events_db_is_noop(triage_data_root):
    # Registered but never provisioned events.db → graceful no-op.
    _register_client("ghost")
    result = process_tenant_once("ghost")
    assert result.processed == 0


def test_skip_backlog_is_default(triage_data_root):
    # Default (no backfill): first run must NOT triage the existing backlog
    # — it sets the watermark to current max and processes nothing.
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    for _ in range(3):
        _insert_event(cdir, severity="critical")  # would be 3 escalations if backfilled

    first = process_tenant_once("acme")  # default: skip backlog
    assert first.processed == 0
    assert first.last_event_id == 3      # watermark jumped to max
    assert _note_count(cdir) == 0        # nothing triaged

    # A NEW event arriving after enable IS triaged.
    _insert_event(cdir, severity="critical")
    second = process_tenant_once("acme")
    assert second.processed == 1
    assert _notes(cdir)[-1]["disposition"] == "escalate"


def test_worker_puts_events_db_in_wal(triage_data_root):
    # The worker must flip events.db to WAL so it coexists with live ingest
    # (rollback-journal is the lock-contention we hit on the dev fleet).
    _register_client("acme")
    cdir = triage_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event(cdir, severity="info")

    process_tenant_once("acme", backfill=True)

    conn = sqlite3.connect(cdir / "events.db")
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"


def test_ensure_wal_helper(tmp_path):
    from apps.octo.db import ensure_wal
    db = tmp_path / "t.db"
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"
        assert ensure_wal(conn) is True
        # Persistent: a fresh connection sees WAL too.
    finally:
        conn.close()
    conn2 = sqlite3.connect(db)
    try:
        assert conn2.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn2.close()


def test_worker_status_shape_when_not_running():
    from apps.octo.agent.worker import AutonomousTriageWorker
    w = AutonomousTriageWorker(interval_seconds=15)
    s = w.status()
    # Never started → loop not alive → offline, and the coarse state
    # collapses to 'error' (constructed-but-not-running).
    assert s["online"] is False
    assert s["state"] == "error"
    assert s["interval_seconds"] == 15
    assert set(s) >= {
        "state", "online", "last_tick_at", "last_run",
        "last_error", "consecutive_errors", "interval_seconds",
        "calibration_state",
    }
    assert s["calibration_state"] == "uncalibrated"
