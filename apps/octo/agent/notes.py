"""Shared agent_notes writer — used by BOTH the operator path
(`api/routers/agent_query.py`) and the autonomous worker (`agent/worker.py`).

Single source of truth for: lazy-applying the per-tenant agent_notes
columns that the runtime adds outside the migration runner
(`query_kind` from migration 028, `disposition` from migration 029), and
the INSERT itself. Keeping one writer means the two callers can't drift.

Per-tenant DBs don't auto-migrate at runtime, so the columns are applied
lazily + idempotently on first write (the same pattern migration 028
established for `query_kind`).
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.db import connect


# Per-tenant agent-layer schema (migration 011, @target: events). Inlined
# here so the agent SELF-HEALS its schema on any tenant — including ones
# provisioned BEFORE migration 011, which lack these tables entirely
# (discovered on prod 2026-06-02: the worker silently failed to write
# because the table didn't exist; the column-only ensure no-op'd). Keep in
# sync with apps/octo/migrations/011-agent-notes.sql (the source of truth).
_AGENT_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS agent_notes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_kind           TEXT NOT NULL CHECK (ref_kind IN ('event','ticket','indicator')),
    ref_id             INTEGER NOT NULL,
    agent_id           TEXT NOT NULL CHECK (agent_id IN ('octo','athena')),
    note_text          TEXT NOT NULL,
    confidence         REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT,
    audit_request_id   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_notes_ref ON agent_notes(ref_kind, ref_id);
CREATE INDEX IF NOT EXISTS idx_agent_notes_agent_created ON agent_notes(agent_id, created_at);
CREATE TABLE IF NOT EXISTS agent_pattern_links (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    from_kind          TEXT NOT NULL CHECK (from_kind IN ('event','ticket','indicator')),
    from_id            INTEGER NOT NULL,
    to_kind            TEXT NOT NULL CHECK (to_kind IN ('event','ticket','indicator')),
    to_id              INTEGER NOT NULL,
    relation           TEXT NOT NULL CHECK (relation IN ('same_ioc','same_host','same_ttp','temporal','semantic')),
    strength           REAL NOT NULL CHECK (strength >= 0.0 AND strength <= 1.0),
    rationale          TEXT NOT NULL,
    created_by_agent   TEXT NOT NULL CHECK (created_by_agent IN ('octo','athena')),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_pattern_links_from ON agent_pattern_links(from_kind, from_id);
CREATE INDEX IF NOT EXISTS idx_pattern_links_to ON agent_pattern_links(to_kind, to_id);
CREATE INDEX IF NOT EXISTS idx_pattern_links_relation_created ON agent_pattern_links(relation, created_at);
CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_update
    BEFORE UPDATE ON agent_pattern_links
    BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;
CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_delete
    BEFORE DELETE ON agent_pattern_links
    BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;
"""


def ensure_agent_schema(conn: sqlite3.Connection) -> None:
    """Idempotently ensure the per-tenant agent layer exists: the
    agent_notes + agent_pattern_links tables (migration 011) AND the later
    additive columns (query_kind/028, disposition/029).

    Creates the tables if missing (self-heals pre-011 tenants) then adds
    the columns. All IF-NOT-EXISTS / caught — safe to call on every write.
    """
    conn.executescript(_AGENT_SCHEMA_DDL)
    conn.commit()

    cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_notes)").fetchall()}

    if "query_kind" not in cols:
        try:
            conn.execute("ALTER TABLE agent_notes ADD COLUMN query_kind TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_notes_query_kind "
                "ON agent_notes(query_kind) WHERE query_kind IS NOT NULL"
            )
            conn.commit()
        except sqlite3.OperationalError:
            pass

    if "disposition" not in cols:
        try:
            conn.execute("ALTER TABLE agent_notes ADD COLUMN disposition TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_notes_disposition "
                "ON agent_notes(disposition) WHERE disposition IS NOT NULL"
            )
            conn.commit()
        except sqlite3.OperationalError:
            pass


# Back-compat: old name still used by some call sites; now creates the full
# schema, not just columns.
ensure_agent_notes_columns = ensure_agent_schema


def insert_agent_note_row(
    conn: sqlite3.Connection,
    *,
    ref_kind: str,
    ref_id: int,
    agent_id: str,
    note_text: str,
    confidence: float,
    request_id: str,
    query_kind: Optional[str] = None,
    disposition: Optional[str] = None,
) -> sqlite3.Row:
    """Insert one agent_note on an ALREADY-OPEN connection and return the
    new row. Does not open/close or commit — the caller owns the
    connection and transaction. This is the batch-friendly primitive the
    worker uses to write a whole batch on one connection in one
    transaction (the per-call `insert_agent_note` wrapper is for the
    operator single-shot path).

    The caller must have run `ensure_agent_notes_columns(conn)` first.
    """
    cur = conn.execute(
        "INSERT INTO agent_notes "
        "(ref_kind, ref_id, agent_id, note_text, confidence, "
        " audit_request_id, query_kind, disposition) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ref_kind, ref_id, agent_id, note_text, confidence,
         request_id, query_kind, disposition),
    )
    return conn.execute(
        "SELECT id, agent_id, note_text, confidence, created_at, "
        "       updated_at, query_kind, disposition "
        "FROM agent_notes WHERE id = ?",
        (cur.lastrowid,),
    ).fetchone()


def insert_agent_note(
    client_slug: str,
    *,
    ref_kind: str,
    ref_id: int,
    agent_id: str,
    note_text: str,
    confidence: float,
    request_id: str,
    query_kind: Optional[str] = None,
    disposition: Optional[str] = None,
) -> sqlite3.Row:
    """Single-shot append for the operator path: open the tenant's
    events.db, ensure columns, insert one note, return the row.

    `disposition` is set only by the autonomous triage path; the operator
    enrichment path leaves it None.

    Raises APIError NOT_FOUND if the tenant's events.db doesn't exist
    (a misconfigured request, not a transient failure).
    """
    edb = paths.client_dir(client_slug) / "events.db"
    if not edb.exists():
        raise APIError("NOT_FOUND", f"no events db for tenant {client_slug!r}")
    conn = connect(edb)
    try:
        ensure_agent_notes_columns(conn)
        try:
            return insert_agent_note_row(
                conn,
                ref_kind=ref_kind, ref_id=ref_id, agent_id=agent_id,
                note_text=note_text, confidence=confidence,
                request_id=request_id, query_kind=query_kind,
                disposition=disposition,
            )
        except sqlite3.OperationalError as exc:
            raise APIError(
                "PRECONDITION_FAILED",
                f"agent_notes table missing for {client_slug!r}: {exc}",
            )
    finally:
        conn.close()
