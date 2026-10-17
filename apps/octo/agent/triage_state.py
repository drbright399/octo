"""Per-tenant autonomous-triage watermark (Task #119b).

The worker triages each tenant's events in `id` order and records how far
it has gotten, so a restart resumes instead of re-triaging. The watermark
lives in the tenant's own events.db (one singleton row), keeping it inside
the per-DB isolation boundary like everything else for that tenant.

Idempotent: the table is created lazily on first access (per-tenant DBs
don't run the migration runner at runtime).
"""

from __future__ import annotations

import sqlite3
from typing import Optional

_ENSURE_SQL = """
CREATE TABLE IF NOT EXISTS agent_triage_state (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    last_triaged_event_id  INTEGER NOT NULL DEFAULT 0,
    updated_at             TEXT
);
"""


def ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(_ENSURE_SQL)
    conn.commit()


def get_watermark(conn: sqlite3.Connection) -> int:
    """Highest event id already triaged for this tenant (0 if none)."""
    ensure_table(conn)
    row = conn.execute(
        "SELECT last_triaged_event_id FROM agent_triage_state WHERE id = 1"
    ).fetchone()
    return int(row["last_triaged_event_id"]) if row else 0


def get_watermark_or_none(conn: sqlite3.Connection) -> Optional[int]:
    """The watermark, or None if this tenant has never been triaged.

    Distinguishes 'first run ever' (None → skip-backlog logic decides where
    to start) from 'triaged up to 0' (an explicit 0)."""
    ensure_table(conn)
    row = conn.execute(
        "SELECT last_triaged_event_id FROM agent_triage_state WHERE id = 1"
    ).fetchone()
    return int(row["last_triaged_event_id"]) if row else None


_UPSERT_SQL = (
    "INSERT INTO agent_triage_state (id, last_triaged_event_id, updated_at) "
    "VALUES (1, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT(id) DO UPDATE SET "
    "  last_triaged_event_id = MAX(last_triaged_event_id, excluded.last_triaged_event_id), "
    "  updated_at = excluded.updated_at"
)


def bump_watermark(conn: sqlite3.Connection, event_id: int) -> None:
    """Advance the watermark WITHOUT committing — for use inside a caller's
    transaction so the watermark moves atomically with the notes it
    accounts for. Monotonic (MAX guard never moves it back)."""
    conn.execute(_UPSERT_SQL, (event_id,))


def set_watermark(conn: sqlite3.Connection, event_id: int) -> None:
    """Advance the watermark and commit (standalone use)."""
    ensure_table(conn)
    conn.execute(_UPSERT_SQL, (event_id,))
    conn.commit()
