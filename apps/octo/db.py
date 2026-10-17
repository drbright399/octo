"""SQLite connection helpers.

Every connection:
  - Uses Row factory (dict-like access).
  - Enables foreign keys.
  - WAL journal mode (set once per file during migration).
  - Parameterized queries only — the rest of the codebase treats raw SQL with
    string concatenation on untrusted values as a bug.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote


def connect(path: Path, read_only: bool = False) -> sqlite3.Connection:
    """Open `path` (a path the caller built through `apps.octo.paths` when
    any part of it came from outside — that is where containment is
    enforced). The path is percent-encoded into the SQLite URI: a raw '?',
    '#' or '%' in it would otherwise be parsed as URI syntax — '?mode=rwc'
    inside a path silently overrode `read_only` and opened another file."""
    if not path.parent.exists():
        raise FileNotFoundError(f"parent directory missing: {path.parent}")
    uri = f"file:{quote(str(path), safe='/')}?mode={'ro' if read_only else 'rwc'}"
    conn = sqlite3.connect(uri, uri=True, isolation_level=None)  # autocommit off via explicit BEGIN
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_wal(conn: sqlite3.Connection) -> bool:
    """Ensure the database is in WAL journal mode.

    WAL is persistent in the DB file header — one successful call sets the
    mode for ALL future connections to that file, not just this one. WAL
    lets many readers and a single writer proceed concurrently instead of a
    writer blocking readers (rollback-journal behavior). This is what lets
    the autonomous triage worker run alongside live ingest without the
    'database is locked' contention we hit in rollback mode.

    MUST be called outside an explicit transaction (PRAGMA journal_mode is a
    no-op mid-transaction). Returns True if the DB is in WAL afterward.
    Idempotent and cheap — safe to call on every connection open.
    """
    try:
        row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    except sqlite3.OperationalError:
        return False
    mode = (row[0] if row else "") or ""
    return mode.lower() == "wal"


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Explicit BEGIN IMMEDIATE / COMMIT / ROLLBACK.

    Audit writes use BEGIN IMMEDIATE themselves (see audit.append). For
    higher-level operations that wrap multiple writes across multiple DBs,
    coordinate at the caller level.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
