"""Which events.db rows are EVIDENCE — pointed at by an incident record.

An event a ticket was opened from, that an agent note is about, that a
pattern link or an incident lists, is part of that record. The record is
kept far longer than a signal (tickets and the audit chain: permanently;
agent notes and promoted indicators: six years, HIPAA §164.530(j)), so the
event it cites must outlive the 'events' retention and must never be moved
out of events.db (its id is the citation):

  * the retention job does not delete a referenced event however old it is
    — it is reported as `referenced` (held) instead. A referenced event
    therefore lives as long as its longest-lived referrer: once the last
    note pointing at it ages out (2190 d), the next run prunes it; an event
    a ticket cites is kept for as long as the ticket, i.e. for good;
  * the telemetry move leaves it in events.db.

References, per tenant:

  events.db   agent_notes          ref_kind = 'event', ref_id
              agent_pattern_links  from_kind / to_kind = 'event'
              incidents            event_ids (a JSON array of ids)
              incident_events      event_id (044: an incident's evidence —
                                   trigger, corroboration, context, action)
              incident_signals     event_id (044: an incident's own
                                   `athena.incident` lifecycle events)
  tickets.db  tickets              source_event_id

FAIL CLOSED. A table that does not exist refers to nothing (an older
schema). Anything else — a file that cannot be opened (permissions after a
restore), a damaged one, a busy timeout — raises `ReferencesUnavailable`,
and the caller deletes / moves NOTHING for that tenant: "could not read the
references" must never read as "there are none".

Two ways to use it, both needed:
  * `event_references(client_dir)` — the set of referenced ids, read before
    a delete (planning, the move's per-batch filter);
  * `events_db_guard(conn)` / `referenced_expr(conn)` — SQL for a DELETE
    (or a scan) on events.db that re-checks
    the events.db-resident references INSIDE the delete statement, under
    the write lock, so a note written after the set was read still holds
    its event. tickets.db is another file: its ids are re-read just before
    each delete batch (`ticket_references`). The remaining window — a
    ticket committed between that re-read and the batch's commit — is a few
    milliseconds, and `tickets.create` checks that the event exists first.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Optional


class ReferencesUnavailable(Exception):
    """The reference tables of a tenant could not be read."""


_EVENTS_DB_REFS: tuple[tuple[str, str], ...] = (
    ("agent_notes",
     "SELECT ref_id FROM agent_notes WHERE ref_kind = 'event' AND ref_id IS NOT NULL"),
    ("agent_pattern_links",
     "SELECT from_id FROM agent_pattern_links WHERE from_kind = 'event' "
     "UNION SELECT to_id FROM agent_pattern_links WHERE to_kind = 'event'"),
    ("incidents",
     "SELECT CAST(j.value AS INTEGER) FROM incidents, json_each("
     "  CASE WHEN json_valid(incidents.event_ids) THEN incidents.event_ids ELSE '[]' END) AS j "
     "WHERE j.type IN ('integer', 'text', 'real')"),
    ("incident_events", "SELECT event_id FROM incident_events"),
    ("incident_signals", "SELECT event_id FROM incident_signals"),
)

# Correlated EXISTS (never `IN (list)`: one NULL in a NOT IN list makes the
# predicate NULL for every row). `{t}` = the events table name in the
# statement.
_EVENTS_DB_EXISTS: dict[str, str] = {
    "agent_notes": (
        "EXISTS (SELECT 1 FROM agent_notes n "
        "WHERE n.ref_kind = 'event' AND n.ref_id = {t}.id)"
    ),
    "agent_pattern_links": (
        "EXISTS (SELECT 1 FROM agent_pattern_links l "
        "WHERE (l.from_kind = 'event' AND l.from_id = {t}.id) "
        "   OR (l.to_kind = 'event' AND l.to_id = {t}.id))"
    ),
    "incidents": (
        "EXISTS (SELECT 1 FROM incidents i, json_each("
        "  CASE WHEN json_valid(i.event_ids) THEN i.event_ids ELSE '[]' END) AS j "
        "WHERE j.type IN ('integer', 'text', 'real') AND CAST(j.value AS INTEGER) = {t}.id)"
    ),
    "incident_events": (
        "EXISTS (SELECT 1 FROM incident_events ie WHERE ie.event_id = {t}.id)"
    ),
    "incident_signals": (
        "EXISTS (SELECT 1 FROM incident_signals sg WHERE sg.event_id = {t}.id)"
    ),
}

HELD_TABLE = "retention_held_ids"


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _open_ro(db: Path, timeout: float) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=timeout)
    # Opening is lazy: touch the file now so an unreadable one fails HERE.
    conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
    return conn


def ticket_references(client_dir: Path, *, timeout: float = 10.0,
                      only: Optional[Iterable[int]] = None) -> set[int]:
    """Event ids tickets.db cites (`only`: restricted to those ids).
    No tickets.db / no tickets table = none. Raises ReferencesUnavailable."""
    db = Path(client_dir) / "tickets.db"
    if not db.exists():
        return set()
    try:
        conn = _open_ro(db, timeout)
        try:
            if "tickets" not in _tables(conn):
                return set()
            if only is None:
                return {
                    int(r[0]) for r in conn.execute(
                        "SELECT source_event_id FROM tickets WHERE source_event_id IS NOT NULL")
                }
            ids = sorted({int(i) for i in only})
            out: set[int] = set()
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                out.update(int(r[0]) for r in conn.execute(
                    "SELECT source_event_id FROM tickets WHERE source_event_id IN "
                    f"({','.join('?' * len(chunk))})", chunk))
            return out
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        raise ReferencesUnavailable(f"tickets.db: {type(exc).__name__}: {exc}") from exc


def events_db_references(client_dir: Path, *, timeout: float = 10.0) -> set[int]:
    """Event ids events.db's own reference tables cite. Raises
    ReferencesUnavailable."""
    db = Path(client_dir) / "events.db"
    if not db.exists():
        return set()
    refs: set[int] = set()
    try:
        conn = _open_ro(db, timeout)
        try:
            present = _tables(conn)
            for table, sql in _EVENTS_DB_REFS:
                if table in present:
                    refs.update(int(r[0]) for r in conn.execute(sql) if r[0] is not None)
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        raise ReferencesUnavailable(f"events.db: {type(exc).__name__}: {exc}") from exc
    return refs


def event_references(client_dir: Path, *, timeout: float = 10.0) -> set[int]:
    """Every event id an incident record points at. Raises
    ReferencesUnavailable (fail closed)."""
    return events_db_references(client_dir, timeout=timeout) | ticket_references(
        client_dir, timeout=timeout)


def referenced_expr(conn: sqlite3.Connection, table_ref: str = "events") -> str:
    """A SQL boolean (1 = referenced) for a row of events.db's `events`
    table (named `table_ref` in the statement): events.db's own reference
    tables, plus the connection's temp HELD_TABLE when the caller filled it
    (`load_held` — tickets.db's citations, another file). Evaluated inside
    the statement, so a DELETE re-checks under its own write lock. "0" when
    nothing can refer (an older schema without those tables)."""
    present = _tables(conn)
    parts = [
        sql.format(t=table_ref) for name, sql in _EVENTS_DB_EXISTS.items() if name in present
    ]
    temp = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_temp_master WHERE type = 'table'")}
    if HELD_TABLE in temp:
        parts.append(
            f"EXISTS (SELECT 1 FROM temp.{HELD_TABLE} h WHERE h.id = {table_ref}.id)")
    return "(" + " OR ".join(parts) + ")" if parts else "0"


def events_db_guard(conn: sqlite3.Connection, table_ref: str = "events") -> str:
    """` AND NOT (…)` — exclude every referenced row (see `referenced_expr`)."""
    return f" AND NOT {referenced_expr(conn, table_ref)}"


def load_held(conn: sqlite3.Connection, ids: Iterable[int]) -> None:
    """(Re)fill the connection's temp table of ids that must not be deleted
    (the tickets.db citations — another file, so not joinable in-statement)."""
    conn.execute(f"CREATE TEMP TABLE IF NOT EXISTS {HELD_TABLE} (id INTEGER PRIMARY KEY)")
    conn.execute(f"DELETE FROM temp.{HELD_TABLE}")
    conn.executemany(f"INSERT OR IGNORE INTO temp.{HELD_TABLE} (id) VALUES (?)",
                     ((int(i),) for i in ids))
