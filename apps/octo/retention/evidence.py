"""Evidence windows — what no retention path may delete (Tier Black, 044).

Rick, 2026-10-05: "Ingestion should not stop but if a threat is confirmed
everything from first detection up until the all clear should be treated as
event evidence."

A Red or Black incident IS a confirmed threat (only a rule or a person opens
one). Opening it records an EVIDENCE WINDOW in its tenant's events.db
(`evidence_windows`, migration 044): from the incident's first detection,
open until its all-clear (its close), then ending there — and HELD until an
admin releases it (`apps.octo.threat.windows`). Everything of that tenant
whose time falls inside a held window is evidence. This module is what
every pruning path asks:

  * `held(client_dir)` — the tenant's held windows, read FAIL CLOSED: a store
    that exists but cannot be read raises `WindowsUnavailable` (the caller
    then prunes nothing of the tenant — a window is never ruled out by a read
    that failed). No events.db, or one without the table (a store before
    044): no window. Windows a 044 rollback PARKED (`PARKED`, moved aside
    with their ids, still held) count exactly like live ones until 044 is
    applied to the file again — a re-upgrade that has not reached the tenant
    yet (`apps.octo.threat.store.ensure_schema` is lazy) never lets the
    nightly run or the sweep take what they hold.
  * `RULES` — per (store, table): the SQL that is true when a row lies inside
    window `w`. A row's every timestamp counts — the vendor's (received_at)
    AND the arrival (ingested_at) for an event; an interval (a lease, an
    egress, a first/last-seen pair) when it OVERLAPS the window; an hour or
    a day bucket when the bucket overlaps it. Comparisons are on the
    leading characters (`YYYY-MM-DDTHH:MM:SS`, `…THH`, `YYYY-MM-DD`), so a
    stored value with or without milliseconds — or with an offset suffix —
    compares the same; the window is inclusive at both ends.
  * `guard(...)` / `held_expr(...)` — `NOT EXISTS (…)` / `EXISTS (…)` over the
    windows: against the LIVE table when the rows are in events.db itself
    (evaluated inside the DELETE, under its write lock: a window opened a
    moment ago holds), else against a TEMP copy loaded on the deleting
    connection (`load_temp`), re-read before every batch. The planning-time
    windows are always loaded too: what was planned (and archived, and
    audited) is the most a delete can remove — a window released between
    the plan and the delete never lets more go than was counted.
  * `per_window(...)` — expired rows each window kept (the console's "rows
    kept"; written back to `evidence_windows.kept_rows` by the job).

Nothing here ever slows ingest: ingest never reads a window.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Union

TABLE = "evidence_windows"
# Where a 044 rollback keeps them (ids and all) until a re-upgrade.
PARKED = "evidence_windows_rolled_back_044"
TEMP = "retention_evidence_windows"
# Columns of the window source every rule reads (the live table is
# projected onto these names, the temp copy has them).
_SRC_LIVE = (f"(SELECT id AS ew_id, start_at AS ew_start, end_at AS ew_end FROM main.{TABLE} "
             "WHERE released_at IS NULL)")
_SRC_TEMP = f"temp.{TEMP}"


class WindowsUnavailable(Exception):
    """The tenant's evidence windows could not be read — nothing of it may
    be pruned (a window is never ruled out by a failed read)."""


@dataclass(frozen=True)
class Window:
    id: int
    incident_id: int
    start: str
    end: Optional[str]

    def as_dict(self) -> dict:
        return {"id": self.id, "incident_id": self.incident_id, "start": self.start,
                "end": self.end}


def _has_table(conn: sqlite3.Connection, name: str = TABLE) -> bool:
    return conn.execute("SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?",
                        (name,)).fetchone() is not None


def held_on(conn: sqlite3.Connection) -> list[Window]:
    """The HELD windows of the events.db `conn` is open on: the live table's
    and the parked ones (a 044 rollback's — the latest copy of each id that
    is not live again). Raises sqlite3.Error."""
    out: dict[int, Window] = {}
    if _has_table(conn, PARKED):
        for wid, iid, start, end, released in conn.execute(
                f"SELECT k.id, k.incident_id, k.start_at, k.end_at, k.released_at "
                f"FROM main.{PARKED} k WHERE k.rowid = (SELECT MAX(q.rowid) "
                f"FROM main.{PARKED} q WHERE q.id = k.id)").fetchall():
            if released is None and start:
                out[int(wid)] = Window(int(wid), int(iid), str(start), end)
    if _has_table(conn):
        for wid, iid, start, end, released in conn.execute(
                f"SELECT id, incident_id, start_at, end_at, released_at FROM main.{TABLE}"
                ).fetchall():
            out.pop(int(wid), None)                     # the live row is the record
            if released is None:
                out[int(wid)] = Window(int(wid), int(iid), str(start), end)
    return [out[k] for k in sorted(out)]


def held(client_dir: Path, *, timeout: float = 10.0) -> list[Window]:
    """The tenant's HELD (unreleased) windows — live, or parked by a 044
    rollback (`held_on`). Raises WindowsUnavailable when its events.db
    exists but cannot be read."""
    db = Path(client_dir) / "events.db"
    if not db.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=timeout,
                               isolation_level=None)
        try:
            return held_on(conn)
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise WindowsUnavailable(f"{type(exc).__name__}: {exc}") from exc


def union(*sets: Iterable[Window]) -> list[Window]:
    seen: dict[tuple, Window] = {}
    for s in sets:
        for w in s:
            seen.setdefault((w.id, w.start, w.end), w)
    return list(seen.values())


# ---------------------------------------------------------------------------
# What "inside a window" means, per table
# ---------------------------------------------------------------------------

def at(col: str, n: int = 19) -> str:
    """A point in time `col` inside window w (inclusive)."""
    return (f"({col} IS NOT NULL AND substr({col}, 1, {n}) >= substr(w.ew_start, 1, {n}) "
            f"AND (w.ew_end IS NULL OR substr({col}, 1, {n}) <= substr(w.ew_end, 1, {n})))")


def span(start_col: str, end_col: str, n: int = 19) -> str:
    """The interval [start_col, end_col] (end NULL = still open; start NULL =
    since ever) overlaps window w."""
    return (f"((w.ew_end IS NULL OR {start_col} IS NULL "
            f"  OR substr({start_col}, 1, {n}) <= substr(w.ew_end, 1, {n})) "
            f" AND ({end_col} IS NULL OR substr({end_col}, 1, {n}) >= substr(w.ew_start, 1, {n})))")


def hour(col: str) -> str:
    """An hour bucket ('YYYY-MM-DDTHH…') that overlaps window w."""
    return at(col, 13)


def day(col: str) -> str:
    """A day bucket ('YYYY-MM-DD') that overlaps window w."""
    return at(col, 10)


def _any(*parts: str) -> str:
    return "(" + " OR ".join(parts) + ")"


# (store, table) → the rule, with {t} for the row's table (qualified, so a
# column never resolves to the window source's own).
#
# An events.db stored before 036 whose arrival backfill has not run yet has
# no `ingested_at` column: its events are matched on their vendor time alone
# (`NO_ARRIVAL`, `rule(..., arrival=False)`) — never a "no such column" that
# would stop the very backfill that adds it.
NO_ARRIVAL: dict[tuple[str, str], str] = {
    ("events", "events"): at("{t}.received_at"),
}
RULES: dict[tuple[str, str], str] = {
    # events.db
    ("events", "events"): _any(at("{t}.received_at"), at("{t}.ingested_at")),
    ("events", "agent_notes"): _any(at("{t}.created_at"), at("{t}.updated_at")),
    # indicators.db
    ("indicators", "indicators"): _any(span("{t}.first_seen", "{t}.last_seen"),
                                       at("{t}.promoted_at")),
    # telemetry.db
    ("telemetry", "telemetry_raw"): _any(at("{t}.received_at"), at("{t}.ingested_at")),
    ("telemetry", "telemetry_hourly"): _any(hour("{t}.hour"),
                                            span("{t}.first_seen", "{t}.last_seen"),
                                            at("{t}.last_arrival")),
    ("telemetry", "nextdns_hourly"): _any(hour("{t}.hour"), at("{t}.fetched_at"),
                                          at("{t}.last_arrival")),
    ("telemetry", "nextdns_signal_buckets"): _any(hour("{t}.hour"),
                                                  span("{t}.first_seen", "{t}.last_seen"),
                                                  at("{t}.last_arrival")),
    ("telemetry", "unifi_hourly"): _any(hour("{t}.hour"), at("{t}.last_arrival")),
    ("telemetry", "unifi_signal_buckets"): _any(hour("{t}.hour"),
                                                span("{t}.first_seen", "{t}.last_seen"),
                                                at("{t}.last_arrival")),
    ("telemetry", "unifi_syslog_cursor"): _any(at("{t}.updated_at"), at("{t}.last_arrival")),
    ("telemetry", "first_seen_domains"): span("{t}.first_seen", "{t}.last_seen"),
    # entities.db (migration 040's tables the entity classes prune)
    ("entities", "lk_ip_lease"): span("{t}.valid_from", "{t}.valid_to"),
    ("entities", "lk_join"): at("{t}.at"),
    ("entities", "lk_mac_anomaly"): span("{t}.from_ts", "{t}.to_ts"),
    ("entities", "lk_ip_conflict"): at("{t}.at"),
    ("entities", "lk_uplink"): at("{t}.at"),
    ("entities", "lk_site_egress"): span("{t}.valid_from", "{t}.valid_to"),
    ("entities", "lk_site_subnet"): span("{t}.valid_from", "{t}.valid_to"),
    ("entities", "resolution"): _any(at("{t}.at"), at("{t}.created_at")),
    ("entities", "site_vendor_ref"): _any(span("{t}.valid_from", "{t}.valid_to"),
                                          at("{t}.decided_at")),
    ("entities", "device_link"): _any(span("{t}.valid_from", "{t}.valid_to"),
                                      at("{t}.decided_at")),
    ("entities", "link_suppression"): span("{t}.decided_at", "{t}.expires_at"),
    ("entities", "link_conflict"): _any(span("{t}.first_seen", "{t}.last_seen"),
                                        at("{t}.resolved_at")),
    ("entities", "resolution_run"): span("{t}.started_at", "{t}.finished_at"),
    ("entities", "inv_device"): _any(span("{t}.first_seen_at", "{t}.missing_since"),
                                     at("{t}.last_seen")),
    ("entities", "ndns_device"): span("{t}.first_seen", "{t}.last_seen"),
    ("entities", "ndns_device_hour"): hour("{t}.hour"),
    ("entities", "ndns_presence_hour"): hour("{t}.hour"),
    ("entities", "ndns_ip_day"): day("{t}.day"),
    ("entities", "ndns_device_day"): day("{t}.day"),
    ("entities", "ndns_seed_day"): day("{t}.day"),
}


def rule(store: str, table: str, ref: Optional[str] = None, *, arrival: bool = True) -> str:
    """The rule for a table, its columns qualified by `ref` (default: the
    table's name); `arrival=False`: the table has no arrival column yet
    (`NO_ARRIVAL`). A table without a rule is a programming error: every
    table a retention path deletes from must say what keeps it."""
    try:
        text = ((NO_ARRIVAL.get((store, table)) if not arrival else None)
                or RULES[(store, table)])
    except KeyError:
        raise KeyError(f"no evidence-window rule for {store}.{table}") from None
    return text.replace("{t}", ref or table)


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

def load_temp(conn: sqlite3.Connection, windows: Iterable[Window]) -> None:
    """(Re)fill the connection's temp copy of `windows` — a temp table works
    on a read-only connection too."""
    conn.execute(f"CREATE TEMP TABLE IF NOT EXISTS {TEMP} "
                 "(ew_id INTEGER, ew_start TEXT NOT NULL, ew_end TEXT)")
    conn.execute(f"DELETE FROM temp.{TEMP}")
    conn.executemany(f"INSERT INTO temp.{TEMP} (ew_id, ew_start, ew_end) VALUES (?, ?, ?)",
                     [(w.id, w.start, w.end) for w in windows])


def live(conn: sqlite3.Connection) -> bool:
    """Does this connection's main database hold the windows (events.db)?"""
    return _has_table(conn)


def held_expr(store: str, table: str, *, ref: Optional[str] = None, live_table: bool = False,
              temp: bool = True, arrival: bool = True) -> str:
    """SQL true when the row is inside a held window: the temp copy (the
    planning-time windows plus those re-read before the batch — parked
    ones included) and, on events.db, the LIVE table too."""
    r = rule(store, table, ref, arrival=arrival)
    parts = []
    if temp:
        parts.append(f"EXISTS (SELECT 1 FROM {_SRC_TEMP} w WHERE {r})")
    if live_table:
        parts.append(f"EXISTS (SELECT 1 FROM {_SRC_LIVE} w WHERE {r})")
    return "(" + " OR ".join(parts) + ")" if parts else "0"


def guard(store: str, table: str, **kw) -> str:
    """` AND NOT (inside a held window)` for a DELETE's / count's WHERE."""
    return f" AND NOT {held_expr(store, table, **kw)}"


def per_window(conn: sqlite3.Connection, store: str, table: str, where: str,
               params: Union[Sequence, Mapping], *, ref: Optional[str] = None,
               ) -> dict[int, int]:
    """Rows matching `where` that each window (temp copy) holds: {id: n}.
    `params`: positional (a sequence) or named (a mapping), as `where` binds."""
    r = rule(store, table, ref)
    out: dict[int, int] = {}
    bound = dict(params) if isinstance(params, Mapping) else list(params)
    for wid, n in conn.execute(
            f"SELECT w.ew_id, COUNT(*) FROM {table} JOIN {_SRC_TEMP} w ON {r} "
            f"WHERE {where} GROUP BY w.ew_id", bound):
        if wid is not None:
            out[int(wid)] = out.get(int(wid), 0) + int(n)
    return out


def merge_counts(into: dict[int, int], more: dict[int, int]) -> dict[int, int]:
    for k, v in more.items():
        into[k] = into.get(k, 0) + int(v)
    return into


def record_kept(client_dir: Path, kept: dict[int, int], windows: Iterable[Window], at: str,
                *, timeout: float = 10.0) -> None:
    """Write what the run kept per window (`kept_rows`, `kept_counted_at`) —
    every window held at planning time gets a figure (0 when nothing of it
    had expired yet). Best effort: a window released meanwhile is left as it
    is (released windows are frozen)."""
    ids = sorted({w.id for w in windows})
    if not ids:
        return
    db = Path(client_dir) / "events.db"
    conn = sqlite3.connect(db, timeout=timeout, isolation_level=None)
    try:
        if not _has_table(conn):
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            for wid in ids:
                conn.execute(f"UPDATE {TABLE} SET kept_rows = ?, kept_counted_at = ? "
                             "WHERE id = ? AND released_at IS NULL",
                             (int(kept.get(wid, 0)), at, wid))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
