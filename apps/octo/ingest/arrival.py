"""Arrival time of a stored signal — `events.ingested_at` (migration 036).

OWNER DECISION (2026-09-29): the retention age of a SIGNAL (a row in a
tenant's events.db) is measured from when Athena RECEIVED and stored it,
never from the vendor's timestamp. `events.received_at` keeps its meaning —
the vendor's time of the event (receive time only when the vendor sent
none) — and is still what is stored, shown, searched and deduplicated on;
`events.ingested_at` is the arrival, stamped by the ingest sink on every row
it writes (`SqliteIngestSink`), and it is what the retention job ages a
signal by. Why: history a vendor hands over late — an incident opened
months ago that RocketCyber lists today, a Datto alert re-listed after an
outage, a sensor with a wrong clock — would otherwise be deleted on the very
next nightly run, or (a timestamp in the future) never.

Rows stored BEFORE 036 have no arrival time (NULL). Their best available
estimate (`Estimator`), in this order:
  1. the stamp a ROLLBACK of 036 kept for that very row
     (`events_arrival_rolled_back_036`: id + payload_sha256 must match) —
     a downgrade and re-upgrade gets back the real arrival, never a guess;
  2. else its stored `received_at` — for a live feed within seconds of the
     arrival; for history imported with an old vendor time earlier than
     the real arrival;
  3. never earlier than the arrival of any row with a LOWER id (the
     "floor"): `events.id` is AUTOINCREMENT, so a row cannot have arrived
     before a row stored ahead of it. Pre-036 history a vendor handed over
     late (a still-open alert with a 14-month-old vendor time, stored three
     weeks ago) therefore gets about the arrival of the live rows around
     it, not its vendor time. The floor only ever moves an estimate LATER
     than (2) — it never prunes more; a vendor clock in the future can
     only lengthen retention (to the stamping time at most);
  4. never earlier than the tenant's onboarding (registry
     `clients.onboarded_at`): no row can have reached a tenant's events.db
     before the tenant existed. This covers the rows at the HEAD of the id
     order, which (3) cannot: a tenant whose first rows were old alerts
     listed oldest-first (a Datto re-list, a shim replay) would otherwise
     be pruned at the first enforcing run although they had just arrived.
     Like (3) it only ever moves an estimate LATER (a merged tenant's rows
     that really arrived earlier are kept longer, never shorter);
  5. never later than the stamping time.
The one-off backfill (`scripts/move_telemetry_out_of_events.py`) stamps
them AFTER it has moved the tenant's telemetry out (`stamp_estimates`, in
id order) — so the rewrite touches signals only, not the ~97 % of rows
that leave. A tenant merge copy estimates the same way (`Estimator`). The
telemetry the move takes out keeps received_at as its estimate (raw
telemetry is near real time; its 7-day clock is the move's business).

Until that has happened the tenant's arrival backfill is PENDING (`pending`):
some row has no arrival time. The retention job then prunes neither the
tenant's signals nor its telemetry and says why (`blocked`); a NULL never
matches the prune's `ingested_at < cutoff` in any case.

Schema: the column is nullable with no default (SQLite cannot ADD a column
whose default is not a constant); the sink always writes it. It is added:
  * for a tenant provisioned from 036 on, by the migration's
    `@target: events` section (with its index);
  * for an older events.db, lazily — by the sink on its first write
    (`add_column`: a schema-only change, instant on any size of table), and
    by the backfill. The INDEX on an older events.db is built by the
    backfill once the telemetry has left (`ensure_index`), or by the
    retention job when the table has nothing left to stamp (so it holds
    only post-036 signals): building it reads the whole table under the
    write lock, which on a pre-move events.db (gigabytes) would stall
    ingest.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from apps.octo.ingest.timestamps import normalize_timestamp

COLUMN = "ingested_at"
INDEX = "idx_events_ingested_at"
TABLE = "events"
DEFAULT_STAMP_BATCH = 2000
# What `036-rollback.sql` keeps of the stamps when it drops the column.
PRESERVED_TABLE = "events_arrival_rolled_back_036"
PRESERVED_INDEX = "idx_events_arrival_rolled_back_036"


def has_column(conn: sqlite3.Connection, table: str = TABLE) -> bool:
    return any(r[1] == COLUMN for r in conn.execute(f"PRAGMA table_info({table})"))


def add_column(conn: sqlite3.Connection) -> bool:
    """Add `events.ingested_at` when it is missing. True = added now. Safe
    against a concurrent adder (the loser's duplicate-column error is taken
    as "present")."""
    if has_column(conn):
        return False
    try:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN {COLUMN} TEXT")
    except sqlite3.OperationalError:
        if has_column(conn):
            return False
        raise
    return True


def has_index(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?", (INDEX,),
    ).fetchone() is not None


def ensure_index(conn: sqlite3.Connection) -> bool:
    """Create the arrival index when missing. True = created now."""
    if has_index(conn):
        return False
    conn.execute(f"CREATE INDEX IF NOT EXISTS {INDEX} ON {TABLE}({COLUMN})")
    return True


def pending(conn: sqlite3.Connection) -> bool:
    """Whether some stored row has no arrival time yet (a pre-036 row the
    backfill has not stamped). Cheap: with the index it is one index probe;
    without it the scan stops at the first NULL — on a pre-036 table the
    oldest row."""
    if not has_column(conn):
        return conn.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone() is not None
    return conn.execute(
        f"SELECT 1 FROM {TABLE} WHERE {COLUMN} IS NULL LIMIT 1"
    ).fetchone() is not None


def count_unstamped(conn: sqlite3.Connection) -> int:
    if not has_column(conn):
        return int(conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0])
    return int(conn.execute(
        f"SELECT COUNT(*) FROM {TABLE} WHERE {COLUMN} IS NULL"
    ).fetchone()[0])


def estimate_expr(conn: sqlite3.Connection, alias: str = "") -> str:
    """SQL for a row's arrival — its stamp, else its received_at (the
    estimate for a pre-036 row)."""
    prefix = f"{alias}." if alias else ""
    if has_column(conn):
        return f"COALESCE({prefix}{COLUMN}, {prefix}received_at)"
    return f"{prefix}received_at"


def has_preserved(conn: sqlite3.Connection) -> bool:
    """Whether a rollback of 036 kept arrival stamps in this events.db."""
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (PRESERVED_TABLE,),
    ).fetchone() is not None


def preserved_stamps(
    conn: sqlite3.Connection, lo: int, hi: int,
) -> dict[int, list[tuple[Optional[str], Optional[str]]]]:
    """event id → [(ingested_at, payload_sha256)] a rollback of 036 kept, for
    ids in [lo, hi] (a second rollback appends: several per id possible).
    A preserved table from before the sha was kept gives sha None."""
    if not has_preserved(conn):
        return {}
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({PRESERVED_TABLE})")}
    sha = "payload_sha256" if "payload_sha256" in cols else "NULL"
    out: dict[int, list[tuple[Optional[str], Optional[str]]]] = {}
    for event_id, stamp, digest in conn.execute(
        f"SELECT event_id, ingested_at, {sha} FROM {PRESERVED_TABLE} "
        "WHERE event_id BETWEEN ? AND ? AND ingested_at IS NOT NULL",
        (int(lo), int(hi)),
    ):
        out.setdefault(int(event_id), []).append((stamp, digest))
    return out


def match_preserved(
    kept: Optional[list[tuple[Optional[str], Optional[str]]]], payload_sha256: Optional[str],
) -> Optional[str]:
    """The kept stamp of THIS row: same id (the caller's key) and same
    payload digest — an events.db restored from an older backup reuses ids
    for other rows, whose kept stamp is not theirs. The newest when several
    (a later stamp only keeps a row longer)."""
    stamps = [
        stamp for stamp, digest in (kept or ())
        if stamp and (digest is None or digest == payload_sha256)
    ]
    return max(stamps) if stamps else None


class Estimator:
    """Arrival estimates for rows WITHOUT a stamp, fed every row IN ID ORDER
    (see the module docstring for the rules). `floor`: the latest arrival of
    the rows before the first one fed (None = none)."""

    def __init__(self, now: str, floor: Optional[str] = None) -> None:
        self.now = now
        self.floor = min(floor, now) if floor else None

    def _raise_floor(self, value: str) -> None:
        if self.floor is None or value > self.floor:
            self.floor = value

    def stamped(self, stamp: str) -> str:
        """A row that has its arrival: it is (capped at now) — and raises the
        floor for the rows after it."""
        value = min(str(stamp), self.now)
        self._raise_floor(value)
        return value

    def estimate(self, received_at: Optional[str], preserved: Optional[str] = None) -> str:
        """The estimate for a row without a stamp; raises the floor."""
        value = preserved or received_at or self.floor or self.now
        if self.floor is not None and self.floor > value:
            value = self.floor
        value = min(value, self.now)
        self._raise_floor(value)
        return value


def onboarded_floor(value: object) -> Optional[str]:
    """A tenant's `clients.onboarded_at` as an estimate floor (canonical UTC
    ms), or None when it is missing or unparseable — the estimate then falls
    back to the other rules, which is what it did before this floor."""
    if isinstance(value, datetime):
        value = value.isoformat()
    return normalize_timestamp(value, naive_is_utc=True) or None


def tenant_onboarded_at(data_root: Path, slug: str) -> Optional[str]:
    """Read `slug`'s onboarding time from the registry under `data_root`
    (read-only). None when the registry, the row or the value is not there
    or not readable — never raises: the floor is a safety margin, and without
    it the estimate is simply the id-order one."""
    db = Path(data_root) / "registry.db"
    if not db.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT onboarded_at FROM clients WHERE slug = ?", (slug,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return onboarded_floor(row[0]) if row else None


def stamp_estimates(
    conn: sqlite3.Connection, *, now: str, batch_size: int = DEFAULT_STAMP_BATCH,
    onboarded_at: Optional[str] = None,
) -> int:
    """Stamp every row without an arrival time with its estimate (`Estimator`:
    the stamp a 036 rollback kept for it, else its received_at; never before
    a lower id's arrival nor the tenant's `onboarded_at` when given, never
    later than `now`, canonical UTC ms) — in id
    order, in short write transactions of `batch_size` rows (live ingest
    waits at most one batch). Resumable: "left to do" is simply the rows
    still NULL, and the floor is re-read from the rows already stamped.
    `conn` must be in autocommit mode (isolation_level None). Returns the
    number of rows stamped."""
    add_column(conn)
    ensure_index(conn)
    kept_by_rollback = has_preserved(conn)
    if kept_by_rollback:
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS {PRESERVED_INDEX} ON {PRESERVED_TABLE}(event_id)")
    first, last = conn.execute(
        f"SELECT MIN(id), MAX(id) FROM {TABLE} WHERE {COLUMN} IS NULL"
    ).fetchone()
    if first is None:
        return 0
    floor = conn.execute(
        f"SELECT MAX({COLUMN}) FROM {TABLE} WHERE id < ?", (int(first),),
    ).fetchone()[0]
    onboarded = onboarded_floor(onboarded_at)
    if onboarded and (floor is None or onboarded > floor):
        floor = onboarded
    estimator = Estimator(now, floor)
    total = 0
    cursor = int(first) - 1
    size = max(1, int(batch_size))
    while cursor < int(last):
        conn.execute("BEGIN IMMEDIATE")
        try:
            batch = conn.execute(
                f"SELECT id, received_at, {COLUMN}, payload_sha256 FROM {TABLE} "
                "WHERE id > ? AND id <= ? ORDER BY id LIMIT ?",
                (cursor, int(last), size),
            ).fetchall()
            if not batch:
                conn.execute("COMMIT")
                break
            kept = (preserved_stamps(conn, batch[0][0], batch[-1][0])
                    if kept_by_rollback else {})
            updates: list[tuple[str, int]] = []
            for row_id, received_at, stamp, digest in batch:
                if stamp is not None:
                    estimator.stamped(stamp)
                    continue
                updates.append((
                    estimator.estimate(
                        received_at, match_preserved(kept.get(int(row_id)), digest)),
                    int(row_id),
                ))
            conn.executemany(
                f"UPDATE {TABLE} SET {COLUMN} = ? WHERE id = ? AND {COLUMN} IS NULL",
                updates,
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        cursor = int(batch[-1][0])
        total += len(updates)
    return total
