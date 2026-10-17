"""NextDNS rows in a tenant's telemetry.db (migration 037).

  nextdns_hourly          one row per (clock hour, profile): queries by status
                          and blocked queries by reason class. Written with
                          REPLACE semantics — analytics are absolute counts,
                          so re-reading an hour (a restart, a catch-up) must
                          never add up twice.
  nextdns_signal_buckets  the coalescing ledger (see migration 037): which
                          alert a bucket created and how many hits it has had.
                          HIGH: (profile, device, root domain, reason, clock
                          hour); DGA: (profile, device, reason, clock hour);
                          MEDIUM / LOW: (profile, device, reason, UTC day). A
                          bucket without the root ("*") counts the distinct
                          roots it saw and keeps a few as samples.

Both belong to the telemetry tier (retention class `telemetry_rollup`,
180 days by `last_arrival`); the alerts themselves live in events.db.
Every function opens a short-lived connection (the TelemetryStore's rule),
waits out a concurrent writer for `BUSY_TIMEOUT_SEC`, and raises sqlite3
errors to the caller (the poller logs and retries next cycle).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from apps.octo.ingest import telemetry
from apps.octo.ingest.timestamps import utcnow_iso

BUSY_TIMEOUT_SEC = 5.0
# Line ids remembered at one bucket's newest timestamp (several lines can
# share a millisecond: A + AAAA lookups). Bounded.
MAX_LAST_IDS = 64
# Distinct roots remembered by one bucket without the root in its key (DGA,
# every MEDIUM / LOW reason). Past this the count reads "at least N".
MAX_ROOTS = 200
# Masked sample domains a bucket's note shows (distinct masked forms).
SAMPLE_ROOTS = 5
CROSS_DOMAIN_ROOT = "*"
SPAN_HOUR = "hour"
SPAN_DAY = "day"


def _db(slug: str, data_root: Optional[Path] = None) -> Path:
    path = telemetry.db_path_for(slug, data_root)
    telemetry.ensure_db(path)
    return path


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Hourly roll-up
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HourlyRow:
    hour: str                   # 'YYYY-MM-DDTHH:00:00Z'
    profile_id: str
    queries: int
    default_queries: int
    blocked: int
    allowed: int
    signal_high: int
    signal_medium: int
    signal_low: int
    policy_blocked: int
    signal_reasons: dict[str, int]


def upsert_hourly(
    slug: str, row: HourlyRow, *, arrived: Optional[str] = None,
    data_root: Optional[Path] = None,
) -> None:
    now = arrived or utcnow_iso()
    reasons = json.dumps(
        dict(sorted(row.signal_reasons.items())[:40]), separators=(",", ":"),
    )
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute(
            "INSERT INTO nextdns_hourly (hour, profile_id, queries, default_queries, "
            " blocked, allowed, signal_high, signal_medium, signal_low, policy_blocked, "
            " signal_reasons, fetched_at, last_arrival) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (hour, profile_id) DO UPDATE SET "
            " queries = excluded.queries, default_queries = excluded.default_queries, "
            " blocked = excluded.blocked, allowed = excluded.allowed, "
            " signal_high = excluded.signal_high, signal_medium = excluded.signal_medium, "
            " signal_low = excluded.signal_low, policy_blocked = excluded.policy_blocked, "
            " signal_reasons = excluded.signal_reasons, fetched_at = excluded.fetched_at, "
            " last_arrival = excluded.last_arrival",
            (row.hour, row.profile_id, row.queries, row.default_queries, row.blocked,
             row.allowed, row.signal_high, row.signal_medium, row.signal_low,
             row.policy_blocked, reasons, now, now),
        )
    finally:
        conn.close()


def _read(slug: str, data_root: Optional[Path]) -> Optional[sqlite3.Connection]:
    """A read-only connection to the tenant's telemetry.db, or None when the
    store does not exist (never creates it)."""
    path = telemetry.db_path_for(slug, data_root)
    if not path.exists():
        return None
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SEC)


def first_hour(
    slug: str, profile_id: str, *, data_root: Optional[Path] = None,
) -> Optional[str]:
    """The profile's oldest roll-up hour in this tenant (where its baseline
    starts), or None."""
    conn = _read(slug, data_root)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT MIN(hour) FROM nextdns_hourly WHERE profile_id = ?", (profile_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()
    return str(row[0]) if row and row[0] else None


def hour_history(
    slug: str, profile_id: str, hours: list[str], *, data_root: Optional[Path] = None,
) -> dict[str, int]:
    """{hour: queries} for those of `hours` the profile has a row for (the
    lapse baseline: the same hour of the week on earlier weeks)."""
    if not hours:
        return {}
    conn = _read(slug, data_root)
    if conn is None:
        return {}
    try:
        rows = conn.execute(
            f"SELECT hour, queries FROM nextdns_hourly WHERE profile_id = ? "
            f"AND hour IN ({','.join('?' * len(hours))})",
            (profile_id, *hours),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()
    return {str(r[0]): int(r[1] or 0) for r in rows}


def queries_between(
    slug: str, profile_id: str, from_hour: str, to_hour: str, *,
    data_root: Optional[Path] = None,
) -> tuple[int, int]:
    """(sum of queries, number of hour rows) for the profile's hours from
    `from_hour` to `to_hour`, both included. (0, 0) without a store."""
    conn = _read(slug, data_root)
    if conn is None:
        return 0, 0
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(queries), 0), COUNT(*) FROM nextdns_hourly "
            "WHERE profile_id = ? AND hour >= ? AND hour <= ?",
            (profile_id, from_hour, to_hour),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0, 0
    finally:
        conn.close()
    return int(row[0] or 0), int(row[1] or 0)


def queries_since(
    slug: str, profile_id: str, since_hour: str, *, data_root: Optional[Path] = None,
) -> tuple[int, int]:
    """(sum of queries, number of hour rows) for the profile from `since_hour`
    on. (0, 0) when the store does not exist."""
    path = telemetry.db_path_for(slug, data_root)
    if not path.exists():
        return 0, 0
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SEC)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(queries), 0), COUNT(*) FROM nextdns_hourly "
            "WHERE profile_id = ? AND hour >= ?",
            (profile_id, since_hour),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0, 0
    finally:
        conn.close()
    return int(row[0] or 0), int(row[1] or 0)


# ---------------------------------------------------------------------------
# Coalescing buckets
# ---------------------------------------------------------------------------

def bucket_key(profile_id: str, device: str, root: str, reason_id: str, hour: str,
               span: str = SPAN_HOUR) -> str:
    """The bucket's identity. `hour` is the span's start; a 'day' bucket
    adds its span so it never collides with an 'hour' bucket at 00:00."""
    parts = (profile_id, device, root, reason_id, hour)
    if span != SPAN_HOUR:
        parts = (*parts, span)
    text = "\n".join(parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class Bucket:
    key: str
    hour: str                   # the span's start ('YYYY-MM-DDTHH:00:00Z')
    profile_id: str
    reason_id: str
    root: str                   # CROSS_DOMAIN_ROOT: the key leaves the domain out
    device: str
    span: str = SPAN_HOUR

    @property
    def cross_domain(self) -> bool:
        return self.root == CROSS_DOMAIN_ROOT


@dataclass(frozen=True)
class BucketOutcome:
    """What one signal line did to its bucket.

      new         first line of the bucket: create the alert (then `set_event`)
      unfinished  the bucket's alert was claimed but never written (a crash
                  between the two writes): create it now from this line
      counted     a later hit, counted now — no alert
      seen        this very line was counted before (overlapping windows)
    """
    kind: str
    event_id: Optional[int]
    hits: int


def count_hit(
    slug: str, bucket: Bucket, *, line_ts: str, line_id: str, line_root: str = "",
    arrived: Optional[str] = None, data_root: Optional[Path] = None,
) -> BucketOutcome:
    """Record one signal line in its bucket, exactly once (one transaction)."""
    return count_hits(slug, [(bucket, line_ts, line_id, line_root)], arrived=arrived,
                      data_root=data_root)[0]


def count_hits(
    slug: str, hits: list[tuple], *,
    arrived: Optional[str] = None, data_root: Optional[Path] = None,
) -> list[BucketOutcome]:
    """Record signal lines — (bucket, line timestamp, line id[, line's root
    domain]), oldest first — in ONE transaction, each exactly once. A bucket
    claimed by an earlier line of the same batch answers `counted` for its
    later lines: exactly one line per bucket is ever told to create the
    alert. A cross-domain bucket also counts the distinct roots it saw."""
    if not hits:
        return []
    now = arrived or utcnow_iso()
    out: list[BucketOutcome] = []
    claimed: set[str] = set()
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for hit in hits:
                bucket, line_ts, line_id = hit[0], hit[1], hit[2]
                line_root = hit[3] if len(hit) > 3 else ""
                out.append(_count_one(conn, bucket, line_ts, line_id, now, claimed,
                                      line_root or ""))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return out


def _json_list(text: Optional[str]) -> list:
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def _count_one(
    conn: sqlite3.Connection, bucket: Bucket, line_ts: str, line_id: str, now: str,
    claimed: set[str], line_root: str = "",
) -> BucketOutcome:
    row = conn.execute(
        "SELECT event_id, hits, last_seen, last_ids, roots, distinct_roots "
        "FROM nextdns_signal_buckets WHERE bucket_key = ?", (bucket.key,),
    ).fetchone()
    if row is None:
        roots = [line_root] if bucket.cross_domain and line_root else []
        conn.execute(
            "INSERT INTO nextdns_signal_buckets (bucket_key, hour, span, profile_id, "
            " reason_id, root, roots, distinct_roots, device, event_id, hits, first_seen, "
            " last_seen, last_ids, noted, last_arrival) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 1, ?, ?, ?, 0, ?)",
            (bucket.key, bucket.hour, bucket.span, bucket.profile_id, bucket.reason_id,
             bucket.root, json.dumps(roots), len(roots), bucket.device, line_ts, line_ts,
             json.dumps([line_id]), now),
        )
        claimed.add(bucket.key)
        return BucketOutcome("new", None, 1)
    last_ids = _json_list(row["last_ids"])
    last_seen = row["last_seen"] or ""
    event_id = row["event_id"]
    hits = int(row["hits"])
    # An alert still to be written: THIS batch's claim → just a count; an
    # earlier crash's claim → finish it (once).
    pending = event_id is None and bucket.key not in claimed
    already = line_ts < last_seen or (line_ts == last_seen and line_id in last_ids)
    if already:
        if pending:
            claimed.add(bucket.key)
            return BucketOutcome("unfinished", None, hits)
        return BucketOutcome("seen", event_id, hits)
    if line_ts > last_seen:
        last_seen, last_ids = line_ts, [line_id]
    else:
        last_ids = (last_ids + [line_id])[-MAX_LAST_IDS:]
    hits += 1
    roots = _json_list(row["roots"])
    distinct = int(row["distinct_roots"] or 0)
    if bucket.cross_domain and line_root and line_root not in roots and len(roots) < MAX_ROOTS:
        roots.append(line_root)
        distinct = len(roots)
    conn.execute(
        "UPDATE nextdns_signal_buckets SET hits = ?, last_seen = ?, last_ids = ?, "
        " roots = ?, distinct_roots = ?, last_arrival = ? WHERE bucket_key = ?",
        (hits, last_seen, json.dumps(last_ids), json.dumps(roots), distinct, now,
         bucket.key),
    )
    if pending:
        claimed.add(bucket.key)
        return BucketOutcome("unfinished", None, hits)
    return BucketOutcome("counted", event_id, hits)


def set_event(slug: str, key: str, event_id: int, *, data_root: Optional[Path] = None) -> None:
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute(
            "UPDATE nextdns_signal_buckets SET event_id = ? WHERE bucket_key = ? "
            "AND event_id IS NULL", (int(event_id), key),
        )
    finally:
        conn.close()


@dataclass(frozen=True)
class ClosedBucket:
    key: str
    hour: str
    profile_id: str
    reason_id: str
    event_id: int
    hits: int
    first_seen: str
    last_seen: str
    span: str = SPAN_HOUR
    distinct_roots: int = 0
    # Every root the bucket remembers (≤ MAX_ROOTS), first seen first — the
    # note masks them and shows SAMPLE_ROOTS distinct masked forms.
    sample_roots: tuple[str, ...] = ()


_CLOSED = "((span = 'hour' AND hour < ?) OR (span = 'day' AND hour < ?))"


def _day_of(before_hour: str) -> str:
    return before_hour[:11] + "00:00:00Z"


def closed_unnoted(
    slug: str, *, before_hour: str, before_day: Optional[str] = None, limit: int = 200,
    held: Optional[dict[str, str]] = None, data_root: Optional[Path] = None,
) -> list[ClosedBucket]:
    """Buckets whose span is over (an 'hour' bucket: hour < `before_hour`; a
    'day' bucket: its day < `before_day`, the start of the cutoff's day),
    whose alert exists and whose note is not written yet — oldest first.
    `held`: profile id → an EARLIER cutoff hour for that profile (its log
    backlog is not read up to `before_hour` yet: its spans are not over)."""
    path = telemetry.db_path_for(slug, data_root)
    if not path.exists():
        return []
    day = before_day if before_day is not None else _day_of(before_hour)
    where = f"noted = 0 AND event_id IS NOT NULL AND {_CLOSED}"
    args: list = [before_hour, day]
    for pid, cutoff in sorted((held or {}).items()):
        where += f" AND NOT (profile_id = ? AND NOT {_CLOSED})"
        args += [pid, cutoff, _day_of(cutoff)]
    conn = _connect(_db(slug, data_root))
    try:
        rows = conn.execute(
            "SELECT bucket_key, hour, profile_id, reason_id, event_id, hits, first_seen, "
            f" last_seen, span, distinct_roots, roots FROM nextdns_signal_buckets WHERE {where} "
            "ORDER BY hour LIMIT ?", (*args, int(limit)),
        ).fetchall()
    finally:
        conn.close()
    return [
        ClosedBucket(r["bucket_key"], r["hour"], r["profile_id"], r["reason_id"],
                     int(r["event_id"]), int(r["hits"]), r["first_seen"], r["last_seen"],
                     r["span"] or SPAN_HOUR, int(r["distinct_roots"] or 0),
                     tuple(str(x) for x in _json_list(r["roots"])[:MAX_ROOTS]))
        for r in rows
    ]


def mark_noted(slug: str, key: str, *, data_root: Optional[Path] = None) -> None:
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute("UPDATE nextdns_signal_buckets SET noted = 1 WHERE bucket_key = ?", (key,))
    finally:
        conn.close()


@dataclass(frozen=True)
class EventHits:
    hits: int
    hour: str                   # the bucket span's start
    span: str = SPAN_HOUR
    distinct_roots: int = 0


def hits_for_events(
    slug: str, event_ids: list[int], *, data_root: Optional[Path] = None,
) -> dict[int, EventHits]:
    """{event id: EventHits} for the alerts a bucket created — the "seen N
    times" count. Never creates the store; {} on any read error."""
    if not event_ids:
        return {}
    path = telemetry.db_path_for(slug, data_root)
    if not path.exists():
        return {}
    marks = ",".join("?" * len(event_ids))
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return {}
    try:
        rows = conn.execute(
            f"SELECT event_id, hits, hour, span, distinct_roots FROM nextdns_signal_buckets "
            f"WHERE event_id IN ({marks})", [int(i) for i in event_ids],
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return {int(r[0]): EventHits(int(r[1]), str(r[2]), str(r[3] or SPAN_HOUR),
                                 int(r[4] or 0)) for r in rows}


def iter_buckets(slug: str, *, data_root: Optional[Path] = None) -> Iterator[sqlite3.Row]:
    """Every bucket row (tests, diagnostics)."""
    conn = _connect(_db(slug, data_root))
    try:
        yield from conn.execute("SELECT * FROM nextdns_signal_buckets ORDER BY hour, bucket_key")
    finally:
        conn.close()
