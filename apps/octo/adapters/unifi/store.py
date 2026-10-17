"""UniFi rows in a MAPPED tenant's telemetry.db (migration 039).

One page of a site's system log is applied in ONE transaction
(`apply_page`): the roll-up counts, the signal buckets (claims + hits) and the
site's cursor move together, so every event is counted exactly once whatever
crashes when. A new bucket's first event is claimed with its payload as an
OUTBOX row (`pending_payload`); the poller then stores the alert in events.db
and calls `set_event`, which clears the outbox. `pending()` lists claims whose
alert was never written (a crash between the two writes) so the next pass
finishes them — never a lost alert, never a second one.

Every function opens a short-lived connection (the telemetry store's rule)
and raises sqlite3 errors to the caller (the poller holds the site and
retries next cycle).
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from apps.octo.ingest import telemetry
from apps.octo.ingest.timestamps import utcnow_iso

BUSY_TIMEOUT_SEC = 5.0
MAX_RECENT_IDS = 4_000


def _db(slug: str, data_root: Optional[Path] = None) -> Path:
    path = telemetry.db_path_for(slug, data_root)
    telemetry.ensure_db(path)
    return path


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _read(slug: str, data_root: Optional[Path]) -> Optional[sqlite3.Connection]:
    path = telemetry.db_path_for(slug, data_root)
    if not path.exists():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SEC)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# The cursor
# ---------------------------------------------------------------------------

@dataclass
class Cursor:
    scope: str
    hwm_ms: int
    scanned_to_ms: int
    recent_ids: list[str] = field(default_factory=list)


def cursor(slug: str, scope: str, *, data_root: Optional[Path] = None) -> Optional[Cursor]:
    """The site's cursor in this tenant, or None (never read here yet)."""
    conn = _read(slug, data_root)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT hwm_ms, scanned_to_ms, recent_ids FROM unifi_syslog_cursor WHERE scope = ?",
            (scope,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    try:
        ids = json.loads(row["recent_ids"] or "[]")
    except ValueError:
        ids = []
    return Cursor(scope, int(row["hwm_ms"]), int(row["scanned_to_ms"]),
                  [str(i) for i in ids if isinstance(i, (str, int))] if isinstance(ids, list) else [])


# ---------------------------------------------------------------------------
# One page, applied whole
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Claim:
    """A signal event for its bucket: (key, hour, kind, subject, event time
    ISO, payload) and, for an IPS hit, its REMOTE address (046: a bucket
    coalesces one LAN client + signature whatever the remote end, so the
    split is kept beside the count — `remotes`)."""
    key: str
    hour: str
    kind: str
    subject: str
    seen: str
    payload: dict[str, Any]
    remote: Optional[str] = None


REMOTES_MAX = 16
REMOTE_UNKNOWN, REMOTE_OTHER = "?", "~"


def merge_remotes(text: Optional[str], claim: Claim) -> Optional[str]:
    """The bucket's {remote: hits} with this hit added (IPS buckets only;
    at most REMOTES_MAX addresses, the rest counted under "~"; a hit with no
    remote under "?"). Other kinds keep NULL."""
    if claim.kind != "ips_threat":
        return text
    try:
        held = json.loads(text) if text else {}
    except ValueError:
        held = {}
    held = held if isinstance(held, dict) else {}
    key = (claim.remote or REMOTE_UNKNOWN)[:45]
    named = [k for k in held if k not in (REMOTE_OTHER, REMOTE_UNKNOWN)]
    if key not in held and key != REMOTE_UNKNOWN and len(named) >= REMOTES_MAX:
        key = REMOTE_OTHER
    held[key] = int(held.get(key) or 0) + 1
    return json.dumps(held, sort_keys=True, separators=(",", ":"))


@dataclass
class PageResult:
    new_claims: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    counted: int = 0
    rollups: int = 0


def apply_page(
    slug: str,
    scope: str,
    *,
    rollups: dict[tuple[str, str], tuple[int, int]],
    claims: list[Claim],
    new_cursor: Cursor,
    arrived: Optional[str] = None,
    data_root: Optional[Path] = None,
) -> PageResult:
    """ONE transaction: add the roll-up counts ((hour, kind) → (events,
    ocsf class)), claim / count the signal buckets, move the cursor. Returns
    the NEW claims (key, payload) whose alerts the caller must now store."""
    now = arrived or utcnow_iso()
    out = PageResult()
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for (hour, kind), (n, class_uid) in sorted(rollups.items()):
                if n <= 0:
                    continue
                conn.execute(
                    "INSERT INTO unifi_hourly (hour, scope, kind, ocsf_class_uid, events, "
                    " last_arrival) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (hour, scope, kind) DO UPDATE SET "
                    " events = events + excluded.events, last_arrival = excluded.last_arrival",
                    (hour, scope, kind, int(class_uid), int(n), now),
                )
                out.rollups += int(n)
            for c in claims:
                _count_claim(conn, scope, c, now, out)
            ids = new_cursor.recent_ids[-MAX_RECENT_IDS:]
            conn.execute(
                "INSERT INTO unifi_syslog_cursor (scope, hwm_ms, scanned_to_ms, recent_ids, "
                " updated_at, last_arrival) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (scope) DO UPDATE SET hwm_ms = excluded.hwm_ms, "
                " scanned_to_ms = excluded.scanned_to_ms, recent_ids = excluded.recent_ids, "
                " updated_at = excluded.updated_at, last_arrival = excluded.last_arrival",
                (scope, int(new_cursor.hwm_ms), int(new_cursor.scanned_to_ms),
                 json.dumps(ids), now, now),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return out


def _count_claim(conn: sqlite3.Connection, scope: str, c: Claim, now: str,
                 out: PageResult) -> None:
    """Claim a new bucket (its alert to be stored) or count a hit in it."""
    row = conn.execute(
        "SELECT hits, remotes FROM unifi_signal_buckets WHERE bucket_key = ?", (c.key,),
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO unifi_signal_buckets (bucket_key, hour, scope, kind, "
            " subject, event_id, hits, first_seen, last_seen, pending_payload, "
            " last_arrival, remotes) VALUES (?, ?, ?, ?, ?, NULL, 1, ?, ?, ?, ?, ?)",
            (c.key, c.hour, scope, c.kind, c.subject[:400], c.seen, c.seen,
             json.dumps(c.payload, separators=(",", ":"), sort_keys=True), now,
             merge_remotes(None, c)),
        )
        out.new_claims.append((c.key, c.payload))
    else:
        conn.execute(
            "UPDATE unifi_signal_buckets SET hits = hits + 1, "
            " last_seen = MAX(last_seen, ?), last_arrival = ?, remotes = ? "
            "WHERE bucket_key = ?",
            (c.seen, now, merge_remotes(row[1], c), c.key),
        )
        out.counted += 1


def claim(slug: str, scope: str, claims: list[Claim], *, arrived: Optional[str] = None,
          data_root: Optional[Path] = None) -> PageResult:
    """Claim / count DERIVED signals (entity resolution's findings) in the
    coalescing ledger — ONE transaction, no cursor. Returns the new claims
    whose alerts the caller must store."""
    now = arrived or utcnow_iso()
    out = PageResult()
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for c in claims:
                _count_claim(conn, scope, c, now, out)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()
    return out


def pending(slug: str, scope: str, *, limit: int = 200,
            data_root: Optional[Path] = None) -> list[tuple[str, dict[str, Any]]]:
    """Claims of this site whose alert is not stored yet (key, payload)."""
    conn = _read(slug, data_root)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT bucket_key, pending_payload FROM unifi_signal_buckets "
            "WHERE scope = ? AND event_id IS NULL AND pending_payload IS NOT NULL "
            "ORDER BY first_seen LIMIT ?", (scope, int(limit)),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    out = []
    for r in rows:
        try:
            payload = json.loads(r["pending_payload"])
        except ValueError:
            continue
        if isinstance(payload, dict):
            out.append((str(r["bucket_key"]), payload))
    return out


def set_event(slug: str, key: str, event_id: int, *, data_root: Optional[Path] = None) -> None:
    """The alert of bucket `key` is stored: record its id, clear the outbox."""
    conn = _connect(_db(slug, data_root))
    try:
        conn.execute(
            "UPDATE unifi_signal_buckets SET event_id = ?, pending_payload = NULL "
            "WHERE bucket_key = ? AND event_id IS NULL", (int(event_id), key),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reads (presentation, tests)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EventHits:
    hits: int
    hour: str


def hits_for_events(slug: str, event_ids: list[int], *,
                    data_root: Optional[Path] = None) -> dict[int, EventHits]:
    """{event id: hits} for alerts a bucket created — "seen N times this
    hour". Never creates the store; {} on any read error."""
    if not event_ids:
        return {}
    try:
        conn = _read(slug, data_root)
    except sqlite3.Error:
        return {}
    if conn is None:
        return {}
    try:
        marks = ",".join("?" * len(event_ids))
        rows = conn.execute(
            f"SELECT event_id, hits, hour FROM unifi_signal_buckets WHERE event_id IN ({marks})",
            [int(i) for i in event_ids],
        ).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return {int(r[0]): EventHits(int(r[1]), str(r[2])) for r in rows}


@dataclass(frozen=True)
class BucketInfo:
    """One coalesced alert's row: its count, first / last sighting and the
    remotes of its hits (None: written before 046, not known)."""
    event_id: int
    scope: str
    kind: str
    subject: str
    hits: int
    first_seen: str
    last_seen: str
    remotes: Optional[dict[str, int]]


def _remotes(text: Any) -> Optional[dict[str, int]]:
    if not text:
        return None
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    return {str(k): int(v) for k, v in value.items()
            if isinstance(v, int) and not isinstance(v, bool)}


def bucket_info(slug: str, event_ids: list[int], *,
                data_root: Optional[Path] = None) -> dict[int, BucketInfo]:
    """{event id: BucketInfo} for alerts a bucket created. Never creates the
    store; {} on any read error."""
    ids = sorted({int(i) for i in event_ids})
    if not ids:
        return {}
    try:
        conn = _read(slug, data_root)
    except sqlite3.Error:
        return {}
    if conn is None:
        return {}
    out: dict[int, BucketInfo] = {}
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(unifi_signal_buckets)")}
        rem = "remotes" if "remotes" in cols else "NULL AS remotes"
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            for r in conn.execute(
                    f"SELECT event_id, scope, kind, subject, hits, first_seen, last_seen, {rem} "
                    f"FROM unifi_signal_buckets WHERE event_id IN ({','.join('?' * len(chunk))})",
                    chunk).fetchall():
                out[int(r["event_id"])] = BucketInfo(
                    int(r["event_id"]), str(r["scope"]), str(r["kind"]), str(r["subject"]),
                    int(r["hits"]), str(r["first_seen"]), str(r["last_seen"]),
                    _remotes(r["remotes"]))
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return out


def window_buckets(slug: str, kind: str, since_hour: str, *, scope: Optional[str] = None,
                   data_root: Optional[Path] = None) -> list[BucketInfo]:
    """Every bucket of `kind` from `since_hour` on (one site's, or all) —
    event_id 0 for a claim whose alert is not stored yet. [] when the store
    cannot be read."""
    try:
        conn = _read(slug, data_root)
    except sqlite3.Error:
        return []
    if conn is None:
        return []
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(unifi_signal_buckets)")}
        rem = "remotes" if "remotes" in cols else "NULL AS remotes"
        sql = (f"SELECT COALESCE(event_id, 0) AS event_id, scope, kind, subject, hits, "
               f"first_seen, last_seen, {rem} FROM unifi_signal_buckets "
               f"WHERE kind = ? AND hour >= ?")
        args: list[Any] = [kind, since_hour]
        if scope is not None:
            sql += " AND scope = ?"
            args.append(scope)
        rows = conn.execute(sql, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [BucketInfo(int(r["event_id"]), str(r["scope"]), str(r["kind"]), str(r["subject"]),
                       int(r["hits"]), str(r["first_seen"]), str(r["last_seen"]),
                       _remotes(r["remotes"])) for r in rows]


def hourly(slug: str, scope: Optional[str] = None, *,
           data_root: Optional[Path] = None) -> list[sqlite3.Row]:
    conn = _read(slug, data_root)
    if conn is None:
        return []
    try:
        if scope is None:
            return conn.execute("SELECT * FROM unifi_hourly ORDER BY hour, scope, kind").fetchall()
        return conn.execute("SELECT * FROM unifi_hourly WHERE scope = ? ORDER BY hour, kind",
                            (scope,)).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def buckets(slug: str, *, data_root: Optional[Path] = None) -> Iterator[sqlite3.Row]:
    conn = _read(slug, data_root)
    if conn is None:
        return iter(())
    try:
        return iter(conn.execute(
            "SELECT * FROM unifi_signal_buckets ORDER BY hour, bucket_key").fetchall())
    except sqlite3.OperationalError:
        return iter(())
    finally:
        conn.close()
