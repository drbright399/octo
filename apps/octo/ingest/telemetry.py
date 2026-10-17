"""Per-tenant telemetry store — `clients/<slug>/telemetry.db` (migration 036).

Where the ingest sink puts the events `apps.octo.ingest.tiering` files as
TELEMETRY (answered DNS, TLS / HTTP / flow metadata). One write =
one transaction holding:

  * the raw row (`telemetry_raw`) — same identity as an events.db row:
    (source, payload_sha256, received_at); payload bounded at
    `MAX_PAYLOAD_BYTES` with the sha over the FULL text, so identity
    survives truncation; `ingested_at` = its ARRIVAL (the sink's clock, or
    for a row moved out of events.db that row's arrival / estimate), which
    is what the 7-day retention and the cold archive's day files go by;
  * the hourly roll-up (`telemetry_hourly`, one row per hour × event type ×
    domain × device) — upserted, so concurrent writers add up exactly;
    `last_arrival` = the latest arrival folded into it (the 180-day
    retention's clock);
  * the first-seen ledger (`first_seen_domains`) — order-independent
    (keeps the EARLIEST sighting whatever order rows arrive in, which is what
    lets the one-off move from events.db rebuild it after live ingest has
    started).

The DB file is created lazily — `ensure_db()` applies the migrations'
telemetry sections with user_version tracking (the quarantine store's
pattern) — so tenants provisioned before 036 get it on their first
telemetry write. It is never created for a tenant whose directory does not
exist: telemetry for an unprovisioned tenant fails exactly like an event
does.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from apps.octo import paths
from apps.octo.ingest import tiering
from apps.octo.ingest.timestamps import normalize_timestamp, utcnow_iso
from apps.octo.migration import apply_migration, list_migrations

TELEMETRY_TARGET = "telemetry"
DB_NAME = "telemetry.db"
# A DNS / TLS / flow record is a few hundred bytes to a few KB; an HTTP one
# can be larger. Anything over this is kept truncated (sha over the whole).
MAX_PAYLOAD_BYTES = 32 * 1024
# Ingest must stay fast: a writer waits this long for the file's write lock
# (the retention job's deletes are short batches) before the sink falls
# back to events.db.
BUSY_TIMEOUT_SEC = 5.0

_lock = threading.Lock()
_schema_ensured: set[str] = set()


def telemetry_migration_numbers() -> list[int]:
    return [
        m.number for m in list_migrations(kind="forward")
        if f"-- @target: {TELEMETRY_TARGET}" in m.sql
    ]


def db_path_for(slug: str, data_root: Optional[Path] = None) -> Path:
    """`<data_root>/clients/<slug>/telemetry.db` through the path layer's
    containment check (`paths.resolve_inside`): the slug is validated and
    the result proven inside the data root, symlink-free, before any
    caller touches it. Raises paths.SlugError (a ValueError) otherwise."""
    return paths.client_db_path(slug, "telemetry", root=data_root)  # = DB_NAME


def ensure_db(path: Path) -> list[int]:
    """Create/upgrade one telemetry.db. The tenant directory must exist.
    Returns the migration numbers applied ([] when current). Cheap after the
    first call per file per process."""
    key = str(path)
    if key in _schema_ensured and path.exists():
        return []
    with _lock:
        if not path.exists():
            # Removed since it was ensured (a restore, a test): build it again.
            _schema_ensured.discard(key)
        if key in _schema_ensured:
            return []
        if not path.parent.is_dir():
            raise FileNotFoundError(
                f"tenant directory missing for {path.parent.name!r}; "
                "client must be provisioned before telemetry is stored"
            )
        conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC)
        applied: list[int] = []
        try:
            by_number = {m.number: m for m in list_migrations(kind="forward")}
            for num in telemetry_migration_numbers():
                current = conn.execute("PRAGMA user_version").fetchone()[0]
                if current >= num:
                    continue
                apply_migration(conn, by_number[num], target=TELEMETRY_TARGET)
                applied.append(num)
            conn.commit()
        finally:
            conn.close()
        _schema_ensured.add(key)
    return applied


def reset_schema_cache() -> None:
    """Tests: forget which files were ensured (a new tmp data root)."""
    with _lock:
        _schema_ensured.clear()


def hour_bucket(received_at: str) -> str:
    """'YYYY-MM-DDTHH:00:00Z' (UTC) for a stored timestamp; the current hour
    when it cannot be read (never raises — a bad clock never loses a row)."""
    canonical = normalize_timestamp(received_at, naive_is_utc=True) or utcnow_iso()
    return canonical[:13] + ":00:00Z"


def canonical_ts(received_at: str) -> str:
    return normalize_timestamp(received_at, naive_is_utc=True) or utcnow_iso()


def bounded_payload(text: str) -> tuple[str, bool]:
    raw = text.encode("utf-8")
    if len(raw) <= MAX_PAYLOAD_BYTES:
        return text, False
    return raw[:MAX_PAYLOAD_BYTES].decode("utf-8", errors="ignore"), True


@dataclass(frozen=True)
class TelemetryRow:
    received_at: str
    source: str
    event_type: str
    severity: str
    source_host: Optional[str]
    domain: str
    device: str
    payload: str
    payload_truncated: bool
    payload_sha256: str
    # events.db id this row is being MOVED from (None for live ingest).
    origin_event_id: Optional[int] = None
    # The roll-up's type key when it differs from event_type
    # (`tiering.rollup_event_type`: a Suricata DNS ANSWER record is counted
    # apart from the query, so one lookup is not two). None = event_type.
    rollup_type: Optional[str] = None
    # ARRIVAL (canonical UTC ms): when Athena received the row — the store's
    # clock when None. A moved row carries its events.db arrival (estimate).
    ingested_at: Optional[str] = None
    # The name the sensor knows the device by (Pi-hole v6), "" when none or
    # the same as `device` (`tiering.extract_device_name`).
    device_name: str = ""


@dataclass(frozen=True)
class TelemetryWrite:
    telemetry_id: int
    duplicate: bool
    # For a row carrying origin_event_id that was copied already: whether the
    # stored copy has the same identity (payload_sha256, received_at) as the
    # row offered now. False = the source changed since — do not delete it.
    matches: bool = True


def row_for_ingest(
    *, source: str, event_type: str, severity: str, source_host: Optional[str],
    received_at: str, payload: dict, payload_sha256: str,
    domain: str, device: str, ingested_at: Optional[str] = None,
    device_name: str = "",
) -> TelemetryRow:
    """A live-ingest row. The payload text is the one the events sink would
    have stored (same serialisation), bounded."""
    text, truncated = bounded_payload(json.dumps(payload, separators=(",", ":")))
    return TelemetryRow(
        received_at=received_at, source=source, event_type=event_type,
        severity=severity if severity in _SEVERITIES else "info",
        source_host=source_host, domain=domain, device=device,
        payload=text, payload_truncated=truncated, payload_sha256=payload_sha256,
        rollup_type=tiering.rollup_event_type(event_type, payload),
        ingested_at=ingested_at, device_name=device_name,
    )


_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


class TelemetryStore:
    """Writes telemetry rows for a tenant. Safe from many threads: one
    short-lived connection per call, BEGIN IMMEDIATE for the whole batch."""

    def __init__(
        self, data_root: Optional[Path] = None, *, busy_timeout: float = BUSY_TIMEOUT_SEC,
        clock: Optional[Callable[[], str]] = None,
    ) -> None:
        self._data_root = (
            Path(data_root).resolve() if data_root is not None else paths.data_root()
        )
        self._busy_timeout = busy_timeout
        self._clock = clock or utcnow_iso

    def db_path(self, slug: str) -> Path:
        return db_path_for(slug, self._data_root)

    def write(
        self,
        slug: str,
        rows: Sequence[TelemetryRow],
        *,
        dedup: bool = False,
        identity_includes_time: bool = True,
    ) -> list[TelemetryWrite]:
        """Store `rows` (raw + roll-up + first-seen) in ONE transaction.
        Raises on failure — nothing of the batch is stored then.

        `dedup` applies the events sink's idempotency guard: a row whose
        (source, payload_sha256, received_at) — or (source, payload_sha256)
        when `identity_includes_time` is false (no vendor timestamp) — is
        stored already is not written or counted again. A row carrying
        `origin_event_id` is always checked against that id instead."""
        path = self.db_path(slug)
        ensure_db(path)
        conn = sqlite3.connect(path, timeout=self._busy_timeout, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                now = self._clock()
                out = [
                    _write_one(conn, row, dedup=dedup,
                               identity_includes_time=identity_includes_time,
                               arrived=now)
                    for row in rows
                ]
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()
        return out


def _write_one(
    conn: sqlite3.Connection, row: TelemetryRow, *, dedup: bool,
    identity_includes_time: bool, arrived: str,
) -> TelemetryWrite:
    if row.origin_event_id is not None:
        found = conn.execute(
            "SELECT id, payload_sha256, received_at FROM telemetry_raw "
            "WHERE origin_event_id = ?",
            (row.origin_event_id,),
        ).fetchone()
        if found is not None:
            same = (found[1], found[2]) == (row.payload_sha256, row.received_at)
            return TelemetryWrite(int(found[0]), True, matches=same)
    elif dedup:
        if identity_includes_time:
            found = conn.execute(
                "SELECT id FROM telemetry_raw WHERE payload_sha256 = ? AND source = ? "
                "AND received_at = ? ORDER BY id DESC LIMIT 1",
                (row.payload_sha256, row.source, row.received_at),
            ).fetchone()
        else:
            found = conn.execute(
                "SELECT id FROM telemetry_raw WHERE payload_sha256 = ? AND source = ? "
                "ORDER BY id DESC LIMIT 1",
                (row.payload_sha256, row.source),
            ).fetchone()
        if found is not None:
            return TelemetryWrite(int(found[0]), True)

    # A carried arrival (a moved row's estimate = its vendor time) never lies
    # in the future: a sensor with a fast clock would otherwise never age out.
    ingested = min(canonical_ts(row.ingested_at), arrived) if row.ingested_at else arrived
    cur = conn.execute(
        "INSERT INTO telemetry_raw (received_at, source, event_type, severity, "
        " source_host, domain, device, device_name, payload, payload_truncated, "
        " payload_sha256, origin_event_id, ingested_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            row.received_at, row.source, row.event_type, row.severity,
            row.source_host, row.domain, row.device, row.device_name, row.payload,
            1 if row.payload_truncated else 0, row.payload_sha256,
            row.origin_event_id, ingested,
        ),
    )
    seen = canonical_ts(row.received_at)
    fold(conn, event_type=row.event_type, domain=row.domain, device=row.device,
         seen=seen, count=1, rollup_type=row.rollup_type, arrival=ingested,
         device_name=row.device_name)
    return TelemetryWrite(int(cur.lastrowid), False)


def fold(
    conn: sqlite3.Connection, *, event_type: str, domain: str, device: str,
    seen: str, count: int = 1, last_seen: Optional[str] = None,
    rollup_type: Optional[str] = None, arrival: Optional[str] = None,
    device_name: str = "",
) -> None:
    """Add `count` sightings at `seen` (canonical UTC) to the hourly roll-up
    (under `rollup_type`, default `event_type`) and — for a name that can be
    "new" (`tiering.first_seen_eligible`: not a reverse lookup, not a
    single-label probe, not mDNS) — the first-seen ledger, on the caller's
    transaction. `arrival` (canonical UTC ms; default `last_seen` / `seen`)
    is when those sightings reached Athena: the roll-up row keeps the latest
    (`last_arrival`, the roll-up retention's clock). `device_name`: the
    device's name as the sensor knows it — the roll-up row keeps the latest
    non-empty one."""
    last = last_seen or seen
    arrived = arrival or last
    conn.execute(
        "INSERT INTO telemetry_hourly (hour, event_type, domain, device, device_name, "
        " count, first_seen, last_seen, last_arrival) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (hour, event_type, domain, device) DO UPDATE SET "
        " count = count + excluded.count, "
        " device_name = CASE WHEN excluded.device_name != '' "
        "   THEN excluded.device_name ELSE device_name END, "
        " first_seen = MIN(first_seen, excluded.first_seen), "
        " last_seen = MAX(last_seen, excluded.last_seen), "
        " last_arrival = MAX(last_arrival, excluded.last_arrival)",
        (seen[:13] + ":00:00Z", rollup_type or event_type, domain, device, device_name or "",
         count, seen, last, arrived),
    )
    if not tiering.first_seen_eligible(domain):
        return
    # Every right-hand side reads the row as it was BEFORE this update, so
    # the device/type are taken from whichever sighting is earliest.
    conn.execute(
        "INSERT INTO first_seen_domains (domain, first_seen, first_device, "
        " first_event_type, last_seen) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (domain) DO UPDATE SET "
        " first_device = CASE WHEN excluded.first_seen < first_seen "
        "   THEN excluded.first_device ELSE first_device END, "
        " first_event_type = CASE WHEN excluded.first_seen < first_seen "
        "   THEN excluded.first_event_type ELSE first_event_type END, "
        " first_seen = MIN(first_seen, excluded.first_seen), "
        " last_seen = MAX(last_seen, excluded.last_seen)",
        (domain, seen, device, event_type, last),
    )


def newest_received_at(
    slug: str, *, source: Optional[str] = None, not_before: Optional[str] = None,
    before_id: Optional[int] = None, ceiling: Optional[str] = None,
    data_root: Optional[Path] = None, timeout: float = 1.0,
) -> Optional[str]:
    """`received_at` of the tenant's newest raw telemetry row (optionally only
    `source`'s, none older than `not_before`, none with id ≥ `before_id`, none
    later than `ceiling`). None when there is none or the store can't be
    read — never raises, never creates the file."""
    try:
        path = db_path_for(slug, data_root)
    except ValueError:
        return None
    if not path.exists():
        return None
    sql = "SELECT received_at FROM telemetry_raw WHERE 1 = 1"
    params: list = []
    if ceiling:
        sql += " AND received_at <= ?"
        params.append(ceiling)
    if before_id is not None:
        sql += " AND id < ?"
        params.append(int(before_id))
    if not_before:
        sql += " AND received_at >= ?"
        params.append(not_before)
    if source is not None:
        sql += " AND source = ?"
        params.append(source)
    sql += " ORDER BY received_at DESC LIMIT 1"
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=timeout)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    return row[0] if row else None
