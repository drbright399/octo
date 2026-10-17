"""Move telemetry-class rows out of a tenant's events.db into its telemetry.db.

Two callers:
  * the one-off backfill (`scripts/move_telemetry_out_of_events.py`): every
    row a pre-036 bundle stored before ingest learned to tier;
  * the retention job's nightly SWEEP (bounded to the last few days): rows
    that fell back into events.db because the telemetry store refused a
    write at ingest.

Guarantees:
  * classification is the ingest classifier's (`apps.octo.ingest.tiering`)
    applied to the STORED payload — a row it calls a signal stays put;
  * nothing about a moved row changes: payload text, payload_sha256,
    received_at, source, source_host, severity and event_type are copied
    verbatim (a payload over the telemetry bound is NOT moved, rather than
    truncated); `origin_event_id` records where it came from;
  * a row is deleted from events.db only after its telemetry copy is
    COMMITTED, and only if its (id, payload_sha256, received_at) still match
    what was copied;
  * idempotent and resumable: the copy is keyed by origin_event_id (unique),
    so a run interrupted between copy and delete re-finds the copy and just
    finishes the delete; progress is simply "what is left in events.db";
  * rows an incident record points at (an agent note, a ticket, a pattern
    link, an incident — `apps.octo.retention.references`) stay in events.db:
    evidence keeps its id. FAIL CLOSED — references that cannot be read stop
    the tenant's move (`error`), never read as "none". They are re-checked
    per batch: before the copy (events.db's in the scan itself, tickets.db's
    for the batch's ids), and again at the delete (events.db's INSIDE the
    DELETE statement, under its write lock; tickets.db's re-read just
    before). A row that became evidence after its copy stays put (its copy
    ages out of telemetry.db with the other raw rows);
  * rows inside an EVIDENCE WINDOW (Tier Black, 044: a confirmed threat's
    first detection → its all-clear, held until an admin releases it —
    `apps.octo.retention.evidence`) stay in events.db too, exactly as they
    are: checked in the scan and again INSIDE the DELETE (the window table
    lives in events.db — a window opened a moment ago holds; windows a 044
    rollback parked in the file hold too). The nightly sweep's resume point
    stays below the lowest row a window kept (`evidence_min_id`), so the row
    is moved after all once the window is released;
  * short transactions (one batch at a time on each file) so live ingest
    into either DB waits at most one batch;
  * the hourly roll-up and the first-seen ledger are folded from every
    moved row (order-independent: an older row moved after live ingest
    started still becomes the domain's first sighting);
  * a moved row keeps its ARRIVAL (`ingested_at` — for a row stored before
    036 its received_at, the best available estimate; never later than the
    move), so the move does not restart its retention clock;
  * the FULL move (the backfill: no `since` / `since_id`) then stamps every
    row left in events.db that has no arrival time with its estimate
    (`apps.octo.ingest.arrival`, after building the arrival index — cheap
    now that the telemetry has left) — the tenant's arrival backfill. Only
    a move that finished without error does; the dry run counts it.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from apps.octo import paths
from apps.octo.ingest import arrival
from apps.octo.ingest import telemetry as telemetry_store
from apps.octo.ingest import tiering
from apps.octo.ingest.timestamps import utcnow_iso
from apps.octo.retention import evidence, references

DEFAULT_BATCH = 1000
_CANDIDATES = sorted(tiering.TELEMETRY_CANDIDATE_TYPES)

# Disk the move needs in telemetry.db BEFORE the prune shrinks it. Measured
# on a live buoy tenant (v0.11 verification): one raw telemetry row costs
# ~716 B on disk (payload, columns, its indexes), one hourly roll-up row
# ~231 B — together about three times a typical DNS payload. The estimate
# counts a roll-up row per moved row (the worst case: every sighting its
# own hour × domain × device) and is never below three times the payload
# (a feed whose payloads are larger than the measured DNS rows).
RAW_ROW_BYTES = 716
HOURLY_ROW_BYTES = 231
PAYLOAD_FACTOR = 3
# The real run refuses unless the filesystem holding telemetry.db has at
# least this many times the estimate free (the WAL, the incremental vacuum
# and everything else on the disk need their share too).
FREE_SPACE_FACTOR = 2


def disk_estimate(rows: int, payload_bytes: int) -> int:
    """Upper bound (bytes) of what copying `rows` rows carrying
    `payload_bytes` of payload adds to telemetry.db."""
    return max(int(rows) * (RAW_ROW_BYTES + HOURLY_ROW_BYTES),
               PAYLOAD_FACTOR * int(payload_bytes))


def candidate_totals(events_db: Path, *, timeout: float = 10.0) -> tuple[int, int]:
    """(rows, payload bytes) of every telemetry-CANDIDATE row in events.db —
    one read-only aggregate, no classification, so an upper bound of what a
    move would copy (blocked lookups and alerts among them stay). (0, 0)
    when there is no events.db."""
    if not events_db.exists():
        return 0, 0
    marks = ",".join("?" * len(_CANDIDATES))
    conn = sqlite3.connect(f"file:{events_db}?mode=ro", uri=True, timeout=timeout)
    try:
        n, size = conn.execute(
            f"SELECT COUNT(*), COALESCE(SUM(length(CAST(payload AS BLOB))), 0) "
            f"FROM events WHERE event_type IN ({marks})", _CANDIDATES,
        ).fetchone()
    finally:
        conn.close()
    return int(n), int(size)


def free_bytes(path: Path) -> int:
    """Bytes available to this process on the filesystem holding `path`."""
    st = os.statvfs(path)
    return int(st.f_bavail * st.f_frsize)


def filesystem_id(path: Path) -> int:
    return int(os.stat(path).st_dev)


@dataclass
class MoveReport:
    slug: str
    dry_run: bool
    since: Optional[str] = None
    scanned: int = 0            # candidate-type rows looked at
    telemetry: int = 0          # of those, classified telemetry
    moved: int = 0              # copied into telemetry.db this run
    already_copied: int = 0     # copy existed (an interrupted earlier run)
    deleted: int = 0            # removed from events.db after the copy
    kept_signal: int = 0        # candidate type, but the payload makes it a signal
    kept_referenced: int = 0    # a note / ticket points at it
    kept_evidence: int = 0      # inside an evidence window (a confirmed threat's)
    kept_oversize: int = 0      # payload over the telemetry bound
    kept_changed: int = 0       # changed between copy and delete (left in place)
    copy_bytes: int = 0         # payload bytes copied (dry run: would copy)
    # Dry run with `count_before`: rows it would NEWLY copy whose ARRIVAL
    # (estimate) < count_before, per UTC day of arrival — what the
    # telemetry_raw prune would then find (the retention dry run adds them
    # to its plan).
    would_copy_before: dict[str, int] = field(default_factory=dict)
    # The arrival backfill (full move only): rows left in events.db without
    # an arrival time that were stamped with their estimate (dry run: that
    # would be), and whether the arrival index had to be built.
    arrival_stamped: int = 0
    arrival_index_built: bool = False
    arrival_error: Optional[str] = None
    # The highest events.db id the scan covered — set only when it finished
    # without error (the nightly sweep's resume point).
    through_id: Optional[int] = None
    since_id: Optional[int] = None       # the resume point used (else `since`)
    # The lowest id left in events.db because a held evidence window holds
    # it: the next nightly sweep resumes BELOW it (the retention job's
    # `_sweep_resume`), so once the window is released the row is moved
    # after all (and ages as raw telemetry).
    evidence_min_id: Optional[int] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return asdict(self)


def _kept_in_window(report: MoveReport, row_id: int) -> None:
    if report.evidence_min_id is None or int(row_id) < report.evidence_min_id:
        report.evidence_min_id = int(row_id)


def _already_copied(
    telemetry_db: Path, batch: list[telemetry_store.TelemetryRow],
) -> set[int]:
    """origin ids of `batch` already present in telemetry.db (read-only; the
    file may not exist yet)."""
    if not telemetry_db.exists():
        return set()
    ids = [r.origin_event_id for r in batch if r.origin_event_id is not None]
    try:
        conn = sqlite3.connect(f"file:{telemetry_db}?mode=ro", uri=True, timeout=10.0)
        try:
            marks = ",".join("?" * len(ids))
            return {
                int(r[0]) for r in conn.execute(
                    f"SELECT origin_event_id FROM telemetry_raw "
                    f"WHERE origin_event_id IN ({marks})", ids,
                )
            }
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return set()


def move_tenant(
    slug: str,
    *,
    data_root: Path,
    dry_run: bool,
    since: Optional[str] = None,
    since_id: Optional[int] = None,
    count_before: Optional[str] = None,
    batch_size: int = DEFAULT_BATCH,
    busy_timeout: float = 10.0,
    now: Optional[str] = None,
) -> MoveReport:
    """Move `slug`'s telemetry-class rows from events.db to telemetry.db:
    every one (the backfill), or those received at/after `since`, or those
    with an id above `since_id` (the nightly sweep's resume point — a
    fallback row always gets a new id, whatever its timestamp). Raises only
    for a missing tenant directory, or paths.SlugError for a slug that is
    not one or a tenant path that is not contained / runs through a symlink
    (`paths.client_db_path`, spec §2.3 — checked before anything is
    opened); store errors — and references that cannot be read — are
    reported in `error` (what was committed before stays committed and
    consistent). `now` (canonical UTC ms, default the clock) bounds carried
    arrival estimates."""
    report = MoveReport(slug=slug, dry_run=dry_run, since=since)
    now = now or utcnow_iso()
    full = since is None and since_id is None
    events_db = paths.client_db_path(slug, "events", root=data_root)
    client_dir = events_db.parent
    if not events_db.exists():
        return report
    store = telemetry_store.TelemetryStore(
        data_root, busy_timeout=busy_timeout, clock=lambda: now)
    marks = ",".join("?" * len(_CANDIDATES))
    try:
        # A dry run opens events.db read-only: it must not even checkpoint.
        conn = (
            sqlite3.connect(f"file:{events_db}?mode=ro", uri=True, timeout=busy_timeout,
                            isolation_level=None)
            if dry_run else
            sqlite3.connect(events_db, timeout=busy_timeout, isolation_level=None)
        )
        try:
            through = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])
            # A resume point beyond the file's highest id (events.db restored
            # from an older backup: ids come again) is not trusted — the
            # time window applies instead.
            if since_id is not None and 0 <= since_id <= through:
                last_id, since = int(since_id), None
                report.since, report.since_id = None, int(since_id)
            else:
                last_id = 0
            # events.db's own references, evaluated per row in the scan.
            referenced = references.referenced_expr(conn, "events")
            # Evidence windows: the LIVE table (events.db's own), per row —
            # and those a 044 rollback parked in this file (held all the
            # same until 044 is back: a temp copy). A store before 036
            # without its arrival column matches on the vendor time alone.
            has_live = evidence.live(conn)
            parked = [] if has_live else evidence.held_on(conn)
            has_windows = has_live or bool(parked)
            if parked:
                evidence.load_temp(conn, parked)
            in_window = (evidence.held_expr("events", "events", live_table=has_live,
                                            temp=bool(parked),
                                            arrival=arrival.has_column(conn))
                         if has_windows else "0")
            # A row's arrival: its stamp, else (stored before 036) its
            # received_at — and whether it had a stamp (the dry run's count
            # of rows the arrival backfill would stamp).
            arrived = arrival.estimate_expr(conn)
            stamped = (f"{arrival.COLUMN} IS NOT NULL" if arrival.has_column(conn) else "0")
            sql = (
                "SELECT id, received_at, source, source_host, event_type, severity, "
                f"       payload, payload_sha256, {referenced} AS referenced, "
                f"       {arrived} AS arrived, {stamped} AS stamped, {in_window} AS in_window "
                f"  FROM events WHERE id > ? AND id <= ? AND event_type IN ({marks})"
            )
            if since:
                sql += " AND received_at >= ?"
            sql += " ORDER BY id LIMIT ?"
            delete_sql = (
                "DELETE FROM events WHERE id = ? AND payload_sha256 = ? AND received_at = ?"
                + references.events_db_guard(conn, "events")
                + (f" AND NOT {in_window}" if has_windows else "")
            )
            # Unstamped rows the move takes out (the dry run's arrival count).
            unstamped_leaving = 0
            while True:
                params: list = [last_id, through, *_CANDIDATES]
                if since:
                    params.append(since)
                params.append(batch_size)
                rows = conn.execute(sql, params).fetchall()
                if not rows:
                    break
                last_id = rows[-1][0]
                # tickets.db's citations of this batch (another file).
                ticketed = references.ticket_references(
                    client_dir, timeout=busy_timeout, only=[r[0] for r in rows])
                batch: list[telemetry_store.TelemetryRow] = []
                for (row_id, received_at, source, source_host, event_type, severity,
                     payload_text, sha, is_referenced, arrived_at, has_stamp,
                     is_in_window) in rows:
                    report.scanned += 1
                    try:
                        payload = json.loads(payload_text)
                    except (TypeError, ValueError, RecursionError):
                        payload = None
                    if not tiering.classify(event_type, payload, severity).is_telemetry:
                        report.kept_signal += 1
                        continue
                    report.telemetry += 1
                    if is_referenced or row_id in ticketed:
                        report.kept_referenced += 1
                        continue
                    if is_in_window:
                        report.kept_evidence += 1
                        _kept_in_window(report, row_id)
                        continue
                    if len((payload_text or "").encode("utf-8")) > telemetry_store.MAX_PAYLOAD_BYTES:
                        report.kept_oversize += 1
                        continue
                    domain, device = tiering.extract_dimensions(event_type, payload)
                    batch.append(telemetry_store.TelemetryRow(
                        received_at=received_at, source=source, event_type=event_type,
                        severity=severity, source_host=source_host,
                        domain=domain, device=device, payload=payload_text,
                        payload_truncated=False, payload_sha256=sha,
                        origin_event_id=int(row_id),
                        rollup_type=tiering.rollup_event_type(event_type, payload),
                        ingested_at=min(str(arrived_at or received_at), now),
                        device_name=tiering.extract_device_name(event_type, payload),
                    ))
                    if not has_stamp:
                        unstamped_leaving += 1
                if not batch:
                    continue
                if dry_run:
                    # What a real run would do: copy the new ones, finish the
                    # delete of those an interrupted run already copied.
                    copied = _already_copied(store.db_path(slug), batch)
                    report.already_copied += len(copied)
                    report.moved += len(batch) - len(copied)
                    report.deleted += len(batch)
                    for row in batch:
                        if row.origin_event_id in copied:
                            continue
                        report.copy_bytes += len(row.payload.encode("utf-8"))
                        if count_before is not None and row.ingested_at < count_before:
                            day = row.ingested_at[:10]
                            report.would_copy_before[day] = (
                                report.would_copy_before.get(day, 0) + 1)
                    continue
                # 1) copy — committed before anything is deleted.
                written = store.write(slug, batch)
                deletable = []
                for row, w in zip(batch, written):
                    if w.duplicate and not w.matches:
                        # An earlier copy of this id no longer matches the
                        # row: leave the row, never lose the newer version.
                        report.kept_changed += 1
                        continue
                    if w.duplicate:
                        report.already_copied += 1
                    else:
                        report.moved += 1
                        report.copy_bytes += len(row.payload.encode("utf-8"))
                    deletable.append(row)
                # 2) delete the source rows whose identity still matches and
                # that nothing cites NOW: tickets.db re-read for these ids,
                # events.db's references inside the DELETE itself.
                ticketed = references.ticket_references(
                    client_dir, timeout=busy_timeout,
                    only=[r.origin_event_id for r in deletable])
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for row in deletable:
                        if row.origin_event_id in ticketed:
                            report.kept_referenced += 1
                            continue
                        cur = conn.execute(
                            delete_sql,
                            (row.origin_event_id, row.payload_sha256, row.received_at),
                        )
                        if cur.rowcount:
                            report.deleted += 1
                        elif conn.execute(
                            "SELECT 1 FROM events WHERE id = ? AND payload_sha256 = ? "
                            "AND received_at = ?",
                            (row.origin_event_id, row.payload_sha256, row.received_at),
                        ).fetchone():
                            # Became evidence meanwhile: cited, or inside a
                            # window opened since the scan.
                            if has_windows and conn.execute(
                                    f"SELECT {in_window} FROM events WHERE id = ?",
                                    (row.origin_event_id,)).fetchone()[0]:
                                report.kept_evidence += 1
                                _kept_in_window(report, row.origin_event_id)
                            else:
                                report.kept_referenced += 1
                        else:
                            report.kept_changed += 1
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
            report.through_id = through
            if full:
                _arrival_backfill(conn, report, now, dry_run=dry_run,
                                  leaving=unstamped_leaving, batch_size=batch_size,
                                  onboarded_at=arrival.tenant_onboarded_at(data_root, slug))
        finally:
            conn.close()
    except references.ReferencesUnavailable as exc:
        report.error = f"references unreadable — nothing more moved: {exc}"
    except (sqlite3.Error, OSError) as exc:
        report.error = f"{type(exc).__name__}: {exc}"
    return report


def _arrival_backfill(
    conn: sqlite3.Connection, report: MoveReport, now: str, *, dry_run: bool,
    leaving: int, batch_size: int, onboarded_at: Optional[str] = None,
) -> None:
    """After a full move that finished: stamp the rows left in events.db
    that have no arrival time with their estimate (`arrival`). A failure
    here is the report's `arrival_error` — the move itself stands, and the
    tenant stays "backfill pending" (retention waits) until a re-run
    finishes it."""
    try:
        if dry_run:
            # Rows without a stamp now, less those the move would take out.
            report.arrival_stamped = max(0, arrival.count_unstamped(conn) - leaving)
            report.arrival_index_built = (
                not arrival.has_column(conn) or not arrival.has_index(conn))
            return
        report.arrival_index_built = (
            not arrival.has_column(conn) or not arrival.has_index(conn))
        report.arrival_stamped = arrival.stamp_estimates(
            conn, now=now, batch_size=max(1, batch_size), onboarded_at=onboarded_at)
    except sqlite3.Error as exc:
        report.arrival_error = f"{type(exc).__name__}: {exc}"
