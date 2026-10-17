"""The retention job — per tenant, per data class, delete what has expired.

One run, in order, for every tenant with a directory under the data root
(any status: an offboarded tenant's data ages out like anyone's):

  1. SWEEP   telemetry-class rows that landed in events.db since the last
             completed sweep (an ingest-time fallback) move to telemetry.db
             (`retention.move`, the backfill's code path). The resume point
             is the highest events.db id the tenant's last completed sweep
             covered (kept in `retention_runs`): a fallback row always gets
             a new id whatever its timestamp, so an outage of the telemetry
             store of any length is caught up by the first run after it.
             With no resume point (the first run, a restored events.db) the
             sweep looks back `SWEEP_DAYS`.
  0. ARRIVAL retention ages every row from when it ARRIVED (owner decision
             2026-09-29; `apps.octo.ingest.arrival`), never from the
             vendor's timestamp. A tenant some of whose events.db rows have
             no arrival time yet (stored before 036, the one-off backfill
             `move_telemetry_out_of_events.py` not run for it) is PENDING:
             its sweep is skipped and its signals and telemetry are NOT
             pruned (`blocked`, the run is `partial` and says why) — the
             first nightly run after an upgrade can never prune telemetry
             the operator has not moved and previewed. The backfill's own
             run (sweep over ALL of events.db) is the one that clears it.
  0b. EVIDENCE (Tier Black, 044; Rick 2026-10-05) a confirmed threat — a
             Red or Black incident — holds an EVIDENCE WINDOW of its tenant
             (first detection → the all-clear, kept until an admin releases
             it: `retention.evidence`). EVERY class below, the sweep and the
             archive keep whatever of the tenant lies inside a held window
             (counted per class as `evidence`, per window as its kept rows —
             written back to the window); what lies outside every window is
             pruned as usual (the run is NOT partial for it). Windows that
             cannot be read prune NOTHING of the tenant (`blocked`) — a
             window is never ruled out by a read that failed; windows a 044
             rollback parked hold exactly like live ones. A held window
             never expires: the admins are told when the disk runs low
             while windows keep data, and weekly about windows held long
             after their all-clear (`_evidence_notices`).
  2. PLAN    for each class, the effective retention (`retention.policy`:
             bundle config, per-tenant override, legal-baseline floor), its
             cutoff, and the EXACT rows to go: counted now and bounded by the
             highest matching id now, so what is deleted is what was counted.
             The policy is read FAIL CLOSED: a registry that cannot be read
             fails the run before anything is swept or deleted.
               events               events.db   events.ingested_at — minus
                                                EVIDENCE: an event a ticket,
                                                agent note, pattern link or
                                                incident points at is held
                                                (`referenced`) for as long as
                                                that record points at it
                                                (`retention.references`)
               agent_notes          events.db   agent_notes.created_at
               indicators_auto      indicators  last_seen (not promoted)
               indicators_promoted  indicators  max(last_seen, promoted_at)
               secure_notepad       — no store exists yet: reported, nothing done
               audit                — permanent: never touched
               telemetry_raw        telemetry   ingested_at, whole UTC days
               telemetry_rollup     telemetry   telemetry_hourly.last_arrival (and
                                                the NextDNS roll-up tables of
                                                037: nextdns_hourly,
                                                nextdns_signal_buckets; the
                                                UniFi ones of 039:
                                                unifi_hourly,
                                                unifi_signal_buckets,
                                                unifi_syslog_cursor —
                                                `ROLLUP_TABLES`)
               first_seen_domains   telemetry   last_seen > 365 d (fixed rule)
               entity_*             entities    migration 040's five classes
                                                (`apps.octo.entity.retention`:
                                                closed leases 90 d — guest 7 —
                                                with answers cut to a count,
                                                egress 400, answers 365, ended
                                                links 400, inventory 90)
  3. ARCHIVE raw telemetry about to go is appended to the cold archive, one
             day per UTC day of ARRIVAL (`retention.archive`). Archive DISABLED
             (OCTO_ARCHIVE_ROOT unset) → pruned without a copy, and the run
             says so. Archive ENABLED but a day's write failed (or the root is
             missing/unwritable, or encryption is REQUIRED and its recipients
             are missing / invalid — `retention.archive_crypto`) → that day's
             rows are NOT pruned. Encrypted (age, to the operator's public
             keys): one new part per day per run. Encryption off → the run
             says "archive NOT encrypted" (log, report, audit rows).
  4. AUDIT   a `retention_enforce` row (actor `retention-job`, system) on
             the global chain for every tenant with something TO DELETE,
             BEFORE anything of it is deleted: per class the planned count,
             cutoff, effective days and why; the archive outcome; the sweep;
             who started the run (`initiated_by` — the scheduler, or the OS
             user, host and reason of a script run). An audit write that
             fails stops the run — no delete ever happens unaudited. A tenant
             with nothing to delete gets no row of its own. AFTER every
             tenant, ONE `retention_run` row (client_slug 'global', target =
             the run id, request_id = run id) records the whole run: status,
             trigger, initiator, archive, and per tenant what actually
             happened — deleted / held / referenced / blocked / errors per
             class, the sweep, and the id of its plan row; tenants with
             nothing to do are listed by name. (v0.11: was two rows per
             tenant per night, most of them all-zero — the chain grew by
             two rows per tenant per day for nothing.)
  5. DELETE  in batches of `batch_size`, one short BEGIN IMMEDIATE
             transaction each (SQLite's busy timeout absorbs a concurrent
             ingest write), so live ingest waits at most one batch. The keys
             are picked OUTSIDE the write lock, keyset-paginated (`_batches`):
             a batch re-checks only the rows it deletes — the rows a window
             keeps are passed over once a run, never under the lock.
  6. RECLAIM a file with auto_vacuum = INCREMENTAL (every telemetry.db, and
             per-client DBs provisioned from 036 on) returns freed pages in
             steps of `vacuum_step_pages` within `vacuum_budget_sec`, then a
             WAL checkpoint. A file WITHOUT it (events.db / indicators.db
             provisioned before 036) is NOT full-VACUUMed here — that holds an
             exclusive lock for as long as it takes to rewrite the file
             (minutes for a GB-scale events.db) and would stall ingest; the
             freed pages are reused by new rows (the file stops growing), and
             the run reports the reusable bytes. Returning them to the
             filesystem is the one-time `convert_to_incremental()` (script
             flag `--convert-vacuum`, with octo-core STOPPED), after which
             the nightly steps apply to that file too.

Dry run = the same plan, archive check and counts, and NOTHING written:
no sweep, no archive file, no audit row, no registry row, no delete, no
vacuum. The sweep is counted instead of done, and the raw rows it WOULD move
that are already past the telemetry_raw cutoff are added to that class's
plan (a real run moves them and then prunes them in the same run).

Overlap: an exclusive, non-blocking lock on `<data_root>/.retention.lock`
(fcntl) — a second run while one is going (the in-app scheduler and the
script, or two scripts) reports `skipped` and touches nothing. The job is
idempotent: re-running after a crash finishes what the first run started.

An enforcing run leaves one `retention_runs` row in the registry (started →
finished, per-tenant per-class counts) for Settings → System. The one-off
move script's run has trigger `backfill`: recorded (its sweep resume point
counts) but not "the last retention run" (`last_run`).

Clock check (a SCHEDULED run only, `_clock_refusal`): a clock stepped
forward moves every cutoff with it — one run would delete every signal and
all telemetry, and arrival stamps come from the same clock. A scheduled
run more than 3 days after the last run on record (or, with none, more than
a day after the newest arrival of any row) is refused: status `failed`,
nothing swept, audited, deleted or recorded (its started_at is the suspect
clock — it must not become the next run's reference); the scheduler shows
why. A deliberate catch-up is a script run, which is not checked.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import shutil
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from apps.octo import paths
from apps.octo.ingest import arrival
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.retention import evidence
from apps.octo.retention import move as telemetry_move
from apps.octo.retention import references
from apps.octo.retention.archive import ArchiveError, ColdArchive
from apps.octo.retention.policy import (
    FIRST_SEEN_FORGET_DAYS,
    RETENTION_DEFAULTS,
    ClassPolicy,
    EffectiveRetention,
    PolicyUnavailable,
    effective_retention,
    load_policies,
)

logger = logging.getLogger(__name__)

ACTOR = "retention-job"
AUDIT_ACTION = "retention_enforce"          # per tenant with deletions, BEFORE them
AUDIT_RUN_ACTION = "retention_run"          # one per enforcing run, at its end
LOCK_NAME = ".retention.lock"
# `backfill` = the one-off move script's run (move + telemetry classes
# only). It is recorded like any enforcing run (its sweep resume point
# counts), but it is not "the last retention run": the scheduler's catch-up,
# the clock check and Settings → System skip it (`last_run`).
TRIGGERS = ("scheduler", "script", "api", "backfill")
# Clock check of a SCHEDULED run (`_clock_refusal`): refuse — nothing
# touched — when this run's clock is more than CLOCK_MAX_SINCE_LAST_RUN
# after the last run on record, or (no run on record) more than
# CLOCK_MAX_SINCE_ARRIVAL after the newest arrival stamp of any tenant.
CLOCK_MAX_SINCE_LAST_RUN = timedelta(days=3)
CLOCK_MAX_SINCE_ARRIVAL = timedelta(days=1)
SWEEP_DAYS = 8                   # look-back when a tenant has no resume point
SWEEP_MARK_RUNS = 400            # finished runs searched for a resume point
DEFAULT_BATCH = 2000
DEFAULT_VACUUM_STEP_PAGES = 2048
DEFAULT_VACUUM_BUDGET_SEC = 20.0
DEFAULT_ARCHIVE_CHUNK = 20000
BUSY_TIMEOUT_SEC = 10.0

# Classes a tenant whose arrival backfill is PENDING does not prune: its
# signals (no arrival time to age them by) and its telemetry (the one-off
# move has not run: events.db still holds it, un-previewed).
ARRIVAL_GATED = frozenset({
    "events", "telemetry_raw", "telemetry_rollup", "first_seen_domains",
})
BACKFILL_PENDING_NOTE = (
    "waiting for the one-off backfill (scripts/move_telemetry_out_of_events.py): "
    "rows stored before 036 have no arrival time yet and the telemetry among "
    "them has not been moved — nothing of this class is pruned until it has run"
)

# The hourly roll-up class covers these telemetry.db tables (table, primary
# key), each pruned by its `last_arrival`: the buoys' roll-up (036), the
# NextDNS per-profile hours and coalescing ledger (037), and the UniFi
# per-site hours, coalescing ledger and system-log cursors (039 — a cursor
# is touched every poll while its site is mapped, so only a long-unmapped
# site's ages out; re-mapped later, it back-fills 24 h again).
ROLLUP_TABLES: tuple[tuple[str, str], ...] = (
    ("telemetry_hourly", "(hour, event_type, domain, device)"),
    ("nextdns_hourly", "(hour, profile_id)"),
    ("nextdns_signal_buckets", "bucket_key"),
    ("unifi_hourly", "(hour, scope, kind)"),
    ("unifi_signal_buckets", "bucket_key"),
    ("unifi_syslog_cursor", "scope"),
)

# Report order. The entity classes (migration 040) prune each tenant's
# entities.db (`apps.octo.entity.retention`).
ENTITY_CLASSES = ("entity_lookup_lease", "entity_lookup_egress", "entity_resolution",
                  "entity_links", "entity_inventory")
CLASS_ORDER = (
    "events", "agent_notes", "indicators_auto", "indicators_promoted",
    "secure_notepad", "audit", "telemetry_raw", "telemetry_rollup",
    "first_seen_domains", *ENTITY_CLASSES,
)

# EVIDENCE WINDOWS (Tier Black, 044 — Rick 2026-10-05: "everything from
# first detection up until the all clear should be treated as event
# evidence"): every class that deletes keeps the rows inside a held window
# (`retention.evidence`). Windows that cannot be read stop EVERY class of
# the tenant (and its sweep): evidence is never ruled out by a read that
# failed. The audit chain is permanent anyway.
EVIDENCE_GATED = frozenset(c for c in CLASS_ORDER if c not in ("audit", "secure_notepad"))
WINDOWS_UNREADABLE = ("the evidence windows could not be read — an incident's evidence "
                      "cannot be ruled out, so nothing of this tenant is pruned")
_CLASS_STORE = {"events": "events", "agent_notes": "events", "indicators_auto": "indicators",
                "indicators_promoted": "indicators", "telemetry_raw": "telemetry",
                "telemetry_rollup": "telemetry", "first_seen_domains": "telemetry"}
# A held window never expires (Rick: kept until an admin releases it) — so
# nothing it keeps may fill the disk unseen (a full disk WOULD stop ingest).
# After every real run the admins of the tenant are told (never released
# for them):
#   * daily, while the data volume has less than EVIDENCE_DISK_WARN_FREE_PCT
#     free and a window keeps rows past their retention — naming them;
#   * weekly, about the windows still held more than
#     EVIDENCE_REMIND_AFTER_DAYS after their end (the all-clear).
EVIDENCE_DISK_WARN_FREE_PCT = 15.0
EVIDENCE_REMIND_AFTER_DAYS = 30


@dataclass
class ClassResult:
    data_class: str
    store: str
    status: str                  # ok | permanent | no_store | blocked | error | skipped
    effective_days: Optional[int] = None
    basis: str = ""
    configured_days: Optional[int] = None
    legal_baseline_days: Optional[int] = None
    tenant_days: Optional[int] = None
    cutoff: Optional[str] = None
    planned: int = 0             # rows that expire (dry run: would be deleted)
    deleted: int = 0
    held: int = 0                # expired but kept (archive failed)
    referenced: int = 0          # expired but kept: evidence (events)
    evidence: int = 0            # expired but kept: inside an evidence window
    note: str = ""


@dataclass
class TenantResult:
    slug: str
    classes: dict[str, ClassResult] = field(default_factory=dict)
    sweep: dict = field(default_factory=dict)
    archive: dict = field(default_factory=dict)
    vacuum: dict = field(default_factory=dict)
    # {pending, index_built / index_to_build} — see step 0.
    arrival: dict = field(default_factory=dict)
    # Step 0b: {windows: the held windows at planning, kept: {window id:
    # expired rows it kept}, error: why they could not be read}.
    evidence: dict = field(default_factory=dict)
    audit_row_id: Optional[int] = None   # its retention_enforce (plan) row, if any
    error: Optional[str] = None

    @property
    def deleted(self) -> int:
        return sum(c.deleted for c in self.classes.values())

    @property
    def planned(self) -> int:
        return sum(c.planned for c in self.classes.values())


@dataclass
class RunReport:
    run_id: str
    mode: str                    # enforce | dry_run
    trigger: str
    started_at: str
    finished_at: Optional[str] = None
    status: str = "running"      # ok | partial | failed | skipped
    archive: dict = field(default_factory=dict)
    tenants: list[TenantResult] = field(default_factory=list)
    note: str = ""
    initiated_by: dict = field(default_factory=dict)
    audit_row_id: Optional[int] = None   # the run's retention_run row
    # What the admins were told about held evidence windows (disk / held
    # long after the all-clear): [{tenant, kind, windows, request_id}].
    evidence_notices: list = field(default_factory=list)

    @property
    def deleted_total(self) -> int:
        return sum(t.deleted for t in self.tenants)

    def as_dict(self) -> dict:
        out = asdict(self)
        out["deleted_total"] = self.deleted_total
        for t_out, t in zip(out["tenants"], self.tenants):
            t_out["deleted"] = t.deleted
            t_out["planned"] = t.planned
        return out


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _utc(dt: datetime) -> str:
    return format_utc_ms(dt)


def _next_day(day: str) -> str:
    """Upper bound of a day's ingested_at range. A 'day' that is not a date
    (a malformed stored timestamp) gets an open upper bound — the exact
    substr() match still pins the set."""
    try:
        return (datetime.strptime(day, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return f"{day}\uffff"


def _connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        return sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SEC,
            isolation_level=None,
        )
    return sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,),
    ).fetchone() is not None


def _index_leads_with(conn: sqlite3.Connection, table: str, column: str) -> bool:
    """Has `table` a full (not partial) index whose FIRST column is `column`
    (the batched deletes then walk that index in (column, key) order)?"""
    for idx in conn.execute(f"PRAGMA index_list({table})").fetchall():
        if len(idx) > 4 and idx[4]:
            continue                                      # partial
        info = conn.execute(f"PRAGMA index_info({idx[1]})").fetchall()
        if info and min(info, key=lambda r: r[0])[2] == column:
            return True
    return False


def _table_exists(db: Path, name: str) -> bool:
    if not db.exists():
        return False
    try:
        conn = _connect(db, read_only=True)
    except sqlite3.Error:
        return False
    try:
        return _has_table(conn, name)
    finally:
        conn.close()


class _Lock:
    """Exclusive, non-blocking run lock (fcntl) on a file in the data root."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fd: Optional[int] = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


# ---------------------------------------------------------------------------
# Deletion specs — one per class
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Spec:
    data_class: str
    store: str                   # events | indicators | telemetry
    table: str
    where: str                   # uses :cutoff
    key: str = "id"              # column bounding the planned set (rowid tables)
    # Rows an incident record may cite (`retention.references`): held,
    # never deleted, while cited.
    evidence: bool = False


_SPECS: dict[str, _Spec] = {
    # ARRIVAL, never the vendor's received_at (a NULL — not stamped yet —
    # never matches: such a tenant is gated anyway).
    "events": _Spec("events", "events", "events", "ingested_at < :cutoff", evidence=True),
    "agent_notes": _Spec("agent_notes", "events", "agent_notes", "created_at < :cutoff"),
    "indicators_auto": _Spec(
        "indicators_auto", "indicators", "indicators",
        "promoted_at IS NULL AND last_seen < :cutoff",
    ),
    "indicators_promoted": _Spec(
        "indicators_promoted", "indicators", "indicators",
        "promoted_at IS NOT NULL AND MAX(last_seen, promoted_at) < :cutoff",
    ),
}


def _db_for(client_dir: Path, store: str) -> Path:
    """One of the tenant's stores, through `paths.resolve_inside` (spec
    §2.3): contained in `client_dir` — itself from `paths.client_dir` — and
    not a symlink. A refusal (SlugError) fails the class or the tenant that
    asked, never reads another file."""
    return paths.resolve_inside(client_dir, f"{store}.db")


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------

class RetentionJob:
    def __init__(
        self,
        *,
        data_root: Optional[Path] = None,
        archive: Optional[ColdArchive] = None,
        archive_from_env: bool = True,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        monotonic: Callable[[], float] = time.monotonic,
        batch_size: int = DEFAULT_BATCH,
        vacuum_step_pages: int = DEFAULT_VACUUM_STEP_PAGES,
        vacuum_budget_sec: float = DEFAULT_VACUUM_BUDGET_SEC,
        sweep_days: Optional[int] = SWEEP_DAYS,
        archive_chunk: int = DEFAULT_ARCHIVE_CHUNK,
        move_batch: int = telemetry_move.DEFAULT_BATCH,
    ) -> None:
        """`sweep_days`: the sweep's look-back for a tenant without a resume
        point; None = sweep ALL of events.db (the one-off backfill script's
        run — every pre-036 telemetry row)."""
        self.data_root = Path(data_root) if data_root is not None else paths.data_root()
        self.archive = archive if archive is not None else (
            ColdArchive.from_env() if archive_from_env else None
        )
        self._now = now
        self._monotonic = monotonic
        self.batch_size = max(1, int(batch_size))
        self.vacuum_step_pages = max(1, int(vacuum_step_pages))
        self.vacuum_budget_sec = float(vacuum_budget_sec)
        self.sweep_days = sweep_days
        self.archive_chunk = max(1, int(archive_chunk))
        self.move_batch = max(1, int(move_batch))
        self._classes: Optional[set[str]] = None
        self._sweep_marks: dict[str, int] = {}

    # ----- entry point -----

    def run(
        self, *, dry_run: bool = False, trigger: str = "script",
        slugs: Optional[list[str]] = None,
        classes: Optional[Iterable[str]] = None,
        initiated_by: Optional[dict] = None,
    ) -> RunReport:
        """`classes` limits the run to those data classes (the others are
        reported `skipped`); None = every class — the nightly run.
        `initiated_by` (who started it: os_user, host, reason — a script
        run) is recorded in every audit row of the run."""
        if trigger not in TRIGGERS:
            raise ValueError(f"trigger must be one of {TRIGGERS}")
        wanted = set(classes) if classes is not None else None
        if wanted is not None and not wanted <= set(CLASS_ORDER):
            raise ValueError(f"unknown data class(es): {sorted(wanted - set(CLASS_ORDER))}")
        self._classes = wanted
        now = self._now().astimezone(timezone.utc)
        report = RunReport(
            run_id=str(uuid.uuid4()), mode="dry_run" if dry_run else "enforce",
            trigger=trigger, started_at=_utc(now),
            initiated_by=dict(initiated_by or {"by": trigger}),
        )
        report.archive = self._archive_status()
        if report.archive.get("enabled") and not report.archive.get("encrypted"):
            # Every run says it (encryption off — or required but unusable,
            # and then nothing is archived nor pruned either). A root that is
            # unusable while the encryption is fine is NOT this: its reason
            # is the archive's `reason`, not "NOT encrypted".
            logger.warning("[retention] %s", report.archive.get("encryption_note")
                           or "archive NOT encrypted")
        lock = _Lock(self.data_root / LOCK_NAME)
        if not lock.acquire():
            report.status = "skipped"
            report.note = "another retention run holds the lock; nothing was done"
            report.finished_at = _utc(self._now())
            return report
        try:
            registry = self.data_root / "registry.db"
            # FAIL CLOSED: a policy or tenant list that cannot be read must
            # not turn into "the defaults" — that deletes whatever a longer
            # stored setting keeps. Nothing is swept, planned or deleted.
            try:
                policies = load_policies(registry, strict=True)
                tenants = self._tenants(registry, slugs)
            except (PolicyUnavailable, _RegistryUnavailable) as exc:
                report.status = "failed"
                report.note = f"retention policy unreadable — nothing was done: {exc}"
                report.finished_at = _utc(self._now())
                logger.error("[retention] %s", report.note)
                return report
            if trigger == "scheduler" and not dry_run:
                refusal = self._clock_refusal(registry, tenants, now)
                if refusal:
                    # Not recorded in retention_runs: its started_at is the
                    # suspect clock — it must not become the next run's
                    # reference. The scheduler keeps it for Settings → System.
                    report.status = "failed"
                    report.note = refusal
                    report.finished_at = _utc(self._now())
                    logger.error("[retention] scheduled run REFUSED — %s", refusal)
                    return report
            self._sweep_marks = (
                self._load_sweep_marks(registry) if self.sweep_days is not None else {}
            )
            if not dry_run:
                self._record_start(registry, report)
            failed = False
            for slug, tenant_days in tenants:
                result = TenantResult(slug=slug)
                report.tenants.append(result)
                try:
                    self._tenant(result, policies, tenant_days, now, dry_run, report)
                except _AuditFailed as exc:
                    result.error = f"audit write failed: {exc}"
                    report.note = "stopped: an audit row could not be written"
                    failed = True
                    break
                except Exception as exc:  # noqa: BLE001 — one tenant never stops the rest
                    logger.exception("[retention] tenant %s failed", slug)
                    result.error = f"{type(exc).__name__}: {exc}"
            waiting = [t.slug for t in report.tenants if t.arrival.get("pending")]
            if waiting and not report.note:
                report.note = (
                    "arrival backfill pending for " + ", ".join(waiting)
                    + " — their signals and telemetry were not pruned; run "
                    "scripts/move_telemetry_out_of_events.py (dry run first)"
                )
            if failed:
                report.status = "failed"
            elif any(t.error for t in report.tenants) or any(
                c.status in ("error", "blocked")
                for t in report.tenants for c in t.classes.values()
            ):
                report.status = "partial"
            else:
                report.status = "ok"
            report.finished_at = _utc(self._now())
            if not dry_run:
                self._evidence_notices(report, now)
                # The run's one summary row — what actually happened, after
                # every delete. Its failure cannot undo the deletes (each was
                # preceded by its tenant's plan row); it is said, loudly.
                try:
                    report.audit_row_id = self._audit_run(report)
                except _AuditFailed as exc:
                    logger.error("[retention] run summary audit row not written: %s", exc)
                    if report.status == "ok":
                        report.status = "partial"
                    report.note = (report.note + "; " if report.note else "") + (
                        f"the run's summary audit row could not be written: {exc}")
                self._record_finish(registry, report)
        finally:
            lock.release()
        return report

    # ----- clock check (scheduled runs) -----

    def _clock_refusal(
        self, registry: Path, tenants: list[tuple[str, Optional[int]]], now: datetime,
    ) -> Optional[str]:
        """Why a SCHEDULED run must not trust its clock, or None. A clock
        stepped forward (a bad NTP source, a manual date, a VM restored with
        the wrong time) moves every cutoff with it: one run would delete
        every signal, all raw telemetry and all roll-ups — and arrival stamps
        come from the same clock, so nothing else would catch it. Reference:
        the last retention run on record (not the backfill's); without one,
        the newest arrival stamp of any tenant (ingest is live on a bundle
        worth pruning). A deliberate catch-up after a long pause is a script
        run (`enforce_retention.py`, dry run first), which is not checked."""
        last = last_run(registry)
        if last is not None:
            started = _parse_utc(last.get("started_at"))
            if started is not None and now - started > CLOCK_MAX_SINCE_LAST_RUN:
                return (
                    f"clock check: this run's clock ({_utc(now)}) is {_days(now - started)} "
                    f"after the last retention run on record ({last['started_at']}). "
                    "Either the host clock jumped forward — a run now would delete by the "
                    "wrong date — or retention has not run for that long. Nothing was "
                    "done. Check the host clock; to catch up on purpose run "
                    "enforce_retention.py --dry-run, then --reason \"<why>\"."
                )
            return None
        newest = self._newest_arrival([slug for slug, _ in tenants])
        if newest is not None and now - newest > CLOCK_MAX_SINCE_ARRIVAL:
            return (
                f"clock check: no retention run on record, and this run's clock "
                f"({_utc(now)}) is {_days(now - newest)} after the newest arrival of any "
                f"row ({_utc(newest)}). Either the host clock jumped forward — a run now "
                "would delete by the wrong date — or nothing has arrived for that long. "
                "Nothing was done. Check the host clock; to start enforcing on purpose run "
                "enforce_retention.py --dry-run, then --reason \"<why>\"."
            )
        return None

    def _newest_arrival(self, slugs: list[str]) -> Optional[datetime]:
        """The newest arrival stamp in any tenant's store — indexed reads
        only (an events.db without the arrival index is skipped)."""
        newest: Optional[str] = None
        for slug in slugs:
            try:
                client_dir = paths.client_dir(slug, root=self.data_root)
            except paths.SlugError:
                continue        # refused — the tenant's own pass reports it
            probes = (
                ("telemetry", "telemetry_raw", "ingested_at"),
                ("telemetry", "telemetry_hourly", "last_arrival"),
                ("events", "events", arrival.COLUMN),
            )
            for store, table, column in probes:
                try:
                    path = _db_for(client_dir, store)
                except paths.SlugError:
                    continue
                if not path.exists():
                    continue
                try:
                    conn = _connect(path, read_only=True)
                    try:
                        if not _has_table(conn, table):
                            continue
                        if table == "events" and not (
                                arrival.has_column(conn) and arrival.has_index(conn)):
                            continue
                        value = conn.execute(f"SELECT MAX({column}) FROM {table}").fetchone()[0]
                    finally:
                        conn.close()
                except sqlite3.Error:
                    continue
                if value and (newest is None or str(value) > newest):
                    newest = str(value)
        return _parse_utc(newest)

    # ----- registry bookkeeping -----

    def _tenants(
        self, registry: Path, only: Optional[list[str]],
    ) -> list[tuple[str, Optional[int]]]:
        """(slug, clients.retention_days) for every tenant with a directory.
        A directory without a registry row (a restored or hand-made dir) is
        still covered — with the bundle's retention."""
        rows: dict[str, Optional[int]] = {}
        # Strict: a tenant's own (longer) retention that cannot be read must
        # not silently become "none".
        try:
            conn = _connect(registry, read_only=True)
            try:
                for slug, days in conn.execute(
                    "SELECT slug, retention_days FROM clients"
                ):
                    rows[slug] = int(days) if days is not None else None
            finally:
                conn.close()
        except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
            raise _RegistryUnavailable(
                f"clients.retention_days unreadable: {type(exc).__name__}: {exc}") from exc
        clients = self.data_root / "clients"
        found: list[tuple[str, Optional[int]]] = []
        if clients.is_dir():
            for child in sorted(clients.iterdir()):
                if not child.is_dir():
                    continue
                try:
                    paths.validate_slug(child.name)
                except ValueError:
                    continue
                if only and child.name not in only:
                    continue
                found.append((child.name, rows.get(child.name)))
        return found

    def _record_start(self, registry: Path, report: RunReport) -> None:
        try:
            conn = _connect(registry)
            try:
                conn.execute(
                    "INSERT INTO retention_runs (run_id, started_at, trigger, status, "
                    " archive_enabled) VALUES (?, ?, ?, 'running', ?)",
                    (report.run_id, report.started_at, report.trigger,
                     1 if report.archive.get("enabled") else 0),
                )
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.warning("[retention] run start not recorded (%s)", type(exc).__name__)

    def _record_finish(self, registry: Path, report: RunReport) -> None:
        summary = {
            "mode": report.mode,
            "archive": report.archive,
            "note": report.note,
            "run_audit_row_id": report.audit_row_id,
            "tenants": {
                t.slug: {
                    "error": t.error,
                    "audit_row_id": t.audit_row_id,
                    "sweep_moved": t.sweep.get("moved", 0),
                    "sweep_error": t.sweep.get("error"),
                    "arrival": t.arrival,
                    # The resume point of the next sweep: only a sweep that
                    # finished without error advances it — and never past a
                    # row an evidence window kept (moved once released).
                    "sweep_through_id": _sweep_resume(t.sweep),
                    "evidence_kept": t.evidence.get("kept", {}),
                    "classes": {
                        k: {"status": c.status, "planned": c.planned,
                            "deleted": c.deleted, "held": c.held,
                            "referenced": c.referenced, "evidence": c.evidence,
                            "effective_days": c.effective_days, "basis": c.basis,
                            "cutoff": c.cutoff}
                        for k, c in t.classes.items()
                    },
                    "vacuum": t.vacuum,
                }
                for t in report.tenants
            },
        }
        errors = [f"{t.slug}: {t.error}" for t in report.tenants if t.error]
        try:
            conn = _connect(registry)
            try:
                conn.execute(
                    "UPDATE retention_runs SET finished_at = ?, status = ?, tenants = ?, "
                    " deleted_total = ?, summary_json = ?, error = ? WHERE run_id = ?",
                    (report.finished_at, report.status, len(report.tenants), report.deleted_total,
                     json.dumps(summary, sort_keys=True),
                     ("; ".join(errors) or report.note or None), report.run_id),
                )
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.warning("[retention] run finish not recorded (%s)", type(exc).__name__)

    def _archive_status(self) -> dict:
        return archive_status(self.archive, from_env=False)

    def _load_sweep_marks(self, registry: Path) -> dict[str, int]:
        """slug → the highest events.db id its last completed sweep covered
        (newest run that has one). Unreadable → {} (the sweep then looks
        back SWEEP_DAYS — the safe, pre-mark behaviour)."""
        marks: dict[str, int] = {}
        try:
            conn = _connect(registry, read_only=True)
            try:
                rows = conn.execute(
                    "SELECT summary_json FROM retention_runs WHERE finished_at IS NOT NULL "
                    "ORDER BY started_at DESC, id DESC LIMIT ?", (SWEEP_MARK_RUNS,),
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return {}
        for (summary_json,) in rows:
            try:
                tenants = (json.loads(summary_json or "{}") or {}).get("tenants") or {}
            except ValueError:
                continue
            for slug, t in tenants.items():
                through = (t or {}).get("sweep_through_id")
                if slug not in marks and isinstance(through, int):
                    marks[slug] = through
        return marks

    # ----- one tenant -----

    def _raw_cutoff(self, policies: dict[str, ClassPolicy], now: datetime) -> Optional[str]:
        """telemetry_raw's cutoff (whole UTC days), None when not enforced."""
        policy = policies.get("telemetry_raw") or _fallback_policy("telemetry_raw")
        eff = effective_retention(policy)
        if eff.days is None:
            return None
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return _utc(midnight - timedelta(days=eff.days))

    def _sweep(
        self, result: TenantResult, now: datetime, dry_run: bool, raw_cutoff: Optional[str],
    ) -> None:
        mark = self._sweep_marks.get(result.slug)
        since = (
            _utc(now - timedelta(days=self.sweep_days)) if self.sweep_days is not None else None
        )
        report = telemetry_move.move_tenant(
            result.slug, data_root=self.data_root, dry_run=dry_run,
            since=since, since_id=mark if self.sweep_days is not None else None,
            count_before=raw_cutoff if dry_run else None,
            batch_size=self.move_batch, now=_utc(now),
        )
        result.sweep = report.as_dict()

    def _arrival_state(self, client_dir: Path, dry_run: bool) -> dict:
        """Step 0 for one tenant: is its arrival backfill pending? A real run
        also finishes the cheap parts itself — the column on an EMPTY pre-036
        table, and the index once nothing is left to stamp (the table then
        holds only rows stamped from 036 on: signals, a small scan)."""
        db = _db_for(client_dir, "events")
        if not db.exists():
            return {"pending": False}
        conn = _connect(db, read_only=dry_run)
        try:
            if not _has_table(conn, "events"):
                return {"pending": False}
            if (not dry_run and not arrival.has_column(conn)
                    and conn.execute("SELECT 1 FROM events LIMIT 1").fetchone() is None):
                arrival.add_column(conn)
            if arrival.pending(conn):
                return {"pending": True, "note": BACKFILL_PENDING_NOTE}
            out: dict = {"pending": False}
            if arrival.has_column(conn) and not arrival.has_index(conn):
                if dry_run:
                    out["index_to_build"] = True
                else:
                    arrival.ensure_index(conn)
                    out["index_built"] = True
            return out
        finally:
            conn.close()

    @staticmethod
    def _held_windows(client_dir: Path) -> tuple[list[evidence.Window], Optional[str]]:
        """Step 0b: the tenant's held evidence windows — or, when they cannot
        be read, why nothing of it may be pruned."""
        try:
            return evidence.held(client_dir, timeout=BUSY_TIMEOUT_SEC), None
        except evidence.WindowsUnavailable as exc:
            logger.error("[retention] %s: evidence windows unreadable (%s)", client_dir.name, exc)
            return [], WINDOWS_UNREADABLE

    @staticmethod
    def _windows_now(client_dir: Path,
                     planned: list[evidence.Window]) -> list[evidence.Window]:
        """The windows a delete batch must keep: those held at planning (what
        was planned and audited is the most that goes) AND those held now (a
        window opened since holds at once). Raises WindowsUnavailable."""
        return evidence.union(planned, evidence.held(client_dir, timeout=BUSY_TIMEOUT_SEC))

    def _evidence_notices(self, report: RunReport, now: datetime) -> None:
        """Tell each tenant's admins (never release anything): the disk is
        getting full while its held windows keep rows past their retention
        (daily), or windows are still held long after their all-clear
        (weekly). Best effort — a notice that cannot be sent never fails
        the run."""
        try:
            usage = shutil.disk_usage(self.data_root)
            free_pct: Optional[float] = (usage.free * 100.0 / usage.total) if usage.total else None
        except OSError:
            free_pct = None
        low = free_pct is not None and free_pct < EVIDENCE_DISK_WARN_FREE_PCT
        stale_before = _utc(now - timedelta(days=EVIDENCE_REMIND_AFTER_DAYS))
        day, week = _utc(now)[:10], now.strftime("%G-W%V")
        for t in report.tenants:
            wins = list(t.evidence.get("windows") or [])
            if not wins:
                continue
            kept = {str(k): int(v) for k, v in (t.evidence.get("kept") or {}).items()}

            def line(w: dict) -> str:
                return (f"window #{w['id']} (incident #{w['incident_id']}): {w['start']} → "
                        f"{w.get('end') or 'open'}, {kept.get(str(w['id']), 0)} row(s) kept past "
                        "retention")

            keeping = [w for w in wins if kept.get(str(w["id"]), 0) > 0]
            stale = [w for w in wins if w.get("end") and str(w["end"]) < stale_before]
            sends = []
            if low and keeping:
                sends.append((
                    "disk", f"evw-disk:{t.slug}:{day}",
                    f"Disk {free_pct:.0f}% free — evidence windows are keeping data",
                    f"The data volume has {free_pct:.1f}% free. These evidence windows keep this "
                    "client's data past its normal retention until an admin releases them (a "
                    "full disk stops ingestion): " + "; ".join(line(w) for w in keeping)
                    + ". Nothing is released automatically — review them in Settings → Threats.",
                    keeping))
            if stale:
                sends.append((
                    "held", f"evw-held:{t.slug}:{week}",
                    f"{len(stale)} evidence window(s) still held {EVIDENCE_REMIND_AFTER_DAYS}+ "
                    "days after their end",
                    "Still held after their end (the all-clear): "
                    + "; ".join(line(w) for w in stale)
                    + ". They are kept until an admin releases them (Settings → Threats) — "
                    "release them once the evidence is no longer needed.",
                    stale))
            for kind, request_id, title, body, which in sends:
                try:
                    from apps.octo.threat import notify

                    notify.notify_admins(kind="threat_registry", slug=t.slug, title=title,
                                         body=body, request_id=request_id)
                    report.evidence_notices.append({
                        "tenant": t.slug, "kind": kind, "request_id": request_id,
                        "windows": [w["id"] for w in which]})
                except Exception as exc:  # noqa: BLE001 — never fails the run
                    logger.warning("[retention] %s: evidence notice not sent (%s)",
                                   t.slug, type(exc).__name__)

    @staticmethod
    def _evidence_note(cr: ClassResult, windows: list[evidence.Window],
                       per_window: dict[int, int]) -> None:
        if not cr.evidence:
            return
        ids = sorted({w.incident_id for w in windows if per_window.get(w.id)})
        text = (f"{cr.evidence} expired row(s) kept: inside an evidence window (incident "
                + (", ".join(f"#{i}" for i in ids) or "—") + ")")
        cr.note = f"{cr.note}; {text}" if cr.note else text

    def _tenant(
        self, result: TenantResult, policies: dict[str, ClassPolicy],
        tenant_days: Optional[int], now: datetime, dry_run: bool, report: RunReport,
    ) -> None:
        # Contained and symlink-free (spec §2.3) before anything is read: a
        # refused directory is this tenant's error, nothing of it is touched.
        client_dir = paths.client_dir(result.slug, root=self.data_root)
        raw_cutoff = self._raw_cutoff(policies, now)

        # 0) arrival — the backfill's own run (sweep over everything) is
        # never gated: it is what clears the gate.
        result.arrival = (
            self._arrival_state(client_dir, dry_run) if self.sweep_days is not None
            else {"pending": False, "backfill_run": True}
        )
        gated = bool(result.arrival.get("pending"))
        # 0b) evidence windows — what lies inside one is kept by every class;
        # unreadable, nothing of the tenant is swept or pruned.
        windows, unreadable = self._held_windows(client_dir)
        result.evidence = {"windows": [w.as_dict() for w in windows], "kept": {}}
        if unreadable:
            result.evidence["error"] = unreadable

        # 1) sweep (it leaves in-window rows in events.db — `retention.move`)
        if unreadable:
            result.sweep = {"skipped": True, "note": unreadable}
        elif gated:
            result.sweep = {"skipped": True, "note": BACKFILL_PENDING_NOTE}
        else:
            self._sweep(result, now, dry_run, raw_cutoff)

        # 2) plan
        plans: dict[str, tuple[ClassResult, dict]] = {}
        kept: dict[int, int] = {}
        for data_class in CLASS_ORDER:
            if self._classes is not None and data_class not in self._classes:
                cr, detail = ClassResult(data_class, "-", "skipped",
                                         note="not part of this run"), {}
            elif unreadable and data_class in EVIDENCE_GATED:
                cr, detail = ClassResult(data_class, _CLASS_STORE.get(data_class, "entities"),
                                         "blocked", note=unreadable), {}
            elif gated and data_class in ARRIVAL_GATED:
                store = "events" if data_class == "events" else "telemetry"
                cr, detail = ClassResult(data_class, store, "blocked",
                                         note=BACKFILL_PENDING_NOTE), {}
            else:
                cr, detail = self._plan_class(
                    client_dir, data_class, policies, tenant_days, now, windows,
                )
                per = detail.pop("per_window", {}) if isinstance(detail, dict) else {}
                evidence.merge_counts(kept, per)
                self._evidence_note(cr, windows, per)
            result.classes[data_class] = cr
            plans[data_class] = (cr, detail)
        result.evidence["kept"] = {str(k): v for k, v in sorted(kept.items())}

        # A dry run did not move what the sweep would move: raw rows it
        # would copy that are already past the cutoff are pruned by the real
        # run in the same pass — count them, so the preview is the run.
        raw_cr, raw_detail = plans["telemetry_raw"]
        if dry_run and raw_cr.status == "ok" and raw_cr.cutoff:
            days = raw_detail.setdefault("days", {})
            for day, n in (result.sweep.get("would_copy_before") or {}).items():
                entry = days.setdefault(day, {"count": 0, "max_id": 0})
                entry["count"] += int(n)
                raw_cr.planned += int(n)

        # 3) archive (raw telemetry) — the rows the prune will take, never
        # the ones a window keeps
        allowed_days = self._archive_raw(
            client_dir, result, raw_cr, raw_detail, dry_run, report, windows,
        )

        if dry_run:
            return

        # 4) audit — before any delete; only a tenant with something to
        # delete gets a row of its own (the run's summary row lists the rest).
        if result.planned > 0:
            result.audit_row_id = self._audit(result, report)

        # 5) delete — every class is attempted; a failure is that class's
        # error, recorded in the result row below. Every delete batch keeps
        # the rows inside a window held at planning OR now.
        def fresh() -> list[evidence.Window]:
            return self._windows_now(client_dir, windows)

        touched: set[str] = set()
        for data_class in CLASS_ORDER:
            cr, detail = plans[data_class]
            # 'blocked' = raw telemetry whose archive failed for SOME days:
            # the days that did archive are still pruned.
            if cr.status not in ("ok", "blocked") or cr.planned == 0:
                continue
            try:
                if data_class == "telemetry_raw":
                    cr.deleted = self._delete_raw(client_dir, detail, allowed_days, fresh)
                elif data_class == "telemetry_rollup":
                    cr.deleted = sum(
                        self._delete_keyed(
                            _db_for(client_dir, "telemetry"), table, key,
                            "last_arrival < ?", [cr.cutoff], fresh,
                        )
                        for table, key in ROLLUP_TABLES
                        if _table_exists(_db_for(client_dir, "telemetry"), table)
                    )
                elif data_class == "first_seen_domains":
                    cr.deleted = self._delete_keyed(
                        _db_for(client_dir, "telemetry"), "first_seen_domains",
                        "domain", "last_seen < ?", [cr.cutoff], fresh,
                    )
                elif data_class in ENTITY_CLASSES:
                    from apps.octo.entity import retention as entity_retention

                    cr.deleted = entity_retention.prune(
                        _db_for(client_dir, "entities"), data_class, cr.cutoff, now,
                        batch=self.batch_size, windows=fresh,
                    )
                else:
                    spec = _SPECS[data_class]
                    cr.deleted = self._delete_spec(client_dir, spec, cr.cutoff, detail["max_id"],
                                                   windows, fresh)
            except references.ReferencesUnavailable as exc:
                cr.status = "error"
                cr.note = f"references unreadable — nothing deleted: {exc}"
            except evidence.WindowsUnavailable as exc:
                cr.status = "error"
                cr.note = f"evidence windows unreadable — nothing more deleted: {exc}"
            except Exception as exc:  # noqa: BLE001 — recorded, the other classes go on
                cr.status = "error"
                cr.note = f"{type(exc).__name__}: {exc}"
            if cr.deleted:
                touched.add(cr.store)

        # What each window kept, on the window (the console's "rows kept").
        if windows:
            try:
                evidence.record_kept(client_dir, kept, windows, _utc(now),
                                     timeout=BUSY_TIMEOUT_SEC)
            except sqlite3.Error as exc:
                result.evidence["record_error"] = f"{type(exc).__name__}"
                logger.warning("[retention] %s: kept rows not recorded on the windows (%s)",
                               result.slug, type(exc).__name__)

        # 6) reclaim (what actually happened goes on the chain in the run's
        # summary row, after every tenant)
        for store in sorted(touched | {"telemetry"}):
            db = _db_for(client_dir, store)
            if db.exists():
                try:
                    result.vacuum[store] = self._reclaim(db)
                except sqlite3.Error as exc:
                    result.vacuum[store] = {"error": f"{type(exc).__name__}: {exc}"}

    # ----- planning -----

    def _plan_class(
        self, client_dir: Path, data_class: str, policies: dict[str, ClassPolicy],
        tenant_days: Optional[int], now: datetime,
        windows: Optional[list[evidence.Window]] = None,
    ) -> tuple[ClassResult, dict]:
        """One class's plan: the rows that expire and may go — never one
        inside an evidence window (`windows`, held at planning), which is
        counted as `evidence` instead (and per window, in the returned
        detail's `per_window`)."""
        windows = list(windows or [])
        if data_class == "first_seen_domains":
            cr = ClassResult(
                data_class, "telemetry", "ok", effective_days=FIRST_SEEN_FORGET_DAYS,
                basis="fixed", cutoff=_utc(now - timedelta(days=FIRST_SEEN_FORGET_DAYS)),
                note="domains not seen for a year are forgotten (their return is new again)",
            )
            per: dict[int, int] = {}
            self._count_keyed(cr, _db_for(client_dir, "telemetry"), "first_seen_domains",
                              "last_seen < ?", windows, per)
            return cr, {"per_window": per}
        policy = policies.get(data_class) or _fallback_policy(data_class)
        eff: EffectiveRetention = effective_retention(policy, tenant_days=tenant_days)
        store = {
            "secure_notepad": "tickets", "audit": "audit",
            "telemetry_raw": "telemetry", "telemetry_rollup": "telemetry",
            **{c: "entities" for c in ENTITY_CLASSES},
        }.get(data_class) or _SPECS[data_class].store
        cr = ClassResult(
            data_class, store, "ok", effective_days=eff.days, basis=eff.basis,
            configured_days=eff.configured_days,
            legal_baseline_days=eff.legal_baseline_days, tenant_days=eff.tenant_days,
        )
        if eff.days is None:
            cr.status = "permanent"
            cr.note = "never pruned"
            return cr, {}
        if data_class == "secure_notepad":
            cr.status = "no_store"
            cr.note = "no secure-notepad table exists yet; nothing to prune"
            return cr, {}
        if data_class in ENTITY_CLASSES:
            from apps.octo.entity import retention as entity_retention

            cr.cutoff = _utc(now - timedelta(days=eff.days))
            try:
                cr.planned, cr.evidence, per = entity_retention.count_with_evidence(
                    _db_for(client_dir, "entities"), data_class, cr.cutoff, now, windows)
            except sqlite3.Error as exc:
                cr.status = "error"
                cr.note = f"entities.db unreadable — nothing deleted: {type(exc).__name__}"
                return cr, {}
            return cr, {"per_window": per}
        if data_class == "telemetry_raw":
            # Whole UTC days only: a day's rows are archived in one file and
            # pruned together.
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            cr.cutoff = _utc(midnight - timedelta(days=eff.days))
            return self._plan_raw(cr, _db_for(client_dir, "telemetry"), windows)
        if data_class == "telemetry_rollup":
            # By ARRIVAL (the latest sighting folded into the hour row), on
            # whole hours.
            hour = now.replace(minute=0, second=0, microsecond=0)
            cr.cutoff = _utc(hour - timedelta(days=eff.days))
            per = {}
            for table, _key in ROLLUP_TABLES:
                part = self._count_keyed(
                    ClassResult(cr.data_class, cr.store, cr.status, cutoff=cr.cutoff),
                    _db_for(client_dir, "telemetry"), table, "last_arrival < ?", windows, per,
                )
                cr.planned += part.planned
                cr.evidence += part.evidence
            return cr, {"per_window": per}
        cr.cutoff = _utc(now - timedelta(days=eff.days))
        spec = _SPECS[data_class]
        db = _db_for(client_dir, spec.store)
        if not db.exists():
            cr.note = f"no {spec.store}.db"
            return cr, {"max_id": 0}
        held_ids: set[int] = set()
        if spec.evidence:
            try:
                held_ids = references.ticket_references(client_dir, timeout=BUSY_TIMEOUT_SEC)
            except references.ReferencesUnavailable as exc:
                cr.status = "error"
                cr.note = f"references unreadable — nothing deleted: {exc}"
                return cr, {"max_id": 0}
        conn = _connect(db, read_only=True)
        per = {}
        try:
            if not _has_table(conn, spec.table):
                cr.note = f"no {spec.table} table"
                return cr, {"max_id": 0}
            if spec.data_class == "events" and not arrival.has_column(conn):
                # An empty pre-036 table in a dry run (a real run adds it).
                cr.note = "no arrival column yet (nothing stored)"
                return cr, {"max_id": 0}
            where = spec.where.replace(":cutoff", "?")
            evidence.load_temp(conn, windows)
            in_window = evidence.held_expr(spec.store, spec.table)
            referenced = "0"
            if spec.evidence:
                references.load_held(conn, held_ids)
                referenced = references.referenced_expr(conn, spec.table)
            # Disjoint: cited evidence first, then window evidence, then
            # what may go.
            count, max_id, held, kept = conn.execute(
                f"SELECT COALESCE(SUM(NOT {referenced} AND NOT {in_window}), 0), "
                f"       COALESCE(MAX(CASE WHEN NOT {referenced} AND NOT {in_window} "
                f"                         THEN id END), 0), "
                f"       COALESCE(SUM({referenced}), 0), "
                f"       COALESCE(SUM(NOT {referenced} AND {in_window}), 0) "
                f"FROM {spec.table} WHERE {where}",
                (cr.cutoff,),
            ).fetchone()
            cr.referenced, cr.evidence = int(held), int(kept)
            if cr.referenced:
                cr.note = (f"{cr.referenced} expired row(s) held: a ticket, agent note, "
                           "pattern link or incident cites them")
            if cr.evidence:
                per = evidence.per_window(conn, spec.store, spec.table,
                                          f"{where} AND NOT {referenced}", (cr.cutoff,))
        finally:
            conn.close()
        cr.planned = int(count)
        return cr, {"max_id": int(max_id), "per_window": per}

    def _plan_raw(self, cr: ClassResult, db: Path,
                  windows: Optional[list[evidence.Window]] = None) -> tuple[ClassResult, dict]:
        if not db.exists():
            return cr, {"days": {}}
        conn = _connect(db, read_only=True)
        per: dict[int, int] = {}
        try:
            evidence.load_temp(conn, windows or [])
            in_window = evidence.held_expr("telemetry", "telemetry_raw")
            rows = conn.execute(
                "SELECT substr(ingested_at, 1, 10) AS day, COUNT(*), MAX(id) "
                f"FROM telemetry_raw WHERE ingested_at < ? AND NOT {in_window} "
                "GROUP BY day ORDER BY day",
                (cr.cutoff,),
            ).fetchall()
            if windows:
                cr.evidence = int(conn.execute(
                    f"SELECT COUNT(*) FROM telemetry_raw WHERE ingested_at < ? AND {in_window}",
                    (cr.cutoff,)).fetchone()[0])
                if cr.evidence:
                    per = evidence.per_window(conn, "telemetry", "telemetry_raw",
                                              "ingested_at < ?", (cr.cutoff,))
        finally:
            conn.close()
        days = {day: {"count": int(n), "max_id": int(mx)} for day, n, mx in rows}
        cr.planned = sum(d["count"] for d in days.values())
        return cr, {"days": days, "per_window": per}

    def _count_keyed(self, cr: ClassResult, db: Path, table: str, where: str,
                     windows: Optional[list[evidence.Window]] = None,
                     per: Optional[dict[int, int]] = None) -> ClassResult:
        """Count `table`'s expired rows that may go (`planned`) and those an
        evidence window keeps (`evidence`, added per window into `per`)."""
        if not db.exists():
            return cr
        conn = _connect(db, read_only=True)
        try:
            if not _has_table(conn, table):
                return cr
            evidence.load_temp(conn, windows or [])
            in_window = evidence.held_expr("telemetry", table)
            planned, kept = conn.execute(
                f"SELECT COALESCE(SUM(NOT {in_window}), 0), COALESCE(SUM({in_window}), 0) "
                f"FROM {table} WHERE {where}", (cr.cutoff,),
            ).fetchone()
            cr.planned, cr.evidence = int(planned), int(kept)
            if cr.evidence and per is not None:
                evidence.merge_counts(per, evidence.per_window(
                    conn, "telemetry", table, where, (cr.cutoff,)))
        finally:
            conn.close()
        return cr

    # ----- archive -----

    def _archive_raw(
        self, client_dir: Path, result: TenantResult, cr: ClassResult, detail: dict,
        dry_run: bool, report: RunReport,
        windows: Optional[list[evidence.Window]] = None,
    ) -> set[str]:
        """Archive every expired day — the rows its prune takes, never the
        ones an evidence window keeps (they stay in telemetry.db: the archive
        gets them when they go, after the window's release); return the days
        that may be pruned."""
        windows = list(windows or [])
        days: dict[str, dict] = detail.get("days", {})
        summary = {
            "enabled": self.archive is not None, "days": [], "failed_days": [],
            "rows_archived": 0,
            "encrypted": bool(self.archive is not None and self.archive.encryption.active),
        }
        if self.archive is not None and not self.archive.encryption.required:
            summary["encryption_note"] = self.archive.encryption.note()
        result.archive = summary
        if not days:
            return set()
        if self.archive is None:
            summary["note"] = "archive disabled (OCTO_ARCHIVE_ROOT unset): pruned without a copy"
            summary["days"] = sorted(days)
            return set(days)
        unusable = self.archive.unusable_reason()
        if unusable:
            summary["failed_days"] = sorted(days)
            summary["error"] = unusable
            cr.status = "blocked"
            cr.held, cr.planned = cr.planned, 0
            cr.note = f"archive unusable — nothing pruned: {unusable}"
            return set()
        if dry_run:
            summary["days"] = sorted(days)
            summary["rows_to_archive"] = cr.planned
            return set(days)
        allowed: set[str] = set()
        db = _db_for(client_dir, "telemetry")
        for day in sorted(days):
            bound = days[day]["max_id"]
            added = 0
            try:
                # In chunks, so memory stays bounded on a large day. What the
                # day already holds (plaintext ids, the encrypted parts'
                # ledger) is read ONCE, then carried from chunk to chunk
                # (this run holds the lock: no other writer). Plaintext: each
                # chunk is one atomic append (a failure leaves the file as
                # the previous chunk left it, and the day is not pruned).
                # Encrypted: the chunks become ONE new part at finish().
                writer = self.archive.day_writer(result.slug, day)
                last_id = 0
                while True:
                    chunk = self._raw_rows(db, day, last_id, bound, windows)
                    if not chunk:
                        break
                    last_id = chunk[-1]["id"]
                    writer.add(chunk)
                added = writer.finish().rows_added
            except (ArchiveError, sqlite3.Error, OSError) as exc:
                summary["failed_days"].append(day)
                summary.setdefault("errors", []).append(f"{day}: {exc}")
                cr.held += days[day]["count"]
                continue
            allowed.add(day)
            summary["days"].append(day)
            summary["rows_archived"] += added
        if summary["failed_days"]:
            cr.status = "blocked"
            cr.note = (
                f"archive write failed for {len(summary['failed_days'])} day(s) — "
                "those rows were NOT pruned"
            )
            cr.planned -= cr.held
        return allowed

    def _raw_rows(self, db: Path, day: str, after_id: int, bound: int,
                  windows: Optional[list[evidence.Window]] = None) -> list[dict]:
        """One chunk of a day's raw rows (ids in (after_id, bound]) outside
        every evidence window held at planning, as the archive stores them."""
        conn = _connect(db, read_only=True)
        try:
            conn.row_factory = sqlite3.Row
            evidence.load_temp(conn, windows or [])
            keep = evidence.guard("telemetry", "telemetry_raw")
            return [
                {
                    "id": r["id"], "received_at": r["received_at"],
                    "ingested_at": r["ingested_at"],
                    "source": r["source"], "event_type": r["event_type"],
                    "severity": r["severity"], "source_host": r["source_host"],
                    "domain": r["domain"], "device": r["device"],
                    "device_name": r["device_name"],
                    "payload": r["payload"],
                    "payload_truncated": bool(r["payload_truncated"]),
                    "payload_sha256": r["payload_sha256"],
                    "origin_event_id": r["origin_event_id"],
                }
                for r in conn.execute(
                    "SELECT * FROM telemetry_raw WHERE ingested_at >= ? "
                    "AND ingested_at < ? AND substr(ingested_at, 1, 10) = ? "
                    f"AND id > ? AND id <= ?{keep} ORDER BY id LIMIT ?",
                    (day, _next_day(day), day, after_id, bound, self.archive_chunk),
                )
            ]
        finally:
            conn.close()

    # ----- audit -----

    def _reason(self, report: RunReport) -> str:
        reason = (report.initiated_by or {}).get("reason") or (
            "scheduled retention enforcement" if report.trigger == "scheduler"
            else "retention enforcement"
        )
        return str(reason)[:500]

    def _append(self, entry_kw: dict) -> int:
        from apps.octo.auth import audit

        try:
            g = _connect(self.data_root / "global" / "audit.db")
            try:
                g.row_factory = sqlite3.Row
                return audit.append(g, audit.AuditEntry(
                    actor=ACTOR, actor_kind="system", **entry_kw))
            finally:
                g.close()
        except Exception as exc:  # noqa: BLE001
            raise _AuditFailed(f"{type(exc).__name__}: {exc}") from exc

    def _audit(self, result: TenantResult, report: RunReport) -> int:
        """The tenant's PLAN, before any of its deletes."""
        after = {
            "run_id": report.run_id,
            "trigger": report.trigger,
            "initiated_by": report.initiated_by,
            "classes": {
                k: {
                    "status": c.status, "planned": c.planned, "held": c.held,
                    "referenced": c.referenced, "evidence": c.evidence,
                    "cutoff": c.cutoff, "effective_days": c.effective_days,
                    "basis": c.basis, "configured_days": c.configured_days,
                    "legal_baseline_days": c.legal_baseline_days,
                    "tenant_days": c.tenant_days,
                }
                for k, c in result.classes.items()
            },
            "archive": {
                "enabled": result.archive.get("enabled"),
                "encrypted": result.archive.get("encrypted", False),
                "days": result.archive.get("days", []),
                "failed_days": result.archive.get("failed_days", []),
                "rows_archived": result.archive.get("rows_archived", 0),
                "note": (result.archive.get("note") or result.archive.get("error")
                         or result.archive.get("encryption_note")),
            },
            "sweep": {
                "moved": result.sweep.get("moved", 0),
                "deleted": result.sweep.get("deleted", 0),
                "error": result.sweep.get("error"),
                "kept_evidence": result.sweep.get("kept_evidence", 0),
            },
            # The evidence windows the plan kept (first detection → the
            # all-clear, held until released) and the expired rows each kept.
            "evidence_windows": result.evidence.get("windows", []),
            "evidence_kept": result.evidence.get("kept", {}),
        }
        return self._append(dict(
            action=AUDIT_ACTION, target_kind="client", target_id=result.slug,
            client_slug=result.slug, after_state=after,
            reason=self._reason(report), request_id=report.run_id,
        ))

    @staticmethod
    def _tenant_outcome(t: TenantResult) -> dict:
        """What actually happened for one tenant — the classes where
        something did (or could not) happen."""
        return {
            "plan_audit_row_id": t.audit_row_id,
            "deleted": t.deleted,
            "error": t.error,
            "sweep": {
                "moved": t.sweep.get("moved", 0),
                "deleted": t.sweep.get("deleted", 0),
                "error": t.sweep.get("error"),
                "skipped": bool(t.sweep.get("skipped")),
            },
            "arrival_pending": bool(t.arrival.get("pending")),
            "classes": {
                k: {
                    "status": c.status, "planned": c.planned, "deleted": c.deleted,
                    "held": c.held, "referenced": c.referenced, "evidence": c.evidence,
                    "error": c.note if c.status in ("error", "blocked") else None,
                }
                for k, c in t.classes.items()
                if c.planned or c.deleted or c.held or c.referenced or c.evidence
                or c.status in ("error", "blocked")
            },
            "evidence_kept": t.evidence.get("kept", {}),
            "evidence_error": t.evidence.get("error"),
        }

    @classmethod
    def _idle(cls, t: TenantResult) -> bool:
        out = cls._tenant_outcome(t)
        return (not out["classes"] and not out["error"] and not out["sweep"]["moved"]
                and not out["sweep"]["deleted"] and not out["sweep"]["error"]
                and not out["arrival_pending"] and not out["evidence_error"]
                and not t.evidence.get("windows"))

    def _audit_run(self, report: RunReport) -> int:
        """The run's ONE summary row, after every tenant (request_id = run
        id, so it and the tenants' plan rows read as one unit)."""
        after = {
            "run_id": report.run_id,
            "status": report.status,
            "trigger": report.trigger,
            "initiated_by": report.initiated_by,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "archive": {k: report.archive.get(k)
                        for k in ("enabled", "root", "usable", "encrypted", "encryption_note")},
            "deleted_total": report.deleted_total,
            "tenants": {
                t.slug: self._tenant_outcome(t) for t in report.tenants if not self._idle(t)
            },
            "idle_tenants": sorted(t.slug for t in report.tenants if self._idle(t)),
            "note": report.note or None,
        }
        return self._append(dict(
            action=AUDIT_RUN_ACTION, target_kind="retention_run", target_id=report.run_id,
            client_slug="global", after_state=after,
            reason=self._reason(report), request_id=report.run_id,
        ))

    # ----- deletes -----

    def _batches(
        self, db: Path, *, table: str, key: tuple[str, ...], where: str, params: list,
        seek: Optional[str] = None, seek_from: Optional[str] = None,
        prepare: Optional[Callable[[sqlite3.Connection], str]] = None,
        refresh: Optional[Callable[[sqlite3.Connection], None]] = None,
    ) -> int:
        """Delete `table`'s rows matching `where` (and `seek >= seek_from`)
        and the guard `prepare` returns (references, evidence windows — SQL
        without parameters) in batches of `batch_size`, KEYSET-paginated:

          1. pick: the next batch of candidate keys AFTER the last one
             picked — a plain read, OUTSIDE any write lock (every store is
             WAL: a reader never holds up ingest). In `(seek, key)` order
             when `seek` (the column `where` bounds) has an index — the
             index range is walked once, from where the last pick stopped —
             else in `key` order (the rowid / the primary key);
          2. delete: one short BEGIN IMMEDIATE that re-reads the windows
             (`refresh`) and deletes exactly those keys that STILL match
             `where` and the guard.

        Under the write lock a batch examines at most `batch_size` rows,
        however many expired rows an evidence window keeps: they are passed
        over once per run, in step 1, and never looked at again by a later
        batch (the run is one pass over the range)."""
        one = len(key) == 1
        key_cols = ", ".join(key)
        key_value = key[0] if one else f"({key_cols})"
        key_marks = "?" if one else "(" + ", ".join("?" * len(key)) + ")"
        total = 0
        conn = _connect(db)
        try:
            ordered = seek is not None and _index_leads_with(conn, table, seek)
            order = ", ".join(((seek,) if ordered else ()) + key)
            lower = f" AND {seek} >= ?" if seek is not None and seek_from is not None else ""
            lower_params = [seek_from] if lower else []
            guard = prepare(conn) if prepare else ""
            if refresh is not None:
                refresh(conn)
            last: Optional[tuple] = None
            while True:
                if last is None:
                    pick_where = f"({where}){lower}"
                    pick_params = [*params, *lower_params]
                elif ordered:
                    # (seek, key) > the last pick's — the seek column
                    # bounded on its own so the index seeks straight there.
                    pick_where = (f"({where}) AND {seek} >= ? AND ({seek} > ? OR "
                                  f"{key_value} > {key_marks})")
                    pick_params = [*params, last[0], last[0], *last[1:]]
                else:
                    pick_where = f"({where}){lower} AND {key_value} > {key_marks}"
                    pick_params = [*params, *lower_params, *last]
                rows = [tuple(r) for r in conn.execute(
                    f"SELECT {order} FROM {table} WHERE {pick_where}{guard} "
                    f"ORDER BY {order} LIMIT ?", [*pick_params, self.batch_size]).fetchall()]
                if not rows:
                    return total
                last = rows[-1]
                picked = [r[1:] for r in rows] if ordered else rows
                if one:
                    chosen = f"{key[0]} IN ({','.join('?' * len(picked))})"
                    flat = [r[0] for r in picked]
                else:
                    chosen = f"({key_cols}) IN (VALUES {','.join([key_marks] * len(picked))})"
                    flat = [v for r in picked for v in r]
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if refresh is not None:
                        refresh(conn)
                    n = conn.execute(
                        f"DELETE FROM {table} WHERE {chosen} AND ({where}){lower}{guard}",
                        [*flat, *params, *lower_params]).rowcount
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                total += max(0, n)
                if len(rows) < self.batch_size:
                    return total
        finally:
            conn.close()

    @staticmethod
    def _window_refresh(
        fresh: Optional[Callable[[], list[evidence.Window]]],
        planned: Optional[list[evidence.Window]] = None,
    ) -> Callable[[sqlite3.Connection], None]:
        """Before every batch's delete: the windows held at planning AND now
        (`fresh` — parked ones included; else the planned ones), into the
        deleting connection's temp copy."""
        def refresh(conn: sqlite3.Connection) -> None:
            evidence.load_temp(conn, fresh() if fresh is not None else list(planned or []))
        return refresh

    def _delete_spec(
        self, client_dir: Path, spec: _Spec, cutoff: str, max_id: int,
        windows: Optional[list[evidence.Window]] = None,
        fresh: Optional[Callable[[], list[evidence.Window]]] = None,
    ) -> int:
        where = spec.where.replace(":cutoff", "?") + " AND id <= ?"
        planned = list(windows or [])
        held_ids: set[int] = set()
        if spec.evidence:
            # tickets.db's citations re-read NOW (not at planning), into a
            # temp table; events.db's own references are re-checked inside
            # every DELETE, under its write lock.
            held_ids = references.ticket_references(client_dir, timeout=BUSY_TIMEOUT_SEC)
        on_events_db = spec.store == "events"

        def prepare(conn: sqlite3.Connection) -> str:
            out = ""
            if spec.evidence:
                references.load_held(conn, held_ids)
                out = references.events_db_guard(conn, spec.table)
            # The windows held at planning (temp; re-read with those held now
            # before every delete — parked ones included) — and, in
            # events.db, the LIVE table, inside every DELETE under its write
            # lock (a window opened a moment ago holds at once).
            evidence.load_temp(conn, planned)
            return out + evidence.guard(spec.store, spec.table,
                                        live_table=on_events_db and evidence.live(conn))

        return self._batches(
            _db_for(client_dir, spec.store), table=spec.table, key=("id",), where=where,
            params=[cutoff, max_id], prepare=prepare,
            refresh=self._window_refresh(fresh, planned),
        )

    def _delete_raw(self, client_dir: Path, detail: dict, allowed_days: set[str],
                    fresh: Optional[Callable[[], list[evidence.Window]]] = None) -> int:
        db = _db_for(client_dir, "telemetry")
        keep = evidence.guard("telemetry", "telemetry_raw")
        total = 0
        for day, info in sorted(detail.get("days", {}).items()):
            if day not in allowed_days:
                continue
            # The range lets the ingested_at index find the day; substr()
            # keeps the set exactly the one planned and archived; the guard
            # keeps every row inside an evidence window (held at planning or
            # now).
            # Walked in (ingested_at, id) order from the day's start (a row
            # the sweep moved keeps its old arrival but gets a new id: an id
            # walk could cross the whole table for one day).
            total += self._batches(
                db, table="telemetry_raw", key=("id",),
                where="ingested_at < ? AND substr(ingested_at, 1, 10) = ? AND id <= ?",
                params=[_next_day(day), day, info["max_id"]],
                seek="ingested_at", seek_from=day,
                prepare=lambda _conn: keep,
                refresh=self._window_refresh(fresh),
            )
        return total

    def _delete_keyed(
        self, db: Path, table: str, key: str, where: str, params: list,
        fresh: Optional[Callable[[], list[evidence.Window]]] = None,
    ) -> int:
        """Batched delete from a WITHOUT ROWID table (telemetry.db) by its
        primary key (`key` = "col" or "(col, col, …)"), never a row inside an
        evidence window. `where` is "<column> < ?": walked along that
        column's index when it has one (else in primary-key order)."""
        columns = tuple(c.strip() for c in key.strip("()").split(","))
        keep = evidence.guard("telemetry", table)
        bound = re.fullmatch(r"\s*(\w+)\s*<\s*\?\s*", where)
        return self._batches(
            db, table=table, key=columns, where=where, params=params,
            seek=bound.group(1) if bound else None,
            prepare=lambda _conn: keep,
            refresh=self._window_refresh(fresh),
        )

    # ----- reclaim -----

    def _reclaim(self, db: Path) -> dict:
        conn = _connect(db)
        try:
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
            before_pages = conn.execute("PRAGMA page_count").fetchone()[0]
            free_before = conn.execute("PRAGMA freelist_count").fetchone()[0]
            out: dict = {
                "auto_vacuum": {0: "none", 1: "full", 2: "incremental"}.get(mode, str(mode)),
                "freelist_bytes_before": free_before * page_size,
            }
            if mode != 2:
                out["reclaimed_bytes"] = 0
                out["reusable_bytes"] = free_before * page_size
                out["note"] = (
                    "not incremental: freed pages are reused by new rows; returning "
                    "them to the filesystem needs the one-time conversion "
                    "(enforce_retention.py --convert-vacuum, octo-core stopped)"
                )
                return out
            deadline = self._monotonic() + self.vacuum_budget_sec
            steps = 0
            try:
                while conn.execute("PRAGMA freelist_count").fetchone()[0] > 0:
                    if self._monotonic() >= deadline:
                        out["budget_exhausted"] = True
                        break
                    # One step = one short write transaction of its own.
                    conn.execute(
                        f"PRAGMA incremental_vacuum({self.vacuum_step_pages})").fetchall()
                    steps += 1
            except sqlite3.Error as exc:
                # Busy past the timeout (ingest), say: the space is reclaimed
                # on a later night — the deletes already stand.
                out["error"] = f"{type(exc).__name__}: {exc}"
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            except sqlite3.Error:
                pass
            after_pages = conn.execute("PRAGMA page_count").fetchone()[0]
            out.update({
                "steps": steps,
                "reclaimed_bytes": max(0, before_pages - after_pages) * page_size,
                "freelist_bytes_after": conn.execute(
                    "PRAGMA freelist_count").fetchone()[0] * page_size,
            })
            return out
        finally:
            conn.close()


class _AuditFailed(Exception):
    pass


class _RegistryUnavailable(Exception):
    pass


def _sweep_resume(sweep: dict) -> Optional[int]:
    """The next sweep's resume point from this one's report: None when it
    did not finish (or failed); else the highest id it covered, held back
    below the lowest row a held evidence window kept in events.db."""
    if not sweep or sweep.get("error"):
        return None
    through = sweep.get("through_id")
    if not isinstance(through, int):
        return None
    kept = sweep.get("evidence_min_id")
    return min(through, int(kept) - 1) if isinstance(kept, int) else through


def _fallback_policy(data_class: str) -> ClassPolicy:
    d = RETENTION_DEFAULTS[data_class]
    return ClassPolicy(data_class, d["days"], d["legal_baseline_days"], True)


def script_initiator(script: str, reason: str) -> dict:
    """Who started a script run — for its audit rows: the OS account and
    host name the process runs as (inside the container: the container's),
    and the reason given. Nothing secret."""
    import getpass
    import socket

    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 — no passwd entry in a container
        user = f"uid:{os.getuid()}"
    return {"by": "script", "script": script, "os_user": user,
            "host": socket.gethostname(), "reason": (reason or "").strip()[:500]}


ARCHIVE_DISABLED_REASON = (
    "OCTO_ARCHIVE_ROOT is not set — raw telemetry is pruned WITHOUT a cold copy"
)


# Settings → System polls the archive state every 30 s: the file count (a
# walk of the archive tree, on array disks) is reused this long per root.
FILE_COUNT_CACHE_SEC = 600.0
_file_count_cache: dict[str, tuple[float, dict]] = {}


def _file_counts(archive: ColdArchive, cached: bool) -> dict:
    key = str(archive.root)
    hit = _file_count_cache.get(key)
    if cached and hit is not None and time.monotonic() - hit[0] < FILE_COUNT_CACHE_SEC:
        return dict(hit[1])
    counts = archive.file_counts()
    _file_count_cache[key] = (time.monotonic(), counts)
    return dict(counts)


def archive_status(archive: Optional[ColdArchive] = None, *, from_env: bool = True,
                   cached_counts: bool = False) -> dict:
    """{enabled, root, usable, reason, warning, encrypted, encryption,
    encryption_note, files} for `archive` (or the env's). `warning` = the
    root is open to other users (`permission_warning`); `reason` also says
    why a REQUIRED encryption is unusable (nothing is pruned then);
    `encrypted` = the encryption POLICY is required and usable (new files
    are encrypted whenever anything is written — a root that is unusable
    for another reason, a missing mount, is `usable`/`reason`, not this);
    `encryption` = mode / custody / recipients (public-key short forms and
    fingerprints only); `encryption_note` = "archive NOT encrypted …" when
    new files are plaintext; `files` = plaintext vs encrypted data files,
    and leftover plaintext temp files of interrupted writes
    (`cached_counts`: reuse a count up to FILE_COUNT_CACHE_SEC old)."""
    if archive is None and from_env:
        archive = ColdArchive.from_env()
    if archive is None:
        return {"enabled": False, "root": None, "usable": None,
                "reason": ARCHIVE_DISABLED_REASON, "warning": None,
                "encrypted": False, "encryption": None, "encryption_note": None,
                "files": None}
    reason = archive.unusable_reason()
    enc = archive.encryption
    if not enc.required:
        note = enc.note()
    elif not enc.active:
        note = ("archive NOT encrypted — encryption is required but unusable, so "
                "nothing is archived or pruned")
    else:
        note = None
    return {"enabled": True, "root": str(archive.root), "usable": reason is None,
            "reason": reason, "warning": archive.permission_warning(),
            "encrypted": enc.active,
            "encryption": enc.status(), "encryption_note": note,
            "files": _file_counts(archive, cached_counts) if archive.root.is_dir() else None}


def archive_encryption_lines(status: dict) -> list[str]:
    """What the scripts print about the archive's encryption, after their
    own enabled / UNUSABLE line. Public-key short forms only."""
    enc = status.get("encryption")
    if not status.get("enabled") or not enc:
        return []
    lines = []
    if enc.get("mode") == "required":
        keys = ", ".join(f"{r['short']} ({r['fingerprint']})" for r in enc.get("recipients") or [])
        if enc.get("encrypted"):
            lines.append(f"archive: ENCRYPTED (age X25519) to {len(enc['recipients'])} "
                         f"recipient(s): {keys} — custody: {enc.get('custody')} (the "
                         "private key stays off this machine)")
        else:
            lines.append(f"archive: encryption REQUIRED but UNUSABLE — {enc.get('error')} "
                         "(nothing is archived or pruned until it is fixed)")
    else:
        lines.append(f"archive: {status.get('encryption_note') or 'archive NOT encrypted'}")
        if enc.get("recipients_error"):
            lines.append(f"archive: recipients file problem — {enc['recipients_error']}")
    files = status.get("files")
    if files:
        lines.append(f"archive: files: {files['plaintext']} plaintext · {files['encrypted']} "
                     "encrypted" + ("" if files.get("complete", True) else " (count incomplete)"))
        if files.get("plaintext_temp"):
            lines.append(f"archive: {files['plaintext_temp']} of the plaintext file(s) are "
                         "temp files interrupted writes left (plaintext rows inside) — "
                         "encrypt_archive.py --delete-plaintext removes them")
    return lines


# ---------------------------------------------------------------------------
# One-time conversion (explicit, operator-run)
# ---------------------------------------------------------------------------

def convert_to_incremental(db: Path) -> dict:
    """Switch an existing DB to auto_vacuum = INCREMENTAL. Requires a full
    VACUUM, which holds the file's write lock for the whole rewrite — every
    writer to it (ingest: 10 s busy timeout; the Datto poller then logs the
    failure and moves its cursor on) fails meanwhile. So: octo-core STOPPED
    (`docker compose stop octo-core` + `docker compose run --rm octo-core …`),
    never by the nightly job.

    Disk: VACUUM builds a complete temporary copy of the database, then
    copies it back through the write-ahead log (which grows to about the
    file's size before the checkpoint). SQLite would put that temp copy in
    TMPDIR / /var/tmp / /tmp — in a container, the image's writable layer
    (often a small image file shared by every container). It is
    pointed at the database's own directory instead, and the check requires
    free space there of about TWICE the file (temp copy + WAL), plus 10 %."""
    size = db.stat().st_size
    wal = db.with_name(db.name + "-wal")
    need = int((size * 2 + (wal.stat().st_size if wal.exists() else 0)) * 1.1)
    conn = _connect(db)
    try:
        mode = conn.execute("PRAGMA auto_vacuum").fetchone()[0]
        if mode == 2:
            return {"db": str(db), "changed": False, "note": "already incremental"}
        free = os.statvfs(db.parent)
        available = free.f_bavail * free.f_frsize
        if available < need:
            return {"db": str(db), "changed": False,
                    "note": (f"refused: not enough free disk for the rewrite in {db.parent} "
                             f"(need ~{need} bytes, {available} free)")}
        # The temp copy goes next to the database (same filesystem as the
        # check above), not into the container layer.
        conn.execute("PRAGMA temp_store = FILE")
        conn.execute(f"PRAGMA temp_store_directory = '{_sql_quote(str(db.parent))}'")
        started = time.monotonic()
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
        conn.execute("VACUUM")
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        except sqlite3.Error:
            pass
        elapsed = time.monotonic() - started
        return {
            "db": str(db), "changed": True, "lock_seconds": round(elapsed, 3),
            "bytes_before": size, "bytes_after": db.stat().st_size,
            "temp_dir": str(db.parent),
        }
    finally:
        try:
            # temp_store_directory is process-global in SQLite: put it back.
            conn.execute("PRAGMA temp_store_directory = ''")
        except sqlite3.Error:
            pass
        conn.close()


def _sql_quote(text: str) -> str:
    return text.replace("'", "''")


def _parse_utc(text: Optional[str]) -> Optional[datetime]:
    from apps.octo.ingest.timestamps import normalize_timestamp

    canonical = normalize_timestamp(text, naive_is_utc=True) if text else None
    if not canonical:
        return None
    return datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _days(delta: timedelta) -> str:
    days = delta.total_seconds() / 86400
    return f"{days:.1f} days"


def last_run(registry: Optional[Path] = None, *, include_backfill: bool = False,
             ) -> Optional[dict]:
    """The newest ENFORCING run on record (None when none / pre-036). The
    one-off backfill's run (trigger `backfill`: move + telemetry classes
    only) is not "the last retention run" unless `include_backfill`."""
    reg = registry or paths.registry_db_path()
    if not Path(reg).exists():
        return None
    try:
        conn = _connect(Path(reg), read_only=True)
        try:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT run_id, started_at, finished_at, trigger, status, "
                " archive_enabled, tenants, deleted_total, summary_json, error "
                "FROM retention_runs "
                + ("" if include_backfill else "WHERE trigger != 'backfill' ")
                + "ORDER BY started_at DESC, id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    out = dict(row)
    try:
        out["summary"] = json.loads(out.pop("summary_json") or "{}")
    except ValueError:
        out["summary"] = {}
    out["archive_enabled"] = bool(out["archive_enabled"])
    return out
