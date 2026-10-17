"""super_admin Data Management surface — storage stats + (read-only)
retention timeframes.

This is v1: read-only
stats + retention defaults shown but not editable. Retention WRITES
need a `bundle_config` table migration (deferred) — the panel surfaces
the current hardcoded values now so operators have a single regulator-
pointable view today.

Endpoints (all super_admin gated):

  GET /api/v1/admin/data/storage-stats
      Per-tenant DB sizes + row counts. Global pattern + audit DB
      stats. Disk-free for data_root. Cheap to compute — pure
      filesystem stat + sqlite COUNT(*).

  GET /api/v1/admin/data/retention
      Current retention timeframes per data class. Read-only today;
      future PATCH endpoint will persist into bundle_config.retention.

Cross-tenant safety: this surface intentionally shows every tenant's
storage footprint to super_admin. Below super_admin tier returns 403
via the role-gate. The audit log records who fetched it, since storage
footprint can imply customer-base size — rolled up per session per hour
(`auth.audit_rollup`), because the System page polls both GETs.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_super_admin
from apps.octo.api.routers.auth import _audit_append
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import sessions
from apps.octo.auth.audit_rollup import PolledReadAudit
from apps.octo.db import connect
from apps.octo.retention import job as retention_job
from apps.octo.retention.policy import (
    RETENTION_DEFAULTS as _POLICY_DEFAULTS,
    ClassPolicy,
    effective_retention,
)


router = APIRouter(prefix="/admin/data", tags=["admin-data"])


# ---------------------------------------------------------------------------
# Retention defaults
# ---------------------------------------------------------------------------
#
# Hardcoded fallback for callers that hit /retention before migration 012
# has been applied. The live source of truth is the
# `bundle_config_retention` table (registry.db); these values get seeded
# in by the migration but stay here as the safety net.
#
# Migration 012 (2026-05-14) added super_admin-editable persistence.

# The catalogue now lives with the enforcement job (`apps.octo.retention.
# policy`, which also decides the EFFECTIVE retention); re-exported here
# under its historical name.
RETENTION_DEFAULTS = _POLICY_DEFAULTS


# ---------------------------------------------------------------------------
# Storage stats
# ---------------------------------------------------------------------------

class ClientDbStat(BaseModel):
    name: str  # 'events' | 'indicators' | 'audit' | 'telemetry' | 'entities'
    size_bytes: int
    row_count_estimate: Optional[int]
    row_count_exact: bool = True
    """False: `row_count_estimate` is a fast ESTIMATE (the file is over the
    exact-count gate) — the UI shows it as "≈"."""
    last_modified: Optional[str]


class TenantStat(BaseModel):
    slug: str
    display_name: Optional[str]
    status: str
    dbs: list[ClientDbStat]
    total_size_bytes: int


class GlobalDbStat(BaseModel):
    name: str  # 'registry' | 'patterns' | 'audit'
    size_bytes: int
    row_count_estimate: Optional[int]
    row_count_exact: bool = True
    last_modified: Optional[str]


class DiskStat(BaseModel):
    total_bytes: int
    """Raw volume capacity from statvfs(data_root). In cloud or
    container deployments this is the MOUNTED VOLUME size, not the
    host disk."""
    used_bytes: int
    free_bytes: int
    data_root_bytes: int
    """Subtree size — what Athena/OCTO is actually consuming under
    data_root."""
    used_pct: float
    """used / total — for the raw volume."""
    mount_point: Optional[str]
    """The filesystem mount point that data_root lives under (parsed
    from /proc/self/mountinfo on Linux, longest-prefix match). Helps
    operators correlate this report against their cloud volume / VM
    disk attachment. None on non-Linux."""
    mount_device: Optional[str]
    """Block device backing the mount (e.g., /dev/nvme0n1p1). Same
    Linux-only source. None when undetectable."""
    quota_bytes: Optional[int]
    """Operator-declared bundle storage cap from
    `BUNDLE_STORAGE_QUOTA_BYTES` env. None = no quota declared; use
    the raw volume size as the implicit limit. When set, the panel
    surfaces 'used vs quota' AS WELL AS 'used vs raw volume'."""
    used_pct_against_quota: Optional[float]
    """data_root_bytes / quota_bytes — only present when quota_bytes
    is set. This is the regulator-visible number for an MSP that has
    allocated this bundle a slice of a shared volume."""


class StorageStatsResponse(BaseModel):
    tenants: list[TenantStat]
    globals: list[GlobalDbStat]
    disk: DiskStat
    snapshot_at: str  # ISO timestamp the stats were computed


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _file_stat(p: Path) -> tuple[int, Optional[str]]:
    """Return (size_bytes, last_modified_iso) — both None when file missing."""
    if not p.exists():
        return 0, None
    st = p.stat()
    from datetime import datetime, timezone
    return st.st_size, datetime.fromtimestamp(
        st.st_mtime, tz=timezone.utc,
    ).isoformat(timespec="seconds")


def _count_rows(p: Path, table: str) -> tuple[Optional[int], bool]:
    """(row count, exact?) — best effort, never slow.

    Below the exact-count gate (`count_gate_bytes()`): `COUNT(*)`, exact.
    At or above it: a fast ESTIMATE (`_estimate_rows`: rowid span × the
    density of a fixed stratified sample — a few hundred b-tree lookups),
    flagged not exact; the UI shows it as "≈". A full COUNT(*) there used
    to be skipped outright (the page said "—"): on a multi-GB events.db it
    ran long enough to trip the reverse proxy's timeout, and a progress handler
    cannot interrupt a single SCAN opcode.

    (None, True) when the file is missing or unreadable (a transient lock,
    a table that does not exist)."""
    if not p.exists():
        return None, True
    try:
        big = p.stat().st_size >= count_gate_bytes()
    except OSError:
        return None, True
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=2.0)
        try:
            if big:
                return _estimate_rows(conn, table), False
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            return (row[0] if row else None), True
        finally:
            conn.close()
    except sqlite3.Error:
        return None, True


# Probes of the estimate: stratified over the rowid span, so a table whose
# ids have long deleted runs (the telemetry move, retention) is estimated by
# how much of the span is still there — not by MAX(rowid) - MIN(rowid) + 1,
# which after the move would overstate events.db ~30×.
ESTIMATE_PROBES = 512


def _estimate_rows(conn: sqlite3.Connection, table: str) -> Optional[int]:
    lo, hi = conn.execute(f"SELECT MIN(rowid), MAX(rowid) FROM {table}").fetchone()
    if lo is None or hi is None:
        return 0
    span = int(hi) - int(lo) + 1
    if span <= ESTIMATE_PROBES:
        # Small span: probing every id IS the count.
        return int(conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE rowid BETWEEN ? AND ?", (lo, hi),
        ).fetchone()[0])
    probes = sorted({int(lo) + int((i + 0.5) * span / ESTIMATE_PROBES)
                     for i in range(ESTIMATE_PROBES)})
    marks = ",".join("?" * len(probes))
    present = int(conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE rowid IN ({marks})", probes,
    ).fetchone()[0])
    return int(round(span * present / len(probes)))


# Exact COUNT(*) only below this file size. The first cut (50 MB) was tuned
# on a slow-HDD host, where multi-GB per-tenant events.db files could trip
# the reverse proxy's timeout; the bundle keeps its state on SSD
# (docs/operations/bundle.md), and above the gate the page now shows a fast
# estimate instead of "—", so the default is 256 MB.
# OCTO_STORAGE_EXACT_COUNT_MAX_MB overrides it (a host on spinning disks:
# lower it).
DEFAULT_COUNT_GATE_MB = 256
COUNT_SIZE_LIMIT_BYTES = DEFAULT_COUNT_GATE_MB * 1024 * 1024


def count_gate_bytes() -> int:
    raw = os.environ.get("OCTO_STORAGE_EXACT_COUNT_MAX_MB", "").strip()
    try:
        mb = int(raw) if raw else DEFAULT_COUNT_GATE_MB
    except ValueError:
        mb = DEFAULT_COUNT_GATE_MB
    return max(1, mb) * 1024 * 1024


def _subtree_size(root: Path) -> int:
    total = 0
    for dirpath, _, files in os.walk(root):
        for f in files:
            try:
                total += (Path(dirpath) / f).stat().st_size
            except OSError:
                continue
    return total


def _resolve_mount(path: Path) -> tuple[Optional[str], Optional[str]]:
    """Return (mount_point, device) for the filesystem `path` lives on.

    Parses /proc/self/mountinfo on Linux (longest-prefix match against
    path). Falls back to (None, None) when /proc isn't available or
    no entry matches — non-Linux runtimes, weird chroots, etc.
    """
    try:
        target = str(path.resolve())
    except OSError:
        return None, None
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.exists():
        return None, None
    best_mp: str = ""
    best_dev: Optional[str] = None
    try:
        with mountinfo.open() as fh:
            for line in fh:
                # mountinfo line: id parent_id maj:min root mount_point ...
                # Trailing fields after `-` include fs_type + device.
                # We want field 4 (mount_point) and the post-`-` device.
                parts = line.split()
                if len(parts) < 5:
                    continue
                mp = parts[4]
                if not target.startswith(mp):
                    continue
                if len(mp) <= len(best_mp):
                    continue
                # Find the `-` separator; the device is two fields later.
                try:
                    sep = parts.index("-")
                    dev = parts[sep + 2] if sep + 2 < len(parts) else None
                except ValueError:
                    dev = None
                best_mp = mp
                best_dev = dev
    except OSError:
        return None, None
    return (best_mp or None), best_dev


def _quota_bytes() -> Optional[int]:
    """Read the MSP-declared storage cap from
    `BUNDLE_STORAGE_QUOTA_BYTES`. Returns None when unset or invalid —
    panel falls back to raw volume size as the implicit limit."""
    raw = os.environ.get("BUNDLE_STORAGE_QUOTA_BYTES")
    if not raw:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except ValueError:
        return None


def _list_tenants() -> list[tuple[str, Optional[str], str]]:
    reg = paths.registry_db_path()
    if not reg.exists():
        return []
    conn = sqlite3.connect(f"file:{reg}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT slug, display_name, status FROM clients ORDER BY slug"
        ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]
    finally:
        conn.close()


@router.get("/storage-stats", response_model=StorageStatsResponse)
def storage_stats(
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> StorageStatsResponse:
    """Snapshot of every per-tenant DB + global DB size + disk capacity.
    Audited as a fetch — storage footprint can imply customer-base size,
    so super_admin reads are logged (rolled up per session per hour).
    """
    data_root = paths.data_root()

    tenant_stats: list[TenantStat] = []
    for slug, display, status in _list_tenants():
        dbs: list[ClientDbStat] = []
        for name in ("events", "indicators", "audit", "telemetry", "entities"):
            p = paths.client_dir(slug) / f"{name}.db"
            if name in ("telemetry", "entities") and not p.exists():
                continue  # created on the tenant's first write of that kind
            size, lm = _file_stat(p)
            table = {"events": "events", "indicators": "indicators",
                     "audit": "audit_log", "telemetry": "telemetry_raw",
                     "entities": "lk_ip_lease"}[name]
            count, exact = _count_rows(p, table)
            dbs.append(ClientDbStat(
                name=name, size_bytes=size,
                row_count_estimate=count, row_count_exact=exact, last_modified=lm,
            ))
        tenant_stats.append(TenantStat(
            slug=slug, display_name=display, status=status,
            dbs=dbs, total_size_bytes=sum(d.size_bytes for d in dbs),
        ))

    globals_out: list[GlobalDbStat] = []
    for name, p, table in (
        ("registry", paths.registry_db_path(), "operators"),
        ("patterns", paths.patterns_db_path(), "patterns"),
        ("audit",    paths.global_audit_db_path(), "audit_log"),
    ):
        size, lm = _file_stat(p)
        count, exact = _count_rows(p, table)
        globals_out.append(GlobalDbStat(
            name=name, size_bytes=size,
            row_count_estimate=count, row_count_exact=exact,
            last_modified=lm,
        ))

    du = shutil.disk_usage(data_root) if data_root.exists() \
        else shutil.disk_usage("/")
    data_root_bytes = _subtree_size(data_root) if data_root.exists() else 0
    mount_point, mount_device = _resolve_mount(data_root)
    quota = _quota_bytes()
    used_pct_quota: Optional[float] = None
    if quota:
        used_pct_quota = round((data_root_bytes / quota) * 100, 2)

    # A POLLED read (the System page refreshes it every 30 s): rolled up per
    # session per hour — `auth.audit_rollup`, docs/audit-policy.md. The
    # fact that a super_admin looked at the footprint is still on the chain.
    PolledReadAudit.for_app(request.app).record(
        "admin_data.storage_stats_fetch",
        operator_id=info.operator_id, session_id=info.id,
        reason="super_admin storage view",
        detail={
            "tenant_count": len(tenant_stats),
            "data_root_bytes": data_root_bytes,
            "quota_bytes": quota,
            "mount_point": mount_point,
        },
    )

    return StorageStatsResponse(
        tenants=tenant_stats,
        globals=globals_out,
        disk=DiskStat(
            total_bytes=du.total, used_bytes=du.used, free_bytes=du.free,
            data_root_bytes=data_root_bytes,
            used_pct=round((du.used / du.total) * 100, 2) if du.total else 0.0,
            mount_point=mount_point,
            mount_device=mount_device,
            quota_bytes=quota,
            used_pct_against_quota=used_pct_quota,
        ),
        snapshot_at=_iso_now(),
    )


# ---------------------------------------------------------------------------
# Retention (read-only v1)
# ---------------------------------------------------------------------------

class RetentionPolicy(BaseModel):
    data_class: str
    days: Optional[int]  # None = permanent (audit)
    editable: bool
    description: str
    overridden: bool = False  # always False until per-tenant overrides land
    allowed_days: list[int] = []
    """Enum of acceptable retention values for this class. Empty list
    means 'not editable' — UI hides the dropdown. Server enforces the
    same list on PATCH."""
    legal_baseline_days: Optional[int] = None
    """Regulator-baseline retention for this data class. NULL for the
    'audit' row (permanent has no fixed-day baseline). UI compares
    `days` against this to color-code below-baseline picks; the modal
    surfaces it verbatim in the disclosure copy."""
    regulator_basis: str = ""
    """Short human-readable citation of the regulators that set the
    baseline. Surfaces in the disclosure modal so super_admin can see
    *why* a value is the baseline before editing it."""
    effective_days: Optional[int] = None
    """What the retention job actually applies bundle-wide: `days`, floored
    at `legal_baseline_days` (a below-baseline setting is stored but never
    enforced). None = permanent. Per-tenant 'events' values can only
    lengthen it (`apps.octo.retention.policy`)."""
    floored: bool = False
    """True when `days` is below the baseline and the job uses the
    baseline instead."""
    enforced: bool = True
    """False when the job has nothing to prune for this class (permanent,
    or no store exists yet — secure_notepad)."""
    last_run_deleted: Optional[int] = None
    """Rows of this class the most recent enforcing run deleted, across
    tenants (None when no run is on record)."""
    last_run_referenced: Optional[int] = None
    """Expired rows of this class the most recent enforcing run HELD because
    an incident record (ticket, agent note, pattern link, incident) cites
    them — 'events' only (None when no run is on record)."""
    last_run_evidence: Optional[int] = None
    """Expired rows of this class the most recent enforcing run KEPT because
    they lie inside an evidence window (a confirmed threat's first
    detection → its all-clear, until an admin releases it) — None when no
    run is on record."""


class RetentionTelemetryStoreOut(BaseModel):
    """Is buoy telemetry landing in the telemetry store? A refused write is
    stored in events.db instead (ingest never fails for it) and moved by
    the nightly sweep; both are counted here so a store fault is visible —
    RECENT faults only (the last `window_hours`), so the warning clears a
    day after the fault did instead of lasting until the next restart."""
    recent_fallbacks: int = 0
    """Telemetry writes stored in events.db instead in the last
    `window_hours` (all tenants; this server process — memory only)."""
    window_hours: int = 24
    last_fallback_at: Optional[str] = None
    """When the newest of them happened (None when there was none)."""
    tenants: dict[str, int] = {}
    """…per tenant."""
    last_sweep_moved: Optional[int] = None
    """Rows the most recent enforcing run's sweep moved out of events.db
    (None when no run is on record)."""
    last_sweep_errors: list[str] = []
    """Tenants whose sweep failed in that run (their rows wait for the next)."""


class RetentionRunOut(BaseModel):
    run_id: str
    started_at: str
    finished_at: Optional[str] = None
    trigger: str
    status: str
    archive_enabled: bool
    tenants: int
    deleted_total: int
    error: Optional[str] = None


class RetentionSchedulerOut(BaseModel):
    enabled: bool
    hour_utc: Optional[int] = None
    next_run_at: Optional[str] = None
    last_failure: Optional[str] = None
    """Why this process's last scheduled run failed — e.g. the clock check
    refused it (nothing was done; such a run is not in retention_runs)."""


class RetentionArchiveRecipientOut(BaseModel):
    """A PUBLIC key the archive encrypts to — short form + fingerprint only."""
    short: str
    fingerprint: str


class RetentionArchiveEncryptionOut(BaseModel):
    mode: str
    """required | off (OCTO_ARCHIVE_ENCRYPTION; default: required when
    recipients are configured)."""
    source: str
    """env | default | archive — where the mode came from (archive = unset,
    and the archive already holds encrypted files: required, fail closed)."""
    custody: str
    """operator = the private key is held off this machine (option b)."""
    scheme: str
    encrypted: bool
    """New archive files are encrypted (required AND usable)."""
    recipients_path: Optional[str] = None
    recipients: list[RetentionArchiveRecipientOut] = []
    error: Optional[str] = None
    """Why a REQUIRED encryption is unusable (the archive then prunes nothing)."""
    recipients_error: Optional[str] = None
    note: Optional[str] = None
    """"archive NOT encrypted — …" when new files are plaintext."""


class RetentionArchiveFilesOut(BaseModel):
    plaintext: int
    encrypted: int
    plaintext_temp: int = 0
    """Of `plaintext`: temp files interrupted writes left of plaintext day
    files (plaintext rows inside; encrypt_archive.py --delete-plaintext
    removes them)."""
    complete: bool = True
    """False: the count stopped early (a folder unreadable / very large)."""


class RetentionArchiveOut(BaseModel):
    enabled: bool
    root: Optional[str] = None
    usable: Optional[bool] = None
    reason: Optional[str] = None
    warning: Optional[str] = None
    """The root is open to other users (it holds unmasked DNS history)."""
    encrypted: bool = False
    encryption: Optional[RetentionArchiveEncryptionOut] = None
    encryption_note: Optional[str] = None
    files: Optional[RetentionArchiveFilesOut] = None
    """Data files in the archive, plaintext vs encrypted (cached ≤ 10 min)."""


class RetentionResponse(BaseModel):
    policies: list[RetentionPolicy]
    note: str
    last_run: Optional[RetentionRunOut] = None
    """The newest ENFORCING run of the retention job (dry runs write
    nothing). None = retention has never been enforced on this bundle."""
    scheduler: RetentionSchedulerOut = RetentionSchedulerOut(enabled=False)
    archive: RetentionArchiveOut = RetentionArchiveOut(enabled=False)
    telemetry_store: RetentionTelemetryStoreOut = RetentionTelemetryStoreOut()


# Allowed retention values per data class. Enum-only by design —
# arbitrary day counts would invite "1 day" misconfigs that retro-
# actively delete prod telemetry.
#
# Each list spans values both BELOW and ABOVE the regulator baseline,
# so super_admin can either tighten (storage cost reduction) or extend
# (above-regulator retention for paranoid tenants). Below-baseline
# picks are still allowed but trigger the disclosure modal's
# below-baseline branch (red copy + extra acknowledgment).
ALLOWED_RETENTION_DAYS: dict[str, list[int]] = {
    "events":              [30, 90, 180, 365, 730, 2190],          # 1mo → 6yr
    "indicators_auto":     [30, 90, 180, 365],
    "indicators_promoted": [365, 730, 2190, 3650],                 # 1yr → 10yr
    "secure_notepad":      [30, 90, 180, 365, 2190],
    "agent_notes":         [365, 730, 2190, 3650],
    # Migration 036 (tiered telemetry). No value below the operational
    # baseline is offered: the job would floor it anyway.
    "telemetry_raw":       [7, 14, 30, 90],
    "telemetry_rollup":    [180, 365, 730],
    # 'audit' intentionally not in this map — uneditable.
}


def _defaults_fallback() -> list[dict]:
    """Build the same shape as a bundle_config_retention row from
    RETENTION_DEFAULTS. Used when the migration hasn't been applied yet
    (older dev DBs) or the table is empty."""
    return [
        {
            "data_class": k,
            "retention_days": v["days"],
            "legal_baseline_days": v["legal_baseline_days"],
            "regulator_basis": v["regulator_basis"],
            "editable": 1 if v["editable"] else 0,
            "description": v["description"],
        }
        for k, v in RETENTION_DEFAULTS.items()
    ]


def _load_retention_rows() -> list[dict]:
    """Pull all retention policies from bundle_config_retention. Falls
    back to RETENTION_DEFAULTS when the migration hasn't been applied
    (older dev DBs)."""
    reg = paths.registry_db_path()
    if not reg.exists():
        return _defaults_fallback()
    try:
        conn = sqlite3.connect(f"file:{reg}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT data_class, retention_days, legal_baseline_days, "
                "       regulator_basis, editable, description "
                "  FROM bundle_config_retention ORDER BY data_class"
            ).fetchall()
            if not rows:
                # Pre-migration-012 DB — fall back.
                return _defaults_fallback()
            return [dict(r) for r in rows]
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return _defaults_fallback()


@router.get("/retention", response_model=RetentionResponse)
def get_retention(
    request: Request,
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> RetentionResponse:
    """Current retention timeframes per data class. Reads from
    bundle_config_retention; falls back to hardcoded defaults if the
    migration hasn't been applied."""
    # A POLLED read (fetched with storage-stats every 30 s): rolled up per
    # session per hour. Changing a retention is audited per call (PATCH).
    PolledReadAudit.for_app(request.app).record(
        "admin_data.retention_fetch",
        operator_id=info.operator_id, session_id=info.id,
        reason="super_admin retention view",
    )
    last = retention_job.last_run(paths.registry_db_path())
    last_counts: dict[str, int] = {}
    last_referenced: dict[str, int] = {}
    last_evidence: dict[str, int] = {}
    skipped_classes: set[str] = set()
    sweep_moved = 0
    sweep_errors: list[str] = []
    if last is not None:
        for slug, tenant in (last.get("summary") or {}).get("tenants", {}).items():
            sweep_moved += int(tenant.get("sweep_moved") or 0)
            if tenant.get("sweep_error"):
                sweep_errors.append(f"{slug}: {tenant['sweep_error']}")
            for cls, c in (tenant.get("classes") or {}).items():
                if c.get("status") == "skipped":
                    # Not part of that run (a run limited to some classes):
                    # "last run: 0 deleted" would be untrue.
                    skipped_classes.add(cls)
                    continue
                last_counts[cls] = last_counts.get(cls, 0) + int(c.get("deleted") or 0)
                last_referenced[cls] = (
                    last_referenced.get(cls, 0) + int(c.get("referenced") or 0))
                last_evidence[cls] = last_evidence.get(cls, 0) + int(c.get("evidence") or 0)
    policies = []
    for r in _load_retention_rows():
        eff = effective_retention(ClassPolicy(
            r["data_class"], r["retention_days"], r.get("legal_baseline_days"),
            bool(r["editable"]),
        ))
        policies.append(RetentionPolicy(
            data_class=r["data_class"],
            days=r["retention_days"],
            editable=bool(r["editable"]),
            description=r["description"],
            allowed_days=ALLOWED_RETENTION_DAYS.get(r["data_class"], []),
            legal_baseline_days=r.get("legal_baseline_days"),
            regulator_basis=r.get("regulator_basis") or "",
            effective_days=eff.days,
            floored=eff.floored,
            enforced=eff.days is not None and r["data_class"] != "secure_notepad",
            last_run_deleted=(
                last_counts.get(r["data_class"],
                                None if r["data_class"] in skipped_classes else 0)
                if last is not None else None
            ),
            last_run_referenced=(
                last_referenced.get(r["data_class"],
                                    None if r["data_class"] in skipped_classes else 0)
                if last is not None else None
            ),
            last_run_evidence=(
                last_evidence.get(r["data_class"],
                                  None if r["data_class"] in skipped_classes else 0)
                if last is not None else None
            ),
        ))
    from apps.octo.ingest.sink import FAULT_WINDOW_HOURS, telemetry_fallbacks

    recent = telemetry_fallbacks()
    refused = {slug: int(v.get("count") or 0) for slug, v in recent.items()}
    last_fault = max((str(v.get("last_at") or "") for v in recent.values()), default="") or None
    scheduler = getattr(request.app.state, "retention_scheduler", None)
    sched_out = (
        RetentionSchedulerOut(**{
            k: v for k, v in scheduler.status().items()
            if k in ("enabled", "hour_utc", "next_run_at", "last_failure")
        })
        if scheduler is not None else RetentionSchedulerOut(enabled=False)
    )
    return RetentionResponse(
        policies=policies,
        note=(
            "super_admin can edit each editable row. Audit class is "
            "permanent + uneditable per regulator requirement; the "
            "PATCH endpoint rejects any change to it. The retention job "
            "never deletes below a class's legal baseline, and a tenant's "
            "own events retention can only lengthen the bundle's."
        ),
        last_run=RetentionRunOut(**{
            k: last[k] for k in RetentionRunOut.model_fields if k in last
        }) if last is not None else None,
        scheduler=sched_out,
        archive=RetentionArchiveOut(**retention_job.archive_status(cached_counts=True)),
        telemetry_store=RetentionTelemetryStoreOut(
            recent_fallbacks=sum(refused.values()),
            window_hours=FAULT_WINDOW_HOURS,
            last_fallback_at=last_fault,
            tenants=refused,
            last_sweep_moved=sweep_moved if last is not None else None,
            last_sweep_errors=sweep_errors,
        ),
    )


class RetentionPatchRequest(BaseModel):
    retention_days: Optional[int]  # None NOT permitted via API — server rejects
    """New retention value. Must be a member of ALLOWED_RETENTION_DAYS
    for the target data_class. Null is rejected — only the 'audit'
    class is permanent and that class isn't editable."""


class RetentionPatchResponse(BaseModel):
    data_class: str
    retention_days: Optional[int]
    previous_days: Optional[int]
    updated_at: str


def _super_admin_step_up(
    _role: sessions.SessionInfo = Depends(session_super_admin),
    info: sessions.SessionInfo = Depends(require_step_up),
) -> sessions.SessionInfo:
    """super_admin FIRST (an admin gets 403, not a re-auth prompt), then an
    active step-up window on the same session — as the compliance sign-off
    (`tenant_compliance._super_admin_step_up`)."""
    return info


@router.patch("/retention/{data_class}", response_model=RetentionPatchResponse)
def patch_retention(
    data_class: str,
    body: RetentionPatchRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(_super_admin_step_up),
) -> RetentionPatchResponse:
    """Update retention for one data class. super_admin WITH STEP-UP (v0.11:
    since 036 the nightly job enforces this value — lowering it deletes data
    at the next run, so a session cookie alone must not be enough; 401
    STEP_UP_REQUIRED opens the re-auth dialog). Rejects:
      - unknown data_class
      - 'audit' (uneditable — regulator requirement)
      - retention_days outside ALLOWED_RETENTION_DAYS for that class
      - retention_days = None / null (only 'audit' is permanent and
        'audit' isn't editable)

    Audits every successful change with operator_id + before + after.
    """
    request_id = str(uuid.uuid4())

    if data_class not in ALLOWED_RETENTION_DAYS:
        raise APIError("VALIDATION_FAILED",
                       f"data_class {data_class!r} is not editable")
    if body.retention_days is None:
        raise APIError("VALIDATION_FAILED",
                       "retention_days must be a finite integer; "
                       "permanent retention is only valid for 'audit' "
                       "which is uneditable")
    if body.retention_days not in ALLOWED_RETENTION_DAYS[data_class]:
        allowed = ALLOWED_RETENTION_DAYS[data_class]
        raise APIError("VALIDATION_FAILED",
                       f"retention_days {body.retention_days!r} not in "
                       f"allowed set for {data_class!r}: {allowed}")

    reg = connect(paths.registry_db_path())
    try:
        # Load existing row so we can capture before-state for audit.
        reg.row_factory = sqlite3.Row
        row = reg.execute(
            "SELECT retention_days, editable FROM bundle_config_retention "
            "WHERE data_class = ?", (data_class,),
        ).fetchone()
        if row is None:
            raise APIError("VALIDATION_FAILED",
                           f"data_class {data_class!r} has no config row "
                           "(migration 012 not applied?)")
        if not row["editable"]:
            # Defense in depth — also blocked by ALLOWED_RETENTION_DAYS
            # but explicit check + audit-friendly error makes the
            # rejection unambiguous.
            raise APIError("ISOLATION_VIOLATION",
                           f"data_class {data_class!r} is not editable "
                           "(regulator requirement)")
        prev_days = row["retention_days"]
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        reg.execute(
            "UPDATE bundle_config_retention "
            "   SET retention_days = ?, updated_at = ?, updated_by = ? "
            " WHERE data_class = ?",
            (body.retention_days, now, info.operator_id, data_class),
        )
        reg.commit()
    finally:
        reg.close()

    _audit_append(
        "admin_data.retention_update",
        actor=f"operator:{info.operator_id}",
        target_id=data_class,
        before={"retention_days": prev_days},
        after={"retention_days": body.retention_days,
               "session_id_prefix": info.id[:8]},
        reason=f"super_admin retention change for {data_class}",
        request_id=request_id,
    )

    return RetentionPatchResponse(
        data_class=data_class,
        retention_days=body.retention_days,
        previous_days=prev_days,
        updated_at=now,
    )
