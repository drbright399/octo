#!/usr/bin/env python3
"""backup_databases.py — durable, online backups of every OCTO database.

Replaces the documented-but-broken `rsync the data_root` story flagged
by all 5 external reviewers as a unanimous block-ship finding. rsync
against WAL-mode SQLite silently produces torn-page-corrupted backups
when a writer is active; the SQLite online backup API (Python's
`sqlite3.Connection.backup`) is the only safe option.

What this script does:

  1. Discover every database under `<data_root>`:
       - registry.db
       - global/audit.db
       - global/patterns.db
       - global/quarantine.db   (held integration traffic; created lazily)
       - clients/<slug>/events.db, indicators.db, audit.db, tickets.db,
         telemetry.db (the tiered DNS / flow store, migration 036; created
         on a tenant's first telemetry write), entities.db (entity
         resolution, migration 040)
  2. For each DB:
       - Run PRAGMA integrity_check on the SOURCE first. A corrupt
         source produces a corrupt backup; per the v2 external review
         (2026-05-21), a backup that silently propagates source bit-
         rot consumes retention windows hiding the problem. If source
         integrity_check fails, the backup is still written (forensics
         need it) but the per-DB result is marked ok=False.
       - Open source read-only.
       - Open destination as a fresh file.
       - Call src.backup(dst) — page-by-page copy with proper WAL
         handling. Concurrent writers do not corrupt the backup.
       - Run PRAGMA integrity_check on the destination.
       - Compress with gzip (unless --no-compress).
  3. (Optional) rsync the backup directory to a remote destination.
  4. Rotate: delete backup directories older than --retention-days.
  5. Emit a structured JSON report (same shape as
     verify_audit_chain.py) to stdout or --report-out, and — the LAST
     write into the run directory — a copy of it as
     `<run>/backup-report.json` (RUN_REPORT_NAME): the run's "finished"
     marker for scripts/seal_backup_runs.py.

Exit codes:
  0   every database backed up + integrity-checked clean
  1   one or more backups FAILED (read error, integrity failure, etc.)
  2   setup failure (data root missing, dest dir uncreatable)
  3   partial — backups OK but remote sync or rotation had errors

Designed to run as a scheduled systemd-timer job. Recommended cadence:
daily at 02:00. The legacy host's companion units live with its deploy
files (ops/legacy-host/backup-databases.{service,timer}, not part of the
public copy).

Banked 2026-05-21 in response to external concept review.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# Every run directory is named by its start time in UTC with this format
# (`20261012T060001Z`). rotate() and scripts/seal_backup_runs.py recognise a
# run ONLY by it — anything else under the backups root is never touched.
RUN_STAMP_FORMAT = "%Y%m%dT%H%M%SZ"

# The LAST thing a backup writes into its run directory: its own copy of the
# report. It is the run's "finished" marker (scripts/seal_backup_runs.py
# seals a run once it holds it) and keeps every run's report with the run
# (the --report-out file is overwritten by the next backup).
# restore_databases.py ignores it (not a database name).
RUN_REPORT_NAME = "backup-report.json"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class DbBackupResult:
    """Outcome of backing up one database file."""
    source: str
    label: str                  # "registry" / "global:audit" / "tenant:<slug>:events"
    ok: bool
    error: Optional[str]
    source_bytes: int
    backup_bytes: int           # post-compress if compressed
    elapsed_ms: int
    source_integrity: Optional[str]  # "ok" / err line / None if skipped
    integrity: Optional[str]    # destination "ok" / err line
    compressed: bool


@dataclass
class BackupRunReport:
    """Top-level report aggregating all per-DB backups + post-actions."""
    started_at: float
    finished_at: float = 0.0
    data_root: str = ""
    dest_dir: str = ""
    remote_dest: Optional[str] = None
    retention_days: int = 14
    databases_total: int = 0
    databases_failed: int = 0
    bytes_source_total: int = 0
    bytes_backup_total: int = 0
    elapsed_ms_total: int = 0
    remote_sync_ok: Optional[bool] = None
    remote_sync_error: Optional[str] = None
    rotation_removed: int = 0
    rotation_error: Optional[str] = None
    results: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

# Every per-tenant database file. tickets.db was missing here until the
# telemetry change (2026-09-29) — tickets, notes and Autotask push state were
# never in a backup run; telemetry.db arrived with migration 036, entities.db
# with 040 (entity resolution: operator link decisions must survive a restore).
TENANT_DB_FILES: tuple[str, ...] = (
    "events.db", "indicators.db", "audit.db", "tickets.db", "telemetry.db", "entities.db",
)


def discover_databases(data_root: Path) -> list[tuple[Path, str]]:
    """Return [(source_path, label), ...] in deterministic order.

    Labels follow the convention used in the verifier:
        registry           — registry.db
        global:audit       — global/audit.db
        global:patterns    — global/patterns.db
        global:quarantine  — global/quarantine.db (held integration traffic)
        tenant:<slug>:<db> — clients/<slug>/{events,indicators,audit,
                             tickets,telemetry,entities}.db
    """
    targets: list[tuple[Path, str]] = []

    registry = data_root / "registry.db"
    if registry.exists():
        targets.append((registry, "registry"))

    global_dir = data_root / "global"
    if global_dir.is_dir():
        for name in ("audit.db", "patterns.db", "quarantine.db"):
            p = global_dir / name
            if p.exists():
                targets.append((p, f"global:{name.removesuffix('.db')}"))

    clients_dir = data_root / "clients"
    if clients_dir.is_dir():
        for tenant_dir in sorted(clients_dir.iterdir()):
            if not tenant_dir.is_dir():
                continue
            for name in TENANT_DB_FILES:
                p = tenant_dir / name
                if p.exists():
                    targets.append((
                        p, f"tenant:{tenant_dir.name}:{name.removesuffix('.db')}",
                    ))
    return targets


# ---------------------------------------------------------------------------
# Per-DB backup
# ---------------------------------------------------------------------------

def _online_backup(src: Path, dst: Path) -> None:
    """Copy `src` to `dst` via SQLite's online backup API.

    Critical: this is the only way to safely back up a WAL-mode SQLite
    file while a concurrent writer holds the database. rsync / cp /
    similar will produce torn-page corruption.
    """
    src_conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    try:
        dst_conn = sqlite3.connect(str(dst))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()


def _integrity_check(p: Path) -> str:
    """Run PRAGMA integrity_check on the backup. Returns 'ok' on success
    or the first failure line. Surfaces silent corruption that the
    online backup could miss (e.g. a buggy SQLite, disk bit-flip)."""
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        if rows and rows[0][0] == "ok":
            return "ok"
        return rows[0][0] if rows else "no result"
    finally:
        conn.close()


def backup_one(
    src: Path,
    dst_dir: Path,
    label: str,
    *,
    compress: bool,
    verify: bool,
) -> DbBackupResult:
    """Back up one DB. Returns a structured result."""
    started = time.monotonic()
    source_bytes = src.stat().st_size if src.exists() else 0

    # Destination filename mirrors the source path under dst_dir, with
    # the label as the suffix so duplicates across tenants don't collide.
    # `tenant:acme:events` → `tenant_acme_events.db`
    safe_label = label.replace(":", "_").replace("/", "_")
    raw_path = dst_dir / f"{safe_label}.db"

    # Source-side integrity check FIRST. v2 reviewer point: a backup
    # of a corrupted source silently propagates the corruption to the
    # WORM copy and burns retention windows hiding bit-rot. We still
    # produce the backup (forensics need it) but mark the result as
    # ok=False so alerts fire on the source — not on the backup chain.
    source_integrity: Optional[str] = None
    source_integrity_error: Optional[str] = None
    if verify:
        try:
            source_integrity = _integrity_check(src)
        except Exception as e:  # noqa: BLE001
            source_integrity_error = f"source integrity_check raised: {e}"

    try:
        dst_dir.mkdir(parents=True, exist_ok=True)
        if raw_path.exists():
            raw_path.unlink()  # never overwrite an existing backup with a partial
        _online_backup(src, raw_path)
    except Exception as e:  # noqa: BLE001
        return DbBackupResult(
            source=str(src), label=label, ok=False,
            error=f"online_backup failed: {e}",
            source_bytes=source_bytes, backup_bytes=0,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            source_integrity=source_integrity,
            integrity=None, compressed=False,
        )

    # If the source itself was corrupt, fail loud now — the on-disk
    # backup is preserved for forensics, but we don't pretend it's
    # healthy. Same shape applies if the source check raised.
    if source_integrity_error is not None:
        return DbBackupResult(
            source=str(src), label=label, ok=False,
            error=source_integrity_error,
            source_bytes=source_bytes,
            backup_bytes=raw_path.stat().st_size,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            source_integrity=None, integrity=None, compressed=False,
        )
    if source_integrity is not None and source_integrity != "ok":
        return DbBackupResult(
            source=str(src), label=label, ok=False,
            error=f"source integrity_check failed: {source_integrity}",
            source_bytes=source_bytes,
            backup_bytes=raw_path.stat().st_size,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            source_integrity=source_integrity,
            integrity=None, compressed=False,
        )

    integrity = None
    if verify:
        try:
            integrity = _integrity_check(raw_path)
            if integrity != "ok":
                return DbBackupResult(
                    source=str(src), label=label, ok=False,
                    error=f"integrity_check failed: {integrity}",
                    source_bytes=source_bytes,
                    backup_bytes=raw_path.stat().st_size,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    source_integrity=source_integrity,
                    integrity=integrity, compressed=False,
                )
        except Exception as e:  # noqa: BLE001
            return DbBackupResult(
                source=str(src), label=label, ok=False,
                error=f"integrity_check raised: {e}",
                source_bytes=source_bytes,
                backup_bytes=raw_path.stat().st_size,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                source_integrity=source_integrity,
                integrity=None, compressed=False,
            )

    final_path = raw_path
    compressed_flag = False
    if compress:
        gz_path = raw_path.with_suffix(raw_path.suffix + ".gz")
        try:
            with raw_path.open("rb") as fin, gzip.open(gz_path, "wb", compresslevel=6) as fout:
                shutil.copyfileobj(fin, fout, length=1024 * 1024)
            raw_path.unlink()
            final_path = gz_path
            compressed_flag = True
        except Exception as e:  # noqa: BLE001
            return DbBackupResult(
                source=str(src), label=label, ok=False,
                error=f"gzip failed: {e}",
                source_bytes=source_bytes,
                backup_bytes=raw_path.stat().st_size if raw_path.exists() else 0,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                source_integrity=source_integrity,
                integrity=integrity, compressed=False,
            )

    return DbBackupResult(
        source=str(src), label=label, ok=True, error=None,
        source_bytes=source_bytes,
        backup_bytes=final_path.stat().st_size,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        source_integrity=source_integrity,
        integrity=integrity, compressed=compressed_flag,
    )


# ---------------------------------------------------------------------------
# Post-backup: remote sync, rotation
# ---------------------------------------------------------------------------

def remote_sync(local_dir: Path, remote_dest: str) -> tuple[bool, Optional[str]]:
    """rsync the backup directory to `remote_dest`.

    `remote_dest` shape: 'user@host:/abs/path/' OR 'host:/abs/path/' OR
    a plain '/abs/path/' for a local cross-volume copy. Trailing slash
    behavior matches rsync.
    """
    try:
        result = subprocess.run(
            ["rsync", "-az", "--partial", "--delete-after",
             str(local_dir) + "/", remote_dest],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode == 0:
            return True, None
        return False, result.stderr.strip()[:500] or f"rsync exit {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "rsync timeout (600s)"
    except FileNotFoundError:
        return False, "rsync binary not on PATH"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def rotate(backups_root: Path, retention_days: int) -> tuple[int, Optional[str]]:
    """Delete backup directories older than `retention_days`.

    Backup directories are named with their start timestamp
    (YYYYMMDDTHHMMSSZ). We walk `backups_root` and remove any whose
    timestamp falls before the retention horizon.
    """
    if not backups_root.is_dir():
        return 0, None
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    removed = 0
    last_err: Optional[str] = None
    for entry in sorted(backups_root.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        # Expect YYYYMMDDTHHMMSSZ
        try:
            stamp = datetime.strptime(name, RUN_STAMP_FORMAT).replace(
                tzinfo=timezone.utc,
            )
        except ValueError:
            # Unknown directory shape — leave it alone (defensive: don't
            # rm anything we didn't create).
            continue
        if stamp >= cutoff:
            continue
        try:
            shutil.rmtree(entry)
            removed += 1
        except Exception as e:  # noqa: BLE001
            last_err = f"{entry.name}: {e}"
    return removed, last_err


def write_run_report(run_dir: Path, text: str) -> Optional[str]:
    """Write `text` to <run_dir>/RUN_REPORT_NAME atomically (a hidden temp
    file, then a rename): it appears whole or not at all. The error text, or
    None."""
    tmp = run_dir / f".{RUN_REPORT_NAME}.tmp"
    try:
        tmp.write_text(text + "\n")
        os.replace(tmp, run_dir / RUN_REPORT_NAME)
        return None
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        return f"{type(e).__name__}: {e.strerror or e}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def default_data_root() -> Path:
    """The data root when --data-root is not given, resolved at run time:
    $OCTO_DATA_ROOT, else ``~/octo/data`` of the account running the backup
    (the single-host layout; the same default as
    apps/octo/auth/config.py:data_root(), kept stdlib-only here)."""
    override = os.environ.get("OCTO_DATA_ROOT")
    if override:
        return Path(override).resolve()
    # No usable home (none, relative, or "/"): refuse rather than guess.
    try:
        home = Path.home()
    except RuntimeError:
        home = None
    if home is None or not home.is_absolute() or home == Path(home.anchor):
        raise RuntimeError(
            "no --data-root, no $OCTO_DATA_ROOT and no usable home "
            "directory for the ~/octo/data default; pass --data-root")
    return home / "octo" / "data"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--data-root", type=Path, default=None,
        help="OCTO data root. Default: $OCTO_DATA_ROOT, else ~/octo/data "
             "of the account running the backup (the single-host "
             "production layout).",
    )
    parser.add_argument(
        "--backups-root", type=Path, default=None,
        help="Parent directory for timestamped backup runs. "
             "Defaults to <data_root>/_backups.",
    )
    parser.add_argument(
        "--remote-dest", type=str, default=None,
        help="Optional rsync target (user@host:/path/, etc.). "
             "Off-host destination is strongly recommended for any "
             "real deployment; if unset, backups stay on the OCTO host "
             "and a host loss = backup loss.",
    )
    parser.add_argument(
        "--retention-days", type=int, default=14,
        help="Delete backup runs older than this many days. Default 14.",
    )
    parser.add_argument(
        "--no-compress", dest="compress", action="store_false",
        default=True,
        help="Keep raw .db files instead of gzipping. Default: compress.",
    )
    parser.add_argument(
        "--no-verify", dest="verify", action="store_false",
        default=True,
        help="Skip post-backup PRAGMA integrity_check. "
             "Default: verify (recommended).",
    )
    parser.add_argument(
        "--report-out", type=Path, default=None,
        help="Write the structured JSON report to this path. "
             "Default: stdout.",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-DB stderr summary. JSON report is still produced.",
    )
    args = parser.parse_args(argv)
    if args.data_root is None:
        try:
            args.data_root = default_data_root()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 2

    backups_root = args.backups_root or (args.data_root / "_backups")
    started_ts = time.time()
    stamp = datetime.now(timezone.utc).strftime(RUN_STAMP_FORMAT)
    run_dir = backups_root / stamp

    targets = discover_databases(args.data_root)
    if not targets:
        print(f"no databases found under {args.data_root}", file=sys.stderr)
        return 2

    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        print(f"could not create {run_dir}: {e}", file=sys.stderr)
        return 2

    results = [
        backup_one(
            src, run_dir, label,
            compress=args.compress, verify=args.verify,
        )
        for src, label in targets
    ]

    report = BackupRunReport(
        started_at=started_ts,
        data_root=str(args.data_root),
        dest_dir=str(run_dir),
        remote_dest=args.remote_dest,
        retention_days=args.retention_days,
        databases_total=len(results),
        databases_failed=sum(1 for r in results if not r.ok),
        bytes_source_total=sum(r.source_bytes for r in results),
        bytes_backup_total=sum(r.backup_bytes for r in results),
        elapsed_ms_total=sum(r.elapsed_ms for r in results),
        results=[asdict(r) for r in results],
    )

    # Remote sync (only if every local backup succeeded; pushing partial
    # state to a remote isn't worth the bandwidth + masks the failure).
    if args.remote_dest and report.databases_failed == 0:
        ok, err = remote_sync(run_dir, args.remote_dest)
        report.remote_sync_ok = ok
        report.remote_sync_error = err

    # Rotate the historical runs (keep `retention_days` worth).
    removed, rot_err = rotate(backups_root, args.retention_days)
    report.rotation_removed = removed
    report.rotation_error = rot_err

    report.finished_at = time.time()

    out_text = json.dumps(asdict(report), indent=2)
    # The run's own copy of the report, LAST inside the run directory: the
    # "finished" marker (RUN_REPORT_NAME). Failing to write it is a warning,
    # not a failed backup: the databases are all there.
    marker_err = write_run_report(run_dir, out_text)
    if marker_err:
        print(f"warning: could not write {run_dir / RUN_REPORT_NAME}: {marker_err}",
              file=sys.stderr)
    if args.report_out:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(out_text + "\n")
    else:
        print(out_text)

    if not args.quiet:
        for r in results:
            mark = "OK " if r.ok else "FAIL"
            err = f" — {r.error}" if r.error else ""
            print(
                f"  {mark}  {r.label:40s}  src={_fmt_bytes(r.source_bytes):>8s}  "
                f"bak={_fmt_bytes(r.backup_bytes):>8s}  "
                f"{r.elapsed_ms:>6d}ms{err}",
                file=sys.stderr,
            )
        print(
            f"\nBacked up {report.databases_total} db(s) "
            f"({_fmt_bytes(report.bytes_source_total)} → "
            f"{_fmt_bytes(report.bytes_backup_total)}); "
            f"{report.databases_failed} failed. "
            f"Total {report.elapsed_ms_total}ms.",
            file=sys.stderr,
        )
        if args.remote_dest:
            print(
                f"Remote sync ({args.remote_dest}): "
                f"{'OK' if report.remote_sync_ok else 'FAIL ' + (report.remote_sync_error or '')}",
                file=sys.stderr,
            )
        if removed:
            print(f"Rotation: removed {removed} old run(s).", file=sys.stderr)

    if report.databases_failed > 0:
        return 1
    if args.remote_dest and report.remote_sync_ok is False:
        return 3
    if report.rotation_error:
        return 3
    return 0


def _fmt_bytes(n: int) -> str:
    """Human-readable byte size."""
    if n < 1024:
        return f"{n}B"
    units = ["KB", "MB", "GB", "TB"]
    val = float(n) / 1024.0
    for u in units:
        if val < 1024.0:
            return f"{val:.1f}{u}"
        val /= 1024.0
    return f"{val:.1f}PB"


if __name__ == "__main__":
    # Make `apps.octo.*` importable so tests/external code can reuse
    # discover_databases() etc. without venv juggling.
    _REPO_ROOT = Path(__file__).resolve().parent.parent
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    sys.exit(main())
