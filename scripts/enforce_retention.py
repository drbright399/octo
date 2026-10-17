#!/usr/bin/env python3
"""enforce_retention.py — run the retention job by hand (or from a host cron).

The same job octo-core runs nightly in-process when OCTO_RETENTION_SCHEDULE=1
(`apps.octo.retention.job`): per tenant, per data class, archive-then-prune
raw telemetry, prune expired signals / indicators / agent notes / roll-ups /
first-seen domains, a `retention_enforce` audit row (before its deletes) for
each tenant with something to delete and one `retention_run` row per run,
then reclaim space. Existing audit rows are never touched. Runs take a lock in the data
root: a run that finds another one going reports `skipped` and does nothing.

Usage (bundle host):
    docker compose exec octo-core python /app/scripts/enforce_retention.py --dry-run
    docker compose exec octo-core python /app/scripts/enforce_retention.py --reason "why"
    ... --slug acme-corp            # only these tenants (repeatable)
    ... --class telemetry_raw       # only these classes (repeatable)
    ... --json                      # the full report

A run by hand that deletes (not --dry-run) needs --reason: it is recorded,
with the OS user and host the script ran as, in every audit row of the run.

    # ONE-TIME, with octo-core STOPPED: switch pre-036 events.db /
    # indicators.db files to incremental auto-vacuum so the nightly run can
    # return freed space to the filesystem. A full VACUUM per file holds its
    # write lock for as long as the rewrite takes — any writer (ingest,
    # pollers) fails after its 10 s busy timeout, and a poller moves its
    # cursor on past what it could not store — so never with the app up.
    # Needs free disk of about twice the file in its own directory (the
    # temp copy is written there, not into the container layer). Reports the
    # lock time per file. Refuses when the disk is too full.
    docker compose stop octo-core
    docker compose run --rm octo-core python /app/scripts/enforce_retention.py --convert-vacuum --slug acme-corp
    docker compose up -d octo-core

Archive: OCTO_ARCHIVE_ROOT (or --archive-root) enables the cold archive; unset
= raw telemetry is pruned without a copy, which the output says. Encryption
(OCTO_ARCHIVE_ENCRYPTION, OCTO_ARCHIVE_RECIPIENTS_PATH) is said too: required
and usable, required but UNUSABLE (nothing archived or pruned), or "archive
NOT encrypted".

Exit: 0 ok · 1 partial / failed (see the report) · 2 nothing to do / setup ·
3 skipped (another run holds the lock).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "packages" / "shared-adapter-contract"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def _print_report(report) -> None:
    from apps.octo.retention.job import BACKFILL_PENDING_NOTE, archive_encryption_lines

    print(f"retention {report.mode} run {report.run_id}: {report.status}"
          + (f" — {report.note}" if report.note else ""))
    arch = report.archive
    if arch.get("enabled"):
        print(f"archive: {arch.get('root')}"
              + ("" if arch.get("usable") else f" — UNUSABLE: {arch.get('reason')}"))
        if arch.get("warning"):
            print(f"archive: WARNING — {arch.get('warning')}")
        for line in archive_encryption_lines(arch):
            print(line)
    else:
        print(f"archive: DISABLED — {arch.get('reason')}")
    verb = "expiring" if report.mode == "dry_run" else "deleted"
    for t in report.tenants:
        parts = []
        for name, c in t.classes.items():
            if c.status in ("permanent", "skipped"):
                continue
            n = c.planned if report.mode == "dry_run" else c.deleted
            label = f"{name} {n}"
            if c.status == "blocked" and c.note == BACKFILL_PENDING_NOTE:
                label += " [waiting for the one-off backfill]"
            elif c.status not in ("ok",):
                label += f" [{c.status}{': ' + c.note if c.note else ''}]"
            elif c.basis in ("legal_baseline_floor", "tenant_override"):
                label += f" ({c.effective_days}d, {c.basis})"
            if c.referenced:
                label += f" (+{c.referenced} held: cited by a ticket / note)"
            parts.append(label)
        moved = t.sweep.get("moved", 0)
        print(f"  {t.slug}: {verb} " + " · ".join(parts)
              + (f" · swept {moved} telemetry row(s) out of events.db" if moved else "")
              + (f" · ERROR {t.error}" if t.error else ""))
    if report.mode == "dry_run":
        print("dry run — nothing was written")


def _convert(args, convert_to_incremental) -> int:
    results = []
    for tenant in sorted((args.data_root / "clients").iterdir()):
        if not tenant.is_dir() or (args.slug and tenant.name not in args.slug):
            continue
        for name in ("events.db", "indicators.db"):
            db = tenant / name
            if db.exists():
                r = convert_to_incremental(db)
                results.append(r)
                print(f"{tenant.name}/{name}: "
                      + (f"converted — locked {r['lock_seconds']}s, "
                         f"{r['bytes_before']} → {r['bytes_after']} bytes"
                         if r.get("changed") else r.get("note", "")))
    if args.json:
        print(json.dumps(results, indent=2))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    from apps.octo.auth.config import data_root
    from apps.octo.retention.archive import ColdArchive
    from apps.octo.retention.job import (
        CLASS_ORDER, LOCK_NAME, RetentionJob, _Lock, convert_to_incremental, script_initiator,
    )

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", type=Path, default=data_root(),
                        help="OCTO data root. Default: $OCTO_DATA_ROOT.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Plan and count only; write nothing anywhere.")
    parser.add_argument("--slug", action="append", default=[],
                        help="Only this tenant (repeatable).")
    parser.add_argument("--class", dest="classes", action="append", default=[],
                        choices=list(CLASS_ORDER), help="Only this data class (repeatable).")
    parser.add_argument("--archive-root", type=Path, default=None,
                        help="Cold-archive root (overrides OCTO_ARCHIVE_ROOT).")
    parser.add_argument("--convert-vacuum", action="store_true",
                        help="ONE-TIME: switch events.db / indicators.db to incremental "
                             "auto-vacuum (full VACUUM, exclusive lock). octo-core STOPPED.")
    parser.add_argument("--reason", default="",
                        help="Why this run (required unless --dry-run); recorded in the audit.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = parser.parse_args(argv)

    if not (args.data_root / "clients").is_dir():
        print(f"no clients/ under {args.data_root}", file=sys.stderr)
        return 2

    if args.convert_vacuum:
        # The same run lock as the job: never rewrite a file a run is pruning.
        lock = _Lock(args.data_root / LOCK_NAME)
        if not lock.acquire():
            print("skipped: a retention run holds the lock — try again when it is done",
                  file=sys.stderr)
            return 3
        try:
            return _convert(args, convert_to_incremental)
        finally:
            lock.release()

    if not args.dry_run and not args.reason.strip():
        print("refused: a retention run by hand deletes data — say why with --reason "
              "(it is recorded in the audit), or use --dry-run", file=sys.stderr)
        return 2

    # --archive-root replaces the root only: the encryption policy is the
    # environment's (OCTO_ARCHIVE_ENCRYPTION / OCTO_ARCHIVE_RECIPIENTS_PATH).
    archive = ColdArchive.from_env(args.archive_root) if args.archive_root else None
    job = RetentionJob(
        data_root=args.data_root, archive=archive,
        archive_from_env=args.archive_root is None,
    )
    report = job.run(
        dry_run=args.dry_run, trigger="script", slugs=args.slug or None,
        classes=args.classes or None,
        initiated_by=script_initiator("enforce_retention.py", args.reason),
    )
    _print_report(report)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, default=str))
    if report.status == "skipped":
        return 3
    return 0 if report.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
