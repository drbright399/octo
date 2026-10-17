#!/usr/bin/env python3
"""move_telemetry_out_of_events.py — one-off move of telemetry-class rows
from each tenant's events.db into its telemetry.db (migration 036).

Why: before 036 every buoy event — ~97 % of it answered DNS (suricata.dns +
pihole.query recording the same lookups) — was stored in events.db under the
one-year signal retention. From 036 on ingest files such rows in telemetry.db
(raw 7 days, hourly roll-ups 180 days, first-seen domains); this moves the
rows stored before that, so the roll-ups and first-seen ledger start with the
bundle's real history and events.db holds signals only.

What it does, per tenant (`apps.octo.retention.move`):
  * classifies every candidate-type row with the ingest classifier on its
    STORED payload — a blocked Pi-hole lookup, a Suricata record carrying an
    alert, an unknown status… stays in events.db as a signal;
  * copies each telemetry row VERBATIM (payload, payload_sha256, received_at,
    source, source_host, severity, event_type unchanged; origin_event_id =
    its events.db id) and folds it into the hourly roll-up + first-seen
    ledger, one committed batch at a time;
  * only then deletes it from events.db (by id AND payload_sha256 AND
    received_at);
  * leaves rows a ticket or an agent note points at, and rows whose payload
    is over the telemetry bound (they would have to be truncated).

Then, unless --no-prune, the retention job runs for the same tenants,
limited to the telemetry classes: raw rows older than the telemetry_raw
retention (7 days) are archived (when OCTO_ARCHIVE_ROOT is set — never
pruned if that write fails; encrypted to the operator's public keys when
OCTO_ARCHIVE_ENCRYPTION is required, never pruned while that encryption is
unusable — the dry run says which) and pruned, roll-ups older than 180 days pruned
— so the end state is "raw within 7 days, roll-ups and first-seen rebuilt
from everything moved". The move itself runs INSIDE that job (its sweep,
over all of events.db): one run lock for move + prune (the nightly run
waits it out as `skipped`), a plan audit row per tenant with something to
delete and one run row, a retention_runs row with trigger `backfill` (not
counted as "the last retention run": turning the schedule on days later
does not start a catch-up run 5 minutes after start, and Settings → System
keeps saying whether retention itself has run). With --no-prune the move
alone runs, under the same lock.

The dry run is the preview of exactly that: rows it would move, and how
many raw rows the prune would then delete — archived, or (archive disabled)
deleted WITHOUT a copy. The latter is the only irreversible step of the
upgrade, so a real run with the archive disabled that would prune anything
REFUSES unless --prune-without-archive says so (or --no-prune: move only;
note that the nightly run then prunes those rows without a copy too — set
OCTO_ARCHIVE_ROOT first to keep them).

Idempotent and resumable: the copy is keyed by origin_event_id, so an
interrupted run re-finds its copies and just finishes the deletes; "what is
left to do" is simply what is still in events.db. Short transactions: live
ingest waits at most one batch.

Disk: telemetry.db grows BEFORE the prune shrinks it — by about three times
the moved payload: per row ~716 B raw (payload, columns, indexes) + up to
~231 B of hourly roll-up, measured on a live buoy tenant
(`apps.octo.retention.move.disk_estimate`). The dry run prints that estimate
per tenant and the free space where telemetry.db lives; a real run checks
first (an upper bound: every candidate row, even those that stay as signals)
and REFUSES when the free space is under twice the estimate
(`--ignore-free-space` to proceed anyway, having checked; `--slug` to move
one tenant at a time). events.db does NOT shrink (freed pages are reused by
new rows) until the one-time `enforce_retention.py --convert-vacuum`
(octo-core stopped).

Usage (bundle host) — dry-run first:
    docker compose exec octo-core python /app/scripts/move_telemetry_out_of_events.py --dry-run
    docker compose exec octo-core python /app/scripts/move_telemetry_out_of_events.py
    ... --slug acme-corp                  # only these tenants (repeatable)
    ... --no-prune                        # move only; leave pruning to the nightly run
    ... --prune-without-archive           # archive disabled: accept pruning without a copy
    ... --ignore-free-space               # proceed although the disk check refuses

Honours OCTO_DATA_ROOT / --data-root. Exit 0 = done, 1 = a tenant failed
(the others were still processed; re-run to finish), 2 = nothing to inspect /
refused, 3 = another retention run holds the lock (try again).
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


# The retention step this script runs: telemetry classes only (the other
# classes are the nightly run's business).
TELEMETRY_CLASSES = ("telemetry_raw", "telemetry_rollup", "first_seen_domains")


def _tenants(data_root: Path, slugs: list[str]) -> list[str]:
    clients = data_root / "clients"
    if not clients.is_dir():
        return []
    wanted = set(slugs)
    return [
        c.name for c in sorted(clients.iterdir())
        if (c / "events.db").is_file() and (not wanted or c.name in wanted)
    ]


def _mb(n: int) -> str:
    return f"{n / 1_000_000:.1f} MB"


def _move_line(slug: str, r: dict, dry_run: bool) -> str:
    from apps.octo.retention.move import disk_estimate

    verb = "would move" if dry_run else "moved"
    stamp = "would stamp" if dry_run else "stamped"
    return (
        f"{slug}: scanned {r['scanned']} candidate rows · telemetry {r['telemetry']} · "
        f"{verb} {r['moved']} (+{r['already_copied']} copied by an earlier run, "
        f"~{_mb(r.get('copy_bytes', 0))} of payload"
        + (f", ~{_mb(disk_estimate(r['moved'], r.get('copy_bytes', 0)))} on disk"
           if dry_run else "")
        + ") · "
        f"{'would delete' if dry_run else 'deleted'} {r['deleted']} from events.db · "
        f"kept: signal {r['kept_signal']}, referenced {r['kept_referenced']}, "
        f"oversize {r['kept_oversize']}, changed {r['kept_changed']} · "
        f"arrival: {stamp} {r.get('arrival_stamped', 0)} row(s) with an arrival estimate"
        + (f" · ARRIVAL ERROR {r['arrival_error']} (re-run to finish)"
           if r.get("arrival_error") else "")
        + (f" · ERROR {r['error']} (re-run to finish)" if r.get("error") else "")
    )


def _space_check(data_root: Path, need: dict[str, int], *, upper_bound: bool
                 ) -> tuple[bool, list[str]]:
    """Free space vs FREE_SPACE_FACTOR × the telemetry.db growth, per
    filesystem (tenants on one disk add up). (ok, report lines)."""
    from apps.octo.retention.move import (
        FREE_SPACE_FACTOR, HOURLY_ROW_BYTES, RAW_ROW_BYTES, filesystem_id, free_bytes,
    )

    groups: dict[int, list[str]] = {}
    for slug in need:
        groups.setdefault(filesystem_id(data_root / "clients" / slug), []).append(slug)
    ok = True
    lines = []
    for slugs in groups.values():
        where = data_root / "clients" / slugs[0]
        total = sum(need[s] for s in slugs)
        free = free_bytes(where)
        enough = free >= FREE_SPACE_FACTOR * total
        ok = ok and enough
        lines.append(
            f"disk: telemetry.db of {', '.join(slugs)} grows by "
            f"{'at most' if upper_bound else 'about'} ~{_mb(total)} before the prune "
            f"(per row ~{RAW_ROW_BYTES} B raw + up to ~{HOURLY_ROW_BYTES} B roll-up, "
            f"≥ 3× the payload) · free ~{_mb(free)} · needs {FREE_SPACE_FACTOR}× = "
            f"~{_mb(FREE_SPACE_FACTOR * total)} — "
            + ("enough" if enough else "NOT ENOUGH")
        )
    return ok, lines


def main(argv: Optional[list[str]] = None) -> int:
    from apps.octo.auth.config import data_root
    from apps.octo.retention.job import (
        LOCK_NAME, RetentionJob, _Lock, archive_encryption_lines, archive_status,
        script_initiator,
    )
    from apps.octo.retention.move import (
        DEFAULT_BATCH, candidate_totals, disk_estimate, move_tenant,
    )

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", type=Path, default=data_root(),
                        help="OCTO data root (contains clients/). Default: $OCTO_DATA_ROOT.")
    parser.add_argument("--slug", action="append", default=[],
                        help="Only this tenant (repeatable). Default: every tenant.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what WOULD move and be pruned; write nothing.")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH,
                        help=f"Rows per transaction (default {DEFAULT_BATCH}).")
    parser.add_argument("--no-prune", action="store_true",
                        help="Move only; leave archive + prune to the nightly retention run.")
    parser.add_argument("--prune-without-archive", action="store_true",
                        help="Archive disabled (OCTO_ARCHIVE_ROOT unset): accept that raw "
                             "rows older than 7 days are deleted without a copy.")
    parser.add_argument("--ignore-free-space", action="store_true",
                        help="Proceed although the free disk is under twice the "
                             "estimated telemetry.db growth (you checked it yourself).")
    parser.add_argument("--reason", default="one-off telemetry move out of events.db (036)",
                        help="Recorded in the audit rows of the prune.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = parser.parse_args(argv)

    slugs = _tenants(args.data_root, args.slug)
    if not slugs:
        print(f"no tenant events.db found under {args.data_root}", file=sys.stderr)
        return 2

    if not args.dry_run:
        # Before anything moves: will telemetry.db fit? (An upper bound —
        # every candidate row, one aggregate read per tenant.)
        need = {
            slug: disk_estimate(*candidate_totals(
                args.data_root / "clients" / slug / "events.db"))
            for slug in slugs
        }
        enough, lines = _space_check(args.data_root, need, upper_bound=True)
        for line in lines:
            print(line)
        if not enough and not args.ignore_free_space:
            print(
                "refused: not enough free disk for the move — telemetry.db grows "
                "before the prune shrinks it, and the check wants twice the "
                "estimate free. Free space (or move one tenant at a time with "
                "--slug), or pass --ignore-free-space having checked yourself.",
                file=sys.stderr,
            )
            return 2

    failed = 0
    if args.no_prune:
        # The move alone — under the retention run lock, so it never runs
        # while a retention run is archiving / pruning the same files.
        lock = _Lock(args.data_root / LOCK_NAME)
        if not lock.acquire():
            print("skipped: a retention run holds the lock — try again when it is done",
                  file=sys.stderr)
            return 3
        reports = []
        try:
            for slug in slugs:
                r = move_tenant(slug, data_root=args.data_root, dry_run=args.dry_run,
                                batch_size=args.batch).as_dict()
                reports.append(r)
                failed += bool(r["error"])
                print(_move_line(slug, r, args.dry_run))
        finally:
            lock.release()
        if args.dry_run:
            _print_dry_run_space(args.data_root, {r["slug"]: r for r in reports})
        if args.json:
            print(json.dumps({"move": reports, "retention": None}, indent=2, default=str))
        if args.dry_run:
            print("dry run — nothing was written")
        return 1 if failed else 0

    archive = archive_status()

    def run(dry_run: bool):
        return RetentionJob(data_root=args.data_root, sweep_days=None,
                            move_batch=args.batch).run(
            # 'backfill': recorded, but not "the last retention run" — the
            # scheduler's catch-up and Settings → System skip it.
            dry_run=dry_run, trigger="backfill", slugs=slugs, classes=TELEMETRY_CLASSES,
            initiated_by=script_initiator("move_telemetry_out_of_events.py", args.reason),
        )

    if not args.dry_run and not archive.get("enabled") and not args.prune_without_archive:
        preview = run(True)
        if preview.status == "skipped":
            print("skipped: a retention run holds the lock — try again when it is done",
                  file=sys.stderr)
            return 3
        at_risk = sum(t.classes["telemetry_raw"].planned for t in preview.tenants)
        if at_risk:
            print(
                f"refused: OCTO_ARCHIVE_ROOT is not set, so {at_risk} raw telemetry row(s) "
                "older than the telemetry_raw retention would be DELETED WITHOUT A COPY "
                "right after the move. Set OCTO_ARCHIVE_ROOT (docs/operations/bundle.md) to "
                "archive them first, or pass --prune-without-archive to accept the loss, or "
                "--no-prune to move only (the nightly run then prunes them without a copy "
                "too, unless the archive is set by then).",
                file=sys.stderr,
            )
            return 2

    report = run(args.dry_run)
    if report.status == "skipped":
        print("skipped: a retention run holds the lock — try again when it is done",
              file=sys.stderr)
        return 3
    for t in report.tenants:
        print(_move_line(t.slug, t.sweep, args.dry_run))
        if t.sweep.get("error"):
            failed += 1
    print(f"retention ({report.mode}): {report.status}"
          + (f" — {report.note}" if report.note else ""))
    enabled = archive.get("enabled")
    unusable = bool(enabled) and archive.get("usable") is False
    if not enabled:
        print("archive: " + str(archive.get("reason")))
    elif unusable:
        # Step 3 of the upgrade is where a mis-owned or missing array mount
        # first shows: say so, as enforce_retention.py does.
        print(f"archive: {archive.get('root')} — UNUSABLE: {archive.get('reason')} "
              "(nothing older than the telemetry_raw retention is pruned until it is fixed)")
    else:
        print(f"archive: enabled → {archive.get('root')}")
    if archive.get("warning"):
        print(f"archive: WARNING — {archive.get('warning')}")
    # Encrypted to the operator's public keys, or "archive NOT encrypted";
    # a REQUIRED encryption that is unusable is the UNUSABLE reason above.
    for line in archive_encryption_lines(archive):
        print(line)
    for t in report.tenants:
        raw = t.classes.get("telemetry_raw")
        roll = t.classes.get("telemetry_rollup")
        if raw is None or roll is None:
            print(f"  {t.slug}: ERROR {t.error}")
            continue
        n_raw = raw.planned if args.dry_run else raw.deleted
        if unusable:
            fate = ("would prune nothing (archive unusable)" if args.dry_run
                    else "pruned nothing (archive unusable)")
        elif args.dry_run:
            fate = ("would archive, then prune" if enabled
                    else "would prune WITHOUT a copy (archive disabled)")
        else:
            fate = "archived + pruned" if enabled else "pruned WITHOUT a copy (archive disabled)"
        print(
            f"  {t.slug}: telemetry_raw {fate}: {n_raw} (held {raw.held}, {raw.status}) · "
            f"telemetry_rollup {'expiring' if args.dry_run else 'deleted'} "
            f"{roll.planned if args.dry_run else roll.deleted}"
            + (f" · ERROR {t.error}" if t.error else "")
        )
    if args.dry_run:
        print("  (roll-up hours and first-seen entries built from moved rows older than "
              "180 days / a year are pruned in the same run; they are counts derived from "
              "the raw rows above, not in these numbers)")
        _print_dry_run_space(args.data_root, {t.slug: t.sweep for t in report.tenants})
    if args.json:
        print(json.dumps({"move": [t.sweep for t in report.tenants],
                          "retention": report.as_dict()}, indent=2, default=str))
    if args.dry_run:
        print("dry run — nothing was written")
    if report.status == "failed":
        failed += 1
    return 1 if failed else 0


def _print_dry_run_space(data_root: Path, reports: dict[str, dict]) -> None:
    from apps.octo.retention.move import disk_estimate

    need = {slug: disk_estimate(r.get("moved", 0), r.get("copy_bytes", 0))
            for slug, r in reports.items()}
    enough, lines = _space_check(data_root, need, upper_bound=False)
    for line in lines:
        print(line)
    if not enough:
        print("  the real run will REFUSE: free disk is under twice the estimate "
              "(free space, --slug one tenant at a time, or --ignore-free-space)")


if __name__ == "__main__":
    raise SystemExit(main())
