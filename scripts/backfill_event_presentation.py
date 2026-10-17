#!/usr/bin/env python3
"""backfill_event_presentation.py — re-derive `summary` + `event_type` for
stored events from their own payload.

Why: until the presentation change, the ingest sink dropped every adapter's
summary and typed every adapter-written row "alert". Those rows still hold
their full payload. The dashboard feed already presents them at read time
(nothing to run for that); THIS script is for everything that reads the
COLUMNS instead — search's text filter and result table, exports, the triage
worker's recurrence signature (source + event_type + host) and the summary it
hands the model.

What it touches — and what it never touches:
  UPDATE events SET summary = ?, event_type = ?  WHERE id = ? AND source = ?
  * never payload, payload_sha256, received_at, source, source_host, severity
    or id: ingest idempotency is (source, payload_sha256, received_at), so a
    re-poll after the backfill still dedups against the same rows;
  * only rows whose `source` is exactly the adapter's slug (rows its poller /
    webhook wrote) and whose event_type is "alert" or already "<slug>.…" — a
    type some other writer declared is left alone;
  * a row whose payload cannot be parsed is counted and skipped.

Idempotent: a second run changes nothing. Commits per batch of 500 rows so
live ingest is never blocked for long; an interrupted run is completed by
running it again.

Usage (bundle host):
    docker compose exec octo-core python /app/scripts/backfill_event_presentation.py --dry-run
    docker compose exec octo-core python /app/scripts/backfill_event_presentation.py
    ... --slug acme-dental --slug example-clinic      # only these tenants
    ... --show 5                                      # print 5 sample headlines per tenant

Honours OCTO_DATA_ROOT / --data-root. Exit 0 = done, 1 = a tenant failed
(the others were still processed), 2 = nothing to inspect.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "packages" / "shared-adapter-contract"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_BATCH = 500
_MAX_STORED_SUMMARY = 500   # same bound the ingest sink applies


def _presenters() -> dict[str, Callable[[dict[str, Any]], Any]]:
    """source slug → present_event. Adapters gain an entry here when they
    gain the capability."""
    from apps.octo.adapters.datto import DattoSourceAdapter

    return {"datto": DattoSourceAdapter.present_event}


def _tenant_dbs(data_root: Path, slugs: list[str]) -> list[tuple[str, Path]]:
    clients = data_root / "clients"
    if not clients.is_dir():
        return []
    wanted = set(slugs)
    out = []
    for child in sorted(clients.iterdir()):
        db = child / "events.db"
        if db.is_file() and (not wanted or child.name in wanted):
            out.append((child.name, db))
    return out


def backfill_db(
    db_path: Path,
    source: str,
    present: Callable[[dict[str, Any]], Any],
    *,
    dry_run: bool,
    show: int = 0,
) -> dict[str, Any]:
    """Process one events.db. Returns counters (+ `samples` when show > 0)."""
    stats: dict[str, Any] = {
        "scanned": 0, "changed": 0, "unparseable": 0, "foreign_type": 0,
        "unrecognised": 0, "types": Counter(), "samples": [],
    }
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        has_summary = any(
            r[1] == "summary" for r in conn.execute("PRAGMA table_info(events)")
        )
        select = (
            "SELECT id, event_type, payload"
            + (", summary" if has_summary else "")
            + " FROM events WHERE source = ? AND id > ? ORDER BY id LIMIT ?"
        )
        last_id = 0
        while True:
            # One short write transaction per batch: live ingest into this DB
            # waits at most one batch, never the whole scan.
            if not dry_run:
                conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(select, (source, last_id, _BATCH)).fetchall()
            if not rows:
                conn.rollback()
                break
            for row in rows:
                last_id = row["id"]
                stats["scanned"] += 1
                old_type = row["event_type"] or ""
                if old_type != "alert" and not old_type.startswith(source + "."):
                    stats["foreign_type"] += 1
                    continue
                try:
                    payload = json.loads(row["payload"])
                except (TypeError, ValueError, RecursionError):
                    payload = None
                if not isinstance(payload, dict):
                    stats["unparseable"] += 1
                    continue
                shown = present(payload)
                old_summary = row["summary"] if has_summary else ""
                if getattr(shown, "fallback", False) and old_summary:
                    # The presenter recognised nothing in this payload (a row
                    # filed under the source without the vendor's shape —
                    # dev synthetic traffic, say): its bare label must not
                    # overwrite a summary the row already has.
                    stats["unrecognised"] += 1
                    continue
                new_type = shown.event_type
                new_summary = (shown.headline or "")[:_MAX_STORED_SUMMARY]
                stats["types"][new_type] += 1
                if not has_summary:
                    old_summary = new_summary
                if new_type == old_type and new_summary == old_summary:
                    continue
                stats["changed"] += 1
                if len(stats["samples"]) < show:
                    stats["samples"].append((row["id"], new_type, new_summary))
                if dry_run:
                    continue
                if has_summary:
                    conn.execute(
                        "UPDATE events SET summary = ?, event_type = ? "
                        "WHERE id = ? AND source = ?",
                        (new_summary, new_type, row["id"], source),
                    )
                else:
                    conn.execute(
                        "UPDATE events SET event_type = ? WHERE id = ? AND source = ?",
                        (new_type, row["id"], source),
                    )
            if not dry_run:
                conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return stats


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    from apps.octo.auth.config import data_root

    parser.add_argument(
        "--data-root", type=Path, default=data_root(),
        help="OCTO data root (contains clients/). Default: $OCTO_DATA_ROOT, "
             "else the deployment default.",
    )
    parser.add_argument(
        "--slug", action="append", default=[],
        help="Only this tenant (repeatable). Default: every tenant.",
    )
    parser.add_argument(
        "--source", default="datto",
        help="Adapter slug whose rows to re-derive. Default: datto.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what WOULD change; write nothing.",
    )
    parser.add_argument(
        "--show", type=int, default=0,
        help="Print up to N sample (id, event_type, headline) per tenant. "
             "Headlines are vendor alert text — mind where the output goes.",
    )
    args = parser.parse_args(argv)

    present = _presenters().get(args.source)
    if present is None:
        print(f"no presenter for source {args.source!r}", file=sys.stderr)
        return 2
    targets = _tenant_dbs(args.data_root, args.slug)
    if not targets:
        print(f"no tenant events.db found under {args.data_root}", file=sys.stderr)
        return 2

    verb = "would change" if args.dry_run else "changed"
    failed = 0
    for slug, db_path in targets:
        try:
            stats = backfill_db(
                db_path, args.source, present, dry_run=args.dry_run, show=args.show,
            )
        except Exception as exc:  # noqa: BLE001 — keep going; report at exit
            failed += 1
            print(f"{slug}: FAILED ({type(exc).__name__}: {exc}) — the open "
                  "batch was rolled back; re-run to finish", file=sys.stderr)
            continue
        types = ", ".join(f"{t}={n}" for t, n in sorted(stats["types"].items()))
        print(
            f"{slug}: scanned {stats['scanned']} {args.source} rows, {verb} "
            f"{stats['changed']}, unparseable {stats['unparseable']}, "
            f"other-typed (left alone) {stats['foreign_type']}"
            + (f", unrecognised (summary kept) {stats['unrecognised']}"
               if stats["unrecognised"] else "")
            + (f" · {types}" if types else "")
        )
        for event_id, new_type, headline in stats["samples"]:
            print(f"    #{event_id} {new_type}: {headline}")
    if args.dry_run:
        print("dry run — nothing was written")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
