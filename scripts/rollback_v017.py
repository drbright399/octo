#!/usr/bin/env python3
"""rollback_v017.py — the SQL rollback of v0.17 (migration 044: Tier Black
slice 1 — incident records, the threat registries, the threat notices).
DRY RUN unless --apply.

  clients/<slug>/events.db   044 rollback (events) — every tenant whose
                             events.db carries the 044 columns
  registry.db                044 rollback (registry) → user_version 43

Nothing is destroyed: the incidents' threat columns are kept (JSON, by id)
in `incidents_threat_rolled_back_044`, the threat notices in
`operator_notices_rolled_back_044`, the `athena.incident` lifecycle
events (with their ids) in `events_athena_rolled_back_044` and the
EVIDENCE WINDOWS (with their ids) in `evidence_windows_rolled_back_044`;
the new tables
(asset tags, the registries, tier settings, brakes, the worker's state;
incident_events / incident_notes / incident_decisions / incident_signals /
threat_fact / threat_would_fire) are left as they are — nothing before 044
reads them — and a re-upgrade takes everything back. Every file gets `PRAGMA integrity_check` after. To go
further back (v0.16 → v0.15), run `rollback_v016.py` AFTER this one.

EVIDENCE WINDOWS — READ THIS FIRST. v0.16 does not know evidence windows
(Rick, 2026-10-05: a confirmed threat's first detection → its all-clear is
evidence, kept until an admin releases it): its nightly retention prunes
by the clock alone, inside a window or not. The plan (dry run included)
lists every window still HELD (`held_windows` — live, or parked by an
earlier rollback) with a `warning`. While any is listed, --apply is
REFUSED (exit 1) unless
  * OCTO_RETENTION_SCHEDULE is NOT on in this environment (the rolled-back
    bundle must not prune — and no enforce_retention.py run either), and
  * --accept-unprotected-evidence "<why>" says a person decided it (the
    reason is in the output).
Better: release the windows that are no longer needed first, or keep
v0.17. The FAST rollback (the v0.16 image) has the same gap: run this
script's dry run first to list the windows, and switch
OCTO_RETENTION_SCHEDULE off before starting the v0.16 image.

The events.db files go first (tenant by tenant), the registry last: a
failure part-way leaves the registry at 44, so the v0.17 image still starts
and re-applies 044 lazily to the tenants already rolled back.

The FAST rollback (the v0.16 image on the 044 schema) needs none of this —
v0.16 never reads the new tables or columns, writes no threat notice, and
its only touch of `incidents` (a merge's row count, the retention job's
`event_ids` references) is unchanged; it never deletes an incident, which
044's triggers would refuse. ONE caveat: the `athena.incident` lifecycle
events stay in events.db, and v0.16's step-up search returns them to a
client user who searches their own tenant (v0.17 hides them) — if client
users search, run this SQL rollback, which moves them aside. Run this
inside the v0.17 container (its
migrations folder), with the bundle STOPPED and a fresh backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v017.py
  docker compose run --rm octo-core python /app/scripts/rollback_v017.py --apply

Exit: 0 done (or nothing to do), 1 refused / a file failed, 2 bad usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

MIGRATION = 44


def _version(path: Path) -> int:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _has_044(path: Path) -> bool:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
    finally:
        conn.close()
    return "tier" in cols and "ladder_started_at" in cols


def _held_windows(path: Path) -> list[dict[str, Any]]:
    """The tenant's evidence windows still HELD (unreleased) — live, or
    parked by an earlier rollback — read-only."""
    from apps.octo.retention import evidence

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [{"window": w.id, "incident": w.incident_id, "start": w.start, "end": w.end}
                for w in evidence.held_on(conn)]
    finally:
        conn.close()


WINDOWS_WARNING = (
    "evidence windows are still HELD (listed in held_windows): v0.16 does not honour them — "
    "its nightly retention prunes by the clock alone. Keep retention OFF on the rolled-back "
    "bundle (OCTO_RETENTION_SCHEDULE unset, no enforce_retention.py run) until a release "
    "that honours them is back; the windows themselves are kept aside "
    "(evidence_windows_rolled_back_044) and come back with a re-upgrade. --apply is refused "
    "while they are held unless retention is off here AND --accept-unprotected-evidence "
    "\"<why>\" is given."
)


def _windows_refusal(accepted: Any) -> str | None:
    """Why --apply may not go ahead while windows are held (None: it may)."""
    from apps.octo.retention.scheduler import schedule_enabled

    if schedule_enabled():
        return ("evidence windows are held and OCTO_RETENTION_SCHEDULE is on: the rolled-back "
                "bundle's nightly retention would delete what they hold. Switch it off (and "
                "run no enforce_retention.py) first — or release the windows no longer "
                "needed, or stay on v0.17")
    if not (isinstance(accepted, str) and len(accepted.strip()) >= 10):
        return ("evidence windows are held (held_windows): v0.16 does not honour them. "
                "Release the ones no longer needed, or stay on v0.17 — or, to go ahead, "
                "--accept-unprotected-evidence \"<who decided and why, 10+ chars>\"")
    return None


def _apply(path: Path, migration: Any, target: str) -> str:
    from apps.octo.migration import apply_migration

    conn = sqlite3.connect(path, isolation_level=None)
    try:
        apply_migration(conn, migration, target=target)
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        conn.close()


def plan(data_root: Path) -> dict[str, Any]:
    """What --apply would do (nothing is written)."""
    registry = data_root / "registry.db"
    if not registry.exists():
        return {"ok": False, "error": f"no registry at {registry}"}
    reg_v = _version(registry)
    if reg_v > MIGRATION:
        return {"ok": False, "error": f"registry is at version {reg_v}; this rolls back "
                                      f"{MIGRATION} only (roll back the newer release first)"}
    steps: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    clients = data_root / "clients"
    for events in sorted(clients.glob("*/events.db")) if clients.is_dir() else []:
        try:
            if _has_044(events):
                steps.append({"file": str(events), "migration": MIGRATION,
                              "target": "events"})
            held.extend({"tenant": events.parent.name, **w} for w in _held_windows(events))
        except sqlite3.Error as exc:
            return {"ok": False, "error": f"{events} could not be read ({type(exc).__name__})"}
    if reg_v == MIGRATION:
        steps.append({"file": str(registry), "migration": MIGRATION, "target": "registry"})
    out: dict[str, Any] = {"ok": True, "registry_version": reg_v, "steps": steps,
                           "held_windows": held}
    if held:
        out["warning"] = WINDOWS_WARNING
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", default=None,
                        help="the bundle's data root (default: OCTO_DATA_ROOT)")
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--accept-unprotected-evidence", metavar="REASON", default=None,
                        help="roll back although evidence windows are held (v0.16 does not "
                             "honour them): who decided and why")
    args = parser.parse_args(argv)
    root = Path(args.data_root or os.environ.get("OCTO_DATA_ROOT", "")).expanduser()
    if not str(root) or not root.is_dir():
        print("rollback_v017: --data-root (or OCTO_DATA_ROOT) must be the data root",
              file=sys.stderr)
        return 2
    p = plan(root)
    if not p["ok"]:
        print(json.dumps(p, indent=1))
        return 1
    if p.get("warning"):
        print(f"rollback_v017: WARNING — {p['warning']}", file=sys.stderr)
    if not args.apply or not p["steps"]:
        print(json.dumps({**p, "applied": False}, indent=1))
        return 0
    if p["held_windows"]:
        refusal = _windows_refusal(args.accept_unprotected_evidence)
        if refusal:
            print(json.dumps({**p, "applied": False, "refused": refusal}, indent=1))
            print(f"rollback_v017: REFUSED — {refusal}", file=sys.stderr)
            return 1
        p["accepted_unprotected_evidence"] = args.accept_unprotected_evidence.strip()
    from apps.octo.migration import list_migrations

    rollback = next(m for m in list_migrations(kind="rollback") if m.number == MIGRATION)
    done, failed = [], []
    for step in p["steps"]:
        try:
            result = _apply(Path(step["file"]), rollback, step["target"])
        except sqlite3.Error as exc:
            failed.append({**step, "error": type(exc).__name__})
            break
        (done if result == "ok" else failed).append({**step, "integrity": result})
        if result != "ok":
            break
    print(json.dumps({**p, "applied": True, "done": done, "failed": failed}, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
