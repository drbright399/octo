#!/usr/bin/env python3
"""rollback_v0173.py — the SQL rollback of v0.17.3 (migration 047: the Datto
device's serial number, manufacturer and model from its audit). DRY RUN
unless --apply.

  clients/<slug>/entities.db    047 rollback (entities) where it is at 47
                                → 46: every device's `serial`,
                                `manufacturer`, `model` and `audit_at` kept in
                                `inv_device_audit_rolled_back_047`, the four
                                columns dropped
  registry.db                   047 rollback (registry) → user_version 46

Nothing is destroyed: a re-upgrade puts the four columns back from what was
kept (the devices' serials show again at once; the poller re-reads an audit
only when it is older than 7 days). Every file gets `PRAGMA integrity_check`
after. To go further back (v0.17.2 → v0.17), run `rollback_v0172.py` AFTER
this one (it refuses a registry at 47).

WHAT A ROLLED-BACK BUNDLE DOES DIFFERENTLY: a release before 047 reads no
device audit — a Datto alert's device line names no manufacturer, model or
serial number. Its alert signatures are v0.17.2's: a Datto NOC service /
disk alert is keyed by the event-log code + source + log again (not by its
services / drive), so an acknowledgement or expected condition made on
v0.17.3 for one of those stops matching (and v0.17.2's own ones match
again); a RocketCyber alert stays acknowledge-only (it names no device).

The tenant files go first, the registry last: a failure part-way leaves the
registry at 47, so the v0.17.3 image still starts and re-applies 047 lazily
to the files already rolled back — and `rollback_v0172.py` keeps refusing.

The FAST rollback (the v0.17.2 image on the 047 schema) needs none of this:
v0.17.2 never reads the four columns, they are nullable and named in none of
its statements (its INSERTs name their columns). Run this inside the v0.17.3
container (its migrations folder), with the bundle STOPPED and a fresh
backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v0173.py
  docker compose run --rm octo-core python /app/scripts/rollback_v0173.py --apply

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

MIGRATION = 47


def _version(path: Path) -> int:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


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
    clients = data_root / "clients"
    for f in sorted(clients.glob("*/entities.db")) if clients.is_dir() else []:
        try:
            if f.stat().st_size and _version(f) >= MIGRATION:
                steps.append({"file": str(f), "migration": MIGRATION, "target": "entities"})
        except sqlite3.Error as exc:
            return {"ok": False, "error": f"{f} could not be read ({type(exc).__name__})"}
    if reg_v == MIGRATION:
        steps.append({"file": str(registry), "migration": MIGRATION, "target": "registry"})
    return {"ok": True, "registry_version": reg_v, "steps": steps}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", default=None,
                        help="the bundle's data root (default: OCTO_DATA_ROOT)")
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    args = parser.parse_args(argv)
    root = Path(args.data_root or os.environ.get("OCTO_DATA_ROOT", "")).expanduser()
    if not str(root) or not root.is_dir():
        print("rollback_v0173: --data-root (or OCTO_DATA_ROOT) must be the data root",
              file=sys.stderr)
        return 2
    p = plan(root)
    if not p["ok"]:
        print(json.dumps(p, indent=1))
        return 1
    if not args.apply or not p["steps"]:
        print(json.dumps({**p, "applied": False}, indent=1))
        return 0
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
