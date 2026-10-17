#!/usr/bin/env python3
"""rollback_v013.py — the SQL rollback of v0.13 (migrations 040, 039, 038),
newest first, over every file they touched. DRY RUN unless --apply.

  registry.db                 040 rollback (registry section), then 038's
                              → user_version 37
  clients/<slug>/telemetry.db 039 rollback (telemetry) where it is at 39
                              → 37 (a client never read since v0.13 is
                              still at 37: left alone)
  clients/<slug>/entities.db  LEFT IN PLACE (040's design: with the switch
                              gone nothing reads them; a re-upgrade finds
                              them current)

Nothing is destroyed: each rollback keeps what it removes in
`*_rolled_back_0NN` tables (every client's switch, the known-benign rules,
the entity-review notices, the UniFi telemetry tables) and a re-upgrade
takes them back. Each file gets `PRAGMA integrity_check` after.

The FAST rollback (the v0.12 image on the 040 schema) needs none of this —
see docs/operations/bundle.md, "v0.13". Run this inside the v0.13
container (its migrations folder), with the bundle STOPPED and a fresh
backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v013.py
  docker compose run --rm octo-core python /app/scripts/rollback_v013.py --apply

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

FIRST, LAST = 38, 40


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
    steps: list[dict[str, Any]] = []
    if reg_v < FIRST - 1 or reg_v > LAST:
        return {"ok": False, "error": f"registry is at version {reg_v}; this rolls back "
                                      f"{LAST}…{FIRST} only"}
    # Newest first: 040 (registry), 039 (each telemetry at 39), 038 (registry).
    if reg_v >= 40:
        steps.append({"file": str(registry), "migration": 40, "target": "registry"})
    for tel in sorted((data_root / "clients").glob("*/telemetry.db")):
        if _version(tel) >= 39:
            steps.append({"file": str(tel), "migration": 39, "target": "telemetry"})
    if reg_v >= 38:
        steps.append({"file": str(registry), "migration": 38, "target": "registry"})
    return {"ok": True, "registry_version": reg_v, "steps": steps,
            "entities_left_in_place": len(list((data_root / "clients").glob("*/entities.db")))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", default=None,
                        help="the bundle's data root (default: OCTO_DATA_ROOT)")
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    args = parser.parse_args(argv)
    root = Path(args.data_root or os.environ.get("OCTO_DATA_ROOT", "")).expanduser()
    if not str(root) or not root.is_dir():
        print("rollback_v013: --data-root (or OCTO_DATA_ROOT) must be the data root",
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

    rollbacks = {m.number: m for m in list_migrations(kind="rollback")
                 if FIRST <= m.number <= LAST}
    done, failed = [], []
    for step in p["steps"]:
        try:
            result = _apply(Path(step["file"]), rollbacks[step["migration"]], step["target"])
        except sqlite3.Error as exc:
            failed.append({**step, "error": type(exc).__name__})
            break                       # newest first: never past a failed step
        (done if result == "ok" else failed).append({**step, "integrity": result})
        if result != "ok":
            break
    print(json.dumps({**p, "applied": True, "done": done, "failed": failed}, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
