#!/usr/bin/env python3
"""rollback_v016.py — the SQL rollback of v0.16 (migration 043: PROPOSALS —
Autotask addresses proposed as site locations — and the pins' provenance).
DRY RUN unless --apply.

  registry.db   043 rollback (registry) → user_version 42

That is the whole schema change of v0.16: telemetry, events and entities
files are untouched (the host pin lives in the existing `bundle_config`
row, 022).

Nothing is destroyed: every proposal is kept in `proposals_rolled_back_043`,
the provenance of every pin confirmed from a proposal in
`site_locations_origin_rolled_back_043` (the pins themselves stay in
`site_locations`), and a re-upgrade takes both back. The file gets
`PRAGMA integrity_check` after. To go further back (v0.14), run
`rollback_v015.py` AFTER this one.

The FAST rollback (the v0.15 image on the 043 schema) needs none of this —
v0.15 never reads `proposals` and never names the two new columns (a pin it
inserts is 'manual' by default; one it edits is made 'manual' by 043's
trigger — never "from Autotask, confirmed by" the hand editor). Run this
inside the v0.16 container (its migrations folder), with the bundle STOPPED
and a fresh backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v016.py
  docker compose run --rm octo-core python /app/scripts/rollback_v016.py --apply

Exit: 0 done (or nothing to do), 1 refused / the file failed, 2 bad usage.
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

MIGRATION = 43


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
        print("rollback_v016: --data-root (or OCTO_DATA_ROOT) must be the data root",
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
    print(json.dumps({**p, "applied": True, "done": done, "failed": failed}, indent=1))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
