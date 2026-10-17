#!/usr/bin/env python3
"""rollback_v0172.py — the SQL rollback of v0.17.2 (migration 046: alert
ACKNOWLEDGE / EXPECTED verdicts, remote-IP enrichment, the Datto device list
for every tenant). DRY RUN unless --apply.

  clients/<slug>/telemetry.db   046 rollback (telemetry) where it is at 46
                                → 39: every IPS bucket's `remotes` kept in
                                `unifi_bucket_remotes_rolled_back_046`, the
                                column dropped
  clients/<slug>/entities.db    046 rollback (entities) where it is at 46
                                → 40: every device's `ext_ip` kept in
                                `inv_device_ext_ip_rolled_back_046`, the
                                column dropped
  registry.db                   046 rollback (registry) → user_version 44

Nothing is destroyed: the verdicts (`alert_verdict`), the expected
conditions and the enrichment cache are LEFT AS THEY ARE — nothing before
046 reads them — and a re-upgrade takes everything back (the two columns
are restored from what was kept; every acknowledgement and every live
expected condition applies again). Every file gets `PRAGMA integrity_check`
after. To go further back (v0.17 → v0.16), run `rollback_v017.py` AFTER
this one.

WHAT A ROLLED-BACK BUNDLE DOES DIFFERENTLY: a release before 046 has no
acknowledge and no expected label — every alert counts towards its site's
Yellow again, and the Datto device list is read only for tenants with entity
resolution in shadow / on (the other tenants' rows stay in entities.db,
unread).

The tenant files go first, the registry last: a failure part-way leaves the
registry at 46, so the v0.17.2 image still starts and re-applies 046 lazily
to the files already rolled back.

The FAST rollback (the v0.17 image on the 046 schema) needs none of this:
v0.17 never reads the new tables, and the two new columns are nullable and
named in none of its statements (its INSERTs name their columns). Run this
inside the v0.17.2 container (its migrations folder), with the bundle
STOPPED and a fresh backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v0172.py
  docker compose run --rm octo-core python /app/scripts/rollback_v0172.py --apply

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

MIGRATION = 46


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
    for name, target in (("telemetry.db", "telemetry"), ("entities.db", "entities")):
        for f in sorted(clients.glob(f"*/{name}")) if clients.is_dir() else []:
            try:
                if f.stat().st_size and _version(f) >= MIGRATION:
                    steps.append({"file": str(f), "migration": MIGRATION, "target": target})
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
        print("rollback_v0172: --data-root (or OCTO_DATA_ROOT) must be the data root",
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
