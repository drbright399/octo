#!/usr/bin/env python3
"""rollback_v0175.py — the SQL rollback of v0.17.5 (migration 048: RECALL an
acknowledgement, and NOTES on it). DRY RUN unless --apply.

  registry.db                   048 rollback (registry) → user_version 47

Nothing is destroyed: `alert_verdict_followup` (every note and recall) is
LEFT AS IT IS — nothing before 048 reads it — and a re-upgrade finds it
current (every recall applies again, every note shows again). The registry
gets `PRAGMA integrity_check` after. To go further back (v0.17.3 → v0.17.2),
run `rollback_v0173.py` AFTER this one (it refuses a registry at 48).

WHAT A ROLLED-BACK BUNDLE DOES DIFFERENTLY: a release before 048 does not
know recalls — a RECALLED acknowledgement covers its alert again (out of
"needs attention", not counted towards the site's colour), and the notes are
not shown. The dry run counts the recalled acknowledgements
(`recalled_acks`): non-zero → tell Rick which alerts go quiet again (or
acknowledge-and-wait: they return on the re-upgrade).

The FAST rollback (the v0.17.4 image on the 048 schema) needs none of this —
v0.17.4 never reads the table — and does the same as above. Run this inside
the v0.17.5 container (its migrations folder), with the bundle STOPPED and a
fresh backup:

  docker compose run --rm octo-core python /app/scripts/rollback_v0175.py
  docker compose run --rm octo-core python /app/scripts/rollback_v0175.py --apply

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

MIGRATION = 48


def _version(path: Path) -> int:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _recalled(path: Path) -> int:
    """The acknowledgements recalled (they cover their alerts again after a
    rollback). 0 when the table is not there."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM alert_verdict_followup "
                                "WHERE kind = 'recall'").fetchone()[0])
    except sqlite3.OperationalError:
        return 0
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
    return {"ok": True, "registry_version": reg_v, "steps": steps,
            "recalled_acks": _recalled(registry)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", default=None,
                        help="the bundle's data root (default: OCTO_DATA_ROOT)")
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    args = parser.parse_args(argv)
    root = Path(args.data_root or os.environ.get("OCTO_DATA_ROOT", "")).expanduser()
    if not str(root) or not root.is_dir():
        print("rollback_v0175: --data-root (or OCTO_DATA_ROOT) must be the data root",
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
