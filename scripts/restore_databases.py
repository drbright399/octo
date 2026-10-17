#!/usr/bin/env python3
"""restore_databases.py — rebuild an OCTO data root from one backup run.

Counterpart to backup_databases.py, which flattens every database into a
timestamped run directory:

    registry.db.gz
    global_audit.db.gz            global_patterns.db.gz
    tenant_<slug>_events.db.gz    tenant_<slug>_indicators.db.gz   …

This script reverses that mapping into the live layout:

    <data_root>/registry.db
    <data_root>/global/{audit,patterns,quarantine}.db
    <data_root>/clients/<slug>/{events,indicators,audit,tickets,telemetry,entities}.db

Safety:
  - the target data root must not already contain a registry.db (restore
    into an EMPTY root, then swap directories — never over a live one)
  - every restored file gets PRAGMA integrity_check; any failure = exit 1
  - secrets (mfa-key.env, adapter-credentials-key.env) are NOT in database
    backups by design — restore them from your key escrow. Without the
    original mfa-key.env every operator must re-enrol 2FA
    (`bundle_bootstrap --reset-factory-admin` gets the first admin back in).

Usage (inside the bundle image):
    python /app/scripts/restore_databases.py \\
        --backup-run /backup/20260919T151326Z --data-root /restore-target

Exit codes: 0 all restored + clean · 1 a restore/integrity failure · 2 setup error
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path

_SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
# The per-tenant and global database names backup_databases.py writes
# (telemetry = the tiered DNS / flow store, migration 036). A name outside
# these lists is not restored into the live layout.
TENANT_DBS = ("events", "indicators", "audit", "tickets", "telemetry", "entities")
GLOBAL_DBS = ("audit", "patterns", "quarantine")
_TENANT_RE = re.compile(rf"^tenant_({_SLUG})_({'|'.join(TENANT_DBS)})\.db(\.gz)?$")
_GLOBAL_RE = re.compile(rf"^global_({'|'.join(GLOBAL_DBS)})\.db(\.gz)?$")
_REGISTRY_RE = re.compile(r"^registry\.db(\.gz)?$")


def _target_for(name: str, root: Path) -> Path | None:
    if _REGISTRY_RE.match(name):
        return root / "registry.db"
    m = _GLOBAL_RE.match(name)
    if m:
        return root / "global" / f"{m.group(1)}.db"
    m = _TENANT_RE.match(name)
    if m:
        return root / "clients" / m.group(1) / f"{m.group(2)}.db"
    return None  # -wal / -shm sidecars, reports, anything unknown


def _integrity_ok(path: Path) -> bool:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--backup-run", type=Path, required=True,
                    help="one timestamped run directory written by backup_databases.py")
    ap.add_argument("--data-root", type=Path, required=True,
                    help="EMPTY directory to rebuild the data root in")
    args = ap.parse_args(argv)

    run, root = args.backup_run, args.data_root
    if not run.is_dir():
        print(f"setup error: {run} is not a directory", file=sys.stderr)
        return 2
    if (root / "registry.db").exists():
        print(f"refusing: {root} already has a registry.db — restore into an "
              "empty directory, then swap", file=sys.stderr)
        return 2
    root.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    for src in sorted(run.iterdir()):
        dst = _target_for(src.name, root)
        if dst is None or not src.is_file():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            if src.suffix == ".gz":
                with gzip.open(src, "rb") as fin, open(dst, "wb") as fout:
                    shutil.copyfileobj(fin, fout)
            else:
                shutil.copyfile(src, dst)
            ok = _integrity_ok(dst)
        except Exception as exc:  # noqa: BLE001 — report every file, then fail
            results.append({"file": src.name, "ok": False, "error": repr(exc)})
            continue
        results.append({"file": src.name, "ok": ok,
                        "restored_to": str(dst.relative_to(root)),
                        "bytes": dst.stat().st_size})

    failed = [r for r in results if not r["ok"]]
    print(json.dumps({"restored": len(results) - len(failed),
                      "failed": len(failed), "results": results}, indent=2))
    if not results:
        print("setup error: no database files recognised in the run directory",
              file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
