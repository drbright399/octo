#!/usr/bin/env python3
"""dev_reset_triage.py — wipe the autonomous-triage layer from dev tenants.

Clears agent_notes + agent_pattern_links + the agent_triage_state watermark
from each dev tenant's events.db so the worker re-baselines from a clean
slate (skip-backlog → watermark jumps to current max on the next tick;
the /tickets triage feed starts empty and fills only with fresh, real
worker output).

Use after dev demos that left manual-triage cruft. Unlike
dev_clean_synthetic_notes.sh (which removes only `synthetic-%` seed notes),
this clears ALL agent notes incl. real `triage-`/uuid demo notes — it's a
full re-baseline, dev-only.

HARD-GATED to dev, with the dev-root check every dev tool shares
(apps/octo/dev/dev_root.py): the data root, after resolving symlinks and
`..`, must sit under ~/.octo-dev or strictly under /tmp or /var/tmp, and
never inside a production data-root location (/var/lib/octo, ~/octo), even
when a dev path leads there. A path that merely contains "octo-dev" is not
enough. Each tenant's events.db is checked the same way, so a clients/,
tenant or events.db symlink out of the dev root is refused too; any
refusal (exit 2) happens before anything is reset. --slug must be a plain
tenant directory name. Never touches production. Idempotent.

Usage:
  scripts/dev_reset_triage.py                 # all dev tenants
  scripts/dev_reset_triage.py --slug dev-buoy-acme
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

# Repo root on sys.path so the strict dev-root check (apps.octo.dev.dev_root,
# standard library only) imports when this runs as a plain script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from apps.octo.dev.dev_root import dev_root_problem  # noqa: E402


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


# Recreate the migration-011 append-only triggers after we delete (dev only).
_PATTERN_LINK_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_update "
    "BEFORE UPDATE ON agent_pattern_links "
    "BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;",
    "CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_delete "
    "BEFORE DELETE ON agent_pattern_links "
    "BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;",
)


def _reset_tenant(edb: Path) -> dict[str, int]:
    counts = {"agent_notes": 0, "agent_pattern_links": 0, "agent_triage_state": 0}
    conn = sqlite3.connect(edb, timeout=15)
    try:
        if _table_exists(conn, "agent_notes"):
            counts["agent_notes"] = conn.execute(
                "SELECT COUNT(*) FROM agent_notes").fetchone()[0]
            conn.execute("DELETE FROM agent_notes")
        if _table_exists(conn, "agent_pattern_links"):
            counts["agent_pattern_links"] = conn.execute(
                "SELECT COUNT(*) FROM agent_pattern_links").fetchone()[0]
            # The append-only triggers block DELETE — drop, clear, recreate.
            conn.execute("DROP TRIGGER IF EXISTS agent_pattern_links_no_delete")
            conn.execute("DROP TRIGGER IF EXISTS agent_pattern_links_no_update")
            conn.execute("DELETE FROM agent_pattern_links")
            for ddl in _PATTERN_LINK_TRIGGERS:
                conn.execute(ddl)
        if _table_exists(conn, "agent_triage_state"):
            counts["agent_triage_state"] = conn.execute(
                "SELECT COUNT(*) FROM agent_triage_state").fetchone()[0]
            conn.execute("DELETE FROM agent_triage_state")
        conn.commit()
    finally:
        conn.close()
    return counts


def _refuse(message: str) -> int:
    print(f"ERROR: refusing to reset: {message}", file=sys.stderr)
    return 2


def _is_plain_name(slug: str) -> bool:
    """A single directory name: no path separator, not '.' or '..'."""
    return slug not in ("", ".", "..") and Path(slug).name == slug


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-root", default=os.environ.get(
        "OCTO_DATA_ROOT", str(Path.home() / ".octo-dev" / "data")))
    ap.add_argument("--slug", default=None,
                    help="Reset a single tenant (default: all dev tenants).")
    args = ap.parse_args(argv)

    # Strict dev-root gate before anything under the root is read.
    problem = dev_root_problem(args.data_root)
    if problem is not None:
        return _refuse(f"{problem}. This tool only resets dev tenants.")
    data_root = Path(args.data_root).expanduser().resolve()
    if args.slug is not None and not _is_plain_name(args.slug):
        return _refuse(
            f"--slug must be a single tenant directory name, got {args.slug!r}.")

    clients = data_root / "clients"
    if not clients.is_dir():
        print(f"no clients dir at {clients} — nothing to reset.")
        return 0

    if args.slug:
        tenant_dirs = [clients / args.slug]
    else:
        tenant_dirs = sorted(d for d in clients.glob("dev-*") if d.is_dir())

    # The root passed, but clients/, a tenant dir or events.db itself may be
    # a symlink out of it: check where each database really lives, and
    # refuse before resetting any of them.
    targets: list[tuple[str, Path]] = []
    for d in tenant_dirs:
        edb = d / "events.db"
        if not edb.exists():
            continue
        problem = dev_root_problem(edb)
        if problem is not None:
            return _refuse(
                f"tenant {d.name!r}: its events.db fails the dev-root check "
                f"({problem}).")
        targets.append((d.name, edb.resolve()))

    totals = {"agent_notes": 0, "agent_pattern_links": 0, "agent_triage_state": 0}
    for name, edb in targets:
        c = _reset_tenant(edb)
        if any(c.values()):
            print(f"  {name}: notes={c['agent_notes']} "
                  f"links={c['agent_pattern_links']} watermark_rows={c['agent_triage_state']}")
        for k in totals:
            totals[k] += c[k]

    print(f"\nReset across {len(tenant_dirs)} tenant(s): "
          f"{totals['agent_notes']} notes, {totals['agent_pattern_links']} links, "
          f"{totals['agent_triage_state']} watermark(s) cleared.")
    print("The worker will re-baseline (skip-backlog) on its next tick; the "
          "triage feed starts clean and fills with fresh output.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
