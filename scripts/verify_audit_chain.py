#!/usr/bin/env python3
"""verify_audit_chain.py — walk every audit.db and verify hash-link integrity.

Builds on `apps/octo/auth/audit.py:verify()` (which walks one DB) by
iterating every audit.db on this host:

  - <data_root>/global/audit.db                  (global audit chain)
  - <data_root>/clients/<slug>/audit.db          (per-tenant chain, one per client)

For each DB:
  - Open read-only.
  - Call `audit.verify()`.
  - Record (ok, row_count, first_error) and the file path.

Exit code:
  0   every chain verified clean
  1   one or more chains FAILED verification (tampering or corruption)
  2   could not inspect (permissions, missing files, etc.)

Output:
  - Human-readable summary to stderr.
  - Structured JSON report to stdout (or --report-out=<path>) for
    consumption by cron / monitoring.

Designed to run as a scheduled systemd-timer job. Recommended cadence:
hourly for the global chain, daily for the per-tenant chains (latter
can be slower as they grow). For v1 we run everything hourly.

This script ships in `scripts/` rather than `apps/octo/` because it's
an operational tool, not part of the runtime surface. The output is
intended for a systemd timer that fires this every hour and pipes the
JSON report to a monitoring log file. The legacy host's deploy spec is
`ops/legacy-host/verify-audit-chain.{service,timer}` (deploy files, not
part of the public copy).

Banked 2026-05-21 in response to external concept review: 4 of 5
reviewers asked for a scheduled chain-integrity verifier beyond the
write-time `hash_link`. ChatGPT and Kimi additionally asked for WORM
off-host checkpointing (separate slice; this script is the local
verifier half).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# Make `apps.octo.*` importable when running this file directly from
# the scripts dir. The systemd unit normally sets PYTHONPATH=<repo
# root>; this fallback covers ad-hoc invocation.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from apps.octo.auth import audit  # noqa: E402
from apps.octo.auth import config  # noqa: E402
from apps.octo.db import connect  # noqa: E402


@dataclass
class ChainResult:
    """Outcome of verifying one audit.db file."""
    db_path: str
    label: str                  # "global" or "tenant:<slug>"
    ok: bool
    row_count: int
    error: Optional[str]        # None on success
    elapsed_ms: int


def _verify_one(p: Path, label: str) -> ChainResult:
    """Verify one audit.db. Catches read failures + chain mismatches."""
    if not p.exists():
        return ChainResult(
            db_path=str(p), label=label, ok=False, row_count=0,
            error="file not found", elapsed_ms=0,
        )
    start = time.monotonic()
    try:
        conn = connect(p, read_only=True)
    except Exception as e:  # noqa: BLE001
        return ChainResult(
            db_path=str(p), label=label, ok=False, row_count=0,
            error=f"open failed: {e}",
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    try:
        ok, count, first_error = audit.verify(conn)
        return ChainResult(
            db_path=str(p), label=label, ok=ok, row_count=count,
            error=first_error,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except Exception as e:  # noqa: BLE001
        return ChainResult(
            db_path=str(p), label=label, ok=False, row_count=0,
            error=f"verify raised: {e}",
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    finally:
        conn.close()


def _discover_audit_dbs(data_root: Path) -> list[tuple[Path, str]]:
    """List every audit.db reachable under `data_root`.

    Returns (path, label) tuples in deterministic order: global first,
    then per-tenant ordered by slug. Both `data_root/global/audit.db`
    and `data_root/clients/*/audit.db` are recognized.
    """
    targets: list[tuple[Path, str]] = []
    global_db = data_root / "global" / "audit.db"
    if global_db.exists():
        targets.append((global_db, "global"))
    clients_dir = data_root / "clients"
    if clients_dir.is_dir():
        for tenant_dir in sorted(clients_dir.iterdir()):
            if not tenant_dir.is_dir():
                continue
            tenant_audit = tenant_dir / "audit.db"
            if tenant_audit.exists():
                targets.append((tenant_audit, f"tenant:{tenant_dir.name}"))
    return targets


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--data-root", type=Path, required=False, default=None,
        help="OCTO data root (contains global/ and clients/). "
             "Default: $OCTO_DATA_ROOT, else ~/octo/data of the account "
             "running the check (the single-host production layout).",
    )
    parser.add_argument(
        "--report-out", type=Path, default=None,
        help="Write the structured JSON report to this path. "
             "Default: stdout.",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the human-readable stderr summary. JSON report is "
             "still produced.",
    )
    args = parser.parse_args(argv)
    if args.data_root is None:
        # Resolved at run time (apps/octo/auth/config.py), never a baked path.
        # No usable home = "could not inspect" (2), never exit 1 (tampering).
        try:
            args.data_root = config.data_root()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            return 2

    started = time.time()
    targets = _discover_audit_dbs(args.data_root)
    if not targets:
        msg = f"no audit.db files found under {args.data_root}"
        print(msg, file=sys.stderr)
        return 2

    results = [_verify_one(p, label) for p, label in targets]

    n_total = len(results)
    n_failed = sum(1 for r in results if not r.ok)
    total_rows = sum(r.row_count for r in results)
    total_ms = sum(r.elapsed_ms for r in results)

    report = {
        "started_at": started,
        "finished_at": time.time(),
        "data_root": str(args.data_root),
        "chains_total": n_total,
        "chains_failed": n_failed,
        "rows_verified": total_rows,
        "elapsed_ms_total": total_ms,
        "results": [asdict(r) for r in results],
    }

    out_text = json.dumps(report, indent=2)
    if args.report_out:
        args.report_out.write_text(out_text + "\n")
    else:
        print(out_text)

    if not args.quiet:
        for r in results:
            mark = "OK " if r.ok else "FAIL"
            err = f" — {r.error}" if r.error else ""
            print(
                f"  {mark}  {r.label:30s}  rows={r.row_count:>7d}  "
                f"{r.elapsed_ms:>4d}ms{err}",
                file=sys.stderr,
            )
        print(
            f"\nVerified {n_total} chain(s), {total_rows} rows, "
            f"{total_ms}ms total. {n_failed} failed.",
            file=sys.stderr,
        )

    return 0 if n_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
