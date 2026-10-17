#!/usr/bin/env python3
"""Mint a client ingest token (buoy / shim) against the bundle registry.

Usage (on the bundle host, venv python, OCTO_DATA_ROOT set):

    python scripts/mint_client_token.py --slug tenant-a \
        --label "buoy-forwarder tenant-a" [--kind buoy] \
        [--source-instance-id wazuh/primary]

Prints the plaintext token ONCE to stdout (never stored). The registry
stores only the PBKDF2 hash + prefix (`apps.octo.auth.core.hash_token`).
Run per buoy + one for the wazuh-shim during the ADR-0003 cutover.
"""
from __future__ import annotations

import argparse
import secrets
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "packages" / "shared-adapter-contract"))

from apps.octo import paths  # noqa: E402
from apps.octo.auth import core as auth_core  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--kind", default="buoy")
    ap.add_argument("--source-instance-id", default=None)
    args = ap.parse_args()

    reg = sqlite3.connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        client = reg.execute(
            "SELECT slug, status FROM clients WHERE slug = ?", (args.slug,)
        ).fetchone()
        if client is None:
            print(f"ERROR: no client with slug {args.slug!r}", file=sys.stderr)
            return 2
        if client["status"] != "active":
            print(
                f"ERROR: client {args.slug!r} is {client['status']}, not active",
                file=sys.stderr,
            )
            return 2

        plaintext = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        reg.execute(
            """
            INSERT INTO client_tokens
                (slug, token_hash, token_prefix, kind, label,
                 created_at, created_by, source_instance_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                args.slug,
                auth_core.hash_token(plaintext),
                auth_core.token_prefix(plaintext),
                args.kind,
                args.label,
                now,
                "mint_client_token.py",
                args.source_instance_id,
            ),
        )
        reg.commit()
    finally:
        reg.close()

    print(f"# token for {args.slug} ({args.label}) — shown ONCE, store in vault")
    print(plaintext)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
