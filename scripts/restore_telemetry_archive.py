#!/usr/bin/env python3
"""restore_telemetry_archive.py — read archived raw telemetry back into a
SCRATCH database for forensics.

The retention job archives raw telemetry (answered DNS, TLS / HTTP / flow
metadata) to one gzip JSONL file per tenant per UTC day of ARRIVAL before
pruning it (`apps.octo.retention.archive`; a row's own `received_at` — the
sensor's time — is inside: for a sensor-time day, load its neighbours too).
This script loads chosen days back into a
standalone SQLite file with the telemetry.db schema — raw rows under their
ORIGINAL ids, payload / payload_sha256 / received_at / ingested_at exactly as archived,
plus the hourly roll-up and first-seen ledger rebuilt from them — so the
rows can be queried with any SQLite tool.

Encrypted archive files (age, X25519 — `apps.octo.retention.archive_crypto`:
nightly parts `<day>.pNNN.jsonl.gz.age`, converted day files
`<day>.jsonl.gz.age`) are read with `--identity <path>`: the operator's age
identity file (`age-keygen` output), brought for the restore — Athena never
holds it. A day split over a plaintext file and encrypted parts loads as ONE
day. A day with encrypted files and no --identity is not loaded (the report
says so).

Safety:
  * every file is checked against its .sha256 sidecar first — for an
    encrypted file, BEFORE it is decrypted; a mismatch is reported and that
    day is NOT loaded (--no-verify to load anyway, e.g. to salvage a damaged
    file);
  * the identity file is refused when group or other users can access it;
    no key material is ever printed or logged (only public-key short forms);
  * the output must be a NEW file (or --append to one this script made),
    owner-only (0600), and is refused anywhere under the live data root —
    the live telemetry.db is never written by this script. The scratch DB is
    as sensitive as the plaintext archive: with encrypted days, put it AND
    the identity file on host tmpfs (never a disk array, cache or app-data
    share — an unlink there is not a secure erase), remove the identity as
    soon as the restore has run and the scratch DB when the analysis is done
    (docs/operations/bundle.md "Archive encryption").

Usage:
    python /app/scripts/restore_telemetry_archive.py \\
        --archive-root /var/lib/octo/archive --tenant acme-corp \\
        --day 2026-09-20 --day 2026-09-21 --out /tmp/acme-dns-0920.db
    ... --from 2026-09-01 --to 2026-09-07        # a range of days
    ... --identity /run/archive-identity.txt      # encrypted files (0600, tmpfs mount)
    ... --list                                    # what the archive holds

Exit: 0 loaded · 1 a day failed verification / could not be read · 2 setup.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "packages" / "shared-adapter-contract"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_MARKER_TABLE = "restored_telemetry_archive"


def _days(args) -> list[str]:
    days = list(args.day)
    if args.date_from or args.date_to:
        if not (args.date_from and args.date_to):
            raise ValueError("--from and --to go together")
        d = date.fromisoformat(args.date_from)
        end = date.fromisoformat(args.date_to)
        if end < d:
            raise ValueError("--to is before --from")
        while d <= end:
            days.append(d.isoformat())
            d += timedelta(days=1)
    return sorted(set(days))


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def restore(
    archive_root: Path, tenant: str, days: list[str], out: Path, *,
    append: bool = False, verify: bool = True, data_root: Optional[Path] = None,
    identities=None,
) -> dict:
    """Load `days` of `tenant`'s archive into the scratch DB `out`. Returns a
    report; raises ValueError for a refused output. `identities`: the
    operator's `AgeIdentities` for encrypted files (None = plaintext only)."""
    from apps.octo.ingest import telemetry as telemetry_store
    from apps.octo.ingest import tiering
    from apps.octo.migration import apply_migration, list_migrations
    from apps.octo.retention.archive import ArchiveError, ColdArchive, is_encrypted_name

    if data_root is not None and _inside(out, data_root):
        raise ValueError(f"refusing to write inside the live data root ({data_root})")
    if out.exists() and not append:
        raise ValueError(f"{out} exists — choose a new file, or --append to a scratch DB")
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists():
        # The scratch DB holds unmasked DNS (device names too): owner-only,
        # whatever the umask (SQLite gives its -wal / -shm the same mode).
        os.close(os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        os.chmod(out, 0o600)
    conn = sqlite3.connect(out)
    try:
        if out.exists() and append:
            has_marker = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = ?", (_MARKER_TABLE,),
            ).fetchone()
            if not has_marker and conn.execute(
                "SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                raise ValueError(f"{out} was not made by this script — refusing to append")
        for mig in list_migrations(kind="forward"):
            if f"-- @target: {telemetry_store.TELEMETRY_TARGET}" in mig.sql:
                if conn.execute("PRAGMA user_version").fetchone()[0] < mig.number:
                    apply_migration(conn, mig, target=telemetry_store.TELEMETRY_TARGET)
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {_MARKER_TABLE} ("
            " day TEXT NOT NULL, tenant TEXT NOT NULL, rows INTEGER NOT NULL, "
            " sha256_verified INTEGER NOT NULL, loaded_at TEXT NOT NULL "
            " DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))"
        )
        conn.commit()

        archive = ColdArchive(archive_root)
        report: dict = {"tenant": tenant, "out": str(out), "days": {}}
        for day in days:
            try:
                files = archive.day_files(tenant, day)
                rows = archive.read_day(tenant, day, verify=verify, identities=identities)
            except (ArchiveError, OSError) as exc:
                report["days"][day] = {"ok": False, "error": str(exc)}
                continue
            loaded = 0
            conn.execute("BEGIN")
            for r in rows:
                # The row's arrival as archived (a line written before the
                # arrival column existed has none: its sensor time stands in).
                arrived = r.get("ingested_at") or r["received_at"]
                cur = conn.execute(
                    "INSERT OR IGNORE INTO telemetry_raw (id, received_at, source, "
                    " event_type, severity, source_host, domain, device, device_name, "
                    " payload, payload_truncated, payload_sha256, origin_event_id, "
                    " ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (r["id"], r["received_at"], r["source"], r["event_type"],
                     r.get("severity") or "info", r.get("source_host"),
                     r.get("domain") or "", r.get("device") or "",
                     r.get("device_name") or "", r["payload"],
                     1 if r.get("payload_truncated") else 0, r["payload_sha256"],
                     r.get("origin_event_id"), arrived),
                )
                if cur.rowcount:
                    loaded += 1
                    try:
                        parsed = json.loads(r["payload"])
                    except (TypeError, ValueError, RecursionError):
                        parsed = None      # a truncated payload: type as stored
                    telemetry_store.fold(
                        conn, event_type=r["event_type"], domain=r.get("domain") or "",
                        device=r.get("device") or "",
                        seen=telemetry_store.canonical_ts(r["received_at"]),
                        rollup_type=tiering.rollup_event_type(r["event_type"], parsed),
                        arrival=telemetry_store.canonical_ts(arrived),
                        device_name=r.get("device_name") or "",
                    )
            conn.execute(
                f"INSERT INTO {_MARKER_TABLE} (day, tenant, rows, sha256_verified) "
                "VALUES (?, ?, ?, ?)", (day, tenant, loaded, 1 if verify else 0),
            )
            conn.execute("COMMIT")
            report["days"][day] = {
                "ok": True, "rows": len(rows), "loaded": loaded, "verified": verify,
                "files": len(files),
                "encrypted_files": sum(1 for f in files if is_encrypted_name(f.name)),
            }
        return report
    finally:
        conn.close()


def main(argv: Optional[list[str]] = None) -> int:
    from apps.octo import paths
    from apps.octo.retention.archive import ColdArchive

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archive-root", type=Path, default=paths.archive_root(),
                    help="Archive root (default: $OCTO_ARCHIVE_ROOT).")
    ap.add_argument("--tenant", required=True, help="Tenant slug.")
    ap.add_argument("--day", action="append", default=[], help="UTC day YYYY-MM-DD (repeatable).")
    ap.add_argument("--from", dest="date_from", help="First day of a range (YYYY-MM-DD).")
    ap.add_argument("--to", dest="date_to", help="Last day of a range (YYYY-MM-DD).")
    ap.add_argument("--out", type=Path, help="Scratch SQLite file to create.")
    ap.add_argument("--append", action="store_true",
                    help="Add days to a scratch DB this script created earlier.")
    ap.add_argument("--no-verify", dest="verify", action="store_false", default=True,
                    help="Load even when a file does not match its checksum.")
    ap.add_argument("--identity", type=Path,
                    help="The operator's age identity file (age-keygen output, mode 0600) "
                         "for encrypted archive files. Never printed or logged.")
    ap.add_argument("--list", action="store_true", help="List the tenant's archived days.")
    args = ap.parse_args(argv)

    if args.archive_root is None:
        print("setup error: no archive root (--archive-root or OCTO_ARCHIVE_ROOT)", file=sys.stderr)
        return 2
    archive = ColdArchive(args.archive_root)
    if args.list:
        print(json.dumps(archive.manifest(args.tenant), indent=2))
        return 0
    try:
        days = _days(args)
    except ValueError as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2
    if not days or args.out is None:
        print("setup error: give --out and at least one --day (or --from/--to)", file=sys.stderr)
        return 2
    identities = None
    if args.identity is not None:
        from apps.octo.retention.archive_crypto import EncryptionConfigError, load_identities

        try:
            identities = load_identities(args.identity)
        except EncryptionConfigError as exc:
            print(f"setup error: {exc}", file=sys.stderr)
            return 2
        print("identity: " + ", ".join(d["short"] for d in identities.describe())
              + " (public keys of the identities given)", file=sys.stderr)
    try:
        report = restore(args.archive_root, args.tenant, days, args.out,
                         append=args.append, verify=args.verify,
                         data_root=paths.data_root(), identities=identities)
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if all(d["ok"] for d in report["days"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
