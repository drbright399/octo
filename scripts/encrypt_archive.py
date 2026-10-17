#!/usr/bin/env python3
"""encrypt_archive.py — encrypt the cold archive's existing PLAINTEXT day files.

The archive written before encryption existed (2026-10-07: gzip JSONL per
tenant per day, `apps.octo.retention.archive`) holds unmasked DNS with
device names. This converts it, file by file, to the age format the nightly
run now writes (`apps.octo.retention.archive_crypto`: X25519, to the
operator's PUBLIC keys in OCTO_ARCHIVE_RECIPIENTS_PATH — the private key
never comes onto the bundle host).

Four steps, each its own run (Rick's rule: nothing is shredded until it is
verified):

  (no flag)            DRY RUN — per tenant and day: plaintext / encrypted copy
                       (verified or not) / plaintext deleted, and what the next
                       step would do. Writes nothing.
  --apply              encrypt each plaintext day file to the configured
                       recipients: `<day>.jsonl.gz.age` + `.sha256` (over the
                       ciphertext) + the day's row-id ledger + a manifest entry
                       recording the plaintext's sha256. The plaintext is KEPT.
                       A plaintext that changed since its copy (a later
                       plaintext append) is encrypted again.
  --verify --identity <path>
                       decrypt every encrypted file with the operator's age
                       identity file (brought for this run, 0600, never
                       printed): checksum first, then the rows against the
                       ledger and — a converted file — the decrypted bytes
                       against the plaintext's recorded sha256. A file that
                       passes gets a verify record in the manifest.
  --delete-plaintext   unlink each plaintext day file (+ its sidecar) whose
                       encrypted copy has a verify record matching BOTH files
                       as they are now. Anything else is refused and named.
                       Also removes the temp files interrupted writes left
                       (`.<file>.tmp-<hex>`: a killed plaintext append leaves
                       a full PLAINTEXT copy of the day there; its rows are
                       in the committed files or still in telemetry.db —
                       never counted as archived). The dry run lists them.
                       This is an unlink, NOT a secure erase: on a
                       copy-on-write filesystem, a parity array, a
                       snapshot or a backup the old blocks / copies may
                       persist.

Each writing step holds the retention run lock (a nightly run never writes
the same day meanwhile; a run in progress = exit 3, try again).

Usage (bundle host):
    docker compose exec octo-core python /app/scripts/encrypt_archive.py
    docker compose exec octo-core python /app/scripts/encrypt_archive.py --apply
    # --verify: the identity on host tmpfs for this run only, removed right
    # after (docs/operations/bundle.md "Archive encryption"):
    docker compose run --rm --no-deps -v /dev/shm/archive-identity.txt:/run/archive-identity.txt:ro \
        octo-core python /app/scripts/encrypt_archive.py --verify --identity /run/archive-identity.txt
    rm /dev/shm/archive-identity.txt
    docker compose exec octo-core python /app/scripts/encrypt_archive.py --delete-plaintext
    ... --tenant acme-corp                    # only these tenants (repeatable)
    ... --day 2026-10-07 / --from … --to …    # only these days
    ... --json

Exit: 0 done · 1 a file failed or was refused (the others were done) ·
2 setup / nothing to do · 3 another retention run holds the lock.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "packages" / "shared-adapter-contract"):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

NOT_SECURE_ERASE = (
    "note: deletion is an UNLINK, not a secure erase — on a copy-on-write "
    "filesystem, a parity array, a snapshot or a backup the old plaintext "
    "may persist; treat those copies as plaintext until they age out"
)


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


def _state(archive, slug: str, day: str) -> dict:
    """What one day holds, for the dry run."""
    plain = archive.day_file(slug, day)
    files = archive.manifest(slug).get("files") or {}
    copies = archive.copies_of_plaintext(slug, day)
    current = archive.current_copy(slug, day)
    parts = [p for p in archive.encrypted_files(slug, day) if p not in copies]
    out = {"tenant": slug, "day": day, "plaintext": plain.exists(),
           "encrypted_copy": bool(copies), "parts": len(parts)}
    if plain.exists():
        out["plaintext_bytes"] = plain.stat().st_size
    if copies:
        out["copy_current"] = current is not None
        out["verified"] = bool(current is not None and (
            files.get(archive._rel(slug, current)) or {}).get("verified"))
    if not plain.exists():
        out["next"] = None
        out["state"] = ("plaintext deleted — encrypted copy only" if copies
                        else "no plaintext day file")
    elif not copies:
        out["state"], out["next"] = "plaintext only", "--apply would encrypt it"
    elif not out.get("copy_current"):
        out["state"], out["next"] = ("plaintext changed since its encrypted copy",
                                     "--apply would encrypt it again")
    elif not out.get("verified"):
        out["state"], out["next"] = ("plaintext + encrypted copy, NOT verified",
                                     "--verify --identity <path> would check it")
    else:
        out["state"], out["next"] = ("plaintext + VERIFIED encrypted copy",
                                     "--delete-plaintext would unlink the plaintext")
    return out


def main(argv: Optional[list[str]] = None) -> int:
    from apps.octo import paths
    from apps.octo.auth.config import data_root
    from apps.octo.retention import archive_crypto
    from apps.octo.retention.archive import ArchiveError, ColdArchive, is_plaintext_temp
    from apps.octo.retention.job import LOCK_NAME, _Lock

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--archive-root", type=Path, default=paths.archive_root(),
                    help="Archive root (default: $OCTO_ARCHIVE_ROOT).")
    ap.add_argument("--data-root", type=Path, default=data_root(),
                    help="OCTO data root — for the retention run lock. Default: $OCTO_DATA_ROOT.")
    ap.add_argument("--tenant", action="append", default=[], help="Only this tenant (repeatable).")
    ap.add_argument("--day", action="append", default=[], help="Only this UTC day (repeatable).")
    ap.add_argument("--from", dest="date_from", help="First day of a range (YYYY-MM-DD).")
    ap.add_argument("--to", dest="date_to", help="Last day of a range (YYYY-MM-DD).")
    step = ap.add_mutually_exclusive_group()
    step.add_argument("--apply", action="store_true",
                      help="Encrypt each plaintext day file (the plaintext is kept).")
    step.add_argument("--verify", action="store_true",
                      help="Decrypt-check every encrypted file with --identity; record it.")
    step.add_argument("--delete-plaintext", action="store_true",
                      help="Unlink plaintext day files whose encrypted copy was verified.")
    ap.add_argument("--identity", type=Path,
                    help="The operator's age identity file for --verify (0600; never printed).")
    ap.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = ap.parse_args(argv)

    if args.archive_root is None:
        print("setup error: no archive root (--archive-root or OCTO_ARCHIVE_ROOT)", file=sys.stderr)
        return 2
    if args.identity is not None and not args.verify:
        print("setup error: --identity goes with --verify (the other steps never need "
              "the private key)", file=sys.stderr)
        return 2
    try:
        wanted_days = _days(args)
    except ValueError as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2
    archive = ColdArchive(args.archive_root)
    if not archive.root.is_dir():
        print(f"setup error: archive root {archive.root} does not exist", file=sys.stderr)
        return 2
    tenants = [t for t in archive.tenants() if not args.tenant or t in args.tenant]
    if not tenants:
        print(f"nothing to do: no tenant folder under {archive.root / 'telemetry'}",
              file=sys.stderr)
        return 2

    def days_of(slug: str) -> list[str]:
        held = archive.days(slug)
        return [d for d in held if d in wanted_days] if wanted_days else held

    def temps_of(slug: str) -> dict[str, list[Path]]:
        """Leftover temp files of interrupted writes, by day (a day may have
        nothing else: its first write was the one killed)."""
        return {d: fs for d, fs in sorted(archive.leftover_temps(slug).items())
                if not wanted_days or d in wanted_days}

    policy = archive_crypto.load_policy()
    report: dict = {"mode": "dry_run", "tenants": tenants, "files": []}
    failed = 0

    if args.verify:
        report["mode"] = "verify"
        if args.identity is None:
            print("setup error: --verify needs --identity <path> (the operator's age "
                  "identity file)", file=sys.stderr)
            return 2
        try:
            identities = archive_crypto.load_identities(args.identity)
        except archive_crypto.EncryptionConfigError as exc:
            print(f"setup error: {exc}", file=sys.stderr)
            return 2
        print("identity: " + ", ".join(d["short"] for d in identities.describe())
              + " (public keys of the identities given)")
    elif args.apply:
        report["mode"] = "apply"
        if policy.recipients_error or not policy.recipients:
            print("refused: no usable recipients — "
                  + (policy.recipients_error or
                     f"put the operator's PUBLIC key in {policy.recipients_path} "
                     f"({archive_crypto.RECIPIENTS_ENV})"), file=sys.stderr)
            return 2
        enc = archive_crypto.with_recipients(policy.recipients, path=policy.recipients_path)
        print("recipients: " + ", ".join(
            f"{d['short']} ({d['fingerprint']})" for d in archive_crypto.describe_recipients(
                enc.recipients)))
        if not policy.required:
            print(f"note: {archive_crypto.POLICY_ENV} is off — the nightly run keeps writing "
                  "NEW files in plaintext")
    elif args.delete_plaintext:
        report["mode"] = "delete_plaintext"

    if report["mode"] == "dry_run":
        if policy.recipients:
            print("recipients: " + ", ".join(
                f"{d['short']} ({d['fingerprint']})"
                for d in archive_crypto.describe_recipients(policy.recipients)))
        else:
            print("recipients: NONE usable — "
                  + (policy.recipients_error or "no recipients file")
                  + " (--apply needs them)")
        counts = {"plaintext only": 0, "changed": 0, "unverified": 0, "verified": 0,
                  "deleted": 0, "temp": 0, "plaintext temp": 0}
        for slug in tenants:
            for day, temps in temps_of(slug).items():
                for f in temps:
                    plaintext = is_plaintext_temp(f.name)
                    counts["temp"] += 1
                    counts["plaintext temp"] += plaintext
                    report["files"].append({"tenant": slug, "day": day, "temp": str(f),
                                            "plaintext": plaintext})
                    print(f"{slug} {day}: leftover temp file of an interrupted write "
                          f"{f.name}" + (" — PLAINTEXT rows inside" if plaintext else "")
                          + " — --delete-plaintext would remove it")
            for day in days_of(slug):
                s = _state(archive, slug, day)
                report["files"].append(s)
                if s["next"] is None and not s["encrypted_copy"]:
                    continue
                key = ("deleted" if not s["plaintext"] else
                       "plaintext only" if not s["encrypted_copy"] else
                       "changed" if not s.get("copy_current") else
                       "verified" if s.get("verified") else "unverified")
                counts[key] += 1
                print(f"{slug} {day}: {s['state']}"
                      + (f" (+{s['parts']} nightly part(s))" if s["parts"] else "")
                      + (f" — {s['next']}" if s["next"] else ""))
        report["counts"] = counts
        print(f"plaintext day files: {counts['plaintext only']} not yet encrypted · "
              f"{counts['changed']} changed since their copy · {counts['unverified']} "
              f"copy NOT verified · {counts['verified']} verified (deletable) · "
              f"{counts['deleted']} already deleted")
        if counts["temp"]:
            print(f"leftover temp files: {counts['temp']} ({counts['plaintext temp']} with "
                  "plaintext rows) — if no retention run is in progress, these are from "
                  "interrupted writes; --delete-plaintext removes them")
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        print("dry run — nothing was written")
        return 0

    lock = _Lock(args.data_root / LOCK_NAME)
    if not lock.acquire():
        print("skipped: a retention run holds the lock — try again when it is done",
              file=sys.stderr)
        return 3
    deleted = temps_removed = 0
    try:
        for slug in tenants:
            for day in days_of(slug):
                try:
                    if args.apply:
                        r = archive.convert_day(slug, day, enc)
                        if r["status"] != "no-plaintext":
                            print(f"{slug} {day}: {r['status']}"
                                  + (f" → {Path(r['file']).name}" if r.get("file") else ""))
                        report["files"].append(dict(r, tenant=slug))
                    elif args.verify:
                        for r in archive.verify_encrypted(slug, day, identities):
                            report["files"].append(dict(r, tenant=slug))
                            failed += not r["ok"]
                            print(f"{slug} {day}: {Path(r['file']).name}: "
                                  + (f"verified ({r['rows']} rows)" if r["ok"]
                                     else f"FAILED — {r['error']}"))
                    else:
                        r = archive.delete_plaintext(slug, day)
                        report["files"].append(dict(r, tenant=slug))
                        if r["status"] == "deleted":
                            deleted += 1
                            print(f"{slug} {day}: plaintext unlinked")
                        elif r["status"] == "refused":
                            failed += 1
                            print(f"{slug} {day}: plaintext KEPT — {r['reason']}")
                except ArchiveError as exc:
                    failed += 1
                    report["files"].append({"tenant": slug, "day": day, "error": str(exc)})
                    print(f"{slug} {day}: ERROR {exc}")
            if not args.delete_plaintext:
                continue
            # Under the lock no write is in progress: every temp is a leftover.
            for day in temps_of(slug):
                try:
                    for r in archive.remove_leftover_temps(slug, day):
                        temps_removed += 1
                        report["files"].append(dict(r, tenant=slug, status="temp-removed"))
                        print(f"{slug} {day}: leftover temp file {Path(r['file']).name} "
                              "removed" + (" (it held plaintext rows)" if r["plaintext"] else ""))
                except ArchiveError as exc:
                    failed += 1
                    report["files"].append({"tenant": slug, "day": day, "error": str(exc)})
                    print(f"{slug} {day}: ERROR {exc}")
    finally:
        lock.release()
    if args.delete_plaintext:
        print(f"{deleted} plaintext day file(s) unlinked, {temps_removed} leftover temp "
              "file(s) removed")
        print(NOT_SECURE_ERASE)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
