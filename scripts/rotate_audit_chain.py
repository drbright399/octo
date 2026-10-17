#!/usr/bin/env python3
"""rotate_audit_chain.py — one-time rotation of a global audit chain that was
forked by the pre-fix concurrency race (prev_hash read outside the write lock;
fixed in the commit passed as --fix-commit).

Rewrites NO history. The forked chain is consolidated into a single read-only
SQLite file and LINKED — by hash — from the first row of a fresh chain and
from an external manifest, so neither file can later be swapped undetected.

Run with the API STOPPED, inside the FIXED image, as the container user:

    docker run --rm --user 1000:1000 --network none \\
        -v <state>:/var/lib/octo/state -v <out>:/rotation \\
        <fixed-image> python /app/scripts/rotate_audit_chain.py \\
        --data-root /var/lib/octo/state --out /rotation \\
        --fix-commit <40-hex> --image-tag <tag> --operator "<name>" \\
        --archived-location "<label — no hostnames/paths>"

It REFUSES to rotate (exit 3, nothing changed) unless the damage is fully
explained by the race:
  - every row's own row_hash recomputes from that row's stored prev_hash
    (an EDITED row would not)
  - every fork's prev_hash equals the row_hash of an EARLIER row
    (a DELETED row would leave a parent that matches nothing)
  - ids are contiguous from 1..N
Anything else is not this bug — stop and investigate.

Outputs in --out: audit-global-forked.db (journal_mode=DELETE, no sidecars),
rotation-manifest.json, pre-rotation-verify.json. The caller moves them to
the compliance archive, verifies hashes on both ends, THEN deletes the
originals. Exit: 0 rotated · 2 setup · 3 refused (unexplained damage)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apps.octo import paths  # noqa: E402
from apps.octo.auth import audit  # noqa: E402
from apps.octo.db import connect  # noqa: E402
from apps.octo.migration import apply_migration, list_migrations  # noqa: E402

_COLS = ("id", "ts", "actor", "actor_kind", "action", "target_kind", "target_id",
         "before_state", "after_state", "reason", "request_id", "client_slug",
         "prev_hash", "row_hash")


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _analyse(db_path: Path) -> dict:
    """Classify every row. Independent of SQLite page layout."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"SELECT {', '.join(_COLS)} FROM audit_log ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    content = hashlib.sha256()
    seen_hashes: dict[str, int] = {}
    self_valid, forks, unresolvable = 0, [], []
    prev_row_hash = audit.GENESIS_PREV_HASH
    for r in rows:
        content.update(json.dumps([r[c] for c in _COLS], separators=(",", ":"),
                                  ensure_ascii=False).encode() + b"\n")
        expected = audit._row_hash(
            prev_hash=r["prev_hash"], row_id=r["id"], ts=r["ts"], actor=r["actor"],
            action=r["action"], target_kind=r["target_kind"], target_id=r["target_id"],
            before_state=r["before_state"], after_state=r["after_state"],
            reason=r["reason"], request_id=r["request_id"])
        if expected == r["row_hash"]:
            self_valid += 1
        if r["prev_hash"] != prev_row_hash:
            forks.append(r["id"])
            if r["prev_hash"] not in seen_hashes:      # parent must be EARLIER
                unresolvable.append(r["id"])
        seen_hashes[r["row_hash"]] = r["id"]
        prev_row_hash = r["row_hash"]
    ids = [r["id"] for r in rows]
    return {
        "row_count": len(rows),
        "rows_self_hash_valid": self_valid,
        "fork_row_ids": forks,
        "forks_with_unresolvable_parent": unresolvable,
        "ids_contiguous": ids == list(range(1, len(rows) + 1)),
        "tip_row_id": ids[-1] if ids else None,
        "tip_row_hash": rows[-1]["row_hash"] if rows else None,
        "ts_min": rows[0]["ts"] if rows else None,
        "ts_max": rows[-1]["ts"] if rows else None,
        "content_sha256": content.hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--fix-commit", required=True)
    ap.add_argument("--image-tag", required=True)
    ap.add_argument("--operator", required=True)
    ap.add_argument("--archived-location", required=True)
    args = ap.parse_args(argv)

    if len(args.fix_commit) != 40 or any(c not in "0123456789abcdef" for c in args.fix_commit):
        print("setup: --fix-commit must be the full 40-hex commit", file=sys.stderr)
        return 2
    if any(tok in args.archived_location for tok in ("/", "\\", "@", ".net", ".com", ".local")):
        print("setup: --archived-location must be a label, not a path/host "
              "(it becomes a permanent, hashed audit field)", file=sys.stderr)
        return 2

    os.environ["OCTO_DATA_ROOT"] = str(args.data_root)
    live = paths.global_audit_db_path()
    if not live.exists():
        print(f"setup: {live} not found", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    archived = args.out / "audit-global-forked.db"
    if archived.exists():
        print(f"setup: {archived} already exists — refusing to overwrite", file=sys.stderr)
        return 2

    # Pre-rotation state of EVERY audit chain under the data root (global +
    # any per-tenant audit.db), kept as evidence.
    pre = {"global": None, "tenants": {}}
    c = connect(live, read_only=True)
    try:
        ok, n, err = audit.verify(c)
    finally:
        c.close()
    pre["global"] = {"ok": ok, "rows_verified": n, "first_error": err}
    for t in sorted((args.data_root / "clients").glob("*/audit.db")):
        tc = connect(t, read_only=True)
        try:
            tok, tn, terr = audit.verify(tc)
        finally:
            tc.close()
        pre["tenants"][t.parent.name] = {"ok": tok, "rows_verified": tn, "first_error": terr}
    (args.out / "pre-rotation-verify.json").write_text(json.dumps(pre, indent=2))
    if ok:
        print("global chain verifies — nothing to rotate")
        archived.unlink(missing_ok=True)
        return 0

    # Consolidate (WAL-safe) → single file → journal_mode=DELETE BEFORE hashing,
    # so the archive opens read-only later and its hash never changes.
    src = sqlite3.connect(f"file:{live}?mode=ro", uri=True)
    dst = sqlite3.connect(archived)
    try:
        src.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
        dst.commit()
    finally:
        dst.close()
        src.close()
    for side in ("-wal", "-shm"):
        if Path(str(archived) + side).exists():
            print(f"refusing: sidecar {side} exists next to the archive", file=sys.stderr)
            return 3

    a = _analyse(archived)
    explained = (a["rows_self_hash_valid"] == a["row_count"]
                 and not a["forks_with_unresolvable_parent"]
                 and a["ids_contiguous"] and a["fork_row_ids"])
    if not explained:
        print("REFUSING TO ROTATE — damage is NOT explained by the append race:\n"
              + json.dumps({k: a[k] for k in ("row_count", "rows_self_hash_valid",
                           "forks_with_unresolvable_parent", "ids_contiguous")}, indent=2),
              file=sys.stderr)
        return 3

    rotated_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    after_state = {
        "schema": "audit_chain_rotation/v1",
        "archived_sha256": _sha256_file(archived),
        "archived_size_bytes": archived.stat().st_size,
        "archived_content_sha256": a["content_sha256"],
        "archived_row_count": a["row_count"],
        "archived_tip_row_id": a["tip_row_id"],
        "archived_tip_row_hash": a["tip_row_hash"],
        "archived_ts_min": a["ts_min"],
        "archived_ts_max": a["ts_max"],
        "fork_row_ids_count": len(a["fork_row_ids"]),
        "first_fork_row_id": a["fork_row_ids"][0],
        "rows_self_hash_valid": a["rows_self_hash_valid"],
        "forks_with_unresolvable_parent": 0,
        "ids_contiguous": True,
        "archived_location": args.archived_location,
        "fix_commit": args.fix_commit,
        "image_tag": args.image_tag,
        "rotated_at": rotated_at,
    }

    # Fresh chain: same schema (migration 003, target 'audit'), first row
    # written by the FIXED append().
    fresh = live.with_name("audit.db.rotating")
    fresh.unlink(missing_ok=True)
    fc = connect(fresh)
    try:
        for mig in list_migrations(kind="forward"):
            if mig.number == 3:
                apply_migration(fc, mig, target="audit")
        request_id = str(uuid.uuid4())
        audit.append(fc, audit.AuditEntry(
            actor=args.operator, actor_kind="human", action="audit_chain_rotated",
            target_kind="audit_chain", target_id="global", client_slug="global",
            before_state=None, after_state=after_state,
            reason=("previous chain forked by concurrent appends (prev_hash read "
                    "outside the write lock); archived intact, linked by hash"),
            request_id=request_id,
        ))
        ok2, n2, err2 = audit.verify(fc)
        genesis_hash = fc.execute("SELECT row_hash FROM audit_log WHERE id = 1").fetchone()[0]
        fc.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        fc.close()
    if not (ok2 and n2 == 1):
        fresh.unlink(missing_ok=True)
        print(f"refusing: fresh chain did not verify ({err2})", file=sys.stderr)
        return 3

    # Swap: forked live file (+ sidecars) out, fresh chain in.
    for side in ("", "-wal", "-shm"):
        Path(str(live) + side).unlink(missing_ok=True)
    for side in ("-wal", "-shm"):
        Path(str(fresh) + side).unlink(missing_ok=True)
    fresh.rename(live)
    os.chmod(live, 0o640)

    manifest = dict(after_state)
    manifest.update({
        "fork_row_ids": a["fork_row_ids"],
        "new_genesis_row_hash": genesis_hash,
        "new_genesis_request_id": request_id,
        "operator": args.operator,
        "tenant_chains": pre["tenants"] or "none provisioned",
        "reverify_hint": "open the archive with file:<path>?mode=ro&immutable=1",
        "backups_note": (f"database backups taken before {rotated_at} contain the forked "
                         "chain; never restore them over the live global/audit.db"),
    })
    body = json.dumps(manifest, indent=2, sort_keys=True)
    manifest_path = args.out / "rotation-manifest.json"
    manifest_path.write_text(body + "\n")
    print(json.dumps({
        "rotated": True, "archived_rows": a["row_count"], "forks": len(a["fork_row_ids"]),
        "archived_sha256": after_state["archived_sha256"],
        "new_genesis_row_hash": genesis_hash,
        "manifest_sha256": hashlib.sha256((body + "\n").encode()).hexdigest(),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
