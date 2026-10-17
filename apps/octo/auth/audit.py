"""Hash-chained audit logging — spec §3.4 and §7.

Canonical hash form (§3.4):
    sha256(prev_hash || "\n" || id || "\n" || ts || "\n" || actor || "\n" ||
           action || "\n" || target_kind || "\n" || coalesce(target_id,'') ||
           "\n" || coalesce(before_state,'') || "\n" || coalesce(after_state,'') ||
           "\n" || coalesce(reason,'') || "\n" || request_id)

First row's prev_hash is the all-zero digest (64 hex chars of '0').
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

GENESIS_PREV_HASH = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _canonical_line(
    prev_hash: str,
    row_id: int,
    ts: str,
    actor: str,
    action: str,
    target_kind: str,
    target_id: Optional[str],
    before_state: Optional[str],
    after_state: Optional[str],
    reason: Optional[str],
    request_id: str,
) -> bytes:
    parts = [
        prev_hash,
        str(row_id),
        ts,
        actor,
        action,
        target_kind,
        target_id or "",
        before_state or "",
        after_state or "",
        reason or "",
        request_id,
    ]
    return "\n".join(parts).encode()


def _row_hash(**kwargs) -> str:
    return hashlib.sha256(_canonical_line(**kwargs)).hexdigest()


@dataclass
class AuditEntry:
    actor: str
    actor_kind: str          # 'human' | 'service' | 'system'
    action: str
    target_kind: str
    client_slug: str
    target_id: Optional[str] = None
    before_state: Optional[dict[str, Any] | list | str] = None
    after_state: Optional[dict[str, Any] | list | str] = None
    reason: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def _serialize(self, obj: Any) -> Optional[str]:
        if obj is None:
            return None
        if isinstance(obj, str):
            return obj
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def append(db: sqlite3.Connection, entry: AuditEntry) -> int:
    """Append an audit row. Returns the new row id.

    Must NOT be called on a connection that already has an open transaction:
    append() takes its own `BEGIN IMMEDIATE` (SQLite cannot nest them). Every
    production caller hands it a dedicated audit-DB connection.
    """
    before_json = entry._serialize(entry.before_state)
    after_json = entry._serialize(entry.after_state)

    # We need the row id before we can compute the hash — use a placeholder
    # strategy: INSERT, retrieve id, compute hash, UPDATE row_hash/prev_hash.
    # But the table forbids UPDATE. Alternative: pre-allocate the id via
    # INSERT with a deterministic computed hash that references a known id.
    # We compute: next_id = last(id)+1, hash with that, then INSERT with
    # AUTOINCREMENT. If a concurrent writer races us, we retry.

    # The audit log uses a coarse-grained lock via BEGIN IMMEDIATE to serialize
    # writes — contention is low because audit is per-client.
    db.execute("BEGIN IMMEDIATE")
    try:
        # The chain tip (id AND hash) and the timestamp MUST be read under
        # the write lock. Reading prev_hash before BEGIN IMMEDIATE let two
        # concurrent writers chain to the same parent: ids stayed unique but
        # the second row carried a stale prev_hash, so verify() reported
        # tampering. Seen on a production bundle within 15 minutes of its
        # first login (the dashboard fires 3 audited requests in parallel
        # every 30 s → 34 forks in 129 rows). ts under the lock also keeps
        # timestamps monotonic with ids.
        tip = db.execute(
            "SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = tip["row_hash"] if tip else GENESIS_PREV_HASH
        next_id = (tip["id"] if tip else 0) + 1
        ts = _utcnow_iso()
        row_hash = _row_hash(
            prev_hash=prev_hash,
            row_id=next_id,
            ts=ts,
            actor=entry.actor,
            action=entry.action,
            target_kind=entry.target_kind,
            target_id=entry.target_id,
            before_state=before_json,
            after_state=after_json,
            reason=entry.reason,
            request_id=entry.request_id,
        )
        db.execute(
            """
            INSERT INTO audit_log (
                id, ts, actor, actor_kind, action, target_kind, target_id,
                before_state, after_state, reason, request_id, client_slug,
                prev_hash, row_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_id, ts, entry.actor, entry.actor_kind, entry.action,
                entry.target_kind, entry.target_id, before_json, after_json,
                entry.reason, entry.request_id, entry.client_slug,
                prev_hash, row_hash,
            ),
        )
        db.execute("COMMIT")
        return next_id
    except Exception:
        # SQLite auto-rolls-back on SQLITE_FULL / IOERR / NOMEM; an
        # unconditional ROLLBACK would then raise "no transaction is active"
        # and mask the real error.
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def verify(db: sqlite3.Connection) -> tuple[bool, int, str | None]:
    """Walk the chain. Returns (ok, row_count, first_error).

    first_error is None on success, or a human-readable message pointing to the
    first row whose prev_hash or row_hash does not match.
    """
    prev = GENESIS_PREV_HASH
    count = 0
    for row in db.execute(
        """
        SELECT id, ts, actor, action, target_kind, target_id, before_state,
               after_state, reason, request_id, prev_hash, row_hash
          FROM audit_log
         ORDER BY id ASC
        """
    ):
        if row["prev_hash"] != prev:
            return False, count, f"row {row['id']}: prev_hash mismatch"
        expected = _row_hash(
            prev_hash=prev,
            row_id=row["id"],
            ts=row["ts"],
            actor=row["actor"],
            action=row["action"],
            target_kind=row["target_kind"],
            target_id=row["target_id"],
            before_state=row["before_state"],
            after_state=row["after_state"],
            reason=row["reason"],
            request_id=row["request_id"],
        )
        if row["row_hash"] != expected:
            return False, count, f"row {row['id']}: row_hash mismatch"
        prev = row["row_hash"]
        count += 1
    return True, count, None
