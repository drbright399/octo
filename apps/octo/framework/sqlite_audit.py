"""SQLite-backed AuditLogBackend for the bridge server.

Per ADR-004 invariant 4 (per-query audit log) + roadmap Gap G1 (immutable
WORM audit export). v1 lands a hash-chained append-only schema so the
forensic story is real today and Gap G1 only needs to add the verifier
plus tooling, not a schema migration.

Hash chain semantics:
- Each row carries `prev_hash` (the previous row's row_hash; literal
  "GENESIS" for the first row) and `row_hash` (sha256 over prev_hash +
  canonical-serialized payload).
- Tampering with any row breaks the chain at that row and every row
  after it. The verifier (lands with Gap G1) walks the table validating
  each link.
- This module is strictly append-only at the application layer. There
  are no UPDATE or DELETE statements anywhere; verifying that property
  via grep is part of the Gap G1 pre-merge gate.

audit_entry_id is assigned explicitly (max + 1) inside the same
transaction as the INSERT so it's deterministic and chain-derivable.
SQLite's AUTOINCREMENT was avoided because it's race-tolerant only at
the cost of unpredictable IDs across rolled-back inserts, which would
complicate chain verification.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from shared_bridge import AuditLogEntry


SCHEMA_VERSION = 1
GENESIS_PREV_HASH = "GENESIS"
"""Sentinel value used for the prev_hash of the very first row.

The verifier (Gap G1) treats this string as the canonical chain root."""


_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS bridge_audit_log (
    audit_entry_id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    operator_id INTEGER NOT NULL,
    operator_role TEXT NOT NULL,
    session_id TEXT NOT NULL,
    session_tenant TEXT NOT NULL,
    template_id TEXT NOT NULL,
    params_hash TEXT NOT NULL,
    result_row_count INTEGER NOT NULL,
    elapsed_ms REAL NOT NULL,
    accepted INTEGER NOT NULL,
    rejection_reason TEXT,
    cross_tenant_access INTEGER NOT NULL DEFAULT 0,
    extra_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bridge_audit_session
    ON bridge_audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_bridge_audit_operator
    ON bridge_audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_bridge_audit_tenant
    ON bridge_audit_log(session_tenant);
CREATE INDEX IF NOT EXISTS idx_bridge_audit_timestamp
    ON bridge_audit_log(timestamp);
"""


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class SqliteAuditLogBackend:
    """SQLite-backed AuditLogBackend with chain-ready schema.

    Production callers pass a path inside the OCTO data volume
    (e.g., `/var/lib/octo/state/bridge_audit.db`). Tests use tmp_path.
    """

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        conn = sqlite3.connect(
            self._db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        if self._db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema(conn)
        self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        conn.execute("BEGIN")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    @staticmethod
    def _init_schema(conn: sqlite3.Connection) -> None:
        conn.executescript(_SCHEMA_DDL)
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current < SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------------
    # AuditLogBackend Protocol
    # ------------------------------------------------------------------

    def append(self, entry: AuditLogEntry) -> int:
        """Append an entry. Returns the assigned audit_entry_id.

        Computes prev_hash (last row's row_hash, or GENESIS) and row_hash
        (sha256 over prev_hash + canonical payload) inside the same
        transaction as the INSERT. Strictly append-only — no UPDATE or
        DELETE in this code path."""
        with self._txn() as conn:
            # Read the chain tip under the same transaction
            tip_row = conn.execute(
                "SELECT audit_entry_id, row_hash FROM bridge_audit_log "
                "ORDER BY audit_entry_id DESC LIMIT 1"
            ).fetchone()

            if tip_row is None:
                next_id = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                next_id = tip_row["audit_entry_id"] + 1
                prev_hash = tip_row["row_hash"]

            row_hash = _compute_row_hash(prev_hash=prev_hash, entry=entry)

            conn.execute(
                """
                INSERT INTO bridge_audit_log (
                    audit_entry_id, timestamp, operator_id, operator_role,
                    session_id, session_tenant, template_id, params_hash,
                    result_row_count, elapsed_ms, accepted, rejection_reason,
                    cross_tenant_access, extra_json,
                    prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_id,
                    entry.timestamp,
                    entry.operator_id,
                    entry.operator_role,
                    entry.session_id,
                    entry.session_tenant,
                    entry.template_id,
                    entry.params_hash,
                    entry.result_row_count,
                    entry.elapsed_ms,
                    1 if entry.accepted else 0,
                    entry.rejection_reason,
                    1 if entry.cross_tenant_access else 0,
                    json.dumps(entry.extra, sort_keys=True),
                    prev_hash,
                    row_hash,
                ),
            )
            return next_id

    def query(
        self,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        conn = self._connect()
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if operator_id is not None:
            clauses.append("operator_id = ?")
            params.append(operator_id)
        if tenant is not None:
            clauses.append("session_tenant = ?")
            params.append(tenant)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        sql = "SELECT * FROM bridge_audit_log"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY audit_entry_id ASC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Chain inspection (precursor to Gap G1 verifier)
    # ------------------------------------------------------------------

    def chain_tip(self) -> tuple[int, str] | None:
        """Return (audit_entry_id, row_hash) of the most recent row, or None.

        Used by external monitors to detect tampering: if the tip row_hash
        ever fails to match an externally-mirrored copy, integrity is lost.
        Full chain verification lands with Gap G1 (#46)."""
        conn = self._connect()
        row = conn.execute(
            "SELECT audit_entry_id, row_hash FROM bridge_audit_log "
            "ORDER BY audit_entry_id DESC LIMIT 1"
        ).fetchone()
        return (row["audit_entry_id"], row["row_hash"]) if row else None

    def verify_chain(self) -> bool:
        """Walk the chain validating every prev_hash → row_hash link.

        Returns True iff every row's row_hash matches sha256(prev_hash +
        canonical_payload). Returns False on any mismatch.

        v1 is intentionally minimal — Gap G1 (#46) replaces this with a
        full verifier that emits structured violation reports + raises
        compliance alarms. This routine is here so tests can confirm the
        write path produces a valid chain."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM bridge_audit_log ORDER BY audit_entry_id ASC"
        ).fetchall()

        expected_prev = GENESIS_PREV_HASH
        for row in rows:
            entry = _row_to_entry(row)
            if row["prev_hash"] != expected_prev:
                return False
            recomputed = _compute_row_hash(prev_hash=row["prev_hash"], entry=entry)
            if recomputed != row["row_hash"]:
                return False
            expected_prev = row["row_hash"]
        return True


# ---------------------------------------------------------------------------
# Hashing + serialization
# ---------------------------------------------------------------------------

def _compute_row_hash(*, prev_hash: str, entry: AuditLogEntry) -> str:
    """sha256(prev_hash || canonical_payload(entry)).

    Canonical payload is sorted-keys JSON so the hash is stable across
    Python's dict-iteration ordering. The payload covers every field
    that comes through AuditLogEntry — adding a new field requires
    bumping SCHEMA_VERSION + writing a migration that re-hashes
    historical rows under the new payload definition.
    """
    payload = {
        "timestamp": entry.timestamp,
        "operator_id": entry.operator_id,
        "operator_role": entry.operator_role,
        "session_id": entry.session_id,
        "session_tenant": entry.session_tenant,
        "template_id": entry.template_id,
        "params_hash": entry.params_hash,
        "result_row_count": entry.result_row_count,
        "elapsed_ms": entry.elapsed_ms,
        "accepted": entry.accepted,
        "rejection_reason": entry.rejection_reason,
        "cross_tenant_access": entry.cross_tenant_access,
        "extra": entry.extra,
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _row_to_entry(row: sqlite3.Row) -> AuditLogEntry:
    return AuditLogEntry(
        timestamp=row["timestamp"],
        operator_id=row["operator_id"],
        operator_role=row["operator_role"],
        session_id=row["session_id"],
        session_tenant=row["session_tenant"],
        template_id=row["template_id"],
        params_hash=row["params_hash"],
        result_row_count=row["result_row_count"],
        elapsed_ms=row["elapsed_ms"],
        accepted=bool(row["accepted"]),
        rejection_reason=row["rejection_reason"],
        cross_tenant_access=bool(row["cross_tenant_access"]),
        extra=json.loads(row["extra_json"]),
    )
