"""SQLite-backed RegistryBackend implementation.

Per ADR-005 (adapter contract). Adapter instance state
must survive container restarts; the in-memory backend was always
intended as a test stub. This module persists `AdapterInstance` rows to
a SQLite database (the OCTO `registry.db` in production).

Adapter CLASSES are NOT persisted — they're re-discovered at every boot
via `discover_adapters()`. Only INSTANCE state lives here.

Schema is intentionally narrow (one table). Audit of state changes is
handled separately by subscribers to AdapterRegistry events; the
RegistryBackend's job is purely instance-state persistence.

The schema_version PRAGMA is set at first connection so future migrations
can detect drift.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from apps.octo.framework.lifecycle import AdapterLifecycleState
from apps.octo.framework.registry import AdapterInstance


SCHEMA_VERSION = 1
"""Bumped on backward-incompatible schema changes. A migration handler
fires on connection if the stored value is below this constant."""


_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS adapter_instances (
    instance_key TEXT PRIMARY KEY,
    vendor_slug TEXT NOT NULL,
    tenant_slug TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    state TEXT NOT NULL,
    credentials_ref TEXT NOT NULL,
    tenant_mapping_json TEXT NOT NULL DEFAULT '{}',
    rate_limit_overrides_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    last_state_change_at TEXT NOT NULL,
    state_change_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_adapter_instances_vendor
    ON adapter_instances(vendor_slug);
CREATE INDEX IF NOT EXISTS idx_adapter_instances_tenant
    ON adapter_instances(tenant_slug);
CREATE INDEX IF NOT EXISTS idx_adapter_instances_state
    ON adapter_instances(state);
"""


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class SqliteRegistryBackend:
    """SQLite-backed RegistryBackend.

    Constructed with a Path to the SQLite database file. Use ":memory:"
    or a tmp_path file for tests; production passes a stable path inside
    the OCTO container's data volume.

    Connection per-instance is opened lazily and reused. SQLite's WAL
    journaling is enabled so concurrent readers don't block writers
    (relevant when the operator settings UI reads while ingest paths write).
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
            isolation_level=None,  # autocommit; we manage txn boundaries explicitly
        )
        conn.row_factory = sqlite3.Row
        # Sane defaults for OCTO's read-heavy access pattern
        if self._db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema(conn)
        self._conn = conn
        return conn

    def close(self) -> None:
        """Close the underlying SQLite connection. Idempotent."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        """Run a write under an explicit BEGIN/COMMIT envelope.

        Reads can use the raw connection; writes go through this so
        partial failures roll back rather than leaving the table in
        an inconsistent state.
        """
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
        # `executescript` runs multiple statements separated by `;`
        conn.executescript(_SCHEMA_DDL)
        # Stamp schema_version
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current < SCHEMA_VERSION:
            # Future: dispatch migrations between current and SCHEMA_VERSION here
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------------
    # RegistryBackend Protocol
    # ------------------------------------------------------------------

    def get_instance(self, instance_key: str) -> AdapterInstance | None:
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM adapter_instances WHERE instance_key = ?",
            (instance_key,),
        ).fetchone()
        return _row_to_instance(row) if row is not None else None

    def put_instance(self, instance: AdapterInstance) -> None:
        with self._txn() as conn:
            conn.execute(
                """
                INSERT INTO adapter_instances (
                    instance_key, vendor_slug, tenant_slug, instance_id,
                    state, credentials_ref,
                    tenant_mapping_json, rate_limit_overrides_json,
                    created_at, last_state_change_at, state_change_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(instance_key) DO UPDATE SET
                    state = excluded.state,
                    credentials_ref = excluded.credentials_ref,
                    tenant_mapping_json = excluded.tenant_mapping_json,
                    rate_limit_overrides_json = excluded.rate_limit_overrides_json,
                    last_state_change_at = excluded.last_state_change_at,
                    state_change_reason = excluded.state_change_reason
                """,
                (
                    instance.instance_key,
                    instance.vendor_slug,
                    instance.tenant_slug,
                    instance.instance_id,
                    instance.state.value,
                    instance.credentials_ref,
                    json.dumps(instance.tenant_mapping, sort_keys=True),
                    json.dumps(instance.rate_limit_overrides, sort_keys=True),
                    instance.created_at,
                    instance.last_state_change_at,
                    instance.state_change_reason,
                ),
            )

    def list_instances(
        self,
        *,
        vendor_slug: str | None = None,
        tenant_slug: str | None = None,
        state: AdapterLifecycleState | None = None,
    ) -> list[AdapterInstance]:
        conn = self._connect()
        clauses: list[str] = []
        params: list[Any] = []
        if vendor_slug is not None:
            clauses.append("vendor_slug = ?")
            params.append(vendor_slug)
        if tenant_slug is not None:
            clauses.append("tenant_slug = ?")
            params.append(tenant_slug)
        if state is not None:
            clauses.append("state = ?")
            params.append(state.value)
        sql = "SELECT * FROM adapter_instances"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY instance_key"
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_instance(r) for r in rows]

    def delete_instance(self, instance_key: str) -> None:
        with self._txn() as conn:
            conn.execute(
                "DELETE FROM adapter_instances WHERE instance_key = ?",
                (instance_key,),
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row_to_instance(row: sqlite3.Row) -> AdapterInstance:
    """Project a SQLite row back into the frozen AdapterInstance dataclass."""
    return AdapterInstance(
        instance_key=row["instance_key"],
        vendor_slug=row["vendor_slug"],
        tenant_slug=row["tenant_slug"],
        instance_id=row["instance_id"],
        state=AdapterLifecycleState(row["state"]),
        credentials_ref=row["credentials_ref"],
        tenant_mapping=json.loads(row["tenant_mapping_json"]),
        rate_limit_overrides=json.loads(row["rate_limit_overrides_json"]),
        created_at=row["created_at"],
        last_state_change_at=row["last_state_change_at"],
        state_change_reason=row["state_change_reason"],
    )
