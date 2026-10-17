"""SQLite-backed LayoutRepository implementation.

Per ADR-006 §`Layout persistence` + ADR-004 (boundary: UI state lives in
Athena). Layouts persist to a SQLite database file inside the Athena
container's data volume — separate from any OCTO database.

Schema is a single table keyed by (operator_id, tenant_slug). The
LayoutGrid is serialized as JSON; layout schema version + last-updated
timestamps are columnar for indexable lookup.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from shared_widget_contract import (
    LayoutGrid,
    LayoutItem,
    LayoutPosition,
    LayoutSize,
)


SCHEMA_VERSION = 1
"""Bumped on backward-incompatible schema changes."""


_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS operator_dashboard_layouts (
    operator_id INTEGER NOT NULL,
    tenant_slug TEXT NOT NULL,
    layout_version INTEGER NOT NULL,
    layout_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (operator_id, tenant_slug)
);
CREATE INDEX IF NOT EXISTS idx_operator_dashboard_layouts_operator
    ON operator_dashboard_layouts(operator_id);
"""


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------

class SqliteLayoutRepository:
    """SQLite-backed LayoutRepository.

    Production deployments pass a path inside the Athena data volume
    (e.g., `/var/lib/athena/state/layouts.db`). Tests use tmp_path.
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
    # LayoutRepository Protocol
    # ------------------------------------------------------------------

    def get(self, *, operator_id: int, tenant_slug: str) -> LayoutGrid | None:
        conn = self._connect()
        row = conn.execute(
            """
            SELECT layout_version, layout_json
            FROM operator_dashboard_layouts
            WHERE operator_id = ? AND tenant_slug = ?
            """,
            (operator_id, tenant_slug),
        ).fetchone()
        if row is None:
            return None
        return _layout_from_json(row["layout_version"], row["layout_json"])

    def put(
        self,
        *,
        operator_id: int,
        tenant_slug: str,
        layout: LayoutGrid,
    ) -> None:
        layout_json = _layout_to_json(layout)
        with self._txn() as conn:
            conn.execute(
                """
                INSERT INTO operator_dashboard_layouts (
                    operator_id, tenant_slug, layout_version, layout_json, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(operator_id, tenant_slug) DO UPDATE SET
                    layout_version = excluded.layout_version,
                    layout_json = excluded.layout_json,
                    updated_at = excluded.updated_at
                """,
                (operator_id, tenant_slug, layout.version, layout_json, _utc_iso_now()),
            )

    def delete(self, *, operator_id: int, tenant_slug: str) -> None:
        with self._txn() as conn:
            conn.execute(
                """
                DELETE FROM operator_dashboard_layouts
                WHERE operator_id = ? AND tenant_slug = ?
                """,
                (operator_id, tenant_slug),
            )

    def list_for_operator(self, *, operator_id: int) -> dict[str, LayoutGrid]:
        conn = self._connect()
        rows = conn.execute(
            """
            SELECT tenant_slug, layout_version, layout_json
            FROM operator_dashboard_layouts
            WHERE operator_id = ?
            ORDER BY tenant_slug
            """,
            (operator_id,),
        ).fetchall()
        return {
            r["tenant_slug"]: _layout_from_json(r["layout_version"], r["layout_json"])
            for r in rows
        }

    def updated_at(self, *, operator_id: int, tenant_slug: str) -> str | None:
        """Diagnostic helper — last-write timestamp for this layout."""
        conn = self._connect()
        row = conn.execute(
            """
            SELECT updated_at FROM operator_dashboard_layouts
            WHERE operator_id = ? AND tenant_slug = ?
            """,
            (operator_id, tenant_slug),
        ).fetchone()
        return row["updated_at"] if row is not None else None


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _layout_to_json(layout: LayoutGrid) -> str:
    """Serialize LayoutGrid to a stable JSON string.

    Frozen dataclasses don't `json.dumps` directly; manual mapping keeps
    the on-disk format owned here (so changes don't accidentally couple
    to the in-memory shape).
    """
    return json.dumps(
        {
            "version": layout.version,
            "grid": [
                {
                    "widget_id": item.widget_id,
                    "position": {"x": item.position.x, "y": item.position.y},
                    "size": {"w": item.size.w, "h": item.size.h},
                    "hidden": item.hidden,
                    "operator_config": item.operator_config,
                }
                for item in layout.grid
            ],
        },
        sort_keys=True,
    )


def _layout_from_json(version: int, layout_json: str) -> LayoutGrid:
    """Project the serialized form back to a LayoutGrid."""
    payload = json.loads(layout_json)
    items: list[LayoutItem] = []
    for raw in payload.get("grid", []):
        items.append(LayoutItem(
            widget_id=raw["widget_id"],
            position=LayoutPosition(
                x=raw["position"]["x"],
                y=raw["position"]["y"],
            ),
            size=LayoutSize(w=raw["size"]["w"], h=raw["size"]["h"]),
            hidden=raw.get("hidden", False),
            operator_config=raw.get("operator_config", {}),
        ))
    # Trust the columnar version (it's authoritative for index lookups);
    # also defensively coerce in case payload has a stale value.
    return LayoutGrid(version=version, grid=items)


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
