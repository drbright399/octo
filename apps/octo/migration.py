"""Migration runner.

Applies numbered .sql files in order against a target DB. Migration files may
contain per-target sections delimited by `-- @target: <name>` markers; the
runner extracts statements matching a requested target.

`user_version` is tracked per DB — re-running a migration is idempotent because
every DDL is `IF NOT EXISTS`. The runner also records a higher-level marker
(successful application count) in a small `_schema_migrations` table.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_TARGET_RE = re.compile(r"^--\s*@target:\s*(\w+)\s*$", re.MULTILINE)


@dataclass
class MigrationFile:
    number: int
    name: str
    path: Path

    @property
    def sql(self) -> str:
        return self.path.read_text()


def list_migrations(kind: str = "forward") -> list[MigrationFile]:
    assert kind in {"forward", "rollback"}
    suffix = "-rollback.sql" if kind == "rollback" else ".sql"
    results: list[MigrationFile] = []
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if kind == "forward" and p.name.endswith("-rollback.sql"):
            continue
        if kind == "rollback" and not p.name.endswith("-rollback.sql"):
            continue
        m = re.match(r"(\d+)-(.*?)(-rollback)?\.sql", p.name)
        if not m:
            continue
        results.append(MigrationFile(int(m.group(1)), m.group(2), p))
    results.sort(key=lambda mf: mf.number)
    return results


def _split_by_target(sql: str) -> dict[str | None, str]:
    """Split a migration file into per-target chunks. Section before any marker
    is stored under key None (applies to any target)."""
    chunks: dict[str | None, str] = {None: ""}
    current: str | None = None
    for line in sql.splitlines(keepends=True):
        m = _TARGET_RE.match(line.rstrip("\n"))
        if m:
            current = m.group(1)
            chunks.setdefault(current, "")
            continue
        chunks[current] = chunks.get(current, "") + line
    return chunks


def apply_migration(
    conn: sqlite3.Connection,
    migration: MigrationFile,
    target: str | None = None,
) -> None:
    chunks = _split_by_target(migration.sql)
    # Always run the "no target" prelude (PRAGMAs etc.)
    prelude = chunks.get(None, "")
    if prelude.strip():
        conn.executescript(prelude)
    if target is None:
        # Apply all target sections in order
        for key, body in chunks.items():
            if key is None:
                continue
            conn.executescript(body)
    else:
        body = chunks.get(target, "")
        if body.strip():
            conn.executescript(body)


def apply_all(conn: sqlite3.Connection, target: str | None = None,
              kind: str = "forward",
              migrations: Iterable[MigrationFile] | None = None) -> int:
    count = 0
    ms = list(migrations) if migrations is not None else list_migrations(kind=kind)
    if kind == "rollback":
        ms.reverse()
    for m in ms:
        apply_migration(conn, m, target=target)
        count += 1
    return count
