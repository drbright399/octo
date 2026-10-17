"""A tenant's entities.db — the ONE file entity resolution reads and writes
for that tenant (migration 040, `-- @target: entities`).

  * `ensure_db(path)` creates / upgrades the file (the telemetry store's
    pattern: user_version tracking, auto_vacuum = INCREMENTAL set before the
    first table, WAL). The tenant directory must exist — a file is never
    created for a tenant that was not provisioned.
  * `TenantDB.for_tenant(slug)` is the only way in. It validates the slug,
    builds the path through `paths.client_db_path` (the one containment
    check: realpath, prefix guard, no symlink below the data root) and
    REFUSES anything outside `clients/<slug>/` (a symlink, a traversal) —
    again on every connection: there is no API that takes two slugs or a
    path.
  * `read()` answers None when the file does not exist or has no schema yet
    (a tenant created before 040): callers say "unresolved", never a 500
    (the lazy-migration rule: probe sqlite_master on every read path).
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from apps.octo import paths
from apps.octo.migration import apply_migration, list_migrations

TARGET = "entities"
DB_NAME = "entities.db"
BUSY_TIMEOUT_SEC = 5.0

_lock = threading.Lock()
_ensured: set[str] = set()


class EntityPathError(ValueError):
    """A path that is not THIS tenant's entities.db."""


def _contained(slug: str) -> Path:
    """`<data_root>/clients/<slug>/entities.db` through `paths.client_db_path`
    (slug validated, realpath'd, contained, symlink-free below the data
    root). A refusal is this module's EntityPathError, as before."""
    try:
        return paths.client_db_path(slug, TARGET)
    except paths.SlugError as exc:
        raise EntityPathError(str(exc)) from None


def migration_numbers() -> list[int]:
    return [m.number for m in list_migrations(kind="forward")
            if f"-- @target: {TARGET}" in m.sql]


def ensure_db(path: Path) -> list[int]:
    """Create / upgrade one entities.db. Returns the migrations applied."""
    key = str(path)
    if key in _ensured and path.exists():
        return []
    with _lock:
        if not path.exists():
            _ensured.discard(key)
        if key in _ensured:
            return []
        if not path.parent.is_dir():
            raise FileNotFoundError(
                f"tenant directory missing for {path.parent.name!r}; the client must be "
                "provisioned before entity data is stored")
        conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC)
        applied: list[int] = []
        try:
            if not conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
            conn.execute("PRAGMA journal_mode = WAL")
            by_number = {m.number: m for m in list_migrations(kind="forward")}
            for num in migration_numbers():
                current = conn.execute("PRAGMA user_version").fetchone()[0]
                if current >= num:
                    continue
                apply_migration(conn, by_number[num], target=TARGET)
                applied.append(num)
            conn.commit()
        finally:
            conn.close()
        _ensured.add(key)
    return applied


def reset_schema_cache() -> None:
    """Tests: forget which files were ensured (a new tmp data root)."""
    with _lock:
        _ensured.clear()


def has_schema(conn: sqlite3.Connection) -> bool:
    try:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'resolution'",
        ).fetchone() is not None
    except sqlite3.Error:
        return False


class TenantDB:
    """The entities.db of ONE tenant. Built only by `for_tenant`."""

    __slots__ = ("slug", "path")

    def __init__(self, slug: str, path: Path) -> None:
        self.slug = slug
        self.path = path

    @classmethod
    def for_tenant(cls, slug: str) -> "TenantDB":
        paths.validate_slug(slug)
        # The path is never hand-built from the slug: `client_db_path` is the
        # one containment check (spec §2.3 — realpath, prefix guard under the
        # data root, no symlink below it), applied before anything touches
        # the filesystem through it.
        path = _contained(slug)
        cls.guard(slug, path)
        return cls(slug, path)

    @staticmethod
    def guard(slug: str, path: Path) -> None:
        """Refuse a path that is not `<data_root>/clients/<slug>/entities.db`
        — after resolving symlinks — or that traverses a symlink."""
        if path.name != DB_NAME:
            raise EntityPathError(f"not an {DB_NAME}: {path.name!r}")
        want = _contained(slug)
        cur = Path(path.anchor)
        for part in path.parts[1:]:
            cur = cur / part
            if cur.is_symlink():
                raise EntityPathError(f"symlink refused at {cur}")
        resolved = path.resolve()
        if resolved != want:
            raise EntityPathError(
                f"{resolved} is not the entities.db of tenant {slug!r}")

    def exists(self) -> bool:
        return self.path.exists()

    def ensure(self) -> None:
        ensure_db(self.path)

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """A connection inside BEGIN IMMEDIATE … COMMIT (ROLLBACK on error).
        Creates / upgrades the file first."""
        self.guard(self.slug, self.path)
        ensure_db(self.path)
        conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """An autocommit read/write connection (the caller manages
        transactions). Creates / upgrades the file first."""
        self.guard(self.slug, self.path)
        ensure_db(self.path)
        conn = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[Optional[sqlite3.Connection]]:
        """A read-only connection, or None when there is nothing to read yet
        (no file, or a file without the 040 schema). Never creates the file."""
        self.guard(self.slug, self.path)
        if not self.path.exists():
            yield None
            return
        try:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True,
                                   timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
        except sqlite3.Error:
            yield None
            return
        conn.row_factory = sqlite3.Row
        try:
            if not has_schema(conn):
                yield None
            else:
                yield conn
        finally:
            conn.close()
