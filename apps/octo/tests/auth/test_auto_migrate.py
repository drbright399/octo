"""Auto-migrate regression tests.

Asserts:
  - `_registry_migration_numbers()` discovers every registry-touching forward
    migration from the on-disk files (matches the previously hardcoded list).
  - `apply_pending_registry_migrations()` advances a fresh DB to the latest
    `user_version` in one call.
  - A second call on the same DB is a no-op (returns []).
  - When a DB is rewound to an intermediate `user_version`, the helper picks
    up only the migrations above that version.
  - `ensure_registry_migrations_applied()` returns [] for ":memory:" (no-op
    in the test path so create_app() can call it unconditionally).
  - `create_app()` applies pending migrations during server start. This is
    the regression we're guarding against — a deployed bundle whose code
    has rolled forward but whose registry.db is still at an older
    user_version. Pre-fix: the server would 500 the first time anything
    queried a not-yet-added table. Post-fix: startup catches it up.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _max_registry_migration_number() -> int:
    return max(bootstrap._registry_migration_numbers())


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def test_registry_migration_numbers_discovery_includes_known_set():
    nums = bootstrap._registry_migration_numbers()
    # The list previously hardcoded in init_data_root() — every number here
    # MUST still be discovered after the refactor, otherwise we've regressed.
    assert nums == [1, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 19, 20, 21, 22, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 46, 47, 48]


def test_patterns_migration_numbers_discovery_includes_known_set():
    nums = bootstrap._patterns_migration_numbers()
    # 003 = base patterns schema. 023 = HMAC schema upgrade.
    # 024 = pool extractor cursor.
    assert nums == [3, 23, 24]


# ---------------------------------------------------------------------------
# apply_pending_registry_migrations
# ---------------------------------------------------------------------------

def test_apply_pending_advances_fresh_db_to_latest(auth_data_root):
    # auth_data_root already ran init_data_root() which applies everything.
    # Calling the helper again on the same DB must be a no-op.
    from apps.octo import paths
    conn = connect(paths.registry_db_path())
    try:
        applied = bootstrap.apply_pending_registry_migrations(conn)
        assert applied == []
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == _max_registry_migration_number()
    finally:
        conn.close()


def test_apply_pending_picks_up_migrations_above_current_version(
    tmp_path, monkeypatch,
):
    """Simulate a stale DB legitimately at user_version=12 (the realistic
    drift scenario: deployed bundle had migrations 1..12 last time the
    server started, then code rolled forward with 15+18+19+20+21
    queued).

    We can't just rewind `user_version` on a fully-migrated DB because
    migrations 18+ ALTER TABLE / ADD COLUMN aren't idempotent. So we
    monkey-patch the discovery to return only the early migrations,
    let the helper build a v12 DB, then unpatch and call the helper
    again — it should pick up everything above 12.
    """
    db_path = tmp_path / "registry.db"
    conn = connect(db_path)
    try:
        # Phase 1: pretend only migrations 1..12 exist; build a stale DB.
        early = [n for n in bootstrap._registry_migration_numbers() if n <= 12]
        monkeypatch.setattr(
            bootstrap, "_registry_migration_numbers", lambda: early,
        )
        applied_first = bootstrap.apply_pending_registry_migrations(conn)
        assert applied_first == early
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 12

        # Phase 2: restore real discovery (simulates the new code rolling
        # in). The helper should apply only the newer migrations.
        monkeypatch.undo()
        applied_second = bootstrap.apply_pending_registry_migrations(conn)
        assert applied_second == [15, 18, 19, 20, 21, 22, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 40, 41, 42, 43, 44, 46, 47, 48]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == (
            _max_registry_migration_number()
        )
    finally:
        conn.close()


def test_ensure_registry_migrations_applied_is_noop_for_in_memory():
    # create_app() in tests passes ":memory:" — the helper must skip
    # cleanly rather than try to connect (which would fail since there's
    # no parent dir).
    applied = bootstrap.ensure_registry_migrations_applied(":memory:")
    assert applied == []


# ---------------------------------------------------------------------------
# Server-start integration — the regression we actually care about
# ---------------------------------------------------------------------------

def test_create_app_auto_applies_pending_migrations(tmp_path, monkeypatch):
    """Regression: a deployed bundle's registry.db lagging the code.

    The "stale bundle" scenario:
      - Earlier image deployed → init ran → registry.db reached v12.
      - octo-updater rolled the container forward with code that includes
        new registry migrations 15..21.
      - The new container starts; `init_data_root()` is NOT re-run
        (init is one-shot, not on every boot).
      - Pre-fix: registry.db stays at v12 forever — any query hitting
        a newer table 500s.
      - Post-fix: create_app() invokes ensure_registry_migrations_applied
        on startup which catches the DB up.

    Build a stale-v12 DB (same trick as above — monkey-patch discovery
    so only early migrations apply), then call create_app() with full
    discovery, then assert user_version reached max.
    """
    from apps.octo.main import OctoConfig, create_app

    # Step 1: build a registry.db at v12 (stale relative to current code).
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    registry_path = state_dir / "registry.db"
    early = [n for n in bootstrap._registry_migration_numbers() if n <= 12]
    monkeypatch.setattr(
        bootstrap, "_registry_migration_numbers", lambda: early,
    )
    conn = connect(registry_path)
    try:
        bootstrap.apply_pending_registry_migrations(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 12
    finally:
        conn.close()
    monkeypatch.undo()

    # Step 2: create_app() with this registry path — startup should
    # auto-migrate.
    cfg = OctoConfig(
        registry_db_path=str(registry_path),
        audit_db_path=":memory:",
        state_dir=str(state_dir),
    )
    create_app(config=cfg)

    # Step 3: verify the DB has caught up to the latest.
    conn = connect(registry_path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == _max_registry_migration_number()
    finally:
        conn.close()
