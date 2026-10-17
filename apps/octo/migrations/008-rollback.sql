-- ============================================================================
-- Migration 008 rollback — drop operators.display_name.
--
-- SQLite supports DROP COLUMN since 3.35; the runner targets a newer
-- SQLite. The column being dropped is plain TEXT with no foreign-key
-- or trigger dependencies, so this is safe.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators DROP COLUMN display_name;

PRAGMA user_version = 7;
