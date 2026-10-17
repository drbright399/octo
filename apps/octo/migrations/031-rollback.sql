-- Rollback migration 031.

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_operators_removed;
ALTER TABLE operators DROP COLUMN removed_reason;
ALTER TABLE operators DROP COLUMN removed_by;
ALTER TABLE operators DROP COLUMN removed_at;

PRAGMA user_version = 30;
