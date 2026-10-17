-- Rollback migration 026.

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_operators_is_factory;
ALTER TABLE operators DROP COLUMN is_factory;

PRAGMA user_version = 25;
