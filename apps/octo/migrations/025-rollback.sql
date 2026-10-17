-- Rollback migration 025.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators DROP COLUMN preferences;

PRAGMA user_version = 24;
