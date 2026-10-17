-- Rollback migration 027.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators DROP COLUMN l2_llm_granted;

PRAGMA user_version = 26;
