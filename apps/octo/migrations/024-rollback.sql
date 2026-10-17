-- Rollback migration 024.

PRAGMA foreign_keys = ON;

-- @target: patterns

DROP INDEX IF EXISTS idx_pool_extractor_cursor_last_run;
DROP TABLE IF EXISTS pool_extractor_cursor;

PRAGMA user_version = 23;
