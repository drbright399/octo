-- Rollback for migration 019: drop buoy_commands.

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_buoy_commands_requested_at;
DROP INDEX IF EXISTS idx_buoy_commands_slug_status;
DROP TABLE IF EXISTS buoy_commands;

PRAGMA user_version = 18;
