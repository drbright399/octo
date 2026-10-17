-- Rollback for migration 018: drop the buoys table.
--
-- Rollback resets user_version to 17 (previous schema apex). Bedrock's
-- init_data_root() guards re-application with `current_version < N`, so
-- the rolled-back DB will re-run 018 cleanly on next boot.

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_buoys_last_heartbeat;
DROP TABLE IF EXISTS buoys;

PRAGMA user_version = 17;
