-- Rollback for migration 022 — bundle_config key-value table.
-- @target: registry

DROP TABLE IF EXISTS bundle_config;

PRAGMA user_version = 21;
