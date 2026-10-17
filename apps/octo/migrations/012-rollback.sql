-- Rollback migration 012: drop bundle_config_retention.
-- Pre-launch only; no real bundle-config writes have happened yet.

PRAGMA user_version = 11;

-- @target: registry

DROP TABLE IF EXISTS bundle_config_retention;
