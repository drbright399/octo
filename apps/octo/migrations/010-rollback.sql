-- ============================================================================
-- Migration 010 rollback — drop step_up_auth_ip_prefix column.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE sessions DROP COLUMN step_up_auth_ip_prefix;

PRAGMA user_version = 9;
