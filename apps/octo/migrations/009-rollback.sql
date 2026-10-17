-- ============================================================================
-- Migration 009 rollback — drop step-up auth columns + index.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_sessions_step_up;
ALTER TABLE sessions DROP COLUMN step_up_auth_until;
ALTER TABLE sessions DROP COLUMN step_up_auth_granted_at;

PRAGMA user_version = 8;
