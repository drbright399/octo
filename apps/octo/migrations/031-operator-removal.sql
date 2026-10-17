-- Migration 031: operator removal (tombstones).
--
-- The console could only DISABLE an operator. A disabled account still shows
-- in the list and keeps its UNIQUE username + email forever, so a mistyped
-- invite or a departed analyst could never be cleaned up.
--
-- Operators who have ACTED cannot be hard-deleted: audit rows name the actor
-- by operator id, and buoy_notes.author_id / buoy_commands.requested_by
-- reference operators(id) with no ON DELETE rule. So "remove" is:
--   - never-used account (never signed in, no password) → row deleted
--   - account with history → RETIRED: access revoked, username + email freed,
--     hidden from the default list, row kept so the audit trail still
--     resolves to an identity. These columns mark a retired row.
--
-- NOTE: an unmerged local branch (sanitized-pool consumption surface) also
-- carries a migration numbered 031; it must be renumbered if it ever merges.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators ADD COLUMN removed_at TEXT;
ALTER TABLE operators ADD COLUMN removed_by INTEGER REFERENCES operators(id) ON DELETE SET NULL;
ALTER TABLE operators ADD COLUMN removed_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_operators_removed
    ON operators(removed_at) WHERE removed_at IS NOT NULL;

PRAGMA user_version = 31;
