-- ============================================================================
-- Migration 009 — add step-up authentication columns to sessions.
--
-- The /search/* surface (client DB query feature) requires the operator
-- to prove identity a second time before accessing potentially-sensitive
-- ingested customer data, even within an already-authenticated session.
-- This is the standard "sudo mode" / "step-up auth" pattern.
--
-- Two new columns on sessions:
--   step_up_auth_granted_at  — ISO-8601 UTC, when re-auth most recently
--                              succeeded. NULL = never elevated. Anchors
--                              the 4-hour absolute cap.
--   step_up_auth_until       — ISO-8601 UTC, sliding expiry. Updated on
--                              each /search/* action: max(current,
--                              now+30min). Never exceeds
--                              step_up_auth_granted_at + 4 hours.
--
-- Both are NULL by default — existing sessions get no elevation and
-- must call /search/elevate to access /search/*.
--
-- Audit-log entries (in audit_log.action, no enum constraint to extend):
--   step_up_granted          — re-auth succeeded
--   step_up_failed           — re-auth attempt failed (wrong password
--                              or TOTP); helps spot brute force
--   search.events            — operator ran a search
--   search.event_payload     — operator opened a specific event's
--                              full payload
--
-- Idempotency: ADD COLUMN — runner probes for column existence, skips
-- on re-application. Direct re-run of the SQL file errors on the second
-- ALTER; the runner-level guard prevents that in normal use.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE sessions ADD COLUMN step_up_auth_granted_at TEXT;
ALTER TABLE sessions ADD COLUMN step_up_auth_until      TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_step_up
    ON sessions(step_up_auth_until) WHERE step_up_auth_until IS NOT NULL;

PRAGMA user_version = 9;
