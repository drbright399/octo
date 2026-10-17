-- ============================================================================
-- Migration 008 — add operators.display_name.
--
-- Nullable TEXT column for the operator's friendly name (what Athena
-- refers to them as in UI greetings, dropdowns, audit summaries, etc.).
-- Falls back to `username` everywhere the SPA renders when null. Set by
-- the operator themselves via the new PATCH /auth/me/profile endpoint,
-- or pre-seeded by an admin at create time in a future iteration.
--
-- Idempotency: same shape as the prior ADD COLUMN migrations — the
-- migration runner probes for column existence and skips re-application
-- when it's already there. Direct re-run of the SQL file will error on
-- the second ADD COLUMN; the runner-level guard prevents that in
-- normal use.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators ADD COLUMN display_name TEXT;

PRAGMA user_version = 8;
