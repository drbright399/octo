-- Migration 017: tickets.due_at (SLA storage prep).
--
-- Adds a nullable ISO-8601 due_at column. The full SLA policy engine
-- (compute target from contract + severity, badge on overdue,
-- escalation actions) is Zack's extension surface — see
-- the 2026-05-14 Autotask write-back hand-off §2.7 (archived outside
-- the repo).
--
-- Per-tenant DB: <data_root>/clients/<slug>/tickets.db.

PRAGMA user_version = 17;
PRAGMA foreign_keys = ON;

-- @target: tickets

ALTER TABLE tickets ADD COLUMN due_at TEXT;

-- Quick lookup for "tickets due in the next N hours" — the partial
-- predicate keeps the index footprint to non-null due_at rows.
CREATE INDEX IF NOT EXISTS idx_tickets_due_at
    ON tickets (due_at) WHERE due_at IS NOT NULL;
