-- Rollback migration 014: drop ticket_notes.
-- Pre-launch only — no ticket notes have been written yet.

PRAGMA user_version = 13;

-- @target: tickets

DROP TRIGGER IF EXISTS trg_ticket_notes_touch_ticket;
DROP INDEX IF EXISTS idx_ticket_notes_autotask;
DROP INDEX IF EXISTS idx_ticket_notes_by_ticket;
DROP TABLE IF EXISTS ticket_notes;
