-- Rollback migration 013: drop tickets + ticket_status_history.
-- Pre-launch only — no real ticket data has been ingested yet.

PRAGMA user_version = 12;

-- @target: tickets

DROP INDEX IF EXISTS idx_status_history_ticket;
DROP INDEX IF EXISTS idx_tickets_source_event;
DROP INDEX IF EXISTS idx_tickets_autotask_id;
DROP INDEX IF EXISTS idx_tickets_assignee_status;
DROP INDEX IF EXISTS idx_tickets_open_by_updated;
DROP TABLE IF EXISTS ticket_status_history;
DROP TABLE IF EXISTS tickets;
