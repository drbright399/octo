-- Rollback migration 011: drop agent_notes + agent_pattern_links.
-- Both tables are per-client events.db. Used by tests and for the
-- rare "scrap and re-create" path; production rollback is via the
-- migration runner.

PRAGMA user_version = 10;

-- @target: events

DROP TRIGGER IF EXISTS agent_pattern_links_no_update;
DROP TRIGGER IF EXISTS agent_pattern_links_no_delete;
DROP INDEX IF EXISTS idx_pattern_links_relation_created;
DROP INDEX IF EXISTS idx_pattern_links_to;
DROP INDEX IF EXISTS idx_pattern_links_from;
DROP TABLE IF EXISTS agent_pattern_links;

DROP INDEX IF EXISTS idx_agent_notes_agent_created;
DROP INDEX IF EXISTS idx_agent_notes_ref;
DROP TABLE IF EXISTS agent_notes;
