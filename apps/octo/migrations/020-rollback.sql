-- Rollback for migration 020.
-- Drops the two buoy-notes tables + their indexes. Loses any rows
-- written since migration 020 ran. There is no preserve-the-data
-- variant — if you need to keep rows, snapshot the DB before rolling.

PRAGMA user_version = 19;

DROP INDEX IF EXISTS idx_buoy_agent_notes_correlation;
DROP INDEX IF EXISTS idx_buoy_agent_notes_slug_created;
DROP TABLE IF EXISTS buoy_agent_notes;

DROP INDEX IF EXISTS idx_buoy_user_notes_slug_created;
DROP TABLE IF EXISTS buoy_user_notes;
