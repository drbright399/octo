-- Rollback migration 048.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (046 / 047's pattern):
--   * registry — `alert_verdict_followup` (the notes and recalls on
--     acknowledgements) is LEFT AS IT IS: nothing before 048 reads it, and a
--     re-upgrade finds it current (every recall applies again, every note
--     shows again). The version goes back to 47.
--
-- What a rolled-back bundle does differently: it does not know recalls — a
-- RECALLED acknowledgement covers its alert again (out of "needs attention",
-- not counted towards the site's colour) until the re-upgrade; the notes are
-- not shown.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

PRAGMA user_version = 47;

COMMIT;
