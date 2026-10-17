-- Rollback migration 041.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 040's pattern):
--   * registry — every manual tenant location is kept under
--     `tenant_locations_rolled_back_041` (appended to on a second rollback),
--     then `tenant_locations` is dropped; the version goes back to 40. Code
--     before 041 never reads it (the v0.13 Fleet tab has no site pins).
--     Re-applying 041 restores the newest kept row of every tenant that
--     still exists.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS tenant_locations_rolled_back_041
    AS SELECT * FROM tenant_locations WHERE 0;
INSERT INTO tenant_locations_rolled_back_041 SELECT * FROM tenant_locations;
DROP TABLE IF EXISTS tenant_locations;

PRAGMA user_version = 40;

COMMIT;
