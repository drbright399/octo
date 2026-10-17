-- Rollback migration 042.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 040 / 041's pattern):
--   * registry — every manual site location is kept under
--     `site_locations_rolled_back_042` (appended to on a second rollback),
--     then `site_locations` is dropped; the version goes back to 41. Code
--     before 042 never reads it (v0.14 pins by tenant only). Re-applying 042
--     restores the newest kept row of every site whose tenant still exists.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS site_locations_rolled_back_042
    AS SELECT * FROM site_locations WHERE 0;
INSERT INTO site_locations_rolled_back_042 SELECT * FROM site_locations;
DROP INDEX IF EXISTS idx_site_locations_tenant;
DROP TABLE IF EXISTS site_locations;

PRAGMA user_version = 41;

COMMIT;
