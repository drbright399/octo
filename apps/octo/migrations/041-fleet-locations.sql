-- Migration 041: Fleet v2 — the manual per-tenant location override.
--
-- The Fleet map pins a site where its UniFi console says it is
-- (/v1/hosts reportedState.location, already read by the UniFi adapter). A
-- tenant without UniFi (Datto / NextDNS only), or whose console reports no
-- coordinates, can be placed by an operator: admin+ sets a latitude /
-- longitude and a label, audited (`tenant_location_set` /
-- `tenant_location_clear`, written BEFORE the row). Precedence, read time:
-- the UniFi location, else this override, else no pin (listed only). There is
-- NO IP geolocation anywhere — coordinates never leave the box (the map tiles
-- are self-hosted).
--
-- registry section
--   tenant_locations   one row per tenant slug: lat / lng (WGS84 degrees),
--                      a label, who set it and when. (0, 0) is refused (the
--                      "unset" value of too many systems). The row is
--                      deleted when the override is cleared; offboarding a
--                      tenant leaves it (read only for ACTIVE tenants).
--
-- Nothing else changes. The ISP-outage correlator keeps its state in the
-- existing adapter_poller_state (036) under the UniFi instance.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS tenant_locations (
    slug        TEXT PRIMARY KEY,
    lat         REAL NOT NULL CHECK (lat BETWEEN -90.0 AND 90.0),
    lng         REAL NOT NULL CHECK (lng BETWEEN -180.0 AND 180.0),
    label       TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    set_by      INTEGER,
    set_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (NOT (lat = 0.0 AND lng = 0.0))
);

-- A re-upgrade takes back what a rollback kept (036 / 040's pattern): the
-- newest kept row per tenant that still exists. Created empty on a first
-- upgrade (one code path).
CREATE TABLE IF NOT EXISTS tenant_locations_rolled_back_041
    AS SELECT * FROM tenant_locations WHERE 0;
INSERT OR IGNORE INTO tenant_locations (slug, lat, lng, label, set_by, set_at)
SELECT k.slug, k.lat, k.lng, k.label, k.set_by, k.set_at
  FROM tenant_locations_rolled_back_041 k
 WHERE k.slug IN (SELECT slug FROM clients)
   AND k.lat BETWEEN -90.0 AND 90.0 AND k.lng BETWEEN -180.0 AND 180.0
   AND NOT (k.lat = 0.0 AND k.lng = 0.0)
   AND length(k.label) BETWEEN 1 AND 120
   AND k.rowid = (SELECT MAX(q.rowid) FROM tenant_locations_rolled_back_041 q
                   WHERE q.slug = k.slug);
-- Taken back: the kept rows are spent (a LATER rollback keeps the state of
-- THEN — an operator's change in between is never undone by old rows).
DELETE FROM tenant_locations_rolled_back_041;

PRAGMA user_version = 41;

COMMIT;
