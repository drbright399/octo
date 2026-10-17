-- Migration 042: Fleet v2 — the manual location of ONE site (locked pins).
--
-- 041 placed a whole TENANT by hand. A client with several sites (a city
-- hall console AND a police console) needs each site pinned on its own, and
-- a console that reports the wrong place (its setup's guess, sometimes states
-- away) needs correcting per site. An operator (admin+) sets a site's
-- latitude / longitude and a label — typed, pasted from a map, or picked from
-- an address lookup the operator ran — audited (`site_location_set` /
-- `site_location_clear`, written BEFORE the row). The stored pair is LOCKED:
-- never re-geocoded, never moved by a console's report.
--
-- Precedence, read time (`apps.octo.fleet.locations.resolve`): this site
-- override, else the UniFi console's location (a single-site console, or a
-- multi-site console that is this tenant's alone), else the tenant's 041
-- override (the fallback), else no pin. There is NO IP geolocation anywhere.
--
-- registry section
--   site_locations     one row per Fleet site key (the opaque `u-…` / `t-…`
--                      key the Fleet API shows): the tenant it was set for
--                      (a site re-mapped to another tenant does not carry
--                      the pin — read only when the tenant still matches),
--                      lat / lng (WGS84 degrees), a label, who / when.
--                      (0, 0) is refused. The row is deleted when cleared.
--
-- Nothing else changes; tenant_locations (041) stays as it is.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS site_locations (
    site_key    TEXT PRIMARY KEY CHECK (length(site_key) BETWEEN 3 AND 40),
    tenant_slug TEXT NOT NULL,
    lat         REAL NOT NULL CHECK (lat BETWEEN -90.0 AND 90.0),
    lng         REAL NOT NULL CHECK (lng BETWEEN -180.0 AND 180.0),
    label       TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    set_by      INTEGER,
    set_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (NOT (lat = 0.0 AND lng = 0.0))
);

CREATE INDEX IF NOT EXISTS idx_site_locations_tenant ON site_locations(tenant_slug);

-- A re-upgrade takes back what a rollback kept (036 / 040 / 041's pattern):
-- the newest kept row per site whose tenant still exists. Created empty on a
-- first upgrade (one code path).
CREATE TABLE IF NOT EXISTS site_locations_rolled_back_042
    AS SELECT * FROM site_locations WHERE 0;
INSERT OR IGNORE INTO site_locations (site_key, tenant_slug, lat, lng, label, set_by, set_at)
SELECT k.site_key, k.tenant_slug, k.lat, k.lng, k.label, k.set_by, k.set_at
  FROM site_locations_rolled_back_042 k
 WHERE k.tenant_slug IN (SELECT slug FROM clients)
   AND length(k.site_key) BETWEEN 3 AND 40
   AND k.lat BETWEEN -90.0 AND 90.0 AND k.lng BETWEEN -180.0 AND 180.0
   AND NOT (k.lat = 0.0 AND k.lng = 0.0)
   AND length(k.label) BETWEEN 1 AND 120
   AND k.rowid = (SELECT MAX(q.rowid) FROM site_locations_rolled_back_042 q
                   WHERE q.site_key = k.site_key);
-- Taken back: the kept rows are spent (a LATER rollback keeps the state of
-- THEN — an operator's change in between is never undone by old rows).
DELETE FROM site_locations_rolled_back_042;

PRAGMA user_version = 42;

COMMIT;
