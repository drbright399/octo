-- Migration 021: Add geographic coords to the buoys table for the
--                  Fleet map view (per 2026-05-19 fleet-redesign handoff).
--
-- The Fleet map (apps/athena/web/src/components/fleet-map-view.tsx)
-- needs lat/lng to plot buoys against the basemap. Operators set
-- these once per buoy in /etc/buoy-heartbeat/heartbeat.env on the
-- buoy itself (LAT + LNG env vars); the daemon includes them in
-- every heartbeat, and OCTO upserts the latest values here.
--
-- Both columns nullable: pre-migration buoys + buoys without env-var
-- config still heartbeat fine, they just don't render on the map
-- view (the frontend filters them out with a "geo data missing"
-- banner counting the un-mapped buoys).
--
-- Pure additive migration — no data destruction, no FK constraints,
-- safe to re-run via INSERT-OR-IGNORE pattern.

PRAGMA user_version = 21;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE buoys ADD COLUMN lat REAL;
ALTER TABLE buoys ADD COLUMN lng REAL;
