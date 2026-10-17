-- Migration 022: generic bundle_config key-value table.
--
-- Earlier bundle-scoped config lived in scattered per-feature tables
-- (bundle_config_retention from migration 012, ATHENA_BUNDLE_BRAND_*
-- env vars handled in branding.py). This migration introduces a
-- single key-value store for operator-editable bundle-level
-- configuration that doesn't warrant its own dedicated schema:
--
--   - `octo_location` — lat/lng/display/city/msp for the OCTO hub
--     marker on the Fleet map. Read by /api/v1/dashboard/octo-location;
--     used by the frontend to position the hub icon at the MSP's true
--     business location (was hardcoded to a placeholder).
--   - Future keys can be added (e.g. `branding_logo_url`,
--     `default_tenant_theme`) without further migrations — the table
--     stores arbitrary JSON.
--
-- Values are JSON-encoded to keep the schema simple while preserving
-- structure. Reads parse, writes serialize; the API layer validates
-- shape per key.

PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS bundle_config (
    key             TEXT PRIMARY KEY,
    value_json      TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    updated_at      TEXT NOT NULL,                 -- ISO-8601 UTC
    updated_by      INTEGER REFERENCES operators(id) ON DELETE SET NULL
);

-- Seed a placeholder hub location (operators set the real one via the
-- bundle-config API). A future MSP-onboarding wizard re-seeds this with the
-- customer's own address.
--
-- The seed values were made neutral on 2026-10-16 (they now match the public
-- copy). INSERT OR IGNORE: this changes fresh installs only. A bundle that
-- already applied 022 keeps its existing row (migrations run by
-- user_version, so 022 never runs again there), and nothing else in this
-- migration changed.
INSERT OR IGNORE INTO bundle_config (key, value_json, description, updated_at) VALUES (
    'octo_location',
    '{"slug":"primary","display":"Primary","city":"Example City","msp":"the MSP","lat":39.7817,"lng":-89.6501}',
    'Lat/lng + display name of this bundle''s OCTO hub. Drives the hub icon position on the Fleet map.',
    '2026-05-20T19:11:00Z'
);

PRAGMA user_version = 22;
