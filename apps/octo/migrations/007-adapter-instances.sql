-- ============================================================================
-- Migration 007 — adapter_instances table.
--
-- Distinct from `source_instances` (migration 004) which is per-CLIENT and
-- token-scoped. `adapter_instances` is **bundle-scoped**: one row per
-- configured upstream (one Datto API config, one Wazuh manager, etc.),
-- regardless of how many OCTO clients map onto it. Tenant routing happens
-- inside the adapter via `route_to_tenant()` + the tenant-mapping wizard
-- step (see `feedback_integrations_catalog_sidebar_popout`).
--
-- v1 constraint: ONE active instance per `vendor_slug`. The partial unique
-- index enforces this without preventing future multi-instance support
-- (the multi-Datto case becomes: drop the partial unique index, distinguish
-- instances by `display_name`).
--
-- Credentials are stored encrypted via `apps.octo.credentials.store()`;
-- the resulting opaque versioned ciphertext lives in `cred_ref`. No
-- credential values ever appear in this DB or its backups in cleartext.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS adapter_instances (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_slug                 TEXT NOT NULL
                                  CHECK (vendor_slug GLOB '[a-z]*'
                                         AND vendor_slug NOT GLOB '*[^a-z0-9-]*'),
    display_name                TEXT NOT NULL,
    cred_ref                    TEXT NOT NULL,
    instance_config_json        TEXT NOT NULL DEFAULT '{}',
    default_tenant_slug         TEXT,
    status                      TEXT NOT NULL DEFAULT 'starting'
                                  CHECK (status IN (
                                      'starting',
                                      'running',
                                      'disabled',
                                      'error'
                                  )),
    status_detail               TEXT,
    configured_at               TEXT NOT NULL
                                  DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    configured_by_operator_id   INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    last_test_at                TEXT,
    last_event_at               TEXT,
    disabled_at                 TEXT,
    disabled_by_operator_id     INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    disabled_reason             TEXT
);

-- One active instance per vendor in v1. Disabled instances are excluded so
-- an operator can re-create after a teardown without colliding on the index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_adapter_instances_active_vendor
    ON adapter_instances(vendor_slug)
    WHERE disabled_at IS NULL;

-- Status filter for the read-back endpoint + auto-start boot hook.
CREATE INDEX IF NOT EXISTS idx_adapter_instances_status
    ON adapter_instances(status);

PRAGMA user_version = 7;
