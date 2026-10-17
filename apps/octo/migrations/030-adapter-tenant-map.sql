-- Migration 030: generic per-instance tenant map.
--
-- The cross-source client-identity layer. Each adapter's
-- route_to_tenant() yields a VENDOR tenant id (Datto siteUid, Wazuh
-- agent group, RocketCyber customerId, …). This table maps that vendor
-- id → the canonical OCTO client slug, per adapter instance, so events
-- from every source land under one client (one events.db). This is how
-- "Client A in Datto == Client A in Wazuh" is established — the OCTO
-- client slug is the join key, declared (or auto-matched) here.
--
-- Generalizes the Autotask-specific autotask_tenant_company_map
-- (migration 015) to a vendor-neutral shape so every telemetry adapter
-- (datto / wazuh / rocketcyber / unifi / …) shares one mapping store.
-- Lives in registry.db (bundle-config, not per-tenant data).
--
-- match_source anticipates the master-directory auto-matcher: a mapping
-- the operator typed is 'manual'; one suggested by matching the vendor
-- tenant's name/domain against the PSA/IT-Glue client directory is
-- 'auto-domain' / 'auto-name' (operator-confirmable).

-- @target: registry

CREATE TABLE IF NOT EXISTS adapter_tenant_map (
    adapter_instance_id      INTEGER NOT NULL,
    -- The vendor's own tenant identifier (the value route_to_tenant
    -- returns): Datto siteUid, Wazuh group name, RC customerId, etc.
    vendor_tenant_id         TEXT NOT NULL,
    -- The canonical OCTO client this vendor tenant belongs to. Events
    -- routing through this instance for `vendor_tenant_id` ingest under
    -- this client's events.db.
    octo_client_slug         TEXT NOT NULL,
    -- Vendor-side display name (e.g. the Datto site name), for the UI.
    vendor_tenant_label      TEXT,
    -- How this mapping was established: 'manual' | 'auto-domain' |
    -- 'auto-name' | 'directory'. Drives the auto-matcher's confirm UX.
    match_source             TEXT NOT NULL DEFAULT 'manual',
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by_operator_id   INTEGER,
    PRIMARY KEY (adapter_instance_id, vendor_tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_adapter_tenant_by_client
    ON adapter_tenant_map (adapter_instance_id, octo_client_slug);

PRAGMA user_version = 30;
