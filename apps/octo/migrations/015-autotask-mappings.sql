-- Migration 015: Autotask integration mappings (P4-b1).
--
-- Three companion tables for the Autotask PSA integration, all under
-- registry.db (bundle-config, not per-tenant data). Per the locked
-- Option C decision (2026-05-14 research doc), Autotask is the first
-- PSA adapter and these tables shape how the adapter resolves the
-- per-instance picklist + identity bridges between Athena and
-- Autotask.
--
-- All three are keyed by `adapter_instance_id` so a bundle that
-- (later) connects to multiple Autotask tenants keeps them
-- disambiguated. v1 assumes a single instance per bundle but the
-- schema doesn't bake that in.
--
-- Picklist cache: per-Autotask-instance integer IDs for status /
-- priority / queue / category. Refreshed on a cadence by the
-- adapter's picklist worker (P4-c1 prereq); read at outbound-push
-- time (P4-c2) to translate Athena labels → Autotask integer values.
-- Athena's internal schema (migration 014 ticket_notes etc.) stores
-- labels; this table is the bridge.
--
-- Operator → Resource map: super_admin populates at integration
-- setup, mapping each Athena operator to an Autotask Resource (= an
-- API-callable identity that can create tickets, assign tickets, etc.).
-- Used at outbound push time to fill `createdByContactID` /
-- `assignedResourceID` on Autotask side.
--
-- Tenant → Company map: super_admin populates at integration setup,
-- mapping each Athena client slug to an Autotask companyID. PLUS
-- stores the tenant's Autotask web-UI homepage URL so the Settings
-- panel can surface a "Open in Autotask →" quick-link per Rick's
-- 2026-05-14 directive.

PRAGMA user_version = 15;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS autotask_picklist_cache (
    adapter_instance_id    INTEGER NOT NULL,
    entity                 TEXT NOT NULL,         -- 'Tickets', 'TicketNotes', etc.
    field_name             TEXT NOT NULL,         -- 'status', 'priority', 'noteType', 'publish', ...
    athena_label           TEXT NOT NULL,         -- Athena-internal canonical label (e.g., 'new', 'in_progress')
    autotask_value_id      INTEGER NOT NULL,      -- per-instance integer id
    autotask_value_label   TEXT NOT NULL,         -- the Autotask-side display label (for the operator's reference)
    is_default             INTEGER NOT NULL DEFAULT 0
                              CHECK (is_default IN (0, 1)),
    is_active              INTEGER NOT NULL DEFAULT 1
                              CHECK (is_active IN (0, 1)),
    last_refreshed_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (adapter_instance_id, entity, field_name, athena_label)
);

-- Hot path: "give me the autotask integer id for THIS athena label"
-- — outbound push reads this row before every POST/PATCH. The PK
-- already covers it but the index gives us a partial-coverage hit
-- when we look up by entity+field across all labels (e.g., loading
-- the entire status picklist into a Settings UI dropdown).
CREATE INDEX IF NOT EXISTS idx_autotask_picklist_by_entity
    ON autotask_picklist_cache (adapter_instance_id, entity, field_name);


CREATE TABLE IF NOT EXISTS autotask_operator_resource_map (
    adapter_instance_id      INTEGER NOT NULL,
    operator_id              INTEGER NOT NULL
                                REFERENCES operators(id) ON DELETE CASCADE,
    autotask_resource_id     INTEGER NOT NULL,
    autotask_resource_email  TEXT,                 -- for display + match-confirm at setup time
    autotask_resource_name   TEXT,                 -- "Last, First" per Autotask convention
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by_operator_id   INTEGER,              -- super_admin who set it
    PRIMARY KEY (adapter_instance_id, operator_id)
);

CREATE INDEX IF NOT EXISTS idx_autotask_operator_by_resource
    ON autotask_operator_resource_map (adapter_instance_id, autotask_resource_id);


CREATE TABLE IF NOT EXISTS autotask_tenant_company_map (
    adapter_instance_id      INTEGER NOT NULL,
    tenant_slug              TEXT NOT NULL,
    autotask_company_id      INTEGER NOT NULL,
    autotask_company_name    TEXT,
    -- The Autotask web-UI homepage for THIS company. Surfaces in
    -- Settings as a per-tenant "Open in Autotask →" quick-link. May
    -- be NULL if the operator hasn't filled it in yet; the UI hides
    -- the link in that case.
    autotask_homepage_url    TEXT,
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by_operator_id   INTEGER,
    PRIMARY KEY (adapter_instance_id, tenant_slug)
);

CREATE INDEX IF NOT EXISTS idx_autotask_tenant_by_company
    ON autotask_tenant_company_map (adapter_instance_id, autotask_company_id);
