-- Migration 004: source-instance registry + per-event human summary.
--
-- Adds:
--   1. `source_instances` table to registry.db — registers per-tenant
--      Wazuh / Splunk / etc. manager bindings with the (slug, type, instance)
--      tuple from feedback_tailscale_acl_protocol-style design.
--   2. `source_instance_id` column on `client_tokens` — service-kind tokens
--      can now bind to a specific source instance, so `service:<slug>:<type>:
--      <instance>` token scope is enforceable at ingest time.
--   3. `summary` column on per-client `events` table — operator-facing
--      drill-down line per `feedback_human_readable_drilldown.md`. Default
--      `''` so existing rows don't violate NOT NULL; new rows from source-
--      adapter ingestion populate it from `adapter.human_summary()`.
--
-- See PHASE-F4B-SOURCE-REGISTRY-SPEC.md for the design rationale.

PRAGMA user_version = 4;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS source_instances (
    -- Identity tuple: (slug, type, instance). PK enforces uniqueness within
    -- (slug, source_type) so an operator can't accidentally collide names.
    slug                TEXT NOT NULL REFERENCES clients(slug) ON DELETE RESTRICT,
    source_type         TEXT NOT NULL
                          CHECK (source_type GLOB '[a-z]*'
                                 AND source_type NOT GLOB '*[^a-z0-9-]*'),
    source_instance_id  TEXT NOT NULL
                          CHECK (source_instance_id GLOB '[a-z0-9]*'
                                 AND source_instance_id NOT GLOB '*--*'
                                 AND source_instance_id NOT GLOB '*-'
                                 AND source_instance_id NOT GLOB '*[^a-z0-9-]*'),
    display_name        TEXT NOT NULL,
    description         TEXT,
    -- Free-form notes — operators record Wazuh manager version, region,
    -- migration history, etc. here. Per Q4 forward-compat decision.
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_by_operator INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    revoked_at          TEXT,
    revoked_by_operator INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    revoked_reason      TEXT,
    PRIMARY KEY (slug, source_type, source_instance_id)
);

CREATE INDEX IF NOT EXISTS idx_source_instances_live
    ON source_instances(slug, source_type)
    WHERE revoked_at IS NULL;

-- Add source_instance_id to client_tokens for service-kind bindings.
-- ALTER TABLE ADD COLUMN is safe on populated tables; existing rows
-- (buoy + admin tokens) get NULL, which is correct since they aren't
-- source-bound. The router enforces NOT NULL at the application layer
-- when token.kind = 'service' and the URL routes to /<source_type>/.
--
-- Idempotency: SQLite has no `ADD COLUMN IF NOT EXISTS`, so we guard at
-- the runner level. Re-running this migration is a no-op because we check
-- for the column first via a probing pragma in the runner. For raw
-- application of this file (e.g. against a fresh DB), SQLite will error
-- on the second run — which is the correct failure mode.
ALTER TABLE client_tokens ADD COLUMN source_instance_id TEXT;

CREATE INDEX IF NOT EXISTS idx_client_tokens_source_instance
    ON client_tokens(slug, source_instance_id)
    WHERE source_instance_id IS NOT NULL AND revoked_at IS NULL;

-- @target: events

-- Add human-readable summary to per-client events. Default empty string so
-- the column is NOT NULL but old rows don't break. Adapters populate this
-- via the SourceAdapter Protocol (see octo_admin/sources/base.py).
ALTER TABLE events ADD COLUMN summary TEXT NOT NULL DEFAULT '';

-- Idempotency-key index for SELECT-before-INSERT dedup.
-- The key lives in the JSON `payload` blob under `data._idempotency_key`
-- (set by the source-ingest router from `adapter.idempotency_key()`).
-- JSON1 expression index gives us a fast lookup without a dedicated column.
-- Partial index — only rows that opt into dedup get the index entry.
CREATE INDEX IF NOT EXISTS idx_events_idempotency_key
    ON events(json_extract(payload, '$.data._idempotency_key'))
    WHERE json_extract(payload, '$.data._idempotency_key') IS NOT NULL;

-- Help summary-based search in the future UI without forcing a full table
-- scan. Plain index — summaries are short.
CREATE INDEX IF NOT EXISTS idx_events_summary
    ON events(summary)
    WHERE summary != '';
