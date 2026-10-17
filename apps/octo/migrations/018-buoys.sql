-- Migration 018: Buoy fleet heartbeat table.
--
-- Each deployed buoy (Pi-class sensor appliance) pushes a heartbeat to
-- /api/v1/buoy/heartbeat every INTERVAL_SEC seconds with its current
-- system load, service-unit states, and last-event-forwarded timestamp.
-- OCTO upserts the row keyed by tenant slug (v1 = one buoy per tenant);
-- the dashboard + /fleet page read from here to render live status.
--
-- Scope: registry-level (bundle config + fleet metadata), NOT per-tenant
-- data. Buoy rows are bundle-wide visibility-gated by the operator's
-- scope_slugs (admin/analyst → assigned clients, viewer → own client,
-- super_admin → all).
--
-- Design notes:
--   - Single row per slug. If multi-buoy-per-tenant arrives later, this
--     becomes (slug, hostname) composite PK or a synthetic buoy_id.
--   - services_json: JSON blob of {unit_name: "active"|"inactive"|...}.
--     Stored as TEXT so adding new units (suricata, pihole-FTL, etc.)
--     doesn't require schema changes.
--   - interval_sec: reported BY the buoy in each heartbeat so the
--     dashboard can derive staleness without hardcoding 60. Lets us
--     bump cadence per-buoy in the future.
--   - last_event_at: when buoy-forwarder last successfully forwarded a
--     sensor event to OCTO. Separate from heartbeat success — answers
--     "is the buoy SEEING traffic" not just "is it ONLINE."
--   - No FK on slug → clients.slug. The buoy may report a slug that
--     hasn't been provisioned yet (race during onboarding); we accept
--     the heartbeat and let the operator UI flag it. Strict FK would
--     drop visibility into provisioning issues.

PRAGMA user_version = 18;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS buoys (
    slug               TEXT PRIMARY KEY,
    hostname           TEXT NOT NULL,
    last_heartbeat_at  TEXT NOT NULL,    -- ISO-8601 UTC, when we received this row
    boot_time          TEXT,             -- ISO-8601 UTC, derived from uptime_sec at receipt
    uptime_sec         INTEGER NOT NULL,
    interval_sec       INTEGER NOT NULL DEFAULT 60,
    load_1             REAL,
    load_5             REAL,
    load_15            REAL,
    mem_used_mb        INTEGER,
    mem_total_mb       INTEGER,
    disk_used_pct      INTEGER,
    services_json      TEXT NOT NULL DEFAULT '{}',
    last_event_at      TEXT,             -- last successful sensor event forwarded
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_buoys_last_heartbeat
    ON buoys(last_heartbeat_at DESC);
