-- Rollback migration 037.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036's pattern):
--   * registry — every ignore choice is kept under
--     `adapter_ignored_vendor_tenants_rolled_back_037` (appended to on a
--     second rollback), then the table goes. Re-applying 037 restores the
--     newest kept row per (instance, vendor tenant) whose instance still
--     exists. Code before 037 has no NextDNS adapter and never reads it.
--   * telemetry — both NextDNS tables are kept under `<name>_rolled_back_037`
--     (appended to), then dropped; the version goes back to 36. Re-applying
--     037 (the lazy ensure_db path) creates fresh empty tables beside the
--     preserved copies (never pruned by Athena: they are not the live
--     tables). The signals themselves live in events.db and are untouched.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS adapter_ignored_vendor_tenants_rolled_back_037 (
    adapter_instance_id     INTEGER NOT NULL,
    vendor_tenant_id        TEXT NOT NULL,
    vendor_tenant_label     TEXT,
    ignored_at              TEXT NOT NULL,
    ignored_by_operator_id  INTEGER
);
INSERT INTO adapter_ignored_vendor_tenants_rolled_back_037 (
    adapter_instance_id, vendor_tenant_id, vendor_tenant_label, ignored_at,
    ignored_by_operator_id)
SELECT adapter_instance_id, vendor_tenant_id, vendor_tenant_label, ignored_at,
       ignored_by_operator_id
  FROM adapter_ignored_vendor_tenants;
DROP TABLE IF EXISTS adapter_ignored_vendor_tenants;

PRAGMA user_version = 36;

COMMIT;

-- @target: telemetry

CREATE TABLE IF NOT EXISTS nextdns_hourly_rolled_back_037
    AS SELECT * FROM nextdns_hourly WHERE 0;
INSERT INTO nextdns_hourly_rolled_back_037 SELECT * FROM nextdns_hourly;
DROP INDEX IF EXISTS idx_nextdns_hourly_arrival;
DROP INDEX IF EXISTS idx_nextdns_hourly_profile;
DROP TABLE IF EXISTS nextdns_hourly;

CREATE TABLE IF NOT EXISTS nextdns_signal_buckets_rolled_back_037
    AS SELECT * FROM nextdns_signal_buckets WHERE 0;
INSERT INTO nextdns_signal_buckets_rolled_back_037 SELECT * FROM nextdns_signal_buckets;
DROP INDEX IF EXISTS idx_nextdns_buckets_arrival;
DROP INDEX IF EXISTS idx_nextdns_buckets_event;
DROP INDEX IF EXISTS idx_nextdns_buckets_open;
DROP TABLE IF EXISTS nextdns_signal_buckets;

PRAGMA user_version = 36;
