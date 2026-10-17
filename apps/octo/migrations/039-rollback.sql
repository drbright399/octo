-- Rollback migration 039.
--
-- Nothing is destroyed by a downgrade (036 / 037's pattern):
--   * telemetry — the three UniFi tables are kept under
--     `<name>_rolled_back_039` (appended to on a second rollback), then
--     dropped; the version goes back to 37 (038 has no telemetry section).
--     Re-applying 039 (the lazy ensure_db path) creates fresh empty tables
--     beside the preserved copies; the poller then re-reads each mapped
--     site's last 24 hours (signals are stored once: the sink's identity
--     guard). The signals themselves live in events.db and are untouched.

-- @target: telemetry

CREATE TABLE IF NOT EXISTS unifi_hourly_rolled_back_039 AS SELECT * FROM unifi_hourly WHERE 0;
INSERT INTO unifi_hourly_rolled_back_039 SELECT * FROM unifi_hourly;
DROP INDEX IF EXISTS idx_unifi_hourly_arrival;
DROP INDEX IF EXISTS idx_unifi_hourly_scope;
DROP TABLE IF EXISTS unifi_hourly;

CREATE TABLE IF NOT EXISTS unifi_signal_buckets_rolled_back_039
    AS SELECT * FROM unifi_signal_buckets WHERE 0;
INSERT INTO unifi_signal_buckets_rolled_back_039 SELECT * FROM unifi_signal_buckets;
DROP INDEX IF EXISTS idx_unifi_buckets_arrival;
DROP INDEX IF EXISTS idx_unifi_buckets_event;
DROP INDEX IF EXISTS idx_unifi_buckets_pending;
DROP TABLE IF EXISTS unifi_signal_buckets;

CREATE TABLE IF NOT EXISTS unifi_syslog_cursor_rolled_back_039
    AS SELECT * FROM unifi_syslog_cursor WHERE 0;
INSERT INTO unifi_syslog_cursor_rolled_back_039 SELECT * FROM unifi_syslog_cursor;
DROP INDEX IF EXISTS idx_unifi_cursor_arrival;
DROP TABLE IF EXISTS unifi_syslog_cursor;

PRAGMA user_version = 37;
