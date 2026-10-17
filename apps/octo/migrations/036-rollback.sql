-- Rollback migration 036.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what
-- it kept (so a downgrade + upgrade never shortens anything's retention):
--   * registry — the run history is kept under
--     `retention_runs_rolled_back_036` and the two telemetry retention rows
--     (with any value a super_admin set) under
--     `bundle_config_retention_rolled_back_036` (both appended to if they
--     exist already); then the table and the rows go. The audit chain's
--     `retention_enforce` / `retention_run` rows are untouched (append-only).
--     Re-applying 036 restores the newest kept retention row per class
--     BEFORE it seeds the defaults (a super_admin's 30-day telemetry_raw
--     comes back as 30, not 7). The run history stays in its kept copy
--     (the Settings page starts a new one; the nightly sweep then looks
--     back its fixed window — the safe behaviour without a resume point).
--   * registry — adapter_poller_state is kept under
--     `adapter_poller_state_rolled_back_036` (appended to), then dropped.
--     Re-applying 036 restores the newest kept value per (instance, key) —
--     RocketCyber's history-skipped incidents stay skipped.
--   * events — the arrival stamps are kept under
--     `events_arrival_rolled_back_036` (id, ingested_at, payload_sha256;
--     indexed by id; appended to on a second rollback), then the index and
--     the column go (DROP COLUMN rewrites the table: minutes on a large
--     events.db — a rollback is an offline step). Code before 036 never
--     reads the column. After a re-upgrade the column is back (NULL) and
--     the tenant is "backfill pending" until the one-off backfill runs; it
--     stamps each row with ITS kept stamp (same id AND payload digest — an
--     events.db restored from an older backup reuses ids), and only rows
--     stored during the downgrade get an estimate (`apps.octo.ingest.arrival`).
--   * telemetry — every table is kept under `<name>_rolled_back_036`
--     (appended to on a second rollback), then dropped. The file stays in
--     the tenant's directory; re-applying 036 creates fresh empty tables
--     next to the preserved copies (never pruned by Athena: they are not
--     the live tables). Code before 036 never reads telemetry.db.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

DROP INDEX IF EXISTS idx_retention_runs_started;
CREATE TABLE IF NOT EXISTS retention_runs_rolled_back_036
    AS SELECT * FROM retention_runs WHERE 0;
INSERT INTO retention_runs_rolled_back_036 SELECT * FROM retention_runs;
DROP TABLE IF EXISTS retention_runs;

CREATE TABLE IF NOT EXISTS bundle_config_retention_rolled_back_036
    AS SELECT * FROM bundle_config_retention WHERE 0;
INSERT INTO bundle_config_retention_rolled_back_036
    SELECT * FROM bundle_config_retention
     WHERE data_class IN ('telemetry_raw', 'telemetry_rollup');
DELETE FROM bundle_config_retention
 WHERE data_class IN ('telemetry_raw', 'telemetry_rollup');

CREATE TABLE IF NOT EXISTS adapter_poller_state_rolled_back_036
    AS SELECT * FROM adapter_poller_state WHERE 0;
INSERT INTO adapter_poller_state_rolled_back_036 SELECT * FROM adapter_poller_state;
DROP TABLE IF EXISTS adapter_poller_state;

PRAGMA user_version = 35;

COMMIT;

-- @target: events

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS events_arrival_rolled_back_036 (
    event_id       INTEGER NOT NULL,
    ingested_at    TEXT,
    payload_sha256 TEXT
);
-- The re-upgrade's backfill looks stamps up by id (`arrival.stamp_estimates`).
CREATE INDEX IF NOT EXISTS idx_events_arrival_rolled_back_036
    ON events_arrival_rolled_back_036(event_id);
INSERT INTO events_arrival_rolled_back_036 (event_id, ingested_at, payload_sha256)
    SELECT id, ingested_at, payload_sha256 FROM events WHERE ingested_at IS NOT NULL;
DROP INDEX IF EXISTS idx_events_ingested_at;
ALTER TABLE events DROP COLUMN ingested_at;

COMMIT;

-- @target: telemetry

BEGIN IMMEDIATE;

DROP INDEX IF EXISTS idx_first_seen_domains_last;
DROP INDEX IF EXISTS idx_first_seen_domains_first;
CREATE TABLE IF NOT EXISTS first_seen_domains_rolled_back_036
    AS SELECT * FROM first_seen_domains WHERE 0;
INSERT INTO first_seen_domains_rolled_back_036 SELECT * FROM first_seen_domains;
DROP TABLE IF EXISTS first_seen_domains;

DROP INDEX IF EXISTS idx_telemetry_hourly_arrival;
DROP INDEX IF EXISTS idx_telemetry_hourly_domain;
CREATE TABLE IF NOT EXISTS telemetry_hourly_rolled_back_036
    AS SELECT * FROM telemetry_hourly WHERE 0;
INSERT INTO telemetry_hourly_rolled_back_036 SELECT * FROM telemetry_hourly;
DROP TABLE IF EXISTS telemetry_hourly;

DROP INDEX IF EXISTS idx_telemetry_raw_origin;
DROP INDEX IF EXISTS idx_telemetry_raw_sha;
DROP INDEX IF EXISTS idx_telemetry_raw_ingested;
DROP INDEX IF EXISTS idx_telemetry_raw_received;
CREATE TABLE IF NOT EXISTS telemetry_raw_rolled_back_036
    AS SELECT * FROM telemetry_raw WHERE 0;
INSERT INTO telemetry_raw_rolled_back_036 SELECT * FROM telemetry_raw;
DROP TABLE IF EXISTS telemetry_raw;

PRAGMA user_version = 0;

COMMIT;
