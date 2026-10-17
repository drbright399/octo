-- Rollback migration 046.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 040 / 044's pattern):
--   * registry — the verdicts, the expected conditions and the enrichment
--     cache are LEFT AS THEY ARE: nothing before 046 reads them (a release
--     before 046 has no acknowledge, no expected label — every alert counts
--     towards Yellow again), and a re-upgrade finds them current: every
--     acknowledgement and every live expected condition applies again. The
--     version goes back to 44 (045 is the parallel v0.17.1 branch's: once
--     it is merged, this goes back to 45 — the rollback test pins it to the
--     newest registry migration before 046).
--   * telemetry (each telemetry.db at 46) — every IPS bucket's `remotes`
--     is kept under `unifi_bucket_remotes_rolled_back_046`, the column is
--     dropped; the version goes back to 39.
--   * entities (each entities.db at 46) — every device's `ext_ip` is kept
--     under `inv_device_ext_ip_rolled_back_046`, the column is dropped; the
--     version goes back to 40.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

PRAGMA user_version = 44;

COMMIT;

-- @target: telemetry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS unifi_bucket_remotes_rolled_back_046 (
    bucket_key TEXT NOT NULL,
    remotes    TEXT
);
INSERT INTO unifi_bucket_remotes_rolled_back_046 (bucket_key, remotes)
SELECT bucket_key, remotes FROM unifi_signal_buckets WHERE remotes IS NOT NULL;
ALTER TABLE unifi_signal_buckets DROP COLUMN remotes;

PRAGMA user_version = 39;

COMMIT;

-- @target: entities

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS inv_device_ext_ip_rolled_back_046 (
    adapter_instance_id INTEGER NOT NULL,
    device_uid          TEXT NOT NULL,
    ext_ip              TEXT
);
INSERT INTO inv_device_ext_ip_rolled_back_046 (adapter_instance_id, device_uid, ext_ip)
SELECT adapter_instance_id, device_uid, ext_ip FROM inv_device WHERE ext_ip IS NOT NULL;
ALTER TABLE inv_device DROP COLUMN ext_ip;

PRAGMA user_version = 40;

COMMIT;
