-- Rollback for migration 021.
-- SQLite < 3.35 cannot DROP COLUMN, so we recreate the table without
-- lat/lng. Modern SQLite (>= 3.35) could use ALTER TABLE DROP COLUMN
-- directly, but the recreate approach works on every version. Loses
-- whatever geo coords have been written since 021 ran.

PRAGMA user_version = 20;
PRAGMA foreign_keys = OFF;

-- @target: registry

BEGIN;

CREATE TABLE buoys_pre021 AS
  SELECT slug, hostname, last_heartbeat_at, boot_time, uptime_sec,
         interval_sec, load_1, load_5, load_15, mem_used_mb, mem_total_mb,
         disk_used_pct, services_json, last_event_at, created_at, updated_at
  FROM buoys;

DROP TABLE buoys;
ALTER TABLE buoys_pre021 RENAME TO buoys;

CREATE INDEX IF NOT EXISTS idx_buoys_last_heartbeat
  ON buoys(last_heartbeat_at DESC);

COMMIT;

PRAGMA foreign_keys = ON;
