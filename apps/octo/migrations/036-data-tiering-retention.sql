-- Migration 036: data tiering (per-tenant telemetry store) + retention
-- enforcement bookkeeping.
--
-- WHY. Measured on a small buoy site (owner decision 2026-09-29): about
-- 1,300 events an hour, ~97 % of them DNS telemetry (suricata.dns ~2/3,
-- pihole.query ~1/3 — the same lookups recorded twice), all of it stored in
-- events.db under the one-year events retention — which nothing enforced.
-- From this migration on the ingest path files every event as a SIGNAL
-- (events.db, as before) or TELEMETRY (the new per-tenant telemetry.db);
-- the classification registry is `apps/octo/ingest/tiering.py`.
--
-- registry section:
--   * two new retention classes in bundle_config_retention, editable like
--     the others:
--       telemetry_raw     7 d   — raw DNS / TLS / HTTP / flow metadata rows.
--                                 Operational baseline (no regulator names
--                                 a hot-store period for resolver logs);
--                                 anything longer-lived is the COLD ARCHIVE
--                                 (gzip JSONL per tenant per UTC day under
--                                 OCTO_ARCHIVE_ROOT), which is written before
--                                 a raw row is pruned and is never pruned by
--                                 Athena.
--       telemetry_rollup  180 d — hourly counts per (event type, domain,
--                                 device). Operational baseline: two
--                                 quarters of trend for "is this new?".
--   * adapter_poller_state — durable per-instance poller state (see the
--     table below; RocketCyber's history-skipped incidents).
--   * a RE-upgrade (after 036-rollback.sql) restores the kept telemetry
--     retention rows and poller state before anything is seeded; the empty
--     `*_rolled_back_036` copies this creates on a first upgrade are that
--     one code path, not data.
--   * retention_runs — one row per ENFORCING run of the retention job
--     (`apps/octo/retention/job.py`): when, which trigger, the outcome and
--     the per-tenant, per-class counts the Settings → System page shows. A
--     dry run writes nothing anywhere, this table included. The audit chain
--     holds the authoritative record (actor `retention-job`): a
--     `retention_enforce` row per tenant with something to delete, before
--     the deletes, and one `retention_run` row per run after it.
--
-- events section (clients/<slug>/events.db):
--   * events.ingested_at — the ARRIVAL time (when Athena received and stored
--     the row; canonical UTC ms, stamped by the ingest sink). OWNER DECISION
--     2026-09-29: retention of a signal is measured from arrival, never from
--     the vendor's timestamp (`received_at`, which stays stored and shown).
--     Nullable, no default (ALTER TABLE cannot add a non-constant default;
--     the sink always writes it). Rows stored before 036 are NULL until the
--     one-off backfill (scripts/move_telemetry_out_of_events.py) stamps them
--     with the best available arrival estimate — the stamp a rollback of 036
--     kept for the row, else its received_at, never before a lower id's
--     arrival — after it has moved their telemetry out
--     (`apps/octo/ingest/arrival.py`).
--   * This section runs where the runner applies @target: events — a NEW
--     tenant's events.db (client provisioning). An events.db provisioned
--     before 036 gets the column lazily (the sink's first write, the
--     backfill) and the index from the backfill: building it on a pre-move
--     events.db would hold its write lock for the whole scan.
--
-- telemetry section (clients/<slug>/telemetry.db — a per-tenant file,
-- created by client provisioning for new tenants and lazily, on first
-- telemetry write, for existing ones; user_version tracks it like the
-- quarantine store):
--   * auto_vacuum = INCREMENTAL, set before any table exists (it cannot be
--     switched on later without a full VACUUM), so the retention job can
--     hand pruned pages back to the filesystem in short steps.
--   * telemetry_raw — one row per telemetry event. Identity = the events
--     sink's: (source, payload_sha256, received_at); payload bounded
--     (`telemetry.MAX_PAYLOAD_BYTES`, sha over the full text);
--     origin_event_id = the events.db id a row was MOVED from (the one-off
--     move of existing rows), unique, so a re-run never copies a row twice.
--     ingested_at = ARRIVAL (a moved row keeps its events.db arrival /
--     estimate, never later than the move): the 7-day retention and the
--     cold archive's day files go by it, not by the sensor's clock.
--   * device = the LAN client's ADDRESS wherever the sensor gives one (the
--     key Suricata has: one device, one key across sensors), device_name =
--     the name Pi-hole v6 knows it by — a search by either finds it.
--   * telemetry_hourly — hourly roll-up, UNIQUE per (hour, event type,
--     domain, device), upserted in the same transaction as the raw row;
--     last_arrival = the latest arrival folded in — the 180-day retention's
--     clock (a sensor with a wrong clock files hours in the past or the
--     future; they still age out 180 days after they arrived).
--   * first_seen_domains — the first time the tenant looked up each domain
--     (and who, and how); last_seen lets the retention job forget a domain
--     not seen for a year, so its return counts as new again.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

-- A RE-upgrade after a rollback of 036 takes back what the rollback kept
-- (036-rollback.sql) BEFORE the defaults below are seeded: the newest kept
-- telemetry retention row per class — a super_admin's value, not the
-- default (otherwise the first nightly run after the re-upgrade deletes
-- what that value kept). The kept-copy table is created empty on a first
-- upgrade so this is one code path; a later rollback appends to it.
CREATE TABLE IF NOT EXISTS bundle_config_retention_rolled_back_036
    AS SELECT * FROM bundle_config_retention WHERE 0;
INSERT OR IGNORE INTO bundle_config_retention
    (data_class, retention_days, legal_baseline_days, regulator_basis, editable,
     description, updated_at, updated_by)
SELECT k.data_class, k.retention_days, k.legal_baseline_days, k.regulator_basis,
       k.editable, k.description, k.updated_at, k.updated_by
  FROM bundle_config_retention_rolled_back_036 k
 WHERE k.data_class IN ('telemetry_raw', 'telemetry_rollup')
   AND k.rowid = (SELECT MAX(q.rowid) FROM bundle_config_retention_rolled_back_036 q
                   WHERE q.data_class = k.data_class);

INSERT OR IGNORE INTO bundle_config_retention
    (data_class, retention_days, legal_baseline_days, regulator_basis, editable, description, updated_by)
VALUES
    ('telemetry_raw',          7,     7,
     'Operational baseline (no regulator citation); long-term raw copies live in the cold archive',
     1,
     'Raw DNS / TLS / HTTP / flow metadata from buoys (telemetry.db). Archived to a compressed daily file under OCTO_ARCHIVE_ROOT before it is pruned, when the archive is configured.',
     NULL),
    ('telemetry_rollup',       180,   180,
     'Operational baseline (no regulator citation)',
     1,
     'Hourly counts per event type, domain and device (telemetry.db) — the DNS summary and trend view.',
     NULL);

CREATE TABLE IF NOT EXISTS retention_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL UNIQUE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    -- 'backfill' = the one-off move script's run (not a nightly-kind run).
    trigger         TEXT NOT NULL
                      CHECK (trigger IN ('scheduler','script','api','backfill')),
    status          TEXT NOT NULL
                      CHECK (status IN ('running','ok','partial','failed')),
    archive_enabled INTEGER NOT NULL DEFAULT 0 CHECK (archive_enabled IN (0,1)),
    tenants         INTEGER NOT NULL DEFAULT 0,
    deleted_total   INTEGER NOT NULL DEFAULT 0,
    summary_json    TEXT NOT NULL DEFAULT '{}',
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_retention_runs_started
    ON retention_runs(started_at);

-- Small, durable per-instance poller state (v0.11): what a poller must know
-- after a restart that is NOT in the events it stored. First user:
-- RocketCyber's history-skipped incidents (skipped at first connect, never
-- stored) — without it, a restart forgot them and the next change of such an
-- incident's updatedAt stored it as a new HIGH row. One JSON value per
-- (instance, key), bounded by the writer (`apps/octo/instances/poller_state.py`).
CREATE TABLE IF NOT EXISTS adapter_poller_state (
    instance_id INTEGER NOT NULL,
    key         TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 64),
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (instance_id, key)
) WITHOUT ROWID;

-- A re-upgrade takes back the newest value per (instance, key) a rollback
-- kept (RocketCyber's history-skipped incidents would otherwise come back
-- as new HIGH rows). Created empty on a first upgrade (one code path).
CREATE TABLE IF NOT EXISTS adapter_poller_state_rolled_back_036
    AS SELECT * FROM adapter_poller_state WHERE 0;
INSERT OR IGNORE INTO adapter_poller_state (instance_id, key, value_json, updated_at)
SELECT k.instance_id, k.key, k.value_json, k.updated_at
  FROM adapter_poller_state_rolled_back_036 k
 WHERE k.rowid = (SELECT MAX(q.rowid) FROM adapter_poller_state_rolled_back_036 q
                   WHERE q.instance_id = k.instance_id AND q.key = k.key);

PRAGMA user_version = 36;

COMMIT;

-- @target: events

ALTER TABLE events ADD COLUMN ingested_at TEXT;

-- The retention prune (ingested_at < cutoff) and the backfill's "anything
-- left to stamp?" probe.
CREATE INDEX IF NOT EXISTS idx_events_ingested_at ON events(ingested_at);

-- @target: telemetry

PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS telemetry_raw (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at       TEXT NOT NULL,
    source            TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info'
                        CHECK (severity IN ('info','low','medium','high','critical')),
    source_host       TEXT,
    domain            TEXT NOT NULL DEFAULT '',
    device            TEXT NOT NULL DEFAULT '',   -- the LAN client's address (else its name)
    device_name       TEXT NOT NULL DEFAULT '',   -- the name Pi-hole v6 knows it by
    payload           TEXT NOT NULL,
    payload_truncated INTEGER NOT NULL DEFAULT 0 CHECK (payload_truncated IN (0,1)),
    payload_sha256    TEXT NOT NULL,
    origin_event_id   INTEGER,
    ingested_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Newest-event freshness, the DNS search's raw window (the sensor's time).
CREATE INDEX IF NOT EXISTS idx_telemetry_raw_received
    ON telemetry_raw(received_at);
-- Prune (ingested_at < cutoff) and archive-by-arrival-day.
CREATE INDEX IF NOT EXISTS idx_telemetry_raw_ingested
    ON telemetry_raw(ingested_at);
-- The sink's idempotency lookup (source, payload_sha256, received_at).
CREATE INDEX IF NOT EXISTS idx_telemetry_raw_sha
    ON telemetry_raw(payload_sha256);
-- The move from events.db is idempotent per source row.
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_raw_origin
    ON telemetry_raw(origin_event_id) WHERE origin_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS telemetry_hourly (
    hour        TEXT NOT NULL,              -- 'YYYY-MM-DDTHH:00:00Z' (UTC)
    event_type  TEXT NOT NULL,
    domain      TEXT NOT NULL DEFAULT '',
    device      TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',    -- latest name seen for the device
    count       INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_arrival TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (hour, event_type, domain, device)
) WITHOUT ROWID;

-- "Top domains in the last N hours" (hour range, grouped by domain).
CREATE INDEX IF NOT EXISTS idx_telemetry_hourly_domain
    ON telemetry_hourly(domain, hour);
-- The roll-up prune (last_arrival < cutoff).
CREATE INDEX IF NOT EXISTS idx_telemetry_hourly_arrival
    ON telemetry_hourly(last_arrival);

CREATE TABLE IF NOT EXISTS first_seen_domains (
    domain            TEXT PRIMARY KEY,
    first_seen        TEXT NOT NULL,
    first_device      TEXT NOT NULL DEFAULT '',
    first_event_type  TEXT NOT NULL,
    last_seen         TEXT NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_first_seen_domains_first
    ON first_seen_domains(first_seen);
CREATE INDEX IF NOT EXISTS idx_first_seen_domains_last
    ON first_seen_domains(last_seen);

PRAGMA user_version = 36;
