-- Migration 037: NextDNS integration (v0.12) — the "ignore" choice for vendor
-- tenants, and the two small telemetry-tier tables the NextDNS poller keeps.
--
-- The full DNS firehose never comes into Athena. The NextDNS poller asks the
-- cheap question first (analytics per mapped profile) and stores:
--   * SIGNALS — security blocks, coalesced — in events.db like any alert;
--   * per-profile HOURLY aggregates and the coalescing counters here, in the
--     tenant's telemetry.db, retention class `telemetry_rollup` (180 days,
--     by `last_arrival` — the retention job prunes both tables with
--     telemetry_hourly).
--
-- registry section
--   adapter_ignored_vendor_tenants — a vendor tenant (a NextDNS profile) an
--     admin said Athena should leave alone: it stops being listed as
--     "needs mapping". It is never polled either way (unmapped profiles are
--     never polled); ignoring is the operator's "yes, on purpose" for the
--     account's personal and test profiles. Generic by design: keyed by
--     adapter instance + the vendor's tenant id, like adapter_tenant_map.
--     A row is never both mapped and ignored (the save route refuses it).
--
-- telemetry section (clients/<slug>/telemetry.db)
--   nextdns_hourly — one row per (clock hour, profile): queries by status
--     (default / blocked / allowed) and blocked queries by reason CLASS
--     (high / medium / low signal, not-a-signal policy blocks), plus the
--     signal-class reason ids seen that hour (usually none). Re-fetching an
--     hour REPLACES its row (analytics are absolute counts, never added).
--   nextdns_signal_buckets — the alert-fatigue coalescing ledger: the FIRST
--     security block per (profile, device-or-client-IP, root domain, reason,
--     SPAN) creates one signal (`event_id`); later hits in the bucket only
--     count here (`hits`), so the stored alert's payload / sha / received_at
--     identity is never touched. `span` = 'hour' (HIGH reasons: the clock
--     hour) or 'day' (MEDIUM / LOW: the UTC day; `hour` then holds the
--     day's 00:00). A cross-domain reason (DGA) leaves the root out of the
--     key (`root` = '*') and keeps the distinct roots it saw in `roots`
--     (bounded list) / `distinct_roots`. `last_seen` + `last_ids` make
--     counting exactly-once when overlapping windows re-read the same log
--     lines. `event_id` NULL = a claim whose alert is still being written
--     (a crash leaves it for the next pass to finish, never a second alert).
--     `noted` = the "seen N times this hour" note was written at bucket close.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS adapter_ignored_vendor_tenants (
    adapter_instance_id     INTEGER NOT NULL
                              REFERENCES adapter_instances(id) ON DELETE CASCADE,
    vendor_tenant_id        TEXT NOT NULL
                              CHECK (length(vendor_tenant_id) BETWEEN 1 AND 256),
    vendor_tenant_label     TEXT,
    ignored_at              TEXT NOT NULL
                              DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ignored_by_operator_id  INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    PRIMARY KEY (adapter_instance_id, vendor_tenant_id)
) WITHOUT ROWID;

-- A re-upgrade takes back what a rollback kept (036's pattern): an operator's
-- ignore choices survive a downgrade + upgrade. Created empty on a first
-- upgrade (one code path).
CREATE TABLE IF NOT EXISTS adapter_ignored_vendor_tenants_rolled_back_037 (
    adapter_instance_id     INTEGER NOT NULL,
    vendor_tenant_id        TEXT NOT NULL,
    vendor_tenant_label     TEXT,
    ignored_at              TEXT NOT NULL,
    ignored_by_operator_id  INTEGER
);
INSERT OR IGNORE INTO adapter_ignored_vendor_tenants (
    adapter_instance_id, vendor_tenant_id, vendor_tenant_label, ignored_at,
    ignored_by_operator_id)
SELECT k.adapter_instance_id, k.vendor_tenant_id, k.vendor_tenant_label, k.ignored_at,
       CASE WHEN k.ignored_by_operator_id IN (SELECT id FROM operators)
            THEN k.ignored_by_operator_id END
  FROM adapter_ignored_vendor_tenants_rolled_back_037 k
 WHERE k.adapter_instance_id IN (SELECT id FROM adapter_instances)
   AND k.rowid = (SELECT MAX(q.rowid) FROM adapter_ignored_vendor_tenants_rolled_back_037 q
                   WHERE q.adapter_instance_id = k.adapter_instance_id
                     AND q.vendor_tenant_id = k.vendor_tenant_id);

PRAGMA user_version = 37;

COMMIT;

-- @target: telemetry

CREATE TABLE IF NOT EXISTS nextdns_hourly (
    hour            TEXT NOT NULL,              -- 'YYYY-MM-DDTHH:00:00Z' (UTC)
    profile_id      TEXT NOT NULL,
    queries         INTEGER NOT NULL DEFAULT 0 CHECK (queries >= 0),
    default_queries INTEGER NOT NULL DEFAULT 0 CHECK (default_queries >= 0),
    blocked         INTEGER NOT NULL DEFAULT 0 CHECK (blocked >= 0),
    allowed         INTEGER NOT NULL DEFAULT 0 CHECK (allowed >= 0),
    signal_high     INTEGER NOT NULL DEFAULT 0 CHECK (signal_high >= 0),
    signal_medium   INTEGER NOT NULL DEFAULT 0 CHECK (signal_medium >= 0),
    signal_low      INTEGER NOT NULL DEFAULT 0 CHECK (signal_low >= 0),
    policy_blocked  INTEGER NOT NULL DEFAULT 0 CHECK (policy_blocked >= 0),
    signal_reasons  TEXT NOT NULL DEFAULT '{}', -- signal-class reason id → queries
    fetched_at      TEXT NOT NULL,
    last_arrival    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (hour, profile_id)
) WITHOUT ROWID;

-- The roll-up prune (last_arrival < cutoff).
CREATE INDEX IF NOT EXISTS idx_nextdns_hourly_arrival
    ON nextdns_hourly(last_arrival);

CREATE TABLE IF NOT EXISTS nextdns_signal_buckets (
    bucket_key  TEXT PRIMARY KEY,               -- sha256(profile|device|root|reason|hour[|day])[:32]
    hour        TEXT NOT NULL,                  -- 'YYYY-MM-DDTHH:00:00Z' (span start)
    span        TEXT NOT NULL DEFAULT 'hour' CHECK (span IN ('hour', 'day')),
    profile_id  TEXT NOT NULL,
    reason_id   TEXT NOT NULL,
    root        TEXT NOT NULL DEFAULT '',       -- '*' for a cross-domain reason
    roots       TEXT NOT NULL DEFAULT '[]',     -- cross-domain: distinct roots (bounded)
    distinct_roots INTEGER NOT NULL DEFAULT 0 CHECK (distinct_roots >= 0),
    device      TEXT NOT NULL DEFAULT '',       -- device id, else the client IP
    event_id    INTEGER,                        -- events.db id of the ONE alert
    hits        INTEGER NOT NULL DEFAULT 1 CHECK (hits >= 1),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_ids    TEXT NOT NULL DEFAULT '[]',     -- line ids counted AT last_seen
    noted       INTEGER NOT NULL DEFAULT 0 CHECK (noted IN (0, 1)),
    last_arrival TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_nextdns_buckets_arrival
    ON nextdns_signal_buckets(last_arrival);
CREATE INDEX IF NOT EXISTS idx_nextdns_buckets_event
    ON nextdns_signal_buckets(event_id);
-- Buckets whose span is over and whose note is not written yet.
CREATE INDEX IF NOT EXISTS idx_nextdns_buckets_open
    ON nextdns_signal_buckets(noted, hour);
-- The lapse baseline: a profile's same hour on earlier days.
CREATE INDEX IF NOT EXISTS idx_nextdns_hourly_profile
    ON nextdns_hourly(profile_id, hour);

PRAGMA user_version = 37;
