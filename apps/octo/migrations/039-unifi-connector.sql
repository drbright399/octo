-- Migration 039: the UniFi connector adapter (cloud Site Manager API) — the
-- three small telemetry-tier tables its poller keeps in each MAPPED tenant's
-- telemetry.db. No registry change: sites map through adapter_tenant_map
-- (vendor tenant id "<hostId>/<siteId>" — site ids COLLIDE across consoles,
-- so the console is always part of the key), the ignore list is 037's
-- adapter_ignored_vendor_tenants, the poller's fleet state is
-- adapter_poller_state.
--
-- telemetry section (clients/<slug>/telemetry.db), retention class
-- `telemetry_rollup` (180 days by `last_arrival`):
--   unifi_hourly — per (clock hour, site, kind) the count of system-log
--     events that are roll-ups only (firewall blocks, client connect /
--     disconnect / roam, ISP quality, WAN flaps, device events, other),
--     with the OCSF class they map to. Counted EXACTLY ONCE: written in the
--     same transaction as the site's cursor.
--   unifi_signal_buckets — the coalescing ledger: the FIRST signal per
--     (site, kind, subject, clock hour) creates ONE alert (`event_id`); later
--     hits only count (`hits`). `pending_payload` is the outbox: the first
--     event's sanitised payload, held until its alert is stored (a crash
--     between the two writes finishes it on the next pass — never a lost or a
--     second alert), then cleared.
--   unifi_syslog_cursor — per site, the system log's restart-safe high-water
--     mark: the newest event time processed, the end of the last window read
--     whole, and the ids processed inside the re-read overlap (exactly once).
--     It lives in the tenant's OWN file: a site re-mapped to another tenant
--     starts fresh there, and nothing about one tenant is kept in another's.

-- @target: telemetry

CREATE TABLE IF NOT EXISTS unifi_hourly (
    hour            TEXT NOT NULL,              -- 'YYYY-MM-DDTHH:00:00Z' (UTC)
    scope           TEXT NOT NULL,              -- '<hostId>/<siteId>'
    kind            TEXT NOT NULL,              -- catalogue roll-up kind
    ocsf_class_uid  INTEGER NOT NULL DEFAULT 0,
    events          INTEGER NOT NULL DEFAULT 0 CHECK (events >= 0),
    last_arrival    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (hour, scope, kind)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_unifi_hourly_arrival ON unifi_hourly(last_arrival);
CREATE INDEX IF NOT EXISTS idx_unifi_hourly_scope ON unifi_hourly(scope, hour);

CREATE TABLE IF NOT EXISTS unifi_signal_buckets (
    bucket_key      TEXT PRIMARY KEY,           -- sha256(scope|kind|subject|hour)[:32]
    hour            TEXT NOT NULL,
    scope           TEXT NOT NULL,
    kind            TEXT NOT NULL,
    subject         TEXT NOT NULL DEFAULT '',
    event_id        INTEGER,                    -- events.db id of the ONE alert
    hits            INTEGER NOT NULL DEFAULT 1 CHECK (hits >= 1),
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    pending_payload TEXT,                       -- outbox until the alert is stored
    last_arrival    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_unifi_buckets_arrival ON unifi_signal_buckets(last_arrival);
CREATE INDEX IF NOT EXISTS idx_unifi_buckets_event ON unifi_signal_buckets(event_id);
CREATE INDEX IF NOT EXISTS idx_unifi_buckets_pending
    ON unifi_signal_buckets(scope) WHERE event_id IS NULL;

CREATE TABLE IF NOT EXISTS unifi_syslog_cursor (
    scope           TEXT PRIMARY KEY,
    hwm_ms          INTEGER NOT NULL CHECK (hwm_ms >= 0),
    scanned_to_ms   INTEGER NOT NULL CHECK (scanned_to_ms >= 0),
    recent_ids      TEXT NOT NULL DEFAULT '[]',
    updated_at      TEXT NOT NULL,
    last_arrival    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_unifi_cursor_arrival ON unifi_syslog_cursor(last_arrival);

PRAGMA user_version = 39;
