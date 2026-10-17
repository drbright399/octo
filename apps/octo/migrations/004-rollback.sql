-- Rollback for migration 004.
--
-- SQLite has no `DROP COLUMN` for `client_tokens.source_instance_id` or
-- `events.summary` before SQLite 3.35.0. Modern SQLite (3.35+) supports it,
-- but to keep this rollback portable we use the table-rename strategy:
--   1. CREATE the original-shape table
--   2. INSERT INTO new SELECT old-cols FROM old
--   3. DROP old; RENAME new
--
-- We don't bother dropping the indexes on the columns we're removing —
-- they go with the table rebuild.

-- @target: registry

DROP INDEX IF EXISTS idx_client_tokens_source_instance;
DROP INDEX IF EXISTS idx_source_instances_live;
DROP TABLE IF EXISTS source_instances;

-- Rebuild client_tokens without source_instance_id.
CREATE TABLE IF NOT EXISTS client_tokens_v3 (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT NOT NULL REFERENCES clients(slug) ON DELETE RESTRICT,
    token_hash    TEXT NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('buoy','service','admin')),
    label         TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_by    TEXT NOT NULL,
    revoked_at    TEXT,
    revoked_by    TEXT,
    last_used_at  TEXT,
    last_used_ip  TEXT
);

INSERT INTO client_tokens_v3
    (id, slug, token_hash, token_prefix, kind, label, created_at,
     created_by, revoked_at, revoked_by, last_used_at, last_used_ip)
SELECT id, slug, token_hash, token_prefix, kind, label, created_at,
       created_by, revoked_at, revoked_by, last_used_at, last_used_ip
FROM client_tokens;

DROP TABLE client_tokens;
ALTER TABLE client_tokens_v3 RENAME TO client_tokens;

CREATE INDEX IF NOT EXISTS idx_client_tokens_slug   ON client_tokens(slug);
CREATE INDEX IF NOT EXISTS idx_client_tokens_prefix ON client_tokens(token_prefix);
CREATE INDEX IF NOT EXISTS idx_client_tokens_live   ON client_tokens(slug, revoked_at)
    WHERE revoked_at IS NULL;

-- @target: events

DROP INDEX IF EXISTS idx_events_idempotency_key;
DROP INDEX IF EXISTS idx_events_summary;

-- Rebuild events without summary.
CREATE TABLE IF NOT EXISTS events_v3 (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source         TEXT NOT NULL,
    source_host    TEXT,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    payload        TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    relay_status   TEXT NOT NULL DEFAULT 'pending'
                     CHECK (relay_status IN ('pending','sent','failed','skipped')),
    relay_attempts INTEGER NOT NULL DEFAULT 0,
    relayed_at     TEXT,
    relay_response INTEGER
);

INSERT INTO events_v3
    (id, received_at, source, source_host, event_type, severity,
     payload, payload_sha256, relay_status, relay_attempts,
     relayed_at, relay_response)
SELECT id, received_at, source, source_host, event_type, severity,
       payload, payload_sha256, relay_status, relay_attempts,
       relayed_at, relay_response
FROM events;

DROP TABLE events;
ALTER TABLE events_v3 RENAME TO events;

CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_relay_pending
    ON events(relay_status, received_at) WHERE relay_status = 'pending';
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, received_at);

-- Reset user_version
PRAGMA user_version = 3;
