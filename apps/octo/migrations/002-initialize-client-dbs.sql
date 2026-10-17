-- Migration 002: per-client DB initialization.
-- Applied ONCE per client DB triple: indicators.db, events.db, audit.db.
-- The migration runner selects the right statements for each target DB
-- based on --target flag (indicators|events|audit). Statements are grouped
-- below with "-- @target:" markers the runner parses.

PRAGMA user_version = 2;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: indicators

CREATE TABLE IF NOT EXISTS indicators (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    value          TEXT NOT NULL,
    type           TEXT NOT NULL
                     CHECK (type IN ('ip','ipv6','domain','url','md5','sha1','sha256','email','cidr','cve','other')),
    source         TEXT NOT NULL,
    severity       TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    confidence     REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    context        TEXT,
    first_seen     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    hits           INTEGER NOT NULL DEFAULT 1,
    deleted_at     TEXT,
    deleted_by     TEXT,
    delete_reason  TEXT,
    promoted_at    TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_value_type
    ON indicators(value, type) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_indicators_severity
    ON indicators(severity) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_indicators_last_seen ON indicators(last_seen);
CREATE INDEX IF NOT EXISTS idx_indicators_promoted
    ON indicators(promoted_at) WHERE promoted_at IS NOT NULL;

-- @target: events

CREATE TABLE IF NOT EXISTS events (
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

CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_relay_pending
    ON events(relay_status, received_at) WHERE relay_status = 'pending';
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, received_at);
-- Lookup index for the ingest sink's idempotency guard
-- (source, payload_sha256, received_at). Deliberately NOT unique: an identical
-- payload at a different vendor timestamp is a distinct event. Older DBs get
-- it lazily from SqliteIngestSink on first write.
CREATE INDEX IF NOT EXISTS idx_events_payload_sha256 ON events(payload_sha256);

CREATE TABLE IF NOT EXISTS sensitive_data_guard_hits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    category      TEXT NOT NULL CHECK (category IN ('PHI','PCI','CJI','PII','CREDENTIAL','OTHER')),
    field_path    TEXT NOT NULL,
    raw_sha256    TEXT NOT NULL,
    action        TEXT NOT NULL CHECK (action IN ('scrubbed','rejected')),
    source        TEXT NOT NULL,
    request_id    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sdgh_detected ON sensitive_data_guard_hits(detected_at);
CREATE INDEX IF NOT EXISTS idx_sdgh_category
    ON sensitive_data_guard_hits(category, detected_at);

CREATE TABLE IF NOT EXISTS incidents (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    severity              TEXT NOT NULL CHECK (severity IN ('high','critical')),
    indicator_ids         TEXT NOT NULL,
    event_ids             TEXT NOT NULL,
    summary               TEXT NOT NULL,
    evidence_refs         TEXT NOT NULL,
    compliance_frameworks TEXT,
    status                TEXT NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','acknowledged','notified',
                                              'investigating','closed','false_positive')),
    notification_sent_at  TEXT,
    notification_channels TEXT,
    notification_receipt  TEXT,
    acknowledged_by       TEXT,
    acknowledged_at       TEXT,
    assigned_to           TEXT,
    closed_by             TEXT,
    closed_at             TEXT,
    close_reason          TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status, detected_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, detected_at);

-- @target: audit

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor          TEXT NOT NULL,
    actor_kind     TEXT NOT NULL CHECK (actor_kind IN ('human','service','system')),
    action         TEXT NOT NULL,
    target_kind    TEXT NOT NULL,
    target_id      TEXT,
    before_state   TEXT,
    after_state    TEXT,
    reason         TEXT,
    request_id     TEXT NOT NULL,
    client_slug    TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    row_hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor, ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_kind, target_id);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(FAIL,'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(FAIL,'audit_log is append-only'); END;
