-- Migration 003: global/patterns.db + global/audit.db initialization.
-- See spec §3.5 for sanitization rules; patterns.db is written exclusively
-- through the validated enrichment pipeline.

PRAGMA user_version = 3;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- @target: patterns

CREATE TABLE IF NOT EXISTS patterns (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type           TEXT NOT NULL
                         CHECK (ioc_type IN ('ip','ipv6','domain','url','md5','sha1','sha256','email','cidr','other')),
    ioc_value          TEXT NOT NULL,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    tlp                TEXT NOT NULL DEFAULT 'amber'
                         CHECK (tlp IN ('red','amber','green','white')),
    client_hashes      TEXT NOT NULL,
    client_count       INTEGER NOT NULL CHECK (client_count >= 1),
    severity_max       TEXT NOT NULL CHECK (severity_max IN ('low','medium','high','critical')),
    confidence_avg     REAL NOT NULL CHECK (confidence_avg >= 0.0 AND confidence_avg <= 1.0),
    pepper_version     TEXT NOT NULL,
    promoted_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_patterns_ioc
    ON patterns(ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_patterns_severity
    ON patterns(severity_max);
CREATE INDEX IF NOT EXISTS idx_patterns_client_count
    ON patterns(client_count);

CREATE TABLE IF NOT EXISTS sanitization_rejects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rejected_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    source_slug     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    raw_excerpt     TEXT NOT NULL
);

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

CREATE INDEX IF NOT EXISTS idx_global_audit_ts     ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_global_audit_actor  ON audit_log(actor, ts);
CREATE INDEX IF NOT EXISTS idx_global_audit_action ON audit_log(action, ts);

CREATE TRIGGER IF NOT EXISTS global_audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(FAIL,'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS global_audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(FAIL,'audit_log is append-only'); END;
