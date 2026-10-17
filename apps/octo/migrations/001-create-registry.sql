-- Migration 001: create registry.db
-- Source of truth for client identity, tokens, operators, roles.
-- See spec §3.1 of octo-multi-tenancy-per-database.md v1.1.

PRAGMA user_version = 1;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS clients (
    slug                   TEXT PRIMARY KEY
                             CHECK (slug GLOB '[a-z0-9]*'
                                    AND slug NOT GLOB '*--*'
                                    AND slug NOT GLOB '*-'
                                    AND slug NOT GLOB '*[^a-z0-9-]*'),
    display_name           TEXT NOT NULL,
    tier                   TEXT NOT NULL DEFAULT 'standard'
                             CHECK (tier IN ('standard','premium')),
    contact_email          TEXT,
    notification_email     TEXT,
    notification_sla_hours INTEGER NOT NULL DEFAULT 24,
    compliance_flags       TEXT NOT NULL DEFAULT '[]',
    status                 TEXT NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active','disabled','offboarded','archived')),
    retention_days         INTEGER NOT NULL DEFAULT 365
                             CHECK (retention_days >= 30 AND retention_days <= 2555),
    onboarded_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    disabled_at            TEXT,
    offboarded_at          TEXT,
    archived_at            TEXT,
    notes                  TEXT,
    schema_version         INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);

CREATE TABLE IF NOT EXISTS clients_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT NOT NULL,
    changed_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    before_state  TEXT,
    after_state   TEXT,
    reason        TEXT,
    request_id    TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_history_slug       ON clients_history(slug);
CREATE INDEX IF NOT EXISTS idx_clients_history_changed_at ON clients_history(changed_at);

CREATE TABLE IF NOT EXISTS client_tokens (
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

CREATE INDEX IF NOT EXISTS idx_client_tokens_slug   ON client_tokens(slug);
CREATE INDEX IF NOT EXISTS idx_client_tokens_prefix ON client_tokens(token_prefix);
CREATE INDEX IF NOT EXISTS idx_client_tokens_live   ON client_tokens(slug, revoked_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS roles (
    name         TEXT PRIMARY KEY,
    description  TEXT NOT NULL,
    permissions  TEXT NOT NULL
);

INSERT OR IGNORE INTO roles (name, description, permissions) VALUES
    ('admin', 'Full access to all clients and operations',
     '["client:*","indicator:*","event:read","audit:read","pattern:read","token:*","migration:*"]');

CREATE TABLE IF NOT EXISTS operators (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT NOT NULL UNIQUE,
    email                 TEXT NOT NULL UNIQUE,
    token_hash            TEXT NOT NULL UNIQUE,
    token_prefix          TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    disabled_at           TEXT,
    mfa_enabled           INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0,1)),
    mfa_secret_enc        TEXT,
    mfa_backup_codes_enc  TEXT,
    last_mfa_verified_at  TEXT,
    mfa_required_at       TEXT
);

CREATE TABLE IF NOT EXISTS operator_roles (
    operator_id   INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    role_name     TEXT NOT NULL REFERENCES roles(name) ON DELETE RESTRICT,
    scope_slugs   TEXT NOT NULL DEFAULT '["*"]',
    granted_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (operator_id, role_name)
);

-- Scheduled purges — watched by octo-archive-gc.timer
CREATE TABLE IF NOT EXISTS scheduled_purges (
    slug                  TEXT PRIMARY KEY,
    scheduled_purge_at    TEXT NOT NULL,
    scheduled_by          TEXT NOT NULL,
    scheduled_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    reason                TEXT NOT NULL
);
