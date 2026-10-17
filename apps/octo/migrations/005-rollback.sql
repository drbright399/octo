-- Rollback for migration 005 (Athena auth core schema additions).
--
-- Order matters:
--   1. Drop tables that hold FK references TO operators (so the operators
--      rebuild below doesn't leave dangling references).
--   2. Remove the three new role rows. ON DELETE RESTRICT in operator_roles
--      means this fails if any live operator still holds super_admin /
--      analyst / viewer — that is the correct failure mode (the operator
--      doing the rollback must explicitly clean up role assignments first).
--   3. Rebuild operators without the new G.1 columns via the table-rename
--      strategy (portable across SQLite < 3.35; matches migration 004's
--      rollback shape). DROP TABLE does NOT cascade-delete from
--      operator_roles in SQLite — FK references are resolved at DML time,
--      not DDL time, so operator_roles rows survive the swap and the FK
--      target re-attaches when the renamed table takes the `operators`
--      name back.
--
-- This rollback is destructive of all G.1 auth state: passkey credentials,
-- live sessions, outstanding magic-link tokens, and backup-code-set history
-- are all dropped. The pre-G.1 snapshot (`registry-pre-G1.db` in the deploy
-- host's root home directory, per the corrections doc rollback table) is the
-- recovery source if you need any of that data back.

PRAGMA user_version = 4;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

-- ----------------------------------------------------------------------------
-- 1. Drop new tables (these have FK to operators).
-- ----------------------------------------------------------------------------

DROP INDEX IF EXISTS idx_backup_code_sets_active;
DROP TABLE IF EXISTS backup_code_sets;

DROP INDEX IF EXISTS idx_magic_link_unused;
DROP TABLE IF EXISTS magic_link_tokens;

DROP INDEX IF EXISTS idx_sessions_active;
DROP INDEX IF EXISTS idx_sessions_operator;
DROP TABLE IF EXISTS sessions;

DROP INDEX IF EXISTS idx_webauthn_operator;
DROP TABLE IF EXISTS webauthn_credentials;

-- ----------------------------------------------------------------------------
-- 2. Remove the three Athena Console roles.
-- ----------------------------------------------------------------------------

DELETE FROM roles WHERE name IN ('super_admin','analyst','viewer');

-- ----------------------------------------------------------------------------
-- 3. Rebuild operators without the G.1 columns.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS operators_pre_g1 (
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

INSERT INTO operators_pre_g1
    (id, username, email, token_hash, token_prefix, created_at, disabled_at,
     mfa_enabled, mfa_secret_enc, mfa_backup_codes_enc,
     last_mfa_verified_at, mfa_required_at)
SELECT id, username, email, token_hash, token_prefix, created_at, disabled_at,
       mfa_enabled, mfa_secret_enc, mfa_backup_codes_enc,
       last_mfa_verified_at, mfa_required_at
FROM operators;

DROP TABLE operators;
ALTER TABLE operators_pre_g1 RENAME TO operators;
