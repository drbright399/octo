-- Migration 005: Athena auth core schema additions.
--
-- Phase G.1. Adds Console-facing auth surface on top of the existing OCTO
-- bearer-token infrastructure. See PHASE-G1-AUTH-CORE-PROPOSAL.md and the
-- companion PHASE-G1-AUTH-CORE-PROPOSAL-CORRECTIONS.md for full design.
--
-- This migration only touches registry.db. No per-client events.db changes.
--
-- Adds:
--   1. New columns on `operators` for password/lockout posture + AI-access flag.
--   2. Three new rows in `roles` for Athena Console: super_admin, analyst,
--      viewer. (The existing `admin` role is preserved untouched — it gates
--      OCTO admin-API bearer-token access; the three new roles gate Athena
--      Console UI access via session middleware.)
--   3. `webauthn_credentials` — passkey storage, one row per registered
--      authenticator per operator.
--   4. `sessions` — issued on successful Console auth, revoked on
--      logout/expiry; both absolute and idle expiry tracked.
--   5. `magic_link_tokens` — single-use, short-lived initial-setup +
--      re-auth + passkey-recovery tokens. Hash-stored; plaintext returned
--      exactly once.
--   6. `backup_code_sets` — audit-trail design (option ii). Each
--      regenerate-codes event creates a new row; old set is revoked in the
--      same transaction. Full history queryable.
--
-- Idempotency: ALTER TABLE ADD COLUMN errors on second run in raw SQLite.
-- The migration runner probes for column existence and skips re-application;
-- re-running the file under the runner is a no-op. Direct `sqlite3 < file`
-- on the second run will fail at the first ADD COLUMN — that is the correct
-- failure mode.
--
-- The pre-existing `mfa_secret_enc`, `mfa_backup_codes_enc`,
-- `last_mfa_verified_at`, `mfa_required_at` columns on `operators` are
-- reused. `mfa_backup_codes_enc` is left in place but treated as legacy:
-- new code sources active backup codes from `backup_code_sets` where
-- `revoked_at IS NULL`. The legacy column may be dropped in a future
-- migration after a confirmed-no-references audit.

PRAGMA user_version = 5;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

-- ----------------------------------------------------------------------------
-- 1. Extend operators with password + login-posture + AI-access columns.
-- ----------------------------------------------------------------------------

ALTER TABLE operators ADD COLUMN password_hash TEXT;
ALTER TABLE operators ADD COLUMN password_changed_at TEXT;
ALTER TABLE operators ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0
    CHECK (must_change_password IN (0,1));
ALTER TABLE operators ADD COLUMN last_login_at TEXT;
ALTER TABLE operators ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators ADD COLUMN locked_until TEXT;
ALTER TABLE operators ADD COLUMN ai_access_enabled INTEGER NOT NULL DEFAULT 0
    CHECK (ai_access_enabled IN (0,1));
ALTER TABLE operators ADD COLUMN ai_access_expires_at TEXT;
ALTER TABLE operators ADD COLUMN ai_access_granted_by INTEGER REFERENCES operators(id) ON DELETE SET NULL;
ALTER TABLE operators ADD COLUMN ai_access_reason TEXT;

-- ----------------------------------------------------------------------------
-- 2. Seed three Athena Console roles.
--    Distinct from the existing 'admin' OCTO API role. An operator can hold
--    both (Rick + Zack will, post-bootstrap: 'admin' for CLI bearer-token use,
--    'super_admin' for Console UI use).
-- ----------------------------------------------------------------------------

INSERT OR IGNORE INTO roles (name, description, permissions) VALUES
    ('super_admin',
     'Athena Console full access; all tenants; all AI capabilities.',
     '["athena:*"]'),
    ('analyst',
     'Athena Console scoped access; tenant management within scope_slugs; AI engagement enabled by default.',
     '["athena:read","athena:write","athena:ai"]'),
    ('viewer',
     'Athena Console read-only within scope_slugs; AI engagement gated by ai_access_enabled flag.',
     '["athena:read"]');

-- ----------------------------------------------------------------------------
-- 3. WebAuthn credentials (passkeys).
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id   INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,        -- WebAuthn credential ID (binary)
    public_key    BLOB NOT NULL,               -- COSE-encoded public key
    sign_count    INTEGER NOT NULL DEFAULT 0,
    label         TEXT,                        -- "Rick's iPhone passkey", "Zack's YubiKey"
    transports    TEXT,                        -- JSON array, e.g. '["internal","usb","nfc","ble"]'
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_used_at  TEXT,
    revoked_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_webauthn_operator
    ON webauthn_credentials(operator_id, revoked_at);

-- ----------------------------------------------------------------------------
-- 4. Sessions.
--    24h absolute expiry from issue, 8h idle expiry from last activity.
--    auth_method = 'bootstrap' is reserved for the one-time bootstrap-key
--    flow that provisions the very first super_admin (no existing session
--    can authorize that creation).
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,                  -- 32-byte URL-safe random (cookie value)
    operator_id     INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    issued_at       TEXT NOT NULL,
    last_active_at  TEXT NOT NULL,
    expires_at      TEXT NOT NULL,                     -- absolute, 24h from issue
    idle_expires_at TEXT NOT NULL,                     -- rolling, 8h from last activity
    auth_method     TEXT NOT NULL
                      CHECK (auth_method IN ('password+totp','passkey','magic-link','bootstrap')),
    ip_address      TEXT,
    user_agent      TEXT,
    revoked_at      TEXT,
    revoked_by      INTEGER REFERENCES operators(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_operator
    ON sessions(operator_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_active
    ON sessions(expires_at) WHERE revoked_at IS NULL;

-- ----------------------------------------------------------------------------
-- 5. Magic-link tokens.
--    PBKDF2-hashed at storage; plaintext returned exactly once.
--    'initial-setup' = 24h, 're-auth' / 'passkey-recovery' = 15min.
--    Single-use enforced via `used_at` timestamp.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS magic_link_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash   TEXT UNIQUE NOT NULL,
    operator_id  INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    purpose      TEXT NOT NULL
                   CHECK (purpose IN ('initial-setup','re-auth','passkey-recovery')),
    used_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_magic_link_unused
    ON magic_link_tokens(token_hash, expires_at) WHERE used_at IS NULL;

-- ----------------------------------------------------------------------------
-- 6. Backup-code sets.
--    Per resolved §9-3: option (ii) audit-trail design. Each regenerate
--    creates a new row; old set's revoked_at is set in the same transaction.
--    Active set per operator is the row WHERE revoked_at IS NULL (uniqueness
--    enforced by application-layer, not at the DB level — codes_enc holds the
--    full set as encrypted JSON, individual codes are not separately rowed).
--
--    Codes are PBKDF2-hashed inside codes_enc (the JSON contains a list of
--    hashes alongside the encrypted plaintext-set blob) so that a single
--    code consumption can mark itself used without exposing the rest.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS backup_code_sets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id     INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    codes_enc       TEXT NOT NULL,                                       -- encrypted JSON (per-code hashes + plaintext-set)
    generated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    generated_by    INTEGER REFERENCES operators(id) ON DELETE SET NULL, -- self-rotate or admin-issue
    revoked_at      TEXT,
    revoked_by      INTEGER REFERENCES operators(id) ON DELETE SET NULL,
    revoke_reason   TEXT
                      CHECK (revoke_reason IS NULL
                             OR revoke_reason IN ('rotated','compromise','admin-revoke','operator-disabled'))
);

CREATE INDEX IF NOT EXISTS idx_backup_code_sets_active
    ON backup_code_sets(operator_id) WHERE revoked_at IS NULL;
