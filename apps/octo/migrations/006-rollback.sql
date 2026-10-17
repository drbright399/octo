-- ============================================================================
-- Migration 006 — rollback: restore the original CHECK constraint
-- (drops password-reset rows since they wouldn't satisfy the old constraint).
-- ============================================================================

-- @target: registry

PRAGMA foreign_keys = OFF;

DELETE FROM magic_link_tokens WHERE purpose = 'password-reset';

CREATE TABLE magic_link_tokens_v5 (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash   TEXT UNIQUE NOT NULL,
    operator_id  INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    purpose      TEXT NOT NULL
                   CHECK (purpose IN ('initial-setup','re-auth','passkey-recovery')),
    used_at      TEXT
);

INSERT INTO magic_link_tokens_v5
    (id, token_hash, operator_id, issued_at, expires_at, purpose, used_at)
SELECT
    id, token_hash, operator_id, issued_at, expires_at, purpose, used_at
FROM magic_link_tokens;

DROP INDEX IF EXISTS idx_magic_link_unused;
DROP TABLE magic_link_tokens;
ALTER TABLE magic_link_tokens_v5 RENAME TO magic_link_tokens;

CREATE INDEX IF NOT EXISTS idx_magic_link_unused
    ON magic_link_tokens(token_hash, expires_at) WHERE used_at IS NULL;

PRAGMA foreign_keys = ON;
PRAGMA user_version = 5;
