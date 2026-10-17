-- Rollback for migration 023 — sanitized-pool HMAC schema upgrade.
-- @target: patterns

-- SQLite doesn't natively support DROP COLUMN before 3.35; if the
-- target SQLite is older, this rollback fails fast. Modern SQLite
-- (3.35+) handles ALTER TABLE DROP COLUMN cleanly.

DROP INDEX IF EXISTS idx_sanitization_rejects_reason;

ALTER TABLE patterns DROP COLUMN tenant_hmacs;
ALTER TABLE patterns DROP COLUMN hmac_version;

ALTER TABLE sanitization_rejects DROP COLUMN source_tenant_hmac;
ALTER TABLE sanitization_rejects DROP COLUMN reason_code;
ALTER TABLE sanitization_rejects DROP COLUMN hmac_version;

PRAGMA user_version = 22;
