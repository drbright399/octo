-- Migration 023: sanitized-pool HMAC schema upgrade.
--
-- Migrates the pool from "peppered hash" identity to "HMAC-per-bundle"
-- identity per the M1-M9 safety envelope (see
-- docs/design/sanitized-pool/m1-m9-safety-envelope.md §3 — M2).
--
-- Why this migration:
--   - The 2026-05-20 external review found a vulnerability in the
--     "peppered hash" identity scheme: an operator who can inject a
--     known unique IOC into their own tenant can observe the resulting
--     hash and thereafter recognize that tenant's contributions
--     anywhere. HMAC-per-bundle with a server-held secret defeats
--     this — the operator can't compute hashes without the secret.
--
--   - The existing `sanitization_rejects.source_slug` column stores
--     the source-tenant slug in plaintext, which is a deanon-channel
--     for anyone with read access to the table. We add a parallel
--     `source_tenant_hmac` column so the extractor writes the HMAC
--     instead. The plaintext column stays nullable for backward
--     compat during the migration window; a later cleanup migration
--     drops it once the extractor consistently populates the HMAC
--     column.
--
-- Migration safety:
--   - All ALTER TABLE ADD COLUMN statements default to NULL on
--     existing rows. No backfill required for the pre-launch scaffold
--     (the extractor isn't yet running, so the pool tables are empty
--     in production). When the extractor IS running, a rotation
--     (M9) procedure handles re-extraction under the new identity.
--
--   - `pepper_version` stays on the patterns table for backward
--     compat. New writes set `hmac_version` instead. Cleanup migration
--     later drops the legacy column.

PRAGMA foreign_keys = ON;

-- @target: patterns

-- Add HMAC-based columns alongside the existing peppered-hash ones.
-- Existing scaffolded rows (if any) keep their `client_hashes` +
-- `pepper_version` values; new writes use the HMAC columns.
ALTER TABLE patterns ADD COLUMN tenant_hmacs TEXT;       -- JSON array of HMAC hex
ALTER TABLE patterns ADD COLUMN hmac_version TEXT;       -- e.g. "v1"

-- Replace `source_slug` on sanitization_rejects with `source_tenant_hmac`.
-- Both columns coexist during the transition; the API layer (M3 gate)
-- ensures only super_admin can read raw rows of either column, and
-- the read-side returns ONLY tenant_hmac to operators (no slug leak).
ALTER TABLE sanitization_rejects ADD COLUMN source_tenant_hmac TEXT;
ALTER TABLE sanitization_rejects ADD COLUMN reason_code TEXT;
ALTER TABLE sanitization_rejects ADD COLUMN hmac_version TEXT;

-- Add an index on reason_code for the aggregate-counts endpoint
-- (analyst+ surface; doesn't reveal per-tenant data).
CREATE INDEX IF NOT EXISTS idx_sanitization_rejects_reason
    ON sanitization_rejects(reason_code);

PRAGMA user_version = 23;
