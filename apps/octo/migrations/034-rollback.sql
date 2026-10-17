-- Rollback migration 034.
--
-- Nothing is destroyed by a downgrade:
--   * tenant_compliance_signoffs — every row (live, expired, revoked) is kept
--     under `tenant_compliance_signoffs_rolled_back_034` (appended to if that
--     exists already), then the table goes. Re-applying 034 starts an EMPTY
--     sign-off table: every 'cloud' tenant that needs a sign-off runs as
--     'local' until a super_admin signs again — fail closed, never a
--     sign-off resurrected without a human (its ids continue after these).
--   * tenant_change_requests — the v0.10 columns' values are kept by request
--     id under `tenant_change_requests_rolled_back_034`, then the columns are
--     dropped (the rows themselves stay, in the 033 shape). Re-applying 034
--     restores them from there.
--   Every archived row carries the rollback's `rolled_back_generation` (1, 2,
--   … — one per rollback of this migration) and `rolled_back_at`: a second
--   rollback appends a second generation, never an unlabelled duplicate.
--   * clients — the confirmed-needs-a-kind triggers go. Rows 034 moved back
--     to 'pending' stay pending: that is the state v0.9 code handles, and a
--     human confirming them with a kind is what was asked for anyway.
--   * clients_history — recreated EMPTY in its 001 shape (it held no rows:
--     034 refused to drop a non-empty one).

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

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

DROP TRIGGER IF EXISTS clients_confirmed_needs_kind_update;
DROP TRIGGER IF EXISTS clients_confirmed_needs_kind_insert;

-- The archives (034 creates them too; this shape is 034's).
CREATE TABLE IF NOT EXISTS tenant_change_requests_rolled_back_034 (
    id INTEGER, request_id TEXT, kind TEXT, subject_slug TEXT, target_slug TEXT,
    approval_mode TEXT, attestation TEXT, subject_confirmation TEXT, post_review_state TEXT,
    post_reviewed_by INTEGER, post_reviewed_at TEXT, post_review_note TEXT,
    rolled_back_generation INTEGER NOT NULL, rolled_back_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_compliance_signoffs_rolled_back_034 (
    id INTEGER, slug TEXT, policy TEXT, flags_covered TEXT, baa_reference TEXT,
    attestation_text TEXT, attestation_sha256 TEXT, attestation_version TEXT,
    signed_by INTEGER, signed_at TEXT, expires_at TEXT, revoked_at TEXT, revoked_by INTEGER,
    revoked_kind TEXT, revoke_reason TEXT, request_id TEXT,
    rolled_back_generation INTEGER NOT NULL, rolled_back_at TEXT NOT NULL
);
CREATE TEMP TABLE m034_rollback_generation AS
SELECT COALESCE(MAX(g), 0) + 1 AS generation,
       strftime('%Y-%m-%dT%H:%M:%fZ','now') AS at
  FROM (SELECT MAX(rolled_back_generation) AS g FROM tenant_change_requests_rolled_back_034
        UNION ALL
        SELECT MAX(rolled_back_generation) FROM tenant_compliance_signoffs_rolled_back_034);

INSERT INTO tenant_change_requests_rolled_back_034 (
    id, request_id, kind, subject_slug, target_slug, approval_mode, attestation,
    subject_confirmation, post_review_state, post_reviewed_by, post_reviewed_at,
    post_review_note, rolled_back_generation, rolled_back_at)
    SELECT r.id, r.request_id, r.kind, r.subject_slug, r.target_slug, r.approval_mode,
           r.attestation, r.subject_confirmation, r.post_review_state, r.post_reviewed_by,
           r.post_reviewed_at, r.post_review_note, g.generation, g.at
      FROM tenant_change_requests r, m034_rollback_generation g;
ALTER TABLE tenant_change_requests DROP COLUMN post_review_note;
ALTER TABLE tenant_change_requests DROP COLUMN post_reviewed_at;
ALTER TABLE tenant_change_requests DROP COLUMN post_reviewed_by;
ALTER TABLE tenant_change_requests DROP COLUMN post_review_state;
ALTER TABLE tenant_change_requests DROP COLUMN subject_confirmation;
ALTER TABLE tenant_change_requests DROP COLUMN attestation;
ALTER TABLE tenant_change_requests DROP COLUMN approval_mode;

DROP TRIGGER IF EXISTS tenant_compliance_signoffs_revoke_once;
DROP TRIGGER IF EXISTS tenant_compliance_signoffs_no_delete;
DROP INDEX IF EXISTS idx_compliance_signoffs_slug;
DROP INDEX IF EXISTS idx_compliance_signoffs_one_unrevoked;
INSERT INTO tenant_compliance_signoffs_rolled_back_034 (
    id, slug, policy, flags_covered, baa_reference, attestation_text, attestation_sha256,
    attestation_version, signed_by, signed_at, expires_at, revoked_at, revoked_by,
    revoked_kind, revoke_reason, request_id, rolled_back_generation, rolled_back_at)
    SELECT s.id, s.slug, s.policy, s.flags_covered, s.baa_reference, s.attestation_text,
           s.attestation_sha256, s.attestation_version, s.signed_by, s.signed_at,
           s.expires_at, s.revoked_at, s.revoked_by, s.revoked_kind, s.revoke_reason,
           s.request_id, g.generation, g.at
      FROM tenant_compliance_signoffs s, m034_rollback_generation g;
DROP TABLE IF EXISTS tenant_compliance_signoffs;
DROP TABLE m034_rollback_generation;

PRAGMA user_version = 33;

COMMIT;
