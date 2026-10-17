-- Migration 034: v0.10 — compliance sign-off before cloud AI, the attested
-- single-person merge columns, "confirmed needs a kind" as a schema rule, and
-- the never-used clients_history table dropped. ONE migration carries all of
-- v0.10's schema; the whole registry section is one transaction.
--
-- (1) tenant_compliance_signoffs — APPEND-ONLY record of a super_admin
--     signing, under the MSP's BAA, that a tenant's data may go to a CLOUD
--     model. `clients.ai_policy = 'cloud'` stays the stored intent; it is
--     HONOURED only while a live sign-off (not revoked, not expired) covers
--     EXACTLY the tenant's current compliance flags — otherwise the tenant
--     runs as 'local' (`instances.ai_policy.effective_ai_policy`). Flags
--     '["none"]' ("we checked, no regime applies") need no sign-off; '[]'
--     ("never tagged") does — fail closed.
--       flags_covered        canonical JSON list (sorted, unique) signed for.
--       baa_reference        the agreements the sign-off names: a JSON object,
--                            one reference per regime covered ({"hipaa":
--                            "<BAA ref>", "cjis": "<Security Addendum ref>"},
--                            or {"untagged": "<DPA ref>"} for a tenant never
--                            tagged) — a BAA is HIPAA's instrument, not
--                            CJIS's or BIPA's (`instances.ai_policy`).
--       attestation_text     the operator's typed attestation, exact; its
--       attestation_sha256   sha256, and the version of the attestation
--       attestation_version  template the console showed them.
--       expires_at           signed_at + the term (default 12 months — the
--                            annual cycle BAAs and HIPAA risk evaluations
--                            already follow, so a sign-off can never outlive
--                            the review that justified it by more than a
--                            year; the API offers 1–12). NULL = no expiry;
--                            the API never writes it.
--       revoked_*            set ONCE, by an operator ('operator'), by a
--                            flag change ('flags_changed'), by a merge that
--                            added flags to the tenant ('merge_added_flags'),
--                            or by a newer sign-off ('superseded').
--     Triggers: no DELETE, and no UPDATE except revoking a not-yet-revoked
--     row (every other column unchanged). At most ONE unrevoked row per
--     tenant (partial unique index) — signing again supersedes. Re-applied
--     after this migration's rollback, the table starts EMPTY (no sign-off
--     comes back without a human) but its ids continue after the archived
--     ones: a new sign-off never reuses an id the archive or the audit chain
--     already names.
--
-- (2) tenant_change_requests gains the columns the attested single-person
--     merge (v0.10 item 7) records: approval_mode ('two_person' — the
--     default — or 'single_attested'), the typed attestation, the subject
--     slug as the operator typed it server-side, and an optional post-hoc
--     review by a second person. Re-applied after this migration's
--     rollback, each record gets back the values the rollback archived for
--     it (its latest generation): a single-person change is never
--     relabelled two-person.
--
-- (3) clients: a CONFIRMED tenant has a real kind. Rows inserted by bare SQL
--     took migration 033's column defaults (confirmed + unclassified); they
--     go back to 'pending' for a human to tag, then BEFORE INSERT / UPDATE
--     triggers refuse the combination for good. Triggers, not a CHECK: SQLite
--     cannot add a CHECK by ALTER, and rebuilding `clients` (referenced by
--     client_tokens / source_instances foreign keys, its columns spread over
--     two migrations) is a risk this rule does not need — a trigger enforces
--     the same predicate on every insert and update, and leaves every row,
--     rowid and foreign key exactly where it was.
--
-- (4) clients_history (migration 001) was never written — tenant lifecycle
--     history is the global audit chain. Dropped; a non-empty table stops
--     the migration (rolled back whole) rather than lose a row.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

-- (1) --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_compliance_signoffs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    slug                 TEXT NOT NULL,
    policy               TEXT NOT NULL DEFAULT 'cloud' CHECK (policy IN ('cloud')),
    flags_covered        TEXT NOT NULL CHECK (flags_covered GLOB '[[]*[]]'),
    baa_reference        TEXT NOT NULL
                           CHECK (length(trim(baa_reference)) BETWEEN 1 AND 1000),
    attestation_text     TEXT NOT NULL
                           CHECK (length(attestation_text) BETWEEN 40 AND 2000),
    attestation_sha256   TEXT NOT NULL
                           CHECK (length(attestation_sha256) = 64
                                  AND attestation_sha256 NOT GLOB '*[^0-9a-f]*'),
    attestation_version  TEXT NOT NULL
                           CHECK (length(attestation_version) BETWEEN 1 AND 64),
    signed_by            INTEGER NOT NULL,
    signed_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at           TEXT CHECK (expires_at IS NULL OR expires_at > signed_at),
    revoked_at           TEXT,
    revoked_by           INTEGER,
    revoked_kind         TEXT CHECK (revoked_kind IN
                           ('operator','flags_changed','merge_added_flags','superseded')),
    revoke_reason        TEXT CHECK (revoke_reason IS NULL
                                     OR length(revoke_reason) BETWEEN 1 AND 500),
    -- The audit row that recorded the signing carries the same id.
    request_id           TEXT NOT NULL,
    -- Revocation is all four fields at once, or none.
    CHECK ((revoked_at IS NULL AND revoked_by IS NULL AND revoked_kind IS NULL
            AND revoke_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL
            AND revoked_kind IS NOT NULL AND revoke_reason IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_signoffs_one_unrevoked
    ON tenant_compliance_signoffs(slug) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_compliance_signoffs_slug
    ON tenant_compliance_signoffs(slug, id);

CREATE TRIGGER IF NOT EXISTS tenant_compliance_signoffs_no_delete
    BEFORE DELETE ON tenant_compliance_signoffs
BEGIN
    SELECT RAISE(ABORT, 'tenant_compliance_signoffs is append-only');
END;

CREATE TRIGGER IF NOT EXISTS tenant_compliance_signoffs_revoke_once
    BEFORE UPDATE ON tenant_compliance_signoffs
    WHEN OLD.revoked_at IS NOT NULL
      OR NEW.revoked_at IS NULL
      OR NEW.id IS NOT OLD.id
      OR NEW.slug IS NOT OLD.slug
      OR NEW.policy IS NOT OLD.policy
      OR NEW.flags_covered IS NOT OLD.flags_covered
      OR NEW.baa_reference IS NOT OLD.baa_reference
      OR NEW.attestation_text IS NOT OLD.attestation_text
      OR NEW.attestation_sha256 IS NOT OLD.attestation_sha256
      OR NEW.attestation_version IS NOT OLD.attestation_version
      OR NEW.signed_by IS NOT OLD.signed_by
      OR NEW.signed_at IS NOT OLD.signed_at
      OR NEW.expires_at IS NOT OLD.expires_at
      OR NEW.request_id IS NOT OLD.request_id
BEGIN
    SELECT RAISE(ABORT, 'tenant_compliance_signoffs is append-only: only an unrevoked row may be revoked, once');
END;

-- The rollback's archive, in the shape it appends to — created EMPTY when
-- absent so the id continuation below can read it unconditionally.
CREATE TABLE IF NOT EXISTS tenant_compliance_signoffs_rolled_back_034 (
    id INTEGER, slug TEXT, policy TEXT, flags_covered TEXT, baa_reference TEXT,
    attestation_text TEXT, attestation_sha256 TEXT, attestation_version TEXT,
    signed_by INTEGER, signed_at TEXT, expires_at TEXT, revoked_at TEXT, revoked_by INTEGER,
    revoked_kind TEXT, revoke_reason TEXT, request_id TEXT,
    rolled_back_generation INTEGER NOT NULL, rolled_back_at TEXT NOT NULL
);
INSERT INTO sqlite_sequence (name, seq)
SELECT 'tenant_compliance_signoffs', m
  FROM (SELECT MAX(id) AS m FROM tenant_compliance_signoffs_rolled_back_034)
 WHERE m IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'tenant_compliance_signoffs');

-- (2) --------------------------------------------------------------------

ALTER TABLE tenant_change_requests ADD COLUMN approval_mode TEXT NOT NULL
    DEFAULT 'two_person' CHECK (approval_mode IN ('two_person','single_attested'));
ALTER TABLE tenant_change_requests ADD COLUMN attestation TEXT;
ALTER TABLE tenant_change_requests ADD COLUMN subject_confirmation TEXT;
ALTER TABLE tenant_change_requests ADD COLUMN post_review_state TEXT NOT NULL
    DEFAULT 'not_requested'
    CHECK (post_review_state IN ('not_requested','pending','reviewed_ok','reviewed_concern'));
ALTER TABLE tenant_change_requests ADD COLUMN post_reviewed_by INTEGER;
ALTER TABLE tenant_change_requests ADD COLUMN post_reviewed_at TEXT;
ALTER TABLE tenant_change_requests ADD COLUMN post_review_note TEXT;

CREATE TABLE IF NOT EXISTS tenant_change_requests_rolled_back_034 (
    id INTEGER, request_id TEXT, kind TEXT, subject_slug TEXT, target_slug TEXT,
    approval_mode TEXT, attestation TEXT, subject_confirmation TEXT, post_review_state TEXT,
    post_reviewed_by INTEGER, post_reviewed_at TEXT, post_review_note TEXT,
    rolled_back_generation INTEGER NOT NULL, rolled_back_at TEXT NOT NULL
);
UPDATE tenant_change_requests
   SET approval_mode = a.approval_mode, attestation = a.attestation,
       subject_confirmation = a.subject_confirmation, post_review_state = a.post_review_state,
       post_reviewed_by = a.post_reviewed_by, post_reviewed_at = a.post_reviewed_at,
       post_review_note = a.post_review_note
  FROM (SELECT x.* FROM tenant_change_requests_rolled_back_034 x
         WHERE x.rolled_back_generation = (
               SELECT MAX(y.rolled_back_generation) FROM tenant_change_requests_rolled_back_034 y
                WHERE y.id = x.id AND y.request_id = x.request_id)) AS a
 WHERE a.id = tenant_change_requests.id AND a.request_id = tenant_change_requests.request_id;

-- (3) --------------------------------------------------------------------

UPDATE clients SET review_state = 'pending'
 WHERE review_state = 'confirmed' AND kind = 'unclassified';

CREATE TRIGGER IF NOT EXISTS clients_confirmed_needs_kind_insert
    BEFORE INSERT ON clients
    WHEN NEW.review_state = 'confirmed' AND NEW.kind = 'unclassified'
BEGIN
    SELECT RAISE(ABORT, 'clients: a confirmed tenant needs a kind other than unclassified');
END;

CREATE TRIGGER IF NOT EXISTS clients_confirmed_needs_kind_update
    BEFORE UPDATE ON clients
    WHEN NEW.review_state = 'confirmed' AND NEW.kind = 'unclassified'
BEGIN
    SELECT RAISE(ABORT, 'clients: a confirmed tenant needs a kind other than unclassified');
END;

-- (4) --------------------------------------------------------------------

CREATE TEMP TABLE m034_clients_history_guard (
    rows INTEGER NOT NULL CONSTRAINT clients_history_must_be_empty CHECK (rows = 0)
);
INSERT INTO m034_clients_history_guard SELECT COUNT(*) FROM clients_history;
DROP TABLE m034_clients_history_guard;
DROP INDEX IF EXISTS idx_clients_history_slug;
DROP INDEX IF EXISTS idx_clients_history_changed_at;
DROP TABLE IF EXISTS clients_history;

PRAGMA user_version = 34;

COMMIT;
