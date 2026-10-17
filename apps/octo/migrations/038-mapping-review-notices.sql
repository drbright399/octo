-- Migration 038: the same-name fix (Phase 0 of the UniFi / entity build) —
-- operator notices of a new kind, `mapping_review`.
--
-- Until 2026-10-01 two paths could map a vendor site to a client by NAME
-- alone: the ingest path's auto-link (`tenant_autocreate`, match_source
-- 'auto') and the NextDNS panel's bulk "Use N suggestions" ('auto-name').
-- Both are closed in code: a name now only ever SUGGESTS. The rows they wrote
-- still route traffic, so every admin+ operator is told once, in-app, which
-- mappings were made that way and should be re-reviewed
-- (`apps.octo.instances.mapping_review`). `operator_notices.kind` is a CHECK
-- constraint (035), so the table is rebuilt with the new kind; every row,
-- id, acknowledgement and e-mail record is copied as it is.
--
--   kind 'mapping_review'   actor_id 0 (the platform), subject_slug 'global',
--                           change_request_id NULL, request_id
--                           'mapping-review:<digest of the listed mappings>'.
--
-- Nothing else changes; no other table references operator_notices.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS operator_notices_038 (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard',
                                          'mapping_review')),
    actor_id            INTEGER NOT NULL,
    subject_slug        TEXT NOT NULL,
    target_slug         TEXT,
    change_request_id   INTEGER REFERENCES tenant_change_requests(id) ON DELETE SET NULL,
    title               TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    body                TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    acknowledged_at     TEXT,
    email_state         TEXT NOT NULL DEFAULT 'pending'
                          CHECK (email_state IN
                            ('pending','sent','failed','not_configured','no_address')),
    email_attempted_at  TEXT,
    request_id          TEXT NOT NULL,
    UNIQUE (recipient_id, change_request_id)
);

INSERT INTO operator_notices_038 (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices;

DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_038 RENAME TO operator_notices;

CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);
-- A mapping-review notice is created once per (recipient, digest).
CREATE INDEX IF NOT EXISTS idx_operator_notices_request
    ON operator_notices(kind, request_id, recipient_id);

-- A re-upgrade takes back what a rollback kept (037's pattern): the
-- mapping-review notices a downgrade set aside come back for recipients
-- that still exist. Created empty on a first upgrade (one code path).
CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_038
    AS SELECT * FROM operator_notices WHERE 0;
INSERT OR IGNORE INTO operator_notices (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT k.id, k.recipient_id, k.kind, k.actor_id, k.subject_slug, k.target_slug, NULL,
       k.title, k.body, k.created_at, k.acknowledged_at, k.email_state,
       k.email_attempted_at, k.request_id
  FROM operator_notices_rolled_back_038 k
 WHERE k.kind = 'mapping_review'
   AND k.recipient_id IN (SELECT id FROM operators)
   AND k.rowid = (SELECT MAX(q.rowid) FROM operator_notices_rolled_back_038 q
                   WHERE q.id = k.id);

PRAGMA user_version = 38;

COMMIT;
