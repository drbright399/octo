-- Rollback migration 038.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 037's pattern):
--   * registry — every `mapping_review` notice is kept under
--     `operator_notices_rolled_back_038` (appended to on a second rollback),
--     then `operator_notices` is rebuilt with 035's kind constraint holding
--     every other row exactly as it was (ids, acknowledgements, e-mail
--     records). Code before 038 never writes or reads the new kind.
--     Re-applying 038 restores the kept notices whose recipient still exists.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_038
    AS SELECT * FROM operator_notices WHERE 0;
INSERT INTO operator_notices_rolled_back_038
    SELECT * FROM operator_notices WHERE kind = 'mapping_review';

CREATE TABLE IF NOT EXISTS operator_notices_037 (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard')),
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

INSERT INTO operator_notices_037 (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices
 WHERE kind IN ('single_attested_merge', 'single_attested_offboard');

DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_request;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_037 RENAME TO operator_notices;

CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);

PRAGMA user_version = 37;

COMMIT;
