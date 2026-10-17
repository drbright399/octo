-- Rollback migration 040.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 037 / 038's pattern):
--   * registry — each tenant's entity_resolution switch is kept in
--     `clients_entity_resolution_rolled_back_040`, then the column is dropped;
--     the known-benign rules are kept in `known_benign_rules_rolled_back_040`,
--     then the table goes; every `entity_review` notice is kept in
--     `operator_notices_rolled_back_040` and the table is rebuilt with 038's
--     kind constraint holding every other row exactly as it was. The entity
--     retention classes are removed from bundle_config_retention (a
--     super_admin's edit of them comes back as the seed value). Code before
--     040 never reads any of it. Re-applying 040 restores the kept switches,
--     rules and notices — and empties what it kept (those rows are spent: a
--     second rollback keeps the state of THEN, never older rows).
--   * entities — entities.db files are LEFT AS THEY ARE (the design's
--     choice: with the switch gone, nothing reads them; a re-upgrade finds
--     them current). The section only records the downgrade.

PRAGMA foreign_keys = ON;

-- @target: entities

PRAGMA user_version = 40;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS clients_entity_resolution_rolled_back_040 (
    slug TEXT NOT NULL, entity_resolution TEXT NOT NULL);
-- EVERY tenant's switch, 'off' included: a re-upgrade restores exactly the
-- state of the rollback (a switch turned off in between stays off).
INSERT INTO clients_entity_resolution_rolled_back_040 (slug, entity_resolution)
SELECT slug, entity_resolution FROM clients;
ALTER TABLE clients DROP COLUMN entity_resolution;

CREATE TABLE IF NOT EXISTS known_benign_rules_rolled_back_040
    AS SELECT * FROM known_benign_rules WHERE 0;
INSERT INTO known_benign_rules_rolled_back_040 SELECT * FROM known_benign_rules;
DROP TABLE IF EXISTS known_benign_rules;

DELETE FROM bundle_config_retention
 WHERE data_class IN ('entity_lookup_lease', 'entity_lookup_egress', 'entity_resolution',
                      'entity_links', 'entity_inventory');

CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_040
    AS SELECT * FROM operator_notices WHERE 0;
INSERT INTO operator_notices_rolled_back_040
    SELECT * FROM operator_notices WHERE kind = 'entity_review';

CREATE TABLE IF NOT EXISTS operator_notices_038r (
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
INSERT INTO operator_notices_038r (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices
 WHERE kind IN ('single_attested_merge', 'single_attested_offboard', 'mapping_review');
DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_request;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_038r RENAME TO operator_notices;
CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);
CREATE INDEX IF NOT EXISTS idx_operator_notices_request
    ON operator_notices(kind, request_id, recipient_id);

PRAGMA user_version = 38;

COMMIT;
