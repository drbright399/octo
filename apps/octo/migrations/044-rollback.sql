-- Rollback migration 044.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 040 / 043's pattern):
--   * registry — every threat notice is kept under
--     `operator_notices_rolled_back_044` (appended to on a second rollback)
--     and `operator_notices` is rebuilt with 040's kind constraint, every
--     other row exactly as it was. The new tables (asset tags, the
--     registries, tier settings, brakes, the worker's state) are LEFT AS
--     THEY ARE: nothing before 044 reads them, and a re-upgrade finds them
--     current (040's choice for entities.db). The version goes back to 43.
--   * events (each tenant's events.db that has the 044 columns) — the
--     threat columns of every incident are kept as JSON under
--     `incidents_threat_rolled_back_044` (by id), then the 044 triggers and
--     indexes go and so do the columns (`incidents` is 002's again; no
--     incident row is removed). incident_events / incident_notes /
--     incident_decisions / incident_signals / threat_fact /
--     threat_would_fire stay as they are (nothing before 044 reads them; the
--     retention job before 044 does not know incident_events — the
--     incidents' own `event_ids` still hold their events). The
--     `athena.incident` lifecycle events are moved aside (with their ids)
--     into `events_athena_rolled_back_044`: a release before 044 does not
--     know them as Athena's own and would let a client user's search return
--     them. The evidence windows are moved aside (with their ids) into
--     `evidence_windows_rolled_back_044`. Re-applying 044's events section
--     restores the columns of every kept id and puts those events and
--     windows back. CAVEAT: a release before 044 does not honour evidence
--     windows — its nightly retention prunes by the clock alone.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_044
    AS SELECT * FROM operator_notices WHERE 0;
INSERT INTO operator_notices_rolled_back_044
    SELECT * FROM operator_notices WHERE kind LIKE 'threat\_%' ESCAPE '\';

CREATE TABLE IF NOT EXISTS operator_notices_040r (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard',
                                          'mapping_review','entity_review')),
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
INSERT INTO operator_notices_040r (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices
 WHERE kind IN ('single_attested_merge', 'single_attested_offboard', 'mapping_review',
                'entity_review');
DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_request;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_040r RENAME TO operator_notices;
CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);
CREATE INDEX IF NOT EXISTS idx_operator_notices_request
    ON operator_notices(kind, request_id, recipient_id);

PRAGMA user_version = 43;

COMMIT;

-- @target: events

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS incidents_threat_rolled_back_044 (
    id   INTEGER NOT NULL,
    row  TEXT NOT NULL
);
INSERT INTO incidents_threat_rolled_back_044 (id, row)
SELECT id, json_object(
    'tier', tier, 'rule_id', rule_id, 'rule_version', rule_version,
    'dedupe_key', dedupe_key, 'site_key', site_key, 'device_ref', device_ref,
    'device_label', device_label, 'scope', scope, 'stages', stages,
    'last_evidence_at', last_evidence_at, 'escalation_step', escalation_step,
    'last_escalated_at', last_escalated_at, 'ladder_started_at', ladder_started_at,
    'contained_at', contained_at, 'contained_by', contained_by,
    'close_reason_code', close_reason_code, 'reclassified_from', reclassified_from,
    'reopened_count', reopened_count,
    'client_visible_at', client_visible_at, 'autonomy_mode_at_open', autonomy_mode_at_open,
    'snapshot_sha256', snapshot_sha256, 'opened_by', opened_by, 'open_reason', open_reason)
  FROM incidents;

-- The `athena.incident` lifecycle events go aside WITH THEIR IDS (a release
-- before 044 would hand them to a client user's search); a re-upgrade puts
-- them back.
CREATE TABLE IF NOT EXISTS events_athena_rolled_back_044 (
    id             INTEGER NOT NULL,
    received_at    TEXT NOT NULL,
    source         TEXT NOT NULL,
    source_host    TEXT,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    payload        TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    relay_status   TEXT NOT NULL
);
INSERT INTO events_athena_rolled_back_044 (id, received_at, source, source_host, event_type,
                                           severity, payload, payload_sha256, relay_status)
SELECT id, received_at, source, source_host, event_type, severity, payload, payload_sha256,
       relay_status
  FROM events WHERE source = 'athena' AND event_type = 'athena.incident';
DELETE FROM events WHERE source = 'athena' AND event_type = 'athena.incident';

-- The evidence windows go aside WITH THEIR IDS (the incident timeline
-- names them); a re-upgrade puts them back. The table goes (its triggers
-- name the incidents' 044 columns, which go below). A release before 044
-- never reads them — and does not honour them: its retention prunes by the
-- clock alone (`rollback_v017.py` names every window still held and
-- refuses while any is, unless told).
CREATE TABLE IF NOT EXISTS evidence_windows_rolled_back_044
    AS SELECT * FROM evidence_windows WHERE 0;
INSERT INTO evidence_windows_rolled_back_044 SELECT * FROM evidence_windows;
DROP TABLE evidence_windows;

-- SQLite refuses to drop a column a trigger or an index names.
DROP TRIGGER IF EXISTS incidents_no_delete;
DROP TRIGGER IF EXISTS incidents_frozen;
DROP TRIGGER IF EXISTS incidents_tier_no_lower;
DROP INDEX IF EXISTS ux_incidents_open_dedupe;
DROP INDEX IF EXISTS idx_incidents_tier;

ALTER TABLE incidents DROP COLUMN open_reason;
ALTER TABLE incidents DROP COLUMN opened_by;
ALTER TABLE incidents DROP COLUMN snapshot_sha256;
ALTER TABLE incidents DROP COLUMN autonomy_mode_at_open;
ALTER TABLE incidents DROP COLUMN client_visible_at;
ALTER TABLE incidents DROP COLUMN reopened_count;
ALTER TABLE incidents DROP COLUMN reclassified_from;
ALTER TABLE incidents DROP COLUMN close_reason_code;
ALTER TABLE incidents DROP COLUMN contained_by;
ALTER TABLE incidents DROP COLUMN contained_at;
ALTER TABLE incidents DROP COLUMN ladder_started_at;
ALTER TABLE incidents DROP COLUMN last_escalated_at;
ALTER TABLE incidents DROP COLUMN escalation_step;
ALTER TABLE incidents DROP COLUMN last_evidence_at;
ALTER TABLE incidents DROP COLUMN stages;
ALTER TABLE incidents DROP COLUMN scope;
ALTER TABLE incidents DROP COLUMN device_label;
ALTER TABLE incidents DROP COLUMN device_ref;
ALTER TABLE incidents DROP COLUMN site_key;
ALTER TABLE incidents DROP COLUMN dedupe_key;
ALTER TABLE incidents DROP COLUMN rule_version;
ALTER TABLE incidents DROP COLUMN rule_id;
ALTER TABLE incidents DROP COLUMN tier;

COMMIT;
