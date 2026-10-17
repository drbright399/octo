-- Migration 044: TIER BLACK, slice 1 — incident records, the threat layer's
-- plumbing and the registries the tier rules read (v0.17; the design doc
-- calls these 043 / 044 — 043 is v0.16's proposals, so ONE migration with
-- both targets carries them).
--
-- Product rules the schema carries (design 2026-10-02, sections 2.1, 6.3,
-- 6.4 and Rick's section 9):
--   * Red and Black come ONLY from an `incidents` row (a rule or a person
--     opened it); only a person closes it; there is NO lower / mute /
--     snooze: a Black can never become a Red in place (`incidents_tier_no_
--     lower`), a record is never deleted (`incidents_no_delete`), what it
--     was opened on is frozen (`incidents_frozen`). "Close as reclassified"
--     closes the Black and opens a LINKED Red (`reclassified_from`).
--   * One OPEN incident per dedupe key (`ux_incidents_open_dedupe`); a
--     closed one is history, so the same key may open (or reopen) again.
--   * 911 / life-safety first: an analyst-set, audited asset tag
--     `life_safety` (registry `asset_tag`); every lockdown request carves
--     those assets and their paths out and says so (`incident_decisions.
--     excluded_json` + `notice`).
--   * Client (viewer) decisions on an incident — exactly two kinds,
--     'lockdown' and 'allow' — are RECORDED (who, when, what was excluded);
--     nothing in slice 1 executes a network change.
--
-- events section (clients/<slug>/events.db; a NEW tenant gets it at
-- provisioning, an existing events.db from `apps.octo.threat.store.
-- ensure_schema` on first use — the lazy-migration rule: every read path
-- probes for the `tier` column first):
--   incidents          + tier ('red' | 'black'), rule_id / rule_version, the
--                      dedupe key, where (site_key, device_ref / label,
--                      scope 'device' | 'site' | 'tenant'), stages (the
--                      timeline of tier changes, JSON), the paging ladder
--                      (escalation_step, last_escalated_at, ladder_started_
--                      at), containment, the close code, the reclassify
--                      link, reopen count, when a client user
--                      may see it (client_visible_at), the autonomy mode at
--                      open, who opened it and why, the evidence snapshot's
--                      sha256 (evidence_refs holds the frozen snapshot).
--   incident_events    incident ↔ event, role trigger / corroboration /
--                      context / action — the retention job keeps an event
--                      an incident cites (`retention.references`).
--   incident_signals   incident ↔ its `athena.incident` lifecycle events (OCSF
--                      2005, appended to `events` at every change — the
--                      immutable timeline; the retention job keeps them).
--   incident_notes     the human timeline: notes, ack, assign, contain,
--                      raise, close, reopen, decisions — never edited,
--                      never deleted.
--   incident_decisions a client's "lock down" / "allow" and an analyst's
--                      lockdown request — recorded only; `excluded_json`
--                      lists every life-safety asset / path carved out.
--   evidence_windows   Rick, 2026-10-05: a Red / Black is a confirmed threat
--                      — everything of the tenant from its first detection
--                      to its all-clear is EVIDENCE: kept by every
--                      retention path until an admin releases the window
--                      (ingestion never stops). Widened, never shrunk;
--                      released, never deleted. Replaces the tenant-wide
--                      legal hold.
--   threat_fact        one row per fact a rule evaluated (G11 fact key,
--                      unique) — the R6 password is NEVER stored (length +
--                      salted hash only).
--   threat_would_fire  what a SHADOW rule would have opened (never colours
--                      a pin).
--
-- registry section
--   asset_tag          (tenant, ref_kind device | path, ref, tag) — lab,
--                      evidence_hold, dev, kiosk, hands_off, server, dc,
--                      cjis, life_safety, patient_care, critical_24x7. A tag
--                      is CLEARED (who, when, why), never deleted.
--   remote_access_registry, ra_baseline, msp_roster, egress_set,
--   attribution_ledger, threat_exception (≤ 90 d), analyst_verdict
--                      (365 d), domain_intel, canary_scanner_allowlist —
--                      the facts later slices' rules read; slice 1 creates
--                      them and exposes the admin read / write the design
--                      lists for slice 1.
--   tier_settings      per-MSP ('msp') or per-tenant Yellow / Notice knobs,
--                      bounded in code — no setting can produce Red or Black.
--   rule_brake         the storm brake: one automated rule held at a Red
--                      ceiling for ≤ 24 h (super_admin, step-up, reason).
--   threat_worker_state the tier worker's heartbeat and per-tenant cursors.
--   operator_notices   + kinds threat_black, threat_red, threat_escalation,
--                      threat_coverage, threat_client, threat_registry
--                      (rebuilt, 038 / 040's precedent).
-- Every registry table above has a no-delete trigger.
--
-- A rollback keeps everything and a re-upgrade takes it back (036 / 040 /
-- 043's pattern): the new registry tables and the new events.db tables are
-- LEFT AS THEY ARE (nothing before 044 reads them — 040's choice for
-- entities.db); the threat notices, the incidents' new columns and the
-- evidence windows are kept aside and restored. (A release before 044
-- does not honour evidence windows: its retention prunes by the clock
-- alone — `scripts/rollback_v017.py` names every window still held and
-- refuses while any is, unless told.)

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS asset_tag (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug  TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    ref_kind     TEXT NOT NULL DEFAULT 'device' CHECK (ref_kind IN ('device', 'path')),
    device_ref   TEXT NOT NULL CHECK (length(device_ref) BETWEEN 1 AND 200),
    tag          TEXT NOT NULL CHECK (tag IN ('lab', 'evidence_hold', 'dev', 'kiosk',
                                               'hands_off', 'server', 'dc', 'cjis',
                                               'life_safety', 'patient_care',
                                               'critical_24x7')),
    set_by       INTEGER NOT NULL,
    set_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    reason       TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    cleared_by   INTEGER,
    cleared_at   TEXT,
    clear_reason TEXT CHECK (clear_reason IS NULL OR length(clear_reason) BETWEEN 3 AND 500),
    CHECK (cleared_at IS NULL OR (cleared_by IS NOT NULL AND clear_reason IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_tag_live
    ON asset_tag(tenant_slug, ref_kind, device_ref, tag) WHERE cleared_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_asset_tag_tenant ON asset_tag(tenant_slug, tag);
CREATE TRIGGER IF NOT EXISTS asset_tag_no_delete BEFORE DELETE ON asset_tag
BEGIN SELECT RAISE(ABORT, 'asset tags are cleared, never deleted'); END;
-- Only the clearing columns change, once.
CREATE TRIGGER IF NOT EXISTS asset_tag_only_cleared BEFORE UPDATE ON asset_tag
WHEN OLD.cleared_at IS NOT NULL
  OR NEW.tenant_slug IS NOT OLD.tenant_slug OR NEW.ref_kind IS NOT OLD.ref_kind
  OR NEW.device_ref IS NOT OLD.device_ref OR NEW.tag IS NOT OLD.tag
  OR NEW.set_by IS NOT OLD.set_by OR NEW.set_at IS NOT OLD.set_at
  OR NEW.reason IS NOT OLD.reason
BEGIN SELECT RAISE(ABORT, 'an asset tag is only ever cleared'); END;

CREATE TABLE IF NOT EXISTS remote_access_registry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug   TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),  -- '*' = MSP-global
    product       TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 80),
    instance_key  TEXT NOT NULL DEFAULT '' CHECK (length(instance_key) <= 200),
    relay_host    TEXT CHECK (relay_host IS NULL OR length(relay_host) <= 253),
    relay_port    INTEGER CHECK (relay_port IS NULL OR relay_port BETWEEN 1 AND 65535),
    relationship  TEXT NOT NULL CHECK (relationship IN ('current', 'ended', 'unconfirmed',
                                                        'forbidden')),
    confirmed_by  TEXT CHECK (confirmed_by IS NULL OR length(confirmed_by) <= 120),
    confirmed_on  TEXT,
    note          TEXT CHECK (note IS NULL OR length(note) <= 500),
    created_by    INTEGER NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ended_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_ra_registry_tenant ON remote_access_registry(tenant_slug, product);
CREATE TRIGGER IF NOT EXISTS ra_registry_no_delete BEFORE DELETE ON remote_access_registry
BEGIN SELECT RAISE(ABORT, 'registry rows are ended, never deleted'); END;

CREATE TABLE IF NOT EXISTS ra_baseline (
    tenant_slug   TEXT NOT NULL,
    device_ref    TEXT NOT NULL,
    instance_key  TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    source        TEXT NOT NULL,
    PRIMARY KEY (tenant_slug, device_ref, instance_key)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS ra_baseline_no_delete BEFORE DELETE ON ra_baseline
BEGIN SELECT RAISE(ABORT, 'the baseline is never deleted'); END;

CREATE TABLE IF NOT EXISTS msp_roster (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    adapter_instance_id  INTEGER,
    actor                TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    class                TEXT NOT NULL CHECK (class IN ('msp', 'client_it', 'vendor-support',
                                                        'system')),
    added_by             INTEGER NOT NULL,
    added_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    removed_at           TEXT
);
CREATE TRIGGER IF NOT EXISTS msp_roster_no_delete BEFORE DELETE ON msp_roster
BEGIN SELECT RAISE(ABORT, 'roster rows are removed by date, never deleted'); END;

CREATE TABLE IF NOT EXISTS egress_set (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr       TEXT NOT NULL CHECK (length(cidr) BETWEEN 3 AND 64),
    label      TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    added_by   INTEGER NOT NULL,
    added_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    removed_at TEXT
);
CREATE TRIGGER IF NOT EXISTS egress_set_no_delete BEFORE DELETE ON egress_set
BEGIN SELECT RAISE(ABORT, 'egress rows are removed by date, never deleted'); END;

CREATE TABLE IF NOT EXISTS attribution_ledger (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL CHECK (kind IN ('athena_dispatch', 'datto_job', 'ir_artifact',
                                                'window')),
    tenant_slug   TEXT NOT NULL,
    device_ref    TEXT,
    job_uid       TEXT,
    executed_at   TEXT,
    window_start  TEXT,
    window_end    TEXT,
    actor         TEXT NOT NULL,
    reason        TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    -- A declared window is at most 8 hours.
    CHECK (kind <> 'window' OR (window_start IS NOT NULL AND window_end IS NOT NULL
           AND julianday(window_end) > julianday(window_start)
           AND (julianday(window_end) - julianday(window_start)) * 24.0 <= 8.0))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_attribution_job
    ON attribution_ledger(job_uid, device_ref) WHERE job_uid IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS attribution_no_delete BEFORE DELETE ON attribution_ledger
BEGIN SELECT RAISE(ABORT, 'the attribution ledger is append-only'); END;

CREATE TABLE IF NOT EXISTS threat_exception (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug   TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    binding_kind  TEXT NOT NULL CHECK (binding_kind IN ('path_prefix', 'product_instance',
                                                        'signature')),
    binding       TEXT NOT NULL CHECK (length(binding) BETWEEN 1 AND 300),
    rule_id       TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 16),
    reason        TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    created_by    INTEGER NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at    TEXT NOT NULL,
    revoked_at    TEXT,
    revoked_by    INTEGER,
    revoke_reason TEXT,
    -- ≤ 90 days from creation.
    CHECK (julianday(expires_at) > julianday(created_at)
           AND julianday(expires_at) - julianday(created_at) <= 90.0)
);
CREATE INDEX IF NOT EXISTS idx_threat_exception_tenant ON threat_exception(tenant_slug, rule_id);
CREATE TRIGGER IF NOT EXISTS threat_exception_no_delete BEFORE DELETE ON threat_exception
BEGIN SELECT RAISE(ABORT, 'exceptions are revoked or expire, never deleted'); END;

CREATE TABLE IF NOT EXISTS analyst_verdict (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug   TEXT NOT NULL,
    device_ref    TEXT,
    verdict_key   TEXT NOT NULL CHECK (length(verdict_key) BETWEEN 1 AND 400),
    rule_id       TEXT NOT NULL,
    incident_id   INTEGER,
    reason        TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    created_by    INTEGER NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    expires_at    TEXT NOT NULL,
    void_at       TEXT,
    void_reason   TEXT,
    CHECK (julianday(expires_at) > julianday(created_at)
           AND julianday(expires_at) - julianday(created_at) <= 366.0)
);
CREATE INDEX IF NOT EXISTS idx_analyst_verdict_key ON analyst_verdict(tenant_slug, verdict_key);
CREATE TRIGGER IF NOT EXISTS analyst_verdict_no_delete BEFORE DELETE ON analyst_verdict
BEGIN SELECT RAISE(ABORT, 'verdicts expire or are voided, never deleted'); END;

CREATE TABLE IF NOT EXISTS domain_intel (
    domain       TEXT PRIMARY KEY CHECK (length(domain) BETWEEN 1 AND 253),
    created_date TEXT,
    registrar    TEXT,
    nameservers  TEXT NOT NULL DEFAULT '[]',
    ti_json      TEXT NOT NULL DEFAULT '{}',
    source       TEXT NOT NULL,
    fetched_at   TEXT NOT NULL
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS domain_intel_no_delete BEFORE DELETE ON domain_intel
BEGIN SELECT RAISE(ABORT, 'domain intel is refreshed, never deleted'); END;

CREATE TABLE IF NOT EXISTS canary_scanner_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    ip          TEXT NOT NULL CHECK (length(ip) BETWEEN 2 AND 64),
    label       TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
    added_by    INTEGER NOT NULL,
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    removed_at  TEXT,
    removed_by  INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_canary_allowlist_live
    ON canary_scanner_allowlist(tenant_slug, ip) WHERE removed_at IS NULL;
CREATE TRIGGER IF NOT EXISTS canary_allowlist_no_delete BEFORE DELETE ON canary_scanner_allowlist
BEGIN SELECT RAISE(ABORT, 'allowlist rows are removed by date, never deleted'); END;

CREATE TABLE IF NOT EXISTS tier_settings (
    scope       TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 64),     -- 'msp' or a slug
    key         TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 64),
    value_json  TEXT NOT NULL,
    updated_by  INTEGER NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (scope, key)
) WITHOUT ROWID;
CREATE TRIGGER IF NOT EXISTS tier_settings_no_delete BEFORE DELETE ON tier_settings
BEGIN SELECT RAISE(ABORT, 'tier settings are changed, never deleted'); END;

CREATE TABLE IF NOT EXISTS rule_brake (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 16),
    ceiling      TEXT NOT NULL DEFAULT 'red' CHECK (ceiling = 'red'),
    set_by       INTEGER NOT NULL,
    set_at       TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    reason       TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
    released_at  TEXT,
    released_by  INTEGER,
    -- ≤ 24 hours.
    CHECK (julianday(expires_at) > julianday(set_at)
           AND (julianday(expires_at) - julianday(set_at)) * 24.0 <= 24.0001)
);
CREATE INDEX IF NOT EXISTS idx_rule_brake_rule ON rule_brake(rule_id, expires_at);
CREATE TRIGGER IF NOT EXISTS rule_brake_no_delete BEFORE DELETE ON rule_brake
BEGIN SELECT RAISE(ABORT, 'brakes expire or are released, never deleted'); END;

CREATE TABLE IF NOT EXISTS threat_worker_state (
    key         TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 120),
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS operator_notices_044 (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard',
                                          'mapping_review','entity_review',
                                          'threat_black','threat_red','threat_escalation',
                                          'threat_coverage','threat_client',
                                          'threat_registry')),
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
INSERT INTO operator_notices_044 (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
       title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id
  FROM operator_notices;
DROP INDEX IF EXISTS idx_operator_notices_open;
DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_request;
DROP TABLE operator_notices;
ALTER TABLE operator_notices_044 RENAME TO operator_notices;
CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);
CREATE INDEX IF NOT EXISTS idx_operator_notices_request
    ON operator_notices(kind, request_id, recipient_id);

-- A re-upgrade takes back what a rollback kept. Created empty on a first
-- upgrade (one code path); the kept rows are spent afterwards.
CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_044
    AS SELECT * FROM operator_notices WHERE 0;
INSERT OR IGNORE INTO operator_notices (
    id, recipient_id, kind, actor_id, subject_slug, target_slug, change_request_id,
    title, body, created_at, acknowledged_at, email_state, email_attempted_at, request_id)
SELECT k.id, k.recipient_id, k.kind, k.actor_id, k.subject_slug, k.target_slug, NULL,
       k.title, k.body, k.created_at, k.acknowledged_at, k.email_state,
       k.email_attempted_at, k.request_id
  FROM operator_notices_rolled_back_044 k
 WHERE k.kind LIKE 'threat\_%' ESCAPE '\'
   AND k.recipient_id IN (SELECT id FROM operators)
   AND k.rowid = (SELECT MAX(q.rowid) FROM operator_notices_rolled_back_044 q
                   WHERE q.id = k.id);
DELETE FROM operator_notices_rolled_back_044;

PRAGMA user_version = 44;

COMMIT;

-- @target: events

BEGIN IMMEDIATE;

ALTER TABLE incidents ADD COLUMN tier TEXT CHECK (tier IS NULL OR tier IN ('red', 'black'));
ALTER TABLE incidents ADD COLUMN rule_id TEXT;
ALTER TABLE incidents ADD COLUMN rule_version INTEGER;
ALTER TABLE incidents ADD COLUMN dedupe_key TEXT;
ALTER TABLE incidents ADD COLUMN site_key TEXT;
ALTER TABLE incidents ADD COLUMN device_ref TEXT;
ALTER TABLE incidents ADD COLUMN device_label TEXT;
ALTER TABLE incidents ADD COLUMN scope TEXT
    CHECK (scope IS NULL OR scope IN ('device', 'site', 'tenant'));
ALTER TABLE incidents ADD COLUMN stages TEXT NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN last_evidence_at TEXT;
ALTER TABLE incidents ADD COLUMN escalation_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN last_escalated_at TEXT;
ALTER TABLE incidents ADD COLUMN ladder_started_at TEXT;
ALTER TABLE incidents ADD COLUMN contained_at TEXT;
ALTER TABLE incidents ADD COLUMN contained_by TEXT;
ALTER TABLE incidents ADD COLUMN close_reason_code TEXT
    CHECK (close_reason_code IS NULL OR close_reason_code IN
           ('remediated', 'authorized_activity', 'duplicate', 'false_positive',
            'reclassified_red'));
ALTER TABLE incidents ADD COLUMN reclassified_from INTEGER;
ALTER TABLE incidents ADD COLUMN reopened_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN client_visible_at TEXT;
ALTER TABLE incidents ADD COLUMN autonomy_mode_at_open TEXT;
ALTER TABLE incidents ADD COLUMN snapshot_sha256 TEXT;
ALTER TABLE incidents ADD COLUMN opened_by TEXT;
ALTER TABLE incidents ADD COLUMN open_reason TEXT;

-- Kept by a rollback: the threat columns of every row, put back (by id) on
-- a re-upgrade BEFORE the triggers exist. Created empty on a first upgrade.
CREATE TABLE IF NOT EXISTS incidents_threat_rolled_back_044 (
    id   INTEGER NOT NULL,
    row  TEXT NOT NULL
);
UPDATE incidents SET
    tier = (SELECT json_extract(k.row, '$.tier') FROM incidents_threat_rolled_back_044 k
             WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    rule_id = (SELECT json_extract(k.row, '$.rule_id') FROM incidents_threat_rolled_back_044 k
                WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    rule_version = (SELECT json_extract(k.row, '$.rule_version')
                      FROM incidents_threat_rolled_back_044 k
                     WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    dedupe_key = (SELECT json_extract(k.row, '$.dedupe_key')
                    FROM incidents_threat_rolled_back_044 k
                   WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    site_key = (SELECT json_extract(k.row, '$.site_key') FROM incidents_threat_rolled_back_044 k
                 WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    device_ref = (SELECT json_extract(k.row, '$.device_ref')
                    FROM incidents_threat_rolled_back_044 k
                   WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    device_label = (SELECT json_extract(k.row, '$.device_label')
                      FROM incidents_threat_rolled_back_044 k
                     WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    scope = (SELECT json_extract(k.row, '$.scope') FROM incidents_threat_rolled_back_044 k
              WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    stages = COALESCE((SELECT json_extract(k.row, '$.stages')
                         FROM incidents_threat_rolled_back_044 k
                        WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1), '[]'),
    last_evidence_at = (SELECT json_extract(k.row, '$.last_evidence_at')
                          FROM incidents_threat_rolled_back_044 k
                         WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    escalation_step = COALESCE((SELECT json_extract(k.row, '$.escalation_step')
                                  FROM incidents_threat_rolled_back_044 k
                                 WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1), 0),
    last_escalated_at = (SELECT json_extract(k.row, '$.last_escalated_at')
                           FROM incidents_threat_rolled_back_044 k
                          WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    ladder_started_at = (SELECT json_extract(k.row, '$.ladder_started_at')
                           FROM incidents_threat_rolled_back_044 k
                          WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    contained_at = (SELECT json_extract(k.row, '$.contained_at')
                      FROM incidents_threat_rolled_back_044 k
                     WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    contained_by = (SELECT json_extract(k.row, '$.contained_by')
                      FROM incidents_threat_rolled_back_044 k
                     WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    close_reason_code = (SELECT json_extract(k.row, '$.close_reason_code')
                           FROM incidents_threat_rolled_back_044 k
                          WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    reclassified_from = (SELECT json_extract(k.row, '$.reclassified_from')
                           FROM incidents_threat_rolled_back_044 k
                          WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    reopened_count = COALESCE((SELECT json_extract(k.row, '$.reopened_count')
                                 FROM incidents_threat_rolled_back_044 k
                                WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1), 0),
    client_visible_at = (SELECT json_extract(k.row, '$.client_visible_at')
                           FROM incidents_threat_rolled_back_044 k
                          WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    autonomy_mode_at_open = (SELECT json_extract(k.row, '$.autonomy_mode_at_open')
                               FROM incidents_threat_rolled_back_044 k
                              WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    snapshot_sha256 = (SELECT json_extract(k.row, '$.snapshot_sha256')
                         FROM incidents_threat_rolled_back_044 k
                        WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    opened_by = (SELECT json_extract(k.row, '$.opened_by') FROM incidents_threat_rolled_back_044 k
                  WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1),
    open_reason = (SELECT json_extract(k.row, '$.open_reason')
                     FROM incidents_threat_rolled_back_044 k
                    WHERE k.id = incidents.id ORDER BY k.rowid DESC LIMIT 1)
 WHERE id IN (SELECT id FROM incidents_threat_rolled_back_044);
DELETE FROM incidents_threat_rolled_back_044;

-- Kept by a rollback: the `athena.incident` lifecycle events (a release
-- before 044 does not know them as Athena's own records — a client user's
-- search would return them), put back WITH THEIR IDS on a re-upgrade (the
-- id is what `incident_signals` cites). 002's columns only: every events.db
-- has them.
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
INSERT OR IGNORE INTO events (id, received_at, source, source_host, event_type, severity,
                              payload, payload_sha256, relay_status)
SELECT id, received_at, source, source_host, event_type, severity, payload, payload_sha256,
       relay_status
  FROM events_athena_rolled_back_044;
DELETE FROM events_athena_rolled_back_044;

-- One OPEN incident per dedupe key; closed ones are history.
CREATE UNIQUE INDEX IF NOT EXISTS ux_incidents_open_dedupe
    ON incidents(dedupe_key)
    WHERE dedupe_key IS NOT NULL AND status NOT IN ('closed', 'false_positive');
CREATE INDEX IF NOT EXISTS idx_incidents_tier ON incidents(tier, status);

-- A record is never deleted.
CREATE TRIGGER IF NOT EXISTS incidents_no_delete BEFORE DELETE ON incidents
BEGIN SELECT RAISE(ABORT, 'incidents are closed, never deleted'); END;
-- What it was opened on is frozen.
CREATE TRIGGER IF NOT EXISTS incidents_frozen BEFORE UPDATE ON incidents
WHEN NEW.detected_at IS NOT OLD.detected_at
  OR (OLD.rule_id IS NOT NULL AND NEW.rule_id IS NOT OLD.rule_id)
  OR (OLD.snapshot_sha256 IS NOT NULL AND NEW.snapshot_sha256 IS NOT OLD.snapshot_sha256)
  OR (OLD.snapshot_sha256 IS NOT NULL AND NEW.evidence_refs IS NOT OLD.evidence_refs)
BEGIN SELECT RAISE(ABORT, 'an incident''s opening facts are frozen'); END;
-- A Black is never lowered in place (close as reclassified opens a linked
-- Red); a tier is never removed.
CREATE TRIGGER IF NOT EXISTS incidents_tier_no_lower BEFORE UPDATE OF tier ON incidents
WHEN OLD.tier IS NOT NULL
 AND (NEW.tier IS NULL OR (OLD.tier = 'black' AND NEW.tier <> 'black'))
BEGIN SELECT RAISE(ABORT, 'a Black incident is never lowered'); END;

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL,
    event_id    INTEGER NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('trigger', 'corroboration', 'context', 'action')),
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (incident_id, event_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id);
CREATE TRIGGER IF NOT EXISTS incident_events_no_delete BEFORE DELETE ON incident_events
BEGIN SELECT RAISE(ABORT, 'incident evidence is never deleted'); END;

-- The lifecycle events (design 6.3): every change appends ONE
-- `athena.incident` event (OCSF 2005 Incident Finding) to this events.db in
-- the same transaction; this lists them per incident, so the retention job
-- keeps every one for as long as the incident (for good).
CREATE TABLE IF NOT EXISTS incident_signals (
    incident_id INTEGER NOT NULL,
    event_id    INTEGER NOT NULL,
    change      TEXT NOT NULL,
    added_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (incident_id, event_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_incident_signals_event ON incident_signals(event_id);
CREATE TRIGGER IF NOT EXISTS incident_signals_no_delete BEFORE DELETE ON incident_signals
BEGIN SELECT RAISE(ABORT, 'the incident timeline is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_signals_no_update BEFORE UPDATE ON incident_signals
BEGIN SELECT RAISE(ABORT, 'the incident timeline is append-only'); END;

CREATE TABLE IF NOT EXISTS incident_notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER NOT NULL,
    author       TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('open', 'note', 'ack', 'assign', 'contain',
                                               'raise', 'close', 'reopen', 'reclassify',
                                               'evidence', 'escalation', 'decision',
                                               'client_visible', 'evidence_window')),
    text         TEXT NOT NULL CHECK (length(text) <= 4000),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id, id);
CREATE TRIGGER IF NOT EXISTS incident_notes_no_delete BEFORE DELETE ON incident_notes
BEGIN SELECT RAISE(ABORT, 'the incident timeline is append-only'); END;
CREATE TRIGGER IF NOT EXISTS incident_notes_no_update BEFORE UPDATE ON incident_notes
BEGIN SELECT RAISE(ABORT, 'the incident timeline is append-only'); END;

CREATE TABLE IF NOT EXISTS incident_decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('lockdown', 'allow')),
    requested_by    TEXT NOT NULL,
    requested_role  TEXT NOT NULL CHECK (requested_role IN ('client', 'analyst')),
    tier_at_request TEXT NOT NULL CHECK (tier_at_request IN ('red', 'black')),
    status          TEXT NOT NULL CHECK (status IN ('recorded', 'pending_analyst',
                                                    'confirmed', 'declined')),
    scope_json      TEXT NOT NULL DEFAULT '[]',
    excluded_json   TEXT NOT NULL DEFAULT '[]',
    notice          TEXT NOT NULL DEFAULT '',
    note            TEXT CHECK (note IS NULL OR length(note) <= 500),
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    decided_by      TEXT,
    decided_at      TEXT,
    decision_note   TEXT,
    -- Nothing in slice 1 executes: a decision is a record.
    executed        INTEGER NOT NULL DEFAULT 0 CHECK (executed = 0)
);
CREATE INDEX IF NOT EXISTS idx_incident_decisions_incident
    ON incident_decisions(incident_id, id);
CREATE TRIGGER IF NOT EXISTS incident_decisions_no_delete BEFORE DELETE ON incident_decisions
BEGIN SELECT RAISE(ABORT, 'decisions are never deleted'); END;
-- What was requested (and what was carved out) never changes; only the
-- analyst's answer to a pending request is written, once.
CREATE TRIGGER IF NOT EXISTS incident_decisions_frozen BEFORE UPDATE ON incident_decisions
WHEN NEW.kind IS NOT OLD.kind OR NEW.requested_by IS NOT OLD.requested_by
  OR NEW.requested_role IS NOT OLD.requested_role OR NEW.scope_json IS NOT OLD.scope_json
  OR NEW.excluded_json IS NOT OLD.excluded_json OR NEW.notice IS NOT OLD.notice
  OR NEW.created_at IS NOT OLD.created_at OR OLD.status <> 'pending_analyst'
BEGIN SELECT RAISE(ABORT, 'a recorded decision is frozen'); END;

-- EVIDENCE WINDOWS (Rick, 2026-10-05: "Ingestion should not stop but if a
-- threat is confirmed everything from first detection up until the all
-- clear should be treated as event evidence"). A Red or Black IS a
-- confirmed threat (only a rule or a person opens one): opening it records
-- a window for its tenant, from its FIRST DETECTION (the earliest time of
-- the evidence linked to it, else its open) and OPEN until its close — the
-- all-clear — which then becomes its end. Every retention / prune / sweep
-- path keeps what of the tenant falls inside a HELD window
-- (`apps.octo.retention.evidence`); what lies outside every window ages as
-- usual, and ingestion never waits on a window. After the all-clear the
-- window is kept until an admin RELEASES it (step-up, a reason, audited
-- before the write, the other admins told) — it never expires by itself.
-- It never shrinks:
--   * its start only moves EARLIER (an analyst widens it — dwell time found
--     later — and earlier evidence linked to the incident widens it too);
--   * its end only moves LATER, or back to open (a reopen, an admin's
--     extension); an automatic window's end is written once, at its
--     incident's close, and is that close's time — never earlier than
--     `min_end_at`, the latest end it ever had (an admin's extension past
--     the close survives a reopen and the next close);
--   * released, it is history (frozen); a window is never deleted.
--   kind 'incident'  the automatic window: one held per incident; a
--                    reclassify carries it to the linked Red (the Red's
--                    close ends it).
--   kind 'manual'    an admin's (the former legal hold): an explicit start
--                    and an end — or none: held open until released.
-- `kept_rows` / `kept_counted_at`: what the last nightly retention run kept
-- past its normal retention because of the window (written by the job).
CREATE TABLE IF NOT EXISTS evidence_windows (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        INTEGER NOT NULL,
    origin_incident_id INTEGER NOT NULL,
    kind               TEXT NOT NULL CHECK (kind IN ('incident', 'manual')),
    start_at           TEXT NOT NULL CHECK (length(start_at) >= 19),
    end_at             TEXT CHECK (end_at IS NULL OR length(end_at) >= 19),
    -- The latest end the window ever had (an admin's extension, the end a
    -- reopen opened again): its next all-clear never ends it earlier.
    min_end_at         TEXT CHECK (min_end_at IS NULL OR length(min_end_at) >= 19),
    opened_by          TEXT NOT NULL,
    opened_at          TEXT NOT NULL,
    reason             TEXT NOT NULL CHECK (length(reason) BETWEEN 3 AND 2000),
    released_at        TEXT,
    released_by        TEXT,
    release_reason     TEXT CHECK (release_reason IS NULL
                                   OR length(release_reason) BETWEEN 3 AND 2000),
    kept_rows          INTEGER CHECK (kept_rows IS NULL OR kept_rows >= 0),
    kept_counted_at    TEXT,
    CHECK (end_at IS NULL OR end_at >= start_at),
    CHECK ((released_at IS NULL) = (released_by IS NULL)
           AND (released_at IS NULL) = (release_reason IS NULL))
);
-- Kept by a rollback (moved aside, ids and all); put back on a re-upgrade
-- BEFORE the triggers exist. Created empty on a first upgrade.
CREATE TABLE IF NOT EXISTS evidence_windows_rolled_back_044
    AS SELECT * FROM evidence_windows WHERE 0;
INSERT OR IGNORE INTO evidence_windows
SELECT k.* FROM evidence_windows_rolled_back_044 k
 WHERE k.rowid = (SELECT MAX(q.rowid) FROM evidence_windows_rolled_back_044 q
                   WHERE q.id = k.id);
DELETE FROM evidence_windows_rolled_back_044;
CREATE UNIQUE INDEX IF NOT EXISTS ux_evidence_windows_auto
    ON evidence_windows(incident_id) WHERE kind = 'incident' AND released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_windows_incident
    ON evidence_windows(incident_id, origin_incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_windows_held
    ON evidence_windows(start_at) WHERE released_at IS NULL;
CREATE TRIGGER IF NOT EXISTS evidence_windows_no_delete BEFORE DELETE ON evidence_windows
BEGIN SELECT RAISE(ABORT, 'evidence windows are released, never deleted'); END;
-- Who opened it, why, and for which incident never change; a released
-- window is history.
CREATE TRIGGER IF NOT EXISTS evidence_windows_frozen BEFORE UPDATE ON evidence_windows
WHEN OLD.released_at IS NOT NULL
  OR NEW.origin_incident_id IS NOT OLD.origin_incident_id OR NEW.kind IS NOT OLD.kind
  OR NEW.opened_by IS NOT OLD.opened_by OR NEW.opened_at IS NOT OLD.opened_at
  OR NEW.reason IS NOT OLD.reason
BEGIN SELECT RAISE(ABORT, 'an evidence window''s record is frozen'); END;
-- Nobody shrinks a window except by releasing it.
CREATE TRIGGER IF NOT EXISTS evidence_windows_never_shrink BEFORE UPDATE ON evidence_windows
WHEN NEW.start_at > OLD.start_at
  OR (OLD.end_at IS NOT NULL AND NEW.end_at IS NOT NULL AND NEW.end_at < OLD.end_at)
  OR (NEW.end_at IS NOT NULL AND NEW.min_end_at IS NOT NULL AND NEW.end_at < NEW.min_end_at)
  OR (OLD.min_end_at IS NOT NULL
      AND (NEW.min_end_at IS NULL OR NEW.min_end_at < OLD.min_end_at))
  -- an end opened again (a reopen) keeps what it covered as its floor
  OR (OLD.end_at IS NOT NULL AND NEW.end_at IS NULL
      AND (NEW.min_end_at IS NULL OR NEW.min_end_at < OLD.end_at))
BEGIN SELECT RAISE(ABORT, 'an evidence window never shrinks — release it instead'); END;
-- An open window gets an end only at its incident's all-clear: an automatic
-- window, its incident closed, the end = that close's time (never before
-- the window's start: a close stamped earlier — a clock stepped back — ends
-- it at its start; never before its `min_end_at`: an end it had before a
-- reopen, an admin's extension, is never taken back by the next close).
CREATE TRIGGER IF NOT EXISTS evidence_windows_end_at_all_clear
BEFORE UPDATE OF end_at ON evidence_windows
WHEN OLD.end_at IS NULL AND NEW.end_at IS NOT NULL
 AND (OLD.kind <> 'incident' OR NOT EXISTS (
      SELECT 1 FROM incidents i WHERE i.id = NEW.incident_id
         AND i.status IN ('closed', 'false_positive')
         AND max(i.closed_at, OLD.start_at, COALESCE(OLD.min_end_at, OLD.start_at))
             = NEW.end_at))
BEGIN SELECT RAISE(ABORT, 'an open evidence window ends only at its incident''s all-clear'); END;
-- It moves only to the Red its Black was reclassified to.
CREATE TRIGGER IF NOT EXISTS evidence_windows_carried
BEFORE UPDATE OF incident_id ON evidence_windows
WHEN NEW.incident_id IS NOT OLD.incident_id AND NOT EXISTS (
     SELECT 1 FROM incidents i WHERE i.id = NEW.incident_id
        AND i.reclassified_from = OLD.incident_id)
BEGIN SELECT RAISE(ABORT, 'an evidence window moves only to its reclassified Red'); END;
-- Evidence is kept until the all-clear: no release while its incident is open.
CREATE TRIGGER IF NOT EXISTS evidence_windows_release_after_all_clear
BEFORE UPDATE OF released_at ON evidence_windows
WHEN OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND NOT EXISTS (
     SELECT 1 FROM incidents i WHERE i.id = OLD.incident_id
        AND i.status IN ('closed', 'false_positive'))
BEGIN SELECT RAISE(ABORT, 'evidence is kept until the all-clear: close the incident first'); END;

CREATE TABLE IF NOT EXISTS threat_fact (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fact_key        TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL,
    stage           TEXT NOT NULL DEFAULT 'live' CHECK (stage IN ('shadow', 'live')),
    device_ref      TEXT,
    site_key        TEXT,
    res_tier        TEXT,
    observed_at     TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_event_id INTEGER,
    prevented       INTEGER NOT NULL DEFAULT 0 CHECK (prevented IN (0, 1)),
    attrs           TEXT NOT NULL DEFAULT '{}',
    attribution     TEXT,
    attribution_ref TEXT,
    incident_id     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_threat_fact_device ON threat_fact(device_ref, observed_at);
CREATE INDEX IF NOT EXISTS idx_threat_fact_kind ON threat_fact(kind, observed_at);

CREATE TABLE IF NOT EXISTS threat_would_fire (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    tier         TEXT NOT NULL CHECK (tier IN ('red', 'black')),
    dedupe_key   TEXT NOT NULL,
    fact_key     TEXT NOT NULL,
    device_ref   TEXT,
    site_key     TEXT,
    summary      TEXT NOT NULL,
    fired_at     TEXT NOT NULL,
    explained_at TEXT,
    explained_by TEXT,
    note         TEXT,
    UNIQUE (rule_id, fact_key)
);
CREATE INDEX IF NOT EXISTS idx_threat_would_fire_at ON threat_would_fire(fired_at);

COMMIT;
