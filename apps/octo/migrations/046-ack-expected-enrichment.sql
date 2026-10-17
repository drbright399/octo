-- Migration 046: ACKNOWLEDGE, EXPECTED and ENRICHMENT (v0.17.2; Rick's
-- decisions of 2026-10-06, A–D). The number skips 045: the parallel v0.17.1
-- branch (NextDNS block tuning + the automated CSAM Black) may take it, and
-- 046 must be applied AFTER it (a file at 46 never applies a 45 section).
--
-- registry section
--   alert_verdict      EVERY human verdict on an alert — 'ack' (the analyst
--                      saw it: it leaves the "needs attention" list and
--                      stops counting towards the site's Yellow until a NEW
--                      occurrence re-surfaces it), 'confirmed' (R8: it
--                      opened a Red) and 'expected' (it created an expected
--                      condition) — with the tenant, the event, its
--                      signature key, who, when, the note. Training labels
--                      for later; append-only (never updated, never
--                      deleted). For a coalesced alert (one row with a hit
--                      count) the count and last-seen AT the verdict are
--                      kept: a count increase or a newer last-seen after an
--                      ack re-surfaces it. `repeat_until` (≤ 24 h): "also
--                      acknowledge repeats" of the same (tenant, device,
--                      signature key) until then — never longer, and never
--                      for an alert that names no device. `alert_ref` = the
--                      vendor's alert identity (a Datto alert uid: its raise
--                      and its resolution; a RocketCyber incident id: its
--                      versions) — an ack covers the other rows of it.
--   expected_condition a KNOWN condition (the Siris → Datto backup IPS hits,
--                      the sleeping cold-storage server's backup criticals):
--                      tenant + device + signature key (+ optionally a
--                      remote IP / network / forward-confirmed host for a
--                      network alert) — ONE device, never client-wide.
--                      Matching alerts are labelled
--                      "expected (rule #N)": grey, not Yellow, STILL STORED
--                      (an event is never altered or deleted). A reason of
--                      at least 10 characters and a REVIEW DATE at most 90
--                      days out (the threat-exception rule); on that date it
--                      stops matching — there is no renewal (a new rule is a
--                      new decision). Revoked, never deleted; what it was
--                      created with is frozen. Never for a NextDNS 'csam'
--                      block (v0.17.1 makes it an automated Black) — the
--                      CHECK below holds that even against a bad caller —
--                      nor for anything an incident rule reads (the API).
--   enrichment_cache   remote-IP enrichment (PTR over DNS-over-HTTPS to a
--                      public resolver, the owner over RDAP — never the
--                      local resolver, never the remote IP itself), keyed by
--                      kind + key, with an expiry (7 days for an answer, 1
--                      hour for a failure). A cache: rows are replaced and
--                      pruned.
-- telemetry section (clients/<slug>/telemetry.db)
--   unifi_signal_buckets + `remotes`: the remote addresses of an IPS bucket's
--                      hits ({ip: hits}, bounded; "~" counts the rest) — a
--                      bucket coalesces one LAN client + signature over an
--                      hour whatever the remote end, so "N× in 24 h from
--                      this remote" and an expected rule limited to one
--                      remote need the split. NULL for a bucket written
--                      before 046 (its remotes are not known: a rule limited
--                      to a remote never matches it).
-- entities section (clients/<slug>/entities.db)
--   inv_device + `ext_ip`: the device's external address as Datto reports it
--                      (D: hostname, uid, internal / external IP, online,
--                      type, OS, last seen — NEVER a UDF). The device list is
--                      now read for EVERY Datto-mapped tenant; identity
--                      LINKING stays gated by the entity switch.
--
-- A rollback keeps everything and a re-upgrade takes it back (036 / 040 /
-- 044's pattern): the registry tables are LEFT AS THEY ARE (nothing before
-- 046 reads them); the two new columns are kept aside, dropped, and put
-- back on a re-upgrade.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS alert_verdict (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug   TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    event_id      INTEGER NOT NULL CHECK (event_id >= 1),
    source        TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40),
    device_key    TEXT NOT NULL DEFAULT '' CHECK (length(device_key) <= 300),
    signature_key TEXT NOT NULL CHECK (length(signature_key) BETWEEN 1 AND 400),
    verdict       TEXT NOT NULL CHECK (verdict IN ('ack', 'confirmed', 'expected')),
    actor         INTEGER NOT NULL,
    at            TEXT NOT NULL CHECK (length(at) >= 19),
    note          TEXT CHECK (note IS NULL OR length(note) <= 500),
    hits_at       INTEGER CHECK (hits_at IS NULL OR hits_at >= 1),
    last_seen_at  TEXT,
    repeat_until  TEXT,
    rule_id       INTEGER,
    incident_id   INTEGER,
    -- The VENDOR's identity of the alert the event is a row of ('datto:<alert
    -- uid>' — its raise and its resolution; 'rocketcyber:<incident id>' —
    -- every stored version): an ack covers the other rows of the same alert.
    alert_ref     TEXT CHECK (alert_ref IS NULL OR length(alert_ref) BETWEEN 3 AND 200),
    -- "acknowledge repeats" lasts at most 24 hours, only on an ack, and only
    -- for an alert that names its device (else it would cover the client).
    CHECK (repeat_until IS NULL OR (verdict = 'ack' AND device_key <> ''
           AND julianday(repeat_until) > julianday(at)
           AND (julianday(repeat_until) - julianday(at)) * 24.0 <= 24.0001)),
    CHECK (rule_id IS NULL OR verdict = 'expected'),
    CHECK (incident_id IS NULL OR verdict = 'confirmed')
);
CREATE INDEX IF NOT EXISTS idx_alert_verdict_event ON alert_verdict(tenant_slug, event_id);
CREATE INDEX IF NOT EXISTS idx_alert_verdict_at ON alert_verdict(tenant_slug, at);
CREATE INDEX IF NOT EXISTS idx_alert_verdict_key
    ON alert_verdict(tenant_slug, signature_key, device_key);
CREATE INDEX IF NOT EXISTS idx_alert_verdict_ref ON alert_verdict(tenant_slug, alert_ref)
    WHERE alert_ref IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS alert_verdict_no_delete BEFORE DELETE ON alert_verdict
BEGIN SELECT RAISE(ABORT, 'verdicts are training labels: never deleted'); END;
CREATE TRIGGER IF NOT EXISTS alert_verdict_no_update BEFORE UPDATE ON alert_verdict
BEGIN SELECT RAISE(ABORT, 'a recorded verdict is never changed'); END;

CREATE TABLE IF NOT EXISTS expected_condition (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_slug     TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    source          TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40),
    device_key      TEXT NOT NULL DEFAULT '' CHECK (length(device_key) <= 300),
    signature_key   TEXT NOT NULL CHECK (length(signature_key) BETWEEN 1 AND 400),
    remote          TEXT CHECK (remote IS NULL OR length(remote) BETWEEN 2 AND 253),
    label           TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 240),
    reason          TEXT NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
    origin_event_id INTEGER NOT NULL CHECK (origin_event_id >= 1),
    created_by      INTEGER NOT NULL,
    created_at      TEXT NOT NULL CHECK (length(created_at) >= 19),
    review_at       TEXT NOT NULL CHECK (length(review_at) >= 19),
    reminded_at     TEXT,
    revoked_at      TEXT,
    revoked_by      INTEGER,
    revoke_reason   TEXT CHECK (revoke_reason IS NULL
                                OR length(revoke_reason) BETWEEN 3 AND 500),
    -- A review date ≤ 90 days out (the threat-exception rule).
    CHECK (julianday(review_at) > julianday(created_at)
           AND julianday(review_at) - julianday(created_at) <= 90.0001),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)
           AND (revoked_at IS NULL) = (revoke_reason IS NULL)),
    -- A CSAM lookup is never "expected" (v0.17.1: an automated Black).
    CHECK (signature_key NOT LIKE 'nextdns:csam|%'),
    -- Always ONE device: an alert that names none (a RocketCyber incident)
    -- would make it a client-wide condition.
    CHECK (device_key <> '')
);
CREATE INDEX IF NOT EXISTS idx_expected_condition_tenant
    ON expected_condition(tenant_slug, review_at);
CREATE TRIGGER IF NOT EXISTS expected_condition_no_delete BEFORE DELETE ON expected_condition
BEGIN SELECT RAISE(ABORT, 'expected conditions are revoked or reach review, never deleted'); END;
-- What it was created with is frozen; a revoke is final; the reminder is
-- stamped once.
CREATE TRIGGER IF NOT EXISTS expected_condition_frozen BEFORE UPDATE ON expected_condition
WHEN NEW.tenant_slug IS NOT OLD.tenant_slug OR NEW.source IS NOT OLD.source
  OR NEW.device_key IS NOT OLD.device_key OR NEW.signature_key IS NOT OLD.signature_key
  OR NEW.remote IS NOT OLD.remote OR NEW.label IS NOT OLD.label
  OR NEW.reason IS NOT OLD.reason OR NEW.origin_event_id IS NOT OLD.origin_event_id
  OR NEW.created_by IS NOT OLD.created_by OR NEW.created_at IS NOT OLD.created_at
  OR NEW.review_at IS NOT OLD.review_at
  OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at
      OR NEW.revoked_by IS NOT OLD.revoked_by OR NEW.revoke_reason IS NOT OLD.revoke_reason))
  OR (OLD.reminded_at IS NOT NULL AND NEW.reminded_at IS NOT OLD.reminded_at)
BEGIN SELECT RAISE(ABORT, 'an expected condition''s record is frozen — revoke it, create a new one'); END;

CREATE TABLE IF NOT EXISTS enrichment_cache (
    kind        TEXT NOT NULL CHECK (kind IN ('ip', 'host', 'rdap_bootstrap')),
    key         TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 300),
    value_json  TEXT NOT NULL,
    ok          INTEGER NOT NULL CHECK (ok IN (0, 1)),
    fetched_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (kind, key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires ON enrichment_cache(expires_at);

PRAGMA user_version = 46;

COMMIT;

-- @target: telemetry

BEGIN IMMEDIATE;

ALTER TABLE unifi_signal_buckets ADD COLUMN remotes TEXT;
-- Kept by a rollback; put back on a re-upgrade (then spent). Created empty
-- on a first upgrade (one code path).
CREATE TABLE IF NOT EXISTS unifi_bucket_remotes_rolled_back_046 (
    bucket_key TEXT NOT NULL,
    remotes    TEXT
);
UPDATE unifi_signal_buckets SET remotes = (
    SELECT k.remotes FROM unifi_bucket_remotes_rolled_back_046 k
     WHERE k.bucket_key = unifi_signal_buckets.bucket_key ORDER BY k.rowid DESC LIMIT 1)
 WHERE bucket_key IN (SELECT bucket_key FROM unifi_bucket_remotes_rolled_back_046);
DELETE FROM unifi_bucket_remotes_rolled_back_046;

PRAGMA user_version = 46;

COMMIT;

-- @target: entities

BEGIN IMMEDIATE;

ALTER TABLE inv_device ADD COLUMN ext_ip TEXT;
CREATE TABLE IF NOT EXISTS inv_device_ext_ip_rolled_back_046 (
    adapter_instance_id INTEGER NOT NULL,
    device_uid          TEXT NOT NULL,
    ext_ip              TEXT
);
UPDATE inv_device SET ext_ip = (
    SELECT k.ext_ip FROM inv_device_ext_ip_rolled_back_046 k
     WHERE k.adapter_instance_id = inv_device.adapter_instance_id
       AND k.device_uid = inv_device.device_uid ORDER BY k.rowid DESC LIMIT 1)
 WHERE EXISTS (SELECT 1 FROM inv_device_ext_ip_rolled_back_046 k
                WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                  AND k.device_uid = inv_device.device_uid);
DELETE FROM inv_device_ext_ip_rolled_back_046;

PRAGMA user_version = 46;

COMMIT;
