-- Migration 043: PROPOSALS — an integration proposes, an operator confirms.
--
-- The first instance is Autotask's company / company-location addresses
-- proposed as Fleet SITE locations (kind 'site_location', source
-- 'autotask'). The table is GENERIC: later kinds (a friendly destination
-- name, an entity link, …) and sources reuse it without a migration.
--
-- Product rules the table carries:
--   * an integration only PROPOSES; an operator (admin+) CONFIRMS or REJECTS,
--     audited BEFORE the write, with a reason (enforced below: a decided row
--     names who decided, when, and why);
--   * a rejection is never proposed again while the source data is the same
--     (`source_hash`: a hash of the NORMALIZED source data and the tenant it
--     maps to — a cosmetic edit in the source does not re-propose);
--   * a CHANGE in the source supersedes the open proposal and proposes the
--     new data with the old one alongside (the diff); whatever is in force
--     (a confirmed pin) stays until the new proposal is confirmed;
--   * client users (viewers) never see a proposal (the API is admin+).
--
-- registry section
--   proposals          id, kind, source, tenant_slug, target_key (a Fleet site
--                      key, or NULL = "pick a site" — the operator chooses at
--                      confirm time), source_ref ('company:101' /
--                      'location:12'), payload_json (what is proposed: the
--                      address parts, the one-line address, the label …),
--                      source_hash, flags_json (warnings: shared address,
--                      incomplete, far from the console, a pin already set
--                      …), status (proposed | confirmed | rejected |
--                      superseded), geocode_json (the matches of an
--                      operator's address lookup — on demand only), who /
--                      when / why it was decided, and the proposal that
--                      superseded it.
--                      One LIVE row (any status but superseded) per (kind,
--                      source, source_ref, target_key, source_hash) — the
--                      same data is never open, confirmed or rejected twice;
--                      a superseded row never blocks the same data coming
--                      back (a company re-activated, an address changed
--                      back, a mapping restored).
--   site_locations     + origin ('manual' | 'autotask', default 'manual'):
--                      a pin confirmed from a proposal reads "from Autotask,
--                      confirmed by <operator>" (set_by = the operator who
--                      confirmed); + proposal_id (the proposal it came from).
--                      A hand edit sets origin back to 'manual' — also one
--                      made by code that predates 043 and never names the
--                      two columns (the fast rollback: a trigger).
--
-- A rollback keeps the proposals and the pins' provenance (036 / 040 / 041 /
-- 042's pattern); a re-upgrade takes them back. Nothing else changes.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS proposals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 40),
    source          TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40),
    tenant_slug     TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    target_key      TEXT CHECK (target_key IS NULL OR length(target_key) BETWEEN 3 AND 40),
    source_ref      TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 120),
    payload_json    TEXT NOT NULL DEFAULT '{}',
    source_hash     TEXT NOT NULL CHECK (length(source_hash) BETWEEN 8 AND 128),
    flags_json      TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'proposed'
                        CHECK (status IN ('proposed', 'confirmed', 'rejected', 'superseded')),
    geocode_json    TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    decided_by      INTEGER,
    decided_at      TEXT,
    decision_reason TEXT CHECK (decision_reason IS NULL OR length(decision_reason) <= 500),
    superseded_by   INTEGER,
    -- Anything no longer open says when it closed; an operator's decision
    -- names the operator and carries a reason.
    CHECK (status = 'proposed' OR decided_at IS NOT NULL),
    CHECK (status NOT IN ('confirmed', 'rejected')
           OR (decided_by IS NOT NULL AND length(decision_reason) >= 3))
);

-- One LIVE row per (kind, source, source_ref, target, source data). NULL
-- targets compare equal here (an expression index; SQLite's UNIQUE treats
-- NULLs as distinct). Superseded rows are history: the same data may be
-- proposed again after one (partial index).
CREATE UNIQUE INDEX IF NOT EXISTS uq_proposals_identity
    ON proposals(kind, source, source_ref, COALESCE(target_key, ''), source_hash)
    WHERE status <> 'superseded';
CREATE INDEX IF NOT EXISTS idx_proposals_open
    ON proposals(kind, status, tenant_slug);
CREATE INDEX IF NOT EXISTS idx_proposals_target
    ON proposals(target_key) WHERE target_key IS NOT NULL;

ALTER TABLE site_locations ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'
    CHECK (origin IN ('manual', 'autotask'));
ALTER TABLE site_locations ADD COLUMN proposal_id INTEGER;

-- A hand edit by code that predates 043 (the v0.15 image on this schema —
-- the fast rollback) never names origin / proposal_id: such a pin is
-- 'manual' again, never "from Autotask, confirmed by <the hand editor>".
-- 043's own writes always name both (a hand edit 'manual'; a confirm a NEW
-- proposal id), so this never fires for them.
CREATE TRIGGER IF NOT EXISTS site_locations_hand_edit_is_manual
AFTER UPDATE OF lat, lng, label, set_at ON site_locations
WHEN NEW.origin <> 'manual' AND NEW.proposal_id IS OLD.proposal_id
BEGIN
    UPDATE site_locations SET origin = 'manual', proposal_id = NULL
     WHERE site_key = NEW.site_key;
END;

-- A re-upgrade takes back what a rollback kept. Created empty on a first
-- upgrade (one code path).
CREATE TABLE IF NOT EXISTS proposals_rolled_back_043
    AS SELECT * FROM proposals WHERE 0;
INSERT OR IGNORE INTO proposals (id, kind, source, tenant_slug, target_key, source_ref,
                                 payload_json, source_hash, flags_json, status, geocode_json,
                                 created_at, updated_at, decided_by, decided_at,
                                 decision_reason, superseded_by)
SELECT k.id, k.kind, k.source, k.tenant_slug, k.target_key, k.source_ref, k.payload_json,
       k.source_hash, k.flags_json, k.status, k.geocode_json, k.created_at, k.updated_at,
       k.decided_by, k.decided_at, k.decision_reason, k.superseded_by
  FROM proposals_rolled_back_043 k
 WHERE k.tenant_slug IN (SELECT slug FROM clients)
   AND k.status IN ('proposed', 'confirmed', 'rejected', 'superseded')
   AND (k.status = 'proposed' OR k.decided_at IS NOT NULL)
   AND (k.status NOT IN ('confirmed', 'rejected')
        OR (k.decided_by IS NOT NULL AND length(k.decision_reason) BETWEEN 3 AND 500))
   AND k.rowid = (SELECT MAX(q.rowid) FROM proposals_rolled_back_043 q WHERE q.id = k.id);
-- An id is never handed out twice (the audit log names proposals by id),
-- not even one whose row was not taken back: the counter continues from the
-- highest id the rollback kept or had handed out.
CREATE TABLE IF NOT EXISTS proposals_seq_rolled_back_043 (seq INTEGER NOT NULL);
CREATE TEMP TABLE IF NOT EXISTS _proposals_high_043 AS
SELECT MAX(COALESCE((SELECT MAX(id) FROM proposals_rolled_back_043), 0),
           COALESCE((SELECT MAX(seq) FROM proposals_seq_rolled_back_043), 0)) AS high;
UPDATE sqlite_sequence SET seq = MAX(seq, (SELECT high FROM _proposals_high_043))
 WHERE name = 'proposals';
INSERT INTO sqlite_sequence (name, seq)
SELECT 'proposals', high FROM _proposals_high_043
 WHERE high > 0 AND NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'proposals');
DROP TABLE _proposals_high_043;
DELETE FROM proposals_seq_rolled_back_043;
DELETE FROM proposals_rolled_back_043;

-- The provenance of a pin comes back only if the pin itself is unchanged
-- (same tenant, point and label): a pin edited by hand during the downgrade
-- stays 'manual'.
CREATE TABLE IF NOT EXISTS site_locations_origin_rolled_back_043 (
    site_key    TEXT NOT NULL,
    tenant_slug TEXT NOT NULL,
    lat         REAL NOT NULL,
    lng         REAL NOT NULL,
    label       TEXT NOT NULL,
    origin      TEXT NOT NULL,
    proposal_id INTEGER
);
UPDATE site_locations
   SET origin = (SELECT k.origin FROM site_locations_origin_rolled_back_043 k
                  WHERE k.site_key = site_locations.site_key
                    AND k.tenant_slug = site_locations.tenant_slug
                    AND k.lat = site_locations.lat AND k.lng = site_locations.lng
                    AND k.label = site_locations.label
                    AND k.origin IN ('manual', 'autotask')
                  ORDER BY k.rowid DESC LIMIT 1),
       proposal_id = (SELECT k.proposal_id FROM site_locations_origin_rolled_back_043 k
                       WHERE k.site_key = site_locations.site_key
                         AND k.tenant_slug = site_locations.tenant_slug
                         AND k.lat = site_locations.lat AND k.lng = site_locations.lng
                    AND k.label = site_locations.label
                         AND k.origin IN ('manual', 'autotask')
                       ORDER BY k.rowid DESC LIMIT 1)
 WHERE EXISTS (SELECT 1 FROM site_locations_origin_rolled_back_043 k
                WHERE k.site_key = site_locations.site_key
                  AND k.tenant_slug = site_locations.tenant_slug
                  AND k.lat = site_locations.lat AND k.lng = site_locations.lng
                    AND k.label = site_locations.label
                  AND k.origin IN ('manual', 'autotask'));
DELETE FROM site_locations_origin_rolled_back_043;

PRAGMA user_version = 43;

COMMIT;
