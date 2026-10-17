-- Rollback migration 043.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (036 / 040 / 041 / 042's pattern):
--   * registry — every proposal is kept under `proposals_rolled_back_043`
--     (appended to on a second rollback) and the id counter under
--     `proposals_seq_rolled_back_043`, then `proposals` is dropped;
--   * registry — the provenance of every pin confirmed from a proposal
--     (site key, tenant, the point and label, origin, proposal id) is kept
--     under `site_locations_origin_rolled_back_043`, then its trigger and
--     the two columns go (`site_locations` is 042's again: the pins
--     themselves stay). Code before 043 never reads either. Re-applying
--     043 restores the newest kept proposal of every id whose tenant still
--     exists, and the provenance of every pin that is still where (and as)
--     it was.
--   The version goes back to 42.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS proposals_rolled_back_043
    AS SELECT * FROM proposals WHERE 0;
INSERT INTO proposals_rolled_back_043 SELECT * FROM proposals;
-- The id counter too: a re-upgrade never hands an id out twice.
CREATE TABLE IF NOT EXISTS proposals_seq_rolled_back_043 (seq INTEGER NOT NULL);
INSERT INTO proposals_seq_rolled_back_043 (seq)
SELECT seq FROM sqlite_sequence WHERE name = 'proposals';
DROP INDEX IF EXISTS uq_proposals_identity;
DROP INDEX IF EXISTS idx_proposals_open;
DROP INDEX IF EXISTS idx_proposals_target;
DROP TABLE IF EXISTS proposals;

CREATE TABLE IF NOT EXISTS site_locations_origin_rolled_back_043 (
    site_key    TEXT NOT NULL,
    tenant_slug TEXT NOT NULL,
    lat         REAL NOT NULL,
    lng         REAL NOT NULL,
    label       TEXT NOT NULL,
    origin      TEXT NOT NULL,
    proposal_id INTEGER
);
INSERT INTO site_locations_origin_rolled_back_043
    (site_key, tenant_slug, lat, lng, label, origin, proposal_id)
SELECT site_key, tenant_slug, lat, lng, label, origin, proposal_id
  FROM site_locations WHERE origin <> 'manual';
-- SQLite refuses to drop a column a trigger names.
DROP TRIGGER IF EXISTS site_locations_hand_edit_is_manual;
ALTER TABLE site_locations DROP COLUMN proposal_id;
ALTER TABLE site_locations DROP COLUMN origin;

PRAGMA user_version = 42;

COMMIT;
