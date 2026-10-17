-- Rollback migration 033.
--
-- Nothing a human has not yet decided on is destroyed by a downgrade:
--   * quarantine — for webhook-only vendors the held payloads are the ONLY
--     copies of those events, so the table is preserved under
--     `quarantine_rolled_back_033` (appended to if that exists already)
--     rather than dropped;
--   * tenant_change_requests — in-flight two-person approvals are preserved
--     the same way (`tenant_change_requests_rolled_back_033`).
-- Re-applying 033 creates fresh tables; the preserved copies stay for an
-- operator to inspect or route by hand.
--
-- Auto-created clients SURVIVE a rollback as ordinary `clients` rows (the
-- origin / kind / review_state / ai_policy columns are dropped, so they are
-- no longer distinguishable from manual ones). Adapter mappings they own
-- stay in adapter_tenant_map (migration 030).

PRAGMA foreign_keys = ON;

-- @target: registry

DROP INDEX IF EXISTS idx_tenant_change_requests_subject;
CREATE TABLE IF NOT EXISTS tenant_change_requests_rolled_back_033
    AS SELECT * FROM tenant_change_requests WHERE 0;
INSERT INTO tenant_change_requests_rolled_back_033 SELECT * FROM tenant_change_requests;
DROP TABLE IF EXISTS tenant_change_requests;
DROP INDEX IF EXISTS idx_clients_created_by_instance;
DROP INDEX IF EXISTS idx_clients_review;
ALTER TABLE clients DROP COLUMN ai_policy;
ALTER TABLE clients DROP COLUMN created_by_instance_id;
ALTER TABLE clients DROP COLUMN review_state;
ALTER TABLE clients DROP COLUMN kind;
ALTER TABLE clients DROP COLUMN origin;

PRAGMA user_version = 32;

-- @target: quarantine

DROP INDEX IF EXISTS idx_quarantine_vendor_tenant;
DROP INDEX IF EXISTS idx_quarantine_open;
DROP INDEX IF EXISTS idx_quarantine_instance_received;
CREATE TABLE IF NOT EXISTS quarantine_rolled_back_033 AS SELECT * FROM quarantine WHERE 0;
INSERT INTO quarantine_rolled_back_033 SELECT * FROM quarantine;
DROP TABLE IF EXISTS quarantine;

PRAGMA user_version = 0;
