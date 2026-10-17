-- Rollback migration 035.
--
-- Nothing is destroyed by a downgrade: every notice (acknowledged or not,
-- with its e-mail delivery record) is kept under
-- `operator_notices_rolled_back_035` (appended to if that exists already),
-- then the table goes. Re-applying 035 starts an EMPTY notices table; the
-- single-person changes themselves stay on record in tenant_change_requests
-- and the audit chain, which is where a reader looks for them.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

DROP INDEX IF EXISTS idx_operator_notices_change;
DROP INDEX IF EXISTS idx_operator_notices_open;
CREATE TABLE IF NOT EXISTS operator_notices_rolled_back_035
    AS SELECT * FROM operator_notices WHERE 0;
INSERT INTO operator_notices_rolled_back_035 SELECT * FROM operator_notices;
DROP TABLE IF EXISTS operator_notices;

PRAGMA user_version = 34;

COMMIT;
