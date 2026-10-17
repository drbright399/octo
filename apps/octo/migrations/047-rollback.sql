-- Rollback migration 047.
--
-- Nothing is destroyed by a downgrade, and a re-upgrade takes back what it
-- kept (046's pattern):
--   * registry — the version goes back to 46 (047 changes nothing else
--     there).
--   * entities (each entities.db at 47) — every device's `serial`,
--     `manufacturer`, `model` and `audit_at` are kept under
--     `inv_device_audit_rolled_back_047`, the four columns are dropped; the
--     version goes back to 46.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

PRAGMA user_version = 46;

COMMIT;

-- @target: entities

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS inv_device_audit_rolled_back_047 (
    adapter_instance_id INTEGER NOT NULL,
    device_uid          TEXT NOT NULL,
    serial              TEXT,
    manufacturer        TEXT,
    model               TEXT,
    audit_at            TEXT
);
INSERT INTO inv_device_audit_rolled_back_047 (adapter_instance_id, device_uid, serial,
                                              manufacturer, model, audit_at)
SELECT adapter_instance_id, device_uid, serial, manufacturer, model, audit_at FROM inv_device
 WHERE serial IS NOT NULL OR manufacturer IS NOT NULL OR model IS NOT NULL
    OR audit_at IS NOT NULL;
ALTER TABLE inv_device DROP COLUMN serial;
ALTER TABLE inv_device DROP COLUMN manufacturer;
ALTER TABLE inv_device DROP COLUMN model;
ALTER TABLE inv_device DROP COLUMN audit_at;

PRAGMA user_version = 46;

COMMIT;
