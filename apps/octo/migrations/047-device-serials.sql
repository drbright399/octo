-- Migration 047: the Datto device's SERIAL NUMBER, manufacturer and model
-- (v0.17.3; Rick's decision A of 2026-10-07 — "useful to know what device is
-- throwing the alert").
--
-- entities section (clients/<slug>/entities.db)
--   inv_device + `serial`, `manufacturer`, `model`, `audit_at`: what the
--                      device's Datto AUDIT (GET /api/v2/audit/device/{uid},
--                      read by the inventory poller — at most 40 a round, a
--                      device again after 7 days) says — the BIOS serial
--                      (else the base board's), the system manufacturer and
--                      model; NULL when not read yet or when the vendor's
--                      value is a placeholder ("To Be Filled By O.E.M.",
--                      "Default string", all zeros, …). `audit_at` = the
--                      last audit READ (a device whose audit says "no
--                      serial" is not asked again for 7 days). Nothing else
--                      of the audit is ever kept: no user name, no network
--                      interface / MAC / address, no UDF, no URL, no
--                      software (dropped at the client, unread).
-- registry section
--   the version only (47): it marks the release, so `rollback_v0172.py`
--   refuses a 47 root until `rollback_v0173.py` ran (an entities.db at 47
--   rolled back by 046's rollback alone would keep these columns and break
--   the re-upgrade).
--
-- A rollback keeps everything and a re-upgrade takes it back (046's
-- pattern): the four columns are kept aside, dropped, and put back on a
-- re-upgrade.

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

PRAGMA user_version = 47;

COMMIT;

-- @target: entities

BEGIN IMMEDIATE;

ALTER TABLE inv_device ADD COLUMN serial TEXT;
ALTER TABLE inv_device ADD COLUMN manufacturer TEXT;
ALTER TABLE inv_device ADD COLUMN model TEXT;
ALTER TABLE inv_device ADD COLUMN audit_at TEXT;
-- Kept by a rollback; put back on a re-upgrade (then spent). Created empty
-- on a first upgrade (one code path).
CREATE TABLE IF NOT EXISTS inv_device_audit_rolled_back_047 (
    adapter_instance_id INTEGER NOT NULL,
    device_uid          TEXT NOT NULL,
    serial              TEXT,
    manufacturer        TEXT,
    model               TEXT,
    audit_at            TEXT
);
UPDATE inv_device SET
    serial = (SELECT k.serial FROM inv_device_audit_rolled_back_047 k
               WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                 AND k.device_uid = inv_device.device_uid ORDER BY k.rowid DESC LIMIT 1),
    manufacturer = (SELECT k.manufacturer FROM inv_device_audit_rolled_back_047 k
                     WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                       AND k.device_uid = inv_device.device_uid ORDER BY k.rowid DESC LIMIT 1),
    model = (SELECT k.model FROM inv_device_audit_rolled_back_047 k
              WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                AND k.device_uid = inv_device.device_uid ORDER BY k.rowid DESC LIMIT 1),
    audit_at = (SELECT k.audit_at FROM inv_device_audit_rolled_back_047 k
                 WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                   AND k.device_uid = inv_device.device_uid ORDER BY k.rowid DESC LIMIT 1)
 WHERE EXISTS (SELECT 1 FROM inv_device_audit_rolled_back_047 k
                WHERE k.adapter_instance_id = inv_device.adapter_instance_id
                  AND k.device_uid = inv_device.device_uid);
DELETE FROM inv_device_audit_rolled_back_047;

PRAGMA user_version = 47;

COMMIT;
