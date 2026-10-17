-- Rollback migration 032.

-- @target: registry

DROP TABLE IF EXISTS adapter_webhook_receipts;

PRAGMA user_version = 31;
