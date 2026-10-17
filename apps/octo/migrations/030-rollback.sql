-- Rollback for migration 030: drop the generic tenant map.
-- @target: registry

DROP INDEX IF EXISTS idx_adapter_tenant_by_client;
DROP TABLE IF EXISTS adapter_tenant_map;

PRAGMA user_version = 27;
