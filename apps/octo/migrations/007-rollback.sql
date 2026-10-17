-- ============================================================================
-- Migration 007 rollback — drop the adapter_instances table.
-- ============================================================================

-- @target: registry

DROP INDEX IF EXISTS idx_adapter_instances_active_vendor;
DROP INDEX IF EXISTS idx_adapter_instances_status;
DROP TABLE IF EXISTS adapter_instances;

PRAGMA user_version = 6;
