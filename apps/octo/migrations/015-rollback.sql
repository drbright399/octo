-- Rollback migration 015: drop Autotask mapping tables.
-- Pre-launch only — no production data lives in these yet.

PRAGMA user_version = 14;

-- @target: registry

DROP INDEX IF EXISTS idx_autotask_tenant_by_company;
DROP INDEX IF EXISTS idx_autotask_operator_by_resource;
DROP INDEX IF EXISTS idx_autotask_picklist_by_entity;
DROP TABLE IF EXISTS autotask_tenant_company_map;
DROP TABLE IF EXISTS autotask_operator_resource_map;
DROP TABLE IF EXISTS autotask_picklist_cache;
