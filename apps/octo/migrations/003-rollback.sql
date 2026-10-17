-- Rollback for migration 003.
-- @target: patterns

DROP TABLE IF EXISTS sanitization_rejects;
DROP INDEX IF EXISTS idx_patterns_client_count;
DROP INDEX IF EXISTS idx_patterns_severity;
DROP INDEX IF EXISTS idx_patterns_ioc;
DROP TABLE IF EXISTS patterns;

-- @target: audit

DROP TRIGGER IF EXISTS global_audit_no_delete;
DROP TRIGGER IF EXISTS global_audit_no_update;
DROP INDEX IF EXISTS idx_global_audit_action;
DROP INDEX IF EXISTS idx_global_audit_actor;
DROP INDEX IF EXISTS idx_global_audit_ts;
DROP TABLE IF EXISTS audit_log;
