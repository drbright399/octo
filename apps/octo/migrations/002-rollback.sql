-- Rollback for migration 002.
-- @target: indicators

DROP INDEX IF EXISTS idx_indicators_promoted;
DROP INDEX IF EXISTS idx_indicators_last_seen;
DROP INDEX IF EXISTS idx_indicators_severity;
DROP INDEX IF EXISTS idx_indicators_value_type;
DROP TABLE IF EXISTS indicators;

-- @target: events

DROP INDEX IF EXISTS idx_incidents_severity;
DROP INDEX IF EXISTS idx_incidents_status;
DROP TABLE IF EXISTS incidents;
DROP INDEX IF EXISTS idx_sdgh_category;
DROP INDEX IF EXISTS idx_sdgh_detected;
DROP TABLE IF EXISTS sensitive_data_guard_hits;
DROP INDEX IF EXISTS idx_events_payload_sha256;
DROP INDEX IF EXISTS idx_events_severity;
DROP INDEX IF EXISTS idx_events_relay_pending;
DROP INDEX IF EXISTS idx_events_received_at;
DROP TABLE IF EXISTS events;

-- @target: audit

DROP TRIGGER IF EXISTS audit_no_delete;
DROP TRIGGER IF EXISTS audit_no_update;
DROP INDEX IF EXISTS idx_audit_target;
DROP INDEX IF EXISTS idx_audit_action;
DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_ts;
DROP TABLE IF EXISTS audit_log;
