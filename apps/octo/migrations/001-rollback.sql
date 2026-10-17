-- Rollback for migration 001.
-- Drops registry.db tables. Irreversible — use only with backup in place.

DROP TABLE IF EXISTS scheduled_purges;
DROP TABLE IF EXISTS operator_roles;
DROP TABLE IF EXISTS operators;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS client_tokens;
DROP TABLE IF EXISTS clients_history;
DROP TABLE IF EXISTS clients;

PRAGMA user_version = 0;
