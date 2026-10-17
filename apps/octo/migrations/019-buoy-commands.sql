-- Migration 019: Buoy command queue.
--
-- Operators queue commands at a buoy by POSTing to
-- /api/v1/buoy/:slug/command. The buoy daemon polls for queued
-- commands on each heartbeat (piggybacks the existing 60s cycle —
-- single round-trip, no extra long-poll endpoint to add).
-- Buoy executes + reports result via POST /api/v1/buoy/command/:id/result.
--
-- Status transitions:
--   queued     → dispatched     (buoy fetched it; expected to execute)
--   dispatched → completed      (success, result_json populated)
--   dispatched → failed         (handler raised, exit_code set)
--   queued     → expired        (TTL elapsed before buoy fetched it —
--                                see expires_at; default 5 min)
--
-- Auth + audit (enforced in the router, not at the DB):
--   - All POSTs to /api/v1/buoy/:slug/command require step-up auth.
--   - Role gating per command_kind: ping/refresh/tail-log = analyst+,
--     restart-service = admin+, reboot/update = super_admin only.
--   - requested_by = operator id; audit row in global/audit.db with
--     reason="buoy command queued" + the command_kind + slug.
--   - args_json is FREE-FORM but the router validates against the
--     handler's allowed-arg whitelist BEFORE queueing. Bad args
--     return 400, never reach the queue.
--
-- No FK on slug → buoys.slug — a command can be queued for a slug
-- that exists in clients but hasn't heartbeated yet (operator
-- onboarding edge case). The buoy will pick it up on first heartbeat.

PRAGMA user_version = 19;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS buoy_commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT NOT NULL,
    command_kind    TEXT NOT NULL
                      CHECK (command_kind IN (
                        'ping', 'refresh', 'tail-log',
                        'restart-service', 'reboot', 'update'
                      )),
    args_json       TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'queued'
                      CHECK (status IN (
                        'queued', 'dispatched',
                        'completed', 'failed', 'expired'
                      )),
    requested_by    INTEGER NOT NULL REFERENCES operators(id),
    requested_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    dispatched_at   TEXT,
    completed_at    TEXT,
    result_json     TEXT,
    expires_at      TEXT NOT NULL,
    audit_request_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_buoy_commands_slug_status
    ON buoy_commands(slug, status);
CREATE INDEX IF NOT EXISTS idx_buoy_commands_requested_at
    ON buoy_commands(requested_at DESC);
