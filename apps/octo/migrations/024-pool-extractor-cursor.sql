-- Migration 024: sanitized-pool extractor cursor + run stats.
--
-- The extractor is a scaffolded but disabled-by-default scanner that
-- walks per-tenant events.db for IOC candidates, validates them via
-- M1+M7+M8, computes M2 tenant_hmac, and writes into patterns /
-- sanitization_rejects with M4 dual-write audit. See:
--   apps/octo/sanitized_pool/extractor.py
--
-- Why a cursor:
--   The extractor must be resumable. Each run picks up from the last
--   successfully scanned event_id per tenant and advances on success.
--   If a run crashes mid-scan, the next run retries from the same
--   point — no events lost, no events double-extracted.
--
-- Why patterns.db (not registry.db):
--   This is pool state — it belongs with the pool tables. Keeping all
--   pool state in one DB simplifies the M9 rotation procedure (a
--   secret rotation drops the cursor + tenant_hmacs, then re-extracts
--   from event_id=0 under the new secret).
--
-- Disabled-by-default surface:
--   `bundle_config.sanitized_pool_extractor_enabled` (JSON boolean,
--   default false). The extractor refuses to run when this is unset
--   or false. Operator opts in via the super_admin Settings panel.

PRAGMA foreign_keys = ON;

-- @target: patterns

CREATE TABLE IF NOT EXISTS pool_extractor_cursor (
    tenant_slug         TEXT PRIMARY KEY,
    last_event_id       INTEGER NOT NULL DEFAULT 0,
    last_run_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_run_status     TEXT NOT NULL DEFAULT 'never'
                          CHECK (last_run_status IN ('never','ok','error','disabled')),
    last_error          TEXT,
    events_seen_total   INTEGER NOT NULL DEFAULT 0,
    patterns_written    INTEGER NOT NULL DEFAULT 0,
    rejects_written     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pool_extractor_cursor_last_run
    ON pool_extractor_cursor(last_run_at);

PRAGMA user_version = 24;
