-- Migration 020: Buoy per-buoy notepads (slice 12).
--
-- Two tables, scoped per-buoy:
--
--   - buoy_user_notes:  Free-form operator notes per buoy. MSP-staff-
--                       visible (gated by client-DB access already in
--                       place — no per-note privacy tier per
--                       2026-05-18 product call). Editable by author
--                       or admin.
--
--   - buoy_agent_notes: AI-written, append-only. The agent writes
--                       here when an action crosses one of three
--                       thresholds (action_class CHECK constraint):
--                         alert-behavior  — e.g. Wazuh rule change
--                         client-network  — e.g. Pi-hole allowlist edit
--                         state-change    — e.g. daemon install,
--                                            service restart, migration
--                       Includes a correlation_id so a single
--                       fleet-wide action that lands on N buoys becomes
--                       N rows tied together for UI rollup.
--
-- Visibility model: not enforced at the DB; the router scopes by the
-- caller's client-access grant per the existing per-tenant scoping
-- pattern. Adding a column would only duplicate state.
--
-- No FK on slug → buoys.slug: a note can be pre-queued for a slug
-- that doesn't yet have a buoy row (operator-onboarding edge case,
-- same justification as slice 7's buoy_commands.slug). Garbage-slug
-- notes from operator typos surface in the UI as "unknown buoy" and
-- are operator-cleanable.

PRAGMA user_version = 20;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS buoy_user_notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    slug         TEXT NOT NULL,
    author_id    INTEGER NOT NULL REFERENCES operators(id),
    body_md      TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_buoy_user_notes_slug_created
    ON buoy_user_notes(slug, created_at DESC);

CREATE TABLE IF NOT EXISTS buoy_agent_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT NOT NULL,
    action_class    TEXT NOT NULL
                      CHECK (action_class IN (
                        'alert-behavior',
                        'client-network',
                        'state-change'
                      )),
    body_md         TEXT NOT NULL,
    correlation_id  TEXT,
    session_id      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_buoy_agent_notes_slug_created
    ON buoy_agent_notes(slug, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_buoy_agent_notes_correlation
    ON buoy_agent_notes(correlation_id)
    WHERE correlation_id IS NOT NULL;
