-- Migration 025: per-operator preferences column.
--
-- Adds a JSON `preferences` column on operators so each operator can
-- store small personal settings (theme, accent, LLM opt-out, etc.)
-- without proliferating per-feature columns.
--
-- v1 keys (documented; not enforced — schema is JSON-blob shape):
--   l2_llm_enabled   : bool   default true (per-operator opt-out)
--   theme_accent     : str    future use
--
-- Why JSON-blob over per-key column:
--   The set of preferences will grow over time (theme picker, density,
--   accessibility settings, etc.). One ALTER TABLE per new setting is
--   noise; the JSON column lets the API layer evolve without
--   schema churn. Indexed lookups aren't needed — preferences are
--   read on operator session bootstrap, not joined.
--
-- Read path:
--   GET /api/v1/account/preferences
--     → { l2_llm_enabled: bool, ... }  (defaults filled in if NULL)
--
-- Write path:
--   PUT /api/v1/account/preferences { l2_llm_enabled: false }
--     → partial-update merge with existing JSON; unknown keys
--       rejected by the Pydantic model at the API layer.
--
-- Wire-up:
--   /api/v1/agent-query consults the preference and returns
--   PRECONDITION_FAILED (412, "user_disabled") when the operator has
--   opted out, regardless of bundle_config.l2_llm_enabled.
--
-- Banked 2026-05-21 as Slice 5b of the LLM-container arc.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators ADD COLUMN preferences TEXT;  -- JSON; NULL = defaults

PRAGMA user_version = 25;
