-- Migration 029: per-tenant agent_notes.disposition column.
--
-- Records the autonomous Triage L1 verdict for a note:
--   noise | pattern | escalate | uncertain
-- (the taxonomy from apps/octo_llm/models.py `Disposition` and the
-- project_octo_llm_triage_taxonomy memory).
--
-- NULL for operator-triggered "Ask Octo" enrichment notes (which carry a
-- query_kind instead); set only by the autonomous worker
-- (apps/octo/agent/worker.py), which writes query_kind='auto_enrich' +
-- a disposition on every triaged event.
--
-- Per-tenant migrations don't auto-apply at runtime; the shared note
-- writer adds the column lazily on first insert (see
-- apps/octo/agent/notes.py::ensure_agent_notes_columns). This file
-- documents the schema change and is the source of truth for
-- dev_seed.py's _events_db_schema_sql() builder.
--
-- Banked 2026-06-01 as Task #119b (autonomous triage worker).

PRAGMA foreign_keys = ON;

-- @target: events

ALTER TABLE agent_notes ADD COLUMN disposition TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_notes_disposition
    ON agent_notes(disposition) WHERE disposition IS NOT NULL;
