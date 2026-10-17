-- Migration 028: per-tenant agent_notes.query_kind column.
--
-- Tracks which "Ask Octo" canned-query template produced an
-- operator-triggered enrichment note, so the Agent Triage Feed
-- can distinguish:
--   - autonomous notes (query_kind = NULL or 'auto_enrich')
--   - operator "tell me more" / "patterns" / etc.
--
-- Per-tenant migrations don't currently auto-apply at runtime;
-- the bridge endpoint adds the column lazily on first insert
-- (see _ensure_query_kind_column in agent_query.py). This
-- migration file documents the schema change and is the source
-- of truth for dev_seed.py's _events_db_schema_sql() builder.
--
-- Banked 2026-05-21 as slice 7d.

PRAGMA foreign_keys = ON;

-- @target: events

ALTER TABLE agent_notes ADD COLUMN query_kind TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_notes_query_kind
    ON agent_notes(query_kind) WHERE query_kind IS NOT NULL;
