-- Migration 011: per-client agent notes + agent pattern links.
--
-- Adds the agent note + cross-reference layer to each tenant's
-- events.db. Two agent identities supported:
--
--   * 'octo'   — the data-plane intelligence shipped inside the OCTO
--                container. Deterministic heuristic ruleset by default;
--                optional LLM-backed context mode when configured. THE
--                source of agent notes today.
--
--   * 'athena' — the future analyst-partner orchestrator. Conversational,
--                not yet built. Reserved here so the schema is stable
--                when that workstream starts.
--
-- Spec lives in `project_agent_notes_in_search_with_pattern_links`
-- memory; this migration only lays the storage. The /search drawer
-- surfaces `agent_notes` per row; /tickets sidebar will reuse the same
-- tables queried with `ref_kind='ticket'`.
--
-- The earlier "shallow / deep / athena" three-tier model was retired
-- 2026-05-14 — see `project_octo_athena_naming_2026-05-14` for the
-- rationale. shallow + deep collapsed into 'octo'; athena stays.
--
-- Both tables are append-mostly. `agent_notes.updated_at` is the only
-- mutation path (when an agent revises a confidence or text). Edges
-- in `agent_pattern_links` are immutable once written — re-detection
-- inserts a fresh row rather than updating, so the audit trail
-- preserves "agent saw X on tick T → Y on tick T+N".
--
-- Cross-tenant safety: these tables are PER-TENANT, scoped to the
-- client's own events.db. Cross-tenant edges live in the future
-- sanitized-pool variant (Task #114) and route through the
-- Section-7 audit mitigations from the external audit. No code in
-- this migration touches the global patterns.db.

PRAGMA user_version = 11;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: events

CREATE TABLE IF NOT EXISTS agent_notes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ref_kind           TEXT NOT NULL
                         CHECK (ref_kind IN ('event','ticket','indicator')),
    ref_id             INTEGER NOT NULL,
    agent_id           TEXT NOT NULL
                         CHECK (agent_id IN ('octo','athena')),
    note_text          TEXT NOT NULL,
    confidence         REAL NOT NULL
                         CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT,
    audit_request_id   TEXT NOT NULL
);

-- Fast lookup of "all notes for this event/ticket/indicator", which
-- is the dominant access pattern (drawer/sidebar open → fetch notes
-- for ref).
CREATE INDEX IF NOT EXISTS idx_agent_notes_ref
    ON agent_notes(ref_kind, ref_id);

-- Per-agent timeline (rare but useful for debugging: "what did Deep
-- emit in the last hour?").
CREATE INDEX IF NOT EXISTS idx_agent_notes_agent_created
    ON agent_notes(agent_id, created_at);


CREATE TABLE IF NOT EXISTS agent_pattern_links (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    from_kind          TEXT NOT NULL
                         CHECK (from_kind IN ('event','ticket','indicator')),
    from_id            INTEGER NOT NULL,
    to_kind            TEXT NOT NULL
                         CHECK (to_kind IN ('event','ticket','indicator')),
    to_id              INTEGER NOT NULL,
    relation           TEXT NOT NULL
                         CHECK (relation IN ('same_ioc','same_host','same_ttp','temporal','semantic')),
    strength           REAL NOT NULL
                         CHECK (strength >= 0.0 AND strength <= 1.0),
    rationale          TEXT NOT NULL,
    created_by_agent   TEXT NOT NULL
                         CHECK (created_by_agent IN ('octo','athena')),
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- "Show me everything linked from this row" — outgoing edges. The
-- drawer/sidebar uses this on open to render the recognized-patterns
-- section.
CREATE INDEX IF NOT EXISTS idx_pattern_links_from
    ON agent_pattern_links(from_kind, from_id);

-- Reverse traversal — "what links INTO this row?" Less common but
-- needed for graph-view future work and for the "you may also want
-- to look at" cross-reference panel.
CREATE INDEX IF NOT EXISTS idx_pattern_links_to
    ON agent_pattern_links(to_kind, to_id);

-- Pattern-type analytics ("how many same_ttp edges in last 30d?").
CREATE INDEX IF NOT EXISTS idx_pattern_links_relation_created
    ON agent_pattern_links(relation, created_at);

-- Append-only audit triggers — agents can revise via updated_at on
-- notes, but pattern links are immutable. Edges that turn out wrong
-- get logically retracted via a future `retracted_at` column +
-- companion audit row, not deleted.
CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_update
    BEFORE UPDATE ON agent_pattern_links
BEGIN
    SELECT RAISE(FAIL, 'agent_pattern_links is append-only');
END;

CREATE TRIGGER IF NOT EXISTS agent_pattern_links_no_delete
    BEFORE DELETE ON agent_pattern_links
BEGIN
    SELECT RAISE(FAIL, 'agent_pattern_links is append-only');
END;
