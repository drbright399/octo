-- Migration 013: per-client tickets.db.
--
-- Tickets are PER-TENANT — every MSP customer gets its own file at
-- `<data_root>/clients/<slug>/tickets.db`. Same isolation pattern as
-- events.db + indicators.db: file-level boundary, no cross-tenant
-- joins possible at the SQL layer.
--
-- Spec lives in:
--   - `project_ticket_sidebar_and_deep_linking`  (UI surface)
--   - `project_dual_tier_notes_architecture`     (Type B notes = ticket notes)
--   - `project_per_ticket_secure_notepad`        (sidecar notepad)
--
-- Status vocabulary mirrors Autotask so the future round-trip is a
-- straight field map rather than a translation table. `autotask_id`
-- is nullable: Athena-originated tickets start without one and get
-- stitched on push to Autotask; tickets ingested from Autotask
-- arrive with it already populated.
--
-- Append-only history table (`ticket_status_history`) captures every
-- status transition with operator + reason. This is the audit trail
-- regulators expect for incident-response workflows and is also what
-- powers the future "case timeline" view.
--
-- Cross-tenant safety: this migration creates ONLY the per-tenant
-- schema. No global table touches. The Athena API enforces tenant
-- scope at the router layer (same pattern as /search).

PRAGMA user_version = 13;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: tickets

CREATE TABLE IF NOT EXISTS tickets (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Round-trip identity. NULL until the ticket is pushed to /
    -- ingested from Autotask. UNIQUE so a duplicate-push attempt is
    -- caught at the SQL layer rather than the API layer.
    autotask_id        TEXT UNIQUE,

    -- Core fields. Title + description map 1:1 to Autotask's title +
    -- description. Severity uses the same vocabulary as events
    -- (info|low|medium|high|critical) so an event-derived ticket
    -- inherits without translation.
    title              TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT 'medium'
                         CHECK (severity IN ('info','low','medium','high','critical')),

    -- Status. Vocabulary intentionally matches Autotask's defaults so
    -- the round-trip map is identity. `new` is the on-create state;
    -- `closed` is terminal (transitions out are rare and audit-worthy
    -- — handled by an explicit reopen action that inserts a fresh
    -- status_history row with reason).
    status             TEXT NOT NULL DEFAULT 'new'
                         CHECK (status IN (
                             'new',
                             'in_progress',
                             'waiting_customer',
                             'waiting_vendor',
                             'resolved',
                             'closed',
                             'reopened'
                         )),

    -- Assignment. operator_id is intra-bundle; queue is a free-form
    -- text label for unassigned-but-grouped tickets ("L1", "after-
    -- hours", etc.). The Kaseya-pattern visibility logic
    -- (`project_kaseya_visibility_pattern_ownership_scoping`) reads
    -- both fields when deciding row visibility.
    assignee_operator_id  INTEGER,
    queue                 TEXT,

    -- Provenance. Where the ticket came from. `source_event_id` is
    -- the events.db row that triggered creation (NULL when human-
    -- created). Storing it here (rather than only via
    -- agent_pattern_links) keeps the back-link cheap for the "view
    -- originating event" affordance in the ticket window.
    source_event_id    INTEGER,

    -- Timestamps.
    opened_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    closed_at          TEXT,
    last_autotask_sync_at TEXT
);

-- Hot path: "all open tickets, sorted recent-first" (the default
-- list view). Partial index on non-terminal status keeps it tight.
CREATE INDEX IF NOT EXISTS idx_tickets_open_by_updated
    ON tickets (updated_at DESC)
    WHERE status NOT IN ('closed', 'resolved');

-- Hot path: "my open tickets" (assignee filter on list page).
CREATE INDEX IF NOT EXISTS idx_tickets_assignee_status
    ON tickets (assignee_operator_id, status);

-- Lookup by Autotask id (round-trip ingest dedup).
CREATE INDEX IF NOT EXISTS idx_tickets_autotask_id
    ON tickets (autotask_id) WHERE autotask_id IS NOT NULL;

-- Lookup by originating event ("show ticket for this event").
CREATE INDEX IF NOT EXISTS idx_tickets_source_event
    ON tickets (source_event_id) WHERE source_event_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS ticket_status_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id          INTEGER NOT NULL
                         REFERENCES tickets(id) ON DELETE CASCADE,
    from_status        TEXT,   -- NULL on initial create
    to_status          TEXT NOT NULL,
    -- Operator who made the change. NULL when the transition came
    -- from Autotask round-trip ingest (the reason field will name
    -- the Autotask user in that case).
    changed_by_operator_id  INTEGER,
    reason             TEXT NOT NULL DEFAULT '',
    changed_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    -- Source of the transition: 'operator' | 'autotask_sync' |
    -- 'agent_action' | 'system'. Keeps the audit trail honest about
    -- whether the change was a human, an external system, an Athena
    -- agent acting under approved authority, or a scheduled job.
    source             TEXT NOT NULL DEFAULT 'operator'
                         CHECK (source IN (
                             'operator',
                             'autotask_sync',
                             'agent_action',
                             'system'
                         ))
);

CREATE INDEX IF NOT EXISTS idx_status_history_ticket
    ON ticket_status_history (ticket_id, changed_at DESC);
