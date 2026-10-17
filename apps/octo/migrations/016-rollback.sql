-- Rollback migration 016. Per-tenant tickets.db.
--
-- Drops new tables + removes the added columns from tickets via the
-- standard SQLite recreate-table dance (SQLite has no DROP COLUMN
-- until 3.35, and even then it's row-rewriting which is fine here
-- but we prefer the explicit-rewrite pattern for clarity).

PRAGMA foreign_keys = OFF;

-- @target: tickets

DROP TABLE IF EXISTS autotask_push_log;
DROP TABLE IF EXISTS autotask_push_state;
DROP TABLE IF EXISTS ticket_charges;

-- Rebuild tickets table without the 4 added columns. We use the
-- canonical post-014 shape — anything added between 014 and 016 lives
-- in 015 which only touched registry.db, not per-tenant tickets.db.
CREATE TABLE tickets_rollback (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    autotask_id           TEXT UNIQUE,
    title                 TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    severity              TEXT NOT NULL DEFAULT 'medium'
                            CHECK (severity IN ('info','low','medium','high','critical')),
    status                TEXT NOT NULL DEFAULT 'new'
                            CHECK (status IN (
                                'new', 'in_progress',
                                'waiting_customer', 'waiting_vendor',
                                'resolved', 'closed', 'reopened'
                            )),
    assignee_operator_id  INTEGER,
    queue                 TEXT,
    source_event_id       INTEGER,
    opened_at             TEXT NOT NULL
                            DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at            TEXT NOT NULL
                            DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    closed_at             TEXT,
    last_autotask_sync_at TEXT
);

INSERT INTO tickets_rollback (
    id, autotask_id, title, description, severity, status,
    assignee_operator_id, queue, source_event_id,
    opened_at, updated_at, closed_at, last_autotask_sync_at
)
SELECT
    id, autotask_id, title, description, severity, status,
    assignee_operator_id, queue, source_event_id,
    opened_at, updated_at, closed_at, last_autotask_sync_at
FROM tickets;

DROP TABLE tickets;
ALTER TABLE tickets_rollback RENAME TO tickets;

CREATE INDEX IF NOT EXISTS idx_tickets_open_by_updated
    ON tickets (updated_at DESC)
    WHERE status NOT IN ('closed', 'resolved');
CREATE INDEX IF NOT EXISTS idx_tickets_assignee_status
    ON tickets (assignee_operator_id, status);
CREATE INDEX IF NOT EXISTS idx_tickets_autotask_id
    ON tickets (autotask_id) WHERE autotask_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tickets_source_event
    ON tickets (source_event_id) WHERE source_event_id IS NOT NULL;

PRAGMA user_version = 14;
PRAGMA foreign_keys = ON;
