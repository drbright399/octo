-- Rollback migration 017. Per-tenant tickets.db.
--
-- SQLite has DROP COLUMN since 3.35, but we use the recreate dance
-- for consistency with 016-rollback.sql.

PRAGMA foreign_keys = OFF;

-- @target: tickets

DROP INDEX IF EXISTS idx_tickets_due_at;

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
    last_autotask_sync_at TEXT,
    push_to_autotask      INTEGER NOT NULL DEFAULT 0
                            CHECK (push_to_autotask IN (0, 1)),
    is_billable           INTEGER NOT NULL DEFAULT 1
                            CHECK (is_billable IN (0, 1)),
    billing_code_id       TEXT,
    contract_id           TEXT
);

INSERT INTO tickets_rollback (
    id, autotask_id, title, description, severity, status,
    assignee_operator_id, queue, source_event_id,
    opened_at, updated_at, closed_at, last_autotask_sync_at,
    push_to_autotask, is_billable, billing_code_id, contract_id
)
SELECT
    id, autotask_id, title, description, severity, status,
    assignee_operator_id, queue, source_event_id,
    opened_at, updated_at, closed_at, last_autotask_sync_at,
    push_to_autotask, is_billable, billing_code_id, contract_id
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

PRAGMA user_version = 16;
PRAGMA foreign_keys = ON;
