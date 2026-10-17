-- Migration 014: ticket_notes — per-ticket chronological notes,
-- Autotask-aligned for future round-trip.
--
-- Models the Autotask REST API `TicketNotes` entity field-for-field
-- (REST docs: /help/developerhelp/Content/APIs/REST/Entities/TicketNotesEntity.htm):
--
--   id                   long, PK
--   ticketID             integer, required, FK → tickets
--   title                string(250), optional
--   description          string(32000), required, plain text (Autotask
--                          REST strips rich text + images even when
--                          posted as HTML)
--   noteType             integer picklist, required — values are
--                          per-Autotask-instance via
--                          /entityInformation/fields. We store the
--                          canonical TEXT label here and resolve to the
--                          tenant-specific picklist id at sync time so
--                          the schema stays portable across MSPs.
--   publish              integer picklist, required — same story:
--                          'internal' / 'all_autotask_users' /
--                          'client_portal' are stored as labels and
--                          mapped at sync time.
--   creatorResourceID    read-only on Autotask; we hold the local
--                          operator_id and write the Autotask resource
--                          id on push.
--   createDateTime       read-only on Autotask side.
--   lastActivityDate     ditto.
--
-- Per `project_dual_tier_notes_architecture`: these are TYPE B notes —
-- the canonical ticket conversation that must round-trip to Autotask.
-- The ephemeral SECURE-NOTEPAD scratchpad (Type B') lives in a separate
-- table (planned for #18) and consolidates into one of these on close.
--
-- Cross-tenant safety: ticket_notes is PER-TENANT, scoped to a single
-- client's tickets.db. No cross-tenant joins possible at the SQL layer.

PRAGMA user_version = 14;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: tickets

CREATE TABLE IF NOT EXISTS ticket_notes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id          INTEGER NOT NULL
                         REFERENCES tickets(id) ON DELETE CASCADE,
    -- Round-trip identity. NULL until pushed to Autotask.
    autotask_id        TEXT UNIQUE,

    title              TEXT,
    body               TEXT NOT NULL,
    -- Canonical TEXT label; mapped to Autotask integer picklist at
    -- sync time. Set covers the standard Autotask labels operators
    -- expect to see in the Notes tab.
    note_type          TEXT NOT NULL DEFAULT 'internal'
                         CHECK (note_type IN (
                             'task_detail',
                             'workflow',
                             'internal',
                             'detail',
                             'summary',
                             'resolution',
                             'system_workflow'
                         )),
    publish            TEXT NOT NULL DEFAULT 'internal'
                         CHECK (publish IN (
                             'internal',
                             'all_autotask_users',
                             'client_portal'
                         )),

    -- Author. operator_id is local; the round-trip layer maps to
    -- Autotask CreatorResourceID using the operators ↔ resources
    -- mapping established at integration setup.
    author_operator_id INTEGER,

    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    -- Tracks Autotask's lastActivityDate so we can detect drift
    -- between local + remote without re-fetching the whole note.
    last_activity_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    pushed_to_autotask_at TEXT
);

-- Hot path: "all notes for this ticket, newest first" (the Notes panel
-- inside the ticket window).
CREATE INDEX IF NOT EXISTS idx_ticket_notes_by_ticket
    ON ticket_notes (ticket_id, created_at DESC);

-- Round-trip dedup lookup.
CREATE INDEX IF NOT EXISTS idx_ticket_notes_autotask
    ON ticket_notes (autotask_id) WHERE autotask_id IS NOT NULL;

-- Touch the parent ticket's updated_at whenever a note lands. This
-- keeps the list-page "recently updated" sort honest without the
-- caller having to remember to bump it.
CREATE TRIGGER IF NOT EXISTS trg_ticket_notes_touch_ticket
AFTER INSERT ON ticket_notes
BEGIN
    UPDATE tickets
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
     WHERE id = NEW.ticket_id;
END;
