-- Migration 016: Autotask write-back foundation (P4-c2-α).
--
-- Adds the per-ticket opt-in surface for pushing Athena-originated
-- tickets to Autotask, plus the line-item charges + push-state
-- outbox tables. Schema mirrors Autotask's Ticket + TicketCharge
-- shapes so the eventual REST POST is a direct field map.
--
-- This migration lays the foundation. The actual REST writeback is
-- implemented in apps/octo/adapters/autotask/writeback.py — billing-
-- code / contract picklist sync, charge round-trip, and status echo
-- are Zack's extension surface (see the 2026-05-14 Autotask
-- write-back hand-off, archived outside the repo).
--
-- Per-tenant DB: <data_root>/clients/<slug>/tickets.db.
-- No global tables touched.

PRAGMA user_version = 16;
PRAGMA foreign_keys = ON;

-- @target: tickets

-- -------------------------------------------------------------------
-- tickets — add push opt-in + Autotask billing/contract fields.
-- -------------------------------------------------------------------

-- Per-ticket flag: should this ticket be pushed to Autotask? Default
-- 0 (off) — operator must explicitly opt in so we don't surprise an
-- MSP that's still validating their mapping. The writeback worker
-- only picks up rows where this is 1 AND autotask_id IS NULL (push)
-- or status/notes have advanced since last_autotask_sync_at (echo).
ALTER TABLE tickets
    ADD COLUMN push_to_autotask INTEGER NOT NULL DEFAULT 0
        CHECK (push_to_autotask IN (0, 1));

-- Autotask's `isBillable`-equivalent. Default 1 because Autotask's
-- own default is billable; operator must explicitly mark non-billable.
-- Maps to Autotask Ticket fields the Zack-owned writeback layer will
-- finalize (billingCodeID gates much of this).
ALTER TABLE tickets
    ADD COLUMN is_billable INTEGER NOT NULL DEFAULT 1
        CHECK (is_billable IN (0, 1));

-- Autotask BillingCode picklist value. NULL = let Autotask pick the
-- account default. Stored as TEXT not INT because Autotask picklist
-- IDs are technically numeric but we keep them opaque here — the
-- writeback layer parses them.
ALTER TABLE tickets
    ADD COLUMN billing_code_id TEXT;

-- Autotask Contract picklist value. NULL = unlinked. Same
-- treat-as-opaque-id rationale.
ALTER TABLE tickets
    ADD COLUMN contract_id TEXT;


-- -------------------------------------------------------------------
-- ticket_charges — line-item add-on expenses/items per ticket.
-- -------------------------------------------------------------------
--
-- Mirrors Autotask's TicketCharge entity. Each row becomes a single
-- POST /TicketCharges/ on push. Zack's writeback layer fills in the
-- AT-side IDs (created_autotask_id) when the round-trip lands.

CREATE TABLE IF NOT EXISTS ticket_charges (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id             INTEGER NOT NULL
                            REFERENCES tickets(id) ON DELETE CASCADE,

    -- Display + accounting fields. `name` is what shows up on the
    -- customer's invoice; `description` is the longer note. Matches
    -- Autotask TicketCharge.name + .description.
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',

    -- Pricing. Stored as REAL because Autotask's API returns
    -- decimals; we round to 4 places to match their precision.
    unit_cost             REAL NOT NULL DEFAULT 0.0,
    unit_price            REAL NOT NULL DEFAULT 0.0,
    quantity              REAL NOT NULL DEFAULT 1.0,

    -- billable defaults true (matches Autotask). Operator can flip
    -- per-charge — useful for "added a part to the ticket but
    -- comping it" cases.
    is_billable           INTEGER NOT NULL DEFAULT 1
                            CHECK (is_billable IN (0, 1)),

    -- Optional Autotask BillingCode override for this charge —
    -- distinct from the ticket-level billing_code_id because Autotask
    -- allows per-charge codes (e.g., a ticket on a flat-rate contract
    -- with one-off material charges).
    billing_code_id       TEXT,

    -- Round-trip identity. NULL until pushed. UNIQUE so a duplicate-
    -- push attempt is caught at the SQL layer.
    autotask_charge_id    TEXT UNIQUE,

    -- Operator + timestamps. Operator who added this line. Audit
    -- trail flows up to the ticket-level audit log via the ticket id.
    created_by_operator_id INTEGER,
    created_at            TEXT NOT NULL
                            DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_pushed_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_ticket_charges_ticket
    ON ticket_charges (ticket_id);

CREATE INDEX IF NOT EXISTS idx_ticket_charges_unpushed
    ON ticket_charges (ticket_id) WHERE autotask_charge_id IS NULL;


-- -------------------------------------------------------------------
-- autotask_push_state — per-ticket outbox state.
-- -------------------------------------------------------------------
--
-- One row per ticket that has ever been queued for push. The
-- writeback worker reads `state='pending'` rows, attempts the push,
-- and advances state. Failures bump attempts + record last_error so
-- the operator can see why a push is stalled from the ticket window.
--
-- Note: a ticket only enters this table when push_to_autotask=1 AND
-- the operator (or the writeback worker on initial seed) explicitly
-- creates an outbox row. Setting push_to_autotask=1 alone does NOT
-- imply immediate push — the explicit /push-to-autotask endpoint
-- creates the outbox row.

CREATE TABLE IF NOT EXISTS autotask_push_state (
    ticket_id             INTEGER PRIMARY KEY
                            REFERENCES tickets(id) ON DELETE CASCADE,
    state                 TEXT NOT NULL DEFAULT 'pending'
                            CHECK (state IN (
                                'pending',
                                'in_flight',
                                'pushed',
                                'failed'
                            )),
    attempts              INTEGER NOT NULL DEFAULT 0,
    last_attempt_at       TEXT,
    last_error            TEXT,
    -- When the writeback worker successfully creates the Autotask
    -- ticket, the resulting ID is also stamped on tickets.autotask_id
    -- — duplicated here for fast lookup without joining.
    autotask_ticket_id    TEXT,
    queued_at             TEXT NOT NULL
                            DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    queued_by_operator_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_push_state_pending
    ON autotask_push_state (state, queued_at)
    WHERE state IN ('pending', 'failed');


-- -------------------------------------------------------------------
-- autotask_push_log — append-only audit of every push attempt.
-- -------------------------------------------------------------------
--
-- Distinct from push_state (which is current-state). The log keeps
-- every attempt so when Zack debugs why a sync drifted, the trail is
-- complete — operator, timestamp, payload digest, outcome, error.
-- Auditor-friendly, immutable.

CREATE TABLE IF NOT EXISTS autotask_push_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id             INTEGER NOT NULL
                            REFERENCES tickets(id) ON DELETE CASCADE,
    action                TEXT NOT NULL
                            CHECK (action IN (
                                'create_ticket',
                                'update_ticket',
                                'create_charge',
                                'create_note',
                                'status_echo'
                            )),
    outcome               TEXT NOT NULL
                            CHECK (outcome IN ('success', 'error')),
    autotask_response_id  TEXT,
    error_code            TEXT,
    error_message         TEXT,
    -- payload_digest is a short hex hash of the JSON we sent — lets
    -- the operator confirm "yes the same payload" across retries
    -- without storing the full body.
    payload_digest        TEXT,
    operator_id           INTEGER,
    at                    TEXT NOT NULL
                            DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_push_log_ticket
    ON autotask_push_log (ticket_id, at DESC);
