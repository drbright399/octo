-- Migration 033: tenant lifecycle — auto-created tenants, classification,
-- two-person change requests, and the quarantine store.
--
-- WHY. Every vendor site the integrations see must get a bucket (product
-- ruling: no traffic is ignored). Until now an event whose vendor tenant id
-- mapped to no client was DROPPED and counted; ~90 alerts a night from ~12
-- unmapped sites were being lost. From this migration on, the ingest path
-- may CREATE a tenant from incoming integration traffic (bounded, audited)
-- or LINK it to an existing one when the site name is an obvious match, and
-- everything it cannot attribute is HELD in a quarantine store for a human
-- to route. Tenants therefore need to say where they came from and whether
-- a human has looked at them yet.
--
-- clients (registry):
--   origin                  manual | auto | bootstrap — how the row came to be.
--   kind                    unclassified | client | internal | dev | vendor |
--                           other — what the bucket IS; the onboarding admin
--                           tags it ("ignored" is deliberately not a kind).
--   review_state            confirmed | pending — pending = a human still has
--                           to tag/confirm this tenant. Auto-created rows are
--                           born pending. EVERY pre-existing row is set to
--                           pending too: none of them carries a kind or a
--                           compliance tag yet, and the console must ask for
--                           one rather than pretend they were classified.
--   created_by_instance_id  the adapter instance whose traffic created an
--                           auto row (NULL for manual/bootstrap).
--   ai_policy               none | local | cloud — per-tenant AI consent.
--                           This is the column `agent.llm_escalation.
--                           tenant_ai_consumption_allowed()` was written to
--                           wait for (it read a never-created
--                           `ai_consumption_allowed` and defaulted ALLOW).
--                           Opt-in from here on: 'none' for every row, new
--                           and existing, until an admin sets it.
--   compliance_flags        (existing, JSON list) stays the compliance-tag
--                           store; the curated vocabulary lives in code
--                           (`instances.tenant_lifecycle.COMPLIANCE_TAGS`).
--
-- origin for existing rows: the schema carries no marker for "created by
-- bundle bootstrap", so rows onboarded within an hour of the FIRST operator
-- (the factory super_admin, minted by the same bootstrap run) are tagged
-- 'bootstrap'; every other existing row is 'manual'. origin is informational
-- — nothing gates on it except the auto-create bound, which counts 'auto'.
--
-- tenant_change_requests: offboard by an admin, and every merge, need a
-- second person. The request row is the pending half; approving it applies
-- the change (super_admin, a different operator than the requester).
--
-- quarantine (its own platform DB, global/quarantine.db — never a client
-- dir): held payloads are UNTRUSTED vendor text, stored opaque and bounded,
-- and never create anything by themselves. Idempotent per (instance,
-- payload_sha256) so a poller re-listing an open alert holds it once.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE clients ADD COLUMN origin TEXT NOT NULL DEFAULT 'manual'
    CHECK (origin IN ('manual','auto','bootstrap'));
ALTER TABLE clients ADD COLUMN kind TEXT NOT NULL DEFAULT 'unclassified'
    CHECK (kind IN ('unclassified','client','internal','dev','vendor','other'));
ALTER TABLE clients ADD COLUMN review_state TEXT NOT NULL DEFAULT 'confirmed'
    CHECK (review_state IN ('confirmed','pending'));
ALTER TABLE clients ADD COLUMN created_by_instance_id INTEGER;
ALTER TABLE clients ADD COLUMN ai_policy TEXT NOT NULL DEFAULT 'none'
    CHECK (ai_policy IN ('none','local','cloud'));

-- Pre-existing rows: none is classified yet, so all need a human's look.
UPDATE clients SET review_state = 'pending';
UPDATE clients SET origin = 'bootstrap'
 WHERE onboarded_at <= (
     SELECT strftime('%Y-%m-%dT%H:%M:%fZ', MIN(created_at), '+1 hour')
       FROM operators
 );

CREATE INDEX IF NOT EXISTS idx_clients_review
    ON clients(review_state, origin);
CREATE INDEX IF NOT EXISTS idx_clients_created_by_instance
    ON clients(created_by_instance_id, origin, onboarded_at)
    WHERE created_by_instance_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_change_requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL CHECK (kind IN ('offboard','merge')),
    subject_slug   TEXT NOT NULL,
    -- merge only: the tenant the subject is folded into.
    target_slug    TEXT,
    requested_by   INTEGER NOT NULL,
    requested_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    reason         TEXT NOT NULL,
    state          TEXT NOT NULL DEFAULT 'pending'
                     CHECK (state IN ('pending','approved','rejected','applied','cancelled')),
    decided_by     INTEGER,
    decided_at     TEXT,
    decision_note  TEXT,
    request_id     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_change_requests_subject
    ON tenant_change_requests(subject_slug, state);

PRAGMA user_version = 33;

-- @target: quarantine

CREATE TABLE IF NOT EXISTS quarantine (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    adapter_instance_id  INTEGER NOT NULL,
    vendor_slug          TEXT NOT NULL,
    -- 'poll' | 'webhook' — which door the payload came through.
    source               TEXT NOT NULL,
    vendor_tenant_id     TEXT,
    vendor_tenant_label  TEXT,
    -- Why it is held: no-tenant-id | name-unknown | ambiguous-name |
    -- name-already-mapped | offboarded-tenant | autocreate-limit |
    -- instance-disabled | store-failed (the closed set lives in
    -- instances.quarantine.REASONS).
    reason               TEXT NOT NULL,
    -- The vendor envelope as JSON text, bounded (see quarantine.MAX_PAYLOAD_BYTES).
    payload              TEXT NOT NULL,
    payload_truncated    INTEGER NOT NULL DEFAULT 0 CHECK (payload_truncated IN (0,1)),
    payload_sha256       TEXT NOT NULL,
    -- The adapter's headline for the payload, cleaned + bounded, so the review
    -- list can say what a held event IS without rendering the payload.
    event_summary        TEXT,
    routed_to_slug       TEXT,
    routed_at            TEXT,
    routed_by            TEXT,
    discarded_at         TEXT,
    discarded_by         TEXT,
    discard_reason       TEXT,
    UNIQUE (adapter_instance_id, payload_sha256)
);

CREATE INDEX IF NOT EXISTS idx_quarantine_instance_received
    ON quarantine(adapter_instance_id, received_at);
CREATE INDEX IF NOT EXISTS idx_quarantine_open
    ON quarantine(adapter_instance_id, id)
    WHERE routed_at IS NULL AND discarded_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_quarantine_vendor_tenant
    ON quarantine(adapter_instance_id, vendor_tenant_id);

PRAGMA user_version = 33;
