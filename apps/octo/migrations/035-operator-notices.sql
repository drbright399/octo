-- Migration 035: v0.10 — telling the OTHER admins when one person applied a
-- consequential tenant change alone (the attested single-person merge and
-- offboard, v0.10 item 7), and recording whether the e-mail copy went out.
--
-- operator_notices — one row per (change, recipient):
--   recipient_id       an admin+ operator other than the actor, active and not
--                      removed when the change was applied. A notice is shown
--                      to its recipient on every console load until THEY
--                      acknowledge it (acknowledged_at; the acknowledgement is
--                      audited).
--   kind               single_attested_merge | single_attested_offboard.
--   change_request_id  the tenant_change_requests row (approval_mode
--                      'single_attested') that recorded the change.
--   title / body       plain text the SERVER writes: who, what, which tenants,
--                      when. Never the typed attestation (it lives on the
--                      change record), never a credential.
--   email_state        pending → sent | failed | not_configured | no_address.
--                      The e-mail copy goes out after the change committed,
--                      only through a configured Resend integration; its
--                      outcome per recipient lands here and in one audit row.
-- Rows are created INSIDE the registry transaction that applies the change,
-- under a savepoint: a committed single-person change always has its notices,
-- and a failure to create them never rolls the change back (the failure is
-- recorded in the change's audit marker instead).

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS operator_notices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id        INTEGER NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    kind                TEXT NOT NULL
                          CHECK (kind IN ('single_attested_merge','single_attested_offboard')),
    actor_id            INTEGER NOT NULL,
    subject_slug        TEXT NOT NULL,
    target_slug         TEXT,
    change_request_id   INTEGER REFERENCES tenant_change_requests(id) ON DELETE SET NULL,
    title               TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    body                TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 2000),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    acknowledged_at     TEXT,
    email_state         TEXT NOT NULL DEFAULT 'pending'
                          CHECK (email_state IN
                            ('pending','sent','failed','not_configured','no_address')),
    email_attempted_at  TEXT,
    request_id          TEXT NOT NULL,
    UNIQUE (recipient_id, change_request_id)
);

CREATE INDEX IF NOT EXISTS idx_operator_notices_open
    ON operator_notices(recipient_id, id) WHERE acknowledged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_operator_notices_change
    ON operator_notices(change_request_id);

PRAGMA user_version = 35;

COMMIT;
