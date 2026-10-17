-- Migration 048: RECALL an acknowledgement, and NOTES on it (v0.17.5; Rick,
-- 2026-10-08: he acknowledged a client's alerts, then learned the context —
-- a partner had removed the DNS agents on purpose — and could not go back to
-- add it: "A recall button/feature would be useful for exactly this
-- situation honestly.").
--
-- registry section
--   alert_verdict_followup  what was said AFTER an acknowledgement, one row
--                      per follow-up, never updated, never deleted (046's
--                      alert_verdict is append-only too — the ack row itself
--                      is never touched):
--                        'note'   additive context shown under the ack
--                                 (newest last); 1..500 characters. The
--                                 ack's own note is never edited.
--                        'recall' the ack no longer covers anything — its
--                                 alert (and the other rows of its vendor
--                                 alert, and its "repeats for 24 h") is back
--                                 in "needs attention" and counts towards
--                                 the site's colour again; a reason of at
--                                 least 10 characters. FINAL: one recall per
--                                 ack (acknowledging again = a NEW ack).
--                      A follow-up is always on an ACK ('confirmed' /
--                      'expected' labels take none: an expected RULE has its
--                      own revoke) of the SAME tenant.
--   NEVER REPLACED     (review fix) SQLite's REPLACE — `INSERT OR REPLACE`,
--                      `REPLACE INTO` — on an existing id removes the old
--                      row WITHOUT the delete trigger (recursive_triggers is
--                      off): a recall could be overwritten by a note and its
--                      ack cover the alert again. An insert that names an
--                      existing id is refused — here, and on 046's
--                      alert_verdict (the ack a recall hangs on) and
--                      expected_condition (a REPLACE would un-revoke a rule).
--                      No writer names an id; the triggers on 046's tables
--                      stay after a rollback (harmless: nothing before 048
--                      writes an id either).
--
-- A rollback keeps everything and a re-upgrade takes it back (046 / 047's
-- pattern): the table is LEFT AS IT IS (nothing before 048 reads it) and the
-- version goes back to 47; a re-upgrade finds it current — every recall
-- applies again. NOTE for the deployer: a release before 048 does not know
-- recalls — a recalled acknowledgement covers its alert again there
-- (`rollback_v0175.py` counts them).

PRAGMA foreign_keys = ON;

-- @target: registry

BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS alert_verdict_followup (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id  INTEGER NOT NULL REFERENCES alert_verdict(id),
    tenant_slug TEXT NOT NULL CHECK (length(tenant_slug) BETWEEN 1 AND 64),
    kind        TEXT NOT NULL CHECK (kind IN ('note', 'recall')),
    actor       INTEGER NOT NULL,
    at          TEXT NOT NULL CHECK (length(at) >= 19),
    -- A note says something; a recall says WHY (≥ 10 characters).
    text        TEXT NOT NULL CHECK (length(trim(text)) >= 1 AND length(text) <= 500),
    CHECK (kind <> 'recall' OR length(trim(text)) >= 10)
);
CREATE INDEX IF NOT EXISTS idx_alert_verdict_followup_verdict
    ON alert_verdict_followup(tenant_slug, verdict_id, at);
-- One recall per acknowledgement: a recall is final.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_verdict_followup_one_recall
    ON alert_verdict_followup(verdict_id) WHERE kind = 'recall';
-- Always on an ACK of the same tenant (a confirmed / expected label takes
-- none; a tenant never follows up another tenant's verdict).
CREATE TRIGGER IF NOT EXISTS alert_verdict_followup_on_an_ack
BEFORE INSERT ON alert_verdict_followup
WHEN NOT EXISTS (SELECT 1 FROM alert_verdict v WHERE v.id = NEW.verdict_id
                 AND v.verdict = 'ack' AND v.tenant_slug = NEW.tenant_slug)
BEGIN SELECT RAISE(ABORT, 'a follow-up is on an acknowledgement of the same tenant'); END;
CREATE TRIGGER IF NOT EXISTS alert_verdict_followup_recall_final
BEFORE INSERT ON alert_verdict_followup
WHEN NEW.kind = 'recall' AND EXISTS (SELECT 1 FROM alert_verdict_followup f
                                      WHERE f.verdict_id = NEW.verdict_id AND f.kind = 'recall')
BEGIN SELECT RAISE(ABORT, 'this acknowledgement is already recalled'); END;
CREATE TRIGGER IF NOT EXISTS alert_verdict_followup_no_delete
BEFORE DELETE ON alert_verdict_followup
BEGIN SELECT RAISE(ABORT, 'follow-ups are the history of a verdict: never deleted'); END;
CREATE TRIGGER IF NOT EXISTS alert_verdict_followup_no_update
BEFORE UPDATE ON alert_verdict_followup
BEGIN SELECT RAISE(ABORT, 'a recorded follow-up is never changed'); END;
-- Never REPLACEd (a REPLACE skips the delete trigger): an insert naming an
-- existing id is refused. (An insert that names no id sees NEW.id = -1.)
CREATE TRIGGER IF NOT EXISTS alert_verdict_followup_no_replace
BEFORE INSERT ON alert_verdict_followup
WHEN EXISTS (SELECT 1 FROM alert_verdict_followup f WHERE f.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'a recorded follow-up is never replaced'); END;
CREATE TRIGGER IF NOT EXISTS alert_verdict_no_replace
BEFORE INSERT ON alert_verdict
WHEN EXISTS (SELECT 1 FROM alert_verdict v WHERE v.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'a recorded verdict is never replaced'); END;
CREATE TRIGGER IF NOT EXISTS expected_condition_no_replace
BEFORE INSERT ON expected_condition
WHEN EXISTS (SELECT 1 FROM expected_condition c WHERE c.id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'an expected condition is never replaced'); END;

PRAGMA user_version = 48;

COMMIT;
