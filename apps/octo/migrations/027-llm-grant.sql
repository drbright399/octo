-- Migration 027: per-operator L2 LLM access grant.
--
-- Adds operators.l2_llm_granted. Set by admins/super_admins/factory
-- via the tier rule (a tier-up actor grants/revokes for a tier-down
-- target). The operator's own l2_llm_enabled preference (added by
-- migration 025) is INDEPENDENT — the operator can disable their
-- own access even when granted.
--
-- Bridge gate logic on /api/v1/agent-query:
--   1. operator.l2_llm_granted  must be 1  (admin granted)
--   2. operator.preferences.l2_llm_enabled must be true  (operator opted in)
--   3. bundle_config.l2_llm_enabled must be true  (bundle-wide enabled)
--   4. octo-llm /v1/healthz must return 200
--
-- All four must pass. Any single false → fail-closed to heuristic
-- only with an audit row.
--
-- Backfill policy (Rick's call 2026-05-21):
--   factory super_admin   → granted=1
--   any other super_admin → granted=0 (factory must grant explicitly)
--   admin                 → granted=0 (super_admin must grant)
--   analyst / viewer      → granted=0 (admin+ must grant)
--
-- This makes pool consumption strictly opt-in. New operators land
-- with granted=0 and must be granted access by a tier-up admin.
-- Existing operators (including the dev-admin from slice 5b
-- testing) follow the same default and get granted via the
-- normal flow.
--
-- Banked 2026-05-21 as slice 5d-2.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators ADD COLUMN l2_llm_granted INTEGER NOT NULL DEFAULT 0
    CHECK (l2_llm_granted IN (0, 1));

-- Backfill: factory super_admin gets implicit grant. They can grant
-- the next tier down themselves once they sign in.
UPDATE operators SET l2_llm_granted = 1 WHERE is_factory = 1;

PRAGMA user_version = 27;
