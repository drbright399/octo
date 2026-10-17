-- Migration 026: factory super_admin identifier.
--
-- Adds operators.is_factory so code paths can reliably gate
-- "factory super_admin only" actions (e.g., L2 LLM model
-- download/swap per slice 5d-3) without relying on username
-- comparison against the FACTORY_SUPER_ADMIN_USERNAME constant.
--
-- Why a column not username comparison:
--   The factory super_admin's username is "Root" by default but
--   the operator can be renamed via the regular operator-update
--   endpoint. A username string comparison silently breaks if
--   that happens. The column is set ONCE at first-init in
--   provision_factory_super_admin_if_empty() and never changes
--   thereafter. Renames are safe.
--
-- Backfill:
--   The operator whose username matches FACTORY_SUPER_ADMIN_USERNAME
--   ("Root") gets is_factory=1. All others stay at the default 0.
--   For new bundles this backfill is a no-op (no operators yet); for
--   already-deployed bundles it sets the flag on the existing
--   factory account without requiring a re-init.
--
-- v1 access control surfaces gating on is_factory:
--   - L2 LLM model add/swap/delete (slice 5d-3, this commit cycle)
--   - Future: factory-recovery + dual-control unlock + cred rotation
--
-- Banked 2026-05-21 as slice 5d-1.

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE operators ADD COLUMN is_factory INTEGER NOT NULL DEFAULT 0
    CHECK (is_factory IN (0, 1));

-- Backfill the existing factory account (idempotent — sets the flag on
-- the operator whose username is the well-known factory default).
UPDATE operators SET is_factory = 1 WHERE username = 'Root';

CREATE INDEX IF NOT EXISTS idx_operators_is_factory
    ON operators(is_factory) WHERE is_factory = 1;

PRAGMA user_version = 26;
