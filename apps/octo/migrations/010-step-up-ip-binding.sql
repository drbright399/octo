-- ============================================================================
-- Migration 010 — add IP-prefix binding to step-up auth.
--
-- Defense-in-depth against stolen-session-cookie attacks. When an
-- operator re-authenticates for /search/*, we record the network prefix
-- the request came from (/24 IPv4 or /48 IPv6 by default). Subsequent
-- /search/* requests must come from a matching prefix or the step-up
-- window is revoked and the operator is forced to re-auth.
--
-- The binding mode is env-configurable: strict | subnet | off (see
-- SEARCH_STEP_UP_IP_BINDING in apps/octo/auth/step_up.py).
--
-- New column on sessions:
--   step_up_auth_ip_prefix  — canonical network prefix string at the
--                              time of /elevate. NULL if not elevated OR
--                              the bundle is configured with mode=off.
--                              Examples:
--                                "198.51.100.0/24"
--                                "203.0.113.42/32"   (strict mode)
--                                "2001:db8:1::/48"
--
-- Idempotency: ADD COLUMN — same pattern as the prior ALTER TABLE
-- migrations.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- @target: registry

ALTER TABLE sessions ADD COLUMN step_up_auth_ip_prefix TEXT;

PRAGMA user_version = 10;
