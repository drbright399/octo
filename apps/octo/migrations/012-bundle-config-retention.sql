-- Migration 012: bundle_config.retention — super_admin-editable
-- retention timeframes per data class.
--
-- Surfaces what was previously hardcoded in
-- `apps/octo/api/routers/admin_data.py::RETENTION_DEFAULTS`. The
-- defaults still live there as the SEED + fallback; this migration
-- creates the persistence layer so super_admin can override.
--
-- Per `project_data_management_settings_panel` + the v2 directive
-- (2026-05-14): **defaults already match the regulator baseline** for
-- a regulated-MSP target (HIPAA/CJIS/GLBA/SOC2). Any super_admin edit
-- moves the bundle AWAY from the baseline and requires an
-- acknowledged-disclosure modal in the UI + an audit log entry
-- server-side.
--
-- Schema notes:
-- - Each data class gets one row keyed by its name.
-- - retention_days = NULL means "permanent / never delete" (only
--   valid for 'audit' — enforced server-side, not in SQL).
-- - 'audit' row is INSERTED with editable=0 (regulator requirement)
--   and the API layer rejects any PATCH targeting it.
-- - legal_baseline_days = the regulator-baseline value for this data
--   class. The UI compares the operator's pick against this so it
--   can color-code "below baseline" warnings.
-- - regulator_basis = short human-readable citation (HIPAA §164.530,
--   SOC2 CC7.2, etc.) so the disclosure modal can show *why* a value
--   is the baseline rather than asking the operator to trust the
--   number.
-- - Per-tenant overrides (some MSP tenants need stricter retention
--   than the bundle default) come in a follow-on via a separate
--   `bundle_config_retention_overrides` table; not in this migration.

PRAGMA user_version = 12;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- @target: registry

CREATE TABLE IF NOT EXISTS bundle_config_retention (
    data_class           TEXT PRIMARY KEY,
    retention_days       INTEGER,                       -- NULL = permanent
    legal_baseline_days  INTEGER,                       -- NULL = no fixed baseline (audit only)
    regulator_basis      TEXT NOT NULL DEFAULT '',
    editable             INTEGER NOT NULL DEFAULT 1
                            CHECK (editable IN (0, 1)),
    description          TEXT NOT NULL,
    updated_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_by           INTEGER                        -- operator_id; NULL = system seed
);

-- Seed at regulator-baseline values. INSERT OR IGNORE preserves any
-- prior super_admin edits, but on a freshly-migrated bundle the
-- shipping defaults match the legal floor for the target market.
INSERT OR IGNORE INTO bundle_config_retention
    (data_class, retention_days, legal_baseline_days, regulator_basis, editable, description, updated_by)
VALUES
    ('events',                 365,   365,
     'HIPAA §164.312(b); SOC2 CC7.2; CJIS §5.4.1',
     1,
     'Ingested events from all source adapters. Drives /search default window + dashboard widgets. 1-year baseline = HIPAA audit-log floor.',
     NULL),
    ('indicators_auto',        90,    90,
     'Operational baseline (no regulator citation)',
     1,
     'IOCs auto-extracted from ingested events. Transient enrichment — no regulator mandates retention; 90d aligns with the parent event window.',
     NULL),
    ('indicators_promoted',    2190,  2190,
     'HIPAA §164.530(j) — 6-year records retention',
     1,
     'IOCs an analyst has manually promoted. These become part of the incident record and inherit HIPAA''s 6-year retention floor.',
     NULL),
    ('secure_notepad',         90,    90,
     'Operational; consolidates into ticket on close',
     1,
     'Per-ticket secure notepad — ephemeral scratchpad. Consolidates into the ticket body at close; 90d post-close shred keeps the buffer tight.',
     NULL),
    ('audit',                  NULL,  NULL,
     'HIPAA §164.312(b); SOC2 CC4.1; SOX §404 — permanent',
     0,
     'Append-only audit chain. PERMANENT — regulator requirement. Not editable. Archive to cold storage when size becomes a concern.',
     NULL),
    ('agent_notes',            2190,  2190,
     'HIPAA §164.530(j) — analyst rationale = incident record',
     1,
     'Octo agent notes attached to events / tickets / indicators. Analyst rationale is part of the incident record under HIPAA''s 6-year floor.',
     NULL);
