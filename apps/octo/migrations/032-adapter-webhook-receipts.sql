-- Migration 032: inbound-webhook receipt bookkeeping, per adapter instance.
--
-- A vendor's "test webhook" answered 403 to the operator although the request
-- never reached this platform: something in FRONT of the ingest hostname
-- blocked it. The webhook routes never answer 403, but nothing in the product
-- said "no webhook has ever reached me", so the failure read as the product's
-- fault.
--
-- This table is what lets an integration card say "never" TRUTHFULLY — i.e.
-- across restarts: when a webhook for the instance was last accepted, and
-- when one last reached the route but was rejected (plus a coarse reason
-- class: bad_token / replay_window / malformed / unmapped / rate_limited /
-- not_configured / store_failed — never request content, never a credential).
--
-- Written by `instances.webhook_receipt` from a background flusher, at most
-- once per flush interval however many requests arrive: rejected requests
-- come from the open internet, so they must never cost a write each. Counts
-- are deliberately NOT stored here — they live in memory ("since the service
-- last started"), where a flood cannot amplify into disk writes.
--
-- Vendor-neutral: one row per adapter instance, whatever the vendor. Rows of
-- disabled instances are kept (history); a replacement instance has a new id
-- and therefore starts at "never".

-- @target: registry

CREATE TABLE IF NOT EXISTS adapter_webhook_receipts (
    adapter_instance_id   INTEGER PRIMARY KEY,
    first_accepted_at     TEXT,
    last_accepted_at      TEXT,
    last_rejected_at      TEXT,
    last_reject_reason    TEXT,
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

PRAGMA user_version = 32;
