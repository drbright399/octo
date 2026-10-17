"""Retention enforcement — the part that never existed before migration 036.

  policy     the data-class catalogue + which retention actually applies
             (bundle config, per-tenant override, legal-baseline floor)
  archive    the cold archive for raw telemetry (gzip JSONL per tenant per
             UTC day under OCTO_ARCHIVE_ROOT, checksummed; encrypted parts +
             a row-id ledger when encryption is on)
  archive_crypto
             the archive's encryption: age v1 / X25519 to the operator's
             public keys (OCTO_ARCHIVE_ENCRYPTION, OCTO_ARCHIVE_RECIPIENTS_PATH);
             the private key stays off the machine
  move       telemetry-class rows out of events.db into telemetry.db (the
             one-off backfill and the nightly sweep)
  evidence   evidence windows (Tier Black, 044): what of a tenant lies
             between a confirmed threat's first detection and its
             all-clear is kept by every path above until an admin releases
             the window
  job        the per-tenant, per-class enforcement run (dry-run or enforce)
  scheduler  the in-app nightly trigger
"""
