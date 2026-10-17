"""Sanitized cross-tenant pattern pool.

The pool holds indicator-of-compromise patterns extracted from per-
tenant events, with each contributing tenant's identity replaced by a
per-bundle HMAC so cross-tenant aggregates can be computed without
revealing source-tenant identity.

This package implements the M1-M9 safety envelope documented at
`docs/design/sanitized-pool/m1-m9-safety-envelope.md`. Each control
lives in its own submodule:

  - identity.py  → M2: HMAC-per-bundle secret + tenant_hmac() helper
  - shapes.py    → M1+M7+M8: pattern-shape validators + URL canon
                   + YARA reject
  - audit.py     → M4: pool_audit.append() dual-write wrapper
  - rejects.py   → M3: sanitization_rejects gating + aggregate API
  - noise.py     → §11.1: Laplace frozen-noise DP for public reads
                   (queued — pre-LLM-consumer build moment)

The runtime extractor (which writes into the pool) does NOT yet
exist — this package is the safety substrate that gates it.
"""
