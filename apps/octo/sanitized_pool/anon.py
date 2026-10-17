"""M6 — k-anonymity read-side filter.

A pattern surfaces in cross-tenant queries only when at least `k`
distinct tenants have contributed it. `k` is configurable per-bundle
via `bundle_config.sanitized_pool_k_anonymity` (default = 3).

Why:
  With k=1 (no threshold), an operator who sees pattern X in the
  cross-tenant pool knows at least ONE other tenant saw it — and via
  timing or sequencing of their own contributions, can probabilistically
  attribute X to a specific tenant. With k=3 the privacy floor is
  materially higher: an attacker observing a pattern can't reduce the
  attribution to fewer than 3 tenants.

Where this applies:
  This is a READ-SIDE control. The pool tables continue to store all
  entries regardless of k; the gate runs on every cross-tenant query
  result. The read path counts `len(pool_row.tenant_hmacs)` and drops
  rows below the threshold.

Sister to §11.1 DP noise: noise hides EXACT counts; k-anonymity hides
LOW counts entirely. Both layers compose — first the k-anonymity gate
removes below-threshold rows from the result set, then noise is
applied to the surviving aggregate counts.

What this module DOESN'T do:
  - Anonymize patterns above the threshold further. Above k, the
    individual tenant_hmacs are still present in the row; cross-tenant
    aggregate joins work normally.
  - Apply to per-tenant queries. A tenant querying their OWN events.db
    is not gated by k (they're not crossing tenant boundaries).
  - Configure the threshold itself. That's handled by the bundle_config
    surface (Settings → System → Sanitized Pool → k threshold), which
    edits the row this module reads.

Banked 2026-05-21 closing the read-side substrate alongside §11.1.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Optional


# Default k-anonymity threshold. Operator can override via
# bundle_config; the override is read at query time via
# `load_k_threshold()`. v0 default = 3 per the safety envelope.
DEFAULT_K = 3

# bundle_config key for the override.
BUNDLE_CONFIG_KEY = "sanitized_pool_k_anonymity"


@dataclass(frozen=True)
class KConfig:
    """Resolved k-anonymity configuration for a query."""
    k: int
    source: str  # "default" | "bundle_config" — for audit visibility


def load_k_threshold(
    registry_conn: sqlite3.Connection,
    *,
    default: int = DEFAULT_K,
) -> KConfig:
    """Read the k-anonymity threshold from bundle_config.

    Falls back to `default` (DEFAULT_K=3) when:
      - the bundle_config table doesn't exist yet (pre-migration 022)
      - no row exists for the key
      - the JSON value is malformed (we don't trust a typoed config to
        accidentally weaken privacy; fall back loud-and-conservatively
        to the default)

    Returns KConfig with the resolved value + source label so query
    audit rows can record whether the override was active.
    """
    try:
        row = registry_conn.execute(
            "SELECT value_json FROM bundle_config WHERE key = ?",
            (BUNDLE_CONFIG_KEY,),
        ).fetchone()
    except sqlite3.OperationalError:
        return KConfig(k=default, source="default")
    if row is None:
        return KConfig(k=default, source="default")
    try:
        parsed = json.loads(row[0] if not hasattr(row, "keys") else row["value_json"])
    except (json.JSONDecodeError, TypeError):
        return KConfig(k=default, source="default")
    val = parsed.get("k") if isinstance(parsed, dict) else None
    if not isinstance(val, int) or val < 1:
        # Reject sub-1 thresholds — k=0 would defeat the control entirely,
        # negative is meaningless. Fall back to safer default.
        return KConfig(k=default, source="default")
    return KConfig(k=val, source="bundle_config")


def passes_k_anonymity(
    distinct_tenant_count: int,
    *,
    k: int = DEFAULT_K,
) -> bool:
    """Return True iff the pattern's distinct-tenant count meets the
    threshold. The most basic gate; callers normally combine with
    `filter_rows()` below."""
    if not isinstance(distinct_tenant_count, int):
        raise TypeError(
            f"distinct_tenant_count must be int (got {type(distinct_tenant_count)})",
        )
    if k < 1:
        raise ValueError(f"k must be >= 1 (got {k})")
    return distinct_tenant_count >= k


def filter_rows(
    rows: Iterable[dict],
    *,
    k: int = DEFAULT_K,
    count_field: str = "distinct_tenant_count",
) -> list[dict]:
    """Filter an iterable of pool-row dicts to those passing the
    k-anonymity gate.

    Each row must carry the `count_field` key (default
    `distinct_tenant_count`). Rows missing the field are treated as
    distinct_tenant_count=0 — meaning they're dropped by any k>=1.
    This is the safe-by-default behavior (a row whose tenant count is
    unknown is treated as below threshold).
    """
    if k < 1:
        raise ValueError(f"k must be >= 1 (got {k})")
    out = []
    for row in rows:
        count = row.get(count_field, 0)
        if not isinstance(count, int):
            # Same defensive default as missing-field — treat
            # malformed counts as below-threshold.
            continue
        if count >= k:
            out.append(row)
    return out


def compute_distinct_tenant_count(tenant_hmacs_json: Optional[str]) -> int:
    """Helper for read paths: given the `patterns.tenant_hmacs` column
    (a JSON array of HMAC hex strings), return the count of distinct
    contributing tenants.

    Safe against:
      - NULL / None
      - empty string
      - malformed JSON (returns 0)
      - non-array JSON (returns 0)
    """
    if not tenant_hmacs_json:
        return 0
    try:
        parsed = json.loads(tenant_hmacs_json)
    except json.JSONDecodeError:
        return 0
    if not isinstance(parsed, list):
        return 0
    # Use set() to dedupe in case the writer accidentally inserted
    # duplicates (defense in depth — the extractor should already
    # dedupe, but the gate doesn't trust upstream invariants).
    return len(set(parsed))
