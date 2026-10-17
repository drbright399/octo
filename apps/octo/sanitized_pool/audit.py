"""M4 — Dual-write audit wrapper for sanitized-pool operations.

Pool writes carry an audit footprint in BOTH:
  - The global audit chain (bridge invariant #5 — every cross-tenant
    write is globally accountable)
  - The contributing tenant's per-tenant audit chain (so the tenant
    can audit their own contributions independently of the global
    chain)

`pool_audit.append()` is the only function that should be called on a
pool write path. It enforces:

  1. Write to the global audit chain FIRST. This is the cross-tenant
     accountability record; if global fails, we abort the operation
     entirely — no tenant write, no pool write.
  2. Write to the per-tenant audit chain SECOND. If this fails AFTER
     the global succeeded, we append a compensating row to the
     global chain marking the first global row as orphaned. The
     hash-link integrity of the global chain is preserved (no row is
     ever rewritten or removed); reads of the global chain see the
     orphan-marker entry and know to ignore the original.
  3. Returns (global_id, tenant_id) on full success. Raises
     `PoolAuditError` on any failure.

What we deliberately do NOT do:
  - "Atomic" cross-database transactions. SQLite doesn't support
    them across files. Application-level compensation is the
    pragmatic alternative.
  - Silently swallowing failures. Caller must handle PoolAuditError;
    no quiet drops.
  - Anonymizing the tenant slug in the audit chain. The audit chain
    is internal-bundle context — the bundle's super_admin reads it
    for compliance reporting and needs the actual slug. Pool DATA
    tables get the HMAC (per M2); audit DBs get the slug. See
    `docs/design/sanitized-pool/m1-m9-safety-envelope.md` §5 for the
    rationale.

Banked 2026-05-21 closing out Section A of the safety envelope.
"""
from __future__ import annotations

import sqlite3
from dataclasses import replace
from typing import Optional

from apps.octo.auth import audit


class PoolAuditError(Exception):
    """Raised when a pool dual-write fails on either side.

    Attributes:
      stage — "global" (global write failed; nothing committed)
              "tenant" (tenant write failed AFTER global succeeded;
              compensating row was/was-not appended)
      cause — the original exception
      global_id_orphaned — set when stage == "tenant"; the global
              row id that was successfully written but is now
              orphaned (the compensating row references it)
      compensation_appended — bool; True if the orphan-marker row
              was successfully appended to global, False if even
              that compensating write failed
    """
    def __init__(
        self,
        message: str,
        *,
        stage: str,
        cause: Exception,
        global_id_orphaned: Optional[int] = None,
        compensation_appended: Optional[bool] = None,
    ):
        super().__init__(message)
        self.stage = stage
        self.cause = cause
        self.global_id_orphaned = global_id_orphaned
        self.compensation_appended = compensation_appended


def append(
    global_conn: sqlite3.Connection,
    tenant_conn: sqlite3.Connection,
    entry: audit.AuditEntry,
) -> tuple[int, int]:
    """Atomic-ish dual-write of `entry` to the global + per-tenant
    audit chains.

    Returns (global_id, tenant_id) on full success.

    Raises PoolAuditError if either side fails. On tenant-side
    failure, a compensating "tenant_write_failed" row is appended to
    the global chain so the original global row is observable as
    orphaned during reads. The error carries the orphaned id +
    whether compensation succeeded.
    """
    # Stage 1: global write.
    try:
        global_id = audit.append(global_conn, entry)
    except Exception as e:
        raise PoolAuditError(
            f"global audit write failed: {e}",
            stage="global", cause=e,
        ) from e

    # Stage 2: tenant write.
    try:
        tenant_id = audit.append(tenant_conn, entry)
        return global_id, tenant_id
    except Exception as tenant_exc:
        # Tenant failed AFTER global succeeded. The global row is now
        # orphaned — it represents a pool-write intent that was never
        # actually mirrored to the tenant chain. Append a compensating
        # row to global marking the orphan, then raise.
        compensated = False
        marker = replace(
            entry,
            action="pool_audit_tenant_failed",
            target_kind="audit_row",
            target_id=str(global_id),
            reason=(
                f"tenant audit write failed after global success; "
                f"original global row id={global_id} is orphaned. "
                f"Underlying error: {tenant_exc}"
            ),
            # `after_state` carries machine-readable details so a
            # reconciliation job can find the orphan + the failure
            # cause without parsing free-text reason.
            after_state={
                "orphaned_global_id": global_id,
                "tenant_error_type": type(tenant_exc).__name__,
            },
        )
        try:
            audit.append(global_conn, marker)
            compensated = True
        except Exception:  # noqa: BLE001
            # Compensation itself failed. We've lost the ability to
            # mark the orphan in the global chain. Raise with the
            # flag so callers know the chain may have a silent orphan
            # row. The chain is still hash-link-valid; we just have a
            # row that should be ignored on read but isn't marked.
            pass
        raise PoolAuditError(
            f"tenant audit write failed: {tenant_exc} "
            f"(global row {global_id} orphaned, "
            f"compensation={'appended' if compensated else 'ALSO FAILED'})",
            stage="tenant",
            cause=tenant_exc,
            global_id_orphaned=global_id,
            compensation_appended=compensated,
        ) from tenant_exc
