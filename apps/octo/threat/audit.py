"""Audit rows for the tier engine and the incident routes — the global
hash-chained audit log (`auth.audit`), `client_slug` = the tenant (every
router's practice; the design's "per-tenant audit.db" is not what the code
base writes to). The engine's own rows name the system actor
`system:tier-engine` (`actor_kind="system"`).

Audit BEFORE write: a route appends its row first and only then changes the
record; a change that fails after its row appends `<action>_failed`.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from apps.octo import paths
from apps.octo.auth import audit
from apps.octo.db import connect

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system:tier-engine"


def append(*, actor: str, actor_kind: str, action: str, slug: str, target_kind: str,
           target_id: Optional[str], before: Any = None, after: Any = None,
           reason: Optional[str] = None, request_id: Optional[str] = None) -> int:
    """Append one row; raises on failure (a route must not write what it
    could not audit)."""
    g = connect(paths.global_audit_db_path())
    try:
        return audit.append(g, audit.AuditEntry(
            actor=actor, actor_kind=actor_kind, action=action, target_kind=target_kind,
            target_id=target_id, client_slug=slug, before_state=before, after_state=after,
            reason=reason, request_id=request_id or str(uuid.uuid4())))
    finally:
        g.close()


def human(operator_id: int, action: str, slug: str, target_kind: str,
          target_id: Optional[str], *, before: Any = None, after: Any = None,
          reason: Optional[str] = None) -> int:
    return append(actor=str(operator_id), actor_kind="human", action=action, slug=slug,
                  target_kind=target_kind, target_id=target_id, before=before, after=after,
                  reason=reason)


def system(action: str, slug: str, target_kind: str, target_id: Optional[str], *,
           after: Any = None, reason: Optional[str] = None,
           request_id: Optional[str] = None) -> Optional[int]:
    """The engine's row. Never raises (a page or a pass never fails for its
    audit row; the failure is logged)."""
    try:
        return append(actor=SYSTEM_ACTOR, actor_kind="system", action=action, slug=slug,
                      target_kind=target_kind, target_id=target_id, after=after,
                      reason=reason, request_id=request_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("[tier-engine] audit row %s for %s not written (%s)", action, slug,
                     type(exc).__name__)
        return None
