"""Sanitization router — M3 surface for `sanitization_rejects`.

Two endpoints, two gating tiers:

  GET /api/v1/admin/sanitization/rejects
      Super_admin only. Returns raw reject rows (including the
      `source_tenant_hmac`, `raw_excerpt`, `reason_code`). Used for
      forensic investigation when a tenant reports false positives
      or when audit-ing the extractor's behavior.

  GET /api/v1/dashboard/sanitization/reject-counts
      Analyst+ scope. Returns AGGREGATE counts per `reason_code` over
      a time window. No per-tenant or per-IOC content leaks — just
      `{reason_code: count}` distribution. Used for operator-facing
      dashboards to monitor pool health.

The gating split is the M3 control from the safety envelope: raw
rejects are deanonymization-adjacent (raw_excerpt may contain
attacker-injected content that reveals source tenant via timing /
content shape), so they sit behind super_admin. Aggregate counts
are sanitized into a fixed enum and safe to expose more broadly.

Banked 2026-05-21 with migration 023.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.role_gates import session_analyst_plus, session_super_admin
from apps.octo.api.routers.auth import _audit_append
from apps.octo.auth import sessions
from apps.octo.db import connect


router = APIRouter(prefix="", tags=["sanitization"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class RejectRow(BaseModel):
    """A single sanitization-reject row. Super_admin only."""
    id: int
    rejected_at: str                       # ISO-8601 UTC
    reason_code: Optional[str]             # M1 reason_code (e.g. "url_invalid_chars")
    reason: Optional[str]                  # legacy free-text reason; superseded by reason_code
    raw_excerpt: str                       # ≤ 200 chars
    source_tenant_hmac: Optional[str]      # 64-char HMAC; None on legacy rows pre-023
    source_slug: Optional[str]             # plaintext slug (LEGACY; only on rows
                                           # written before migration 023). Will be
                                           # dropped by a cleanup migration once
                                           # the extractor consistently writes
                                           # the HMAC column.
    hmac_version: Optional[str]            # which HMAC secret version produced
                                           # the source_tenant_hmac, for rotation
                                           # tracking


class RejectsResponse(BaseModel):
    """Super_admin raw-rejects response."""
    rejects: list[RejectRow]
    total_returned: int
    window_hours: int


class RejectCount(BaseModel):
    """Aggregate count for one reason_code over the queried window."""
    reason_code: str
    count: int


class RejectCountsResponse(BaseModel):
    """Analyst+ aggregate response. NO per-tenant or per-IOC data."""
    counts: list[RejectCount]
    total: int
    window_hours: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# Hard cap on raw-rejects pagination so a super_admin query can't
# accidentally pull millions of rows + lock up the API process.
_MAX_RAW_LIMIT = 500


@router.get("/admin/sanitization/rejects", response_model=RejectsResponse)
def list_rejects(
    window_hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=100, ge=1, le=_MAX_RAW_LIMIT),
    info: sessions.SessionInfo = Depends(session_super_admin),
) -> RejectsResponse:
    """Raw rejects view — super_admin only.

    Returns the most recent N reject rows from the last `window_hours`
    hours. Includes the per-row tenant_hmac (NOT plaintext source slug,
    except on legacy rows from before migration 023) and the
    truncated raw_excerpt for forensic context.

    Audited per call, empty or not (docs/audit-policy.md: raw excerpts
    on demand are a sensitive read, and nothing polls this route).
    """
    p = paths.patterns_db_path()
    rows: list = []
    if p.exists():
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
        conn = connect(p, read_only=True)
        try:
            rows = conn.execute(
                """
                SELECT id, rejected_at, reason_code, reason, raw_excerpt,
                       source_tenant_hmac, source_slug, hmac_version
                  FROM sanitization_rejects
                 WHERE rejected_at >= ?
                 ORDER BY id DESC
                 LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        finally:
            conn.close()
    _audit_append(
        "sanitization.rejects_fetch",
        actor=f"operator:{info.operator_id}",
        target_id=None,
        before=None,
        after={"window_hours": window_hours, "limit": limit,
               "returned": len(rows), "session_id_prefix": info.id[:8]},
        reason="super_admin raw sanitization rejects view",
        request_id=str(uuid.uuid4()),
    )
    return RejectsResponse(
        rejects=[
            RejectRow(
                id=r["id"],
                rejected_at=r["rejected_at"],
                reason_code=r["reason_code"],
                reason=r["reason"],
                raw_excerpt=r["raw_excerpt"],
                source_tenant_hmac=r["source_tenant_hmac"],
                source_slug=r["source_slug"],
                hmac_version=r["hmac_version"],
            )
            for r in rows
        ],
        total_returned=len(rows),
        window_hours=window_hours,
    )


@router.get(
    "/dashboard/sanitization/reject-counts",
    response_model=RejectCountsResponse,
)
def reject_counts(
    window_hours: int = Query(default=24, ge=1, le=168),
    _info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> RejectCountsResponse:
    """Aggregate reject counts per reason_code — analyst+ scope.

    No per-tenant data; no raw content. Just counts grouped by the
    stable enum reason_code values produced by
    `apps.octo.sanitized_pool.shapes`. Operators use this to monitor
    pool ingestion health.
    """
    p = paths.patterns_db_path()
    if not p.exists():
        return RejectCountsResponse(counts=[], total=0, window_hours=window_hours)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    conn = connect(p, read_only=True)
    try:
        rows = conn.execute(
            """
            SELECT COALESCE(reason_code, reason) AS rc, COUNT(*) AS n
              FROM sanitization_rejects
             WHERE rejected_at >= ?
             GROUP BY rc
             ORDER BY n DESC
            """,
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()
    counts = [
        RejectCount(reason_code=r["rc"] or "unknown", count=r["n"]) for r in rows
    ]
    total = sum(c.count for c in counts)
    return RejectCountsResponse(
        counts=counts, total=total, window_hours=window_hours,
    )
