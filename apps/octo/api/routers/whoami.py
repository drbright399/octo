"""GET /api/v1/whoami — bearer-introspection.

Accepts ANY valid bearer (admin OR buoy/service ingestion token). Returns the
resolved identity in a unified shape. Used by:

- Buoy forwarder v2 startup probe (asserts OCTO_SLUG matches bearer's slug)
- Athena Console session middleware (Phase G.1) for "who am I"
- Any external tooling that needs to verify a token without performing an
  ingestion or admin write

Returns 401 (AUTH_INVALID) if the bearer is missing/malformed/unrecognized.
Bearer-authenticated; no admin scope required (any valid token works).
Rate-limited under `admin_read` (cheap call).

Added 2026-04-26 (Phase F.1 prerequisite + Phase G.1 building block).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header
from pydantic import BaseModel

from apps.octo.auth import core as core_auth
from apps.octo import paths
from apps.octo.api.auth_helpers import _extract_bearer
from apps.octo.api.errors import APIError
from apps.octo.db import connect


router = APIRouter()


class WhoamiResult(BaseModel):
    """Unified identity returned by /whoami.

    Exactly one of (operator vs token) is meaningful per response:
      - admin token  → kind='admin', operator_id+username+email+scope_slugs set
      - buoy token   → kind='buoy',  slug+token_id+label set
      - service token → kind='service', slug+token_id+label set
    """
    kind: str                    # 'admin' | 'buoy' | 'service'
    # Admin-token fields:
    operator_id: Optional[int] = None
    username: Optional[str] = None
    email: Optional[str] = None
    scope_slugs: Optional[list[str]] = None
    # Buoy/service-token fields:
    slug: Optional[str] = None
    token_id: Optional[int] = None
    label: Optional[str] = None


@router.get("/whoami", response_model=WhoamiResult, tags=["whoami"])
def whoami(authorization: Optional[str] = Header(default=None)) -> WhoamiResult:
    """Resolve any valid bearer to its identity. 401 on invalid bearer."""
    token = _extract_bearer(authorization)
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        # Try admin-token resolution first.
        try:
            row = core_auth.resolve_admin_token(reg, token)
        except core_auth.AuthError:
            row = None

        if row is not None:
            # Admin token. Collect scope_slugs from operator_roles.
            import json as _json
            role_rows = reg.execute(
                "SELECT scope_slugs FROM operator_roles WHERE operator_id = ?",
                (row["id"],),
            ).fetchall()
            scope: set[str] = set()
            for r in role_rows:
                for s in _json.loads(r["scope_slugs"]):
                    scope.add(s)
            return WhoamiResult(
                kind="admin",
                operator_id=row["id"],
                username=row["username"],
                email=row["email"],
                scope_slugs=sorted(scope),
            )

        # Not an admin token — try client (buoy/service) token resolution.
        try:
            resolution = core_auth.resolve_client_token(reg, token)
        except core_auth.AuthError:
            raise APIError("AUTH_INVALID")

        return WhoamiResult(
            kind=resolution.kind,
            slug=resolution.slug,
            token_id=resolution.token_id,
            label=resolution.label,
        )
    finally:
        reg.close()
