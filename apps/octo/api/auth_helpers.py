"""Bearer-auth dependencies for admin and ingestion routes.

Each returns a small dataclass with the resolved identity. FastAPI injects
them via `Depends(...)` on route signatures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, Request

from apps.octo.auth import core as core_auth
from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.db import connect


@dataclass(frozen=True)
class AdminIdentity:
    operator_id: int
    username: str
    email: str
    scope_slugs: list[str]

    def sees(self, slug: str) -> bool:
        return "*" in self.scope_slugs or slug in self.scope_slugs


@dataclass(frozen=True)
class IngestionIdentity:
    slug: str
    token_id: int
    kind: str
    label: str
    source_instance_id: Optional[str] = None


# NOTE 2026-05-11 (port from octo_admin):
# `SourceIngestionIdentity` + `source_ingestion_identity` were removed
# from this file during the port. They depend on the legacy
# `octo_admin.sources` module which hasn't been ported into the Phase 2
# framework yet — source ingestion will be re-implemented against the
# new adapter framework (`apps/octo/adapters/`) rather than ported
# verbatim. Re-add when the Wazuh / Graylog / etc. adapter pack lands.


def _extract_bearer(header_value: Optional[str]) -> str:
    if not header_value or not header_value.lower().startswith("bearer "):
        raise APIError("AUTH_MISSING")
    return header_value.split(None, 1)[1].strip()


def admin_identity(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> AdminIdentity:
    token = _extract_bearer(authorization)
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            row = core_auth.resolve_admin_token(reg, token)
        except core_auth.AuthError:
            raise APIError("AUTH_INVALID")
        # Collect scope slugs across all roles
        import json as _json
        role_rows = reg.execute(
            "SELECT scope_slugs FROM operator_roles WHERE operator_id = ?",
            (row["id"],),
        ).fetchall()
        scope: set[str] = set()
        for r in role_rows:
            for s in _json.loads(r["scope_slugs"]):
                scope.add(s)
        if not scope:
            # No roles assigned → cannot see any client
            scope = set()
    finally:
        reg.close()
    return AdminIdentity(
        operator_id=row["id"],
        username=row["username"],
        email=row["email"],
        scope_slugs=sorted(scope),
    )


def require_scope(identity: AdminIdentity, slug: str) -> None:
    if not identity.sees(slug):
        raise APIError("ISOLATION_VIOLATION",
                        f"token scope does not cover client {slug!r}")


def ingestion_identity(
    slug: str,
    authorization: Optional[str] = Header(default=None),
) -> IngestionIdentity:
    token = _extract_bearer(authorization)
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        try:
            resolution = core_auth.resolve_client_token(reg, token)
        except core_auth.AuthError:
            raise APIError("AUTH_INVALID")
    finally:
        reg.close()
    if resolution.slug != slug:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"token scope {resolution.slug!r} ≠ URL slug {slug!r}",
        )
    if resolution.kind not in {"buoy", "service"}:
        raise APIError("TOKEN_KIND_MISMATCH",
                        f"kind {resolution.kind!r} not permitted for ingestion")
    return IngestionIdentity(
        slug=resolution.slug,
        token_id=resolution.token_id,
        kind=resolution.kind,
        label=resolution.label,
        source_instance_id=resolution.source_instance_id,
    )


