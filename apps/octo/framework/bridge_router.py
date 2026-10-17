"""FastAPI router exposing the BridgeServer Protocol over HTTP.

Per ADR-004. This is the network surface that Athena Console calls when
it needs data from OCTO. The router itself is a thin wrapper — all of
the invariant enforcement + audit logging lives in BridgeServerImpl.

Three endpoints under `/bridge/v1`:

  - GET  /health  — no auth; verifies the bridge is reachable.
  - POST /execute — auth required; runs a template + returns rows.
  - GET  /audit   — auth required; role-scoped audit-log read.

Auth is bearer-token via the `Authorization: Bearer <token>` header.
The router does NOT validate tokens itself — it delegates to a
`BearerTokenResolver` that production wires to the Athena auth-core
session store. Tests can use the `StaticTokenResolver` stub.

Errors map to HTTP status per the bridge contract:
  - Invariant 1 (closed registry / param shape)          → 400 / 404
  - Invariant 3 (role insufficient / tenant retargeting) → 403
  - Invariant 4 (session invalid)                        → 401
  - Invariant 5 (cross-tenant leak)                      → 500
"""

from __future__ import annotations

from typing import Any, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from shared_bridge import (
    BRIDGE_CONTRACT_VERSION,
    AuditLogEntry,
    InvariantViolation,
    SessionContext,
)

from apps.octo.framework.bridge_server import BridgeServerImpl


# ---------------------------------------------------------------------------
# Token resolution
# ---------------------------------------------------------------------------

class BearerTokenResolver(Protocol):
    """Maps a bearer token string to a SessionContext.

    Production wires this to the Athena Console auth-core session store
    (per ADR-003). Tests use StaticTokenResolver to inject canned sessions.
    """

    def resolve(self, token: str) -> SessionContext | None:
        """Return the session for this token, or None if invalid / expired."""
        ...


class StaticTokenResolver:
    """In-memory resolver. Suitable for tests + local dev."""

    def __init__(self, sessions: dict[str, SessionContext] | None = None) -> None:
        self._sessions = dict(sessions or {})

    def add(self, token: str, session: SessionContext) -> None:
        self._sessions[token] = session

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)

    def resolve(self, token: str) -> SessionContext | None:
        return self._sessions.get(token)


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    """POST /bridge/v1/execute body."""

    template_id: str = Field(..., description="Registered query template id.")
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Template parameters; shape validated server-side.",
    )


class ExecuteResponse(BaseModel):
    """POST /bridge/v1/execute response body."""

    template_id: str
    rows: list[dict[str, Any]]
    row_count: int
    elapsed_ms: float
    audit_entry_id: int


class AuditLogEntryDTO(BaseModel):
    """One audit log entry, serialized for HTTP response."""

    timestamp: str
    operator_id: int
    operator_role: str
    session_id: str
    session_tenant: str
    template_id: str
    params_hash: str
    result_row_count: int
    elapsed_ms: float
    accepted: bool
    rejection_reason: str | None = None
    cross_tenant_access: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_entry(cls, entry: AuditLogEntry) -> AuditLogEntryDTO:
        return cls(
            timestamp=entry.timestamp,
            operator_id=entry.operator_id,
            operator_role=entry.operator_role,
            session_id=entry.session_id,
            session_tenant=entry.session_tenant,
            template_id=entry.template_id,
            params_hash=entry.params_hash,
            result_row_count=entry.result_row_count,
            elapsed_ms=entry.elapsed_ms,
            accepted=entry.accepted,
            rejection_reason=entry.rejection_reason,
            cross_tenant_access=entry.cross_tenant_access,
            extra=dict(entry.extra),
        )


class AuditLogResponse(BaseModel):
    """GET /bridge/v1/audit response."""

    entries: list[AuditLogEntryDTO]
    count: int


class HealthResponse(BaseModel):
    """GET /bridge/v1/health response."""

    ok: bool = True
    contract_version: str = BRIDGE_CONTRACT_VERSION


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------

def create_bridge_router(
    *,
    server: BridgeServerImpl,
    token_resolver: BearerTokenResolver,
) -> APIRouter:
    """Return a FastAPI APIRouter wired to `server` + `token_resolver`.

    Mount under any FastAPI app:

        app.include_router(create_bridge_router(server=..., token_resolver=...))

    The factory pattern keeps the dependencies explicit per-router, so
    multiple bridge servers (e.g., one per OCTO data shard in a future
    sharded deployment) can each get their own router with their own
    server + resolver pairing.
    """
    router = APIRouter(prefix="/bridge/v1", tags=["bridge"])
    bearer = HTTPBearer(auto_error=False)

    # ------------------------------------------------------------------
    # Auth dependency — bearer token → SessionContext
    # ------------------------------------------------------------------

    def _resolve_session(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> SessionContext:
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing Authorization: Bearer header",
            )
        session = token_resolver.resolve(credentials.credentials)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired token",
            )
        # Defense in depth: ask the server to validate too. validate_session
        # also writes an audit row, so probing tokens leaves a forensic
        # trail per invariant 4.
        if not server.validate_session(session):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="session validation failed",
            )
        return session

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    @router.get(
        "/health",
        response_model=HealthResponse,
        summary="Liveness check (no auth)",
    )
    def health() -> HealthResponse:
        return HealthResponse()

    @router.post(
        "/execute",
        response_model=ExecuteResponse,
        summary="Execute a registered query template",
    )
    def execute(
        body: ExecuteRequest,
        request: Request,  # noqa: ARG001 — reserved for future correlation-id wiring
        session: SessionContext = Depends(_resolve_session),
    ) -> ExecuteResponse:
        try:
            result = server.execute_template(session, body.template_id, body.params)
        except InvariantViolation as exc:
            raise _http_error_from_invariant(exc, body.template_id) from exc

        return ExecuteResponse(
            template_id=result.template_id,
            rows=result.rows,
            row_count=result.row_count,
            elapsed_ms=result.elapsed_ms,
            audit_entry_id=result.audit_entry_id,
        )

    @router.get(
        "/audit",
        response_model=AuditLogResponse,
        summary="Role-scoped audit log read",
    )
    def audit(
        session: SessionContext = Depends(_resolve_session),
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> AuditLogResponse:
        # Cap operator-supplied limit so a single call can't drain the table
        capped_limit = max(1, min(limit, 1000))
        entries = server.get_audit_log_scoped(
            session,
            session_id=session_id,
            operator_id=operator_id,
            tenant=tenant,
            since=since,
            limit=capped_limit,
        )
        dtos = [AuditLogEntryDTO.from_entry(e) for e in entries]
        return AuditLogResponse(entries=dtos, count=len(dtos))

    return router


# ---------------------------------------------------------------------------
# Invariant → HTTP status mapping
# ---------------------------------------------------------------------------

def _http_error_from_invariant(
    exc: InvariantViolation,
    template_id: str,
) -> HTTPException:
    """Translate an InvariantViolation into the contractually correct HTTP error."""
    msg = str(exc)
    detail = {
        "invariant": exc.invariant_number,
        "message": msg,
        "template_id": template_id,
    }

    if exc.invariant_number == 1:
        # Two flavors: not registered vs param shape mismatch
        if "not registered" in msg:
            return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    if exc.invariant_number == 3:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
    if exc.invariant_number == 4:
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)
    if exc.invariant_number == 5:
        # Cross-tenant leak is a server-side bug, not user error
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail,
        )
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail,
    )
