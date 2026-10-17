"""Bridge server runtime — implements the BridgeServer Protocol.

Per ADR-004 (bridge contract). The server sits inside
the `octo-core` container and receives bridge calls from the Athena Console.
Operator reads come through here; adapter writes use a different code path
(BridgeWriteCredential, service-bound, not implemented in this module).

Five mandatory invariants are enforced inline (see ADR-004 §`Five mandatory
invariants`):

1. Parameterized queries only — `enforce_template_registered()` rejects
   any template_id not in the closed registry.
2. Separate read/write credentials — this module ONLY accepts
   BridgeReadCredential-style sessions; writes have a separate code path.
3. Session-bound tenant_id — `enforce_session_tenant_match()` blocks
   mid-session retargeting; cross-tenant templates require admin/super_admin.
4. Per-query audit log — every accepted AND rejected query writes an
   AuditLogEntry before return.
5. Cross-tenant retrieval safety — `validate_no_cross_tenant_leak()` runs
   on rows returned from cross-tenant templates.

The actual SQL execution is pluggable via the `TemplateExecutor` Protocol
so tests can inject mock results and production can wire it to OCTO's
SQLite databases.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from shared_bridge import (
    AuditLogEntry,
    InvariantViolation,
    QueryResult,
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
    enforce_session_tenant_match,
    enforce_template_registered,
    validate_no_cross_tenant_leak,
)


# ---------------------------------------------------------------------------
# Pluggable executor + session validator + audit backend
# ---------------------------------------------------------------------------

class TemplateExecutor(Protocol):
    """Maps a registered QueryTemplate to actual rows.

    Production implementation runs parameterized SQL against the appropriate
    OCTO SQLite database (per-tenant per-source). Tests inject a stub.
    """

    def execute(
        self,
        template: QueryTemplate,
        params: dict[str, Any],
        session: SessionContext,
    ) -> list[dict[str, Any]]:
        """Run the template and return result rows.

        Implementations MUST honor template.requires_tenant_scope by filtering
        to session.session_tenant when True. Cross-tenant templates
        (requires_tenant_scope=False) handle their own scope, but their output
        is still validated by invariant 5.
        """
        ...


class SessionValidator(Protocol):
    """Validates that a SessionContext is still acceptable (not expired, not
    revoked). Implementation typically wraps the auth-core session store.

    For v1 in-process testing, an `AlwaysValidSessionValidator` ships below.
    """

    def is_valid(self, session: SessionContext) -> bool:
        ...


class AuditLogBackend(Protocol):
    """Persistence target for AuditLogEntry records.

    Production implementation persists to OCTO's bridge_audit.db with a
    hash-chained tamper-evidence layer (ADR-005 audit discipline). Tests use
    the in-memory backend.
    """

    def append(self, entry: AuditLogEntry) -> int:
        """Persist an entry; return its assigned audit_entry_id."""
        ...

    def query(
        self,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Filtered read of the audit log."""
        ...


class AlwaysValidSessionValidator:
    """Session validator that accepts every session. ONLY for tests + dev.

    Production wires the real auth-core session store via SessionValidator.
    """

    def is_valid(self, session: SessionContext) -> bool:  # noqa: ARG002
        return True


@dataclass
class _StoredAuditEntry:
    entry: AuditLogEntry
    audit_entry_id: int


class InMemoryAuditLogBackend:
    """In-memory audit backend. Suitable for tests + ephemeral dev runs.

    Production deployment uses a SQLite-backed implementation with a
    hash-chained tamper-evidence layer — that ships in a later phase
    (Gap G1 — Immutable WORM audit export, task #46).
    """

    def __init__(self) -> None:
        self._entries: list[_StoredAuditEntry] = []
        self._next_id: int = 1

    def append(self, entry: AuditLogEntry) -> int:
        audit_entry_id = self._next_id
        self._next_id += 1
        self._entries.append(_StoredAuditEntry(entry=entry, audit_entry_id=audit_entry_id))
        return audit_entry_id

    def query(
        self,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        results: list[AuditLogEntry] = []
        for stored in self._entries:
            e = stored.entry
            if session_id is not None and e.session_id != session_id:
                continue
            if operator_id is not None and e.operator_id != operator_id:
                continue
            if tenant is not None and e.session_tenant != tenant:
                continue
            if since is not None and e.timestamp < since:
                continue
            results.append(e)
        return results[:limit]


# ---------------------------------------------------------------------------
# BridgeServerImpl — the BridgeServer Protocol implementation
# ---------------------------------------------------------------------------

class BridgeServerImpl:
    """Concrete BridgeServer.

    Constructed with:
    - `templates`: closed-set TemplateRegistry (invariant 1)
    - `executor`: TemplateExecutor that maps templates to rows
    - `audit`: AuditLogBackend for invariant 4
    - `session_validator`: SessionValidator (defaults to always-valid for tests)
    """

    def __init__(
        self,
        *,
        templates: TemplateRegistry,
        executor: TemplateExecutor,
        audit: AuditLogBackend | None = None,
        session_validator: SessionValidator | None = None,
    ) -> None:
        self._templates = templates
        self._executor = executor
        self._audit: AuditLogBackend = audit or InMemoryAuditLogBackend()
        self._session_validator: SessionValidator = (
            session_validator or AlwaysValidSessionValidator()
        )

    # ------------------------------------------------------------------
    # BridgeServer Protocol surface
    # ------------------------------------------------------------------

    def validate_session(self, session: SessionContext) -> bool:
        """Per invariant 4: log every validation attempt, accept or reject."""
        accepted = self._session_validator.is_valid(session)
        self._audit.append(AuditLogEntry(
            timestamp=_utc_iso_now(),
            operator_id=session.operator_id,
            operator_role=session.operator_role,
            session_id=session.session_id,
            session_tenant=session.session_tenant,
            template_id="<session_validation>",
            params_hash=_hash_params({}),
            result_row_count=0,
            elapsed_ms=0.0,
            accepted=accepted,
            rejection_reason=None if accepted else "session_invalid",
        ))
        return accepted

    def execute_template(
        self,
        session: SessionContext,
        template_id: str,
        params: dict[str, Any],
    ) -> QueryResult:
        """Execute a registered template under the given session.

        Order of operations (the invariants are checked in dependency order):
        1. Validate session (invariant 4 — even rejections are logged).
        2. Resolve template (invariant 1 — unregistered → reject).
        3. Check role permission (template.min_role).
        4. Enforce session-tenant binding (invariant 3).
        5. Validate parameter shape against template.parameters.
        6. Execute via injected TemplateExecutor.
        7. Validate cross-tenant safety on rows (invariant 5).
        8. Audit-log the accepted query (invariant 4).
        """
        params_hash = _hash_params(params)
        start = time.perf_counter()

        # 1. Session validity
        if not self._session_validator.is_valid(session):
            self._audit_rejection(
                session, template_id, params_hash, "session_invalid",
                elapsed_ms=_elapsed_ms_since(start),
            )
            msg = f"Session '{session.session_id}' is not valid"
            raise InvariantViolation(4, msg)

        # 2. Template registered (invariant 1)
        try:
            template = enforce_template_registered(self._templates, template_id)
        except InvariantViolation as exc:
            self._audit_rejection(
                session, template_id, params_hash, str(exc),
                elapsed_ms=_elapsed_ms_since(start),
            )
            raise

        # 3. Role permission
        if not _role_meets_minimum(session.operator_role, template.min_role):
            reason = (
                f"role '{session.operator_role}' below template min_role "
                f"'{template.min_role}'"
            )
            self._audit_rejection(
                session, template_id, params_hash, reason,
                elapsed_ms=_elapsed_ms_since(start),
            )
            raise InvariantViolation(3, reason)

        # 4. Session-tenant binding (invariant 3)
        try:
            enforce_session_tenant_match(session, template, requested_tenant=None)
        except InvariantViolation as exc:
            self._audit_rejection(
                session, template_id, params_hash, str(exc),
                elapsed_ms=_elapsed_ms_since(start),
            )
            raise

        # 5. Parameter shape
        try:
            _validate_param_shape(template, params)
        except InvariantViolation as exc:
            self._audit_rejection(
                session, template_id, params_hash, str(exc),
                elapsed_ms=_elapsed_ms_since(start),
            )
            raise

        # 6. Execute
        rows = self._executor.execute(template, params, session)

        # 7. Cross-tenant safety (invariant 5)
        try:
            validate_no_cross_tenant_leak(session, template, rows)
        except InvariantViolation as exc:
            self._audit_rejection(
                session, template_id, params_hash, str(exc),
                elapsed_ms=_elapsed_ms_since(start),
            )
            raise

        # 8. Audit-log acceptance
        elapsed_ms = _elapsed_ms_since(start)
        audit_entry_id = self._audit.append(AuditLogEntry(
            timestamp=_utc_iso_now(),
            operator_id=session.operator_id,
            operator_role=session.operator_role,
            session_id=session.session_id,
            session_tenant=session.session_tenant,
            template_id=template_id,
            params_hash=params_hash,
            result_row_count=len(rows),
            elapsed_ms=elapsed_ms,
            accepted=True,
            rejection_reason=None,
            cross_tenant_access=not template.requires_tenant_scope,
        ))

        return QueryResult(
            template_id=template_id,
            rows=rows,
            row_count=len(rows),
            elapsed_ms=elapsed_ms,
            audit_entry_id=audit_entry_id,
        )

    def get_audit_log(
        self,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Unrestricted audit-log read (Protocol-conformant signature).

        Used by super_admin tooling + internal services that already hold
        unrestricted scope. Operator-facing endpoints MUST call
        `get_audit_log_scoped()` instead so role-based scoping is enforced.
        """
        return self._audit.query(
            session_id=session_id,
            operator_id=operator_id,
            tenant=tenant,
            since=since,
            limit=limit,
        )

    def get_audit_log_scoped(
        self,
        session: SessionContext,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Role-scoped audit-log read.

        Per the BridgeServer Protocol's role-filter contract:
        - viewer/analyst: only their own session_id entries (caller filters
          coerced to the bound session)
        - admin: tenant-scoped to their session_tenant; finer filters honored
        - super_admin: unrestricted (all caller filters honored verbatim)
        """
        if session.operator_role in ("viewer", "analyst"):
            effective_session_id = session.session_id
            effective_operator_id = session.operator_id
            effective_tenant = session.session_tenant
        elif session.operator_role == "admin":
            effective_session_id = session_id
            effective_operator_id = operator_id
            effective_tenant = session.session_tenant
        else:  # super_admin
            effective_session_id = session_id
            effective_operator_id = operator_id
            effective_tenant = tenant

        return self._audit.query(
            session_id=effective_session_id,
            operator_id=effective_operator_id,
            tenant=effective_tenant,
            since=since,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _audit_rejection(
        self,
        session: SessionContext,
        template_id: str,
        params_hash: str,
        reason: str,
        *,
        elapsed_ms: float,
    ) -> None:
        """Per invariant 4: rejected queries are still audited."""
        self._audit.append(AuditLogEntry(
            timestamp=_utc_iso_now(),
            operator_id=session.operator_id,
            operator_role=session.operator_role,
            session_id=session.session_id,
            session_tenant=session.session_tenant,
            template_id=template_id,
            params_hash=params_hash,
            result_row_count=0,
            elapsed_ms=elapsed_ms,
            accepted=False,
            rejection_reason=reason,
        ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3, "super_admin": 4}


def _role_meets_minimum(operator_role: str, min_role: str) -> bool:
    return _ROLE_RANK[operator_role] >= _ROLE_RANK[min_role]


def _hash_params(params: dict[str, Any]) -> str:
    """Stable sha256 of the parameter dict — sorted-keys JSON.

    Per AuditLogEntry invariant: actual values are NOT logged; the hash
    suffices for replay / behavioral analysis.
    """
    canonical = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_param_shape(template: QueryTemplate, params: dict[str, Any]) -> None:
    """Validate inbound params against template.parameters.

    Currently checks: declared parameter names match (no unknown keys, no
    missing keys). Type coercion / value validation is the executor's job.
    Raises InvariantViolation(1) on shape mismatch (closed-template invariant
    extends to the parameter shape).
    """
    declared = set(template.parameters.keys())
    provided = set(params.keys())
    unknown = provided - declared
    missing = declared - provided
    if unknown or missing:
        parts = []
        if unknown:
            parts.append(f"unknown params: {sorted(unknown)}")
        if missing:
            parts.append(f"missing params: {sorted(missing)}")
        msg = (
            f"Template '{template.template_id}' parameter shape mismatch — "
            + "; ".join(parts)
        )
        raise InvariantViolation(1, msg)


def _utc_iso_now() -> str:
    """ISO8601 UTC with millisecond precision + Z suffix (matches CanonicalEvent)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _elapsed_ms_since(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


# Static assertion: BridgeServerImpl satisfies the BridgeServer Protocol.
# No-op at runtime; mypy --strict will catch a Protocol drift here.
from shared_bridge import BridgeServer  # noqa: E402

_: type[BridgeServer] = BridgeServerImpl  # type: ignore[type-abstract,misc]
