"""Type definitions for the bridge contract.

Per ADR-004 §`Five mandatory invariants`. These types model the surface
that Athena (client) and OCTO (server) both implement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Auth modes
# ---------------------------------------------------------------------------

BridgeAuthMode = Literal["read", "write"]
"""Bridge has two distinct credential types per invariant 2 (separate r/w
credentials). Conflation is structurally rejected at the server."""


@dataclass(frozen=True)
class BridgeReadCredential:
    """Read-side credential (operator session reads OCTO data).

    Issued at operator login; bound to the operator's session-tenant per
    invariant 3 (session-bound tenant_id). Cannot be used to write."""

    token: str
    issued_for_tenant: str
    issued_at: str
    """ISO8601."""
    expires_at: str
    """ISO8601. Bridge server rejects expired tokens."""
    operator_id: int
    operator_role: Literal["super_admin", "admin", "analyst", "viewer"]


@dataclass(frozen=True)
class BridgeWriteCredential:
    """Write-side credential (adapter ingest writes telemetry to OCTO).

    Issued per (tenant × source_type × instance_id) — service-bound bearer
    tokens; same pattern as today's wazuh-octo-shim deployment."""

    token: str
    bound_tenant_slug: str
    bound_source_type: str
    bound_source_instance_id: str
    issued_at: str
    revoked_at: str | None = None


# ---------------------------------------------------------------------------
# Session context (the operator's "who am I + which tenant" binding)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionContext:
    """The operator's session-bound context for a bridge call.

    Per invariant 3: session_tenant + operator_id + operator_role are FIXED at
    session start; cannot be retargeted mid-session. The bridge server
    validates that template execution honors these bindings (e.g., per-row
    visibility scoping by ownership).
    """

    operator_id: int
    operator_role: Literal["super_admin", "admin", "analyst", "viewer"]
    session_tenant: str
    """Slug of the tenant this session is bound to. Adapters' write credentials
    are scoped similarly (service-bound to one tenant)."""
    session_id: str
    """Unique identifier for this operator session — used as audit-log linkage."""


# ---------------------------------------------------------------------------
# Query template
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class QueryTemplate:
    """Declarative query template registered in the bridge.

    Per invariant 1: only registered templates can be executed. Athena passes
    `(template_id, params)`; OCTO maps the template to actual SQL internally.
    Raw SQL never crosses the bridge.

    Templates are versioned independently from the contract — adapters and
    framework features can add templates without bumping the bridge contract
    version.
    """

    template_id: str
    """Unique identifier (e.g., 'recent_findings', 'list_tenants',
    'datto_rmm.recent_alerts'). Convention: '<scope>.<purpose>' for adapter-
    specific templates; bare lowercase for system templates."""

    description: str
    """Operator-facing + audit-log description of what this template does."""

    parameters: dict[str, str]
    """Parameter name → type-hint string (e.g., {'limit': 'int', 'since': 'ISO8601'}).
    The bridge server validates inbound params against this schema."""

    response_schema: dict[str, str]
    """Field name → type-hint string for response items. Used for OpenAPI doc
    generation + downstream type-safety."""

    requires_tenant_scope: bool = True
    """If True, results MUST be filtered to session.session_tenant per
    invariant 3. Cross-tenant exception templates (sanitized pool lookup,
    super_admin admin-tier introspection) declare requires_tenant_scope=False
    and document their cross-tenant access in the audit log."""

    cross_tenant_safety_required: bool = False
    """If True (only for sanitized pool lookups), invariant 5 enforcement
    applies — anonymized output, opaque tenant hashes, output filter blocks
    cross-tenant identifier leakage."""

    min_role: Literal["super_admin", "admin", "analyst", "viewer"] = "viewer"
    """Minimum operator role required to execute this template."""


@dataclass(frozen=True)
class QueryResult:
    """Result of a bridge query template execution."""

    template_id: str
    rows: list[dict[str, Any]]
    row_count: int
    elapsed_ms: float
    audit_entry_id: int
    """Per invariant 4: every accepted query logs an entry; this references it."""


# ---------------------------------------------------------------------------
# Template registry
# ---------------------------------------------------------------------------

class TemplateRegistry:
    """In-memory registry of bridge query templates.

    Per invariant 1: closed set. Only templates registered here can be
    executed. Implementations on the OCTO side load this from
    `packages/shared-bridge/templates/` at startup.
    """

    def __init__(self) -> None:
        self._templates: dict[str, QueryTemplate] = {}

    def register(self, template: QueryTemplate) -> None:
        """Register a template. Raises ValueError on duplicate template_id."""
        if template.template_id in self._templates:
            msg = f"Template already registered: {template.template_id}"
            raise ValueError(msg)
        self._templates[template.template_id] = template

    def get(self, template_id: str) -> QueryTemplate | None:
        """Return the registered template, or None if not found."""
        return self._templates.get(template_id)

    def list(self) -> list[QueryTemplate]:
        """All registered templates."""
        return list(self._templates.values())

    def __contains__(self, template_id: str) -> bool:
        return template_id in self._templates

    def __len__(self) -> int:
        return len(self._templates)


# ---------------------------------------------------------------------------
# Audit log entry (per invariant 4)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditLogEntry:
    """One audited bridge query execution.

    Per invariant 4: every accepted query is logged. Even rejected queries
    (auth failure, invariant violation) get an audit entry with
    `accepted=False` so behavioral monitoring can detect probing.
    """

    timestamp: str
    """ISO8601 UTC."""
    operator_id: int
    operator_role: str
    session_id: str
    session_tenant: str
    template_id: str
    params_hash: str
    """sha256 of the parameter dict (stable, sorted-keys JSON). The actual
    parameter values are NOT logged — that would create a side-channel leak.
    The hash is sufficient for replay / behavioral analysis."""
    result_row_count: int
    elapsed_ms: float
    accepted: bool
    rejection_reason: str | None = None
    """When accepted=False, why the query was rejected."""
    cross_tenant_access: bool = False
    """True if this was a sanitized-pool / super_admin cross-tenant query."""
    extra: dict[str, Any] = field(default_factory=dict)
