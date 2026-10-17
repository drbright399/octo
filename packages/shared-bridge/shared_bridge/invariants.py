"""Invariant enforcement helpers.

Per ADR-004 §`Five mandatory invariants`. These functions are called by
both the client and server sides to enforce the contract. Tests in
`tests/test_invariants.py` verify they catch the relevant violation classes.
"""

from __future__ import annotations

from typing import Any

from shared_bridge.types import QueryTemplate, SessionContext, TemplateRegistry


class InvariantViolation(Exception):
    """Raised when a bridge contract invariant is violated.

    Carry an explicit invariant_number so audit logs can correlate
    violations with the specific ADR-004 invariant.
    """

    def __init__(self, invariant_number: int, message: str) -> None:
        super().__init__(f"Invariant {invariant_number}: {message}")
        self.invariant_number = invariant_number


# ---------------------------------------------------------------------------
# Invariant 1: Parameterized queries only (closed template registry)
# ---------------------------------------------------------------------------

def enforce_template_registered(
    registry: TemplateRegistry,
    template_id: str,
) -> QueryTemplate:
    """Per invariant 1: only registered templates can be executed.

    Returns the QueryTemplate on success; raises InvariantViolation on
    unregistered template_id.
    """
    template = registry.get(template_id)
    if template is None:
        msg = f"Template '{template_id}' not registered"
        raise InvariantViolation(1, msg)
    return template


# ---------------------------------------------------------------------------
# Invariant 3: Session-bound tenant_id
# ---------------------------------------------------------------------------

def enforce_session_tenant_match(
    session: SessionContext,
    template: QueryTemplate,
    requested_tenant: str | None = None,
) -> None:
    """Per invariant 3: results filter to session.session_tenant unless the
    template explicitly opts out (requires_tenant_scope=False) AND the operator
    role permits cross-tenant access.

    If the caller provides a `requested_tenant` and it differs from
    session.session_tenant, that's a violation (mid-session retargeting).
    """
    if requested_tenant is not None and requested_tenant != session.session_tenant:
        msg = (
            f"Session bound to tenant '{session.session_tenant}'; "
            f"cannot retarget to '{requested_tenant}'"
        )
        raise InvariantViolation(3, msg)

    if not template.requires_tenant_scope and session.operator_role not in (
        "super_admin",
        "admin",
    ):
        msg = (
            f"Template '{template.template_id}' is cross-tenant scope; "
            f"role '{session.operator_role}' insufficient (super_admin or admin required)"
        )
        raise InvariantViolation(3, msg)


# ---------------------------------------------------------------------------
# Invariant 5: Cross-tenant retrieval safety
# ---------------------------------------------------------------------------

def validate_no_cross_tenant_leak(
    session: SessionContext,
    template: QueryTemplate,
    rows: list[dict[str, Any]],
) -> None:
    """Per invariant 5: when a cross-tenant template returns rows, verify no
    raw tenant identifiers (slugs, IDs) leak through.

    The sanitized pool's `tenant_hashes` field carries opaque hashes (not raw
    slugs). This function validates that:
    - When session is bound to tenant X, no row contains slug/ID for any
      other tenant in non-hash form
    - Sanitized-pool outputs use opaque `tenant_hash` fields
    """
    if not template.cross_tenant_safety_required:
        return  # Tenant-scoped template; not subject to this invariant

    # Cross-tenant template — sanitization required
    forbidden_keys = {"tenant_slug", "tenant_id", "client_slug", "client_id"}
    for i, row in enumerate(rows):
        leaked = forbidden_keys & row.keys()
        if leaked:
            msg = (
                f"Row {i} of template '{template.template_id}' (cross-tenant) "
                f"contains forbidden keys: {leaked}. Sanitized output must use "
                f"opaque tenant_hash fields, not raw identifiers."
            )
            raise InvariantViolation(5, msg)
