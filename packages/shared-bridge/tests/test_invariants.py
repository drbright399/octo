"""Conformance tests for the bridge contract invariants.

Per ADR-004 §`Five mandatory invariants`. These tests verify each invariant
is enforced by the helpers in `shared_bridge.invariants`.
"""

from __future__ import annotations

import pytest

from shared_bridge import (
    BRIDGE_CONTRACT_VERSION,
    InvariantViolation,
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
    enforce_session_tenant_match,
    enforce_template_registered,
    validate_no_cross_tenant_leak,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _analyst_session(tenant: str = "client-a") -> SessionContext:
    return SessionContext(
        operator_id=42,
        operator_role="analyst",
        session_tenant=tenant,
        session_id="sess-test",
    )


def _super_admin_session(tenant: str = "client-a") -> SessionContext:
    return SessionContext(
        operator_id=1,
        operator_role="super_admin",
        session_tenant=tenant,
        session_id="sess-super",
    )


def _tenant_scoped_template() -> QueryTemplate:
    return QueryTemplate(
        template_id="recent_findings",
        description="Recent findings for the session tenant",
        parameters={"limit": "int"},
        response_schema={"id": "int", "summary": "string"},
        requires_tenant_scope=True,
        cross_tenant_safety_required=False,
    )


def _cross_tenant_template() -> QueryTemplate:
    return QueryTemplate(
        template_id="cross_tenant_pattern_lookup",
        description="Sanitized cross-tenant indicator pool lookup",
        parameters={"indicator_hash": "string"},
        response_schema={"occurrence_count": "int", "tenant_hashes": "list[string]"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="admin",
    )


# ---------------------------------------------------------------------------
# Contract version
# ---------------------------------------------------------------------------

def test_contract_version_exported() -> None:
    assert BRIDGE_CONTRACT_VERSION == "1.0"


# ---------------------------------------------------------------------------
# Invariant 1: Parameterized queries only (closed template registry)
# ---------------------------------------------------------------------------

def test_invariant_1_unregistered_template_rejected() -> None:
    """Per invariant 1: only registered templates can be executed."""
    registry = TemplateRegistry()
    with pytest.raises(InvariantViolation) as exc_info:
        enforce_template_registered(registry, "nonexistent_template")
    assert exc_info.value.invariant_number == 1


def test_invariant_1_registered_template_accepted() -> None:
    """Registered template returns from the enforcement helper."""
    registry = TemplateRegistry()
    template = _tenant_scoped_template()
    registry.register(template)
    result = enforce_template_registered(registry, template.template_id)
    assert result.template_id == template.template_id


def test_template_registry_rejects_duplicate_id() -> None:
    """Registry enforces unique template_ids — no overwrites."""
    registry = TemplateRegistry()
    template = _tenant_scoped_template()
    registry.register(template)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(template)


# ---------------------------------------------------------------------------
# Invariant 3: Session-bound tenant_id
# ---------------------------------------------------------------------------

def test_invariant_3_mid_session_retarget_rejected() -> None:
    """Caller cannot pass a different tenant than session.session_tenant."""
    session = _analyst_session(tenant="client-a")
    template = _tenant_scoped_template()
    with pytest.raises(InvariantViolation) as exc_info:
        enforce_session_tenant_match(session, template, requested_tenant="client-b")
    assert exc_info.value.invariant_number == 3


def test_invariant_3_matching_tenant_accepted() -> None:
    """When requested_tenant matches session.session_tenant, no violation."""
    session = _analyst_session(tenant="client-a")
    template = _tenant_scoped_template()
    enforce_session_tenant_match(session, template, requested_tenant="client-a")


def test_invariant_3_no_explicit_tenant_uses_session() -> None:
    """When caller doesn't pass requested_tenant, session.session_tenant is implicit."""
    session = _analyst_session(tenant="client-a")
    template = _tenant_scoped_template()
    enforce_session_tenant_match(session, template)


def test_invariant_3_cross_tenant_template_blocks_analyst() -> None:
    """Analyst role cannot execute cross-tenant templates."""
    session = _analyst_session()
    template = _cross_tenant_template()
    with pytest.raises(InvariantViolation) as exc_info:
        enforce_session_tenant_match(session, template)
    assert exc_info.value.invariant_number == 3


def test_invariant_3_cross_tenant_template_allows_super_admin() -> None:
    """Super_admin role can execute cross-tenant templates."""
    session = _super_admin_session()
    template = _cross_tenant_template()
    enforce_session_tenant_match(session, template)


# ---------------------------------------------------------------------------
# Invariant 5: Cross-tenant retrieval safety
# ---------------------------------------------------------------------------

def test_invariant_5_raw_tenant_id_in_cross_tenant_response_rejected() -> None:
    """A cross-tenant template that leaks `tenant_slug` is caught."""
    session = _super_admin_session()
    template = _cross_tenant_template()
    leaky_rows = [
        {"occurrence_count": 3, "tenant_slug": "client-b"},  # forbidden!
    ]
    with pytest.raises(InvariantViolation) as exc_info:
        validate_no_cross_tenant_leak(session, template, leaky_rows)
    assert exc_info.value.invariant_number == 5


def test_invariant_5_opaque_tenant_hash_accepted() -> None:
    """Cross-tenant template with opaque `tenant_hashes` (no raw slugs) passes."""
    session = _super_admin_session()
    template = _cross_tenant_template()
    safe_rows = [
        {
            "occurrence_count": 5,
            "tenant_hashes": ["abc123", "def456", "ghi789"],
        },
    ]
    validate_no_cross_tenant_leak(session, template, safe_rows)


def test_invariant_5_skips_tenant_scoped_templates() -> None:
    """Tenant-scoped templates aren't subject to invariant 5 (they correctly
    return rows with tenant context — that's their whole job)."""
    session = _analyst_session()
    template = _tenant_scoped_template()
    # tenant-scoped template can have tenant fields in its rows
    rows = [{"id": 1, "tenant_slug": "client-a", "summary": "foo"}]
    validate_no_cross_tenant_leak(session, template, rows)  # no raise


def test_invariant_5_multiple_forbidden_keys_caught() -> None:
    """Multiple raw-identifier keys in one row all flagged."""
    session = _super_admin_session()
    template = _cross_tenant_template()
    leaky_rows = [{"client_slug": "x", "tenant_id": "y", "occurrence_count": 1}]
    with pytest.raises(InvariantViolation) as exc_info:
        validate_no_cross_tenant_leak(session, template, leaky_rows)
    assert exc_info.value.invariant_number == 5
