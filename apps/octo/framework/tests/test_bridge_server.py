"""Tests for the bridge server runtime — invariant enforcement + audit logging.

Verifies BridgeServerImpl honors all five ADR-004 invariants:
1. Closed template registry (unregistered → reject + audit)
2. Read/write credential separation (this surface only takes BridgeReadCredential
   sessions; write path is separate — covered structurally, not behaviorally)
3. Session-bound tenant_id (no mid-session retargeting; cross-tenant requires
   admin/super_admin)
4. Per-query audit log (every accept + reject has an entry)
5. Cross-tenant retrieval safety (raw tenant identifiers blocked)
"""

from __future__ import annotations

from typing import Any

import pytest

from shared_bridge import (
    InvariantViolation,
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
)

from apps.octo.framework.bridge_server import (
    BridgeServerImpl,
    InMemoryAuditLogBackend,
    TemplateExecutor,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

class StubExecutor:
    """Test executor — returns canned rows; records last invocation."""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows if rows is not None else []
        self.calls: list[tuple[str, dict[str, Any], SessionContext]] = []

    def execute(
        self,
        template: QueryTemplate,
        params: dict[str, Any],
        session: SessionContext,
    ) -> list[dict[str, Any]]:
        self.calls.append((template.template_id, params, session))
        return list(self.rows)


def _registry_with(*templates: QueryTemplate) -> TemplateRegistry:
    reg = TemplateRegistry()
    for t in templates:
        reg.register(t)
    return reg


def _viewer_session(tenant: str = "client_a") -> SessionContext:
    return SessionContext(
        operator_id=10,
        operator_role="viewer",
        session_tenant=tenant,
        session_id="sess-viewer-1",
    )


def _analyst_session(tenant: str = "client_a") -> SessionContext:
    return SessionContext(
        operator_id=11,
        operator_role="analyst",
        session_tenant=tenant,
        session_id="sess-analyst-1",
    )


def _admin_session(tenant: str = "client_a") -> SessionContext:
    return SessionContext(
        operator_id=12,
        operator_role="admin",
        session_tenant=tenant,
        session_id="sess-admin-1",
    )


def _super_admin_session(tenant: str = "msp_root") -> SessionContext:
    return SessionContext(
        operator_id=1,
        operator_role="super_admin",
        session_tenant=tenant,
        session_id="sess-super-1",
    )


def _basic_template() -> QueryTemplate:
    return QueryTemplate(
        template_id="recent_findings",
        description="Recent findings for the operator's tenant",
        parameters={"limit": "int"},
        response_schema={"id": "int", "summary": "str"},
        requires_tenant_scope=True,
        min_role="viewer",
    )


# ---------------------------------------------------------------------------
# Invariant 1 — closed template registry
# ---------------------------------------------------------------------------

def test_invariant_1_unregistered_template_rejected() -> None:
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=TemplateRegistry(),
        executor=StubExecutor(),
        audit=audit,
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_viewer_session(), "no_such_template", {})
    assert exc_info.value.invariant_number == 1
    # Rejection still audited (invariant 4)
    entries = audit.query()
    assert len(entries) == 1
    assert entries[0].accepted is False
    assert entries[0].template_id == "no_such_template"


def test_invariant_1_unknown_param_rejected() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(
            _viewer_session(), "recent_findings", {"limit": 10, "unexpected": "x"},
        )
    assert exc_info.value.invariant_number == 1
    entries = audit.query()
    assert entries[-1].accepted is False
    assert "unknown params" in (entries[-1].rejection_reason or "")


def test_invariant_1_missing_param_rejected() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_viewer_session(), "recent_findings", {})
    assert exc_info.value.invariant_number == 1
    assert "missing params" in (audit.query()[-1].rejection_reason or "")


# ---------------------------------------------------------------------------
# Invariant 3 — session-bound tenant + role checks
# ---------------------------------------------------------------------------

def test_invariant_3_role_below_template_min_rejected() -> None:
    template = QueryTemplate(
        template_id="admin_only_thing",
        description="admin-only",
        parameters={},
        response_schema={"x": "int"},
        requires_tenant_scope=True,
        min_role="admin",
    )
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_viewer_session(), "admin_only_thing", {})
    assert exc_info.value.invariant_number == 3
    assert audit.query()[-1].accepted is False


def test_invariant_3_cross_tenant_template_blocks_analyst() -> None:
    template = QueryTemplate(
        template_id="sanitized_pool_lookup",
        description="cross-tenant sanitized pool",
        parameters={},
        response_schema={"tenant_hash": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(rows=[{"tenant_hash": "abc123"}]),
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_analyst_session(), "sanitized_pool_lookup", {})
    assert exc_info.value.invariant_number == 3


def test_invariant_3_cross_tenant_template_allows_admin() -> None:
    template = QueryTemplate(
        template_id="sanitized_pool_lookup",
        description="cross-tenant sanitized pool",
        parameters={},
        response_schema={"tenant_hash": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(rows=[{"tenant_hash": "abc123"}]),
        audit=audit,
    )
    result = server.execute_template(_admin_session(), "sanitized_pool_lookup", {})
    assert result.row_count == 1
    # Audit entry flags cross-tenant access
    accepted_entries = [e for e in audit.query() if e.accepted]
    assert len(accepted_entries) == 1
    assert accepted_entries[0].cross_tenant_access is True


# ---------------------------------------------------------------------------
# Invariant 4 — per-query audit log
# ---------------------------------------------------------------------------

def test_invariant_4_accepted_query_audited() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    executor = StubExecutor(rows=[{"id": 1, "summary": "x"}, {"id": 2, "summary": "y"}])
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=executor,
        audit=audit,
    )
    result = server.execute_template(_viewer_session(), "recent_findings", {"limit": 5})
    assert result.row_count == 2
    assert result.audit_entry_id == 1

    entries = audit.query()
    assert len(entries) == 1
    assert entries[0].accepted is True
    assert entries[0].result_row_count == 2
    assert entries[0].template_id == "recent_findings"
    assert entries[0].rejection_reason is None
    # Per-spec: param values NOT logged; only hash
    assert len(entries[0].params_hash) == 64  # sha256 hex


def test_invariant_4_param_hash_stable_for_same_params() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    server.execute_template(_viewer_session(), "recent_findings", {"limit": 10})
    server.execute_template(_viewer_session(), "recent_findings", {"limit": 10})
    server.execute_template(_viewer_session(), "recent_findings", {"limit": 11})
    hashes = [e.params_hash for e in audit.query()]
    assert hashes[0] == hashes[1]
    assert hashes[0] != hashes[2]


def test_invariant_4_session_validation_audited() -> None:
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=TemplateRegistry(),
        executor=StubExecutor(),
        audit=audit,
    )
    server.validate_session(_viewer_session())
    entries = audit.query()
    assert len(entries) == 1
    assert entries[0].template_id == "<session_validation>"
    assert entries[0].accepted is True


def test_invariant_4_invalid_session_rejected_and_audited() -> None:
    class RejectingValidator:
        def is_valid(self, session: SessionContext) -> bool:  # noqa: ARG002
            return False

    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(_basic_template()),
        executor=StubExecutor(),
        audit=audit,
        session_validator=RejectingValidator(),
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_viewer_session(), "recent_findings", {"limit": 10})
    assert exc_info.value.invariant_number == 4
    assert audit.query()[-1].rejection_reason == "session_invalid"


# ---------------------------------------------------------------------------
# Invariant 5 — cross-tenant retrieval safety
# ---------------------------------------------------------------------------

def test_invariant_5_cross_tenant_template_with_raw_tenant_slug_blocked() -> None:
    template = QueryTemplate(
        template_id="bad_sanitization",
        description="sanitization gone wrong",
        parameters={},
        response_schema={"tenant_slug": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    # Executor incorrectly returns a raw tenant_slug — invariant 5 must catch
    leaky_executor = StubExecutor(rows=[{"tenant_slug": "client_a"}])
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=leaky_executor,
        audit=audit,
    )
    with pytest.raises(InvariantViolation) as exc_info:
        server.execute_template(_admin_session(), "bad_sanitization", {})
    assert exc_info.value.invariant_number == 5
    assert audit.query()[-1].accepted is False


def test_invariant_5_cross_tenant_with_opaque_hash_passes() -> None:
    template = QueryTemplate(
        template_id="proper_sanitization",
        description="sanitized output",
        parameters={},
        response_schema={"tenant_hash": "str", "count": "int"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(rows=[
            {"tenant_hash": "h_abc", "count": 5},
            {"tenant_hash": "h_def", "count": 3},
        ]),
    )
    result = server.execute_template(_admin_session(), "proper_sanitization", {})
    assert result.row_count == 2


def test_invariant_5_inactive_for_tenant_scoped_templates() -> None:
    """When requires_tenant_scope=True, invariant 5 doesn't apply — raw
    tenant_slug in rows is fine (the template is single-tenant by definition)."""
    template = QueryTemplate(
        template_id="tenant_scoped",
        description="this is a tenant-scoped query, raw slugs allowed",
        parameters={},
        response_schema={"tenant_slug": "str"},
        requires_tenant_scope=True,
        cross_tenant_safety_required=False,
        min_role="viewer",
    )
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(rows=[{"tenant_slug": "client_a"}]),
    )
    # No InvariantViolation raised
    result = server.execute_template(_viewer_session(), "tenant_scoped", {})
    assert result.row_count == 1


# ---------------------------------------------------------------------------
# Audit-log read scoping (role-based)
# ---------------------------------------------------------------------------

def _seed_multi_op_audit(server: BridgeServerImpl) -> None:
    """Run a few queries from different operators / tenants to populate audit."""
    template = _basic_template()
    server.execute_template(_viewer_session("client_a"), "recent_findings", {"limit": 1})
    server.execute_template(_analyst_session("client_a"), "recent_findings", {"limit": 1})
    server.execute_template(_admin_session("client_a"), "recent_findings", {"limit": 1})
    server.execute_template(
        SessionContext(
            operator_id=20, operator_role="viewer",
            session_tenant="client_b", session_id="sess-viewer-other",
        ),
        "recent_findings", {"limit": 1},
    )
    _ = template  # keep template variable visible (used for the registry below)


def test_audit_read_unrestricted_via_protocol_method() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    _seed_multi_op_audit(server)
    # Protocol-conformant unrestricted method
    all_entries = server.get_audit_log()
    assert len(all_entries) == 4


def test_audit_read_scoped_viewer_sees_only_own_session() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    _seed_multi_op_audit(server)
    viewer = _viewer_session("client_a")
    scoped = server.get_audit_log_scoped(viewer)
    assert len(scoped) == 1
    assert all(e.session_id == viewer.session_id for e in scoped)


def test_audit_read_scoped_admin_tenant_scoped() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    _seed_multi_op_audit(server)
    admin = _admin_session("client_a")
    # Admin can see all client_a entries — even though they tried to filter to client_b
    scoped = server.get_audit_log_scoped(admin, tenant="client_b")
    assert len(scoped) == 3
    assert all(e.session_tenant == "client_a" for e in scoped)


def test_audit_read_scoped_super_admin_unrestricted() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    _seed_multi_op_audit(server)
    super_admin = _super_admin_session()
    scoped = server.get_audit_log_scoped(super_admin)
    assert len(scoped) == 4


def test_audit_read_scoped_super_admin_can_filter_by_tenant() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(),
        audit=audit,
    )
    _seed_multi_op_audit(server)
    super_admin = _super_admin_session()
    scoped = server.get_audit_log_scoped(super_admin, tenant="client_b")
    assert len(scoped) == 1
    assert scoped[0].session_tenant == "client_b"


# ---------------------------------------------------------------------------
# QueryResult contract
# ---------------------------------------------------------------------------

def test_query_result_carries_audit_entry_id() -> None:
    template = _basic_template()
    audit = InMemoryAuditLogBackend()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=StubExecutor(rows=[{"id": 1, "summary": "x"}]),
        audit=audit,
    )
    result = server.execute_template(_viewer_session(), "recent_findings", {"limit": 5})
    # Audit entry exists and matches result.audit_entry_id
    matching = [e for e in audit.query() if e.accepted]
    assert len(matching) == 1
    # Stored entry IDs start at 1; result.audit_entry_id refers to the stored id
    assert result.audit_entry_id == 1
    assert result.template_id == "recent_findings"
    assert result.elapsed_ms >= 0.0


def test_executor_receives_template_params_and_session() -> None:
    template = _basic_template()
    executor = StubExecutor()
    server = BridgeServerImpl(
        templates=_registry_with(template),
        executor=executor,
    )
    session = _viewer_session("client_x")
    server.execute_template(session, "recent_findings", {"limit": 7})
    assert len(executor.calls) == 1
    template_id, params, sess = executor.calls[0]
    assert template_id == "recent_findings"
    assert params == {"limit": 7}
    assert sess.session_tenant == "client_x"
