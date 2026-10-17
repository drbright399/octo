"""Tests for the FastAPI bridge router — HTTP-level invariant + auth coverage."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from shared_bridge import (
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
)

from apps.octo.framework.bridge_router import (
    StaticTokenResolver,
    create_bridge_router,
)
from apps.octo.framework.bridge_server import BridgeServerImpl


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

class StubExecutor:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or [{"id": 1, "summary": "ok"}]

    def execute(self, template, params, session):  # noqa: ARG002
        return list(self.rows)


def _basic_template(min_role: str = "viewer") -> QueryTemplate:
    return QueryTemplate(
        template_id="recent_findings",
        description="recent findings",
        parameters={"limit": "int"},
        response_schema={"id": "int", "summary": "str"},
        requires_tenant_scope=True,
        min_role=min_role,  # type: ignore[arg-type]
    )


def _viewer_session(tenant: str = "client_a") -> SessionContext:
    return SessionContext(
        operator_id=10,
        operator_role="viewer",
        session_tenant=tenant,
        session_id="sess-viewer-1",
    )


def _admin_session(tenant: str = "client_a") -> SessionContext:
    return SessionContext(
        operator_id=12,
        operator_role="admin",
        session_tenant=tenant,
        session_id="sess-admin-1",
    )


def _build_app(
    *,
    template: QueryTemplate | None = None,
    rows: list[dict[str, Any]] | None = None,
    tokens: dict[str, SessionContext] | None = None,
) -> tuple[FastAPI, BridgeServerImpl, StaticTokenResolver]:
    reg = TemplateRegistry()
    if template is not None:
        reg.register(template)
    server = BridgeServerImpl(templates=reg, executor=StubExecutor(rows=rows))
    resolver = StaticTokenResolver(tokens or {})
    app = FastAPI()
    app.include_router(create_bridge_router(server=server, token_resolver=resolver))
    return app, server, resolver


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health_no_auth_required() -> None:
    app, _, _ = _build_app()
    client = TestClient(app)
    resp = client.get("/bridge/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["contract_version"] == "1.0"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def test_execute_without_auth_returns_401() -> None:
    app, _, _ = _build_app(template=_basic_template())
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {"limit": 5}},
    )
    assert resp.status_code == 401
    assert "missing Authorization" in resp.json()["detail"]


def test_execute_with_unknown_token_returns_401() -> None:
    app, _, _ = _build_app(template=_basic_template())
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {"limit": 5}},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_execute_with_revoked_token_returns_401() -> None:
    app, _, resolver = _build_app(
        template=_basic_template(),
        tokens={"valid": _viewer_session()},
    )
    client = TestClient(app)
    # Revoke before call
    resolver.revoke("valid")
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {"limit": 5}},
        headers={"Authorization": "Bearer valid"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Execute — happy path
# ---------------------------------------------------------------------------

def test_execute_happy_path() -> None:
    rows = [{"id": 1, "summary": "alpha"}, {"id": 2, "summary": "beta"}]
    app, _, _ = _build_app(
        template=_basic_template(),
        rows=rows,
        tokens={"tok-1": _viewer_session()},
    )
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {"limit": 5}},
        headers={"Authorization": "Bearer tok-1"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["template_id"] == "recent_findings"
    assert body["row_count"] == 2
    assert body["rows"] == rows
    assert isinstance(body["audit_entry_id"], int)
    assert body["audit_entry_id"] >= 1


# ---------------------------------------------------------------------------
# Invariant → status code mapping
# ---------------------------------------------------------------------------

def test_unregistered_template_returns_404() -> None:
    app, _, _ = _build_app(tokens={"tok-1": _viewer_session()})
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "ghost", "params": {}},
        headers={"Authorization": "Bearer tok-1"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["invariant"] == 1
    assert "not registered" in detail["message"]


def test_param_shape_mismatch_returns_400() -> None:
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok-1": _viewer_session()},
    )
    client = TestClient(app)
    # missing required `limit` param
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {}},
        headers={"Authorization": "Bearer tok-1"},
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    assert detail["invariant"] == 1


def test_role_below_min_returns_403() -> None:
    template = _basic_template(min_role="admin")  # admin-only
    app, _, _ = _build_app(
        template=template,
        tokens={"tok-1": _viewer_session()},
    )
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "recent_findings", "params": {"limit": 5}},
        headers={"Authorization": "Bearer tok-1"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["invariant"] == 3


def test_cross_tenant_template_blocks_analyst_with_403() -> None:
    template = QueryTemplate(
        template_id="sanitized_pool",
        description="cross-tenant",
        parameters={},
        response_schema={"tenant_hash": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    analyst = SessionContext(
        operator_id=11, operator_role="analyst",
        session_tenant="client_a", session_id="sess-analyst",
    )
    app, _, _ = _build_app(template=template, tokens={"tok": analyst})
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "sanitized_pool", "params": {}},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 403


def test_cross_tenant_leak_returns_500() -> None:
    template = QueryTemplate(
        template_id="leaky",
        description="should be sanitized",
        parameters={},
        response_schema={"tenant_slug": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    # Executor returns a raw tenant_slug — invariant 5 catches it
    app, _, _ = _build_app(
        template=template,
        rows=[{"tenant_slug": "client_a"}],
        tokens={"tok": _admin_session()},
    )
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "leaky", "params": {}},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 500
    assert resp.json()["detail"]["invariant"] == 5


# ---------------------------------------------------------------------------
# Audit endpoint — role scoping
# ---------------------------------------------------------------------------

def _seed_audit(client: TestClient, *, token: str, n: int = 3) -> None:
    for _ in range(n):
        client.post(
            "/bridge/v1/execute",
            json={"template_id": "recent_findings", "params": {"limit": 5}},
            headers={"Authorization": f"Bearer {token}"},
        )


def test_audit_requires_auth() -> None:
    app, _, _ = _build_app()
    client = TestClient(app)
    resp = client.get("/bridge/v1/audit")
    assert resp.status_code == 401


def test_audit_viewer_sees_only_own_session() -> None:
    other_viewer = SessionContext(
        operator_id=99, operator_role="viewer",
        session_tenant="client_a", session_id="sess-other",
    )
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok-mine": _viewer_session(), "tok-other": other_viewer},
    )
    client = TestClient(app)
    _seed_audit(client, token="tok-mine", n=2)
    _seed_audit(client, token="tok-other", n=3)

    resp = client.get(
        "/bridge/v1/audit",
        headers={"Authorization": "Bearer tok-mine"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Viewer: only their own session entries (plus session_validation entries
    # written for each request). All entries belong to sess-viewer-1 only.
    for e in body["entries"]:
        assert e["session_id"] == "sess-viewer-1"


def test_audit_admin_tenant_scoped() -> None:
    other_tenant_admin = SessionContext(
        operator_id=13, operator_role="admin",
        session_tenant="client_b", session_id="sess-admin-b",
    )
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={
            "tok-admin-a": _admin_session("client_a"),
            "tok-admin-b": other_tenant_admin,
        },
    )
    client = TestClient(app)
    _seed_audit(client, token="tok-admin-a", n=2)
    _seed_audit(client, token="tok-admin-b", n=2)

    resp = client.get(
        "/bridge/v1/audit",
        headers={"Authorization": "Bearer tok-admin-a"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] > 0
    for e in body["entries"]:
        assert e["session_tenant"] == "client_a"


def test_audit_super_admin_unrestricted() -> None:
    super_admin = SessionContext(
        operator_id=1, operator_role="super_admin",
        session_tenant="msp_root", session_id="sess-super",
    )
    other = SessionContext(
        operator_id=99, operator_role="viewer",
        session_tenant="client_b", session_id="sess-other",
    )
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok-super": super_admin, "tok-other": other},
    )
    client = TestClient(app)
    _seed_audit(client, token="tok-other", n=2)

    resp = client.get(
        "/bridge/v1/audit",
        headers={"Authorization": "Bearer tok-super"},
    )
    body = resp.json()
    # Super admin sees all entries — including the other session's
    sess_ids = {e["session_id"] for e in body["entries"]}
    assert "sess-other" in sess_ids


def test_audit_limit_capped(monkeypatch) -> None:  # noqa: ARG001
    super_admin = SessionContext(
        operator_id=1, operator_role="super_admin",
        session_tenant="msp_root", session_id="sess-super",
    )
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok": super_admin},
    )
    client = TestClient(app)
    # Operator-supplied limit > 1000 must be capped server-side
    resp = client.get(
        "/bridge/v1/audit?limit=99999",
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200


def test_audit_limit_zero_or_negative_clamps_to_min() -> None:
    super_admin = SessionContext(
        operator_id=1, operator_role="super_admin",
        session_tenant="msp_root", session_id="sess-super",
    )
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok": super_admin},
    )
    client = TestClient(app)
    resp = client.get(
        "/bridge/v1/audit?limit=0",
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Body shape validation
# ---------------------------------------------------------------------------

def test_execute_missing_body_returns_422() -> None:
    """FastAPI auto-422 on missing required fields when token is valid."""
    app, _, _ = _build_app(
        template=_basic_template(),
        tokens={"tok": _viewer_session()},
    )
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={},  # missing template_id
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 422


def test_execute_default_params_empty_dict() -> None:
    """params is optional, defaulting to {}."""
    template = QueryTemplate(
        template_id="no_params",
        description="no params",
        parameters={},
        response_schema={"x": "int"},
        requires_tenant_scope=True,
        min_role="viewer",
    )
    app, _, _ = _build_app(
        template=template,
        rows=[{"x": 1}],
        tokens={"tok": _viewer_session()},
    )
    client = TestClient(app)
    resp = client.post(
        "/bridge/v1/execute",
        json={"template_id": "no_params"},
        headers={"Authorization": "Bearer tok"},
    )
    assert resp.status_code == 200
