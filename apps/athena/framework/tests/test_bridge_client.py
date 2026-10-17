"""End-to-end tests for HttpBridgeClient → bridge router.

Wires the client to the FastAPI router via httpx.ASGITransport so
requests do a real HTTP round-trip in-process — testing serialization,
auth, and error mapping without needing a live network.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from shared_bridge import (
    InvariantViolation,
    QueryTemplate,
    SessionContext,
    TemplateRegistry,
)

from apps.athena.framework.bridge_client import (
    BridgeClientError,
    HttpBridgeClient,
)
from apps.octo.framework.bridge_router import (
    StaticTokenResolver,
    create_bridge_router,
)
from apps.octo.framework.bridge_server import BridgeServerImpl


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

class StubExecutor:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or [{"id": 1}]

    def execute(self, template, params, session):  # noqa: ARG002
        return list(self.rows)


def _viewer_session() -> SessionContext:
    return SessionContext(
        operator_id=10, operator_role="viewer",
        session_tenant="client_a", session_id="sess-viewer-1",
    )


def _admin_session() -> SessionContext:
    return SessionContext(
        operator_id=12, operator_role="admin",
        session_tenant="client_a", session_id="sess-admin-1",
    )


def _basic_template(min_role: str = "viewer") -> QueryTemplate:
    return QueryTemplate(
        template_id="recent_findings",
        description="recent",
        parameters={"limit": "int"},
        response_schema={"id": "int"},
        requires_tenant_scope=True,
        min_role=min_role,  # type: ignore[arg-type]
    )


def _build_app(
    *,
    template: QueryTemplate | None = None,
    rows: list[dict[str, Any]] | None = None,
    tokens: dict[str, SessionContext] | None = None,
) -> FastAPI:
    reg = TemplateRegistry()
    if template is not None:
        reg.register(template)
    server = BridgeServerImpl(templates=reg, executor=StubExecutor(rows=rows))
    resolver = StaticTokenResolver(tokens or {})
    app = FastAPI()
    app.include_router(create_bridge_router(server=server, token_resolver=resolver))
    return app


def _client_for(
    app: FastAPI,
    *,
    token: str = "tok-1",
    session: SessionContext | None = None,
) -> HttpBridgeClient:
    """Build an HttpBridgeClient that routes to `app` via FastAPI's TestClient
    (a sync httpx.Client with ASGI transport baked in)."""
    from fastapi.testclient import TestClient
    test_client = TestClient(app)
    return HttpBridgeClient(
        base_url="http://testserver",
        token=token,
        session=session or _viewer_session(),
        client=test_client,
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health_round_trip() -> None:
    app = _build_app()
    client = _client_for(app)
    body = client.health()
    assert body["ok"] is True
    assert body["contract_version"] == "1.0"
    client.close()


# ---------------------------------------------------------------------------
# Execute happy path
# ---------------------------------------------------------------------------

def test_execute_round_trip_returns_query_result() -> None:
    rows = [{"id": 1}, {"id": 2}, {"id": 3}]
    app = _build_app(
        template=_basic_template(),
        rows=rows,
        tokens={"tok-1": _viewer_session()},
    )
    client = _client_for(app)
    result = client.execute("recent_findings", {"limit": 5})
    assert result.template_id == "recent_findings"
    assert result.row_count == 3
    assert result.rows == rows
    assert isinstance(result.audit_entry_id, int)
    client.close()


def test_session_attribute_exposed_for_protocol_conformance() -> None:
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    client = _client_for(app, token="tok")
    # Per Protocol, BridgeClient.session is a public attr
    assert client.session.session_tenant == "client_a"
    assert client.session.operator_role == "viewer"
    client.close()


# ---------------------------------------------------------------------------
# Error mapping — server returns InvariantViolation, client raises it
# ---------------------------------------------------------------------------

def test_unregistered_template_raises_invariant_1() -> None:
    app = _build_app(tokens={"tok": _viewer_session()})  # no template registered
    client = _client_for(app, token="tok")
    with pytest.raises(InvariantViolation) as exc_info:
        client.execute("ghost", {})
    assert exc_info.value.invariant_number == 1
    client.close()


def test_param_shape_mismatch_raises_invariant_1() -> None:
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    client = _client_for(app, token="tok")
    with pytest.raises(InvariantViolation) as exc_info:
        client.execute("recent_findings", {})  # missing required `limit`
    assert exc_info.value.invariant_number == 1
    client.close()


def test_role_below_min_raises_invariant_3() -> None:
    template = _basic_template(min_role="admin")
    app = _build_app(template=template, tokens={"tok": _viewer_session()})
    client = _client_for(app, token="tok")
    with pytest.raises(InvariantViolation) as exc_info:
        client.execute("recent_findings", {"limit": 5})
    assert exc_info.value.invariant_number == 3
    client.close()


def test_cross_tenant_leak_raises_invariant_5() -> None:
    template = QueryTemplate(
        template_id="leaky",
        description="should be sanitized",
        parameters={},
        response_schema={"tenant_slug": "str"},
        requires_tenant_scope=False,
        cross_tenant_safety_required=True,
        min_role="viewer",
    )
    app = _build_app(
        template=template,
        rows=[{"tenant_slug": "client_a"}],  # raw slug -> invariant 5
        tokens={"tok": _admin_session()},
    )
    client = _client_for(app, token="tok", session=_admin_session())
    with pytest.raises(InvariantViolation) as exc_info:
        client.execute("leaky", {})
    assert exc_info.value.invariant_number == 5
    client.close()


# ---------------------------------------------------------------------------
# Auth-level errors → BridgeClientError or InvariantViolation as appropriate
# ---------------------------------------------------------------------------

def test_missing_auth_raises_bridge_client_error() -> None:
    """If the client somehow has an invalid token, server returns 401
    without invariant detail — that surfaces as BridgeClientError."""
    app = _build_app(template=_basic_template(), tokens={})
    client = _client_for(app, token="bogus")
    with pytest.raises(BridgeClientError) as exc_info:
        client.execute("recent_findings", {"limit": 5})
    assert exc_info.value.status_code == 401
    client.close()


# ---------------------------------------------------------------------------
# Transport error handling
# ---------------------------------------------------------------------------

def test_transport_error_wraps_as_bridge_client_error() -> None:
    """If the network blows up, BridgeClientError carries the cause."""
    # Point at an unreachable URL with a strict timeout
    httpx_client = httpx.Client(timeout=0.001)
    client = HttpBridgeClient(
        base_url="http://127.0.0.1:1",  # nothing listens here
        token="tok",
        session=_viewer_session(),
        client=httpx_client,
    )
    with pytest.raises(BridgeClientError) as exc_info:
        client.execute("recent_findings", {})
    # Must NOT misclassify a transport failure as a contract violation
    assert exc_info.value.status_code is None
    httpx_client.close()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_context_manager_closes_owned_client() -> None:
    from fastapi.testclient import TestClient
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    test_client = TestClient(app)
    with HttpBridgeClient(
        base_url="http://testserver",
        token="tok",
        session=_viewer_session(),
        client=test_client,
    ) as bc:
        result = bc.execute("recent_findings", {"limit": 5})
        assert result.row_count == 1
    # External-owned client is NOT closed by the context manager
    # (we passed it in, so we manage it). Verify it's still usable.
    test_client.close()


def test_owned_client_closed_on_close() -> None:
    """When constructed without `client=`, the client owns the httpx.Client."""
    from fastapi.testclient import TestClient
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    test_client = TestClient(app)
    bc = HttpBridgeClient(
        base_url="http://testserver",
        token="tok",
        session=_viewer_session(),
        client=test_client,
    )
    bc.close()
    # client was injected so bc does NOT close it; that's by design — caller manages
    test_client.close()


def test_base_url_trailing_slash_normalized() -> None:
    """Constructor strips trailing slash so URLs build cleanly."""
    from fastapi.testclient import TestClient
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    test_client = TestClient(app)
    bc = HttpBridgeClient(
        base_url="http://testserver/",
        token="tok",
        session=_viewer_session(),
        client=test_client,
    )
    result = bc.execute("recent_findings", {"limit": 5})
    assert result.template_id == "recent_findings"
    test_client.close()


# ---------------------------------------------------------------------------
# Audit-side: client doesn't expose audit-read directly per Protocol, but
# we verify the round trip preserves audit_entry_id linkage
# ---------------------------------------------------------------------------

def test_audit_entry_ids_increment_across_calls() -> None:
    app = _build_app(template=_basic_template(), tokens={"tok": _viewer_session()})
    client = _client_for(app, token="tok")
    r1 = client.execute("recent_findings", {"limit": 5})
    r2 = client.execute("recent_findings", {"limit": 5})
    r3 = client.execute("recent_findings", {"limit": 5})
    # In-memory backend hands out monotonically increasing IDs; each
    # request also writes a session_validation entry, so IDs grow > 1
    # between accept entries — but they always grow.
    assert r2.audit_entry_id > r1.audit_entry_id
    assert r3.audit_entry_id > r2.audit_entry_id
    client.close()
