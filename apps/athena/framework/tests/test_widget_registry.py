"""Tests for the widget registry runtime."""

from __future__ import annotations

from typing import Any

import pytest

from shared_adapter_contract import (
    BaseSourceAdapter,
    CanonicalEvent,
    CredentialField,
    DeepLinkType,
    Severity,
    SmokeResult,
    TenantMappingShape,
)
from shared_widget_contract import WidgetDefinition

from apps.athena.framework.widget_registry import WidgetRegistryImpl
from apps.octo.framework.registry import AdapterRegistry


# ---------------------------------------------------------------------------
# Fixture widgets
# ---------------------------------------------------------------------------

def _adapter_widget(
    *,
    widget_id: str,
    title: str = "Demo",
    min_role: str = "analyst",
    categories: list[str] | None = None,
) -> WidgetDefinition:
    return WidgetDefinition(
        widget_id=widget_id,
        title=title,
        description=f"{title} description",
        default_size="medium",
        default_position="auto",
        data_query="recent_findings",
        render_component_ref="default-alert-feed",
        categories=categories or ["source-adapter"],
        min_role=min_role,  # type: ignore[arg-type]
        refresh_interval_sec=15,
    )


def _system_widget(
    *,
    widget_id: str,
    title: str = "System",
    min_role: str = "viewer",
    categories: list[str] | None = None,
) -> WidgetDefinition:
    return WidgetDefinition(
        widget_id=widget_id,
        title=title,
        description=f"{title} description",
        default_size="large",
        default_position="auto",
        data_query="findings_queue",
        render_component_ref="default-list-with-actions",
        categories=categories or ["system"],
        min_role=min_role,  # type: ignore[arg-type]
        refresh_interval_sec=15,
    )


# ---------------------------------------------------------------------------
# Fixture adapter (used for AdapterRegistry integration tests)
# ---------------------------------------------------------------------------

class _IntegrationTestAdapter(BaseSourceAdapter):
    vendor_slug = "test-vendor"
    vendor_display_name = "Test Vendor"
    vendor_logo_path = "/logos/test.svg"
    auth_model = "api-key"
    delivery_mode = "poll"
    compliance_categories = ["general"]

    def credential_shape(self) -> list[CredentialField]:
        return []

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api", fetch_endpoint="/x",
            vendor_tenant_id_field="id", vendor_tenant_label_field="n",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        return SmokeResult(ok=True, message="ok")

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        return CanonicalEvent(
            vendor_event_id="x", received_at="2026-05-04T18:00:00.000Z",
            severity="info", indicator=None, indicator_type=None,
            source_host=None, summary="x", payload={}, payload_sha256="0" * 64,
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        return None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return "info"

    def human_summary(self, event: CanonicalEvent) -> str:
        return "x"

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        return None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_register_adapter_widget() -> None:
    reg = WidgetRegistryImpl()
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")
    assert reg.get("test-vendor.alerts") is not None


def test_register_adapter_widget_idempotent() -> None:
    reg = WidgetRegistryImpl()
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")
    # Should not raise; widget appears once
    listed = reg.list(role="super_admin")
    matching = [w for w in listed if w.definition.widget_id == "test-vendor.alerts"]
    assert len(matching) == 1


def test_register_adapter_widget_different_def_rejected() -> None:
    reg = WidgetRegistryImpl()
    widget1 = _adapter_widget(widget_id="test-vendor.alerts", title="Alerts")
    widget2 = _adapter_widget(widget_id="test-vendor.alerts", title="DIFFERENT")
    reg.register_adapter_widget(widget1, vendor_slug="test-vendor")
    with pytest.raises(ValueError, match="already registered"):
        reg.register_adapter_widget(widget2, vendor_slug="test-vendor")


def test_register_adapter_widget_different_vendor_rejected() -> None:
    reg = WidgetRegistryImpl()
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")
    with pytest.raises(ValueError, match="already registered"):
        reg.register_adapter_widget(widget, vendor_slug="other-vendor")


def test_register_system_widget() -> None:
    reg = WidgetRegistryImpl()
    widget = _system_widget(widget_id="system.findings-queue")
    reg.register_system_widget(widget, module_name="findings_queue")
    found = reg.get("system.findings-queue")
    assert found is not None
    assert found.source.kind == "system"
    assert found.source.identifier == "findings_queue"


def test_register_system_widget_different_def_rejected() -> None:
    reg = WidgetRegistryImpl()
    widget1 = _system_widget(widget_id="system.q", title="Q1")
    widget2 = _system_widget(widget_id="system.q", title="Q2")
    reg.register_system_widget(widget1, module_name="q")
    with pytest.raises(ValueError, match="already registered"):
        reg.register_system_widget(widget2, module_name="q")


# ---------------------------------------------------------------------------
# list() filtering by role
# ---------------------------------------------------------------------------

def test_list_filters_by_role() -> None:
    reg = WidgetRegistryImpl()
    super_only = _adapter_widget(widget_id="test.super-only", min_role="super_admin")
    visible_to_all = _adapter_widget(widget_id="test.visible-to-all", min_role="viewer")
    reg.register_adapter_widget(super_only, vendor_slug="test-vendor")
    reg.register_adapter_widget(visible_to_all, vendor_slug="test-vendor")

    viewer_listed = reg.list(role="viewer")
    super_listed = reg.list(role="super_admin")

    viewer_ids = {w.definition.widget_id for w in viewer_listed}
    super_ids = {w.definition.widget_id for w in super_listed}

    assert "test.super-only" not in viewer_ids
    assert "test.visible-to-all" in viewer_ids
    assert "test.super-only" in super_ids
    assert "test.visible-to-all" in super_ids


def test_list_role_hierarchy_ladder() -> None:
    """Each higher role sees everything its lower role does, plus more."""
    reg = WidgetRegistryImpl()
    for role in ("viewer", "analyst", "admin", "super_admin"):
        widget = _adapter_widget(widget_id=f"test.{role}-only", min_role=role)
        reg.register_adapter_widget(widget, vendor_slug=f"test-{role}")

    viewer = {w.definition.widget_id for w in reg.list(role="viewer")}
    analyst = {w.definition.widget_id for w in reg.list(role="analyst")}
    admin = {w.definition.widget_id for w in reg.list(role="admin")}
    super_admin = {w.definition.widget_id for w in reg.list(role="super_admin")}

    assert viewer == {"test.viewer-only"}
    assert viewer < analyst
    assert analyst < admin
    assert admin < super_admin


# ---------------------------------------------------------------------------
# list() tenant_scope filtering
# ---------------------------------------------------------------------------

def test_list_tenant_scope_filters_adapter_widgets() -> None:
    """When tenant_scope is set, adapter widgets only appear if the adapter is
    ACTIVE for that tenant."""
    reg = WidgetRegistryImpl()
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")

    # Adapter not active anywhere yet
    assert len(reg.list(role="analyst", tenant_scope="client-a")) == 0

    # Mark active for client-a
    reg._set_adapter_active_for_tenant(
        vendor_slug="test-vendor", tenant_slug="client-a", active=True,
    )
    assert len(reg.list(role="analyst", tenant_scope="client-a")) == 1
    assert len(reg.list(role="analyst", tenant_scope="client-b")) == 0


def test_list_tenant_scope_includes_system_widgets() -> None:
    """System widgets are tenant-agnostic — appear regardless of tenant_scope."""
    reg = WidgetRegistryImpl()
    sw = _system_widget(widget_id="system.findings-queue")
    reg.register_system_widget(sw, module_name="findings_queue")

    # No adapters active; system widget still appears
    listed = reg.list(role="analyst", tenant_scope="client-a")
    assert any(w.definition.widget_id == "system.findings-queue" for w in listed)


def test_list_no_tenant_scope_includes_all_active_widgets() -> None:
    """When tenant_scope is None, adapter widgets appear if ACTIVE for ANY tenant."""
    reg = WidgetRegistryImpl()
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    reg.register_adapter_widget(widget, vendor_slug="test-vendor")
    reg._set_adapter_active_for_tenant(
        vendor_slug="test-vendor", tenant_slug="client-a", active=True,
    )

    listed = reg.list(role="analyst", tenant_scope=None)
    assert any(w.definition.widget_id == "test-vendor.alerts" for w in listed)


# ---------------------------------------------------------------------------
# AdapterRegistry integration — listener pattern
# ---------------------------------------------------------------------------

def test_widget_registry_subscribes_to_adapter_registry() -> None:
    """When the widget registry is constructed with an adapter registry,
    state transitions to/from ACTIVE update widget visibility."""
    adapter_reg = AdapterRegistry()
    adapter_reg.register_adapter_class(_IntegrationTestAdapter)

    widget_reg = WidgetRegistryImpl(adapter_registry=adapter_reg)
    widget = _adapter_widget(widget_id="test-vendor.alerts")
    widget_reg.register_adapter_widget(widget, vendor_slug="test-vendor")

    # Adapter not yet active
    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 0

    # Configure + activate
    inst = adapter_reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    adapter_reg.activate(inst.instance_key)

    # Widget now visible for that tenant
    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 1


def test_pause_removes_widget_visibility() -> None:
    """Adapter PAUSE → widget no longer available for the tenant."""
    adapter_reg = AdapterRegistry()
    adapter_reg.register_adapter_class(_IntegrationTestAdapter)
    widget_reg = WidgetRegistryImpl(adapter_registry=adapter_reg)
    widget_reg.register_adapter_widget(
        _adapter_widget(widget_id="test-vendor.alerts"), vendor_slug="test-vendor",
    )

    inst = adapter_reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    adapter_reg.activate(inst.instance_key)
    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 1

    adapter_reg.pause(inst.instance_key, reason="break")
    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 0


def test_remove_terminates_widget_availability() -> None:
    """Adapter REMOVED → widget unavailable everywhere for that adapter."""
    adapter_reg = AdapterRegistry()
    adapter_reg.register_adapter_class(_IntegrationTestAdapter)
    widget_reg = WidgetRegistryImpl(adapter_registry=adapter_reg)
    widget_reg.register_adapter_widget(
        _adapter_widget(widget_id="test-vendor.alerts"), vendor_slug="test-vendor",
    )

    inst = adapter_reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    adapter_reg.activate(inst.instance_key)
    adapter_reg.remove(inst.instance_key, reason="cleanup")

    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 0


def test_resume_restores_widget_visibility() -> None:
    """Adapter PAUSE → RESUME → widget visible again."""
    adapter_reg = AdapterRegistry()
    adapter_reg.register_adapter_class(_IntegrationTestAdapter)
    widget_reg = WidgetRegistryImpl(adapter_registry=adapter_reg)
    widget_reg.register_adapter_widget(
        _adapter_widget(widget_id="test-vendor.alerts"), vendor_slug="test-vendor",
    )

    inst = adapter_reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    adapter_reg.activate(inst.instance_key)
    adapter_reg.pause(inst.instance_key, reason="break")
    adapter_reg.resume(inst.instance_key)

    assert len(widget_reg.list(role="analyst", tenant_scope="client-a")) == 1


# ---------------------------------------------------------------------------
# get() + categories()
# ---------------------------------------------------------------------------

def test_get_returns_none_for_unregistered() -> None:
    reg = WidgetRegistryImpl()
    assert reg.get("nonexistent.widget") is None


def test_get_returns_system_widget() -> None:
    reg = WidgetRegistryImpl()
    sw = _system_widget(widget_id="system.audit-status")
    reg.register_system_widget(sw, module_name="audit_status")
    found = reg.get("system.audit-status")
    assert found is not None
    assert found.source.kind == "system"


def test_categories_aggregates_across_widgets() -> None:
    reg = WidgetRegistryImpl()
    w1 = _adapter_widget(widget_id="test.a", categories=["source-adapter", "rmm"])
    w2 = _adapter_widget(widget_id="test.b", categories=["source-adapter", "edr"])
    s1 = _system_widget(widget_id="system.fq", categories=["system", "compliance"])
    reg.register_adapter_widget(w1, vendor_slug="t1")
    reg.register_adapter_widget(w2, vendor_slug="t2")
    reg.register_system_widget(s1, module_name="fq")

    cats = reg.categories()
    assert "source-adapter" in cats
    assert "rmm" in cats
    assert "edr" in cats
    assert "system" in cats
    assert "compliance" in cats


def test_categories_dedups() -> None:
    """Same category appearing on multiple widgets returns once in categories()."""
    reg = WidgetRegistryImpl()
    w1 = _adapter_widget(widget_id="t.a", categories=["source-adapter"])
    w2 = _adapter_widget(widget_id="t.b", categories=["source-adapter"])
    reg.register_adapter_widget(w1, vendor_slug="v1")
    reg.register_adapter_widget(w2, vendor_slug="v2")

    cats = reg.categories()
    assert cats.count("source-adapter") == 1


def test_categories_sorted() -> None:
    reg = WidgetRegistryImpl()
    w = _adapter_widget(widget_id="t.a", categories=["z-cat", "a-cat", "m-cat"])
    reg.register_adapter_widget(w, vendor_slug="v")
    assert reg.categories() == ["a-cat", "m-cat", "z-cat"]
