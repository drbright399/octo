"""Tests for the layout persistence runtime — repository + service.

Covers the LayoutService validation surface (registry-aware) and the
InMemoryLayoutRepository CRUD contract.
"""

from __future__ import annotations

import pytest

from shared_widget_contract import (
    LayoutGrid,
    LayoutItem,
    LayoutPosition,
    LayoutSize,
    WidgetDefinition,
)

from apps.athena.framework.layouts import (
    CURRENT_LAYOUT_VERSION,
    InMemoryLayoutRepository,
    LayoutService,
    LayoutValidationError,
    with_added_item,
    with_removed_widget,
    with_replaced_item,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _adapter_widget(
    widget_id: str,
    *,
    min_role: str = "viewer",
) -> WidgetDefinition:
    return WidgetDefinition(
        widget_id=widget_id,
        title=widget_id.replace("_", " ").title(),
        description=f"test widget {widget_id}",
        default_size="medium",
        default_position="auto",
        data_query="recent_findings",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role=min_role,  # type: ignore[arg-type]
        refresh_interval_sec=15,
    )


def _system_widget(
    widget_id: str,
    *,
    min_role: str = "viewer",
) -> WidgetDefinition:
    return WidgetDefinition(
        widget_id=widget_id,
        title=widget_id.replace("_", " ").title(),
        description=f"system widget {widget_id}",
        default_size="small",
        default_position="top-left",
        data_query="findings_queue",
        render_component_ref="default-status-panel",
        categories=["system"],
        min_role=min_role,  # type: ignore[arg-type]
        refresh_interval_sec=30,
    )


def _make_registry_with_active_adapter() -> WidgetRegistryImpl:
    """Registry with one adapter widget ACTIVE for client_a + one system widget."""
    reg = WidgetRegistryImpl()
    adapter_widget = _adapter_widget("datto_recent_alerts")
    reg.register_adapter_widget(adapter_widget, vendor_slug="datto_rmm")
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm",
        tenant_slug="client_a",
        active=True,
    )

    sys_widget = _system_widget("system_health_summary")
    reg.register_system_widget(sys_widget, module_name="system.health")
    return reg


def _layout_with(*items: LayoutItem) -> LayoutGrid:
    return LayoutGrid(version=CURRENT_LAYOUT_VERSION, grid=list(items))


def _item(widget_id: str, *, x: int = 0, y: int = 0, w: int = 4, h: int = 3) -> LayoutItem:
    return LayoutItem(
        widget_id=widget_id,
        position=LayoutPosition(x=x, y=y),
        size=LayoutSize(w=w, h=h),
    )


# ---------------------------------------------------------------------------
# Repository CRUD
# ---------------------------------------------------------------------------

def test_repository_get_returns_none_when_absent() -> None:
    repo = InMemoryLayoutRepository()
    assert repo.get(operator_id=1, tenant_slug="client_a") is None


def test_repository_put_then_get() -> None:
    repo = InMemoryLayoutRepository()
    layout = _layout_with(_item("w1"))
    repo.put(operator_id=1, tenant_slug="client_a", layout=layout)
    got = repo.get(operator_id=1, tenant_slug="client_a")
    assert got is not None
    assert got.widget_ids() == ["w1"]


def test_repository_put_overwrites_previous_layout() -> None:
    repo = InMemoryLayoutRepository()
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w2")))
    got = repo.get(operator_id=1, tenant_slug="client_a")
    assert got is not None
    assert got.widget_ids() == ["w2"]


def test_repository_delete_is_idempotent() -> None:
    repo = InMemoryLayoutRepository()
    # No-op when absent
    repo.delete(operator_id=1, tenant_slug="client_a")
    # Add then delete twice
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    repo.delete(operator_id=1, tenant_slug="client_a")
    repo.delete(operator_id=1, tenant_slug="client_a")
    assert repo.get(operator_id=1, tenant_slug="client_a") is None


def test_repository_per_tenant_isolation() -> None:
    repo = InMemoryLayoutRepository()
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    repo.put(operator_id=1, tenant_slug="client_b", layout=_layout_with(_item("w2")))
    got_a = repo.get(operator_id=1, tenant_slug="client_a")
    got_b = repo.get(operator_id=1, tenant_slug="client_b")
    assert got_a is not None and got_a.widget_ids() == ["w1"]
    assert got_b is not None and got_b.widget_ids() == ["w2"]


def test_repository_per_operator_isolation() -> None:
    repo = InMemoryLayoutRepository()
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    repo.put(operator_id=2, tenant_slug="client_a", layout=_layout_with(_item("w2")))
    assert repo.get(operator_id=1, tenant_slug="client_a").widget_ids() == ["w1"]
    assert repo.get(operator_id=2, tenant_slug="client_a").widget_ids() == ["w2"]


def test_repository_list_for_operator_returns_all_tenants() -> None:
    repo = InMemoryLayoutRepository()
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    repo.put(operator_id=1, tenant_slug="client_b", layout=_layout_with(_item("w2")))
    repo.put(operator_id=2, tenant_slug="client_a", layout=_layout_with(_item("w3")))
    layouts = repo.list_for_operator(operator_id=1)
    assert set(layouts.keys()) == {"client_a", "client_b"}


def test_repository_updated_at_tracks_writes() -> None:
    repo = InMemoryLayoutRepository()
    assert repo.updated_at(operator_id=1, tenant_slug="client_a") is None
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout_with(_item("w1")))
    ts = repo.updated_at(operator_id=1, tenant_slug="client_a")
    assert ts is not None
    assert ts.endswith("Z")


# ---------------------------------------------------------------------------
# LayoutService — validation
# ---------------------------------------------------------------------------

def test_save_unregistered_widget_rejected() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = _layout_with(_item("ghost_widget"))
    with pytest.raises(LayoutValidationError) as exc_info:
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )
    assert any("not registered" in r for r in exc_info.value.reasons)


def test_save_widget_below_role_rejected() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(
        _adapter_widget("admin_only_widget", min_role="admin"),
        vendor_slug="datto_rmm",
    )
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm", tenant_slug="client_a", active=True,
    )
    service = LayoutService(registry=reg)
    layout = _layout_with(_item("admin_only_widget"))
    with pytest.raises(LayoutValidationError) as exc_info:
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )
    assert any("requires role" in r for r in exc_info.value.reasons)


def test_save_adapter_widget_inactive_for_tenant_rejected() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(
        _adapter_widget("datto_recent_alerts"),
        vendor_slug="datto_rmm",
    )
    # Adapter NOT activated for client_b
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm", tenant_slug="client_a", active=True,
    )
    service = LayoutService(registry=reg)
    layout = _layout_with(_item("datto_recent_alerts"))
    with pytest.raises(LayoutValidationError) as exc_info:
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_b", layout=layout,
        )
    assert any("not\n           ACTIVE" in r or "not ACTIVE" in r for r in exc_info.value.reasons)


def test_save_system_widget_works_for_any_tenant() -> None:
    reg = WidgetRegistryImpl()
    reg.register_system_widget(
        _system_widget("system_health_summary"),
        module_name="system.health",
    )
    service = LayoutService(registry=reg)
    layout = _layout_with(_item("system_health_summary"))
    # No adapters configured for any tenant; system widget still ok
    persisted = service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="any_tenant", layout=layout,
    )
    assert persisted.widget_ids() == ["system_health_summary"]


def test_save_duplicate_widget_id_rejected() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = _layout_with(
        _item("datto_recent_alerts"),
        _item("datto_recent_alerts", x=4),
    )
    with pytest.raises(LayoutValidationError) as exc_info:
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )
    assert any("duplicate widget_id" in r for r in exc_info.value.reasons)


def test_save_negative_position_rejected() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = _layout_with(_item("datto_recent_alerts", x=-1, y=0))
    with pytest.raises(LayoutValidationError):
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )


def test_save_zero_size_rejected() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = _layout_with(_item("datto_recent_alerts", w=0, h=0))
    with pytest.raises(LayoutValidationError):
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )


def test_save_collects_multiple_reasons() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = _layout_with(
        _item("ghost_one"),
        _item("ghost_two"),
        _item("datto_recent_alerts", x=-1),
    )
    with pytest.raises(LayoutValidationError) as exc_info:
        service.save_layout(
            operator_id=1, operator_role="viewer",
            tenant_slug="client_a", layout=layout,
        )
    # All three issues surfaced — UI can render field-level errors
    assert len(exc_info.value.reasons) >= 3


# ---------------------------------------------------------------------------
# LayoutService — happy path + reads
# ---------------------------------------------------------------------------

def test_save_valid_layout_persists_and_normalizes_version() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = LayoutGrid(version=999, grid=[_item("datto_recent_alerts")])
    persisted = service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=layout,
    )
    assert persisted.version == CURRENT_LAYOUT_VERSION
    got = service.get_layout(operator_id=1, tenant_slug="client_a")
    assert got is not None
    assert got.widget_ids() == ["datto_recent_alerts"]


def test_get_or_default_returns_empty_layout_when_absent() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    layout = service.get_or_default(operator_id=99, tenant_slug="client_a")
    assert layout.version == CURRENT_LAYOUT_VERSION
    assert layout.grid == []


def test_get_or_default_returns_saved_layout_when_present() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=_layout_with(_item("datto_recent_alerts")),
    )
    layout = service.get_or_default(operator_id=1, tenant_slug="client_a")
    assert layout.widget_ids() == ["datto_recent_alerts"]


def test_delete_layout() -> None:
    service = LayoutService(registry=_make_registry_with_active_adapter())
    service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=_layout_with(_item("datto_recent_alerts")),
    )
    assert service.get_layout(operator_id=1, tenant_slug="client_a") is not None
    service.delete_layout(operator_id=1, tenant_slug="client_a")
    assert service.get_layout(operator_id=1, tenant_slug="client_a") is None


def test_list_layouts_returns_per_tenant_dict() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(_adapter_widget("w1"), vendor_slug="datto_rmm")
    reg._set_adapter_active_for_tenant(vendor_slug="datto_rmm", tenant_slug="client_a", active=True)
    reg._set_adapter_active_for_tenant(vendor_slug="datto_rmm", tenant_slug="client_b", active=True)
    service = LayoutService(registry=reg)
    service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=_layout_with(_item("w1")),
    )
    service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_b", layout=_layout_with(_item("w1")),
    )
    layouts = service.list_layouts(operator_id=1)
    assert set(layouts.keys()) == {"client_a", "client_b"}


# ---------------------------------------------------------------------------
# Clone-with helpers
# ---------------------------------------------------------------------------

def test_with_added_item_appends() -> None:
    base = _layout_with(_item("w1"))
    new = with_added_item(base, _item("w2"))
    assert new.widget_ids() == ["w1", "w2"]
    # Original unchanged (frozen)
    assert base.widget_ids() == ["w1"]


def test_with_removed_widget() -> None:
    base = _layout_with(_item("w1"), _item("w2"), _item("w3"))
    new = with_removed_widget(base, "w2")
    assert new.widget_ids() == ["w1", "w3"]


def test_with_removed_widget_no_op_when_absent() -> None:
    base = _layout_with(_item("w1"))
    new = with_removed_widget(base, "ghost")
    assert new.widget_ids() == ["w1"]


def test_with_replaced_item_replaces() -> None:
    base = _layout_with(_item("w1", x=0), _item("w2"))
    new = with_replaced_item(base, _item("w1", x=99))
    assert new.widget_ids() == ["w1", "w2"]
    assert new.grid[0].position.x == 99


def test_with_replaced_item_appends_when_new() -> None:
    base = _layout_with(_item("w1"))
    new = with_replaced_item(base, _item("w2"))
    assert new.widget_ids() == ["w1", "w2"]


# ---------------------------------------------------------------------------
# Role-hierarchy ladder check
# ---------------------------------------------------------------------------

def test_admin_can_save_admin_role_widget() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(
        _adapter_widget("admin_widget", min_role="admin"),
        vendor_slug="datto_rmm",
    )
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm", tenant_slug="client_a", active=True,
    )
    service = LayoutService(registry=reg)
    persisted = service.save_layout(
        operator_id=1, operator_role="admin",
        tenant_slug="client_a", layout=_layout_with(_item("admin_widget")),
    )
    assert persisted.widget_ids() == ["admin_widget"]


def test_super_admin_can_save_admin_role_widget() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(
        _adapter_widget("admin_widget", min_role="admin"),
        vendor_slug="datto_rmm",
    )
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm", tenant_slug="client_a", active=True,
    )
    service = LayoutService(registry=reg)
    persisted = service.save_layout(
        operator_id=1, operator_role="super_admin",
        tenant_slug="client_a", layout=_layout_with(_item("admin_widget")),
    )
    assert persisted.widget_ids() == ["admin_widget"]


def test_analyst_blocked_from_admin_role_widget() -> None:
    reg = WidgetRegistryImpl()
    reg.register_adapter_widget(
        _adapter_widget("admin_widget", min_role="admin"),
        vendor_slug="datto_rmm",
    )
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto_rmm", tenant_slug="client_a", active=True,
    )
    service = LayoutService(registry=reg)
    with pytest.raises(LayoutValidationError):
        service.save_layout(
            operator_id=1, operator_role="analyst",
            tenant_slug="client_a", layout=_layout_with(_item("admin_widget")),
        )
