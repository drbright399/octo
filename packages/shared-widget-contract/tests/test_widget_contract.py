"""Conformance tests for the widget framework contract."""

from __future__ import annotations

import pytest

from shared_widget_contract import (
    DEFAULT_RENDER_COMPONENTS,
    WIDGET_CONTRACT_VERSION,
    ConfigurableParam,
    LayoutGrid,
    LayoutItem,
    LayoutPosition,
    LayoutSize,
    RegisteredWidget,
    WidgetDefinition,
    WidgetSource,
)


def test_contract_version_exported() -> None:
    assert WIDGET_CONTRACT_VERSION == "1.0"


def test_default_render_components_set() -> None:
    """The 5 canonical render components are exported for adapter authors."""
    assert "default-alert-feed" in DEFAULT_RENDER_COMPONENTS
    assert "default-counter-grid" in DEFAULT_RENDER_COMPONENTS
    assert "default-time-series" in DEFAULT_RENDER_COMPONENTS
    assert "default-list-with-actions" in DEFAULT_RENDER_COMPONENTS
    assert "default-status-panel" in DEFAULT_RENDER_COMPONENTS
    assert len(DEFAULT_RENDER_COMPONENTS) == 5


def test_widget_definition_minimal() -> None:
    """A minimal valid widget definition can be instantiated."""
    w = WidgetDefinition(
        widget_id="test.demo",
        title="Test Demo",
        description="A test widget",
        default_size="medium",
        default_position="auto",
        data_query="recent_findings",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role="analyst",
        refresh_interval_sec=15,
    )
    assert w.widget_id == "test.demo"
    assert w.contract_version == "1.0"


def test_refresh_interval_floor_enforced() -> None:
    """Per ADR-006 Q1: framework enforces 5-second minimum."""
    with pytest.raises(ValueError, match="refresh_interval_sec=3"):
        WidgetDefinition(
            widget_id="test.too-fast",
            title="Too Fast",
            description="bad",
            default_size="small",
            default_position="auto",
            data_query="x",
            render_component_ref="default-alert-feed",
            categories=["source-adapter"],
            min_role="analyst",
            refresh_interval_sec=3,
        )


def test_refresh_interval_floor_value_5_ok() -> None:
    """5 is the floor; should be accepted."""
    w = WidgetDefinition(
        widget_id="test.exact-floor",
        title="Floor",
        description="exactly the floor",
        default_size="small",
        default_position="auto",
        data_query="x",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role="analyst",
        refresh_interval_sec=5,
    )
    assert w.refresh_interval_sec == 5


def test_widget_definition_with_grid_size() -> None:
    """default_size accepts (int, int) tuples for grid units."""
    w = WidgetDefinition(
        widget_id="test.grid-sized",
        title="Grid",
        description="grid sized",
        default_size=(8, 6),
        default_position="top-left",
        data_query="x",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role="analyst",
        refresh_interval_sec=10,
    )
    assert w.default_size == (8, 6)


def test_configurable_param() -> None:
    """ConfigurableParam declarations are flexible across kinds."""
    p = ConfigurableParam(
        name="severity_filter",
        label="Severity",
        kind="severity_filter",
        description="Which severities to show",
        default_value=["high", "critical"],
    )
    assert p.name == "severity_filter"


def test_layout_grid_widget_ids() -> None:
    """LayoutGrid.widget_ids() returns the IDs in placement order."""
    grid = LayoutGrid(
        version=1,
        grid=[
            LayoutItem(
                widget_id="alpha",
                position=LayoutPosition(x=0, y=0),
                size=LayoutSize(w=6, h=4),
            ),
            LayoutItem(
                widget_id="beta",
                position=LayoutPosition(x=6, y=0),
                size=LayoutSize(w=6, h=4),
            ),
        ],
    )
    assert grid.widget_ids() == ["alpha", "beta"]


def test_layout_visible_items_excludes_hidden() -> None:
    """visible_items() filters out hidden=True entries (operator preference)."""
    grid = LayoutGrid(
        version=1,
        grid=[
            LayoutItem(
                widget_id="alpha",
                position=LayoutPosition(x=0, y=0),
                size=LayoutSize(w=6, h=4),
            ),
            LayoutItem(
                widget_id="beta",
                position=LayoutPosition(x=6, y=0),
                size=LayoutSize(w=6, h=4),
                hidden=True,
            ),
        ],
    )
    visible = grid.visible_items()
    assert len(visible) == 1
    assert visible[0].widget_id == "alpha"


def test_registered_widget_shape() -> None:
    """RegisteredWidget combines a definition with runtime registry context."""
    w = WidgetDefinition(
        widget_id="datto-rmm.alert-feed",
        title="Datto RMM Alerts",
        description="Live Datto RMM alert feed",
        default_size="large",
        default_position="auto",
        data_query="datto_rmm.recent_alerts",
        render_component_ref="default-alert-feed",
        categories=["source-adapter", "rmm"],
        min_role="analyst",
        refresh_interval_sec=30,
    )
    rw = RegisteredWidget(
        definition=w,
        source=WidgetSource(kind="adapter", identifier="datto-rmm"),
        available_for_tenants=["client-a", "client-b"],
        contract_version="1.0",
    )
    assert rw.source.kind == "adapter"
    assert "client-a" in rw.available_for_tenants


def test_widget_definition_immutable() -> None:
    """WidgetDefinition is a frozen dataclass."""
    w = WidgetDefinition(
        widget_id="test.x",
        title="x",
        description="x",
        default_size="small",
        default_position="auto",
        data_query="x",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role="analyst",
        refresh_interval_sec=15,
    )
    with pytest.raises(Exception):
        w.title = "y"  # type: ignore[misc]
