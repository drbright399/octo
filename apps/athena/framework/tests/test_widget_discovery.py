"""Tests for system-widget discovery — hermetic via tmp_path fixture packages.

Each test builds a tiny `<root>/<module>.py` tree under tmp_path and runs
discover_system_widgets() against it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from apps.athena.framework.widget_discovery import (
    WidgetDiscoveryReport,
    discover_system_widgets,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# A widget module that exposes a single WIDGET constant.
_SINGLE_WIDGET_TEMPLATE = '''\
from shared_widget_contract import WidgetDefinition

WIDGET = WidgetDefinition(
    widget_id="{widget_id}",
    title="{title}",
    description="test widget",
    default_size="medium",
    default_position="auto",
    data_query="{data_query}",
    render_component_ref="default-status-panel",
    categories=["system"],
    min_role="viewer",
    refresh_interval_sec=15,
)
'''

# Multi-widget module — exposes a WIDGETS list.
_MULTI_WIDGET_TEMPLATE = '''\
from shared_widget_contract import WidgetDefinition

WIDGETS = [
    WidgetDefinition(
        widget_id="{widget_id_a}",
        title="A",
        description="a",
        default_size="small",
        default_position="top-left",
        data_query="qa",
        render_component_ref="default-status-panel",
        categories=["system"],
        min_role="viewer",
        refresh_interval_sec=15,
    ),
    WidgetDefinition(
        widget_id="{widget_id_b}",
        title="B",
        description="b",
        default_size="small",
        default_position="top-right",
        data_query="qb",
        render_component_ref="default-status-panel",
        categories=["system"],
        min_role="viewer",
        refresh_interval_sec=15,
    ),
]
'''


def _make_pkg(parent: Path, name: str) -> Path:
    pkg_dir = parent / name
    pkg_dir.mkdir(parents=True, exist_ok=False)
    (pkg_dir / "__init__.py").write_text("")
    return pkg_dir


@pytest.fixture
def fixture_root(tmp_path: Path):
    parent = tmp_path / "widget_discovery_fixtures"
    parent.mkdir()
    sys.path.insert(0, str(parent))

    root_pkg_name = "fake_system_widgets_root"
    root = _make_pkg(parent, root_pkg_name)

    yield root, root_pkg_name

    if str(parent) in sys.path:
        sys.path.remove(str(parent))
    for key in list(sys.modules):
        if key == root_pkg_name or key.startswith(root_pkg_name + "."):
            del sys.modules[key]


# ---------------------------------------------------------------------------
# Single-widget modules
# ---------------------------------------------------------------------------

def test_discovers_single_widget(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "health.py").write_text(_SINGLE_WIDGET_TEMPLATE.format(
        widget_id="system.health-summary",
        title="Health Summary",
        data_query="health_summary",
    ))
    registry = WidgetRegistryImpl()
    report = discover_system_widgets(root_name, registry)
    assert "system.health-summary" in report.registered
    assert report.failed == []
    assert registry.get("system.health-summary") is not None


def test_module_without_widget_constant_skipped(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "nothing.py").write_text("# no widget here\n")
    registry = WidgetRegistryImpl()
    report = discover_system_widgets(root_name, registry)
    assert report.registered == []
    assert any("nothing" in s for s in report.skipped)


# ---------------------------------------------------------------------------
# Multi-widget modules
# ---------------------------------------------------------------------------

def test_discovers_multi_widget_module(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "ops.py").write_text(_MULTI_WIDGET_TEMPLATE.format(
        widget_id_a="system.ops-a",
        widget_id_b="system.ops-b",
    ))
    registry = WidgetRegistryImpl()
    report = discover_system_widgets(root_name, registry)
    assert sorted(report.registered) == ["system.ops-a", "system.ops-b"]


def test_mixed_modules_discovered_correctly(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "single.py").write_text(_SINGLE_WIDGET_TEMPLATE.format(
        widget_id="system.single",
        title="Single",
        data_query="single_q",
    ))
    (root / "multi.py").write_text(_MULTI_WIDGET_TEMPLATE.format(
        widget_id_a="system.multi-a",
        widget_id_b="system.multi-b",
    ))
    (root / "noop.py").write_text("# nothing\n")
    registry = WidgetRegistryImpl()
    report = discover_system_widgets(root_name, registry)
    assert sorted(report.registered) == [
        "system.multi-a", "system.multi-b", "system.single",
    ]
    assert any("noop" in s for s in report.skipped)


# ---------------------------------------------------------------------------
# Fault tolerance
# ---------------------------------------------------------------------------

def test_broken_module_recorded_as_failed(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "broken.py").write_text("raise RuntimeError('boom')\n")
    (root / "ok.py").write_text(_SINGLE_WIDGET_TEMPLATE.format(
        widget_id="system.ok",
        title="OK",
        data_query="ok_q",
    ))
    registry = WidgetRegistryImpl()
    report = discover_system_widgets(root_name, registry)
    assert "system.ok" in report.registered
    assert any("broken" in name and "boom" in err for name, err in report.failed)


def test_missing_root_package_recorded_as_failed() -> None:
    registry = WidgetRegistryImpl()
    report = discover_system_widgets("definitely.not.a.real.widgets.package", registry)
    assert report.registered == []
    assert any("definitely.not" in name for name, _ in report.failed)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_running_discovery_twice_is_idempotent(fixture_root) -> None:
    root, root_name = fixture_root
    (root / "single.py").write_text(_SINGLE_WIDGET_TEMPLATE.format(
        widget_id="system.single",
        title="Single",
        data_query="single_q",
    ))
    registry = WidgetRegistryImpl()
    discover_system_widgets(root_name, registry)
    # Second pass — registry's idempotent register_system_widget treats
    # same-definition re-registration as a no-op
    second = discover_system_widgets(root_name, registry)
    assert second.registered == ["system.single"]
    assert second.failed == []


# ---------------------------------------------------------------------------
# WidgetDiscoveryReport shape
# ---------------------------------------------------------------------------

def test_widget_discovery_report_default_shape() -> None:
    report = WidgetDiscoveryReport()
    assert report.registered == []
    assert report.skipped == []
    assert report.failed == []
