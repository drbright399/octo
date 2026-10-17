"""End-to-end tests for the framework boot module.

Exercises the whole pipeline: discovery → registry → widget extraction.
Uses tmp_path fixture packages so tests don't depend on production
adapter / widget directories being populated.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from apps.athena.framework.boot import (
    BootReport,
    boot_framework,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl
from apps.octo.framework.lifecycle import AdapterLifecycleState
from apps.octo.framework.registry import AdapterRegistry


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# Adapter package template — class + co-located WIDGET constant.
_ADAPTER_WITH_WIDGET = '''\
from shared_widget_contract import WidgetDefinition

WIDGET = WidgetDefinition(
    widget_id="{widget_id}",
    title="{display}",
    description="adapter widget for {slug}",
    default_size="medium",
    default_position="auto",
    data_query="{slug}.recent_alerts",
    render_component_ref="default-alert-feed",
    categories=["source-adapter"],
    min_role="viewer",
    refresh_interval_sec=15,
)


class {cls_name}:
    vendor_slug = "{slug}"
    vendor_display_name = "{display}"
    vendor_logo_path = "logos/{slug}.svg"
    contract_version = "1.0"
    auth_model = "api_key"
    delivery_mode = "pull"
    availability = "ga"
    compliance_categories = []

    def credential_shape(self): return []
    def tenant_mapping_shape(self): return None
    def smoke_test(self, credentials): return None
    def start(self, instance_config): pass
    def stop(self): pass
    def health(self): return None
    def extract_event(self, raw_envelope): return None
    def route_to_tenant(self, raw_envelope): return None
    def severity_map(self, raw_envelope): return "info"
    def human_summary(self, event): return ""
    def rate_limit_hints(self): return None
    def widget_definition(self): return None
    def deep_link(self, event, link_type): return None
'''

# Adapter package WITHOUT a co-located widget — class only.
_ADAPTER_WITHOUT_WIDGET = '''\
class {cls_name}:
    vendor_slug = "{slug}"
    vendor_display_name = "{display}"
    vendor_logo_path = "logos/{slug}.svg"
    contract_version = "1.0"
    auth_model = "api_key"
    delivery_mode = "pull"
    availability = "ga"
    compliance_categories = []

    def credential_shape(self): return []
    def tenant_mapping_shape(self): return None
    def smoke_test(self, credentials): return None
    def start(self, instance_config): pass
    def stop(self): pass
    def health(self): return None
    def extract_event(self, raw_envelope): return None
    def route_to_tenant(self, raw_envelope): return None
    def severity_map(self, raw_envelope): return "info"
    def human_summary(self, event): return ""
    def rate_limit_hints(self): return None
    def widget_definition(self): return None
    def deep_link(self, event, link_type): return None
'''

# System widget module template.
_SYSTEM_WIDGET = '''\
from shared_widget_contract import WidgetDefinition

WIDGET = WidgetDefinition(
    widget_id="{widget_id}",
    title="{title}",
    description="system widget",
    default_size="small",
    default_position="top-right",
    data_query="{data_query}",
    render_component_ref="default-status-panel",
    categories=["system"],
    min_role="viewer",
    refresh_interval_sec=30,
)
'''


def _make_pkg(parent: Path, name: str) -> Path:
    pkg = parent / name
    pkg.mkdir(parents=True, exist_ok=False)
    (pkg / "__init__.py").write_text("")
    return pkg


def _make_adapter_pkg(
    root: Path,
    subpkg: str,
    *,
    cls_name: str,
    slug: str,
    with_widget: bool = True,
) -> str:
    pkg = root / subpkg
    pkg.mkdir(parents=True, exist_ok=False)
    template = _ADAPTER_WITH_WIDGET if with_widget else _ADAPTER_WITHOUT_WIDGET
    (pkg / "__init__.py").write_text(template.format(
        cls_name=cls_name,
        slug=slug,
        display=cls_name,
        widget_id=f"{slug}.alert-feed",
    ))
    return f"{slug}.alert-feed"


@pytest.fixture
def fixture_root(tmp_path: Path):
    """Set up a parent dir on sys.path with empty adapter + system-widget roots."""
    parent = tmp_path / "boot_fixtures"
    parent.mkdir()
    sys.path.insert(0, str(parent))

    adapters_pkg_name = "fake_boot_adapters"
    system_widgets_pkg_name = "fake_boot_system_widgets"

    adapters_root = _make_pkg(parent, adapters_pkg_name)
    system_widgets_root = _make_pkg(parent, system_widgets_pkg_name)

    yield {
        "adapters_root": adapters_root,
        "adapters_pkg": adapters_pkg_name,
        "system_widgets_root": system_widgets_root,
        "system_widgets_pkg": system_widgets_pkg_name,
    }

    if str(parent) in sys.path:
        sys.path.remove(str(parent))
    for key in list(sys.modules):
        if (
            key == adapters_pkg_name
            or key.startswith(adapters_pkg_name + ".")
            or key == system_widgets_pkg_name
            or key.startswith(system_widgets_pkg_name + ".")
        ):
            del sys.modules[key]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_boot_with_one_adapter_and_one_system_widget(fixture_root) -> None:
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    (fixture_root["system_widgets_root"] / "health.py").write_text(
        _SYSTEM_WIDGET.format(
            widget_id="system.health-summary",
            title="Health Summary",
            data_query="health_q",
        ),
    )

    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )

    # Adapter class registered
    assert booted.adapter_registry.get_adapter_class("datto-rmm") is not None
    # Adapter widget registered + scoped to vendor_slug
    assert booted.widget_registry.get("datto-rmm.alert-feed") is not None
    # System widget registered
    assert booted.widget_registry.get("system.health-summary") is not None
    # Report sums up
    assert booted.report.adapters.registered == ["datto-rmm"]
    assert booted.report.adapter_widgets.registered == ["datto-rmm.alert-feed"]
    assert booted.report.system_widgets.registered == ["system.health-summary"]
    assert not booted.report.has_failures()


def test_boot_with_multiple_adapters(fixture_root) -> None:
    for slug, cls in [
        ("datto-rmm", "DattoRMMAdapter"),
        ("unifi", "UniFiAdapter"),
        ("rc", "RCAdapter"),
    ]:
        _make_adapter_pkg(
            fixture_root["adapters_root"],
            slug.replace("-", "_"),
            cls_name=cls,
            slug=slug,
        )

    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )

    assert sorted(booted.report.adapters.registered) == ["datto-rmm", "rc", "unifi"]
    assert len(booted.report.adapter_widgets.registered) == 3
    assert sorted(booted.report.adapter_widgets.registered) == [
        "datto-rmm.alert-feed", "rc.alert-feed", "unifi.alert-feed",
    ]


# ---------------------------------------------------------------------------
# Adapter widget extraction edge cases
# ---------------------------------------------------------------------------

def test_adapter_without_widget_skipped_not_failed(fixture_root) -> None:
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "no_widget",
        cls_name="NoWidgetAdapter",
        slug="no-widget",
        with_widget=False,
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )
    assert "no-widget" in booted.report.adapters.registered
    assert "no-widget" in booted.report.adapter_widgets.skipped
    assert booted.report.adapter_widgets.failed == []


# ---------------------------------------------------------------------------
# Widget availability propagates from adapter activation
# ---------------------------------------------------------------------------

def test_adapter_widget_becomes_available_when_adapter_active(fixture_root) -> None:
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )

    # Before activation: widget exists in registry but no tenant has it active
    widget = booted.widget_registry.get("datto-rmm.alert-feed")
    assert widget is not None
    assert widget.available_for_tenants == []

    # Configure + activate for client_a
    booted.adapter_registry.configure_instance(
        vendor_slug="datto-rmm",
        tenant_slug="client_a",
        instance_id="i1",
        credentials_ref="vault:datto/i1",
    )
    booted.adapter_registry.transition(
        "datto-rmm:client_a:i1",
        to_state=AdapterLifecycleState.ACTIVE,
        reason="boot test",
    )

    # Widget now available for that tenant
    widget = booted.widget_registry.get("datto-rmm.alert-feed")
    assert widget is not None
    assert widget.available_for_tenants == ["client_a"]


# ---------------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------------

def test_broken_adapter_recorded_but_does_not_abort_boot(fixture_root) -> None:
    # Healthy adapter with widget
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "ok",
        cls_name="OKAdapter",
        slug="ok",
    )
    # Broken adapter package
    broken = fixture_root["adapters_root"] / "broken"
    broken.mkdir()
    (broken / "__init__.py").write_text("raise RuntimeError('boot boom')\n")

    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )

    assert "ok" in booted.report.adapters.registered
    assert "ok.alert-feed" in booted.report.adapter_widgets.registered
    assert any("broken" in name for name, _ in booted.report.adapters.failed)
    assert booted.report.has_failures() is True


def test_has_failures_false_on_clean_boot(fixture_root) -> None:
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )
    assert booted.report.has_failures() is False


# ---------------------------------------------------------------------------
# Summary + injection
# ---------------------------------------------------------------------------

def test_summary_lines_returns_three_lines(fixture_root) -> None:
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )
    lines = booted.report.summary_lines()
    assert len(lines) == 3
    assert any("adapters" in line for line in lines)
    assert any("adapter widgets" in line for line in lines)
    assert any("system widgets" in line for line in lines)


def test_boot_with_injected_registries(fixture_root) -> None:
    """Caller can pre-build registries (e.g., to use a non-default backend)
    and pass them in. Boot uses them rather than constructing fresh ones."""
    adapter_registry = AdapterRegistry()
    widget_registry = WidgetRegistryImpl(adapter_registry=adapter_registry)

    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
        adapter_registry=adapter_registry,
        widget_registry=widget_registry,
    )
    # Same instances returned
    assert booted.adapter_registry is adapter_registry
    assert booted.widget_registry is widget_registry


# ---------------------------------------------------------------------------
# BootReport / BootedFramework shape sanity
# ---------------------------------------------------------------------------

def test_booted_framework_widget_registry_subscribed_to_adapter_registry(fixture_root) -> None:
    """The default-constructed registries inside boot must be wired together
    so adapter state changes propagate to widget availability automatically."""
    _make_adapter_pkg(
        fixture_root["adapters_root"],
        "datto_rmm",
        cls_name="DattoRMMAdapter",
        slug="datto-rmm",
    )
    booted = boot_framework(
        adapters_package=fixture_root["adapters_pkg"],
        system_widgets_package=fixture_root["system_widgets_pkg"],
    )
    # End-to-end: configure + activate → widget becomes available
    booted.adapter_registry.configure_instance(
        vendor_slug="datto-rmm",
        tenant_slug="client_a",
        instance_id="i1",
        credentials_ref="vault:x",
    )
    booted.adapter_registry.activate("datto-rmm:client_a:i1", reason="test")

    widgets = booted.widget_registry.list(role="viewer", tenant_scope="client_a")
    widget_ids = [w.definition.widget_id for w in widgets]
    assert "datto-rmm.alert-feed" in widget_ids


def test_boot_report_exposes_three_phases() -> None:
    """A BootReport always has all three phase sub-reports — never None."""
    booted = boot_framework(
        adapters_package="apps.octo.adapters",  # real but empty
        system_widgets_package="apps.athena.widgets.system",  # real but empty
    )
    assert isinstance(booted.report, BootReport)
    assert booted.report.adapters is not None
    assert booted.report.system_widgets is not None
    assert booted.report.adapter_widgets is not None
