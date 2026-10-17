"""Tests for adapter discovery — hermetic via tmp_path fixture packages.

Each test builds a tiny fake `<root>/<vendor>/__init__.py` package tree
in tmp_path, inserts the parent on sys.path, and runs discover_adapters().
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from apps.octo.framework.discovery import (
    DiscoveryReport,
    discover_adapters,
)
from apps.octo.framework.registry import AdapterRegistry


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

# Boilerplate for a fake adapter class that satisfies the discovery filter
# (has a class-level vendor_slug). Full Protocol conformance isn't needed
# to be discovered — the registry's register_adapter_class() does the
# Protocol-implicit check at registration time, but for these tests we only
# need the discovery walker to find the class.
_ADAPTER_TEMPLATE = '''\
from typing import Any


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


def _make_pkg(parent: Path, name: str) -> Path:
    """Create an empty __init__.py-only package directory."""
    pkg_dir = parent / name
    pkg_dir.mkdir(parents=True, exist_ok=False)
    (pkg_dir / "__init__.py").write_text("")
    return pkg_dir


def _make_adapter_pkg(
    root: Path,
    subpkg_name: str,
    *,
    cls_name: str,
    slug: str,
) -> None:
    pkg = root / subpkg_name
    pkg.mkdir(parents=True, exist_ok=False)
    (pkg / "__init__.py").write_text(
        _ADAPTER_TEMPLATE.format(cls_name=cls_name, slug=slug, display=cls_name),
    )


@pytest.fixture
def fixture_root(tmp_path: Path):
    """Set up a fresh adapters root + cleanup sys.path / modules after."""
    # Unique parent so different tests can coexist on sys.path
    parent = tmp_path / "discovery_fixtures"
    parent.mkdir()
    sys.path.insert(0, str(parent))

    root_pkg_name = "fake_adapters_root"
    root = _make_pkg(parent, root_pkg_name)

    yield root, root_pkg_name

    # Clean up sys.path
    if str(parent) in sys.path:
        sys.path.remove(str(parent))
    # Purge imported modules so the next test gets a fresh import
    for key in list(sys.modules):
        if key == root_pkg_name or key.startswith(root_pkg_name + "."):
            del sys.modules[key]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_discovers_single_adapter(fixture_root) -> None:
    root, root_name = fixture_root
    _make_adapter_pkg(root, "datto_rmm", cls_name="DattoRMMAdapter", slug="datto-rmm")
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    assert "datto-rmm" in report.registered
    assert report.skipped == []
    assert report.failed == []
    assert registry.get_adapter_class("datto-rmm") is not None


def test_discovers_multiple_adapters(fixture_root) -> None:
    root, root_name = fixture_root
    _make_adapter_pkg(root, "datto_rmm", cls_name="DattoRMMAdapter", slug="datto-rmm")
    _make_adapter_pkg(root, "unifi", cls_name="UniFiAdapter", slug="unifi")
    _make_adapter_pkg(root, "rc", cls_name="RCAdapter", slug="rc")
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    assert sorted(report.registered) == ["datto-rmm", "rc", "unifi"]
    assert len(registry.list_adapter_classes()) == 3


# ---------------------------------------------------------------------------
# Skip paths — module imports cleanly but yields no adapter
# ---------------------------------------------------------------------------

def test_skips_subpackage_with_no_adapter_class(fixture_root) -> None:
    root, root_name = fixture_root
    # A subpackage with no SourceAdapter-shaped class
    pkg = root / "empty_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("# nothing here\n")
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    assert report.registered == []
    assert any("empty_pkg" in s for s in report.skipped)


def test_class_without_vendor_slug_is_skipped(fixture_root) -> None:
    root, root_name = fixture_root
    pkg = root / "noslug_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        "class NotAnAdapter:\n    pass\n",
    )
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    assert report.registered == []
    assert any("noslug_pkg" in s for s in report.skipped)


def test_imported_class_from_other_module_is_not_re_registered(fixture_root) -> None:
    """Re-exporting an adapter from another module must not double-register it."""
    root, root_name = fixture_root
    _make_adapter_pkg(root, "primary", cls_name="PrimaryAdapter", slug="primary")
    # Second package re-exports the first's class
    pkg = root / "reexport"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        f"from {root_name}.primary import PrimaryAdapter  # noqa: F401\n",
    )
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    # Only registered once — the re-export package contributes nothing
    assert report.registered == ["primary"]
    assert any("reexport" in s for s in report.skipped)


# ---------------------------------------------------------------------------
# Fault tolerance
# ---------------------------------------------------------------------------

def test_broken_subpackage_recorded_as_failed(fixture_root) -> None:
    root, root_name = fixture_root
    # Adapter package that raises on import
    pkg = root / "broken_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("raise RuntimeError('boom on import')\n")
    # Healthy adapter alongside it
    _make_adapter_pkg(root, "ok_pkg", cls_name="OKAdapter", slug="ok")

    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    # Healthy one still registered
    assert "ok" in report.registered
    # Broken one captured (full dotted name)
    assert any("broken_pkg" in name and "boom" in err for name, err in report.failed)


def test_missing_root_package_recorded_as_failed() -> None:
    registry = AdapterRegistry()
    report = discover_adapters("definitely.not.a.real.package", registry)
    assert report.registered == []
    assert any("definitely.not" in name for name, _ in report.failed)


# ---------------------------------------------------------------------------
# Idempotency + collisions
# ---------------------------------------------------------------------------

def test_running_discovery_twice_is_idempotent(fixture_root) -> None:
    root, root_name = fixture_root
    _make_adapter_pkg(root, "datto_rmm", cls_name="DattoRMMAdapter", slug="datto-rmm")
    registry = AdapterRegistry()
    discover_adapters(root_name, registry)
    # Second pass — same class registered again is a no-op at the registry
    second = discover_adapters(root_name, registry)
    assert second.registered == ["datto-rmm"]
    assert second.failed == []
    assert len(registry.list_adapter_classes()) == 1


def test_collision_two_classes_same_slug_recorded_as_failed(fixture_root) -> None:
    root, root_name = fixture_root
    _make_adapter_pkg(root, "first", cls_name="FirstAdapter", slug="duplicate-slug")
    _make_adapter_pkg(root, "second", cls_name="SecondAdapter", slug="duplicate-slug")
    registry = AdapterRegistry()
    report = discover_adapters(root_name, registry)
    # First one wins; second collides at the registry level
    assert report.registered.count("duplicate-slug") == 1
    assert any("duplicate-slug" in err or "second" in name for name, err in report.failed)


# ---------------------------------------------------------------------------
# DiscoveryReport shape
# ---------------------------------------------------------------------------

def test_discovery_report_default_shape() -> None:
    """A fresh DiscoveryReport has empty lists in every field."""
    report = DiscoveryReport()
    assert report.registered == []
    assert report.skipped == []
    assert report.failed == []
