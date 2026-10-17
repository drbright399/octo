"""Integration test: Datto adapter auto-discovered by the framework.

Same canary as for Wazuh — if someone moves the adapter class out of
where discovery can find it (subpackage __init__ re-export with
__module__ rewrite), this test fails loudly.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from apps.octo.framework.discovery import discover_adapters
from apps.octo.framework.registry import AdapterRegistry
from apps.octo.framework.sqlite_registry import SqliteRegistryBackend


def test_datto_auto_discovered():
    with tempfile.TemporaryDirectory() as tmp:
        backend = SqliteRegistryBackend(str(Path(tmp) / "registry.db"))
        registry = AdapterRegistry(backend=backend)
        report = discover_adapters("apps.octo.adapters", registry)
        assert "datto" in report.registered
        assert report.failed == []


def test_both_adapters_discovered_in_same_pass():
    """Same discovery call returns both Wazuh + Datto. Confirms the
    framework can hold multiple adapters in one MSP bundle (which is
    the entire point of the adapter framework)."""
    with tempfile.TemporaryDirectory() as tmp:
        backend = SqliteRegistryBackend(str(Path(tmp) / "registry.db"))
        registry = AdapterRegistry(backend=backend)
        report = discover_adapters("apps.octo.adapters", registry)
        assert "wazuh" in report.registered
        assert "datto" in report.registered


def test_datto_class_module_is_package_path():
    from apps.octo.adapters.datto import DattoSourceAdapter
    assert DattoSourceAdapter.__module__ == "apps.octo.adapters.datto"
