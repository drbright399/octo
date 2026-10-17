"""Integration test: Wazuh adapter is auto-discovered by the framework.

This is the canary that fails loudly if someone accidentally moves the
adapter class out of where discovery can find it (subpackage __init__
re-export with __module__ rewrite). Without this, the wire-up could
silently regress and the framework would just skip Wazuh — no error,
no events, no obvious reason.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from apps.octo.framework.discovery import discover_adapters
from apps.octo.framework.registry import AdapterRegistry
from apps.octo.framework.sqlite_registry import SqliteRegistryBackend


def test_wazuh_auto_discovered_from_apps_octo_adapters():
    """Calling discovery with the production package path picks up Wazuh."""
    with tempfile.TemporaryDirectory() as tmp:
        backend = SqliteRegistryBackend(str(Path(tmp) / "registry.db"))
        registry = AdapterRegistry(backend=backend)

        report = discover_adapters("apps.octo.adapters", registry)

        assert "wazuh" in report.registered
        assert report.failed == []


def test_wazuh_class_module_is_package_path():
    """The __module__ rewrite is the load-bearing trick that makes
    discovery find this class. Confirm it's still in effect."""
    from apps.octo.adapters.wazuh import WazuhSourceAdapter

    assert WazuhSourceAdapter.__module__ == "apps.octo.adapters.wazuh"
