"""Athena framework runtime — widget registry, layout management, render-side
bridge client.

Per ADR-006 (the widget-framework design note), this package
implements the runtime that hosts the widget framework inside the
`athena` Docker container.

Modules:
- `widget_registry` — derives widget visibility from adapter registry state +
  hosts system widgets; implements the WidgetRegistry Protocol
- `layouts` — per-operator dashboard layout persistence + WidgetRegistry-aware
  validation. Layouts are UI state and live in Athena (ADR-004 boundary).
"""

from apps.athena.framework.boot import (
    AdapterWidgetReport,
    BootReport,
    BootedFramework,
    boot_framework,
)
from apps.athena.framework.bridge_client import (
    BridgeClientError,
    HttpBridgeClient,
)
from apps.athena.framework.layouts import (
    CURRENT_LAYOUT_VERSION,
    InMemoryLayoutRepository,
    LayoutRepository,
    LayoutService,
    LayoutValidationError,
    with_added_item,
    with_removed_widget,
    with_replaced_item,
)
from apps.athena.framework.sqlite_layouts import (
    SCHEMA_VERSION as LAYOUTS_SCHEMA_VERSION,
    SqliteLayoutRepository,
)
from apps.athena.framework.widget_discovery import (
    WidgetDiscoveryReport,
    discover_system_widgets,
    extract_widgets_from_module,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl

__all__ = [
    "AdapterWidgetReport",
    "BootReport",
    "BootedFramework",
    "BridgeClientError",
    "CURRENT_LAYOUT_VERSION",
    "HttpBridgeClient",
    "InMemoryLayoutRepository",
    "LAYOUTS_SCHEMA_VERSION",
    "LayoutRepository",
    "LayoutService",
    "LayoutValidationError",
    "SqliteLayoutRepository",
    "WidgetDiscoveryReport",
    "WidgetRegistryImpl",
    "boot_framework",
    "discover_system_widgets",
    "extract_widgets_from_module",
    "with_added_item",
    "with_removed_widget",
    "with_replaced_item",
]
