"""Widget framework contract for Athena Console.

Per design note ADR-006 (kept outside this repository; index:
`docs/adrs/README.md`), this package defines:
- The full `WidgetDefinition` (referenced by adapters via WidgetDefinitionRef)
- The `RegisteredWidget` shape returned by the registry
- The `WidgetRegistry` Protocol for registry implementations
- Layout persistence shapes (`LayoutItem`, `LayoutGrid`)
- Default render component IDs (the 5 canonical components)

Stable contract version: 1.0
"""

from shared_widget_contract.layout import LayoutGrid, LayoutItem, LayoutPosition, LayoutSize
from shared_widget_contract.registry import RegisteredWidget, WidgetRegistry, WidgetSource
from shared_widget_contract.types import (
    DEFAULT_RENDER_COMPONENTS,
    ConfigurableParam,
    DefaultRenderComponent,
    WidgetCategory,
    WidgetDefinition,
    WidgetSize,
)

WIDGET_CONTRACT_VERSION = "1.0"

__all__ = [
    "DEFAULT_RENDER_COMPONENTS",
    "WIDGET_CONTRACT_VERSION",
    "ConfigurableParam",
    "DefaultRenderComponent",
    "LayoutGrid",
    "LayoutItem",
    "LayoutPosition",
    "LayoutSize",
    "RegisteredWidget",
    "WidgetCategory",
    "WidgetDefinition",
    "WidgetRegistry",
    "WidgetSize",
    "WidgetSource",
]
