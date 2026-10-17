"""Layout persistence shapes for per-operator dashboard layouts.

Per ADR-006 §`Layout persistence`. Layouts are per-operator AND per-tenant —
an MSP analyst working across many tenants can have different widget
arrangements per tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LayoutPosition:
    """Grid coordinates of a widget within the dashboard."""

    x: int
    """Column offset (grid units from left)."""

    y: int
    """Row offset (grid units from top)."""


@dataclass(frozen=True)
class LayoutSize:
    """Grid dimensions of a widget."""

    w: int
    """Width in grid units."""

    h: int
    """Height in grid units."""


@dataclass(frozen=True)
class LayoutItem:
    """One widget's placement + per-instance configuration in an operator's layout."""

    widget_id: str
    """Must match a `WidgetDefinition.widget_id` registered in the framework."""

    position: LayoutPosition

    size: LayoutSize

    hidden: bool = False
    """Operator can hide a widget (per-operator preference) without disabling
    the underlying adapter. Adapter keeps ingesting; widget just doesn't render."""

    operator_config: dict[str, Any] = field(default_factory=dict)
    """Per-operator-tunable params (per `ConfigurableParam` declarations on
    the widget definition). Keys must match `ConfigurableParam.name` values."""


@dataclass(frozen=True)
class LayoutGrid:
    """An operator's full dashboard layout for one tenant."""

    version: int
    """Layout schema version. Bumped when migration runs (e.g., when an
    adapter widget's ID changes between framework versions)."""

    grid: list[LayoutItem]
    """Widgets placed on the operator's dashboard for this tenant. Order
    is informative but the (position, size) on each item is authoritative."""

    def widget_ids(self) -> list[str]:
        """Convenience: list of widget IDs currently on this operator's layout."""
        return [item.widget_id for item in self.grid]

    def visible_items(self) -> list[LayoutItem]:
        """Convenience: only items not hidden by the operator."""
        return [item for item in self.grid if not item.hidden]
