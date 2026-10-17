"""Widget definition + supporting types for the widget framework.

Per ADR-006 §`The contract`. Mirror's the adapter contract's discipline:
frozen dataclasses for immutability + minimum-required-state declaration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Enum-likes
# ---------------------------------------------------------------------------

WidgetSize = Literal["small", "medium", "large"]
"""Discrete widget size classes. Layouts may also use grid units (int, int)."""

WidgetCategory = Literal[
    "source-adapter",   # adapter widgets (Datto-RMM, RC, UniFi, etc.)
    "system",           # ships with the framework (findings queue, threat intel, etc.)
    "rmm",              # vendor-category badges for filter UI
    "edr",
    "mdr",
    "network",
    "compliance",
    "fleet",
    "octopus",          # Octopus telemetry network widgets (when opt-in)
    "custom",
]
"""Categories used by the wizard / settings filter UI to group widgets."""

OperatorRole = Literal["super_admin", "admin", "analyst", "viewer"]
"""Per role taxonomy v2. Widgets declare min_role to control visibility."""


DefaultRenderComponent = Literal[
    "default-alert-feed",
    "default-counter-grid",
    "default-time-series",
    "default-list-with-actions",
    "default-status-panel",
]
"""The 5 canonical render components the framework ships per ADR-006 §5.

Custom components are declared by adapters when the defaults don't fit
(e.g., 'buoy.fleet-flowmap', 'unifi.network-topology'). Custom IDs follow
'<vendor_slug>.<component_name>' convention.
"""

DEFAULT_RENDER_COMPONENTS: frozenset[str] = frozenset({
    "default-alert-feed",
    "default-counter-grid",
    "default-time-series",
    "default-list-with-actions",
    "default-status-panel",
})


# ---------------------------------------------------------------------------
# Configurable parameter declaration
# ---------------------------------------------------------------------------

ParamKind = Literal["bool", "int", "string", "enum", "duration_sec", "severity_filter"]


@dataclass(frozen=True)
class ConfigurableParam:
    """An operator-tunable parameter for a widget instance.

    Operators see these in the widget's edit-mode panel; per-operator value
    persists in `LayoutItem.operator_config`.
    """

    name: str
    """Param key (e.g., 'severity_filter', 'refresh_interval_sec', 'show_resolved')."""

    label: str
    """Operator-facing label."""

    kind: ParamKind

    description: str

    default_value: Any
    """Default applied when operator hasn't customized."""

    enum_choices: list[str] | None = None
    """Required when kind=='enum'. Ignored otherwise."""

    min_value: float | None = None
    """For numeric kinds — operator's UI clamps below this."""

    max_value: float | None = None
    """For numeric kinds — operator's UI clamps above this."""


# ---------------------------------------------------------------------------
# Widget definition (the full contract; referenced by adapters via
# WidgetDefinitionRef in shared_adapter_contract)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WidgetDefinition:
    """Declarative shape for a widget the framework hosts.

    Adapters declare these alongside their backend code; the framework
    discovers them at startup and registers them. System widgets follow the
    same shape but ship with the framework rather than with an adapter.
    """

    widget_id: str
    """Globally unique. Convention: '<vendor_slug>.<purpose>' for adapter
    widgets (e.g., 'datto-rmm.alert-feed'); 'system.<purpose>' for system
    widgets (e.g., 'system.findings-queue')."""

    title: str
    """Display title shown in the widget header."""

    description: str
    """Operator-facing description shown in the available-widgets panel."""

    default_size: WidgetSize | tuple[int, int]
    """Either a discrete size class or grid-unit (width, height)."""

    default_position: Literal["top-left", "top-right", "auto"]
    """Where the widget lands by default. 'auto' = framework picks based on
    available layout space."""

    data_query: str
    """ID of the bridge query template that feeds this widget's data
    (e.g., 'recent_findings', 'datto_rmm.recent_alerts'). Templates live in
    shared_bridge.templates."""

    render_component_ref: str
    """Either one of DEFAULT_RENDER_COMPONENTS or a custom component ID
    (convention: '<vendor_slug>.<component_id>' or 'system.<component_id>')."""

    categories: list[WidgetCategory]
    """For grouping in the available-widgets panel."""

    min_role: OperatorRole
    """Minimum role required to see this widget. Roles ladder:
    super_admin > admin > analyst > viewer."""

    refresh_interval_sec: int
    """How often the widget polls for fresh data via the bridge. Framework
    enforces a 5-second minimum (configurable per-deployment) per ADR-006 Q1."""

    configurable_params: list[ConfigurableParam] = field(default_factory=list)
    """Operator-tunable params for this widget instance."""

    framework_version_min: str = "1.0"
    """Minimum widget-framework version required. Framework rejects widgets
    requiring versions newer than the running framework."""

    contract_version: str = "1.0"
    """Widget contract version this declaration follows."""

    def __post_init__(self) -> None:
        if self.refresh_interval_sec < 5:
            msg = (
                f"refresh_interval_sec={self.refresh_interval_sec} < 5 "
                f"(framework floor per ADR-006 Q1). Use 5 or higher."
            )
            raise ValueError(msg)
