"""Widget registry types — the registry-side shapes consumed by the dashboard.

Per ADR-006 §`Widget Registry`. The registry is implemented in
`apps/athena/framework/widget_registry.py`; this module just defines the
Protocol + dataclasses that callers use to interact with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from shared_widget_contract.types import OperatorRole, WidgetDefinition

WidgetSourceKind = Literal["adapter", "system"]


@dataclass(frozen=True)
class WidgetSource:
    """Where a registered widget came from.

    For adapter widgets: kind='adapter', identifier=<vendor_slug>.
    For system widgets: kind='system', identifier=<system_module_name>.
    """

    kind: WidgetSourceKind
    identifier: str


@dataclass(frozen=True)
class RegisteredWidget:
    """A widget registered in the framework's widget registry.

    Adds runtime context (which tenants the widget is currently available for,
    which contract version the source declares) to the static WidgetDefinition.
    """

    definition: WidgetDefinition

    source: WidgetSource

    available_for_tenants: list[str]
    """Adapter widgets: tenants where the adapter is currently ACTIVE.
    System widgets: all tenants the operator has access to."""

    contract_version: str
    """ADR-005 contract version of the declaring adapter, or 'system-1.0'
    for system widgets. Used for migration/compatibility checks."""


class WidgetRegistry(Protocol):
    """Read interface for the widget registry.

    Implementations (in `apps/athena/framework/widget_registry.py`) are
    responsible for discovery, lifecycle plumbing, and pub/sub on adapter
    state changes. Callers consume the registry through this Protocol.
    """

    def list(
        self,
        *,
        role: OperatorRole,
        tenant_scope: str | None = None,
    ) -> list[RegisteredWidget]:
        """Widgets visible to this operator role, optionally filtered to one tenant.

        Filtering rules:
        - Widget's `min_role` is honored (super_admin sees all; viewer sees
          only widgets with min_role='viewer')
        - When tenant_scope is set, only widgets available for that tenant
          are returned
        - When tenant_scope is None, returns the union across all tenants the
          operator has access to (deduplicated)
        """
        ...

    def get(self, widget_id: str) -> RegisteredWidget | None:
        """Look up a single widget by ID. Returns None if unregistered or
        the operator doesn't have access via min_role."""
        ...

    def categories(self) -> list[str]:
        """Distinct categories across all registered widgets, for the
        available-widgets panel's filter UI."""
        ...
