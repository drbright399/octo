"""Widget registry runtime — implements the WidgetRegistry Protocol.

Per ADR-006 §`Widget Registry` + §`Lifecycle plumbing`. The registry:

1. Hosts adapter widgets — discovered from each adapter dir's widget.py
   module (per ADR-005 directory layout). Each widget is associated with
   its declaring adapter via a stable widget_id.

2. Hosts system widgets — declared in `apps/athena/widgets/system/` and
   registered directly without an adapter. Always available; not subject
   to adapter lifecycle.

3. Subscribes to adapter registry state-change events. When an adapter
   transitions to ACTIVE for a tenant, its widgets become "available for
   that tenant". When it leaves ACTIVE, its widgets are removed from the
   tenant's availability. System widgets are unaffected.

4. Implements the WidgetRegistry Protocol from shared_widget_contract:
   list / get / categories. Filters by min_role + tenant_scope per the
   contract's documented semantics.

The framework's dashboard renderer reads from this registry; layout
persistence sits on top of it.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Literal

from shared_widget_contract import (
    RegisteredWidget,
    WidgetDefinition,
    WidgetRegistry,
    WidgetSource,
)
from shared_widget_contract.types import OperatorRole

from apps.octo.framework.lifecycle import AdapterLifecycleState
from apps.octo.framework.registry import (
    AdapterRegistry,
    StateChangeEvent,
)


# Role hierarchy (super_admin > admin > analyst > viewer).
# Role-rank: higher number = more privileged. A widget's min_role is the
# floor; operators with rank >= min_role's rank can see the widget.
_ROLE_RANK: dict[OperatorRole, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "super_admin": 4,
}


def _role_meets_minimum(operator_role: OperatorRole, min_role: OperatorRole) -> bool:
    """Per ADR-006: widget visible iff operator's role rank >= widget's min_role rank."""
    return _ROLE_RANK[operator_role] >= _ROLE_RANK[min_role]


class WidgetRegistryImpl:
    """Concrete WidgetRegistry implementation.

    Constructed with optional reference to an AdapterRegistry — when provided,
    automatically subscribes to state-change events to maintain per-tenant
    availability for adapter widgets. Tests can omit the AdapterRegistry and
    drive availability manually via _set_adapter_active() helpers.
    """

    def __init__(self, adapter_registry: AdapterRegistry | None = None) -> None:
        # Adapter widgets: keyed by widget_id, with their owning adapter slug.
        self._adapter_widgets: dict[str, WidgetDefinition] = {}
        # vendor_slug -> set of widget_ids declared by that adapter
        self._widgets_by_adapter: dict[str, set[str]] = defaultdict(set)

        # System widgets: keyed by widget_id, with their declaring module name.
        self._system_widgets: dict[str, WidgetDefinition] = {}
        # widget_id -> system module name
        self._system_widget_modules: dict[str, str] = {}

        # Per-tenant availability for adapter widgets:
        # tenant_slug -> set of vendor_slugs currently ACTIVE for that tenant
        self._active_adapters_per_tenant: dict[str, set[str]] = defaultdict(set)

        if adapter_registry is not None:
            adapter_registry.subscribe(self._on_adapter_state_change)

    # ------------------------------------------------------------------
    # Registration — typically called by the discovery mechanism
    # ------------------------------------------------------------------

    def register_adapter_widget(
        self,
        widget: WidgetDefinition,
        *,
        vendor_slug: str,
    ) -> None:
        """Register a widget declared by an adapter.

        Idempotent: re-registering the same widget definition with the same
        vendor_slug is a no-op. A different definition or vendor_slug for an
        already-registered widget_id raises ValueError.
        """
        existing = self._adapter_widgets.get(widget.widget_id)
        if existing is not None:
            if existing != widget:
                msg = (
                    f"Widget '{widget.widget_id}' already registered with a "
                    f"different definition; cannot replace"
                )
                raise ValueError(msg)
            # Same widget already registered — also confirm vendor_slug matches
            existing_slugs = [
                s for s, ids in self._widgets_by_adapter.items()
                if widget.widget_id in ids
            ]
            if existing_slugs and existing_slugs[0] != vendor_slug:
                msg = (
                    f"Widget '{widget.widget_id}' already registered to "
                    f"vendor '{existing_slugs[0]}'; cannot re-register to '{vendor_slug}'"
                )
                raise ValueError(msg)
            return

        self._adapter_widgets[widget.widget_id] = widget
        self._widgets_by_adapter[vendor_slug].add(widget.widget_id)

    def register_system_widget(
        self,
        widget: WidgetDefinition,
        *,
        module_name: str,
    ) -> None:
        """Register a system widget (always-available; no adapter lifecycle)."""
        existing = self._system_widgets.get(widget.widget_id)
        if existing is not None and existing != widget:
            msg = (
                f"System widget '{widget.widget_id}' already registered with a "
                f"different definition; cannot replace"
            )
            raise ValueError(msg)
        self._system_widgets[widget.widget_id] = widget
        self._system_widget_modules[widget.widget_id] = module_name

    # ------------------------------------------------------------------
    # WidgetRegistry Protocol surface
    # ------------------------------------------------------------------

    def list(
        self,
        *,
        role: OperatorRole,
        tenant_scope: str | None = None,
    ) -> list[RegisteredWidget]:
        """Widgets visible to the given role, optionally filtered to one tenant.

        Filtering rules per ADR-006 / WidgetRegistry Protocol:
        - widget.min_role honored — only widgets where operator's role rank
          meets or exceeds min_role's rank are returned
        - When tenant_scope is set, adapter widgets only included if the
          adapter is ACTIVE for that tenant. System widgets always included.
        - When tenant_scope is None, returns the union (deduplicated) of all
          widgets the operator could possibly see across any tenant.
        """
        results: list[RegisteredWidget] = []

        # System widgets first — always available
        for widget_id, widget in self._system_widgets.items():
            if not _role_meets_minimum(role, widget.min_role):
                continue
            module = self._system_widget_modules[widget_id]
            results.append(RegisteredWidget(
                definition=widget,
                source=WidgetSource(kind="system", identifier=module),
                # System widgets are tenant-agnostic. When tenant_scope is set,
                # we still surface them (operator sees them regardless).
                # When tenant_scope is None, all-tenants membership is implicit.
                available_for_tenants=[],  # empty = "all tenants"
                contract_version="system-1.0",
            ))

        # Adapter widgets
        for widget_id, widget in self._adapter_widgets.items():
            if not _role_meets_minimum(role, widget.min_role):
                continue

            # Find the owning adapter
            owning_slug: str | None = None
            for vendor_slug, widget_ids in self._widgets_by_adapter.items():
                if widget_id in widget_ids:
                    owning_slug = vendor_slug
                    break
            if owning_slug is None:
                continue  # Defensive — shouldn't happen if registration is consistent

            # Determine which tenants currently have this adapter ACTIVE
            active_tenants: list[str] = []
            for tenant, active_slugs in self._active_adapters_per_tenant.items():
                if owning_slug in active_slugs:
                    active_tenants.append(tenant)

            # Apply tenant_scope filter
            if tenant_scope is not None and tenant_scope not in active_tenants:
                continue  # Adapter not ACTIVE for this tenant

            results.append(RegisteredWidget(
                definition=widget,
                source=WidgetSource(kind="adapter", identifier=owning_slug),
                available_for_tenants=sorted(active_tenants),
                contract_version="1.0",
            ))

        return results

    def get(self, widget_id: str) -> RegisteredWidget | None:
        """Look up a single widget by ID. Returns the widget regardless of
        role (callers filter by role separately if needed). Returns None if
        unregistered.
        """
        # System widget?
        if widget_id in self._system_widgets:
            widget = self._system_widgets[widget_id]
            module = self._system_widget_modules[widget_id]
            return RegisteredWidget(
                definition=widget,
                source=WidgetSource(kind="system", identifier=module),
                available_for_tenants=[],
                contract_version="system-1.0",
            )

        # Adapter widget?
        if widget_id in self._adapter_widgets:
            widget = self._adapter_widgets[widget_id]
            owning_slug: str | None = None
            for vendor_slug, widget_ids in self._widgets_by_adapter.items():
                if widget_id in widget_ids:
                    owning_slug = vendor_slug
                    break
            if owning_slug is None:
                return None

            active_tenants = sorted([
                t for t, slugs in self._active_adapters_per_tenant.items()
                if owning_slug in slugs
            ])
            return RegisteredWidget(
                definition=widget,
                source=WidgetSource(kind="adapter", identifier=owning_slug),
                available_for_tenants=active_tenants,
                contract_version="1.0",
            )

        return None

    def categories(self) -> list[str]:
        """Distinct categories across all registered widgets, for the
        available-widgets panel's filter UI. Sorted alphabetically."""
        seen: set[str] = set()
        for widget in self._adapter_widgets.values():
            seen.update(widget.categories)
        for widget in self._system_widgets.values():
            seen.update(widget.categories)
        return sorted(seen)

    # ------------------------------------------------------------------
    # Adapter registry event hookup
    # ------------------------------------------------------------------

    def _on_adapter_state_change(self, event: StateChangeEvent) -> None:
        """Subscribed to AdapterRegistry. Updates per-tenant availability when
        adapters move into / out of ACTIVE.
        """
        vendor_slug = event.instance.vendor_slug
        tenant_slug = event.instance.tenant_slug

        if event.to_state == AdapterLifecycleState.ACTIVE:
            self._active_adapters_per_tenant[tenant_slug].add(vendor_slug)
        elif event.from_state == AdapterLifecycleState.ACTIVE:
            # Leaving ACTIVE — drop visibility for this tenant
            self._active_adapters_per_tenant[tenant_slug].discard(vendor_slug)

    # ------------------------------------------------------------------
    # Test/development helpers — production code should drive availability
    # via subscribed AdapterRegistry events
    # ------------------------------------------------------------------

    def _set_adapter_active_for_tenant(
        self,
        *,
        vendor_slug: str,
        tenant_slug: str,
        active: bool,
    ) -> None:
        """Test helper: directly toggle adapter-active state for a tenant
        without going through an AdapterRegistry. Production callers should
        use subscribe() instead."""
        if active:
            self._active_adapters_per_tenant[tenant_slug].add(vendor_slug)
        else:
            self._active_adapters_per_tenant[tenant_slug].discard(vendor_slug)


# Sanity check: WidgetRegistryImpl satisfies the WidgetRegistry Protocol.
# This is a static assertion enforced by mypy --strict; the line is a no-op
# at runtime but ensures the Protocol surface stays implemented.
_: type[WidgetRegistry] = WidgetRegistryImpl  # type: ignore[type-abstract,misc]
