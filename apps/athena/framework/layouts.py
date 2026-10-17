"""Per-operator dashboard layout persistence.

Per ADR-006 §`Layout persistence` + ADR-004 (`no UI knowledge in OCTO`).
Layouts are operator preferences — pure UI state — so they live in Athena,
not OCTO. They do not cross the bridge contract.

Layouts are keyed by (operator_id, tenant_slug). An MSP operator who
works across multiple tenants can have a distinct widget arrangement
per tenant.

Pluggable backend via the `LayoutRepository` Protocol. In-memory
implementation ships now for tests; the SQLite-backed implementation
arrives when athena_state.db lands.

The `LayoutService` wraps the repository with validation against the
`WidgetRegistry`: layouts that reference unregistered widgets, widgets
the operator's role can't see, or adapter widgets whose adapter isn't
ACTIVE for the tenant are rejected at save time.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from shared_widget_contract import (
    LayoutGrid,
    LayoutItem,
    WidgetRegistry,
)
from shared_widget_contract.types import OperatorRole


# ---------------------------------------------------------------------------
# Repository Protocol + in-memory backend
# ---------------------------------------------------------------------------

class LayoutRepository(Protocol):
    """Persistence target for per-operator dashboard layouts."""

    def get(self, *, operator_id: int, tenant_slug: str) -> LayoutGrid | None:
        """Return the operator's layout for the given tenant, or None."""
        ...

    def put(
        self,
        *,
        operator_id: int,
        tenant_slug: str,
        layout: LayoutGrid,
    ) -> None:
        """Insert or replace the operator's layout for the given tenant."""
        ...

    def delete(self, *, operator_id: int, tenant_slug: str) -> None:
        """Remove the operator's layout for the given tenant. No-op if absent."""
        ...

    def list_for_operator(self, *, operator_id: int) -> dict[str, LayoutGrid]:
        """All layouts for an operator, keyed by tenant_slug. Empty dict if none."""
        ...


class InMemoryLayoutRepository:
    """In-memory layout repository. Suitable for tests + ephemeral dev runs.

    Production deployment will use a SQLite-backed implementation against
    athena_state.db (separate from OCTO databases per ADR-004 boundary).
    """

    def __init__(self) -> None:
        # (operator_id, tenant_slug) -> LayoutGrid
        self._layouts: dict[tuple[int, str], LayoutGrid] = {}
        # (operator_id, tenant_slug) -> ISO8601 last-updated timestamp
        self._updated_at: dict[tuple[int, str], str] = {}

    def get(self, *, operator_id: int, tenant_slug: str) -> LayoutGrid | None:
        return self._layouts.get((operator_id, tenant_slug))

    def put(
        self,
        *,
        operator_id: int,
        tenant_slug: str,
        layout: LayoutGrid,
    ) -> None:
        key = (operator_id, tenant_slug)
        self._layouts[key] = layout
        self._updated_at[key] = _utc_iso_now()

    def delete(self, *, operator_id: int, tenant_slug: str) -> None:
        key = (operator_id, tenant_slug)
        self._layouts.pop(key, None)
        self._updated_at.pop(key, None)

    def list_for_operator(self, *, operator_id: int) -> dict[str, LayoutGrid]:
        return {
            tenant: layout
            for (op, tenant), layout in self._layouts.items()
            if op == operator_id
        }

    def updated_at(self, *, operator_id: int, tenant_slug: str) -> str | None:
        """Diagnostic helper — when was this layout last persisted."""
        return self._updated_at.get((operator_id, tenant_slug))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class LayoutValidationError(Exception):
    """Raised when a layout fails validation against the WidgetRegistry.

    Carries a `reasons` list with one human-readable string per offending
    item so the UI can surface field-level errors.
    """

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

CURRENT_LAYOUT_VERSION = 1
"""Layout schema version emitted by save_layout when callers don't supply one.

Bumped only when a backward-incompatible migration is required."""


class LayoutService:
    """Validates + persists per-operator dashboard layouts.

    Wraps a LayoutRepository with WidgetRegistry-driven validation:
    - widget_ids in the layout must be registered
    - the operator's role must satisfy each widget's min_role
    - adapter widgets must have their adapter ACTIVE for the target tenant
      (system widgets are always permissible)
    """

    def __init__(
        self,
        *,
        registry: WidgetRegistry,
        repository: LayoutRepository | None = None,
    ) -> None:
        self._registry = registry
        self._repository: LayoutRepository = repository or InMemoryLayoutRepository()

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_layout(
        self,
        *,
        operator_id: int,
        tenant_slug: str,
    ) -> LayoutGrid | None:
        """Return the operator's layout for the given tenant, or None."""
        return self._repository.get(operator_id=operator_id, tenant_slug=tenant_slug)

    def get_or_default(
        self,
        *,
        operator_id: int,
        tenant_slug: str,
    ) -> LayoutGrid:
        """Return the saved layout, or an empty default."""
        existing = self.get_layout(operator_id=operator_id, tenant_slug=tenant_slug)
        if existing is not None:
            return existing
        return LayoutGrid(version=CURRENT_LAYOUT_VERSION, grid=[])

    def list_layouts(self, *, operator_id: int) -> dict[str, LayoutGrid]:
        """All layouts for an operator, keyed by tenant_slug."""
        return self._repository.list_for_operator(operator_id=operator_id)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------

    def save_layout(
        self,
        *,
        operator_id: int,
        operator_role: OperatorRole,
        tenant_slug: str,
        layout: LayoutGrid,
    ) -> LayoutGrid:
        """Validate + persist a layout for the (operator, tenant) pair.

        Raises LayoutValidationError on any of:
        - widget_id not registered
        - operator's role below the widget's min_role
        - adapter widget whose adapter is not ACTIVE for tenant_slug
        - duplicate widget_id within the same layout

        Returns the persisted layout (which may have its version coerced
        to CURRENT_LAYOUT_VERSION).
        """
        self._validate(
            layout=layout,
            operator_role=operator_role,
            tenant_slug=tenant_slug,
        )
        # Coerce the layout's version field to current. Future migrations
        # will read the original version field before this normalization.
        normalized = LayoutGrid(version=CURRENT_LAYOUT_VERSION, grid=list(layout.grid))
        self._repository.put(
            operator_id=operator_id,
            tenant_slug=tenant_slug,
            layout=normalized,
        )
        return normalized

    def delete_layout(self, *, operator_id: int, tenant_slug: str) -> None:
        """Remove a layout (operator reset)."""
        self._repository.delete(operator_id=operator_id, tenant_slug=tenant_slug)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(
        self,
        *,
        layout: LayoutGrid,
        operator_role: OperatorRole,
        tenant_slug: str,
    ) -> None:
        reasons: list[str] = []

        seen_ids: set[str] = set()
        for item in layout.grid:
            if item.widget_id in seen_ids:
                reasons.append(
                    f"duplicate widget_id '{item.widget_id}' in layout"
                )
                continue
            seen_ids.add(item.widget_id)

            registered = self._registry.get(item.widget_id)
            if registered is None:
                reasons.append(
                    f"widget '{item.widget_id}' is not registered"
                )
                continue

            # Role check
            if not _role_meets_minimum(
                operator_role, registered.definition.min_role,
            ):
                reasons.append(
                    f"widget '{item.widget_id}' requires role "
                    f"'{registered.definition.min_role}'; operator role "
                    f"'{operator_role}' insufficient"
                )
                continue

            # Adapter widgets must be active for this tenant.
            # System widgets (kind='system') are always permissible.
            if registered.source.kind == "adapter":
                if tenant_slug not in registered.available_for_tenants:
                    reasons.append(
                        f"widget '{item.widget_id}' belongs to adapter "
                        f"'{registered.source.identifier}' which is not "
                        f"ACTIVE for tenant '{tenant_slug}'"
                    )

        # Position sanity — non-negative coords + non-zero size
        for item in layout.grid:
            if item.position.x < 0 or item.position.y < 0:
                reasons.append(
                    f"widget '{item.widget_id}' has negative position "
                    f"({item.position.x},{item.position.y})"
                )
            if item.size.w <= 0 or item.size.h <= 0:
                reasons.append(
                    f"widget '{item.widget_id}' has non-positive size "
                    f"({item.size.w}x{item.size.h})"
                )

        if reasons:
            raise LayoutValidationError(reasons)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROLE_RANK: dict[OperatorRole, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "super_admin": 4,
}


def _role_meets_minimum(operator_role: OperatorRole, min_role: OperatorRole) -> bool:
    return _ROLE_RANK[operator_role] >= _ROLE_RANK[min_role]


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Convenience: clone-with helpers for layout edits
# ---------------------------------------------------------------------------

def with_added_item(layout: LayoutGrid, item: LayoutItem) -> LayoutGrid:
    """Return a new LayoutGrid with `item` appended."""
    return LayoutGrid(version=layout.version, grid=[*layout.grid, item])


def with_removed_widget(layout: LayoutGrid, widget_id: str) -> LayoutGrid:
    """Return a new LayoutGrid with the named widget removed (if present)."""
    return LayoutGrid(
        version=layout.version,
        grid=[item for item in layout.grid if item.widget_id != widget_id],
    )


def with_replaced_item(layout: LayoutGrid, item: LayoutItem) -> LayoutGrid:
    """Return a new LayoutGrid with the item for `item.widget_id` replaced.

    If the widget_id wasn't previously in the layout, the item is appended.
    """
    new_grid: list[LayoutItem] = []
    replaced = False
    for existing in layout.grid:
        if existing.widget_id == item.widget_id:
            new_grid.append(item)
            replaced = True
        else:
            new_grid.append(existing)
    if not replaced:
        new_grid.append(item)
    return LayoutGrid(version=layout.version, grid=new_grid)
