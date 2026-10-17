"""System widget discovery — walks `apps/athena/widgets/system/` and
registers WidgetDefinition instances with the WidgetRegistry.

Per ADR-006 §`System widgets`. System widgets are tenant-agnostic and
ship with the framework rather than with an adapter. Each module under
`apps/athena/widgets/system/` exposes either:

  - A module-level constant `WIDGET: WidgetDefinition`
  - OR a list `WIDGETS: list[WidgetDefinition]` for modules that ship more
    than one widget

Discovery imports each module, picks up these constants, and calls
`WidgetRegistryImpl.register_system_widget()`.

Discovery is fault-tolerant — one broken module does not abort startup.
Each failure is captured in a DiscoveryReport.

Adapter widgets are NOT discovered here. They follow the adapter
discovery flow (`apps/octo/framework/discovery.py`): when an adapter is
registered, its `widget_definition()` method is queried separately by
the framework boot sequence to register adapter widgets.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field

from shared_widget_contract import WidgetDefinition

from apps.athena.framework.widget_registry import WidgetRegistryImpl


@dataclass
class WidgetDiscoveryReport:
    """Outcome of a system-widget discovery pass."""

    registered: list[str] = field(default_factory=list)
    """widget_ids registered during this pass."""

    skipped: list[str] = field(default_factory=list)
    """Module names that imported cleanly but exposed no WIDGET / WIDGETS."""

    failed: list[tuple[str, str]] = field(default_factory=list)
    """(module_name, error_message) for imports that raised."""


def discover_system_widgets(
    widgets_package: str,
    registry: WidgetRegistryImpl,
) -> WidgetDiscoveryReport:
    """Walk `<widgets_package>` and register WidgetDefinition objects.

    Args:
        widgets_package: dotted-path name of the system widgets root,
            typically 'apps.athena.widgets.system'.
        registry: the WidgetRegistryImpl to register into.

    Returns:
        WidgetDiscoveryReport summarizing the pass.
    """
    report = WidgetDiscoveryReport()

    try:
        root_module = importlib.import_module(widgets_package)
    except ModuleNotFoundError as exc:
        report.failed.append((widgets_package, f"root package import failed: {exc}"))
        return report

    if not hasattr(root_module, "__path__"):
        report.failed.append((widgets_package, "not a package (missing __path__)"))
        return report

    for finder_info in pkgutil.iter_modules(root_module.__path__):
        module_name = finder_info.name
        full_name = f"{widgets_package}.{module_name}"

        try:
            submodule = importlib.import_module(full_name)
        except Exception as exc:  # noqa: BLE001
            report.failed.append((full_name, f"import error: {exc!r}"))
            continue

        widgets = extract_widgets_from_module(submodule)
        if not widgets:
            report.skipped.append(full_name)
            continue

        for widget in widgets:
            try:
                registry.register_system_widget(widget, module_name=full_name)
            except Exception as exc:  # noqa: BLE001
                report.failed.append((
                    full_name,
                    f"registry rejection for {widget.widget_id}: {exc!r}",
                ))
                continue
            report.registered.append(widget.widget_id)

    return report


def extract_widgets_from_module(module: object) -> list[WidgetDefinition]:
    """Read WIDGET / WIDGETS module constants and return a flat list.

    Both spellings are accepted so single-widget modules don't have to wrap
    their definition in a list.

    Public so adapter-widget boot wiring can reuse the same convention:
    each adapter package may export WIDGET/WIDGETS at module level, and
    the framework boot extracts them via this helper and registers them
    with the WidgetRegistry as adapter widgets keyed to the adapter's
    vendor_slug.
    """
    widgets: list[WidgetDefinition] = []

    single = getattr(module, "WIDGET", None)
    if isinstance(single, WidgetDefinition):
        widgets.append(single)

    plural = getattr(module, "WIDGETS", None)
    if isinstance(plural, list):
        for item in plural:
            if isinstance(item, WidgetDefinition):
                widgets.append(item)

    return widgets
