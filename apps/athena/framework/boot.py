"""Framework boot — wires discovery + registries + adapter-widget extraction
into a single end-to-end startup function.

One operator UI (Athena Console) over one OCTO core per bundle.
In bundle v1 deployment, Athena Console + OCTO core run together (logical bridge
boundary, not network boundary). The boot function:

1. Constructs an AdapterRegistry (data-plane adapter lifecycle).
2. Constructs a WidgetRegistryImpl, subscribing it to the AdapterRegistry's
   state-change events so widget availability tracks adapter ACTIVE state.
3. Runs `discover_adapters()` against `apps.octo.adapters`. Each subpackage
   contributes a SourceAdapter class.
4. For each registered adapter class, extracts WIDGET / WIDGETS from the
   adapter's module (same convention as system widgets) and registers them
   as adapter widgets keyed to the class's vendor_slug.
5. Runs `discover_system_widgets()` against `apps.athena.widgets.system`.
6. Returns a `BootedFramework` with both registries + an aggregated
   `BootReport` so operators can verify what landed and triage failures.

Faults during any phase are captured in the report — boot does not raise
on broken adapters / widgets so a single bad slot can't take the platform
down. Production deployments can wire a startup-time check:

    booted = boot_framework()
    if booted.report.has_failures():
        log.error(...); sys.exit(1)
"""

from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass, field

from apps.athena.framework.widget_discovery import (
    WidgetDiscoveryReport,
    discover_system_widgets,
    extract_widgets_from_module,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl
from apps.octo.framework.discovery import (
    DiscoveryReport,
    discover_adapters,
)
from apps.octo.framework.registry import AdapterRegistry


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@dataclass
class AdapterWidgetReport:
    """Outcome of registering adapter widgets after adapter classes register.

    For each adapter class, we look at its containing module for
    WIDGET / WIDGETS. Empty modules are reported as skipped (adapter
    contributes only to system widgets, or has none).
    """

    registered: list[str] = field(default_factory=list)
    """widget_ids registered as adapter widgets during this pass."""

    skipped: list[str] = field(default_factory=list)
    """vendor_slugs whose modules did not export WIDGET / WIDGETS."""

    failed: list[tuple[str, str]] = field(default_factory=list)
    """(vendor_slug, error_message) when extraction or registration raised."""


@dataclass
class BootReport:
    """Aggregated boot-time discovery report."""

    adapters: DiscoveryReport
    system_widgets: WidgetDiscoveryReport
    adapter_widgets: AdapterWidgetReport

    def has_failures(self) -> bool:
        """True iff any phase recorded a failure. Use for startup-gate checks."""
        return bool(
            self.adapters.failed
            or self.system_widgets.failed
            or self.adapter_widgets.failed,
        )

    def summary_lines(self) -> list[str]:
        """One human-readable line per phase, suitable for boot logs."""
        return [
            (
                f"adapters: registered={len(self.adapters.registered)} "
                f"skipped={len(self.adapters.skipped)} "
                f"failed={len(self.adapters.failed)}"
            ),
            (
                f"adapter widgets: registered={len(self.adapter_widgets.registered)} "
                f"skipped={len(self.adapter_widgets.skipped)} "
                f"failed={len(self.adapter_widgets.failed)}"
            ),
            (
                f"system widgets: registered={len(self.system_widgets.registered)} "
                f"skipped={len(self.system_widgets.skipped)} "
                f"failed={len(self.system_widgets.failed)}"
            ),
        ]


# ---------------------------------------------------------------------------
# BootedFramework — what callers receive
# ---------------------------------------------------------------------------

@dataclass
class BootedFramework:
    """A wired-up framework runtime ready to serve operator requests.

    The widget_registry is already subscribed to adapter_registry's events,
    so configure_instance() / activate() / pause() / remove() calls on the
    adapter registry automatically propagate widget availability.
    """

    adapter_registry: AdapterRegistry
    widget_registry: WidgetRegistryImpl
    report: BootReport


# ---------------------------------------------------------------------------
# Default package paths
# ---------------------------------------------------------------------------

DEFAULT_ADAPTERS_PACKAGE = "apps.octo.adapters"
DEFAULT_SYSTEM_WIDGETS_PACKAGE = "apps.athena.widgets.system"


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

def boot_framework(
    *,
    adapters_package: str = DEFAULT_ADAPTERS_PACKAGE,
    system_widgets_package: str = DEFAULT_SYSTEM_WIDGETS_PACKAGE,
    adapter_registry: AdapterRegistry | None = None,
    widget_registry: WidgetRegistryImpl | None = None,
) -> BootedFramework:
    """Stand up the framework end-to-end.

    Args optional for tests that want to inject pre-built registries.
    Production callers normally pass nothing and let boot construct fresh
    registries.
    """
    if adapter_registry is None:
        adapter_registry = AdapterRegistry()
    if widget_registry is None:
        widget_registry = WidgetRegistryImpl(adapter_registry=adapter_registry)

    # Phase 1: adapter classes
    adapter_report = discover_adapters(adapters_package, adapter_registry)

    # Phase 2: adapter widgets — extract WIDGET/WIDGETS from each adapter's
    # module and register against the WidgetRegistry keyed to the class's
    # vendor_slug. We reuse the same WIDGET/WIDGETS convention as system
    # widgets so adapter authors only have one rule to remember.
    adapter_widget_report = _register_adapter_widgets(
        adapter_registry=adapter_registry,
        widget_registry=widget_registry,
    )

    # Phase 3: system widgets — tenant-agnostic; ship with the framework
    system_widget_report = discover_system_widgets(
        system_widgets_package, widget_registry,
    )

    return BootedFramework(
        adapter_registry=adapter_registry,
        widget_registry=widget_registry,
        report=BootReport(
            adapters=adapter_report,
            system_widgets=system_widget_report,
            adapter_widgets=adapter_widget_report,
        ),
    )


# ---------------------------------------------------------------------------
# Adapter-widget extraction
# ---------------------------------------------------------------------------

def _register_adapter_widgets(
    *,
    adapter_registry: AdapterRegistry,
    widget_registry: WidgetRegistryImpl,
) -> AdapterWidgetReport:
    """For each registered adapter class, register widgets from its module."""
    report = AdapterWidgetReport()

    for adapter_cls in adapter_registry.list_adapter_classes():
        slug = adapter_cls.vendor_slug
        module_name = adapter_cls.__module__

        try:
            module = sys.modules.get(module_name) or importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            report.failed.append((slug, f"could not import module: {exc!r}"))
            continue

        widgets = extract_widgets_from_module(module)
        if not widgets:
            report.skipped.append(slug)
            continue

        for widget in widgets:
            try:
                widget_registry.register_adapter_widget(widget, vendor_slug=slug)
            except Exception as exc:  # noqa: BLE001
                report.failed.append((
                    slug,
                    f"registry rejection for {widget.widget_id}: {exc!r}",
                ))
                continue
            report.registered.append(widget.widget_id)

    return report
