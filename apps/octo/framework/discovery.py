"""Adapter discovery — walks `apps/octo/adapters/` and registers SourceAdapter
implementations.

Per ADR-005 §`Directory layout`. Each adapter ships as a Python package under
`apps/octo/adapters/<vendor_slug>/`. Discovery imports each subpackage,
inspects its top-level namespace for classes that satisfy the SourceAdapter
Protocol, and calls `AdapterRegistry.register_adapter_class()` for each.

Discovery is fault-tolerant: a single broken adapter directory does NOT
abort startup. Each failure is captured in a DiscoveryReport with the
exception text so operators can triage.

Idempotent: re-running discovery on the same directory is a no-op (registry
de-dup handles same-class re-registration). Two different classes claiming
the same vendor_slug surface a registry-level ValueError.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path

from shared_adapter_contract import SourceAdapter

from apps.octo.framework.registry import AdapterRegistry


@dataclass
class DiscoveryReport:
    """Outcome of a discovery pass.

    Use `registered` for the happy-path count, `skipped` for namespaces
    that didn't yield an adapter class, `failed` for triage. Adapter
    authors can wire a startup-time check that bails on len(failed) > 0.
    """

    registered: list[str] = field(default_factory=list)
    """Vendor slugs registered during this pass."""

    skipped: list[str] = field(default_factory=list)
    """Subpackage names that imported cleanly but exposed no SourceAdapter class."""

    failed: list[tuple[str, str]] = field(default_factory=list)
    """(subpackage_name, error_message) for imports / inspections that raised."""


def discover_adapters(
    adapters_package: str,
    registry: AdapterRegistry,
) -> DiscoveryReport:
    """Walk `<adapters_package>` and register adapter classes.

    Args:
        adapters_package: dotted-path name of the adapters root, typically
            'apps.octo.adapters'. Tests pass a temporary package name they
            put on sys.path.
        registry: the AdapterRegistry to register into.

    Returns:
        DiscoveryReport summarizing the pass.
    """
    report = DiscoveryReport()

    try:
        root_module = importlib.import_module(adapters_package)
    except ModuleNotFoundError as exc:
        report.failed.append((adapters_package, f"root package import failed: {exc}"))
        return report

    if not hasattr(root_module, "__path__"):
        report.failed.append((adapters_package, "not a package (missing __path__)"))
        return report

    for finder_info in pkgutil.iter_modules(root_module.__path__):
        subpackage_name = finder_info.name
        full_name = f"{adapters_package}.{subpackage_name}"

        try:
            submodule = importlib.import_module(full_name)
        except Exception as exc:  # noqa: BLE001 — we WANT to log+skip any failure
            report.failed.append((full_name, f"import error: {exc!r}"))
            continue

        adapter_classes = _find_adapter_classes(submodule)
        if not adapter_classes:
            report.skipped.append(full_name)
            continue

        for cls in adapter_classes:
            try:
                registry.register_adapter_class(cls)
            except Exception as exc:  # noqa: BLE001
                report.failed.append((
                    full_name,
                    f"registry rejection for {cls.__name__}: {exc!r}",
                ))
                continue
            report.registered.append(cls.vendor_slug)

    return report


def discover_adapters_from_path(
    adapters_dir: Path,
    package_name: str,
    registry: AdapterRegistry,
) -> DiscoveryReport:
    """Discover adapters from a filesystem directory not on sys.path.

    Helper for tests + ad-hoc loading. Adds `adapters_dir.parent` to sys.path,
    invokes import discovery, then leaves sys.path mutated (caller cleans up
    if needed). Most production callers should put the adapters root on the
    PYTHONPATH at deploy time and call `discover_adapters()` directly.
    """
    import sys

    parent = str(adapters_dir.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    return discover_adapters(package_name, registry)


def _find_adapter_classes(module: object) -> list[type[SourceAdapter]]:
    """Scan a module's namespace for classes implementing the SourceAdapter Protocol.

    A class qualifies if:
    - It's a class
    - Defined in the module being scanned (not re-exported imports)
    - Has class-level `vendor_slug` (the only field discovery uses to confirm
      Protocol intent — full Protocol conformance is enforced at registration time)
    """
    found: list[type[SourceAdapter]] = []
    for _, attr in inspect.getmembers(module, inspect.isclass):
        # Only classes defined in this module — avoids re-importing the Protocol
        # itself or pulling in unrelated re-exports.
        if attr.__module__ != module.__name__:
            continue
        # The Protocol carries `vendor_slug` as a class-level identifier; that's
        # our marker. Concrete adapters set it; abstract bases (BaseSourceAdapter)
        # leave it unset → they're filtered out below.
        if not hasattr(attr, "vendor_slug"):
            continue
        slug = getattr(attr, "vendor_slug", None)
        if not isinstance(slug, str) or not slug:
            continue
        found.append(attr)  # type: ignore[arg-type]
    return found
