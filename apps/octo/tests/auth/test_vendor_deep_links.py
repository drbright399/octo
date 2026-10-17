"""Coverage for apps/octo/api/vendor_deep_links.py.

The resolver is the seam between the API layer and adapter contract
methods. We test:
  - No registry on app.state              → (None, None)
  - Registry without matching adapter     → (None, None)
  - Adapter present but payload missing vendor_event_id → (None, name)
  - Adapter present + good payload        → (url, name)
  - Adapter raises                        → (None, name)  [defensive]
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from apps.octo.api.vendor_deep_links import resolve_alert_link
from shared_adapter_contract.types import CanonicalEvent


# A minimal adapter-class stand-in. Only attributes the resolver actually
# uses are defined.
class _StubAdapter:
    vendor_display_name = "Stub Vendor"

    def deep_link(self, event: CanonicalEvent, link_type: str) -> str | None:
        return f"https://example.test/alert/{event.vendor_event_id}"


class _RaisingAdapter:
    vendor_display_name = "Broken Adapter"

    def deep_link(self, event: CanonicalEvent, link_type: str) -> str | None:
        raise RuntimeError("vendor portal URL not configured")


def _mock_request(adapter_cls: Any | None) -> Any:
    """FastAPI Request stub — only `app.state.adapter_registry.get_adapter_class`
    is read by the resolver."""
    req = MagicMock()
    if adapter_cls is None:
        req.app.state.adapter_registry = None
    else:
        registry = MagicMock()
        registry.get_adapter_class.return_value = adapter_cls
        req.app.state.adapter_registry = registry
    return req


_GOOD_PAYLOAD: dict[str, Any] = {"vendor_event_id": "abc-123", "foo": "bar"}


def test_missing_registry_returns_none() -> None:
    req = MagicMock()
    req.app.state = MagicMock(spec=[])  # no `adapter_registry` attribute
    url, name = resolve_alert_link(
        req,
        source_slug="datto",
        payload=_GOOD_PAYLOAD,
        payload_sha256="x" * 64,
        source_host="host-1",
        received_at="2026-05-13T15:00:00.000Z",
        severity="high",
        summary="ssh brute force",
    )
    assert url is None
    assert name is None


def test_no_matching_adapter_returns_none() -> None:
    req = _mock_request(adapter_cls=None)
    req.app.state.adapter_registry = MagicMock()
    req.app.state.adapter_registry.get_adapter_class.return_value = None
    url, name = resolve_alert_link(
        req,
        source_slug="unknown",
        payload=_GOOD_PAYLOAD,
        payload_sha256="x" * 64,
        source_host=None,
        received_at="2026-05-13T15:00:00.000Z",
        severity="medium",
        summary="—",
    )
    assert url is None
    assert name is None


def test_payload_without_event_id_returns_name_only() -> None:
    req = _mock_request(_StubAdapter)
    url, name = resolve_alert_link(
        req,
        source_slug="stub",
        payload={"no_id_here": True},
        payload_sha256="x" * 64,
        source_host=None,
        received_at="2026-05-13T15:00:00.000Z",
        severity="low",
        summary="",
    )
    assert url is None
    assert name == "Stub Vendor"


def test_happy_path_returns_url_and_name() -> None:
    req = _mock_request(_StubAdapter)
    url, name = resolve_alert_link(
        req,
        source_slug="stub",
        payload=_GOOD_PAYLOAD,
        payload_sha256="x" * 64,
        source_host="host-1",
        received_at="2026-05-13T15:00:00.000Z",
        severity="critical",
        summary="malware blocked",
    )
    assert url == "https://example.test/alert/abc-123"
    assert name == "Stub Vendor"


def test_adapter_exception_falls_through_without_500() -> None:
    """A buggy adapter must NEVER 500 the search response."""
    req = _mock_request(_RaisingAdapter)
    url, name = resolve_alert_link(
        req,
        source_slug="broken",
        payload=_GOOD_PAYLOAD,
        payload_sha256="x" * 64,
        source_host=None,
        received_at="2026-05-13T15:00:00.000Z",
        severity="info",
        summary="",
    )
    assert url is None
    assert name == "Broken Adapter"
