"""Conformance tests for the SourceAdapter Protocol.

These tests verify that the contract is well-formed and that
`BaseSourceAdapter` correctly satisfies the Protocol.
"""

from __future__ import annotations

from typing import Any

import pytest

from shared_adapter_contract import (
    CONTRACT_VERSION,
    BaseSourceAdapter,
    CanonicalEvent,
    CredentialField,
    DeepLinkType,
    Severity,
    SmokeResult,
    SourceAdapter,
    TenantMappingShape,
)
from shared_adapter_contract.types import HealthStatus, RateLimitHints, WidgetDefinitionRef


class _MinimalAdapter(BaseSourceAdapter):
    """Minimum viable adapter for Protocol-conformance testing."""

    vendor_slug = "test-vendor"
    vendor_display_name = "Test Vendor"
    vendor_logo_path = "/logos/test.svg"
    auth_model = "api-key"
    delivery_mode = "poll"
    compliance_categories = ["general"]

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name="TEST_API_KEY",
                label="Test API Key",
                kind="password",
                description="API key for the test vendor",
            )
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/api/v1/tenants",
            vendor_tenant_id_field="tenantId",
            vendor_tenant_label_field="tenantName",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        return SmokeResult(ok=True, message="Test vendor reachable")

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        payload = raw_envelope.get("payload", {})
        return CanonicalEvent(
            vendor_event_id=raw_envelope["id"],
            received_at="2026-05-04T18:00:00.000Z",
            severity=self.severity_map(raw_envelope),
            indicator=payload.get("indicator"),
            indicator_type=payload.get("indicator_type"),
            source_host=payload.get("hostname"),
            summary="Test event",
            payload=payload,
            payload_sha256=self.compute_payload_sha256(payload),
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        return raw_envelope.get("payload", {}).get("tenant_id")

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return raw_envelope.get("payload", {}).get("severity", "info")

    def human_summary(self, event: CanonicalEvent) -> str:
        return f"Test event {event.vendor_event_id}"

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        if link_type == "alert":
            return f"https://test.example.com/alerts/{event.vendor_event_id}"
        return None


def test_contract_version_exported() -> None:
    """The CONTRACT_VERSION constant is the public version pin."""
    assert CONTRACT_VERSION == "1.0"


def test_base_adapter_satisfies_protocol() -> None:
    """A minimal BaseSourceAdapter subclass satisfies the SourceAdapter Protocol."""
    adapter: SourceAdapter = _MinimalAdapter()  # type: ignore[assignment]
    assert adapter.vendor_slug == "test-vendor"
    assert adapter.contract_version == "1.0"


def test_extract_event_is_deterministic() -> None:
    """extract_event called twice on the same envelope produces equal CanonicalEvents."""
    adapter = _MinimalAdapter()
    envelope = {
        "id": "evt-123",
        "payload": {
            "tenant_id": "client-a",
            "severity": "high",
            "indicator": "203.0.113.4",
            "indicator_type": "ip",
            "hostname": "host-1",
        },
    }
    a = adapter.extract_event(envelope)
    b = adapter.extract_event(envelope)
    assert a == b
    assert a.payload_sha256 == b.payload_sha256


def test_route_to_tenant_returns_none_for_unmapped() -> None:
    """Adapter returns None when envelope has no tenant identifier — framework
    will route to _unrouted."""
    adapter = _MinimalAdapter()
    assert adapter.route_to_tenant({"id": "evt-1", "payload": {}}) is None


def test_deep_link_alert_required() -> None:
    """Every adapter must implement deep_link for link_type='alert'."""
    adapter = _MinimalAdapter()
    event = CanonicalEvent(
        vendor_event_id="evt-x",
        received_at="2026-05-04T18:00:00.000Z",
        severity="medium",
        indicator=None,
        indicator_type=None,
        source_host=None,
        summary="x",
        payload={},
        payload_sha256="0" * 64,
    )
    url = adapter.deep_link(event, "alert")
    assert url is not None
    assert url.startswith("https://")


def test_deep_link_other_types_optional() -> None:
    """deep_link for 'device', 'tenant', 'host' may return None."""
    adapter = _MinimalAdapter()
    event = CanonicalEvent(
        vendor_event_id="evt-x",
        received_at="2026-05-04T18:00:00.000Z",
        severity="medium",
        indicator=None,
        indicator_type=None,
        source_host=None,
        summary="x",
        payload={},
        payload_sha256="0" * 64,
    )
    assert adapter.deep_link(event, "device") is None


def test_canonical_event_immutable() -> None:
    """CanonicalEvent is a frozen dataclass — fields cannot be reassigned."""
    event = CanonicalEvent(
        vendor_event_id="evt-x",
        received_at="2026-05-04T18:00:00.000Z",
        severity="info",
        indicator=None,
        indicator_type=None,
        source_host=None,
        summary="x",
        payload={},
        payload_sha256="0" * 64,
    )
    with pytest.raises(Exception):  # FrozenInstanceError
        event.severity = "critical"  # type: ignore[misc]


def test_widget_definition_default_returns_none() -> None:
    """Adapters that don't declare a widget return None from the default impl."""
    adapter = _MinimalAdapter()
    assert adapter.widget_definition() is None


def test_widget_definition_can_return_single_or_list() -> None:
    """Per ADR-005 Q1 resolution: WidgetDefinitionRef | list[...] | None all valid."""

    class _MultiWidgetAdapter(_MinimalAdapter):
        def widget_definition(
            self,
        ) -> WidgetDefinitionRef | list[WidgetDefinitionRef] | None:
            return [
                WidgetDefinitionRef(widget_id="test-vendor.alert-feed"),
                WidgetDefinitionRef(widget_id="test-vendor.device-coverage"),
            ]

    adapter = _MultiWidgetAdapter()
    result = adapter.widget_definition()
    assert isinstance(result, list)
    assert len(result) == 2


def test_health_default() -> None:
    """Default health() returns alive=True with empty metrics."""
    adapter = _MinimalAdapter()
    health = adapter.health()
    assert isinstance(health, HealthStatus)
    assert health.alive is True
    assert health.errors_last_hour == 0


def test_rate_limit_hints_default() -> None:
    """Default rate_limit_hints() returns empty hints."""
    adapter = _MinimalAdapter()
    hints = adapter.rate_limit_hints()
    assert isinstance(hints, RateLimitHints)
    assert hints.requests_per_second is None


def test_compute_payload_sha256_deterministic() -> None:
    """Same payload dict → same sha256 across calls + key ordering."""
    a = BaseSourceAdapter.compute_payload_sha256({"b": 2, "a": 1})
    b = BaseSourceAdapter.compute_payload_sha256({"a": 1, "b": 2})
    assert a == b
    assert len(a) == 64
