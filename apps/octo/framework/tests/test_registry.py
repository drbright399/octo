"""Tests for the adapter registry — class registration + instance lifecycle + listeners."""

from __future__ import annotations

from typing import Any

import pytest

from shared_adapter_contract import (
    BaseSourceAdapter,
    CanonicalEvent,
    CredentialField,
    DeepLinkType,
    Severity,
    SmokeResult,
    TenantMappingShape,
)

from apps.octo.framework.lifecycle import AdapterLifecycleState, StateTransitionError
from apps.octo.framework.registry import (
    AdapterRegistry,
    InMemoryRegistryBackend,
    StateChangeEvent,
)


# ---------------------------------------------------------------------------
# Test adapter fixture (minimal-viable SourceAdapter for registry testing)
# ---------------------------------------------------------------------------

class _TestAdapter(BaseSourceAdapter):
    vendor_slug = "test-vendor"
    vendor_display_name = "Test Vendor"
    vendor_logo_path = "/logos/test.svg"
    auth_model = "api-key"
    delivery_mode = "poll"
    compliance_categories = ["general"]

    def credential_shape(self) -> list[CredentialField]:
        return [
            CredentialField(
                name="TEST_KEY", label="Test Key", kind="password",
                description="Test API key",
            ),
        ]

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="api",
            fetch_endpoint="/api/v1/tenants",
            vendor_tenant_id_field="id",
            vendor_tenant_label_field="name",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        return SmokeResult(ok=True, message="ok")

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        return CanonicalEvent(
            vendor_event_id=raw_envelope.get("id", "test"),
            received_at="2026-05-04T18:00:00.000Z",
            severity="info",
            indicator=None,
            indicator_type=None,
            source_host=None,
            summary="test",
            payload={},
            payload_sha256="0" * 64,
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        return raw_envelope.get("tenant_id")

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return "info"

    def human_summary(self, event: CanonicalEvent) -> str:
        return event.summary

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        if link_type == "alert":
            return f"https://test.example.com/alerts/{event.vendor_event_id}"
        return None


class _OtherAdapter(BaseSourceAdapter):
    """Same vendor_slug as _TestAdapter — used for collision testing."""
    vendor_slug = "test-vendor"
    vendor_display_name = "Other Test Vendor"
    vendor_logo_path = "/logos/other.svg"
    auth_model = "oauth2"
    delivery_mode = "push"
    compliance_categories = ["general"]

    def credential_shape(self) -> list[CredentialField]:
        return []

    def tenant_mapping_shape(self) -> TenantMappingShape:
        return TenantMappingShape(
            fetch_method="manual",
            fetch_endpoint=None,
            vendor_tenant_id_field="x",
            vendor_tenant_label_field="x",
        )

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        return SmokeResult(ok=True, message="ok")

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        return CanonicalEvent(
            vendor_event_id="x", received_at="2026-05-04T18:00:00.000Z",
            severity="info", indicator=None, indicator_type=None,
            source_host=None, summary="x", payload={}, payload_sha256="0" * 64,
        )

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        return None

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        return "info"

    def human_summary(self, event: CanonicalEvent) -> str:
        return "x"

    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None:
        return None


# ---------------------------------------------------------------------------
# Class registration
# ---------------------------------------------------------------------------

def test_register_adapter_class() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    assert reg.get_adapter_class("test-vendor") is _TestAdapter
    assert _TestAdapter in reg.list_adapter_classes()


def test_register_adapter_class_idempotent() -> None:
    """Re-registering the same class is a no-op."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    reg.register_adapter_class(_TestAdapter)
    assert len(reg.list_adapter_classes()) == 1


def test_register_different_class_same_slug_rejected() -> None:
    """Two different classes with the same vendor_slug → ValueError."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    with pytest.raises(ValueError, match="already registered"):
        reg.register_adapter_class(_OtherAdapter)


def test_get_adapter_class_returns_none_for_unknown() -> None:
    reg = AdapterRegistry()
    assert reg.get_adapter_class("unknown-vendor") is None


# ---------------------------------------------------------------------------
# Instance lifecycle — happy path
# ---------------------------------------------------------------------------

def test_configure_instance_creates_in_configured_state() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor",
        tenant_slug="client-a",
        instance_id="primary",
        credentials_ref="vault:test-vendor:client-a:primary",
    )
    assert inst.state == AdapterLifecycleState.CONFIGURED
    assert inst.instance_key == "test-vendor:client-a:primary"
    assert inst.created_at  # set
    assert inst.last_state_change_at == inst.created_at


def test_configure_unknown_adapter_rejected() -> None:
    reg = AdapterRegistry()
    with pytest.raises(ValueError, match="not registered"):
        reg.configure_instance(
            vendor_slug="unknown-vendor",
            tenant_slug="client-a",
            instance_id="primary",
            credentials_ref="vault:x",
        )


def test_configure_duplicate_active_instance_rejected() -> None:
    """Cannot re-configure an instance that's already CONFIGURED / ACTIVE / PAUSED."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    with pytest.raises(ValueError, match="already exists"):
        reg.configure_instance(
            vendor_slug="test-vendor", tenant_slug="client-a",
            instance_id="primary", credentials_ref="vault:y",
        )


def test_configure_after_remove_allowed() -> None:
    """Re-configuring after REMOVED is allowed (operator re-onboards)."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    reg.transition(inst.instance_key, to_state=AdapterLifecycleState.REMOVED, reason="cleanup")
    new_inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:fresh",
    )
    assert new_inst.state == AdapterLifecycleState.CONFIGURED
    assert new_inst.credentials_ref == "vault:fresh"


def test_full_happy_lifecycle() -> None:
    """CONFIGURED → ACTIVE → PAUSED → ACTIVE → REMOVED."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    inst = reg.activate(inst.instance_key)
    assert inst.state == AdapterLifecycleState.ACTIVE
    inst = reg.pause(inst.instance_key, reason="operator break")
    assert inst.state == AdapterLifecycleState.PAUSED
    inst = reg.resume(inst.instance_key)
    assert inst.state == AdapterLifecycleState.ACTIVE
    inst = reg.remove(inst.instance_key, reason="cleanup")
    assert inst.state == AdapterLifecycleState.REMOVED


# ---------------------------------------------------------------------------
# Lifecycle violations
# ---------------------------------------------------------------------------

def test_invalid_transition_raises() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    # CONFIGURED → PAUSED is invalid (can't pause something that's not active)
    with pytest.raises(StateTransitionError):
        reg.transition(
            inst.instance_key,
            to_state=AdapterLifecycleState.PAUSED,
            reason="invalid transition",
        )


def test_transition_unknown_instance_raises() -> None:
    reg = AdapterRegistry()
    with pytest.raises(KeyError, match="not found"):
        reg.transition(
            "unknown:client-a:primary",
            to_state=AdapterLifecycleState.ACTIVE,
            reason="x",
        )


# ---------------------------------------------------------------------------
# Lookup + filtering
# ---------------------------------------------------------------------------

def test_list_instances_unfiltered() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:1",
    )
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-b",
        instance_id="primary", credentials_ref="vault:2",
    )
    assert len(reg.list_instances()) == 2


def test_list_instances_filtered_by_tenant() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:1",
    )
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-b",
        instance_id="primary", credentials_ref="vault:2",
    )
    assert len(reg.list_instances(tenant_slug="client-a")) == 1


def test_list_active_only() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst1 = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:1",
    )
    reg.activate(inst1.instance_key)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-b",
        instance_id="primary", credentials_ref="vault:2",
    )
    # client-b is CONFIGURED but not ACTIVE
    assert len(reg.list_active()) == 1
    assert reg.list_active()[0].tenant_slug == "client-a"


# ---------------------------------------------------------------------------
# State-change subscription
# ---------------------------------------------------------------------------

def test_listener_receives_configure_event() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    received: list[StateChangeEvent] = []

    def listener(event: StateChangeEvent) -> None:
        received.append(event)

    reg.subscribe(listener)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    assert len(received) == 1
    assert received[0].from_state == AdapterLifecycleState.REGISTERED
    assert received[0].to_state == AdapterLifecycleState.CONFIGURED


def test_listener_receives_full_lifecycle_events() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    received: list[StateChangeEvent] = []
    reg.subscribe(lambda e: received.append(e))

    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    reg.activate(inst.instance_key)
    reg.pause(inst.instance_key, reason="break")
    reg.resume(inst.instance_key)
    reg.remove(inst.instance_key, reason="cleanup")

    assert len(received) == 5
    transitions = [(e.from_state, e.to_state) for e in received]
    assert transitions == [
        (AdapterLifecycleState.REGISTERED, AdapterLifecycleState.CONFIGURED),
        (AdapterLifecycleState.CONFIGURED, AdapterLifecycleState.ACTIVE),
        (AdapterLifecycleState.ACTIVE, AdapterLifecycleState.PAUSED),
        (AdapterLifecycleState.PAUSED, AdapterLifecycleState.ACTIVE),
        (AdapterLifecycleState.ACTIVE, AdapterLifecycleState.REMOVED),
    ]


def test_subscribe_idempotent() -> None:
    """Subscribing the same listener twice still only delivers once per event."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    received: list[StateChangeEvent] = []

    def listener(event: StateChangeEvent) -> None:
        received.append(event)

    reg.subscribe(listener)
    reg.subscribe(listener)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    assert len(received) == 1


def test_unsubscribe() -> None:
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    received: list[StateChangeEvent] = []

    def listener(event: StateChangeEvent) -> None:
        received.append(event)

    reg.subscribe(listener)
    reg.unsubscribe(listener)
    reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    assert len(received) == 0


# ---------------------------------------------------------------------------
# Backend interaction
# ---------------------------------------------------------------------------

def test_in_memory_backend_used_by_default() -> None:
    """AdapterRegistry() with no args uses InMemoryRegistryBackend."""
    reg = AdapterRegistry()
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    assert reg.get_instance(inst.instance_key) is not None


def test_explicit_backend_injected() -> None:
    """AdapterRegistry accepts a custom backend (will be SQLite-backed in prod)."""
    backend = InMemoryRegistryBackend()
    reg = AdapterRegistry(backend=backend)
    reg.register_adapter_class(_TestAdapter)
    inst = reg.configure_instance(
        vendor_slug="test-vendor", tenant_slug="client-a",
        instance_id="primary", credentials_ref="vault:x",
    )
    # Backend has the instance
    assert backend.get_instance(inst.instance_key) is not None
