"""BaseSourceAdapter ABC — convenience base class for adapter authors.

Implements `SourceAdapter` Protocol with sensible defaults for the methods
adapter authors typically don't need to customize. Adapters that want maximum
flexibility can implement `SourceAdapter` directly without inheriting.

Subclasses MUST override at minimum:
- vendor_slug, vendor_display_name, vendor_logo_path (class attributes)
- auth_model, delivery_mode, availability, compliance_categories
- credential_shape()
- tenant_mapping_shape()
- smoke_test()
- extract_event()
- route_to_tenant()
- severity_map()
- human_summary()
- deep_link()
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any

from shared_adapter_contract.types import (
    AuthModel,
    Availability,
    CanonicalEvent,
    ComplianceCategory,
    CredentialField,
    DeepLinkType,
    DeliveryMode,
    HealthStatus,
    Onboarding,
    RateLimitHints,
    Severity,
    SmokeResult,
    TenantMappingShape,
    VendorTenantListing,
    WidgetDefinitionRef,
)


class BaseSourceAdapter(ABC):
    """Convenience ABC for adapter authors. Implements `SourceAdapter` Protocol."""

    # Class-level metadata — subclasses override
    vendor_slug: str
    vendor_display_name: str
    vendor_logo_path: str
    contract_version: str = "1.0"
    auth_model: AuthModel
    delivery_mode: DeliveryMode
    availability: Availability = "available"
    compliance_categories: list[ComplianceCategory]

    supports_tenant_discovery: bool = False
    """OPTIONAL capability flag: True when `list_vendor_tenants()` is
    implemented. Checked on the CLASS, before any credential is decrypted."""

    reports_vendor_contact: bool = False
    """OPTIONAL capability flag: True when the adapter's poller reports every
    vendor round-trip (`apps.octo.instances.vendor_contact.ContactReporter`).
    The instance row's status then follows what the poller OBSERVES, and the
    framework does not overwrite an observed failure with 'started'."""

    # ----- Onboarding (subclass override) -----

    @abstractmethod
    def credential_shape(self) -> list[CredentialField]: ...

    @abstractmethod
    def tenant_mapping_shape(self) -> TenantMappingShape: ...

    @abstractmethod
    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult: ...

    def onboarding(self, webhook_url: str | None = None) -> Onboarding | None:
        """Optional guided setup for the Integrations sidebar (webhook URL,
        step-by-step, sample payloads). Default None = credential form only.
        `webhook_url` is the composed inbound URL for push/hybrid adapters,
        passed in by the catalog so adapters don't read deploy config."""
        return None

    def list_vendor_tenants(self, credentials: dict[str, Any]) -> VendorTenantListing:
        """OPTIONAL: every tenant the vendor knows for these credentials, as
        (id, label) — `id` being exactly what `route_to_tenant()` yields, so
        the mapping UI can offer a picker instead of free text.

        Stateless like `smoke_test()`: gets the decrypted credentials, keeps
        nothing. Must drain the vendor's pagination up to a hard cap (then
        `truncated=True`), and must raise `VendorTenantListError` — with an
        operator-safe message — for every vendor-side failure. Set
        `supports_tenant_discovery = True` when overriding.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support vendor tenant discovery"
        )

    # ----- Lifecycle (default: no-op start/stop; override if adapter manages
    # connections, polling threads, etc.) -----

    def start(self, instance_config: dict[str, Any]) -> None:
        """Default: no-op. Override if adapter manages stateful resources."""
        return

    def stop(self) -> None:
        """Default: no-op. Override to release resources."""
        return

    def health(self) -> HealthStatus:
        """Default: alive=True with no metrics. Override for real health reporting."""
        return HealthStatus(
            alive=True, last_event_at=None, lag_seconds=0.0, errors_last_hour=0
        )

    # ----- Data side (subclass override) -----

    @abstractmethod
    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent: ...

    @abstractmethod
    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None: ...

    def vendor_tenant_label(self, raw_envelope: dict[str, Any]) -> str | None:
        """OPTIONAL: the vendor's own display name for the tenant that
        `route_to_tenant()` returns for this envelope (a Datto site name, a
        RocketCyber customer name), when the envelope carries it. Default
        None = not known from the event; the platform then falls back to
        its cached tenant discovery (never a live vendor call on ingest).
        Vendor text — the caller bounds and cleans it."""
        return None

    @abstractmethod
    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity: ...

    @abstractmethod
    def human_summary(self, event: CanonicalEvent) -> str: ...

    # ----- Rate-limit (default: empty hints — adapter polls/pushes carefully on
    # its own) -----

    def rate_limit_hints(self) -> RateLimitHints:
        return RateLimitHints()

    # ----- UI side (subclass override) -----

    def widget_definition(
        self,
    ) -> WidgetDefinitionRef | list[WidgetDefinitionRef] | None:
        """Default: no widget. Override to declare adapter widget(s)."""
        return None

    @abstractmethod
    def deep_link(self, event: CanonicalEvent, link_type: DeepLinkType) -> str | None: ...

    # ----- Helpers (used by subclasses; not part of the Protocol) -----

    @staticmethod
    def compute_payload_sha256(payload: dict[str, Any]) -> str:
        """Stable sha256 over a payload dict using canonical JSON encoding.

        Adapter authors can use this to populate `CanonicalEvent.payload_sha256`
        deterministically.
        """
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
