"""The SourceAdapter Protocol — the contract every adapter implements.

Per ADR-005 §`The contract`. Uses `typing.Protocol` (PEP 544) so third-party
adapter authors can implement the contract without inheriting from a framework
base class.

Adapter authors who want sensible defaults can inherit from `BaseSourceAdapter`
in `shared_adapter_contract.base` instead.
"""

from __future__ import annotations

from typing import Any, Protocol

from shared_adapter_contract.types import (
    AuthModel,
    Availability,
    CanonicalEvent,
    ComplianceCategory,
    CredentialField,
    DeepLinkType,
    DeliveryMode,
    HealthStatus,
    RateLimitHints,
    Severity,
    SmokeResult,
    TenantMappingShape,
    WidgetDefinitionRef,
)


class SourceAdapter(Protocol):
    """Every source adapter implements this Protocol.

    Six mandatory behaviors (per ADR-005):
    1. Determinism in extraction
    2. Fail-loud on unmapped tenants (route_to_tenant returns None → _unrouted)
    3. Idempotency on replay
    4. No PII in human_summary beyond what's in the indicator
    5. Section 7 mitigations applied at the bridge boundary (no direct DB access)
    6. Deep-link URL safety (vendor-portal URLs only; new tab; no untrusted concat)

    Optional capabilities are deliberately NOT members of this Protocol (an
    adapter without them still conforms); the framework probes for them:
    - `supports_tenant_discovery = True` + `list_vendor_tenants(credentials)
      -> VendorTenantListing` — see `BaseSourceAdapter.list_vendor_tenants`.
    - `reports_vendor_contact = True` — the poller reports each vendor
      round-trip; optional `poll_now()` cuts its current wait short.
    - `vendor_tenant_label(raw_envelope) -> str | None` — the vendor's OWN
      name for the tenant `route_to_tenant()` identified, read from the same
      envelope, so the platform can auto-link/auto-create a tenant without
      contacting the vendor on the ingest path.
    """

    # ----- Identity + metadata (declarative, class-level) -----

    vendor_slug: str
    """Canonical identifier (e.g., 'datto-rmm'). Lowercase + hyphens."""

    vendor_display_name: str
    """Human-readable (e.g., 'Datto RMM')."""

    vendor_logo_path: str
    """Path to the vendor logo for wizard + settings UI."""

    contract_version: str
    """Adapter contract version this implements (e.g., '1.0')."""

    auth_model: AuthModel
    delivery_mode: DeliveryMode
    availability: Availability
    compliance_categories: list[ComplianceCategory]

    # ----- Onboarding (wizard) -----

    def credential_shape(self) -> list[CredentialField]:
        """Form fields the wizard renders to collect creds."""
        ...

    def tenant_mapping_shape(self) -> TenantMappingShape:
        """How to discover this vendor's tenant list once creds are vaulted."""
        ...

    def smoke_test(self, credentials: dict[str, Any]) -> SmokeResult:
        """Use freshly-vaulted creds to verify reachability + return a sample event."""
        ...

    # ----- Lifecycle -----

    def start(self, instance_config: dict[str, Any]) -> None:
        """Called when the adapter instance is enabled for one or more tenants.

        instance_config carries `(tenant_mapping, credentials_ref, rate_limit_overrides)`.
        """
        ...

    def stop(self) -> None:
        """Called when the adapter is paused or removed. Must release resources."""
        ...

    def health(self) -> HealthStatus:
        """Returns liveness + lag metrics for the operator settings UI."""
        ...

    # ----- Data side -----

    def extract_event(self, raw_envelope: dict[str, Any]) -> CanonicalEvent:
        """Map vendor-specific envelope to OCTO's CanonicalEvent.

        MUST be deterministic: same raw_envelope → same CanonicalEvent → same
        payload_sha256. Framework dedups on `(tenant × source × vendor_event_id
        × payload_sha256)`.
        """
        ...

    def route_to_tenant(self, raw_envelope: dict[str, Any]) -> str | None:
        """Extract the vendor's tenant identifier from the envelope.

        Returns the raw vendor tenant ID (e.g., Datto siteUid, RC accountId,
        UniFi site_id). The framework looks this up in `source_tenant_mapping`
        to resolve the OCTO slug. Returns None if the envelope has no tenant
        identifier — framework routes to `_unrouted` for operator triage.

        MUST NOT do the actual mapping lookup itself — framework handles that
        centrally per ADR-005 Q3 resolution.
        """
        ...

    def severity_map(self, raw_envelope: dict[str, Any]) -> Severity:
        """Map vendor severity to OCTO canonical severity."""
        ...

    def human_summary(self, event: CanonicalEvent) -> str:
        """Produce an operator-readable one-line summary.

        Summary MUST NOT contain SSN-shape, MRN-shape, or card-number-shape strings
        beyond what the indicator field already exposes. PII regex check applied at
        write-time by the framework runtime.
        """
        ...

    # ----- Rate-limit declaration -----

    def rate_limit_hints(self) -> RateLimitHints:
        """Vendor's known rate limits. Framework uses for retry/backoff tuning."""
        ...

    # ----- UI side (per ADR-006) -----

    def widget_definition(
        self,
    ) -> WidgetDefinitionRef | list[WidgetDefinitionRef] | None:
        """Widget(s) that auto-populate on operator dashboards when this
        adapter is enabled.

        - Single is typical (one live alert feed per adapter)
        - List for advanced cases (e.g., Datto EDR with both 'alerts feed' and
          'device coverage' widgets)
        - None for adapters that contribute only to system widgets

        Full WidgetDefinition lives in `shared_widget_contract`; adapters
        return references here, framework resolves them at registry-build time.
        """
        ...

    def deep_link(
        self,
        event: CanonicalEvent,
        link_type: DeepLinkType,
    ) -> str | None:
        """Return a vendor-portal URL deep-linked to the resource.

        Universal-mandatory for `link_type='alert'`. Optional for 'device',
        'tenant', 'host'.

        Operators clicking events in widget feeds get this URL opened in a new
        tab (target='_blank' rel='noopener noreferrer'). Per ADR-005 §
        `Six mandatory behaviors` rule 6: vendor-portal URLs only; no
        third-party redirects; no opaque shorteners; URL constructed from event
        fields + vendor-config base URL with proper escaping.
        """
        ...
