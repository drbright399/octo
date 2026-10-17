"""Type definitions for the source-adapter contract.

Per ADR-005 §`The contract`. All types are frozen dataclasses to enforce
immutability — adapter authors can't accidentally mutate a CanonicalEvent
after extraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Shared enum-likes
# ---------------------------------------------------------------------------

Severity = Literal["info", "low", "medium", "high", "critical"]
"""OCTO canonical severity. Adapters map vendor severity into this set via
`severity_map(envelope) -> Severity`."""

IndicatorType = Literal["ip", "domain", "url", "sha256", "asn", "other"]
"""Canonical IOC types. None when an event has no indicator."""

AuthModel = Literal["api-key", "oauth2", "webhook-receiver", "mtls", "composite"]
"""How an adapter authenticates with its vendor."""

DeliveryMode = Literal["push", "poll", "hybrid"]
"""Whether telemetry arrives push (vendor webhooks), pull (adapter polls), or both."""

Availability = Literal["available", "pre-launch", "coming-soon", "triggered"]
"""Adapter availability for the operator wizard's adapter list."""

ComplianceCategory = Literal["hipaa-friendly", "cjis-friendly", "glba-friendly", "general"]
"""Compliance posture badge for the wizard. Multiple values possible per adapter."""

OperatorRole = Literal["super_admin", "admin", "analyst", "viewer"]
"""Per role taxonomy v2 (super_admin > admin > analyst > viewer)."""

DeepLinkType = Literal["alert", "device", "tenant", "host"]
"""What kind of vendor-portal page the deep-link targets. 'alert' is universally required;
others are optional per vendor capability."""


# ---------------------------------------------------------------------------
# Canonical event
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanonicalEvent:
    """The shape every event takes after extraction.

    Consumed by OCTO ingest. Must be deterministic — same `raw_envelope` input
    produces byte-equivalent `CanonicalEvent` (same `payload_sha256`). Used for
    dedup keyed on `(tenant × source × vendor_event_id × payload_sha256)`.
    """

    vendor_event_id: str
    """Vendor's stable identifier for this event."""

    received_at: str
    """ISO8601 UTC timestamp."""

    severity: Severity

    indicator: str | None
    """The IOC value (IP, domain, URL, hash). None when no IOC in event."""

    indicator_type: IndicatorType | None

    source_host: str | None
    """Hostname or device identifier."""

    summary: str
    """Operator-readable one-line summary."""

    payload: dict[str, Any]
    """Full original event payload for forensic value. Vendor sanitization is
    trusted (per `10-DECISIONS-POST-REVIEW.md` Cluster 3); OCTO does not
    re-sanitize at extraction. Section 7 cross-tenant mitigations apply at
    the bridge boundary, not at extraction."""

    payload_sha256: str
    """For dedup + audit chain."""


# ---------------------------------------------------------------------------
# Credential declaration (drives the operator wizard)
# ---------------------------------------------------------------------------

CredentialKind = Literal[
    "text", "password", "oauth-flow", "cert-upload", "webhook-url-out", "enum"
]


@dataclass(frozen=True)
class CredentialField:
    """One form field the wizard renders to collect creds for this adapter."""

    name: str
    """Env var name (e.g., 'DATTO_API_KEY')."""

    label: str
    """Form label shown to the operator (e.g., 'Datto API Key')."""

    kind: CredentialKind

    description: str
    """Operator-facing help text."""

    required: bool = True

    validator: str | None = None
    """Regex or named validator (e.g., 'url', 'oauth-token-shape')."""

    choices: list[str] | None = None
    """For kind=='enum': the allowed values the wizard renders as a selector
    (e.g., a connection-mode choice). None for non-enum fields."""

    show_when: dict[str, list[str]] | None = None
    """Conditional visibility: maps a sibling field name → the values of that
    field for which THIS field is shown. e.g. a manager-URL field
    {'WAZUH_MODE': ['existing', 'import']} is hidden in 'bundled' mode.
    None = always shown."""

    required_when: dict[str, list[str]] | None = None
    """Like show_when but for conditional requiredness — the field is required
    only when the sibling field holds one of the listed values. None = use
    the static `required` flag."""


# ---------------------------------------------------------------------------
# Tenant mapping declaration (drives the wizard's tenant-list step)
# ---------------------------------------------------------------------------

TenantFetchMethod = Literal["api", "manual", "webhook-discovered"]


@dataclass(frozen=True)
class TenantMappingShape:
    """Tells the wizard how to fetch and present the vendor's tenant list."""

    fetch_method: TenantFetchMethod

    fetch_endpoint: str | None
    """API path if fetch_method=='api'; None otherwise."""

    vendor_tenant_id_field: str
    """Key in vendor's tenant list response (e.g., 'siteUid' for Datto RMM)."""

    vendor_tenant_label_field: str
    """Display name in vendor's response (e.g., 'siteName')."""

    tenant_noun: str = "tenant"
    """What the vendor calls one tenant, singular and lowercase ('site',
    'agent group', 'customer'). The mapping UI words its labels with it."""

    id_help: str | None = None
    """Operator-facing sentence saying WHICH vendor value the tenant id is and
    what it must not be confused with (e.g. a Datto site's UID, not its
    name). Shown next to the mapping field; None = generic wording."""


# ---------------------------------------------------------------------------
# Vendor tenant discovery (OPTIONAL capability — feeds the mapping picker)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VendorTenant:
    """One tenant as the vendor knows it. `id` is exactly the value
    `route_to_tenant()` yields for that tenant's events — the mapping key."""

    id: str
    label: str


@dataclass(frozen=True)
class VendorTenantListing:
    """Result of `list_vendor_tenants()`."""

    tenants: list[VendorTenant]

    truncated: bool = False
    """True when the adapter stopped at its page cap: `tenants` is a prefix,
    so "not in this list" proves nothing about an id."""


VendorTenantFailureKind = Literal["forbidden", "auth", "transport"]
"""forbidden — authenticated, but the vendor refuses the data (fix on their
side); auth — the vendor rejected the credentials; transport — unreachable /
unexpected answer."""


class VendorTenantListError(Exception):
    """`list_vendor_tenants()` could not get the list.

    `message` is OPERATOR-VISIBLE (it is returned by the API verbatim): the
    adapter guarantees it carries no credential, token or raw vendor body —
    static text, status codes and scrubbed, bounded vendor text only.
    """

    def __init__(self, kind: VendorTenantFailureKind, message: str) -> None:
        self.kind = kind
        self.message = message
        super().__init__(message)


# ---------------------------------------------------------------------------
# Smoke test result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SmokeResult:
    """Result of `smoke_test()` — confirms the adapter can reach its vendor."""

    ok: bool

    message: str
    """Operator-facing success or failure message."""

    sample_payload: dict[str, Any] | None = None
    """If `ok`, one real payload from the vendor. Used by the wizard to show
    the operator what events from this adapter look like."""


# ---------------------------------------------------------------------------
# Guided onboarding (drives the Integrations sidebar's step-by-step)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OnboardingStep:
    """One step in an adapter's guided setup, rendered in the sidebar wizard
    beyond the bare credential form."""

    title: str
    body: str
    copy_value: str | None = None
    """A value the UI shows with a copy button (e.g. the webhook URL)."""

    code_sample: str | None = None
    """A monospaced block to display (e.g. a JSON payload template)."""


@dataclass(frozen=True)
class Onboarding:
    """Optional guided-setup payload an adapter returns for the sidebar.

    `push`/`hybrid` adapters use this to surface the inbound webhook URL plus
    sample payload templates the operator pastes into the vendor. Returning
    None (the default) means the wizard shows only the credential form.
    """

    summary: str
    webhook_url: str | None
    steps: list[OnboardingStep]


# ---------------------------------------------------------------------------
# Widget definition reference
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WidgetDefinitionRef:
    """Forward-reference to a WidgetDefinition.

    The full WidgetDefinition lives in `shared_widget_contract` per ADR-006.
    Adapters declare widget definitions via the widget contract package; this
    reference type exists in the adapter contract because adapters return
    `WidgetDefinition | list[WidgetDefinition] | None` from `widget_definition()`.

    Resolved at runtime by the framework's widget-discovery scan.
    """

    widget_id: str
    """Globally unique widget identifier (e.g., 'datto-rmm.alert-feed')."""


# ---------------------------------------------------------------------------
# Rate-limit hints
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RateLimitHints:
    """Vendor's known rate limits. Framework uses these for retry/backoff tuning."""

    requests_per_second: float | None = None
    requests_per_day: int | None = None
    burst_capacity: int | None = None
    retry_after_header: str | None = None
    """Header name where the vendor reports retry-after on 429s
    (e.g., 'Retry-After', 'X-RateLimit-Reset')."""


# ---------------------------------------------------------------------------
# Lifecycle health metric
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HealthStatus:
    """Returned from adapter `health()` calls."""

    alive: bool
    last_event_at: str | None
    """ISO8601 timestamp of most recently processed event. None if no events yet."""

    lag_seconds: float
    """Wall-clock seconds behind the most recent vendor-side event we know about."""

    errors_last_hour: int
    detail: dict[str, Any] = field(default_factory=dict)
    """Adapter-specific health detail (e.g., 'tenant_count', 'open_connections')."""
