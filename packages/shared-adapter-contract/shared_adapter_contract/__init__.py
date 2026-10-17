"""Source-adapter contract for the Athena/OCTO framework.

Per design note ADR-005 (kept outside this repository; index:
`docs/adrs/README.md`), this package defines:
- The abstract `SourceAdapter` Protocol every adapter implements
- The `CanonicalEvent` shape every adapter produces
- Onboarding-side declarations (`CredentialField`, `TenantMappingShape`, `SmokeResult`)
- The widget-side declaration (`WidgetDefinition`) — full widget contract in `shared_widget_contract`
- A `BaseSourceAdapter` ABC with sensible defaults for adapter authors

Stable contract version: 1.0
"""

from shared_adapter_contract.base import BaseSourceAdapter
from shared_adapter_contract.protocol import SourceAdapter
from shared_adapter_contract.types import (
    CanonicalEvent,
    CredentialField,
    DeepLinkType,
    Severity,
    SmokeResult,
    TenantMappingShape,
    VendorTenant,
    VendorTenantListError,
    VendorTenantListing,
    WidgetDefinitionRef,
)

CONTRACT_VERSION = "1.0"

__all__ = [
    "CONTRACT_VERSION",
    "BaseSourceAdapter",
    "CanonicalEvent",
    "CredentialField",
    "DeepLinkType",
    "Severity",
    "SmokeResult",
    "SourceAdapter",
    "TenantMappingShape",
    "VendorTenant",
    "VendorTenantListError",
    "VendorTenantListing",
    "WidgetDefinitionRef",
]
