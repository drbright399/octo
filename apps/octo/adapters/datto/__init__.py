"""Datto RMM source adapter.

Second concrete adapter under the Phase 2 framework. Pulls alerts from
the Datto RMM API for a configured MSP account, maps each alert
("Critical" / "High" / etc. via `alertPriority`) onto the framework's
`CanonicalEvent` contract, routes per-Site to the corresponding OCTO
client slug.

Auth model: API key + API secret key pair (Datto's API-token scheme).
Both fields are wizard-collected; nothing is hard-coded.

Tenant model: Datto's MSP account contains Sites; each Site maps to
one OCTO client slug via the wizard's tenant_mapping step.

Datacenter region: Datto operates regional clusters (US, EU, AU, etc.)
each with a different API base URL. Operator picks the one matching
their account during onboarding.
"""

from apps.octo.adapters.datto.adapter import DattoSourceAdapter

# Re-export with module rewrite so the framework's discovery walker
# finds the class (same trick as wazuh — see that adapter for context).
DattoSourceAdapter.__module__ = "apps.octo.adapters.datto"

__all__ = ["DattoSourceAdapter"]
