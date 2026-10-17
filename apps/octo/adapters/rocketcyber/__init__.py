"""RocketCyber source adapter.

Pulls Managed SOC incidents from RocketCyber's read-only v3 API for the MSP
(provider) account a single API key belongs to. Polled — RocketCyber has no
webhooks: every open incident, plus a rolling createdAt window of resolved /
suppressed ones, with change detection, so an incident's later resolution /
suppression arrives as its own event however long it stayed open.

Tenant model: the provider account contains Customers; every incident names
its customer (`accountId`), which maps to one OCTO client via the tenant
mapping step (customers are discoverable for the picker; unknown ones are
auto-created or held in quarantine by the platform — a name only ever
suggests).
"""

from apps.octo.adapters.rocketcyber.adapter import RocketCyberSourceAdapter

RocketCyberSourceAdapter.__module__ = "apps.octo.adapters.rocketcyber"

__all__ = ["RocketCyberSourceAdapter"]
