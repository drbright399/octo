"""UniFi source adapter — the whole UniFi fleet through the cloud connector.

One Site Manager API key (api.ui.com) reaches every console of the account
through UniFi's connector proxy. Per MAPPED site (keyed "<hostId>/<siteId>":
site ids collide across consoles): the system log's security, audit and
availability events become signals (OCSF-mapped, coalesced per hour), firewall
blocks and client connects become hourly roll-ups, and the fleet report,
client snapshots, lease boundaries and networks feed entity resolution.
Every call goes through ONE rate limiter; every answer is stripped of secrets
(`x_*`, `utm_token`, anything pass / psk / secret / key) at the boundary.

Replaces the retired local-controller adapter (same vendor slug); see
adapter.py for the migration path and README.md for the whole picture.
"""

from apps.octo.adapters.unifi.adapter import UniFiSourceAdapter

UniFiSourceAdapter.__module__ = "apps.octo.adapters.unifi"

__all__ = ["UniFiSourceAdapter"]
