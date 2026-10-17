"""NextDNS source adapter.

Per MAPPED NextDNS profile, asks the cheap question first (analytics: were
there SECURITY blocks in this window?) and only then reads those blocked
lookups — the full DNS log never comes into Athena. Signals: security
blocks (coalesced per device / domain / reason / hour), and a site's DNS
filtering lapsing / resuming. Hourly per-profile counts go to the
telemetry tier. One API key; every call through one shared rate limiter.
"""

from apps.octo.adapters.nextdns.adapter import NextDNSSourceAdapter

NextDNSSourceAdapter.__module__ = "apps.octo.adapters.nextdns"

__all__ = ["NextDNSSourceAdapter"]
