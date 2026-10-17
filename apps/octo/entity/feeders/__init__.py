"""Feed consumers: what each adapter hands to entity resolution, per MAPPED
vendor scope, turned into this tenant's lookups (`register_all` wires them at
start-up; tests register them explicitly)."""
from __future__ import annotations


def register_all() -> None:
    from apps.octo.adapters.datto import feed as datto_feed
    from apps.octo.adapters.nextdns import feed as nextdns_feed
    from apps.octo.adapters.unifi import feed as unifi_feed
    from apps.octo.entity.feeders.datto import DattoInventoryFeeder
    from apps.octo.entity.feeders.nextdns import NextDNSDeviceFeeder
    from apps.octo.entity.feeders.unifi import UniFiEntityFeeder

    unifi_feed.register(UniFiEntityFeeder())
    datto_feed.register(DattoInventoryFeeder())
    nextdns_feed.register(NextDNSDeviceFeeder())


def unregister_all() -> None:
    from apps.octo.adapters.datto import feed as datto_feed
    from apps.octo.adapters.nextdns import feed as nextdns_feed
    from apps.octo.adapters.unifi import feed as unifi_feed

    unifi_feed.register(None)
    datto_feed.register(None)
    nextdns_feed.register(None)
