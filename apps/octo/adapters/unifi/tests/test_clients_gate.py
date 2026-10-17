"""Review round 3, open problem 7: UniFi client lists were fetched every 5
minutes for clients whose entity switch is OFF (480 calls an hour for 40
sites in the OFF fleet run — half the UniFi budget — all thrown away),
though "off" is documented as "no vendor calls for it". The poller now asks
the feed (`wants`) first; the security reads (system log) are not gated."""
from __future__ import annotations

from apps.octo.adapters.unifi.tests.fake_unifi import SCOPE_A

A = "acme-corp"



class _Picky:
    def __init__(self, wanted: bool) -> None:
        self.wanted = wanted
        self.snapshots = 0

    def wants(self, slug, scope, _data=None):  # noqa: ANN001
        return self.wanted

    def on_client_snapshot(self, slug, scope, snapshot):  # noqa: ANN001
        self.snapshots += 1

    def on_networks(self, slug, scope, networks):  # noqa: ANN001
        return True


def test_the_client_list_is_read_only_for_a_tenant_that_takes_it(world):
    world.map_sites({SCOPE_A: A})
    off = _Picky(False)
    p = world.poller(consumer=off)
    world.run_for(p, 20 * 60)
    assert world.transport.calls_to("/clients") == []
    assert world.transport.calls_to("integration/v1/sites") == []
    assert world.transport.calls_to("system-log")                # security reads go on
    off.wanted = True
    world.run_for(p, 6 * 60)
    assert world.transport.calls_to("/clients") and off.snapshots >= 1


def test_the_real_entity_feeder_takes_clients_only_for_a_switched_on_tenant(world):
    from apps.octo.entity import switch
    from apps.octo.entity.feeders.unifi import UniFiEntityFeeder

    world.map_sites({SCOPE_A: A})
    switch.reset()
    p = world.poller(consumer=UniFiEntityFeeder(now=world.clock.now))
    world.run_for(p, 11 * 60)
    assert world.transport.calls_to("/clients") == []            # 'off' (the default)
    switch.set_mode(A, "shadow")
    world.run_for(p, 6 * 60)
    assert world.transport.calls_to("/clients")
    switch.reset()
