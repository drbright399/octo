"""The UniFi side end to end: the REAL UniFi poller / client / limiter against
the fake cloud + connector (only the socket is fake), feeding the REAL entity
consumer — sites, egress with its NAT kind, leases, the system-log watermark,
subnets; I11 (two consoles with the same site id stay apart); and the
MAC-anomaly rule's finding coming back as a stored `unifi.mac_anomaly`
signal (OCSF at the adapter boundary), exactly once."""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.adapters.unifi import limiter as lim
from apps.octo.adapters.unifi.poller import UniFiPoller
from apps.octo.adapters.unifi.tests.fake_unifi import (
    CREDS,
    HOST_A,
    HOST_B,
    SCOPE_A,
    SCOPE_B,
    FakeClock,
    FakeUniFiTransport,
    client_event,
    client_factory,
    fake_limiter,
    mac,
    real_client,
    standard_fleet,
)
from apps.octo.adapters.unifi import UniFiSourceAdapter
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch, tokens
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.unifi import UniFiEntityFeeder
from apps.octo.entity.tests.conftest import lan
from apps.octo.ingest import SqliteIngestSink, telemetry
from apps.octo.instances import create_instance, freshness, tenant_map, vendor_contact, vendor_tenants
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

A, B = "acme-corp", "example-bakery"


@pytest.fixture
def uw(bedrock_root, monkeypatch):  # noqa: F811
    from apps.octo.entity.tests.conftest import NEXTDNS_RESOLVERS

    monkeypatch.setenv("OCTO_NEXTDNS_RESOLVER_NETS", NEXTDNS_RESOLVERS)
    lim.reset_limiters()
    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()
    tokens.reset_cache()
    switch.reset()
    vendor_contact.reset()
    vendor_tenants.reset()
    freshness.reset()
    clock = FakeClock()
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)
    transport.console(HOST_A).wan_ipv4 = "203.0.113.129"        # the WAN holds the public IP
    # Behind carrier NAT: the WAN holds a 100.64/10 address (made up, in the
    # /23 Tailscale never assigns, so never a real node).
    # scan-sensitive: allow[ip-tailnet] made-up carrier-NAT address: 100.64/10 decides "cgnat"
    transport.console(HOST_B).wan_ipv4 = "100.115.92.7"
    limiter = fake_limiter(clock)
    rec = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                          credentials_dict=dict(CREDS), instance_config={})
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    tenant_map.set_mappings(rec.id, [TenantMapping(SCOPE_A, A, "Acme", "manual"),
                                     TenantMapping(SCOPE_B, B, "Bakery", "manual")])
    switch.set_mode(A, "on")
    switch.set_mode(B, "on")
    feeder = UniFiEntityFeeder(now=clock.now)
    poller = UniFiPoller(adapter=UniFiSourceAdapter(client_factory=client_factory(transport)),
                         client=real_client(transport, limiter=limiter),
                         sink=SqliteIngestSink(publish_to_stream=False), instance_id=rec.id,
                         now=clock.now, consumer=feeder)
    yield clock, transport, poller
    lim.reset_limiters()
    switch.reset()
    vendor_contact.reset()
    vendor_tenants.reset()
    freshness.reset()


def _rows(slug, sql):
    with TenantDB.for_tenant(slug).connect() as conn:
        return [dict(r) for r in conn.execute(sql)]


def _events(slug, event_type):
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return [json.loads(r[0]) for r in conn.execute(
            "SELECT payload FROM events WHERE event_type = ? ORDER BY id", (event_type,))]
    finally:
        conn.close()


def _clients(n_ips):
    return [{"id": f"c{n}", "name": f"PC-{n}", "macAddress": mac(n).upper(), "ipAddress": ip,
             "type": "WIRED", "connectedAt": "2026-10-01T09:00:00Z", "uplinkDeviceId": "sw-1",
             "access": {"type": "DEFAULT"}} for n, ip in n_ips]


def test_the_real_poller_feeds_sites_egress_leases_and_watermarks(uw):
    clock, transport, poller = uw
    transport.site(HOST_A).clients = _clients([(11, lan(11)), (12, lan(12))])
    transport.site(HOST_B).clients = _clients([(11, lan(11))])   # SAME MAC + IP, other client
    poller.run_cycle()
    eg_a = _rows(A, "SELECT * FROM lk_site_egress")
    eg_b = _rows(B, "SELECT * FROM lk_site_egress")
    assert [(e["addr"], e["nat_kind"]) for e in eg_a] == [("203.0.113.129", "direct")]
    assert [(e["addr"], e["nat_kind"]) for e in eg_b] == [("198.51.100.20", "cgnat")]
    assert len(_rows(A, "SELECT * FROM lk_ip_lease")) == 2
    assert len(_rows(B, "SELECT * FROM lk_ip_lease")) == 1
    # I11: the same site id on two consoles = two sites in two files; the
    # same MAC reads as different tokens in each.
    tok_a = {r["mac_tok"] for r in _rows(A, f"SELECT mac_tok FROM lk_ip_lease WHERE mac = '{mac(11)}'")}
    tok_b = {r["mac_tok"] for r in _rows(B, "SELECT mac_tok FROM lk_ip_lease")}
    assert tok_a and tok_b and not tok_a & tok_b
    assert {r["source"] for r in _rows(A, "SELECT source FROM lk_watermark")} >= \
        {"unifi.sites", "unifi.clients", "unifi.syslog", "unifi.networks"}
    subnets = {r["name"]: r["dns_path"] for r in _rows(A, "SELECT * FROM lk_site_subnet")}
    assert subnets == {"Office": "gateway", "Guest": "other"}


def test_a_mac_anomaly_becomes_one_stored_unifi_signal(uw):
    clock, transport, poller = uw
    transport.site(HOST_A).clients = _clients([(11, lan(11))])
    poller.run_cycle()
    # MAC 11 joins AS ANOTHER ADDRESS while UniFi keeps the client connected
    # since 09:00 — two machines on one MAC.
    clock.advance(120)
    transport.site(HOST_A).log.append(client_event(clock.now(), n=11, ip=lan(99)))
    clock.advance(300)
    poller.run_cycle()
    clock.advance(300)
    poller.run_cycle()
    alerts = _events(A, "unifi.mac_anomaly")
    assert len(alerts) == 1
    a = alerts[0]
    assert a["anomaly"]["kind"] == "two_ips" and a["anomaly"]["mac"] == mac(11)
    assert sorted(a["anomaly"]["ips"]) == [lan(11), lan(99)]
    assert (a["ocsf"]["class_uid"], a["ocsf"]["activity_id"]) == (2004, 1)
    assert a["ocsf"]["finding_info"]["analytic"]["uid"] == "athena.entity.M1"
    assert a["signal"]["level"] == "medium"
    assert all(r["signaled"] == 1 for r in _rows(A, "SELECT * FROM lk_mac_anomaly"))
    # A TIME-BOUNDED finding — never a flag on the whole lease row.
    (anomaly,) = _rows(A, "SELECT * FROM lk_mac_anomaly")
    assert anomaly["mac"] == mac(11) and anomaly["from_ts"] <= anomaly["to_ts"]
    assert all(r["conflict"] == 0 for r in _rows(A, "SELECT * FROM lk_ip_lease WHERE mac = "
                                                     f"'{mac(11)}'"))
    for _ in range(2):
        clock.advance(300)
        poller.run_cycle()
    assert len(_events(A, "unifi.mac_anomaly")) == 1                  # once
    assert _events(B, "unifi.mac_anomaly") == []


def test_networks_are_read_once_the_tenant_takes_them_not_a_day_later(uw):
    """Review round 2: a tenant switched 'off' gets no networks read at all;
    switched to 'shadow' it gets them on the next cycles — not a day later —
    and a guest lease stored before them is marked guest."""
    clock, transport, poller = uw
    switch.set_mode(A, "off")
    transport.site(HOST_A).clients = [{**c, "ipAddress": lan(21, 30), "type": "WIRELESS"}
                                      for c in _clients([(21, lan(21, 30))])]
    poller.run_cycle()
    assert transport.calls_to(f"{HOST_A}/proxy/network/api/s/default/rest/networkconf") == []
    assert len(transport.calls_to(f"{HOST_B}/proxy/network/api/s/default/rest/networkconf")) == 1
    switch.set_mode(A, "shadow")
    for _ in range(4):
        clock.advance(5 * 60)
        poller.run_cycle()
    assert len(transport.calls_to(f"{HOST_A}/proxy/network/api/s/default/rest/networkconf")) == 1
    assert {r["name"] for r in _rows(A, "SELECT * FROM lk_site_subnet")} == {"Office", "Guest"}
    leases = _rows(A, "SELECT * FROM lk_ip_lease WHERE valid_to IS NULL")
    assert leases and all(r["is_guest"] == 1 and r["net_id"] == "net-2" for r in leases)


def test_a_dual_stack_consoles_ipv6_egress_reaches_the_tenants_lookups(uw):
    """Review round 3, item 3, end to end: /v1/hosts wans[].ipv6 and the
    delegated prefix → the fleet report → egress intervals of the tenant."""
    clock, transport, poller = uw
    transport.console(HOST_A).wan_ipv6 = "2001:db8:42::1"
    transport.console(HOST_A).wan_pd = "2001:db8:4200::/56"
    poller.run_cycle()
    rows = _rows(A, "SELECT addr, prefix_len, wan, nat_kind FROM lk_site_egress ORDER BY id")
    assert [(r["addr"], r["prefix_len"], r["wan"], r["nat_kind"]) for r in rows] == [
        ("203.0.113.129", 32, "WAN", "direct"), ("2001:db8:42::1", 128, "WAN/v6", "direct"),
        ("2001:db8:4200::", 56, "WAN/pd", "direct")]
    assert [r["addr"] for r in _rows(B, "SELECT addr FROM lk_site_egress")] == ["198.51.100.20"]
