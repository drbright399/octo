"""Shared world for the entity-resolution tests: a real data root (registry,
tenants, credential store), real adapter instances and tenant maps, the real
feed consumers, resolver and worker — on an injected clock. Vendor traffic
comes through the adapters' fake transports (UniFi, NextDNS, Datto); nothing
touches the network."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch, tokens
from apps.octo.entity.db import TenantDB
from apps.octo.entity.feeders.datto import DattoInventoryFeeder
from apps.octo.entity.feeders.nextdns import NextDNSDeviceFeeder
from apps.octo.entity.feeders.unifi import UniFiEntityFeeder
from apps.octo.ingest import telemetry
from apps.octo.instances import create_instance, freshness, tenant_map
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

A, B = "acme-corp", "example-bakery"
HOST_A = "F1X7A0000000000000000000000000000000000000000000000000A001:100000001"
HOST_B = "F1X7B0000000000000000000000000000000000000000000000000B002:100000002"
SITE = "f1x7517e0000000000000001"           # the SAME site id on every console (V11)
SCOPE_A = f"{HOST_A}/{SITE}"
SCOPE_B = f"{HOST_B}/{SITE}"
EGRESS_A = "203.0.113.129"
PROFILE_A = "abc123"
T0 = datetime(2026, 10, 1, 14, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def mac(n: int) -> str:
    return f"00:00:5e:00:53:{n:02x}"


def lan(n: int, net: int = 20) -> str:
    """Address .n of the fixture site's LAN (`net` 20 = 'Office', 30 =
    'Guest': the subnets `office_and_guest` hands out). RFC 1918 on purpose,
    never a TEST-NET address: entity resolution reads an address's class
    (`normalize.is_lan` / `is_public`) and counts a documentation address as
    PUBLIC (an egress), so a LAN device's address must be private."""
    return f"10.{net}.0.{n}"


class Clock:
    def __init__(self, start: datetime = T0) -> None:
        self.t = start

    def now(self) -> datetime:
        return self.t

    def set(self, when: datetime) -> None:
        self.t = when

    def advance(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)


@dataclass
class World:
    root: Path
    clock: Clock
    unifi_id: int
    nextdns_id: int
    datto_id: int
    unifi: UniFiEntityFeeder
    nextdns: NextDNSDeviceFeeder
    datto: DattoInventoryFeeder
    extra: dict[str, Any] = field(default_factory=dict)

    # ----- registry -----

    def set_mode(self, slug: str, mode: str) -> None:
        """As PUT /mode does: the switch, then (off → on) the sweep's start."""
        from apps.octo.entity import worker

        before = switch.set_mode(slug, mode)
        worker.switched(slug, before, mode, now=self.clock.now())

    def map(self, instance_id: int, mappings: dict[str, str], source: str = "manual") -> None:
        tenant_map.set_mappings(instance_id, [TenantMapping(k, v, f"label {k}", source)
                                              for k, v in mappings.items()])

    # ----- entities.db -----

    def db(self, slug: str = A) -> TenantDB:
        return TenantDB.for_tenant(slug)

    def rows(self, sql: str, args: tuple = (), slug: str = A) -> list[sqlite3.Row]:
        with self.db(slug).connect() as conn:
            return conn.execute(sql, args).fetchall()

    def one(self, sql: str, args: tuple = (), slug: str = A) -> Optional[sqlite3.Row]:
        rows = self.rows(sql, args, slug)
        return rows[0] if rows else None

    # ----- feeds (the consumer contract the pollers call) -----

    def site_report(self, at: datetime, *, slug: str = A, scope: str = SCOPE_A,
                    wans: Optional[list[dict[str, Any]]] = None, gateway_online: bool = True,
                    host_connected: bool = True, name: str = "Site A") -> None:
        self.unifi.on_site_report(slug, scope, {
            "scope": scope, "polled_at": iso(at), "name": name, "timezone": "America/Chicago",
            "location": {"lat": 39.0, "long": -89.0, "text": "100 Example St"},
            "wans": wans if wans is not None else [
                {"wan": "WAN", "external_ip": EGRESS_A, "nat_kind": "direct", "asn": 64500,
                 "isp": "Example ISP", "shared_external": False}],
            "gateway_online": gateway_online, "host_connected": host_connected,
            "report_fresh": host_connected})

    def snapshot(self, at: datetime, clients: list[dict[str, Any]], *, slug: str = A,
                 scope: str = SCOPE_A, gateway_online: bool = True) -> Any:
        return self.unifi.on_client_snapshot(slug, scope, {
            "scope": scope, "polled_at": iso(at), "complete": True,
            "gateway_online": gateway_online, "clients": clients})

    def networks(self, nets: Optional[list[dict[str, Any]]] = None, *, slug: str = A,
                 scope: str = SCOPE_A) -> None:
        self.unifi.on_networks(slug, scope, nets if nets is not None else office_and_guest())

    def log(self, events: list[dict[str, Any]], *, slug: str = A, scope: str = SCOPE_A) -> Any:
        return self.unifi.on_log_events(slug, scope, events)

    def log_progress(self, at: datetime, *, slug: str = A, scope: str = SCOPE_A) -> None:
        self.unifi.on_log_progress(slug, scope, {"scanned_to": iso(at)})

    def poll(self, at: datetime, clients: list[dict[str, Any]], *, slug: str = A,
             scope: str = SCOPE_A) -> Any:
        """One UniFi cycle's worth of feeds at `at`: fleet report, system log
        read whole up to `at`, client snapshot."""
        self.site_report(at, slug=slug, scope=scope)
        self.log_progress(at, slug=slug, scope=scope)
        return self.snapshot(at, clients, slug=slug, scope=scope)


def client(n: int, ip: str, *, name: Optional[str] = None, connected: Optional[datetime] = None,
           kind: str = "WIRED", mac_value: Optional[str] = None) -> dict[str, Any]:
    out = {"id": f"cl-{n}", "name": name or f"PC-{n}", "mac": mac_value or mac(n), "ip": ip,
           "type": kind}
    if connected is not None:
        out["connected_at"] = iso(connected)
    return out


def office_and_guest() -> list[dict[str, Any]]:
    """Office VLAN: DHCP hands out the gateway (→ NextDNS via the gateway's
    DNS forwarding); guest VLAN: DHCP hands out the ISP's resolver (bypasses
    NextDNS)."""
    return [
        {"_id": "net-1", "name": "Office", "purpose": "corporate", "ip_subnet": f"{lan(1)}/24",
         "dhcpd_enabled": True, "dhcpd_dns_enabled": False},
        {"_id": "net-2", "name": "Guest", "purpose": "guest", "ip_subnet": f"{lan(1, 30)}/24",
         "vlan": 30, "dhcpd_enabled": True, "dhcpd_dns_enabled": True,
         "dhcpd_dns_1": "198.51.100.53"},
    ]


def join_event(at: datetime, n: int, ip: str, *, event: str = "CLIENT_CONNECTED_WIRED",
               name: Optional[str] = None, mac_value: Optional[str] = None) -> dict[str, Any]:
    ms = int(at.timestamp() * 1000)
    return {"id": f"j-{event}-{n}-{ms}", "ts_ms": ms, "time": iso(at), "event": event,
            "client": {"mac": mac_value or mac(n), "ip": ip, "name": name or f"PC-{n}",
                       "hostname": (name or f"PC-{n}").lower()}}


def store_event(slug: str, source: str, event_type: str, payload: dict[str, Any],
                received_at: str) -> int:
    """Store one event through the REAL ingest sink, as an adapter would."""
    from shared_adapter_contract.types import CanonicalEvent

    from apps.octo.ingest import SqliteIngestSink
    from apps.octo.ingest.presentation import TypedCanonicalEvent

    sha = __import__("hashlib").sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    ev = TypedCanonicalEvent(vendor_event_id=str(payload.get("vendor_event_id") or sha[:32]),
                             received_at=received_at, severity="high", indicator=None,
                             indicator_type=None, source_host=None, summary="test",
                             payload=payload, payload_sha256=sha, event_type=event_type)
    assert isinstance(ev, CanonicalEvent)
    out = SqliteIngestSink(publish_to_stream=False).ingest(slug, source, ev)
    return int(out.event_id)


def nextdns_block(at: datetime, *, client_ip: str = EGRESS_A, device: Optional[dict] = None,
                  client_kind: str = "dnscrypt", domain: str = "x.bad.example",
                  reason: str = "threat-intelligence-feeds", profile: str = PROFILE_A,
                  vid: Optional[str] = None) -> dict[str, Any]:
    return {
        "vendor_event_id": vid or f"line-{int(at.timestamp() * 1000)}-{domain}",
        "kind": "security_block", "profile_id": profile, "profile_name": "Site A office",
        "log": {"timestamp": iso(at), "domain": domain, "root": ".".join(domain.split(".")[-2:]),
                "clientIp": client_ip, "client": client_kind, "device": device,
                "status": "blocked", "reasons": [{"id": reason, "name": "Threat Intelligence"}]},
        "signal": {"level": "high", "reason_id": reason, "reason_label": "a threat-intelligence domain",
                   "bucket_hour": iso(at)[:13] + ":00:00Z", "bucket_span": "hour",
                   "cross_domain": False},
    }


# A stand-in for NextDNS's resolver ranges (bundle configuration): a
# documentation range, never a real one.
NEXTDNS_RESOLVERS = "192.0.2.0/24"


@pytest.fixture
def world(bedrock_root, monkeypatch):  # noqa: F811
    monkeypatch.setenv("OCTO_NEXTDNS_RESOLVER_NETS", NEXTDNS_RESOLVERS)
    from apps.octo.adapters.datto.tests.fake_datto import CREDS as DATTO_CREDS
    from apps.octo.adapters.nextdns.tests.fake_nextdns import CREDS as NEXTDNS_CREDS
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS as UNIFI_CREDS

    telemetry.reset_schema_cache()
    entity_db.reset_schema_cache()
    tokens.reset_cache()
    switch.reset()
    freshness.reset()
    clock = Clock()
    unifi = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                            credentials_dict=dict(UNIFI_CREDS), instance_config={})
    nextdns = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                              credentials_dict=dict(NEXTDNS_CREDS), instance_config={})
    datto = create_instance(vendor_slug="datto", display_name="Datto RMM",
                            credentials_dict=dict(DATTO_CREDS), instance_config={})
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    w = World(bedrock_root, clock, unifi.id, nextdns.id, datto.id,
              UniFiEntityFeeder(now=clock.now), NextDNSDeviceFeeder(now=clock.now),
              DattoInventoryFeeder())
    w.map(unifi.id, {SCOPE_A: A})
    w.map(nextdns.id, {PROFILE_A: A})
    w.set_mode(A, "on")
    yield w
    switch.reset()
    tokens.reset_cache()
    freshness.reset()
