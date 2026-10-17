"""Shared world for the UniFi tests: a real data root (registry, tenants,
credential store), a persisted adapter instance, the real adapter / client /
limiter / poller / sink — and only the socket fake, on ONE fake clock (no
real sleeps, no network)."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.adapters.unifi import UniFiSourceAdapter
from apps.octo.adapters.unifi import feed
from apps.octo.adapters.unifi import limiter as lim
from apps.octo.adapters.unifi.poller import UniFiPoller
from apps.octo.adapters.unifi.tests.fake_unifi import (
    CREDS,
    FakeClock,
    FakeUniFiTransport,
    client_factory,
    fake_limiter,
    real_client,
    standard_fleet,
)
from apps.octo.client_provisioning import create_client
from apps.octo.ingest import SqliteIngestSink, telemetry
from apps.octo.instances import (
    create_instance,
    freshness,
    ignored_tenants,
    tenant_map,
    vendor_contact,
    vendor_tenants,
)
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@dataclass
class World:
    root: Path
    clock: FakeClock
    transport: FakeUniFiTransport
    limiter: Any
    record: Any
    consumer: feed.RecordingConsumer

    def poller(self, **kwargs: Any) -> UniFiPoller:
        return UniFiPoller(
            adapter=UniFiSourceAdapter(client_factory=client_factory(self.transport)),
            client=real_client(self.transport, limiter=self.limiter),
            sink=SqliteIngestSink(publish_to_stream=False),
            instance_id=self.record.id,
            now=self.clock.now,
            consumer=kwargs.pop("consumer", self.consumer),
            **kwargs,
        )

    def map_sites(self, sites: dict[str, str], *, ignore: tuple[str, ...] = ()) -> None:
        tenant_map.set_mappings(self.record.id, [
            TenantMapping(scope, slug, None, "manual") for scope, slug in sites.items()])
        ignored_tenants.set_ignored(self.record.id, [(s, None) for s in ignore])

    def events(self, slug: str, event_type: Optional[str] = None) -> list[sqlite3.Row]:
        db = paths.client_dir(slug) / "events.db"
        if not db.exists():
            return []
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        try:
            if event_type:
                return conn.execute("SELECT * FROM events WHERE event_type = ? ORDER BY id",
                                    (event_type,)).fetchall()
            return conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        finally:
            conn.close()

    def payloads(self, slug: str, event_type: Optional[str] = None) -> list[dict]:
        return [json.loads(r["payload"]) for r in self.events(slug, event_type)]

    def telemetry_rows(self, slug: str, table: str) -> list[sqlite3.Row]:
        db = paths.client_dir(slug) / "telemetry.db"
        if not db.exists():
            return []
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()

    def instance_row(self) -> sqlite3.Row:
        conn = sqlite3.connect(paths.registry_db_path())
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute("SELECT * FROM adapter_instances WHERE id = ?",
                                (self.record.id,)).fetchone()
        finally:
            conn.close()

    def run_for(self, poller: UniFiPoller, seconds: float) -> int:
        """Drive the poller's own loop on the fake clock for `seconds`."""
        end = self.clock.monotonic() + seconds
        cycles = 0
        while self.clock.monotonic() < end:
            delay = poller.cycle_with_reporting()
            cycles += 1
            self.clock.advance(max(1.0, min(delay, end - self.clock.monotonic())))
        return cycles


@pytest.fixture
def world(bedrock_root):  # noqa: F811
    lim.reset_limiters()
    telemetry.reset_schema_cache()
    vendor_contact.reset()
    vendor_tenants.reset()
    freshness.reset()
    feed.register(None)
    clock = FakeClock()
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)
    limiter = fake_limiter(clock)
    record = create_instance(
        vendor_slug="unifi", display_name="UniFi Network",
        credentials_dict=dict(CREDS), instance_config={},
    )
    create_client("acme-corp", "Acme Corp")
    create_client("example-bakery", "Example Bakery")
    yield World(bedrock_root, clock, transport, limiter, record, feed.RecordingConsumer())
    lim.reset_limiters()
    vendor_contact.reset()
    vendor_tenants.reset()
    freshness.reset()
    feed.register(None)
