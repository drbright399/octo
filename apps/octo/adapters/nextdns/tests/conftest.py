"""Shared world for the NextDNS poller tests: a real data root (registry,
tenants, credential store), a persisted adapter instance, the real adapter /
client / limiter / poller / sink — and only the socket fake, on ONE fake
clock (no real sleeps)."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.adapters.nextdns import NextDNSSourceAdapter
from apps.octo.adapters.nextdns import limiter as lim
from apps.octo.adapters.nextdns.poller import NextDNSPoller
from apps.octo.adapters.nextdns.tests.fake_nextdns import (
    CREDS,
    FakeClock,
    FakeNextDNSTransport,
    fake_limiter,
    hour_of,
    real_client,
)
from apps.octo.client_provisioning import create_client
from apps.octo.ingest import SqliteIngestSink, telemetry
from apps.octo.instances import create_instance, freshness, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@dataclass
class World:
    root: Path
    clock: FakeClock
    transport: FakeNextDNSTransport
    limiter: Any
    record: Any

    def poller(self, **kwargs: Any) -> NextDNSPoller:
        return NextDNSPoller(
            adapter=NextDNSSourceAdapter(),
            client=real_client(self.transport, limiter=self.limiter),
            sink=SqliteIngestSink(publish_to_stream=False),
            instance_id=self.record.id,
            now=self.clock.now,
            **kwargs,
        )

    def map(self, **profiles: str) -> None:
        """map(abc123="acme-corp", …) — replaces the instance's mappings."""
        tenant_map.set_mappings(self.record.id, [
            TenantMapping(pid, slug, None, "manual") for pid, slug in profiles.items()
        ])

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

    def notes(self, slug: str, event_id: int) -> list[sqlite3.Row]:
        conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "SELECT * FROM agent_notes WHERE ref_kind = 'event' AND ref_id = ? ORDER BY id",
                (event_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        finally:
            conn.close()

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

    def seed_baseline(self, pid: str, slug: str, *, days: int = 21,
                      until: Optional[datetime] = None) -> int:
        """The hourly rows the poller would have rolled up for `pid` over the
        `days` days before `until` (default: now) — what the fake's
        analytics say for each of those hours, written into the tenant's
        real telemetry store in one transaction. A site's hour-of-week
        baseline without simulating three weeks. Returns the rows written."""
        from apps.octo.adapters.nextdns import store

        end = hour_of(until or self.clock.now())
        rows = []
        h = end - timedelta(days=days)
        while h < end:
            c = self.transport.hour_queries(pid, h)
            rows.append((h.strftime("%Y-%m-%dT%H:00:00Z"), pid, sum(c.values()),
                         c.get("default", 0), c.get("blocked", 0), c.get("allowed", 0),
                         0, 0, 0, c.get("blocked", 0), "{}", "seed", "seed"))
            h += timedelta(hours=1)
        conn = sqlite3.connect(store._db(slug))
        try:
            with conn:
                conn.executemany(
                    "INSERT OR REPLACE INTO nextdns_hourly (hour, profile_id, queries, "
                    " default_queries, blocked, allowed, signal_high, signal_medium, "
                    " signal_low, policy_blocked, signal_reasons, fetched_at, last_arrival) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        finally:
            conn.close()
        return len(rows)

    def run_for(self, poller: NextDNSPoller, seconds: float) -> int:
        """Drive the poller's own loop on the fake clock for `seconds`:
        one cycle, then the wait it asked for. Returns the cycles run."""
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
    freshness.reset()
    clock = FakeClock()
    transport = FakeNextDNSTransport(clock)
    limiter = fake_limiter(clock)
    record = create_instance(
        vendor_slug="nextdns", display_name="NextDNS",
        credentials_dict=dict(CREDS), instance_config={},
    )
    create_client("acme-corp", "Acme Corp")
    create_client("example-bakery", "Example Bakery")
    yield World(bedrock_root, clock, transport, limiter, record)
    lim.reset_limiters()
    vendor_contact.reset()
    freshness.reset()
