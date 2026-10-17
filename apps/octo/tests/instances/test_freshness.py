"""Receive-clock freshness (`instances.freshness`) — the debounce, the reads,
and that it is written on the Datto poll and webhook paths (the Wazuh,
RocketCyber and UniFi pollers are covered with their contact reporting in
test_poller_contact_and_freshness.py). Real registry, real ingest sink, real
Datto poller; only the vendor socket is fake."""
from __future__ import annotations

import sqlite3
import types

import pytest

from apps.octo import paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.poller import DattoPoller
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FakeDattoTransport,
    client_factory,
    real_client,
)
from apps.octo.client_provisioning import create_client
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import create_instance, freshness, quarantine, vendor_tenants
from apps.octo.instances.manager import get_instance
from apps.octo.instances.tenant_map import MappingIngestSink, TenantMapping, set_mappings
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@pytest.fixture(autouse=True)
def _clean_state():
    freshness.reset()
    quarantine.reset_schema_cache()
    vendor_tenants.reset()
    yield
    freshness.reset()
    quarantine.reset_schema_cache()
    vendor_tenants.reset()


@pytest.fixture
def clock(monkeypatch):
    """freshness' monotonic clock, under the test's control."""
    now = [1000.0]
    monkeypatch.setattr(freshness, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    return now


@pytest.fixture
def writes(monkeypatch):
    """Every registry write freshness makes — passed through to the real one."""
    seen: list[tuple[int, str]] = []
    real = freshness._write_instance_last_event

    def _recording(instance_id, at):
        seen.append((instance_id, at))
        return real(instance_id, at)

    monkeypatch.setattr(freshness, "_write_instance_last_event", _recording)
    return seen


def _instance():
    return create_instance(
        vendor_slug="datto", display_name="Datto RMM", credentials_dict=dict(CREDS),
        instance_config={"poll_interval_sec": 0.01},
    )


# ---------------------------------------------------------------------------
# Debounce — measured from the last WRITE
# ---------------------------------------------------------------------------

def test_a_burst_writes_the_registry_once(bedrock_root, clock, writes):  # noqa: F811
    record = _instance()
    for _ in range(500):
        freshness.record_event(instance_id=record.id, slug="acme-corp")
    assert len(writes) == 1
    assert get_instance(record.id).last_event_at == writes[0][1]


def test_a_steady_stream_writes_once_per_interval(bedrock_root, clock, writes):  # noqa: F811
    """One event every 10 s for 100 s. Compared with the PREVIOUS event (10 s
    ago, always < 30 s) nothing after the first would ever be written — the
    frozen-timestamp bug. Measured from the last write: t=0, 30, 60, 90."""
    record = _instance()
    for _ in range(11):
        freshness.record_event(instance_id=record.id)
        clock[0] += 10
    assert len(writes) == 4
    # The row carries the newest WRITTEN receive time, never moving back.
    assert get_instance(record.id).last_event_at == writes[-1][1]
    assert [at for _, at in writes] == sorted(at for _, at in writes)


def test_instances_are_debounced_independently(bedrock_root, clock, writes):  # noqa: F811
    a, b = _instance(), create_instance(
        vendor_slug="wazuh", display_name="Wazuh", credentials_dict={"k": "v"},
    )
    freshness.record_event(instance_id=a.id)
    freshness.record_event(instance_id=b.id)
    freshness.record_event(instance_id=a.id)
    assert [iid for iid, _ in writes] == [a.id, b.id]


def test_never_raises_without_a_registry(tmp_path, monkeypatch, clock):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "nowhere"))
    freshness.record_event(instance_id=7, slug="acme-corp")     # no exception
    assert freshness.instance_last_event(7, None) is not None
    assert freshness.tenant_last_event("acme-corp") is not None


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _insert(slug: str, received_at: str, source: str = "datto") -> None:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        conn.execute(
            "INSERT INTO events (received_at, source, event_type, severity, payload, "
            "payload_sha256) VALUES (?, ?, 'alert', 'low', '{}', ?)",
            (received_at, source, "b" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def test_tenant_falls_back_to_newest_stored_event_ignoring_future_dates(bedrock_root):  # noqa: F811
    create_client("acme-corp", "Acme Corp")
    assert freshness.tenant_last_event("acme-corp") is None
    _insert("acme-corp", "2026-01-02T03:04:05.000Z")
    _insert("acme-corp", "2026-01-01T00:00:00.000Z")
    # A vendor clock years ahead must not keep the tenant looking fresh.
    _insert("acme-corp", "2099-01-01T00:00:00.000Z")
    assert freshness.tenant_last_event("acme-corp") == "2026-01-02T03:04:05.000Z"

    # Received in this process: the receive clock wins over the stored one.
    freshness.record_event(slug="acme-corp")
    assert freshness.tenant_last_event("acme-corp") > "2026-09-01"


def test_newest_stored_event_by_source_within_a_window(bedrock_root):  # noqa: F811
    """The token fallback after a restart: only that token's source label,
    and nothing older than the window (the source filter is unindexed)."""
    create_client("acme-corp", "Acme Corp")
    _insert("acme-corp", "2026-01-03T00:00:00.000Z", source="datto")
    _insert("acme-corp", "2026-01-02T00:00:00.000Z", source="buoy:shim-a")
    _insert("acme-corp", "2026-01-01T00:00:00.000Z", source="buoy:shim-b")
    newest = freshness.newest_stored_event
    assert newest("acme-corp", source="buoy:shim-a") == "2026-01-02T00:00:00.000Z"
    assert newest("acme-corp", source="buoy:shim-b") == "2026-01-01T00:00:00.000Z"
    assert newest("acme-corp", source="buoy:shim-b", not_before="2026-01-01T12:00:00.000Z") is None
    assert newest("acme-corp", source="buoy:none") is None
    assert newest("acme-corp") == "2026-01-03T00:00:00.000Z"


def test_rows_a_post_stored_in_this_process_are_left_out_of_the_read_back(bedrock_root):  # noqa: F811
    """Every post accepted in this process is in memory by token id, so the
    read-back skips the rows those posts stored — by id: an alert's stored
    time is the vendor's and may be older than the process."""
    create_client("acme-corp", "Acme Corp")
    _insert("acme-corp", "2026-01-01T00:00:00.000Z", source="buoy:shim")   # id 1
    _insert("acme-corp", "2026-01-02T00:00:00.000Z", source="buoy:shim")   # id 2
    assert freshness.first_posted_event_id("acme-corp") is None
    # A replay (no new row) marks nothing; a stored post marks its row.
    freshness.record_token_post(7, slug="acme-corp", stored_event_id=None)
    assert freshness.first_posted_event_id("acme-corp") is None
    freshness.record_token_post(7, slug="acme-corp", stored_event_id=2)
    freshness.record_token_post(8, slug="acme-corp", stored_event_id=5)
    assert freshness.first_posted_event_id("acme-corp") == 2
    assert freshness.first_posted_event_id("globex") is None
    newest = freshness.newest_stored_event
    assert newest("acme-corp", source="buoy:shim",
                  before_id=freshness.first_posted_event_id("acme-corp")) == "2026-01-01T00:00:00.000Z"
    assert newest("acme-corp", source="buoy:shim", before_id=1) is None
    freshness.reset()
    assert freshness.first_posted_event_id("acme-corp") is None


def test_token_clocks_keep_requests_and_accepted_posts_apart():
    assert freshness.token_last_request(5) is None and freshness.token_last_post(5) is None
    freshness.record_token_request(5)
    assert freshness.token_last_request(5) is not None
    assert freshness.token_last_post(5) is None          # asked, not (yet) accepted
    freshness.record_token_post(5)
    assert freshness.token_last_post(5) >= freshness.token_last_request(5)
    assert freshness.token_last_post(6) is None           # per token


def test_instance_read_takes_the_later_of_memory_and_row():
    assert freshness.instance_last_event(3, None) is None
    assert freshness.instance_last_event(3, "2026-01-01T00:00:00.000Z") == "2026-01-01T00:00:00.000Z"
    freshness.record_event(instance_id=3)
    assert freshness.instance_last_event(3, "2026-01-01T00:00:00.000Z") > "2026-09-01"


def test_age_seconds():
    from datetime import datetime, timezone

    now = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
    assert freshness.age_seconds("2026-09-28T11:55:00.000Z", now=now) == 300
    assert freshness.age_seconds("2026-09-28T12:05:00Z", now=now) == 0
    assert freshness.age_seconds(None, now=now) is None
    assert freshness.age_seconds("not a time", now=now) is None


# ---------------------------------------------------------------------------
# Written on the Datto poll path (tenant_autocreate.deliver)
# ---------------------------------------------------------------------------

def _alert(n: int, site_uid: str, site_name: str | None = "Acme Corp") -> dict:
    asi = {"siteUid": site_uid, "deviceName": f"WS-{n:02d}"}
    if site_name is not None:
        asi["siteName"] = site_name
    return {
        "alertUid": f"alert-{n}", "priority": "High", "timestamp": 1700000000 + n,
        "alertSourceInfo": asi,
        "alertContext": {"@class": "eventlog_ctx", "message": f"event {n}"},
    }


def _poller(transport: FakeDattoTransport, record) -> DattoPoller:
    return DattoPoller(
        adapter=DattoSourceAdapter(client_factory=client_factory(transport)),
        client=real_client(transport),
        sink=MappingIngestSink(SqliteIngestSink(publish_to_stream=False), record.id),
        default_tenant_slug="_unmapped",
        initial_cursor="2023-01-01T00:00:00.000Z",
        instance_id=record.id,
    )


@pytest.mark.asyncio
async def test_datto_poll_records_instance_and_tenant_freshness(bedrock_root, writes):  # noqa: F811
    record = _instance()
    create_client("acme-corp", "Acme Corp")
    set_mappings(record.id, [TenantMapping("site-uid-0001", "acme-corp")])
    transport = FakeDattoTransport()
    transport.alerts = [_alert(1, "site-uid-0001")]
    poller = _poller(transport, record)

    await poller._drain_once()
    assert get_instance(record.id).last_event_at is not None
    tenant_at = freshness.tenant_last_event("acme-corp")
    instance_at = freshness.instance_last_event(record.id, None)
    assert tenant_at and instance_at

    # The open alert is re-listed on the next poll: a duplicate is not news.
    freshness.reset()
    await poller._drain_once()
    assert freshness.instance_last_event(record.id, None) is None
    assert len(writes) == 1


@pytest.mark.asyncio
async def test_a_newly_held_alert_counts_for_the_instance_not_a_tenant(bedrock_root):  # noqa: F811
    record = _instance()
    transport = FakeDattoTransport()
    transport.alerts = [_alert(2, "site-uid-0009", site_name=None)]   # → quarantine
    await _poller(transport, record)._drain_once()
    assert quarantine.counts(record.id)["held"] == 1
    assert freshness.instance_last_event(record.id, None) is not None
    assert freshness._tenant_last == {}


# ---------------------------------------------------------------------------
# Written on the webhook path (same deliver(), door='webhook')
# ---------------------------------------------------------------------------

from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: E402,F401
    instance_endpoint_client,
)
from apps.octo.tests.auth.test_webhook_reachability import (  # noqa: E402,F401
    _HOOK,
    _create_datto,
    _listed,
    hooks,
)


def test_datto_webhook_records_last_event_at(hooks):  # noqa: F811
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    assert _listed(client, cookies)["last_event_at"] is None
    body = {
        "event": "alert_raised", "alertUid": "wh-1", "alertCategory": "Disk",
        "alertType": "Disk Usage", "alertContext": {"message": "disk full"},
        "device": {"hostname": "WS-1", "uid": "d-1"}, "siteUid": "site-uid-0001",
        "siteName": "Acme Corp",
    }
    r = client.post(_HOOK, json=body, headers={"X-Webhook-Token": token})
    assert r.status_code == 200 and r.json()["ingested"] is True, r.text
    listed = _listed(client, cookies)
    assert listed["last_event_at"] is not None
    assert listed["last_event_at"] == get_instance(iid).last_event_at
    assert freshness.tenant_last_event(r.json()["tenant"]) is not None
