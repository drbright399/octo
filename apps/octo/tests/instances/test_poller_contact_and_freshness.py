"""Vendor contact + receive-clock freshness on the Wazuh, RocketCyber, UniFi
and Autotask pollers — end to end on the real pieces: a persisted
adapter_instances row, InstanceManager.start_instance, the real adapter,
client and poller, the real registry and ingest sink. Only the vendor socket
is fake (fake_vendor_http.py).

The defects this pins: only Datto reported vendor contact, so every other
integration read "awaiting first poll" forever; `adapter_instances.
last_event_at` was never written by anyone; UniFi stored through a bare
sink (no tenant map, no freshness); and Autotask read an instance-id key
the manager never sets, so it polled as instance 0.
"""
from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from apps.octo import paths
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.adapters.autotask import adapter as autotask_adapter_module
from apps.octo.adapters.autotask.client import AutotaskClient
from apps.octo.adapters.rocketcyber import adapter as rocketcyber_adapter_module
from apps.octo.adapters.rocketcyber.client import RocketCyberClient
from apps.octo.adapters.unifi import limiter as unifi_limiter
from apps.octo.adapters.unifi.tests import fake_unifi
from apps.octo.adapters.wazuh import adapter as wazuh_adapter_module
from apps.octo.adapters.wazuh.client import WazuhClient
from apps.octo.client_provisioning import create_client
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.instances import InstanceManager, create_instance, freshness, vendor_contact
from apps.octo.instances.manager import get_instance
from apps.octo.instances.tenant_map import MappingIngestSink, TenantMapping, set_mappings
from apps.octo.tests.instances.fake_vendor_http import (
    FakeVendorTransport,
    mount,
    session_request,
)
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

SECRET = "fixture-secret-" + "7" * 24


@pytest.fixture(autouse=True)
def _clean_state():
    vendor_contact.reset()
    freshness.reset()
    yield
    vendor_contact.reset()
    freshness.reset()


# ---------------------------------------------------------------------------
# Real adapters, wired to the fake socket the way the framework builds them
# (`cls()` with no arguments)
# ---------------------------------------------------------------------------

def _wazuh_class(transport: FakeVendorTransport):
    def factory(config):
        client = WazuhClient(config)
        mount(client._session, transport)
        return client

    class _Wazuh(wazuh_adapter_module.WazuhSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=factory)

    return _Wazuh


def _rocketcyber_class(transport: FakeVendorTransport):
    def factory(config):
        client = RocketCyberClient(config)
        mount(client._session, transport)
        return client

    class _RocketCyber(rocketcyber_adapter_module.RocketCyberSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=factory)

    return _RocketCyber


def _unifi_class(transport: "fake_unifi.FakeUniFiTransport"):
    # The cloud connector adapter (the local-controller one is retired): its
    # own transport-level fake, and a limiter on a fake clock — the 1 s
    # spacing never becomes a real wait here.
    return fake_unifi.unifi_adapter_class(transport)


def _autotask_class(transport: FakeVendorTransport):
    def factory(config):
        return AutotaskClient(config, http_request=session_request(transport))

    class _Autotask(autotask_adapter_module.AutotaskSourceAdapter):
        def __init__(self) -> None:
            # The write-back pusher is not under test.
            super().__init__(client_factory=factory, start_pusher=False)

    return _Autotask


WAZUH_CREDS = {
    "WAZUH_MANAGER_URL": "https://wazuh.example.test:55000",
    "WAZUH_INDEXER_URL": "https://wazuh.example.test:9200",
    "WAZUH_API_KEY": SECRET,
}
# The real API's shape (see adapters/rocketcyber/tests/fake_rocketcyber.py):
# only the key is required; the provider account is read from GET /account.
RC_CREDS = {
    "RC_API_URL": "https://rc.example.test/v3",
    "RC_API_KEY": SECRET,
}
UNIFI_CREDS = dict(fake_unifi.CREDS)
# What the RETIRED local-controller adapter saved.
UNIFI_LEGACY_CREDS = {
    "UNIFI_CONTROLLER_URL": "https://unifi.example.test",
    "UNIFI_API_KEY": SECRET,
}
AUTOTASK_CREDS = {
    "AUTOTASK_USERNAME": "api-user@example.test",
    "AUTOTASK_SECRET": SECRET,
    "AUTOTASK_INTEGRATION_CODE": "FIXTURE-CODE",
    "AUTOTASK_ZONE_URL": "https://zone.example.test/atservicesrest/v1.0/",
}


def _start(
    vendor_slug: str, adapter_cls, creds: dict, *,
    mappings: list[TenantMapping] | None = None, **config: Any,
):
    record = create_instance(
        vendor_slug=vendor_slug,
        display_name=vendor_slug,
        credentials_dict=dict(creds),
        instance_config={"poll_interval_sec": 0.01, **config},
    )
    if mappings:
        set_mappings(record.id, mappings)
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(adapter_cls)
    manager = InstanceManager(adapter_registry=registry)
    manager.start_instance(record)
    return manager, record.id


async def _until(predicate, *, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


async def _stop(manager: InstanceManager, instance_id: int) -> None:
    poller = manager._running[instance_id].adapter._poller
    manager.stop_instance(instance_id)
    await poller.stop()


def _stored(slug: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT source, summary FROM events ORDER BY id").fetchall()
    finally:
        conn.close()


async def _contact_ok(iid: int) -> None:
    # The snapshot moves before the row write lands (two thread hops).
    await _until(lambda: get_instance(iid).status_detail == vendor_contact.OK_DETAIL)
    assert get_instance(iid).status == "running"
    assert vendor_contact.snapshot(iid)["last_ok_at"] is not None


# ---------------------------------------------------------------------------
# Wazuh
# ---------------------------------------------------------------------------

def _wazuh_alert(n: int) -> dict:
    return {
        "id": f"wz-{n}",
        "timestamp": f"2026-09-20T10:00:0{n}.000Z",
        "rule": {"id": "5710", "level": 5, "description": "sshd: attempt", "groups": ["sshd"]},
        "agent": {"id": "001", "name": "ws-01", "labels": {"_octo_tenant_slug": "acme-corp"}},
        "data": {},
    }


@pytest.mark.asyncio
async def test_wazuh_reports_contact_and_records_freshness(bedrock_root):  # noqa: F811
    create_client("acme-corp", "Acme Corp")
    transport = FakeVendorTransport()
    batches = [[_wazuh_alert(1), _wazuh_alert(2)]]
    transport.route(
        "POST", "/_search",
        lambda _r: {"hits": {"hits": [{"_source": a} for a in (batches.pop(0) if batches else [])]}},
    )
    manager, iid = _start("wazuh", _wazuh_class(transport), WAZUH_CREDS)
    try:
        await _until(lambda: vendor_contact.snapshot(iid)["last_ok_at"] is not None)
        await _until(lambda: get_instance(iid).last_event_at is not None)
        await _contact_ok(iid)
        assert [r["source"] for r in _stored("acme-corp")] == ["wazuh", "wazuh"]
        # Receive clock, persisted once for the batch (debounced); the
        # process holds the newest.
        row = get_instance(iid)
        assert row.last_event_at <= freshness.instance_last_event(iid, None)
        assert freshness.tenant_last_event("acme-corp") is not None

        # A failing poll flips the row; the detail is platform text only.
        transport.status = 401
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert detail.startswith("Wazuh rejected the stored credentials")
        assert SECRET not in detail
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_wazuh_transport_failure_then_recovery(bedrock_root):  # noqa: F811
    transport = FakeVendorTransport()
    transport.route("POST", "/_search", lambda _r: {"hits": {"hits": []}})
    transport.status = 503
    manager, iid = _start("wazuh", _wazuh_class(transport), WAZUH_CREDS)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        assert get_instance(iid).status_detail.startswith("Could not reach Wazuh")
        assert vendor_contact.snapshot(iid)["failure_kind"] == "transport"
        transport.status = 200
        await _until(lambda: get_instance(iid).status == "running")
        await _contact_ok(iid)
        # A quiet vendor: contact is fresh, no event was ever received.
        assert get_instance(iid).last_event_at is None
    finally:
        await _stop(manager, iid)


# ---------------------------------------------------------------------------
# RocketCyber
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rocketcyber_reports_contact_and_records_freshness(bedrock_root):  # noqa: F811
    create_client("acme-corp", "Acme Corp")
    transport = FakeVendorTransport()
    created = format_utc_ms(datetime.now(timezone.utc) - timedelta(hours=1))
    incidents = [[{
        "id": 77, "accountId": 2001, "accountName": "Acme Corp",
        "title": "Suspicious PowerShell", "status": "open", "eventCount": 1,
        "createdAt": created, "publishedAt": created, "updatedAt": created,
    }]]
    transport.route(
        "GET", "/account",
        lambda _r: {"name": "Example MSP", "accountPath": "900.1000", "customers": [2001]},
    )
    transport.route(
        "GET", "/incidents",
        lambda _r: (lambda data: {
            "totalCount": len(data), "currentPage": 1, "totalPages": 1,
            "dataCount": len(data), "data": data,
        })(incidents.pop(0) if incidents else []),
    )
    manager, iid = _start(
        "rocketcyber", _rocketcyber_class(transport), RC_CREDS,
        mappings=[TenantMapping("2001", "acme-corp")],
    )
    try:
        await _until(lambda: get_instance(iid).last_event_at is not None)
        await _until(lambda: vendor_contact.snapshot(iid)["last_ok_at"] is not None)
        await _contact_ok(iid)
        assert [r["source"] for r in _stored("acme-corp")] == ["rocketcyber"]

        transport.status = 403
        await _until(lambda: get_instance(iid).status == "error")
        assert get_instance(iid).status_detail.startswith("RocketCyber rejected")
        assert SECRET not in get_instance(iid).status_detail
    finally:
        await _stop(manager, iid)


# ---------------------------------------------------------------------------
# UniFi — the cloud connector adapter
# ---------------------------------------------------------------------------

def _unifi_world():
    unifi_limiter.reset_limiters()
    clock = fake_unifi.FakeClock(datetime.now(timezone.utc))
    transport = fake_unifi.FakeUniFiTransport(clock)
    fake_unifi.standard_fleet(transport)
    fake_unifi.fake_limiter(clock)
    return clock, transport


@pytest.mark.asyncio
async def test_unifi_reports_contact_and_records_freshness(bedrock_root):  # noqa: F811
    create_client("acme-corp", "Acme Corp")
    clock, transport = _unifi_world()
    transport.site(fake_unifi.HOST_A).log.append(
        fake_unifi.ips_event(clock.now() - timedelta(minutes=5), eid="u-1"))
    manager, iid = _start(
        "unifi", _unifi_class(transport), UNIFI_CREDS,
        mappings=[TenantMapping(fake_unifi.SCOPE_A, "acme-corp")],
    )
    try:
        await _until(lambda: get_instance(iid).last_event_at is not None)
        await _contact_ok(iid)
        assert [r["source"] for r in _stored("acme-corp")] == ["unifi"]
        assert freshness.tenant_last_event("acme-corp") is not None
    finally:
        await _stop(manager, iid)
        unifi_limiter.reset_limiters()


@pytest.mark.asyncio
async def test_unifi_with_no_site_mapped_reads_only_the_fleet(bedrock_root):  # noqa: F811
    """No site mapped → the fleet list (two calls) is the only contact — a
    real one, so it may say so — and nothing is stored anywhere."""
    create_client("acme-corp", "Acme Corp")
    clock, transport = _unifi_world()
    manager, iid = _start("unifi", _unifi_class(transport), UNIFI_CREDS)
    try:
        await _until(lambda: vendor_contact.snapshot(iid)["last_ok_at"] is not None)
        assert set(transport.paths()) == {"/v1/hosts", "/v1/sites"}
        assert _stored("acme-corp") == []
        from apps.octo.adapters.unifi import store as unifi_store
        assert unifi_store.cursor("acme-corp", fake_unifi.SCOPE_A) is None
    finally:
        await _stop(manager, iid)
        unifi_limiter.reset_limiters()


def test_a_retired_local_controller_instance_says_what_to_do(bedrock_root):  # noqa: F811
    """The migration path: an instance saved for the local-controller API is
    refused at start with the way forward; its row is kept (nothing lost)."""
    from apps.octo.instances.manager import InstanceLifecycleError

    clock, transport = _unifi_world()
    with pytest.raises(InstanceLifecycleError):
        _start("unifi", _unifi_class(transport), UNIFI_LEGACY_CREDS,
               site_to_tenant={"site-a": "acme-corp"})
    (row,) = [r for r in _instances() if r["vendor_slug"] == "unifi"]
    assert row["status"] == "error" and "Site Manager API key" in row["status_detail"]
    assert "Disable this integration" in row["status_detail"]
    assert transport.calls == []
    unifi_limiter.reset_limiters()


def _instances() -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM adapter_instances ORDER BY id").fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Autotask
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_autotask_polls_as_its_own_instance_and_reports_contact(bedrock_root):  # noqa: F811
    transport = FakeVendorTransport()
    transport.route("GET", "/Tickets/query", lambda _r: {"items": [], "pageDetails": {}})
    transport.route("GET", "/TicketNotes/query", lambda _r: {"items": [], "pageDetails": {}})
    manager, iid = _start("autotask", _autotask_class(transport), AUTOTASK_CREDS)
    try:
        # The manager injects `_instance_id`; the poller used to read a key
        # nobody sets and ran as instance 0.
        assert manager.running_adapter(iid)._poller._instance_id == iid
        await _until(lambda: vendor_contact.snapshot(iid)["last_ok_at"] is not None)
        await _contact_ok(iid)

        # Autotask's own error text quotes the response body: never on the row.
        transport.status = 500
        transport.error_body = {"errors": ["VENDOR-BODY-MARKER"]}
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert detail.startswith("Could not reach Autotask")
        assert "VENDOR-BODY-MARKER" not in detail and SECRET not in detail

        transport.status = 401
        await _until(
            lambda: (get_instance(iid).status_detail or "").startswith("Autotask rejected"),
        )
        assert vendor_contact.snapshot(iid)["failure_kind"] == "auth"
    finally:
        await _stop(manager, iid)
