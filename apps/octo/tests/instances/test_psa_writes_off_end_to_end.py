"""PSA writes kill switch, end to end on the real pieces (slice 0).

A persisted Autotask instance row, `InstanceManager.start_instance`, the real
adapter, client, poller and pusher, the real registry and tenant tickets.db.
Only the Autotask socket is fake (fake_vendor_http.py), and it records every
request — so "no write" is asserted on the wire, not on a mock.

  - switch OFF (the default; the live state on 2026-10-05): the pusher is
    never constructed, a ticket left 'pending' in the outbox stays pending,
    and the fake Autotask sees GETs only — also after a restart, and also
    when a `writes_enabled: true` rides in the credential blob;
  - switch ON then OFF live: the pusher sends, then — once switched off —
    sends nothing more, and a restart keeps it off.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from typing import Any

import pytest

from apps.octo import paths
from apps.octo.adapters.autotask import adapter as autotask_adapter_module
from apps.octo.adapters.autotask.client import AutotaskClient
from apps.octo.adapters.autotask.writeback import AutotaskPusher
from apps.octo.api.routers.tickets import _ensure_schema
from apps.octo.client_provisioning import create_client
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.instances import InstanceManager, create_instance, freshness, vendor_contact
from apps.octo.instances.manager import update_instance_config
from apps.octo.tests.instances.fake_vendor_http import FakeVendorTransport, session_request
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

TENANT = "acme-church"
COMPANY = 9001
CREDS = {
    "AUTOTASK_USERNAME": "api-user@example.test",
    "AUTOTASK_SECRET": "fixture-secret-" + "5" * 24,
    "AUTOTASK_INTEGRATION_CODE": "FIXTURE-CODE",
    "AUTOTASK_ZONE_URL": "https://zone.example.test/atservicesrest/v1.0/",
}


@pytest.fixture(autouse=True)
def _clean_state():
    vendor_contact.reset()
    freshness.reset()
    yield
    vendor_contact.reset()
    freshness.reset()


class _Built:
    pushers: list[AutotaskPusher] = []


def _adapter_class(transport: FakeVendorTransport):
    def client_factory(config):
        return AutotaskClient(config, http_request=session_request(transport))

    def pusher_factory(**kw: Any) -> AutotaskPusher:
        pusher = AutotaskPusher(tick_interval_sec=0.01, **kw)
        _Built.pushers.append(pusher)
        return pusher

    class _Autotask(autotask_adapter_module.AutotaskSourceAdapter):
        def __init__(self) -> None:
            super().__init__(client_factory=client_factory, pusher_factory=pusher_factory)

    return _Autotask


_POSTED: list[dict] = []


def _transport() -> FakeVendorTransport:
    t = FakeVendorTransport()
    t.route("GET", "/Tickets/query", lambda _r: {"items": [], "pageDetails": {}})
    t.route("GET", "/TicketNotes/query", lambda _r: {"items": [], "pageDetails": {}})
    seq = iter(range(5001, 6000))

    def created(request):
        _POSTED.append(json.loads(request.body))
        return {"itemId": next(seq)}

    _POSTED.clear()
    t.route("POST", "/Tickets", created)
    t.route("POST", "/TicketCharges", lambda _r: {"itemId": next(seq)})
    return t


def _writes(transport: FakeVendorTransport) -> list[tuple[str, str]]:
    return [(m, p) for m, p in transport.calls if m != "GET"]


def _queue_ticket(title: str) -> int:
    """A ticket already flagged + 'pending' in the outbox — what a click on
    the old "Push this ticket to Autotask" checkbox left behind."""
    db = _ensure_schema(TENANT)
    conn = sqlite3.connect(db)
    try:
        cur = conn.execute(
            "INSERT INTO tickets (title, severity, status, push_to_autotask, contract_id) "
            "VALUES (?, 'low', 'new', 1, '4711')", (title,))
        tid = int(cur.lastrowid)
        conn.execute("INSERT INTO ticket_charges (ticket_id, name, unit_price, quantity) "
                     "VALUES (?, 'Part', 5, 1)", (tid,))
        conn.execute("INSERT INTO autotask_push_state (ticket_id, state) VALUES (?, 'pending')",
                     (tid,))
        conn.commit()
        return tid
    finally:
        conn.close()


def _state(tid: int) -> str:
    conn = sqlite3.connect(paths.client_dir(TENANT) / "tickets.db")
    try:
        return conn.execute("SELECT state FROM autotask_push_state WHERE ticket_id = ?",
                            (tid,)).fetchone()[0]
    finally:
        conn.close()


def _instance(*, creds_extra: dict | None = None) -> int:
    record = create_instance(
        vendor_slug="autotask", display_name="Autotask",
        credentials_dict={**CREDS, **(creds_extra or {})},
        instance_config={"poll_interval_sec": 0.01, "location_proposals_every_sec": 0},
    )
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute(
            "INSERT INTO autotask_tenant_company_map (adapter_instance_id, tenant_slug, "
            "autotask_company_id) VALUES (?, ?, ?)", (record.id, TENANT, COMPANY))
        conn.commit()
    finally:
        conn.close()
    return record.id


def _start(transport: FakeVendorTransport, iid: int) -> InstanceManager:
    from apps.octo.instances.manager import get_instance

    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(_adapter_class(transport))
    manager = InstanceManager(adapter_registry=registry)
    manager.start_instance(get_instance(iid))
    return manager


async def _until(predicate, *, timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(0.01)


async def _stop(manager: InstanceManager, iid: int) -> None:
    adapter = manager.running_adapter(iid)
    poller, pusher = adapter._poller, adapter._pusher
    manager.stop_instance(iid)
    await poller.stop()
    if pusher is not None:
        await pusher.stop()


async def _polls(transport: FakeVendorTransport, n: int) -> None:
    start = transport.count("/Tickets/query")
    await _until(lambda: transport.count("/Tickets/query") >= start + n)


@pytest.mark.asyncio
async def test_no_autotask_write_of_any_kind_while_the_switch_is_off(bedrock_root):  # noqa: F811
    _Built.pushers = []
    create_client(TENANT, "Acme Church")
    # A `writes_enabled: true` smuggled into the credential blob (which wins
    # the start-config merge) must not turn writes on: the registry row rules.
    iid = _instance(creds_extra={"writes_enabled": True})
    tid = _queue_ticket("Left in the outbox by the old checkbox")
    transport = _transport()

    manager = _start(transport, iid)
    try:
        adapter = manager.running_adapter(iid)
        await _polls(transport, 3)                 # the reads keep working
        await asyncio.sleep(0.1)                   # many pusher ticks' worth
        assert _Built.pushers == []                # never even constructed
        assert adapter._pusher is None and adapter.writes_enabled is False
        assert _writes(transport) == []            # GETs only, on the wire
        assert _state(tid) == "pending"
    finally:
        await _stop(manager, iid)

    # Restart: still off.
    manager = _start(transport, iid)
    try:
        await _polls(transport, 2)
        await asyncio.sleep(0.05)
        assert _Built.pushers == [] and _writes(transport) == []
        assert _state(tid) == "pending"
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_switch_on_sends_then_off_live_sends_nothing_more(bedrock_root):  # noqa: F811
    _Built.pushers = []
    create_client(TENANT, "Acme Church")
    iid = _instance()
    update_instance_config(iid, {"writes_enabled": True})      # (the audited route's write)
    first = _queue_ticket("Allowed while on")
    transport = _transport()

    manager = _start(transport, iid)
    try:
        adapter = manager.running_adapter(iid)
        assert len(_Built.pushers) == 1
        await _until(lambda: _state(first) == "pushed"
                     and transport.count("/TicketCharges") == 1)   # its charge follows
        await asyncio.sleep(0.05)
        sent = _writes(transport)
        assert sent == [("POST", "/atservicesrest/v1.0/V1.0/Tickets"),
                        ("POST", "/atservicesrest/v1.0/V1.0/TicketCharges")]
        # What went out: AW03 "Low" (3), never Critical (4); and no
        # contractID although the row carries one.
        assert len(_POSTED) == 1
        assert _POSTED[0]["priority"] == 3 and _POSTED[0]["companyID"] == COMPANY
        assert not any(k.lower() == "contractid" for k in _POSTED[0])

        # Switch OFF live (what the route does after its audited write).
        update_instance_config(iid, {"writes_enabled": False})
        assert adapter.apply_writes_enabled(False) is True
        await asyncio.sleep(0.05)
        assert adapter._pusher is None
        second = _queue_ticket("Queued after the switch-off")
        await _polls(transport, 3)
        await asyncio.sleep(0.1)
        assert _writes(transport) == sent          # nothing more on the wire
        assert _state(second) == "pending"
    finally:
        await _stop(manager, iid)

    # A restart keeps it off: the persisted switch is what start() reads.
    before = len(_Built.pushers)
    manager = _start(transport, iid)
    try:
        await _polls(transport, 2)
        await asyncio.sleep(0.05)
        assert len(_Built.pushers) == before
        assert _writes(transport) == sent
        assert _state(second) == "pending"
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_running_pusher_obeys_the_persisted_switch_even_if_never_told(bedrock_root):  # noqa: F811
    """Defense in depth: if the live stop never reached the adapter, the
    pusher still re-reads the registry before each send."""
    _Built.pushers = []
    create_client(TENANT, "Acme Church")
    iid = _instance()
    update_instance_config(iid, {"writes_enabled": True})
    transport = _transport()
    manager = _start(transport, iid)
    try:
        assert len(_Built.pushers) == 1
        update_instance_config(iid, {"writes_enabled": False})   # adapter NOT told
        await _until(lambda: _Built.pushers[0].last_cycle_refused is True)
        tid = _queue_ticket("Queued after a silent switch-off")
        await asyncio.sleep(0.15)
        assert _writes(transport) == []
        assert _state(tid) == "pending"
        assert _Built.pushers[0].last_cycle_refused is True
    finally:
        await _stop(manager, iid)


def test_instance_row_without_the_key_reads_off(bedrock_root):  # noqa: F811
    """The live instance (created before slice 0) has no `writes_enabled`
    key at all: that is OFF."""
    from apps.octo.adapters.autotask.writes_switch import (
        instance_writes_enabled,
        psa_writes_enabled,
    )

    iid = _instance()
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        cfg = json.loads(conn.execute(
            "SELECT instance_config_json FROM adapter_instances WHERE id = ?", (iid,),
        ).fetchone()[0])
    finally:
        conn.close()
    assert "writes_enabled" not in cfg
    assert instance_writes_enabled(iid) is False and psa_writes_enabled() is False
