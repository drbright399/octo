"""Poll outcome → instance row, end to end: a persisted adapter_instances row,
InstanceManager.start_instance, the real RocketCyberSourceAdapter / Client /
Poller — only the vendor socket is fake (fake_rocketcyber.py). Plus the
backoff policy with the PRODUCTION constants (only the sleeping is replaced).
"""
from __future__ import annotations

import asyncio
import logging

import pytest

from apps.octo.adapters.rocketcyber import poller as poller_module
from apps.octo.adapters.rocketcyber.poller import RocketCyberPoller
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    API_KEY,
    CREDS,
    INCIDENTS_PATH,
    OLD_CREDS,
    SECRETS,
    FakeRocketCyberTransport,
    incident,
    real_client,
    rocketcyber_adapter_class,
)
from apps.octo.client_provisioning import create_client
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.instances import InstanceManager, create_instance, freshness, vendor_contact
from apps.octo.instances import manager as manager_module
from apps.octo.instances.manager import get_instance
from apps.octo.instances.tenant_map import TenantMapping, set_mappings
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


@pytest.fixture(autouse=True)
def _clean_state():
    vendor_contact.reset()
    freshness.reset()
    yield
    vendor_contact.reset()
    freshness.reset()


@pytest.fixture
def fast_backoff(monkeypatch):
    """Same policy, test-sized delays (production: 60 s → 900 s)."""
    for name in ("CREDENTIAL_BACKOFF_BASE_SEC", "TRANSPORT_BACKOFF_BASE_SEC"):
        monkeypatch.setattr(poller_module, name, 0.01)
    for name in ("CREDENTIAL_BACKOFF_CEILING_SEC", "TRANSPORT_BACKOFF_CEILING_SEC"):
        monkeypatch.setattr(poller_module, name, 0.04)


@pytest.fixture
def status_writes(monkeypatch):
    writes: list[tuple[str, str]] = []
    real = manager_module.set_contact_status

    def _recording(instance_id, *, status, status_detail):
        writes.append((status, status_detail))
        return real(instance_id, status=status, status_detail=status_detail)

    monkeypatch.setattr(manager_module, "set_contact_status", _recording)
    return writes


def _start(transport: FakeRocketCyberTransport, creds: dict | None = None, **config):
    record = create_instance(
        vendor_slug="rocketcyber", display_name="RocketCyber",
        credentials_dict=dict(creds or CREDS),
        instance_config={"poll_interval_sec": 0.01, **config},
    )
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(rocketcyber_adapter_class(transport))
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


def _no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# ---------------------------------------------------------------------------
# Healthy / recovered
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_healthy_instance_reports_running_once_stores_and_records_freshness(
    bedrock_root, status_writes,  # noqa: F811
):
    create_client("acme-corp", "Acme Corp")
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    manager, iid = _start(transport)
    set_mappings(iid, [TenantMapping("2001", "acme-corp")])
    try:
        await _until(lambda: transport.count(INCIDENTS_PATH) >= 5)
        await _until(lambda: get_instance(iid).last_event_at is not None)
        assert status_writes == [("running", vendor_contact.OK_DETAIL)]
        assert vendor_contact.snapshot(iid)["last_ok_at"] is not None
        adapter = manager.running_adapter(iid)
        assert adapter.health().last_event_at == transport.incidents[0]["updatedAt"]
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_an_instance_saved_by_the_old_wizard_polls(bedrock_root, status_writes):  # noqa: F811
    transport = FakeRocketCyberTransport()
    manager, iid = _start(transport, OLD_CREDS)
    try:
        await _until(lambda: get_instance(iid).status_detail == vendor_contact.OK_DETAIL)
        assert transport.incident_queries()[0]["accountId"] == OLD_CREDS["RC_ACCOUNT_ID"]
    finally:
        await _stop(manager, iid)


# ---------------------------------------------------------------------------
# Failures flip the row, with actionable text; recovery clears it
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_forbidden_flips_the_row_then_recovery_clears_it(
    bedrock_root, fast_backoff, status_writes, caplog,  # noqa: F811
):
    caplog.set_level(logging.DEBUG)
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert detail.startswith("RocketCyber accepted the API key but refused")
        assert "keeps retrying" in detail
        assert detail.endswith("RocketCyber's own message: \"fixture: forbidden\"")
        assert vendor_contact.snapshot(iid)["failure_kind"] == "forbidden"
        await _until(lambda: vendor_contact.snapshot(iid)["consecutive_failures"] >= 4)
        assert [s for s, _ in status_writes] == ["error"]       # once, not per poll

        transport.forbid_incidents = False
        await _until(lambda: get_instance(iid).status == "running")
        assert get_instance(iid).status_detail == vendor_contact.OK_DETAIL
        assert [s for s, _ in status_writes] == ["error", "running"]
    finally:
        await _stop(manager, iid)
    for _, written in status_writes:
        _no_secret(written)
    _no_secret(caplog.text)


@pytest.mark.asyncio
async def test_a_rejected_key_advises_replacement_only_once_it_persists(
    bedrock_root, fast_backoff, status_writes,  # noqa: F811
):
    transport = FakeRocketCyberTransport()
    transport.key = "the-vendor-now-wants-another-key"
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        first = status_writes[0][1]
        assert first.startswith("RocketCyber rejected the API key (HTTP 401)")
        assert "Nothing to do yet" in first and "Disable this integration" not in first
        await _until(lambda: "Disable this integration" in (get_instance(iid).status_detail or ""))
        assert "no longer works" in get_instance(iid).status_detail
        assert vendor_contact.snapshot(iid)["failure_kind"] == "auth"
        assert [s for s, _ in status_writes] == ["error", "error"]
        _no_secret(get_instance(iid).status_detail)
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_key_revoked_mid_life_with_403_reads_as_rejected(
    bedrock_root, fast_backoff,  # noqa: F811
):
    transport = FakeRocketCyberTransport()
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status_detail == vendor_contact.OK_DETAIL)
        transport.key = "the-key-was-revoked"
        transport.reject_key_status = 403
        await _until(lambda: get_instance(iid).status == "error")
        assert get_instance(iid).status_detail.startswith(
            "RocketCyber rejected the API key (HTTP 403)")
        assert vendor_contact.snapshot(iid)["failure_kind"] == "auth"
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("knob", "broken", "healthy", "needle"),
    [
        ("unreachable", True, False, "Could not read incidents from RocketCyber"),
        ("force_status", 503, None, "HTTP 503"),
        ("raw_body", b"<html>", None, "not JSON"),
        ("rate_limited", 10**6, 0, "rate limiting"),
    ],
)
async def test_transport_failures_flip_the_row_and_recover(
    bedrock_root, fast_backoff, knob, broken, healthy, needle,  # noqa: F811
):
    transport = FakeRocketCyberTransport()
    setattr(transport, knob, broken)
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert needle in detail
        assert vendor_contact.snapshot(iid)["failure_kind"] == "transport"
        _no_secret(detail)
        setattr(transport, knob, healthy)
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_crash_inside_athena_is_reported_by_class_name_only(
    bedrock_root, status_writes, monkeypatch, caplog,  # noqa: F811
):
    from apps.octo.adapters.rocketcyber.client import RocketCyberClient

    real_fetch = RocketCyberClient.fetch_incidents
    broken = {"on": True}

    def _fetch(self, **kwargs):
        if broken["on"]:
            raise RuntimeError(f"boom MARKER-TEXT {API_KEY}")
        return real_fetch(self, **kwargs)

    monkeypatch.setattr(RocketCyberClient, "fetch_incidents", _fetch)
    caplog.set_level(logging.CRITICAL)
    transport = FakeRocketCyberTransport()
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert "RuntimeError" in detail and "inside Athena" in detail
        assert "MARKER-TEXT" not in detail
        _no_secret(detail)
        broken["on"] = False
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_restart_keeps_the_observed_failure_until_a_poll_reports(
    bedrock_root, fast_backoff,  # noqa: F811
):
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        guidance = get_instance(iid).status_detail
    finally:
        await _stop(manager, iid)
    vendor_contact.reset()
    transport.unreachable = True
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(rocketcyber_adapter_class(transport))
    restarted = InstanceManager(adapter_registry=registry)
    restarted.start_instance(get_instance(iid))
    try:
        assert (get_instance(iid).status, get_instance(iid).status_detail) == ("error", guidance)
        await _until(lambda: "Could not read incidents" in (get_instance(iid).status_detail or ""))
        transport.unreachable = False
        transport.forbid_incidents = False
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(restarted, iid)


@pytest.mark.asyncio
async def test_poll_now_cuts_a_long_backoff_short(bedrock_root):  # noqa: F811
    """PRODUCTION backoff (60 s+): the nudge sent when customer discovery
    succeeds makes the poller look again now."""
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        transport.forbid_incidents = False
        await asyncio.sleep(0.05)
        assert get_instance(iid).status == "error"
        assert manager.nudge(iid) is True
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(manager, iid)


# ---------------------------------------------------------------------------
# Backoff: production constants, bounded, reset on success, never stops
# ---------------------------------------------------------------------------

async def _recorded_delays(transport, script) -> list[float]:
    from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter

    class _Sink:
        def ingest(self, *args):
            return None

    poller = RocketCyberPoller(
        adapter=RocketCyberSourceAdapter(), client=real_client(transport), sink=_Sink(),
        default_tenant_slug="_unmapped",
    )
    delays: list[float] = []

    async def _sleep(seconds: float) -> None:
        delays.append(seconds)
        action = script.get(len(delays))
        if action == "stop":
            poller._stopping.set()
        elif action is not None:
            action()

    poller._sleep_or_stop = _sleep  # type: ignore[method-assign]
    await poller._run()
    return delays


@pytest.mark.asyncio
async def test_forbidden_backoff_doubles_to_a_fifteen_minute_ceiling():
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    delays = await _recorded_delays(transport, {7: "stop"})
    assert delays == [60.0, 120.0, 240.0, 480.0, 900.0, 900.0, 900.0]
    assert transport.count(INCIDENTS_PATH) == 7            # backed off, never stopped


@pytest.mark.asyncio
async def test_backoff_resets_on_the_first_success_and_success_waits_the_interval():
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True

    def _fix() -> None:
        transport.forbid_incidents = False

    def _break() -> None:
        transport.forbid_incidents = True

    delays = await _recorded_delays(transport, {3: _fix, 4: _break, 6: "stop"})
    #          forbidden ×3          ok (5 min)  forbidden again → from the base
    assert delays == [60.0, 120.0, 240.0, 300.0, 60.0, 120.0]


@pytest.mark.asyncio
async def test_transport_failures_back_off_too():
    transport = FakeRocketCyberTransport()
    transport.force_status = 502
    delays = await _recorded_delays(transport, {6: "stop"})
    assert delays == [60.0, 120.0, 240.0, 480.0, 900.0, 900.0]


@pytest.mark.asyncio
async def test_429_waits_what_the_vendor_asks_else_backs_off():
    transport = FakeRocketCyberTransport()
    transport.rate_limited = 2
    transport.retry_after = "42"

    def _no_header() -> None:
        transport.rate_limited = 2
        transport.retry_after = None

    delays = await _recorded_delays(transport, {2: _no_header, 5: "stop"})
    # 42 (asked) · 42 (asked) · 60, 120 (no header: backoff) · 300 (ok)
    assert delays == [42.0, 42.0, 60.0, 120.0, 300.0]


# ---------------------------------------------------------------------------
# The first import waits for the wizard's mapping step
# ---------------------------------------------------------------------------

def _stored(slug: str) -> int:
    import sqlite3

    from apps.octo import paths

    db = paths.client_dir(slug) / "events.db"
    if not db.exists():
        return 0
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def _auto_created() -> set[str]:
    from apps.octo import paths
    from apps.octo.db import connect

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {r[0] for r in reg.execute("SELECT slug FROM clients WHERE origin = 'auto'")}
    finally:
        reg.close()


@pytest.mark.asyncio
async def test_a_new_instance_imports_nothing_until_its_tenant_mapping_is_saved(bedrock_root):  # noqa: F811
    """The wizard steps into tenant mapping right after save, but the first
    cycle ran seconds after save: every customer was auto-linked or
    auto-created before the mapping could be done."""
    from apps.octo.instances import quarantine

    create_client("acme-corp", "Acme Corp")
    transport = FakeRocketCyberTransport()
    transport.incidents = [
        incident(1, account_name="ACME Corporation"),       # named differently in RocketCyber
        incident(2, account_id=2002, account_name="Example Bakery"),
    ]
    manager, iid = _start(transport)
    try:
        await _until(lambda: transport.count(INCIDENTS_PATH) >= 9)      # three cycles read
        assert get_instance(iid).status == "running"                   # the reads work
        assert manager.running_adapter(iid).health().detail["waiting_for_tenant_mapping"] is True
        assert _auto_created() == set() and _stored("acme-corp") == 0
        assert quarantine.list_rows(instance_id=iid)[1] == 0

        set_mappings(iid, [TenantMapping("2001", "acme-corp")])       # the operator maps
        manager.nudge(iid)
        await _until(lambda: _stored("acme-corp") == 1)
        # The customer left unmapped now goes the usual way.
        await _until(lambda: "example-bakery" in _auto_created())
        assert _auto_created() == {"example-bakery"}                   # no "acme-corporation"
        assert manager.running_adapter(iid).health().detail["waiting_for_tenant_mapping"] is False
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_the_first_import_starts_by_itself_when_the_grace_ends(bedrock_root):  # noqa: F811
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    manager, iid = _start(transport, first_import_grace_sec=0.3)
    try:
        await _until(lambda: "acme-corp" in _auto_created())
        assert _stored("acme-corp") == 1
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_an_instance_saved_long_ago_does_not_wait_again_after_a_restart(bedrock_root):  # noqa: F811
    import sqlite3

    from apps.octo import paths

    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    record = create_instance(
        vendor_slug="rocketcyber", display_name="RocketCyber",
        credentials_dict=dict(CREDS), instance_config={"poll_interval_sec": 0.01},
    )
    reg = sqlite3.connect(paths.registry_db_path())
    reg.execute(
        "UPDATE adapter_instances SET configured_at = '2026-01-01T00:00:00.000Z' WHERE id = ?",
        (record.id,),
    )
    reg.commit()
    reg.close()
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(rocketcyber_adapter_class(transport))
    manager = InstanceManager(adapter_registry=registry)
    manager.start_instance(get_instance(record.id))
    try:
        await _until(lambda: _stored("acme-corp") == 1)
    finally:
        await _stop(manager, record.id)
