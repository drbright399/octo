"""Poll outcome → instance row. End to end on the real pieces: a persisted
adapter_instances row, InstanceManager.start_instance, the real
DattoSourceAdapter / DattoClient / DattoPoller — only the vendor socket is
fake (tests/fake_datto.py).

The defect this pins: the row said 'running' / 'started' forever while the
poller logged "HTTP 403" once a minute.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3

import pytest

from apps.octo.adapters.datto import poller as poller_module
from apps.octo.adapters.datto.poller import DattoPoller
from apps.octo.adapters.datto.tests.fake_datto import (
    API_SECRET,
    CREDS,
    FORBIDDEN_QUOTED,
    SECRETS,
    TOKEN_PATH,
    FakeDattoTransport,
    datto_adapter_class,
    real_client,
)
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.instances import InstanceManager, create_instance, unmapped, vendor_contact
from apps.octo.instances import manager as manager_module
from apps.octo.instances.manager import (
    disable_instance,
    get_instance,
    set_contact_status,
)
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

ALERTS_PATH = "/api/v2/account/alerts/open"


@pytest.fixture(autouse=True)
def _clean_contact_state():
    # Process-local state keyed by instance id, and every temp registry starts
    # again at id 1: anything left behind shows up on ANOTHER test's card (a
    # polled alert from an unmapped site is counted as dropped).
    vendor_contact.reset()
    unmapped.reset()
    yield
    vendor_contact.reset()
    unmapped.reset()


@pytest.fixture
def fast_backoff(monkeypatch):
    """Same policy, test-sized delays (production: 60s → 300s)."""
    monkeypatch.setattr(poller_module, "CREDENTIAL_BACKOFF_BASE_SEC", 0.01)
    monkeypatch.setattr(poller_module, "CREDENTIAL_BACKOFF_CEILING_SEC", 0.04)


@pytest.fixture
def status_writes(monkeypatch):
    """Every registry write the reporter makes, passed through to the real one."""
    writes: list[tuple[str, str]] = []
    real = manager_module.set_contact_status

    def _recording(instance_id, *, status, status_detail):
        writes.append((status, status_detail))
        return real(instance_id, status=status, status_detail=status_detail)

    monkeypatch.setattr(manager_module, "set_contact_status", _recording)
    return writes


def _start(transport: FakeDattoTransport):
    record = create_instance(
        vendor_slug="datto",
        display_name="Datto RMM",
        credentials_dict=dict(CREDS),
        instance_config={"poll_interval_sec": 0.01},
    )
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(datto_adapter_class(transport))
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


# ---------------------------------------------------------------------------
# forbidden → 'error' + guidance → recovery → 'running', detail replaced
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_forbidden_poll_flips_the_row_then_recovery_clears_it(
    bedrock_root, fast_backoff, status_writes, caplog,  # noqa: F811
):
    caplog.set_level(logging.DEBUG)
    transport = FakeDattoTransport()
    transport.forbid_data = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        row = get_instance(iid)
        assert row.status_detail.startswith("Datto accepted the API key, but")
        assert "(HTTP 403)" in row.status_detail
        # Uncut: the vendor's words close the detail, after the retry note.
        assert row.status_detail.endswith(FORBIDDEN_QUOTED)
        assert "Setup > Users" in row.status_detail
        assert "keeps retrying" in row.status_detail
        # The key pair is SAVED: regenerating it would force Disable + re-add.
        assert "Do NOT regenerate the API keys" in row.status_detail
        assert vendor_contact.snapshot(iid)["last_ok_at"] is None
        assert vendor_contact.snapshot(iid)["failure_kind"] == "forbidden"

        # It keeps polling (never stops on its own)… Wait on the thing that
        # is asserted: a request being SENT says nothing about its failure
        # having been reported yet (that is two thread hops later).
        await _until(lambda: vendor_contact.snapshot(iid)["consecutive_failures"] >= 5)
        assert transport.count(ALERTS_PATH) >= 5
        # …but the row was written ONCE, on the transition — not per poll.
        assert [status for status, _ in status_writes] == ["error"]

        transport.forbid_data = False        # operator fixed the security level
        await _until(lambda: get_instance(iid).status == "running")
        row = get_instance(iid)
        # No stale error line survives recovery (update_instance_status would
        # have COALESCEd the old one back in).
        assert row.status_detail == vendor_contact.OK_DETAIL
        assert "403" not in row.status_detail
        snap = vendor_contact.snapshot(iid)
        assert snap["last_ok_at"] and snap["consecutive_failures"] == 0

        ok_at = snap["last_ok_at"]
        await _until(lambda: vendor_contact.snapshot(iid)["last_ok_at"] != ok_at)
        assert [status for status, _ in status_writes] == ["error", "running"]
    finally:
        await _stop(manager, iid)

    for status, detail in status_writes:
        for secret in SECRETS:
            assert secret not in detail
    for secret in SECRETS:
        assert secret not in caplog.text


@pytest.mark.asyncio
async def test_healthy_instance_reports_running_once_and_records_contact(
    bedrock_root, status_writes,  # noqa: F811
):
    transport = FakeDattoTransport()
    manager, iid = _start(transport)
    try:
        await _until(lambda: transport.count(ALERTS_PATH) >= 5)
        await _until(lambda: bool(status_writes))
        assert status_writes == [("running", vendor_contact.OK_DETAIL)]
        assert vendor_contact.snapshot(iid)["last_ok_at"] is not None
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("knob", "broken", "healthy", "needle"),
    [
        ("token_status", 401, 200, "rejected credentials (HTTP 401)"),
        ("unreachable", True, False, "Could not read alerts from Datto"),
        ("data_status", 503, 200, "HTTP 503"),
        ("raw_data_body", b"<html>", None, "not JSON"),
    ],
)
async def test_auth_and_transport_failures_also_flip_the_row(
    bedrock_root, fast_backoff, knob, broken, healthy, needle,  # noqa: F811
):
    transport = FakeDattoTransport()
    setattr(transport, knob, broken)
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert needle in detail
        for secret in SECRETS:
            assert secret not in detail
        setattr(transport, knob, healthy)
        await _until(lambda: get_instance(iid).status == "running")
        assert get_instance(iid).status_detail == vendor_contact.OK_DETAIL
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_replace_advice_only_once_the_rejection_has_persisted(
    bedrock_root, fast_backoff, status_writes,  # noqa: F811
):
    """Disable + Add again drops the tenant mappings and the webhook token, so
    one 401 (a vendor-side blip) must not recommend it."""
    transport = FakeDattoTransport()
    transport.token_status = 401
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        first = status_writes[0][1]
        assert "Nothing to do yet" in first and "Disable this integration" not in first
        await _until(lambda: "Disable this integration" in (get_instance(iid).status_detail or ""))
        assert vendor_contact.snapshot(iid)["consecutive_failures"] >= (
            poller_module.AUTH_FAILURES_BEFORE_REPLACE_ADVICE
        )
        assert "no longer works" in get_instance(iid).status_detail
        # Two texts, two writes — still not one per poll.
        assert [status for status, _ in status_writes] == ["error", "error"]
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_poll_that_crashes_inside_athena_flips_the_row_by_class_name_only(
    bedrock_root, status_writes, monkeypatch, caplog,  # noqa: F811
):
    """The 'internal' branch: a bug on OUR side every cycle is still "the most
    recent contact failed". The detail carries the exception CLASS only — an
    arbitrary exception's text is not vetted for what it embeds."""
    from apps.octo.adapters.datto.client import DattoClient

    real_fetch = DattoClient.fetch_alerts_since
    broken = {"on": True}

    def _fetch(self, since_iso, *, max_results=500):
        if broken["on"]:
            raise RuntimeError(f"boom MARKER-TEXT {API_SECRET}")
        return real_fetch(self, since_iso, max_results=max_results)

    monkeypatch.setattr(DattoClient, "fetch_alerts_since", _fetch)
    caplog.set_level(logging.CRITICAL)      # the traceback log is not under test
    transport = FakeDattoTransport()
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        detail = get_instance(iid).status_detail
        assert "RuntimeError" in detail and "inside Athena" in detail
        assert "MARKER-TEXT" not in detail and "boom" not in detail
        for secret in SECRETS:
            assert secret not in detail
        assert vendor_contact.snapshot(iid)["failure_kind"] == "internal"

        broken["on"] = False
        await _until(lambda: get_instance(iid).status == "running")
        assert get_instance(iid).status_detail == vendor_contact.OK_DETAIL
    finally:
        await _stop(manager, iid)
    for _, written in status_writes:
        assert "MARKER-TEXT" not in written


@pytest.mark.asyncio
async def test_a_restart_keeps_the_observed_failure_until_a_poll_reports(
    bedrock_root, fast_backoff,  # noqa: F811
):
    """start_instance used to write running/'started' unconditionally: after a
    process restart a degraded row claimed health until the first poll landed
    — up to two vendor timeouts, exactly when the vendor is timing out."""
    transport = FakeDattoTransport()
    transport.forbid_data = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        guidance = get_instance(iid).status_detail
    finally:
        await _stop(manager, iid)

    # "Restart": process-local state is gone, a new manager starts the row.
    vendor_contact.reset()
    transport.unreachable = True             # and the vendor is not answering
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(datto_adapter_class(transport))
    restarted = InstanceManager(adapter_registry=registry)
    restarted.start_instance(get_instance(iid))
    try:
        # Straight after start(), before any poll has been observed:
        row = get_instance(iid)
        assert (row.status, row.status_detail) == ("error", guidance)
        # The first report is always written, so the row converges.
        await _until(lambda: "Could not read alerts" in (get_instance(iid).status_detail or ""))
        transport.unreachable = False
        transport.forbid_data = False
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(restarted, iid)


def test_an_adapter_that_does_not_report_contact_is_still_marked_running(bedrock_root):  # noqa: F811
    """Only reporting adapters keep their row: for the rest, 'running' after a
    successful start() is all the platform will ever learn."""
    transport = FakeDattoTransport()

    class _Silent(datto_adapter_class(transport)):
        reports_vendor_contact = False

        def start(self, instance_config):   # no poller: nothing reports
            return None

    _Silent.__module__ = "apps.octo.adapters.datto"
    record = create_instance(
        vendor_slug="datto", display_name="Datto RMM", credentials_dict=dict(CREDS),
    )
    manager_module.update_instance_status(
        record.id, status="error", status_detail="adapter.start() raised: fixture",
    )
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(_Silent)
    InstanceManager(adapter_registry=registry).start_instance(get_instance(record.id))
    row = get_instance(record.id)
    assert (row.status, row.status_detail) == ("running", "started")


@pytest.mark.asyncio
async def test_poll_now_cuts_a_long_backoff_short(bedrock_root):  # noqa: F811
    """PRODUCTION backoff (60 s+): after the operator fixes Datto, a nudge —
    sent when site discovery succeeds — makes the poller look again now."""
    transport = FakeDattoTransport()
    transport.forbid_data = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
        transport.forbid_data = False
        await asyncio.sleep(0.05)
        assert get_instance(iid).status == "error"      # still sitting out 60 s
        assert manager.nudge(iid) is True
        await _until(lambda: get_instance(iid).status == "running")
    finally:
        await _stop(manager, iid)
    assert manager.nudge(iid) is False                  # nothing running: no-op


@pytest.mark.asyncio
async def test_the_poller_drains_more_than_one_vendor_page(bedrock_root):  # noqa: F811
    """The fake answers HTTP 400 above 250 per page, as Datto does: the
    default batch (500) used to fail EVERY poll the moment permissions were
    right."""
    transport = FakeDattoTransport()
    transport.alerts = [{"alertUid": f"a-{i}"} for i in range(7)]
    transport.alerts_page_size = 3
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status_detail == vendor_contact.OK_DETAIL)
        assert [q.get("page") for q in transport.alert_queries[:3]] == [None, "1", "2"]
        assert all(int(q["max"]) <= 250 for q in transport.alert_queries)
    finally:
        await _stop(manager, iid)


@pytest.mark.asyncio
async def test_a_late_report_never_revives_a_disabled_row(bedrock_root, fast_backoff):  # noqa: F811
    transport = FakeDattoTransport()
    transport.forbid_data = True
    manager, iid = _start(transport)
    try:
        await _until(lambda: get_instance(iid).status == "error")
    finally:
        await _stop(manager, iid)
    disable_instance(iid, disabled_by_operator_id=None, reason="fixture: replace")
    assert set_contact_status(iid, status="running", status_detail="late") is False
    row = get_instance(iid)
    assert row.status == "disabled" and row.status_detail != "late"


@pytest.mark.asyncio
async def test_registry_write_failure_never_stops_the_poller(
    bedrock_root, fast_backoff, monkeypatch,  # noqa: F811
):
    calls = {"n": 0}
    real = manager_module.set_contact_status

    def _flaky(instance_id, *, status, status_detail):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(instance_id, status=status, status_detail=status_detail)

    monkeypatch.setattr(manager_module, "set_contact_status", _flaky)
    transport = FakeDattoTransport()
    transport.forbid_data = True
    manager, iid = _start(transport)
    try:
        # First write blew up; the poller kept going and the NEXT report landed.
        await _until(lambda: get_instance(iid).status == "error")
        assert calls["n"] == 2
    finally:
        await _stop(manager, iid)


# ---------------------------------------------------------------------------
# Backoff: bounded, capped at a few minutes, reset on success, never stops
# ---------------------------------------------------------------------------

async def _recorded_delays(transport, script) -> list[float]:
    """Run the REAL loop with the PRODUCTION constants; only the sleeping is
    replaced (recorded, then skipped). `script` maps a sleep index to a change
    in the vendor's behaviour."""
    from apps.octo.adapters.datto import DattoSourceAdapter

    class _Sink:
        def ingest(self, *args):
            return None

    poller = DattoPoller(
        adapter=DattoSourceAdapter(), client=real_client(transport), sink=_Sink(),
        default_tenant_slug="_unmapped", poll_interval_sec=30.0,
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
async def test_forbidden_backoff_doubles_to_a_five_minute_ceiling():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    delays = await _recorded_delays(transport, {8: "stop"})
    assert delays == [60.0, 120.0, 240.0, 300.0, 300.0, 300.0, 300.0, 300.0]
    assert max(delays) == poller_module.CREDENTIAL_BACKOFF_CEILING_SEC <= 300.0
    # Still asking the vendor on every cycle — backed off, never stopped.
    assert transport.count(ALERTS_PATH) == 8
    # A fresh token per attempt, so fixed permissions are picked up.
    assert transport.count(TOKEN_PATH) == 8


@pytest.mark.asyncio
async def test_backoff_resets_on_the_first_success():
    transport = FakeDattoTransport()
    transport.forbid_data = True

    def _fix() -> None:
        transport.forbid_data = False

    def _break() -> None:
        transport.forbid_data = True

    delays = await _recorded_delays(transport, {3: _fix, 4: _break, 6: "stop"})
    #          forbidden ×3          ok    forbidden again → from the base
    assert delays == [60.0, 120.0, 240.0, 30.0, 60.0, 120.0]


@pytest.mark.asyncio
async def test_rejected_credentials_back_off_the_same_way():
    transport = FakeDattoTransport()
    transport.token_status = 401
    delays = await _recorded_delays(transport, {5: "stop"})
    assert delays == [60.0, 120.0, 240.0, 300.0, 300.0]


def test_backoff_survives_a_key_left_forbidden_for_months():
    backoff = vendor_contact.FailureBackoff(base_sec=60.0, ceiling_sec=300.0)
    assert {backoff.next() for _ in range(100_000)} == {60.0, 120.0, 240.0, 300.0}
    backoff.reset()
    assert backoff.next() == 60.0
