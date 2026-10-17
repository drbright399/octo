"""WazuhPoller — cursor advance, ingest fanout, error handling.

The HTTP client is mocked — we don't need a live Wazuh manager to
verify the loop's behavior. Real-Wazuh testing happens against a
docker-compose smoke harness in integration tests (out of scope here).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.adapters.wazuh.client import WazuhAuthError, WazuhClientError
from apps.octo.adapters.wazuh.poller import WazuhPoller


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _StubClient:
    """Returns the configured batch on next fetch; tracks the cursor seen."""

    def __init__(
        self,
        batches: list[list[dict[str, Any]]],
    ) -> None:
        self._batches = list(batches)
        self.seen_cursors: list[str] = []

    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.seen_cursors.append(since_iso)
        if not self._batches:
            return []
        return self._batches.pop(0)


class _RecorderSink:
    """Records all ingest() calls in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, CanonicalEvent]] = []

    def ingest(self, tenant_slug: str, source: str, event: CanonicalEvent):
        self.calls.append((tenant_slug, source, event))


def _wazuh_alert(idx: int, *, ts: str, tenant_label: str | None = None):
    """Build a minimal Wazuh-shaped alert envelope for tests."""
    labels = {"_octo_tenant_slug": tenant_label} if tenant_label else {}
    return {
        "id": f"evt-{idx}",
        "timestamp": ts,
        "rule": {
            "id": "5503",
            "level": 7,
            "description": "Test alert",
            "groups": ["pam"],
        },
        "agent": {"id": "001", "name": f"buoy-{idx}", "labels": labels},
        "data": {},
    }


# ---------------------------------------------------------------------------
# Drain + cursor
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_drain_extracts_and_ingests_each_alert():
    """Two alerts in the batch → two ingest() calls in order, cursor
    advances to the latest timestamp."""
    adapter = WazuhSourceAdapter()
    client = _StubClient([
        [
            _wazuh_alert(1, ts="2026-05-11T08:00:01.000Z"),
            _wazuh_alert(2, ts="2026-05-11T08:00:02.000Z"),
        ],
    ])
    sink = _RecorderSink()
    poller = WazuhPoller(
        adapter=adapter,
        client=client,
        sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
    )
    await poller._drain_once()
    assert len(sink.calls) == 2
    assert sink.calls[0][2].vendor_event_id == "evt-1"
    assert sink.calls[1][2].vendor_event_id == "evt-2"
    # Cursor advances to latest seen
    assert poller.cursor == "2026-05-11T08:00:02.000Z"


@pytest.mark.asyncio
async def test_empty_batch_leaves_cursor_unchanged():
    adapter = WazuhSourceAdapter()
    client = _StubClient([[]])
    sink = _RecorderSink()
    initial = "2026-05-11T08:00:00.000Z"
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor=initial,
    )
    await poller._drain_once()
    assert poller.cursor == initial
    assert sink.calls == []


@pytest.mark.asyncio
async def test_cursor_only_advances_forward():
    """If the indexer returns an alert with an older timestamp than our
    cursor (shouldn't happen but defensive), the cursor stays put."""
    adapter = WazuhSourceAdapter()
    initial = "2026-05-11T09:00:00.000Z"
    client = _StubClient([
        [_wazuh_alert(1, ts="2026-05-11T08:00:00.000Z")],  # OLDER than cursor
    ])
    sink = _RecorderSink()
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor=initial,
    )
    await poller._drain_once()
    # Event still ingested (we got it from the indexer; trust it)
    assert len(sink.calls) == 1
    # But cursor doesn't go backward
    assert poller.cursor == initial


# ---------------------------------------------------------------------------
# Tenant routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_explicit_tenant_label_used_when_present():
    adapter = WazuhSourceAdapter()
    client = _StubClient([
        [_wazuh_alert(1, ts="2026-05-11T08:00:01.000Z", tenant_label="acme-msp")],
    ])
    sink = _RecorderSink()
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
    )
    await poller._drain_once()
    assert sink.calls[0][0] == "acme-msp"


@pytest.mark.asyncio
async def test_falls_back_to_default_tenant_when_unrouted():
    adapter = WazuhSourceAdapter()
    client = _StubClient([
        [_wazuh_alert(1, ts="2026-05-11T08:00:01.000Z")],  # no tenant label, no group
    ])
    sink = _RecorderSink()
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="fallback-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
    )
    await poller._drain_once()
    assert sink.calls[0][0] == "fallback-msp"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class _FailingSink:
    def __init__(self, exc):
        self.exc = exc
        self.attempts = 0
    def ingest(self, tenant_slug, source, event):
        self.attempts += 1
        raise self.exc


@pytest.mark.asyncio
async def test_per_event_ingest_failure_does_not_stop_batch():
    """One bad event in a batch should not block the rest."""
    adapter = WazuhSourceAdapter()
    client = _StubClient([
        [
            _wazuh_alert(1, ts="2026-05-11T08:00:01.000Z"),
            _wazuh_alert(2, ts="2026-05-11T08:00:02.000Z"),
        ],
    ])
    sink = _FailingSink(RuntimeError("boom"))
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
    )
    # Both attempts run despite the first raising
    await poller._drain_once()
    assert sink.attempts == 2


@pytest.mark.asyncio
async def test_missing_tenant_db_logged_not_raised(caplog):
    """If the tenant isn't provisioned, ingest raises FileNotFoundError;
    poller logs + continues to the next event."""
    adapter = WazuhSourceAdapter()
    client = _StubClient([
        [_wazuh_alert(1, ts="2026-05-11T08:00:01.000Z", tenant_label="ghost-tenant")],
    ])
    sink = _FailingSink(FileNotFoundError("events.db missing for tenant 'ghost-tenant'"))
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
    )
    # No exception bubbles up — pollers must keep running through
    # mid-onboarding transitional states.
    await poller._drain_once()


# ---------------------------------------------------------------------------
# Start / stop lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stop_signals_cleanly():
    """Start the loop, signal stop, expect graceful exit within the timeout."""
    adapter = WazuhSourceAdapter()
    client = _StubClient([])  # empty batches forever
    sink = _RecorderSink()
    poller = WazuhPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2026-05-11T08:00:00.000Z",
        poll_interval_sec=0.05,  # tight for the test
    )
    await poller.start()
    await asyncio.sleep(0.15)
    await poller.stop()
    # Idempotent — calling stop again is fine
    await poller.stop()
