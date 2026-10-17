"""DattoPoller — cursor advance, timestamp normalization, error handling."""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.poller import DattoPoller


class _StubClient:
    def __init__(self, batches):
        self._batches = list(batches)
        self.seen_cursors: list[str] = []
    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.seen_cursors.append(since_iso)
        if not self._batches:
            return []
        return self._batches.pop(0)


class _RecorderSink:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, CanonicalEvent]] = []
    def ingest(self, tenant_slug: str, source: str, event: CanonicalEvent):
        self.calls.append((tenant_slug, source, event))


def _datto_alert(idx: int, *, ts, site_uid: str | None = "site-acme"):
    return {
        "alertUid": f"alert-{idx}",
        "alertPriority": "Moderate",
        "alertCategory": "perf_threshold",
        "alertContext": {"message": f"alert {idx}"},
        "timestamp": ts,
        "device": {"hostname": f"host-{idx}"},
        "siteUid": site_uid,
    }


# ---------------------------------------------------------------------------
# Drain + cursor
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_drain_extracts_and_ingests_each_alert():
    adapter = DattoSourceAdapter()
    client = _StubClient([
        [
            _datto_alert(1, ts=1700000001),
            _datto_alert(2, ts=1700000002),
        ],
    ])
    sink = _RecorderSink()
    poller = DattoPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2023-01-01T00:00:00.000Z",
    )
    await poller._drain_once()
    assert len(sink.calls) == 2
    assert sink.calls[0][0] == "site-acme"
    assert sink.calls[0][2].vendor_event_id == "alert-1"
    # Cursor advances to latest seen (converted to ISO)
    assert poller.cursor.startswith("2023-11-14T")


@pytest.mark.asyncio
async def test_drain_handles_iso_timestamps_too():
    """Some Datto endpoints return ISO strings, others epoch — both work."""
    adapter = DattoSourceAdapter()
    client = _StubClient([
        [_datto_alert(1, ts="2026-05-11T08:00:00.000Z")],
    ])
    poller = DattoPoller(
        adapter=adapter, client=client, sink=_RecorderSink(),
        default_tenant_slug="x",
        initial_cursor="2026-05-11T07:00:00.000Z",
    )
    await poller._drain_once()
    assert poller.cursor == "2026-05-11T08:00:00.000Z"


@pytest.mark.asyncio
async def test_empty_batch_leaves_cursor_unchanged():
    adapter = DattoSourceAdapter()
    client = _StubClient([[]])
    initial = "2023-01-01T00:00:00.000Z"
    poller = DattoPoller(
        adapter=adapter, client=client, sink=_RecorderSink(),
        default_tenant_slug="x", initial_cursor=initial,
    )
    await poller._drain_once()
    assert poller.cursor == initial


# ---------------------------------------------------------------------------
# Tenant routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_explicit_tenant_label_used():
    adapter = DattoSourceAdapter()
    raw = _datto_alert(1, ts=1700000001, site_uid="site-x")
    raw["_octo_tenant_slug"] = "explicit-tenant"
    client = _StubClient([
        [raw],
    ])
    sink = _RecorderSink()
    poller = DattoPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="default-msp",
        initial_cursor="2023-01-01T00:00:00.000Z",
    )
    await poller._drain_once()
    assert sink.calls[0][0] == "explicit-tenant"


@pytest.mark.asyncio
async def test_default_tenant_when_unrouted():
    adapter = DattoSourceAdapter()
    raw = _datto_alert(1, ts=1700000001)
    raw.pop("siteUid", None)
    client = _StubClient([
        [raw],
    ])
    sink = _RecorderSink()
    poller = DattoPoller(
        adapter=adapter, client=client, sink=sink,
        default_tenant_slug="fallback",
        initial_cursor="2023-01-01T00:00:00.000Z",
    )
    await poller._drain_once()
    assert sink.calls[0][0] == "fallback"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stop_signals_cleanly():
    adapter = DattoSourceAdapter()
    poller = DattoPoller(
        adapter=adapter, client=_StubClient([]), sink=_RecorderSink(),
        default_tenant_slug="x",
        initial_cursor="2023-01-01T00:00:00.000Z",
        poll_interval_sec=0.05,
    )
    await poller.start()
    await asyncio.sleep(0.15)
    await poller.stop()
    await poller.stop()  # idempotent


# ---------------------------------------------------------------------------
# Cursor hygiene
# ---------------------------------------------------------------------------

def test_garbage_timestamp_can_never_become_the_cursor():
    """'zzz' used to win the max() (it sorts above every ISO value) and was
    then sent to Datto as `after=`."""
    got = DattoPoller._latest_timestamp([
        {"timestamp": "zzz"},
        {"timestamp": True},
        {"timestamp": -5},
        {"timestamp": 1789819200},
    ])
    assert got == "2026-09-19T12:00:00.000Z"
    assert DattoPoller._latest_timestamp([{"timestamp": "zzz"}]) is None


def test_latest_timestamp_orders_mixed_precision_and_offsets():
    got = DattoPoller._latest_timestamp([
        {"timestamp": "2026-09-19T12:00:00.500Z"},
        {"timestamp": "2026-09-19T12:00:00Z"},        # 'Z' > '.' lexically
        {"timestamp": "2026-09-19T07:00:00-05:00"},   # same instant as above
    ])
    assert got == "2026-09-19T12:00:00.500Z"


@pytest.mark.asyncio
async def test_garbage_only_batch_leaves_cursor_unchanged():
    initial = "2026-05-11T07:00:00.000Z"
    poller = DattoPoller(
        adapter=DattoSourceAdapter(),
        client=_StubClient([[_datto_alert(1, ts="Sat Sep 19 12:00:00 2026")]]),
        sink=_RecorderSink(), default_tenant_slug="x", initial_cursor=initial,
    )
    await poller._drain_once()
    assert poller.cursor == initial


# ---------------------------------------------------------------------------
# Restart re-poll → zero new rows (idempotency lives in the sink)
# ---------------------------------------------------------------------------

def _provision_events_db(client_dir: Path) -> None:
    """Apply migration 002's `events` section, as client provisioning does."""
    client_dir.mkdir(parents=True)
    sql = (
        Path(__file__).resolve().parents[3]
        / "migrations" / "002-initialize-client-dbs.sql"
    ).read_text()
    lines: list[str] = []
    current = None
    for line in sql.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
        elif current == "events":
            lines.append(line)
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.executescript("\n".join(lines))
        conn.commit()
    finally:
        conn.close()


def _row_count(data_root: Path, slug: str) -> int:
    conn = sqlite3.connect(data_root / "clients" / slug / "events.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_restart_repolling_the_same_open_alerts_writes_zero_new_rows(tmp_path):
    """The cursor is in-memory, so every container restart re-reads the
    lookback window. The second 'process' must add nothing."""
    from apps.octo.ingest import SqliteIngestSink

    _provision_events_db(tmp_path / "clients" / "site-acme")
    open_alerts = [
        _datto_alert(1, ts=1700000001),
        _datto_alert(2, ts="2023-11-14T22:13:22Z"),
    ]

    async def _one_process_lifetime() -> None:
        poller = DattoPoller(
            adapter=DattoSourceAdapter(),
            client=_StubClient([[dict(a) for a in open_alerts]]),
            sink=SqliteIngestSink(data_root=tmp_path, publish_to_stream=False),
            default_tenant_slug="site-acme",
            initial_cursor="2023-01-01T00:00:00.000Z",
        )
        await poller._drain_once()

    await _one_process_lifetime()
    assert _row_count(tmp_path, "site-acme") == 2
    await _one_process_lifetime()   # restart: fresh poller, same open alerts
    assert _row_count(tmp_path, "site-acme") == 2


# ---------------------------------------------------------------------------
# Unmapped vendor tenants are never dropped: with a persisted instance the
# platform auto-links / auto-creates / quarantines (see
# test_tenant_autocreate_poll.py). A poller WITHOUT an instance id routes by
# vendor id and the sink alone decides.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poller_without_instance_routes_by_vendor_id(tmp_path):
    from apps.octo.ingest import SqliteIngestSink

    poller = DattoPoller(
        adapter=DattoSourceAdapter(),
        client=_StubClient([[
            _datto_alert(1, ts=1700000001, site_uid="site-nobody-mapped"),
        ]]),
        sink=SqliteIngestSink(data_root=tmp_path, publish_to_stream=False),
        default_tenant_slug="_unmapped",
        initial_cursor="2023-01-01T00:00:00.000Z",
    )
    await poller._drain_once()          # unprovisioned tenant: logged, not raised
    assert not (tmp_path / "clients" / "site-nobody-mapped").exists()
