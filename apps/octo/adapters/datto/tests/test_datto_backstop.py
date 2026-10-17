"""N0 — the Datto poll backstop (Tier Black slice 1): the alerts RESOLVED
since a cursor are read (read-only) and the ones the open list never showed
— an auto-resolving monitor opens and resolves between two polls — are
ingested once; a first start begins at "now" (never a backlog); the cursor
and the uids seen survive a restart; a backstop failure never fails the open
poll; an open list at its cap is reported (`intake_health`) for FR2."""
from __future__ import annotations

import time
from typing import Any

import pytest

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.client import RESOLVED_ALERTS_PATH
from apps.octo.adapters.datto.poller import BACKSTOP_STATE_KEY, DattoPoller



def _soon() -> int:
    """Vendor times just after "now" (the backstop's first cursor is its
    start) — read per test: a module-level value is minutes old by the time
    a full suite reaches these tests."""
    return int(time.time()) + 5


def _alert(idx: int, ts: int, *, resolved: bool = False) -> dict[str, Any]:
    return {"alertUid": f"alert-{idx}", "alertPriority": "Information",
            "alertCategory": "eventlog", "alertContext": {"message": f"event {idx}"},
            "timestamp": ts, "device": {"hostname": f"ws-{idx:02d}"}, "siteUid": "site-acme",
            "resolved": resolved}


class _Client:
    def __init__(self, open_batches, resolved_batches=None, *, resolved_error=None):
        self.open = list(open_batches)
        self.resolved = list(resolved_batches or [])
        self.resolved_error = resolved_error
        self.resolved_cursors: list[str] = []

    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        return self.open.pop(0) if self.open else []

    def fetch_resolved_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.resolved_cursors.append(since_iso)
        if self.resolved_error is not None:
            raise self.resolved_error
        return self.resolved.pop(0) if self.resolved else []


class _Sink:
    def __init__(self) -> None:
        self.uids: list[str] = []

    def ingest(self, tenant_slug, source, event):
        self.uids.append(event.vendor_event_id)


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _poller(client, sink, clock, *, max_batch: int = 500, instance_id=None) -> DattoPoller:
    return DattoPoller(adapter=DattoSourceAdapter(), client=client, sink=sink,
                       default_tenant_slug="acme-corp", max_batch=max_batch,
                       backstop_every_sec=300.0, clock=clock, instance_id=instance_id)


@pytest.mark.asyncio
async def test_resolved_alerts_the_open_list_never_showed_are_ingested_once():
    SOON = _soon()
    clock = _Clock()
    client = _Client([[_alert(1, SOON)], []],
                     [[_alert(1, SOON, resolved=True),                # seen open: skipped
                       _alert(2, SOON + 60, resolved=True)],          # opened + resolved
                      [_alert(2, SOON + 60, resolved=True)]])        # again: skipped
    sink = _Sink()
    p = _poller(client, sink, clock)
    await p._drain_once()                                            # open poll only
    assert client.resolved_cursors == [] and sink.uids == ["alert-1"]
    clock.t += 301
    await p._drain_once()                                            # + the backstop
    assert sink.uids == ["alert-1", "alert-2"]
    clock.t += 301
    await p._drain_once()
    assert sink.uids == ["alert-1", "alert-2"]                       # never twice
    # The cursor moved to the newest resolved alert's time.
    assert client.resolved_cursors[-1] > client.resolved_cursors[0]


@pytest.mark.asyncio
async def test_a_first_start_begins_now_never_a_backlog():
    client = _Client([[]], [[]])
    p = _poller(client, _Sink(), _Clock())
    assert p.backstop_once() == 0
    (cursor,) = client.resolved_cursors
    assert cursor > "2026-01-01"                                     # now, not 1970 / 24 h


def test_the_backstop_survives_a_restart(monkeypatch):
    from apps.octo.instances import poller_state

    SOON = _soon()
    stored: list[str] = []
    monkeypatch.setattr(DattoPoller, "_ingest_one",
                        lambda self, raw: stored.append(raw["alertUid"]) or True)
    store: dict[tuple[int, str], Any] = {}
    monkeypatch.setattr(poller_state, "load", lambda iid, key: store.get((iid, key)))
    monkeypatch.setattr(poller_state, "save",
                        lambda iid, key, value: store.__setitem__((iid, key), value) or True)
    client = _Client([], [[_alert(4, SOON + 100, resolved=True)]])
    sink = _Sink()
    p = _poller(client, sink, _Clock(), instance_id=7)
    assert p.backstop_once() == 1 and stored == ["alert-4"]
    saved = store[(7, BACKSTOP_STATE_KEY)]
    assert "alert-4" in saved["seen"] and saved["cursor"] > "2026-01-01"
    # A restart: the same resolved alert is not stored again.
    again = _poller(client, sink, _Clock(), instance_id=7)
    client.resolved = [[_alert(4, SOON + 100, resolved=True)]]
    assert again.backstop_once() == 0 and stored == ["alert-4"]
    assert client.resolved_cursors[-1] == saved["cursor"]


@pytest.mark.asyncio
async def test_a_backstop_failure_never_fails_the_open_poll():
    clock = _Clock()
    client = _Client([[_alert(1, 1_759_500_000)]], resolved_error=RuntimeError("boom"))
    sink = _Sink()
    p = _poller(client, sink, clock)
    clock.t += 301
    await p._drain_once()                                            # does not raise
    assert sink.uids == ["alert-1"]
    assert p.intake_health()["backstop_error"] == "RuntimeError"


@pytest.mark.asyncio
async def test_the_open_list_cap_is_reported():
    client = _Client([[_alert(n, 1_759_500_000 + n) for n in range(3)],
                      [_alert(n, 1_759_500_100 + n) for n in range(3, 6)],
                      [_alert(9, 1_759_500_200)]])
    p = _poller(client, _Sink(), _Clock(), max_batch=3)
    await p._drain_once()
    since = p.intake_health()["capped_since"]
    assert since is not None
    await p._drain_once()
    assert p.intake_health()["capped_since"] == since                # the run's start kept
    await p._drain_once()
    assert p.intake_health()["capped_since"] is None                 # drained


def test_the_resolved_path_is_read_only():
    assert RESOLVED_ALERTS_PATH == "/api/v2/account/alerts/resolved"
