"""stop() must really stop the poller — from ANY thread.

Regression: stop() scheduled poller.stop() only when the CALLING thread had a
running event loop and swallowed the RuntimeError otherwise. A sync FastAPI
route (threadpool) such as "disable this integration" therefore stopped
nothing: the poller kept polling with the old credentials and kept writing,
and its last reference was dropped. The earlier test used a stub adapter and
only counted stop() calls; this one runs the REAL adapter + REAL poller.
"""
from __future__ import annotations

import asyncio
import threading
import time

from apps.octo.adapters.datto.adapter import DattoSourceAdapter


class _CountingClient:
    def __init__(self, *_a, **_k) -> None:
        self.calls = 0

    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.calls += 1
        return []

    def close(self) -> None:  # pragma: no cover - interface parity
        pass


class _NullSink:
    def ingest(self, *_a, **_k):  # pragma: no cover - no alerts are returned
        raise AssertionError("no alerts expected")


_CREDS = {
    "DATTO_API_URL": "https://rmm.example.test",
    "DATTO_API_KEY": "k" * 8,
    "DATTO_API_SECRET_KEY": "s" * 8,
    "poll_interval_sec": 0.05,
    "_instance_id": 1,
}


def _api_loop() -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
    """A loop running in its own thread — stands in for uvicorn's."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    return loop, t


def test_stop_from_a_threadpool_thread_really_stops_the_poller():
    client = _CountingClient()
    adapter = DattoSourceAdapter(sink=_NullSink(), client_factory=lambda _cfg: client)
    loop, thread = _api_loop()
    try:
        # start() on the API loop, exactly like the create route does
        asyncio.run_coroutine_threadsafe(_call(adapter.start, dict(_CREDS)), loop).result(5)
        _wait_for(lambda: client.calls >= 2)
        poller = adapter._poller

        # stop() from a plain thread with NO running loop (sync route / threadpool)
        adapter.stop()

        calls_at_stop = client.calls
        time.sleep(0.4)                       # 8 poll intervals
        assert client.calls == calls_at_stop, "poller kept polling after stop()"
        assert poller._task is None or poller._task.done()
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(2)


def test_stop_from_the_loop_thread_still_works():
    client = _CountingClient()
    adapter = DattoSourceAdapter(sink=_NullSink(), client_factory=lambda _cfg: client)

    async def scenario() -> int:
        adapter.start(dict(_CREDS))
        while client.calls < 2:
            await asyncio.sleep(0.01)
        adapter.stop()                        # on the loop thread: scheduled, not awaited
        await asyncio.sleep(0.2)
        before = client.calls
        await asyncio.sleep(0.3)
        return client.calls - before

    assert asyncio.run(scenario()) == 0


def test_stop_without_ever_starting_a_loop_is_a_clean_noop():
    adapter = DattoSourceAdapter(sink=_NullSink(), client_factory=lambda _cfg: _CountingClient())
    adapter.start(dict(_CREDS))               # no running loop → poller deferred
    adapter.stop()                            # must not raise
    assert adapter._poller is None


async def _call(fn, *args):
    return fn(*args)


def _wait_for(pred, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")
