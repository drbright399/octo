"""The ONE background worker that looks remote addresses up — so a page
never waits for the network. The alerts API queues the addresses it showed
without a cached answer (`enqueue`); the worker takes them one by one, at
most `RATE_PER_MIN` a minute (every lookup is a few DoH / RDAP requests),
and writes each answer — or a failure, kept an hour — to the cache. The
queue is bounded and de-duplicated; an address already cached (an answer
or a recent failure) is never queued.

`OCTO_IP_ENRICHMENT=off`: nothing is queued and nothing leaves the box.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Iterable, Optional

from apps.octo.enrich import cache, netintel

logger = logging.getLogger(__name__)

ENV = "OCTO_IP_ENRICHMENT"
RATE_PER_MIN = 20
QUEUE_MAX = 500
IDLE_SEC = 5.0


def enabled() -> bool:
    raw = (os.environ.get(ENV) or "on").strip().lower()
    return raw not in ("0", "off", "false", "no")


class EnrichmentWorker:
    def __init__(self, *, intel_factory: Callable[[], Any] = netintel.NetIntel,
                 rate_per_min: int = RATE_PER_MIN,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._factory = intel_factory
        self._rate = max(1, int(rate_per_min))
        self._clock = clock
        self._queue: "OrderedDict[str, None]" = OrderedDict()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sent: list[float] = []
        self.done = 0
        self.failed = 0

    # ----- the queue -----

    def enqueue(self, ips: Iterable[str]) -> int:
        """Queue the addresses that need a lookup. Returns how many were
        added."""
        if not enabled():
            return 0
        wanted = sorted({str(i) for i in ips if netintel.enrichable(i)})
        if not wanted:
            return 0
        held = cache.many(cache.IP, wanted)
        added = 0
        with self._lock:
            for ip in wanted:
                if ip in held or ip in self._queue:
                    continue
                if len(self._queue) >= QUEUE_MAX:
                    break
                self._queue[ip] = None
                added += 1
        if added:
            self._wake.set()
        return added

    def pending(self) -> list[str]:
        with self._lock:
            return list(self._queue)

    def _allow(self) -> bool:
        now = self._clock()
        self._sent = [t for t in self._sent if now - t < 60.0]
        if len(self._sent) >= self._rate:
            return False
        self._sent.append(now)
        return True

    # ----- one batch, synchronous (tests drive it directly) -----

    def run_once(self, max_items: Optional[int] = None) -> int:
        """Look up queued addresses until the queue is empty, the rate is
        spent or `max_items` are done. Never raises."""
        n = 0
        intel = None
        try:
            while max_items is None or n < max_items:
                with self._lock:
                    if not self._queue:
                        break
                    ip = next(iter(self._queue))
                if not self._allow():
                    break
                with self._lock:
                    self._queue.pop(ip, None)
                if cache.get(cache.IP, ip, include_failed=True) is not None:
                    continue
                if intel is None:
                    intel = self._factory()
                try:
                    found = intel.lookup(ip)
                    cache.put(cache.IP, ip, found.as_dict(), ok=True)
                    self.done += 1
                except netintel.NetIntelError as exc:
                    logger.info("[enrich] %s not looked up (%s)", "a remote address",
                                type(exc).__name__)
                    cache.put(cache.IP, ip, {}, ok=False)
                    self.failed += 1
                except Exception as exc:  # noqa: BLE001 — a lookup never kills the worker
                    logger.warning("[enrich] lookup failed (%s)", type(exc).__name__)
                    try:
                        cache.put(cache.IP, ip, {}, ok=False)
                    except Exception:  # noqa: BLE001
                        pass
                    self.failed += 1
                n += 1
        finally:
            if intel is not None and hasattr(intel, "close"):
                try:
                    intel.close()
                except Exception:  # noqa: BLE001
                    pass
        return n

    # ----- lifecycle (a daemon thread beside the API) -----

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="enrichment-worker",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self._thread = None

    def _run(self) -> None:
        last_prune = 0.0
        while not self._stop.is_set():
            try:
                self.run_once()
                if self._clock() - last_prune > 3600:
                    last_prune = self._clock()
                    cache.prune()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[enrich] batch failed (%s)", type(exc).__name__)
            self._wake.wait(IDLE_SEC)
            self._wake.clear()


_WORKER: Optional[EnrichmentWorker] = None


def current() -> Optional[EnrichmentWorker]:
    return _WORKER


def set_current(worker: Optional[EnrichmentWorker]) -> None:
    global _WORKER
    _WORKER = worker


def enqueue(ips: Iterable[str]) -> int:
    w = _WORKER
    return w.enqueue(ips) if w is not None else 0
