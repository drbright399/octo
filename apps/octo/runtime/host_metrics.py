"""Container/host metrics sampler.

Background asyncio worker that samples the OCTO container's CPU + memory
utilization every ~60s, maintains a 24h ring buffer in memory, and
serves bucketed slices to /api/v1/dashboard/host-metrics.

Universal function — the sampler reads whatever host the container is
running on. In a deployed OCTO bundle that's the container's allocation
inside the bundle host; in dev that's whatever box the developer is
running on. No environment-specific code paths.

Sampling cadence: 60 seconds. The ring buffer keeps 1440 entries =
24h at 1-minute granularity. Endpoint callers ask for a window in
minutes; the sampler returns the most recent N entries optionally
aggregated into coarser buckets (mean within each output bucket).

Cost: psutil.cpu_percent() across one core takes microseconds; the
sampler reads non-blocking percpu=False. Memory footprint of the
buffer is ~80KB (1440 entries × tuple overhead).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


logger = logging.getLogger(__name__)


SAMPLE_INTERVAL_SECONDS = 60
"""How often to sample CPU + memory. 60s gives 1m granularity, which
matches the throughput sparkline's 1m buckets at the 15m / 1h preset."""

RING_BUFFER_MAX_LEN = 24 * 60  # 24h at 1m granularity
"""Ring buffer entry count. Older samples drop off the left as new
ones append on the right — classic deque(maxlen=...) behavior."""


@dataclass(frozen=True)
class HostMetricSample:
    """One point-in-time reading. Timestamps are stored as UTC ISO
    strings so the dashboard's bucketing logic can stay string-based."""
    t: str
    cpu_pct: float
    mem_pct: float


class HostMetricsSampler:
    """Long-running asyncio task that maintains a ring buffer of
    CPU + memory readings. Singleton-per-app — created in
    create_app() and stored on app.state."""

    def __init__(
        self,
        *,
        interval_seconds: int = SAMPLE_INTERVAL_SECONDS,
        max_len: int = RING_BUFFER_MAX_LEN,
        # Test seam: lets pytest inject a synthetic reader without
        # importing psutil. Production path uses the real psutil
        # functions via _real_reader() below.
        reader: Optional[callable] = None,  # type: ignore[type-arg]
    ) -> None:
        self._interval = interval_seconds
        self._buffer: deque[HostMetricSample] = deque(maxlen=max_len)
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._reader = reader or _real_reader

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        # Prime with one immediate sample so the endpoint isn't empty
        # for the first interval after boot.
        self._sample_once()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        try:
            await asyncio.wait_for(self._task, timeout=self._interval + 2)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    def _sample_once(self) -> None:
        try:
            cpu, mem = self._reader()
        except Exception:  # noqa: BLE001
            logger.exception("host metrics sample failed; skipping tick")
            return
        sample = HostMetricSample(
            t=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z"),
            cpu_pct=round(cpu, 2),
            mem_pct=round(mem, 2),
        )
        self._buffer.append(sample)

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                # Run psutil's CPU read in a thread — psutil.cpu_percent
                # blocks briefly on first call to seed the delta.
                await asyncio.to_thread(self._sample_once)
            except Exception:  # noqa: BLE001
                logger.exception("host metrics tick crashed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(),
                    timeout=self._interval,
                )
            except asyncio.TimeoutError:
                pass

    def get_window(
        self, *, window_minutes: int, bucket_minutes: int = 1,
    ) -> tuple[list[HostMetricSample], list[HostMetricSample]]:
        """Return (cpu_points, mem_points) for the most recent
        `window_minutes` of samples, aggregated to `bucket_minutes`
        buckets (mean within each bucket).

        For bucket_minutes=1 this is just the raw samples. For larger
        buckets we group adjacent samples and average them.
        """
        if not self._buffer:
            return [], []
        # Latest N samples (1 sample per minute → N = window_minutes).
        samples = list(self._buffer)[-window_minutes:]
        if bucket_minutes <= 1:
            cpu = [
                HostMetricSample(t=s.t, cpu_pct=s.cpu_pct, mem_pct=0)
                for s in samples
            ]
            mem = [
                HostMetricSample(t=s.t, cpu_pct=0, mem_pct=s.mem_pct)
                for s in samples
            ]
            return cpu, mem
        # Aggregate into buckets — group samples by integer division
        # of their position into bucket_minutes.
        cpu_out: list[HostMetricSample] = []
        mem_out: list[HostMetricSample] = []
        for i in range(0, len(samples), bucket_minutes):
            chunk = samples[i:i + bucket_minutes]
            if not chunk:
                continue
            avg_cpu = sum(s.cpu_pct for s in chunk) / len(chunk)
            avg_mem = sum(s.mem_pct for s in chunk) / len(chunk)
            # Use the chunk's last timestamp as the bucket label —
            # consistent with throughput's "bucket-end" anchoring.
            t = chunk[-1].t
            cpu_out.append(HostMetricSample(t=t, cpu_pct=round(avg_cpu, 2), mem_pct=0))
            mem_out.append(HostMetricSample(t=t, cpu_pct=0, mem_pct=round(avg_mem, 2)))
        return cpu_out, mem_out


def _real_reader() -> tuple[float, float]:
    """Production sampler — reads /proc via psutil. Imports inside
    the function so the test path (with a stub reader) doesn't need
    psutil installed."""
    import psutil
    # interval=None means "since last call" — fast, non-blocking
    # after the priming call.
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    return cpu, mem
