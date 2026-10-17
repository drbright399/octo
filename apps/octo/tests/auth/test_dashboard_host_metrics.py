"""GET /api/v1/dashboard/host-metrics + HostMetricsSampler unit coverage."""
from __future__ import annotations

import asyncio

import pytest

from apps.octo.runtime.host_metrics import HostMetricsSampler

from apps.octo.tests.auth.test_dashboard_throughput import _login


# ---------------------------------------------------------------------------
# Sampler unit tests (no FastAPI, no real psutil)
# ---------------------------------------------------------------------------

def test_sampler_appends_via_stubbed_reader():
    """Reader stub returns predictable values; the sampler aggregates them."""
    seq = iter([(10.0, 20.0), (30.0, 40.0), (50.0, 60.0)])
    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=10,
        reader=lambda: next(seq),
    )
    sampler._sample_once()
    sampler._sample_once()
    sampler._sample_once()
    cpu, mem = sampler.get_window(window_minutes=10, bucket_minutes=1)
    assert [round(p.cpu_pct) for p in cpu] == [10, 30, 50]
    assert [round(p.mem_pct) for p in mem] == [20, 40, 60]


def test_sampler_window_slices_recent_samples():
    """Asking for window_minutes=N returns the last N samples."""
    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=10,
        reader=lambda: (5.0, 5.0),
    )
    for _ in range(7):
        sampler._sample_once()
    cpu, _ = sampler.get_window(window_minutes=3, bucket_minutes=1)
    assert len(cpu) == 3


def test_sampler_bucket_minutes_aggregates_mean():
    """bucket_minutes > 1 groups + averages adjacent samples."""
    vals = iter([(10.0, 0.0), (20.0, 0.0), (30.0, 0.0), (40.0, 0.0)])
    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=10,
        reader=lambda: next(vals),
    )
    for _ in range(4):
        sampler._sample_once()
    cpu, _ = sampler.get_window(window_minutes=10, bucket_minutes=2)
    # 4 samples → 2 buckets of 2 → means [15, 35]
    assert [round(p.cpu_pct) for p in cpu] == [15, 35]


def test_sampler_handles_reader_exceptions():
    """One failing reader call shouldn't break subsequent ones."""
    state = {"count": 0}

    def flaky_reader() -> tuple[float, float]:
        state["count"] += 1
        if state["count"] == 2:
            raise RuntimeError("read failed")
        return (42.0, 42.0)

    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=10, reader=flaky_reader,
    )
    sampler._sample_once()
    sampler._sample_once()  # this one raises internally, skipped
    sampler._sample_once()
    cpu, _ = sampler.get_window(window_minutes=10, bucket_minutes=1)
    # Two successful samples (1st + 3rd); failed one was logged + skipped.
    assert len(cpu) == 2


def test_sampler_buffer_caps_at_max_len():
    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=3,
        reader=lambda: (1.0, 1.0),
    )
    for _ in range(10):
        sampler._sample_once()
    cpu, _ = sampler.get_window(window_minutes=100, bucket_minutes=1)
    assert len(cpu) == 3


# ---------------------------------------------------------------------------
# Endpoint integration test
# ---------------------------------------------------------------------------

def test_endpoint_returns_data_when_sampler_present(auth_client):
    """Wire a sampler with known samples onto app.state; the endpoint
    should slice + return them."""
    sampler = HostMetricsSampler(
        interval_seconds=1, max_len=10,
        reader=lambda: (33.0, 66.0),
    )
    sampler._sample_once()
    sampler._sample_once()
    auth_client.app.state.host_metrics_sampler = sampler

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/host-metrics?window_minutes=10")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["cpu_points"]) == 2
    assert all(p["v"] == 33.0 for p in body["cpu_points"])
    assert all(p["v"] == 66.0 for p in body["mem_points"])


def test_endpoint_returns_empty_when_no_sampler(auth_client):
    """Sampler not wired → empty payload, not 500."""
    # Make sure the attribute is missing or None on app.state.
    if hasattr(auth_client.app.state, "host_metrics_sampler"):
        auth_client.app.state.host_metrics_sampler = None

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/host-metrics")
    assert r.status_code == 200
    assert r.json()["cpu_points"] == []
    assert r.json()["mem_points"] == []
