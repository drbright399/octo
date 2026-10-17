"""buoy-heartbeat daemon — unit tests for the gatherers + retry queue.

Tests run in CI — they exercise the daemon's pure-Python helpers
without actually shelling out to systemctl on a non-buoy host. The
HTTP path is exercised by mocking urllib.

The integration test (daemon → live OCTO heartbeat endpoint) lives in
slice 4 — done manually on the first live buoy after install.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# heartbeat.py lives outside the test package — sys.path-insert to import.
HEARTBEAT_DIR = Path(__file__).resolve().parents[2] / "buoy"
sys.path.insert(0, str(HEARTBEAT_DIR))

import heartbeat  # type: ignore  # noqa: E402


# ---------------------------------------------------------------------------
# Gatherers — these read from /proc + os.statvfs. Mock the file reads so the
# tests are deterministic regardless of host load.
# ---------------------------------------------------------------------------

def test_read_uptime_sec(tmp_path, monkeypatch):
    fake = tmp_path / "uptime"
    fake.write_text("12345.67 9999.00\n")
    monkeypatch.setattr("builtins.open", _open_redirector({"/proc/uptime": fake}))
    assert heartbeat._read_uptime_sec() == 12345


def test_read_uptime_sec_returns_zero_on_failure(monkeypatch):
    def _no(*args, **kwargs):
        raise OSError("nope")
    monkeypatch.setattr("builtins.open", _no)
    assert heartbeat._read_uptime_sec() == 0


def test_read_loadavg(tmp_path, monkeypatch):
    fake = tmp_path / "loadavg"
    fake.write_text("0.10 0.25 0.40 1/123 4567\n")
    monkeypatch.setattr("builtins.open", _open_redirector({"/proc/loadavg": fake}))
    assert heartbeat._read_loadavg() == (0.10, 0.25, 0.40)


def test_read_mem_mb(tmp_path, monkeypatch):
    fake = tmp_path / "meminfo"
    fake.write_text(
        "MemTotal:        4123456 kB\n"
        "MemFree:           50000 kB\n"
        "MemAvailable:    1500000 kB\n"
        "Buffers:           10000 kB\n"
    )
    monkeypatch.setattr("builtins.open", _open_redirector({"/proc/meminfo": fake}))
    used, total = heartbeat._read_mem_mb()
    # 4123456 KiB total → 4026 MiB (floor div); used = (4123456-1500000)//1024 = 2561
    assert total == 4026
    assert used == 2561


def test_read_mem_mb_missing_total_returns_none(tmp_path, monkeypatch):
    fake = tmp_path / "meminfo"
    fake.write_text("Buffers: 1234 kB\n")
    monkeypatch.setattr("builtins.open", _open_redirector({"/proc/meminfo": fake}))
    assert heartbeat._read_mem_mb() == (None, None)


def test_read_disk_pct(monkeypatch):
    class _Stat:
        f_blocks = 1000
        f_bavail = 250    # 750 used of 1000 = 75%
        f_frsize = 4096
    monkeypatch.setattr(os, "statvfs", lambda p: _Stat())
    assert heartbeat._read_disk_pct("/") == 75


def test_read_service_states(monkeypatch):
    """systemctl is-active shells out — mock subprocess.run."""
    calls: list[list[str]] = []

    class _R:
        def __init__(self, stdout: str):
            self.stdout = stdout

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        unit = cmd[-1]
        return _R({"tailscaled": "active",
                   "broken": "failed",
                   "ghost": ""}.get(unit, "missing") + "\n")

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    out = heartbeat._read_service_states(("tailscaled", "broken", "ghost", "nope"))
    assert out["tailscaled"] == "active"
    assert out["broken"] == "failed"
    # Empty stdout falls back to 'missing'.
    assert out["ghost"] == "missing"
    assert out["nope"] == "missing"
    assert len(calls) == 4


def test_read_enabled_states(monkeypatch):
    """systemctl is-enabled shells out (v0.11 B1) — the subprocess is the
    only thing faked: enabled / disabled / masked as systemd prints them,
    'not-found' for an empty answer, 'unknown' when systemctl cannot run."""
    calls: list[list[str]] = []

    class _R:
        def __init__(self, stdout: str):
            self.stdout = stdout

    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        unit = cmd[-1]
        if unit == "boom":
            raise FileNotFoundError("systemctl")
        return _R({"suricata": "enabled\n", "octo-forwarder": "disabled\n",
                   "nextdns": "masked\n", "ghost": ""}.get(unit, "static\n"))

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    out = heartbeat._read_enabled_states(
        ("suricata", "octo-forwarder", "nextdns", "ghost", "tailscaled", "boom"))
    assert out == {"suricata": "enabled", "octo-forwarder": "disabled", "nextdns": "masked",
                   "ghost": "not-found", "tailscaled": "static", "boom": "unknown"}
    assert all(c[:2] == ["systemctl", "is-enabled"] for c in calls)


def test_gather_heartbeat_reports_each_units_enablement(tmp_path, monkeypatch):
    """The payload carries `enabled` beside each watched unit's state."""
    cfg = _fake_config(tmp_path)
    cfg.services = ("tailscaled", "octo-forwarder")
    monkeypatch.setattr(heartbeat, "_read_uptime_sec", lambda: 1)
    monkeypatch.setattr(heartbeat, "_read_loadavg", lambda: (None, None, None))
    monkeypatch.setattr(heartbeat, "_read_mem_mb", lambda: (None, None))
    monkeypatch.setattr(heartbeat, "_read_disk_pct", lambda p="/": None)
    monkeypatch.setattr(heartbeat, "_read_last_event_at", lambda p: None)
    monkeypatch.setattr(heartbeat, "_read_service_states",
                        lambda u: {"tailscaled": "active", "octo-forwarder": "inactive"})
    monkeypatch.setattr(heartbeat, "_read_enabled_states",
                        lambda u: {"tailscaled": "enabled", "octo-forwarder": "disabled"})
    # The version probes shell out too: state only (the probe module's
    # default shape), so nothing runs on the test host.
    import apps.octo.buoy.services as services_mod

    monkeypatch.setattr(services_mod, "probe_all",
                        lambda states: {u: {"state": s} for u, s in states.items()})
    payload = heartbeat._gather_heartbeat(cfg)
    assert payload["services"]["tailscaled"]["state"] == "active"
    assert payload["services"]["tailscaled"]["enabled"] == "enabled"
    assert payload["services"]["octo-forwarder"]["state"] == "inactive"
    assert payload["services"]["octo-forwarder"]["enabled"] == "disabled"


def test_read_last_event_at_none_when_path_missing():
    assert heartbeat._read_last_event_at(None) is None
    assert heartbeat._read_last_event_at(Path("/no/such/path")) is None


def test_read_last_event_at_strips(tmp_path):
    f = tmp_path / "last"
    f.write_text("  2026-05-15T18:00:00.000Z\n")
    assert heartbeat._read_last_event_at(f) == "2026-05-15T18:00:00.000Z"


# ---------------------------------------------------------------------------
# Retry queue
# ---------------------------------------------------------------------------

def _fake_config(tmp_path) -> "heartbeat.Config":
    c = heartbeat.Config()
    c.octo_url = "http://octo.test:8771"
    c.octo_slug = "alpha"
    c.token = "tok"
    c.services = ("tailscaled",)
    c.last_event_file = None
    c.interval_sec = 60
    c.state_dir = tmp_path
    c.http_timeout_sec = 5
    c.queue_max = 3
    c.lat = None
    c.lng = None
    return c


def test_enqueue_and_drain(tmp_path):
    cfg = _fake_config(tmp_path)
    heartbeat._enqueue(cfg, {"slug": "alpha", "ix": 1})
    heartbeat._enqueue(cfg, {"slug": "alpha", "ix": 2})
    assert heartbeat._queue_path(cfg).exists()
    lines = heartbeat._queue_path(cfg).read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["ix"] == 1

    # Drain with a posting fn that succeeds for everything.
    with patch.object(heartbeat, "_post_heartbeat", return_value=True):
        heartbeat._drain_queue(cfg)
    assert not heartbeat._queue_path(cfg).exists()


def test_enqueue_caps_at_queue_max(tmp_path):
    cfg = _fake_config(tmp_path)
    cfg.queue_max = 3
    for i in range(5):
        heartbeat._enqueue(cfg, {"ix": i})
    lines = heartbeat._queue_path(cfg).read_text().splitlines()
    # Oldest two dropped — only last 3 kept.
    assert len(lines) == 3
    assert [json.loads(l)["ix"] for l in lines] == [2, 3, 4]


def test_drain_stops_on_first_failure_and_requeues_rest(tmp_path):
    cfg = _fake_config(tmp_path)
    cfg.queue_max = 10              # raise cap so all 4 items survive enqueue
    for i in range(4):
        heartbeat._enqueue(cfg, {"ix": i})

    call_count = {"n": 0}

    def _fake_post(_cfg, payload):
        call_count["n"] += 1
        # First two succeed, third fails → drain stops with two left.
        return payload["ix"] < 2

    with patch.object(heartbeat, "_post_heartbeat", side_effect=_fake_post):
        heartbeat._drain_queue(cfg)

    assert call_count["n"] == 3  # tried 0,1,2 — failed on 2
    remaining = heartbeat._queue_path(cfg).read_text().splitlines()
    assert [json.loads(l)["ix"] for l in remaining] == [2, 3]


# ---------------------------------------------------------------------------
# HTTP shape (mocked)
# ---------------------------------------------------------------------------

def test_post_heartbeat_accepted_path(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_http_request",
        return_value=(200, {"accepted": True,
                            "slug": "alpha",
                            "next_expected_by": "2026-01-01T00:00:00Z"}),
    ):
        assert heartbeat._post_heartbeat(cfg, {"slug": "alpha"}) is True


def test_post_heartbeat_rejected_path(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_http_request",
        return_value=(403, {"code": "ISOLATION_VIOLATION"}),
    ):
        assert heartbeat._post_heartbeat(cfg, {"slug": "alpha"}) is False


def test_assert_slug_matches_loud_on_mismatch(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_http_request",
        return_value=(200, {"kind": "buoy", "slug": "beta"}),
    ):
        with pytest.raises(RuntimeError, match="slug mismatch"):
            heartbeat._assert_slug_matches(cfg)


def test_assert_slug_matches_ok_on_match(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_http_request",
        return_value=(200, {"kind": "buoy", "slug": "alpha"}),
    ):
        heartbeat._assert_slug_matches(cfg)   # no raise


# ---------------------------------------------------------------------------
# Migration 021 — geo coord env vars (LAT/LNG)
# ---------------------------------------------------------------------------

def test_parse_float_env_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("LAT", raising=False)
    assert heartbeat._parse_float_env("LAT") is None


def test_parse_float_env_parses_decimal(monkeypatch):
    monkeypatch.setenv("LAT", "39.099724")
    assert heartbeat._parse_float_env("LAT") == 39.099724


def test_parse_float_env_handles_whitespace(monkeypatch):
    monkeypatch.setenv("LAT", "  39.099724  ")
    assert heartbeat._parse_float_env("LAT") == 39.099724


def test_parse_float_env_raises_on_garbage(monkeypatch):
    monkeypatch.setenv("LAT", "north-ish")
    with pytest.raises(RuntimeError, match="LAT"):
        heartbeat._parse_float_env("LAT")


def test_gather_heartbeat_includes_lat_lng_when_set(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    cfg.lat = 39.099724
    cfg.lng = -94.578331
    # Stub the helpers that hit /proc + subprocess so the test runs anywhere.
    monkeypatch.setattr(heartbeat, "_read_uptime_sec", lambda: 123)
    monkeypatch.setattr(heartbeat, "_read_loadavg", lambda: (0.1, 0.2, 0.3))
    monkeypatch.setattr(heartbeat, "_read_mem_mb", lambda: (1024, 4096))
    monkeypatch.setattr(heartbeat, "_read_disk_pct", lambda p="/": 30)
    monkeypatch.setattr(heartbeat, "_read_service_states", lambda u: {})
    monkeypatch.setattr(heartbeat, "_read_enabled_states", lambda u: {})
    monkeypatch.setattr(heartbeat, "_read_last_event_at", lambda p: None)
    # services.probe_all is imported lazily — stub at the source module.
    import sys
    services_mod = sys.modules.get("apps.octo.buoy.services") or sys.modules.get("services")
    if services_mod is not None:
        monkeypatch.setattr(services_mod, "probe_all", lambda s: {})

    payload = heartbeat._gather_heartbeat(cfg)
    assert payload["lat"] == 39.099724
    assert payload["lng"] == -94.578331


def test_gather_heartbeat_omits_lat_lng_when_unset(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    cfg.lat = None
    cfg.lng = None
    monkeypatch.setattr(heartbeat, "_read_uptime_sec", lambda: 123)
    monkeypatch.setattr(heartbeat, "_read_loadavg", lambda: (None, None, None))
    monkeypatch.setattr(heartbeat, "_read_mem_mb", lambda: (None, None))
    monkeypatch.setattr(heartbeat, "_read_disk_pct", lambda p="/": None)
    monkeypatch.setattr(heartbeat, "_read_service_states", lambda u: {})
    monkeypatch.setattr(heartbeat, "_read_enabled_states", lambda u: {})
    monkeypatch.setattr(heartbeat, "_read_last_event_at", lambda p: None)
    import sys
    services_mod = sys.modules.get("apps.octo.buoy.services") or sys.modules.get("services")
    if services_mod is not None:
        monkeypatch.setattr(services_mod, "probe_all", lambda s: {})

    payload = heartbeat._gather_heartbeat(cfg)
    # Keys are omitted entirely when None — distinct from "explicit null".
    assert "lat" not in payload
    assert "lng" not in payload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_redirector(redirects: dict):
    """Return a builtins.open replacement that returns real files for the
    paths listed in `redirects` and falls through to the real `open` for
    everything else (so pytest, json, tempfile, etc. still work)."""
    real_open = open

    def _opener(path, *args, **kwargs):
        if isinstance(path, (str, Path)) and str(path) in redirects:
            return real_open(redirects[str(path)], *args, **kwargs)
        return real_open(path, *args, **kwargs)
    return _opener
