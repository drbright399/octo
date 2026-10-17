"""Tests for apps/octo/buoy/services.py — the per-unit probe module
that powers the heartbeat-services contract extension (2026-05-19)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# services.py lives in the buoy daemon dir — same sys.path insertion
# pattern as test_heartbeat_daemon.py.
BUOY_DIR = Path(__file__).resolve().parents[2] / "buoy"
sys.path.insert(0, str(BUOY_DIR))

import services  # type: ignore  # noqa: E402


# ---------------------------------------------------------------------------
# _first_semver
# ---------------------------------------------------------------------------

def test_first_semver_extracts_dotted_version():
    assert services._first_semver("tailscale version 1.86.2") == "1.86.2"
    assert services._first_semver("This is Suricata version 7.0.3 RELEASE") == "7.0.3"
    # Pre/post-release suffixes captured when present.
    assert services._first_semver("Build 1.2.3-beta1") == "1.2.3-beta1"

def test_first_semver_returns_none_on_no_match():
    assert services._first_semver("no version info here") is None
    assert services._first_semver("") is None

def test_first_semver_takes_first_when_multiple():
    assert services._first_semver("module 1.0.0 dep 2.5.0") == "1.0.0"


# ---------------------------------------------------------------------------
# ServiceProbeResult.to_dict — Nones dropped, state always present
# ---------------------------------------------------------------------------

def test_to_dict_drops_none_fields():
    r = services.ServiceProbeResult(state="active", version="1.0", stat=None, last_activity=None)
    assert r.to_dict() == {"state": "active", "version": "1.0"}

def test_to_dict_includes_all_present_fields():
    r = services.ServiceProbeResult(
        state="active", version="1.0", stat="42/min",
        last_activity="2026-05-19T14:00:00Z",
    )
    assert r.to_dict() == {
        "state": "active", "version": "1.0", "stat": "42/min",
        "last_activity": "2026-05-19T14:00:00Z",
    }

def test_to_dict_state_only():
    r = services.ServiceProbeResult(state="failed")
    assert r.to_dict() == {"state": "failed"}


# ---------------------------------------------------------------------------
# Probe behavior — mock subprocess.run
# ---------------------------------------------------------------------------

class _FakeCompleted:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_probe_tailscaled_parses_version(monkeypatch):
    """probe_tailscaled calls `tailscale version` AND systemctl for
    last_activity. Fake responds to each by argv shape."""
    def fake_run(args, **kwargs):
        if args == ["tailscale", "version"]:
            return _FakeCompleted(0, "1.86.2\n  go: 1.23.0\n")
        # last_activity path: systemctl show + date — return harmless.
        return _FakeCompleted(-1, "", "stubbed")
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    r = services._probe_tailscaled("tailscaled", "active")
    assert r.state == "active"
    assert r.version == "1.86.2"


def test_probe_wazuh_agent_parses_quoted_version(monkeypatch):
    def fake_run(args, **kwargs):
        if args[0] == "/var/ossec/bin/wazuh-control":
            return _FakeCompleted(0, 'WAZUH_VERSION="v4.9.2"\nWAZUH_REVISION="40916"\n')
        # systemctl show ActiveEnterTimestamp
        return _FakeCompleted(1, "", "no such unit")
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    r = services._probe_wazuh_agent("wazuh-agent", "active")
    assert r.version == "4.9.2"


def test_probe_default_only_calls_systemctl(monkeypatch):
    """Unknown unit → no version probe, just last_activity from systemd."""
    called = []
    def fake_run(args, **kwargs):
        called.append(args)
        if args[:2] == ["systemctl", "show"]:
            return _FakeCompleted(
                0, "ActiveEnterTimestamp=Mon 2026-05-19 04:21:53 UTC",
            )
        if args[0] == "date":
            return _FakeCompleted(0, "2026-05-19T04:21:53Z\n")
        return _FakeCompleted(-1, "", "unexpected")
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    r = services._probe_default("custom-daemon", "active")
    assert r.state == "active"
    assert r.version is None
    assert r.last_activity == "2026-05-19T04:21:53Z"
    # First call is systemctl show — no unrelated probes.
    assert called[0][:2] == ["systemctl", "show"]


def test_probe_failure_yields_none_version(monkeypatch):
    """Probe subprocess errors must not blow up heartbeat — fields go None."""
    def fake_run(args, **kwargs):
        raise FileNotFoundError("tailscale not installed")
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    r = services._probe_tailscaled("tailscaled", "active")
    assert r.state == "active"
    assert r.version is None


def test_probe_timeout_yields_none(monkeypatch):
    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=3)
    monkeypatch.setattr(services.subprocess, "run", fake_run)
    r = services._probe_tailscaled("tailscaled", "active")
    assert r.version is None


# ---------------------------------------------------------------------------
# probe_all — top-level entrypoint
# ---------------------------------------------------------------------------

def test_probe_all_returns_dict_of_dicts_with_state(monkeypatch):
    monkeypatch.setattr(services.subprocess, "run",
                         lambda *a, **kw: _FakeCompleted(-1, "", "stubbed"))
    out = services.probe_all({
        "tailscaled": "active",
        "wazuh-agent": "failed",
        "custom": "missing",
    })
    assert set(out.keys()) == {"tailscaled", "wazuh-agent", "custom"}
    assert out["tailscaled"]["state"] == "active"
    assert out["wazuh-agent"]["state"] == "failed"
    assert out["custom"]["state"] == "missing"


def test_probe_all_extra_probes_override_builtin(monkeypatch):
    monkeypatch.setattr(services.subprocess, "run",
                         lambda *a, **kw: _FakeCompleted(-1, "", "stubbed"))
    def my_probe(unit, state):
        return services.ServiceProbeResult(state=state, version="custom-1.0")
    out = services.probe_all(
        {"tailscaled": "active"},
        extra_probes={"tailscaled": my_probe},
    )
    assert out["tailscaled"] == {"state": "active", "version": "custom-1.0"}


def test_probe_all_catches_probe_exceptions(monkeypatch):
    """A probe that raises must not break the whole heartbeat batch."""
    monkeypatch.setattr(services.subprocess, "run",
                         lambda *a, **kw: _FakeCompleted(-1, "", "stubbed"))
    def boom(unit, state):
        raise RuntimeError("probe exploded")
    out = services.probe_all(
        {"tailscaled": "active"},
        extra_probes={"tailscaled": boom},
    )
    # State is preserved even though the probe failed.
    assert out["tailscaled"] == {"state": "active"}
