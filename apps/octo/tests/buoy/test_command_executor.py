"""buoy-heartbeat daemon — unit tests for slice 11 command executor.

These tests cover the buoy-side fetch+exec half of slice 7's design:
parse `pending_commands` from the heartbeat response, dispatch each
through a per-kind handler, POST the result back to OCTO.

All tests mock out subprocess.run + the daemon's _http_request so they
run anywhere — no buoy required.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

HEARTBEAT_DIR = Path(__file__).resolve().parents[2] / "buoy"
sys.path.insert(0, str(HEARTBEAT_DIR))

import heartbeat  # type: ignore  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _fake_config(tmp_path) -> "heartbeat.Config":
    c = heartbeat.Config()
    c.octo_url = "http://octo.test:8771"
    c.octo_slug = "alpha"
    c.token = "tok"
    c.services = ("tailscaled", "wazuh-agent", "buoy-forwarder")
    c.last_event_file = None
    c.interval_sec = 60
    c.state_dir = tmp_path
    c.http_timeout_sec = 5
    c.queue_max = 3
    return c


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    """subprocess.CompletedProcess factory for monkey-patched run."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


# ---------------------------------------------------------------------------
# _tail_bytes — UTF-8-safe tail truncation
# ---------------------------------------------------------------------------

def test_tail_bytes_passthrough_when_under_limit():
    assert heartbeat._tail_bytes("hello", max_bytes=100) == "hello"


def test_tail_bytes_truncates_to_tail_when_over_limit():
    s = "abcdefghij"  # 10 bytes ASCII
    assert heartbeat._tail_bytes(s, max_bytes=4) == "ghij"


def test_tail_bytes_handles_multibyte_utf8_at_boundary():
    # Each emoji is 4 bytes in UTF-8. Asking for a max that lands
    # mid-codepoint must still produce valid UTF-8.
    s = "🟢🟢🟢🟢"  # 16 bytes
    out = heartbeat._tail_bytes(s, max_bytes=6)
    # The decoder swallows the partial leading bytes; output must
    # roundtrip cleanly without raising.
    assert isinstance(out, str)
    out.encode("utf-8")  # would raise if invalid


# ---------------------------------------------------------------------------
# _handle_ping — trivial, just confirms shape
# ---------------------------------------------------------------------------

def test_handle_ping_returns_ok(tmp_path):
    cfg = _fake_config(tmp_path)
    ok, exit_code, stdout, stderr, err = heartbeat._handle_ping(cfg, {})
    assert ok is True
    assert exit_code == 0
    assert "pong" in stdout
    assert cfg.octo_slug in stdout
    assert stderr == ""
    assert err is None


# ---------------------------------------------------------------------------
# _handle_refresh — gathers + posts; returns services snapshot
# ---------------------------------------------------------------------------

def test_handle_refresh_success(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_gather_heartbeat",
        return_value={"slug": "alpha", "services": {"tailscaled": "active"}},
    ), patch.object(
        heartbeat, "_post_heartbeat_with_response",
        return_value={"accepted": True, "pending_commands": []},
    ):
        ok, exit_code, stdout, stderr, err = heartbeat._handle_refresh(cfg, {})
    assert ok is True
    assert exit_code == 0
    # stdout carries the fresh services snapshot as JSON.
    assert json.loads(stdout) == {"tailscaled": "active"}
    assert err is None


def test_handle_refresh_failure_propagates(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_gather_heartbeat", return_value={"slug": "alpha"},
    ), patch.object(
        heartbeat, "_post_heartbeat_with_response", return_value=None,
    ):
        ok, exit_code, stdout, stderr, err = heartbeat._handle_refresh(cfg, {})
    assert ok is False
    assert err == "heartbeat_post_failed"


def test_handle_refresh_does_not_recurse(tmp_path):
    """If OCTO returns pending_commands on the refresh's own heartbeat,
    refresh MUST NOT dispatch them — that's the main loop's job.
    Otherwise we'd double-dispatch every queued command."""
    cfg = _fake_config(tmp_path)
    dispatch_calls = []

    with patch.object(
        heartbeat, "_gather_heartbeat",
        return_value={"slug": "alpha", "services": {}},
    ), patch.object(
        heartbeat, "_post_heartbeat_with_response",
        return_value={"accepted": True, "pending_commands": [
            {"id": 99, "command_kind": "ping", "args": {}},
        ]},
    ), patch.object(
        heartbeat, "_dispatch_pending_commands",
        side_effect=lambda *a, **kw: dispatch_calls.append(a),
    ):
        heartbeat._handle_refresh(cfg, {})

    assert dispatch_calls == [], "refresh must not call dispatcher"


# ---------------------------------------------------------------------------
# _handle_tail_log — whitelist + bounded line count + subprocess shape
# ---------------------------------------------------------------------------

def test_handle_tail_log_missing_unit(tmp_path):
    cfg = _fake_config(tmp_path)
    ok, exit_code, _stdout, stderr, err = heartbeat._handle_tail_log(cfg, {})
    assert ok is False
    assert exit_code == 2
    assert "missing required arg 'unit'" in stderr
    assert err == "args_invalid"


def test_handle_tail_log_unit_not_whitelisted(tmp_path):
    cfg = _fake_config(tmp_path)
    ok, exit_code, _stdout, stderr, err = heartbeat._handle_tail_log(
        cfg, {"unit": "sshd"},
    )
    assert ok is False
    assert exit_code == 2
    assert "not in SERVICES whitelist" in stderr
    assert err == "unit_not_whitelisted"


def test_handle_tail_log_success(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    captured = {}

    def _fake_run(args, **kwargs):
        captured["args"] = list(args)
        return _completed(stdout="log line 1\nlog line 2\n", returncode=0)

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    ok, exit_code, stdout, _stderr, err = heartbeat._handle_tail_log(
        cfg, {"unit": "tailscaled", "lines": "50"},
    )
    assert ok is True
    assert exit_code == 0
    assert "log line 1" in stdout
    assert captured["args"] == [
        "journalctl", "-u", "tailscaled", "-n", "50", "--no-pager",
    ]
    assert err is None


def test_handle_tail_log_clamps_lines_arg(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    captured = {}

    def _fake_run(args, **kwargs):
        captured["args"] = list(args)
        return _completed()

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    heartbeat._handle_tail_log(cfg, {"unit": "tailscaled", "lines": "10000"})
    # Clamped to TAIL_LOG_MAX_LINES.
    assert captured["args"][4] == str(heartbeat.TAIL_LOG_MAX_LINES)


def test_handle_tail_log_handles_invalid_lines_arg(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    monkeypatch.setattr(
        heartbeat.subprocess, "run", lambda *a, **kw: _completed(),
    )
    # Non-integer lines arg → defaults to 100, doesn't raise.
    ok, *_ = heartbeat._handle_tail_log(
        cfg, {"unit": "tailscaled", "lines": "not-a-number"},
    )
    assert ok is True


def test_handle_tail_log_timeout(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)

    def _fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=kwargs.get("timeout"))

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    ok, exit_code, _stdout, stderr, err = heartbeat._handle_tail_log(
        cfg, {"unit": "tailscaled"},
    )
    assert ok is False
    assert exit_code == 124
    assert "timed out" in stderr
    assert err == "command_timeout"


# ---------------------------------------------------------------------------
# _handle_restart_service — same whitelist + subprocess shape, different cmd
# ---------------------------------------------------------------------------

def test_handle_restart_service_missing_unit(tmp_path):
    cfg = _fake_config(tmp_path)
    ok, _exit_code, _stdout, _stderr, err = heartbeat._handle_restart_service(
        cfg, {},
    )
    assert ok is False
    assert err == "args_invalid"


def test_handle_restart_service_unit_not_whitelisted(tmp_path):
    cfg = _fake_config(tmp_path)
    ok, _exit_code, _stdout, _stderr, err = heartbeat._handle_restart_service(
        cfg, {"unit": "nginx"},
    )
    assert ok is False
    assert err == "unit_not_whitelisted"


def test_handle_restart_service_success(tmp_path, monkeypatch):
    cfg = _fake_config(tmp_path)
    captured = {}

    def _fake_run(args, **kwargs):
        captured["args"] = list(args)
        return _completed()

    monkeypatch.setattr(heartbeat.subprocess, "run", _fake_run)
    ok, exit_code, _stdout, _stderr, err = heartbeat._handle_restart_service(
        cfg, {"unit": "wazuh-agent"},
    )
    assert ok is True
    assert exit_code == 0
    assert captured["args"] == ["systemctl", "restart", "wazuh-agent"]
    assert err is None


# ---------------------------------------------------------------------------
# _handle_not_implemented — explicit stub for reboot / update
# ---------------------------------------------------------------------------

def test_handle_not_implemented_shape():
    ok, exit_code, _stdout, stderr, err = heartbeat._handle_not_implemented(
        "reboot",
    )
    assert ok is False
    assert exit_code == 78  # sysexits.h EX_CONFIG
    assert "reboot" in stderr
    assert "not implemented" in stderr.lower()
    assert err == "not_implemented"


# ---------------------------------------------------------------------------
# _dispatch_command — routing + defensive defaults
# ---------------------------------------------------------------------------

def test_dispatch_command_known_kind_calls_handler(tmp_path):
    cfg = _fake_config(tmp_path)
    result = heartbeat._dispatch_command(
        cfg, {"id": 1, "command_kind": "ping", "args": {}},
    )
    assert result[0] is True  # ok
    assert "pong" in result[2]  # stdout


def test_dispatch_command_unknown_kind_returns_not_implemented(tmp_path):
    cfg = _fake_config(tmp_path)
    # "reboot" is in the schema's CHECK constraint but absent from the
    # dispatch table — should route to the stub, not raise KeyError.
    result = heartbeat._dispatch_command(
        cfg, {"id": 1, "command_kind": "reboot", "args": {}},
    )
    assert result[0] is False
    assert result[4] == "not_implemented"


def test_dispatch_command_truly_unknown_kind(tmp_path):
    cfg = _fake_config(tmp_path)
    # A kind that wouldn't even pass the server's CHECK constraint —
    # buoy stays defensive anyway.
    result = heartbeat._dispatch_command(
        cfg, {"id": 1, "command_kind": "frobnicate", "args": {}},
    )
    assert result[0] is False
    assert result[4] == "not_implemented"


def test_dispatch_command_handles_non_dict_args(tmp_path):
    cfg = _fake_config(tmp_path)
    # If OCTO ever returned args=null or args=[], we coerce to {} instead
    # of crashing. (Server should never do this, but defensive.)
    result = heartbeat._dispatch_command(
        cfg, {"id": 1, "command_kind": "ping", "args": None},
    )
    assert result[0] is True


def test_dispatch_command_catches_handler_exception(tmp_path):
    cfg = _fake_config(tmp_path)

    def _boom(_cfg, _args):
        raise RuntimeError("handler exploded")

    with patch.dict(heartbeat.COMMAND_DISPATCH, {"ping": _boom}):
        result = heartbeat._dispatch_command(
            cfg, {"id": 1, "command_kind": "ping", "args": {}},
        )
    assert result[0] is False
    assert result[4] == "handler_exception"
    assert "handler exploded" in result[3]


# ---------------------------------------------------------------------------
# _post_command_result — HTTP shape + failure handling
# ---------------------------------------------------------------------------

def test_post_command_result_success(tmp_path):
    cfg = _fake_config(tmp_path)
    captured = {}

    def _fake_http(_cfg, method, path, body=None):
        captured["method"] = method
        captured["path"] = path
        captured["body"] = body
        return (200, {"recorded": True})

    with patch.object(heartbeat, "_http_request", side_effect=_fake_http):
        sent = heartbeat._post_command_result(
            cfg, 42, (True, 0, "stdout", "stderr", None),
        )
    assert sent is True
    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/buoy/command/42/result"
    assert captured["body"]["ok"] is True
    assert captured["body"]["exit_code"] == 0
    assert captured["body"]["stdout_tail"] == "stdout"
    # error key omitted when None — keeps the JSON small + matches the
    # server's Optional[str]=None default.
    assert "error" not in captured["body"]


def test_post_command_result_includes_error_when_present(tmp_path):
    cfg = _fake_config(tmp_path)
    captured = {}

    def _fake_http(_cfg, method, path, body=None):
        captured["body"] = body
        return (200, {})

    with patch.object(heartbeat, "_http_request", side_effect=_fake_http):
        heartbeat._post_command_result(
            cfg, 7, (False, 124, "", "boom", "command_timeout"),
        )
    assert captured["body"]["error"] == "command_timeout"
    assert captured["body"]["ok"] is False


def test_post_command_result_failure(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(
        heartbeat, "_http_request",
        return_value=(500, {"error": "internal"}),
    ):
        sent = heartbeat._post_command_result(
            cfg, 1, (True, 0, "", "", None),
        )
    assert sent is False


# ---------------------------------------------------------------------------
# _dispatch_pending_commands — orchestration
# ---------------------------------------------------------------------------

def test_dispatch_pending_commands_empty_is_noop(tmp_path):
    cfg = _fake_config(tmp_path)
    with patch.object(heartbeat, "_http_request") as http:
        heartbeat._dispatch_pending_commands(cfg, [])
    assert http.call_count == 0


def test_dispatch_pending_commands_runs_each_in_order(tmp_path):
    cfg = _fake_config(tmp_path)
    posted = []

    def _fake_http(_cfg, method, path, body=None):
        if "/result" in path:
            posted.append((path, body["ok"]))
            return (200, {})
        return (200, {})

    pending = [
        {"id": 11, "command_kind": "ping", "args": {}},
        {"id": 22, "command_kind": "ping", "args": {}},
    ]
    with patch.object(heartbeat, "_http_request", side_effect=_fake_http):
        heartbeat._dispatch_pending_commands(cfg, pending)
    assert posted == [
        ("/api/v1/buoy/command/11/result", True),
        ("/api/v1/buoy/command/22/result", True),
    ]


def test_dispatch_pending_commands_skips_non_integer_ids(tmp_path):
    cfg = _fake_config(tmp_path)
    posted = []

    def _fake_http(_cfg, method, path, body=None):
        posted.append(path)
        return (200, {})

    pending = [
        {"id": "bad-string-id", "command_kind": "ping", "args": {}},
        {"id": 5, "command_kind": "ping", "args": {}},
    ]
    with patch.object(heartbeat, "_http_request", side_effect=_fake_http):
        heartbeat._dispatch_pending_commands(cfg, pending)
    assert posted == ["/api/v1/buoy/command/5/result"]


def test_dispatch_pending_commands_failure_does_not_halt_others(tmp_path):
    cfg = _fake_config(tmp_path)
    completed_ids = []

    def _exploding_handler(_cfg, _args):
        raise RuntimeError("kaboom")

    def _fake_http(_cfg, method, path, body=None):
        if "/result" in path:
            # Extract id from the URL
            cmd_id = int(path.rsplit("/", 2)[-2])
            completed_ids.append(cmd_id)
        return (200, {})

    pending = [
        {"id": 1, "command_kind": "ping", "args": {}},
        {"id": 2, "command_kind": "ping", "args": {}},   # will explode
        {"id": 3, "command_kind": "ping", "args": {}},
    ]
    with patch.dict(heartbeat.COMMAND_DISPATCH, {"ping": _exploding_handler}), \
         patch.object(heartbeat, "_http_request", side_effect=_fake_http):
        heartbeat._dispatch_pending_commands(cfg, pending)
    # All 3 commands ran the result-POST (each handler exception was
    # caught + reported as a failure result, didn't abort the loop).
    assert completed_ids == [1, 2, 3]
