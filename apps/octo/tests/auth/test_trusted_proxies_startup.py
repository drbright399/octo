"""OCTO_TRUSTED_PROXIES at startup: a bad value stops octo-core, and the
setting in use is stated in one line that `docker logs` shows.

Documentation ranges only (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32).
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI

from apps.octo.api import client_ip as cip
from apps.octo.api import rate_limit as rl

REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.mark.parametrize("raw, expected", [
    ("bundle-net", "entry 1 is not an IP address or network"),
    ("192.0.2.10/32;192.0.2.20/32", "separate entries with commas or spaces"),
    ("0.0.0.0/0", "entry 1 (0.0.0.0/0) would trust every address"),
    ("192.0.2.10, ::/0", "entry 2 (::/0) would trust every address"),
    ("192.0.2.1/0", "entry 1 (192.0.2.1/0) would trust every address"),
    ("192.0.2.10/16", "entry 1 (192.0.2.10/16) has host bits set"),
    ("192.0.2.10/32 192.0.2.20/24", "entry 2 (192.0.2.20/24) has host bits set"),
    ("::ffff:192.0.2.0/124", "entry 1 (::ffff:192.0.2.0/124) is an IPv4-mapped IPv6 network"),
])
def test_a_bad_setting_stops_the_real_app(auth_data_root, monkeypatch, raw, expected):
    from apps.octo.api import create_app

    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", raw)
    rl.reset_limiter()
    with pytest.raises(cip.TrustedProxiesError) as exc:
        create_app()
    assert expected in str(exc.value)


def test_a_good_setting_builds_the_real_app(auth_data_root, monkeypatch):
    from apps.octo.api import create_app

    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.0/28\n2001:db8::/64,")
    rl.reset_limiter()
    app = create_app()
    assert app.state.auth_failure_limiter is not None


def _startup_records(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == rl.__name__ and r.getMessage().startswith("client addresses:")]


def test_the_startup_line_is_a_warning_naming_the_networks(monkeypatch, caplog):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.0/28, 192.0.2.40")
    monkeypatch.delenv("OCTO_AUTH_FAILURE_LIMIT", raising=False)
    with caplog.at_level(logging.WARNING, logger=rl.__name__):
        rl.install_rate_limit_middleware(FastAPI())
    (record,) = _startup_records(caplog)
    assert record.levelno == logging.WARNING
    assert record.getMessage() == (
        "client addresses: X-Forwarded-For believed only from OCTO_TRUSTED_PROXIES = "
        "192.0.2.0/28, 192.0.2.40/32 (2 networks); failed-auth limiter on: 30 "
        "failures in 600 s from one address -> 900 s cool-down"
    )


def test_the_startup_line_says_when_the_setting_is_empty(monkeypatch, caplog):
    monkeypatch.delenv("OCTO_TRUSTED_PROXIES", raising=False)
    with caplog.at_level(logging.WARNING, logger=rl.__name__):
        rl.install_rate_limit_middleware(FastAPI())
    (record,) = _startup_records(caplog)
    assert record.levelno == logging.WARNING
    assert "OCTO_TRUSTED_PROXIES is empty" in record.getMessage()
    assert "failed-auth limiter is off" in record.getMessage()


def test_the_startup_line_says_when_the_limiter_is_turned_off(monkeypatch, caplog):
    monkeypatch.setenv("OCTO_TRUSTED_PROXIES", "192.0.2.0/28")
    monkeypatch.setenv("OCTO_AUTH_FAILURE_LIMIT", "0")
    with caplog.at_level(logging.WARNING, logger=rl.__name__):
        rl.install_rate_limit_middleware(FastAPI())
    (record,) = _startup_records(caplog)
    assert record.getMessage().endswith(
        "(1 network); failed-auth limiter off (OCTO_AUTH_FAILURE_LIMIT=0)")


# What the container runs: uvicorn, whose logging setup configures only its
# own loggers. Run in a child process so the logging state is uvicorn's.
_UNDER_UVICORN = """
import uvicorn.config
from fastapi import FastAPI
uvicorn.config.Config(app="apps.octo.api:create_app", factory=True)  # configures logging
from apps.octo.api.rate_limit import install_rate_limit_middleware
install_rate_limit_middleware(FastAPI())
"""


def _run_under_uvicorn_logging(setting: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("OCTO_", "PYTEST_"))}
    env.update(OCTO_TRUSTED_PROXIES=setting, PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=str(REPO_ROOT))
    return subprocess.run(
        [sys.executable, "-c", _UNDER_UVICORN], cwd=REPO_ROOT, env=env,
        capture_output=True, text=True, timeout=120,
    )


def test_the_startup_line_reaches_stderr_under_uvicorn_logging():
    """The deploy guide's check is `docker logs octo-core 2>&1 | grep
    'client addresses'`: the line must reach stderr with uvicorn's default
    logging, which drops INFO from the application's loggers."""
    done = _run_under_uvicorn_logging("192.0.2.0/28 2001:db8::/64")
    assert done.returncode == 0, done.stderr
    assert ("client addresses: X-Forwarded-For believed only from "
            "OCTO_TRUSTED_PROXIES = 192.0.2.0/28, 2001:db8::/64 (2 networks)") in done.stderr


def test_a_bad_setting_exits_non_zero_with_the_reason_on_stderr():
    done = _run_under_uvicorn_logging("192.0.2.10/32;s3cr3t-Stderr-Value")
    assert done.returncode != 0
    last = done.stderr.strip().splitlines()[-1]
    assert last.startswith("apps.octo.api.client_ip.TrustedProxiesError: "
                           "OCTO_TRUSTED_PROXIES is not valid, so octo-core will not start")
    assert "entry 1 is not an IP address or network" in last
    assert "s3cr3t" not in done.stderr
