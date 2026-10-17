"""v0.17.2 enrichment tests — a real data root (the enrichment cache is a
registry table), a fake mailer; every network call goes to an
httpx.MockTransport and the system resolver is booby-trapped."""
from __future__ import annotations

import socket

import pytest

from apps.octo.threat.tests.conftest import mailer, troot  # noqa: F401


@pytest.fixture
def no_resolver(monkeypatch):
    """Any use of the system resolver (or a raw connect) fails the test."""
    calls: list[str] = []

    def trap(name):
        def _f(*args, **kwargs):
            calls.append(f"{name}{args[:1]}")
            raise AssertionError(f"socket.{name} must never be called: {args[:1]}")
        return _f

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
                 "create_connection"):
        monkeypatch.setattr(socket, name, trap(name))
    return calls
