"""A fake vendor HTTP API at the `requests` TRANSPORT layer, for the pollers
that have no dedicated fake (Wazuh, RocketCyber, UniFi, Autotask).

Mounted on a REAL client's own session (or, for Autotask, behind a real
`requests.Session.request` handed to the client's `http_request` hook), so
the client's status mapping and exception classes run for real — only the
socket is replaced. Same idea as adapters/datto/tests/fake_datto.py.

Scenario knobs are plain attributes a test flips mid-run.
"""
from __future__ import annotations

import json
from typing import Any, Callable
from urllib.parse import urlsplit

import requests
from requests.adapters import BaseAdapter

Handler = Callable[[requests.PreparedRequest], Any]


class FakeVendorTransport(BaseAdapter):
    def __init__(self) -> None:
        super().__init__()
        # (METHOD, path suffix) → handler returning a JSON-able body.
        self.routes: dict[tuple[str, str], Handler] = {}
        self.status = 200               # answer EVERY request with this instead
        self.error_body: Any = {"error": "fixture"}
        self.unreachable = False        # raise ConnectionError instead
        self.calls: list[tuple[str, str]] = []

    def route(self, method: str, suffix: str, handler: Handler) -> None:
        self.routes[(method.upper(), suffix)] = handler

    def count(self, suffix: str) -> int:
        return sum(1 for _, path in self.calls if path.endswith(suffix))

    def send(self, request, **kwargs):  # noqa: ANN001 — requests' signature
        path = urlsplit(request.url).path
        self.calls.append((request.method, path))
        if self.unreachable:
            raise requests.ConnectionError("fixture: connection refused")
        if self.status != 200:
            return self._response(request, self.status, self.error_body)
        for (method, suffix), handler in self.routes.items():
            if request.method == method and path.endswith(suffix):
                return self._response(request, 200, handler(request))
        return self._response(request, 404, {"error": "fixture: unknown path"})

    def close(self) -> None:
        return None

    @staticmethod
    def _response(request, status: int, body: Any) -> requests.Response:  # noqa: ANN001
        resp = requests.Response()
        resp.status_code = status
        resp._content = body if isinstance(body, bytes) else json.dumps(body).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url = request.url
        resp.request = request
        return resp


def mount(session: requests.Session, transport: FakeVendorTransport) -> None:
    session.mount("https://", transport)
    session.mount("http://", transport)


def session_request(transport: FakeVendorTransport) -> Callable[..., requests.Response]:
    """A real `requests.Session.request` whose socket is `transport` — the
    shape Autotask's client takes as its `http_request` hook."""
    session = requests.Session()
    mount(session, transport)
    return session.request
