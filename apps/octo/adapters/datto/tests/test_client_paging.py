"""DattoClient.fetch_alerts_since against a fake HTTP layer — the REAL client,
so the request it builds is what is asserted (Datto answers HTTP 400 to a
page size above 250 and the whole poll fails)."""
from __future__ import annotations

import time
from typing import Any

from apps.octo.adapters.datto.client import DattoClient, DattoConfig

API = "https://rmm-api.example.test"


class _Resp:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status_code = status
        self._body = body
        self.content = b"x"

    def json(self) -> dict[str, Any]:
        return self._body


class _Session:
    """Mimics the vendor: 400 above the page limit, pages of `page_size`."""

    def __init__(self, total: int, next_host: str = API) -> None:
        self.total = total
        self.next_host = next_host
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, url: str, *, headers=None, params=None, timeout=None,
            allow_redirects=True):
        self.calls.append((url, params))
        self.followed_redirects = allow_redirects
        if params is not None and params["max"] > 250:
            return _Resp(400, {"error": "exceeds the defined limit of 250"})
        # The client sends only the page NUMBER it took from nextPageUrl —
        # always to the configured origin, never to the URL a body named.
        page = (params or {}).get("page", 0)
        size = 250
        chunk = list(range(page * size, min((page + 1) * size, self.total)))
        more = (page + 1) * size < self.total
        return _Resp(200, {
            "alerts": [{"alertUid": f"a-{i}"} for i in chunk],
            "pageDetails": {"nextPageUrl": (
                f"{self.next_host}/api/v2/account/alerts/open?max=250&page={page + 1}"
                if more else None)},
        })


def _client(session: _Session) -> DattoClient:
    c = DattoClient(DattoConfig(api_url=API, api_key="k", api_secret_key="s",
                                verify_tls=True, timeout_seconds=5))
    c._session = session  # type: ignore[assignment]
    c._token, c._token_expires_at = "t", time.time() + 3600
    return c


def test_default_batch_never_exceeds_the_vendor_page_limit():
    s = _Session(total=3)
    alerts = _client(s).fetch_alerts_since("2026-01-01T00:00:00.000Z")
    assert len(alerts) == 3
    assert s.calls[0][1]["max"] == 250


def test_follows_next_page_until_max_results():
    s = _Session(total=620)
    alerts = _client(s).fetch_alerts_since("2026-01-01T00:00:00.000Z", max_results=500)
    assert len(alerts) == 500
    assert [a["alertUid"] for a in alerts[:2]] == ["a-0", "a-1"]
    assert len(s.calls) == 2


def test_next_page_link_to_another_host_is_not_followed():
    s = _Session(total=620, next_host="https://elsewhere.example.test")
    alerts = _client(s).fetch_alerts_since("2026-01-01T00:00:00.000Z", max_results=500)
    assert len(alerts) == 250
    assert len(s.calls) == 1


def test_every_page_goes_to_the_configured_origin_with_the_full_query():
    s = _Session(total=620)
    _client(s).fetch_alerts_since("2026-01-01T00:00:00.000Z", max_results=500)
    assert [url for url, _ in s.calls] == [API + "/api/v2/account/alerts/open"] * 2
    first, second = (params for _, params in s.calls)
    assert "page" not in first and second["page"] == 1
    # The filter travels with every page (nextPageUrl is not trusted to carry it).
    assert second["after"] == first["after"] and second["max"] == 250
    assert s.followed_redirects is False


def test_a_page_size_request_under_the_limit_is_sent_as_is():
    s = _Session(total=3)
    _client(s).fetch_alerts_since("2026-01-01T00:00:00.000Z", max_results=40)
    assert s.calls[0][1]["max"] == 40
