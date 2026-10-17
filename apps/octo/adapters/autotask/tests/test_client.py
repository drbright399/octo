"""AutotaskClient unit tests — zone resolution + health check.

Pure-unit: zero network IO. HTTP is injected via callable stubs so
each path (happy, malformed, 401, 5xx, network failure) tests
deterministically."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

import pytest

from apps.octo.adapters.autotask.client import (
    IN_BATCH,
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskConfig,
    AutotaskRefusedError,
    AutotaskZoneError,
    resolve_zone,
)


@dataclass
class StubResponse:
    """Minimal duck-type matching what `requests.Response` exposes for our
    use — `.status_code`, `.text`, and `.json()`."""
    status_code: int
    text: str = ""
    _json_body: Optional[Any] = None

    def json(self) -> Any:
        if self._json_body is None:
            raise ValueError("no body")
        return self._json_body


# ---------------------------------------------------------------------------
# resolve_zone
# ---------------------------------------------------------------------------

def test_resolve_zone_happy_path():
    captured: dict[str, Any] = {}

    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        captured["url"] = url
        return StubResponse(
            status_code=200,
            _json_body={"url": "https://webservices4.autotask.net/atservicesrest/v1.0/"},
        )

    out = resolve_zone("api-user@example.com", http_get=stub_get)
    assert out == "https://webservices4.autotask.net/atservicesrest/v1.0/"
    assert captured["url"].endswith("?user=api-user@example.com")


def test_resolve_zone_appends_trailing_slash_if_missing():
    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(
            status_code=200,
            _json_body={"url": "https://webservices1.autotask.net/atservicesrest/v1.0"},
        )
    out = resolve_zone("api-user@example.com", http_get=stub_get)
    assert out.endswith("/")


def test_resolve_zone_rejects_non_email_username():
    with pytest.raises(AutotaskZoneError, match="email"):
        resolve_zone("not-an-email")


def test_resolve_zone_rejects_non_200():
    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=404, text="Not Found")
    with pytest.raises(AutotaskZoneError, match="HTTP 404"):
        resolve_zone("api-user@example.com", http_get=stub_get)


def test_resolve_zone_rejects_non_json_body():
    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=200, text="<html>maintenance</html>")
    with pytest.raises(AutotaskZoneError, match="not JSON"):
        resolve_zone("api-user@example.com", http_get=stub_get)


def test_resolve_zone_rejects_missing_url_field():
    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=200, _json_body={"otherKey": "value"})
    with pytest.raises(AutotaskZoneError, match="missing usable 'url'"):
        resolve_zone("api-user@example.com", http_get=stub_get)


def test_resolve_zone_wraps_network_failure():
    def stub_get(url: str, **kwargs: Any) -> StubResponse:
        raise ConnectionError("name resolution failed")
    with pytest.raises(AutotaskZoneError, match="network failure"):
        resolve_zone("api-user@example.com", http_get=stub_get)


# ---------------------------------------------------------------------------
# AutotaskClient.health_check
# ---------------------------------------------------------------------------

def _make_config() -> AutotaskConfig:
    return AutotaskConfig(
        username="api-user@example.com",
        secret="hunter2",
        integration_code="ATINT0000",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )


def test_health_check_happy_path_returns_envelope():
    def stub_request(method: str, url: str, **kwargs: Any) -> StubResponse:
        assert method == "GET"
        assert "/V1.0/Companies/query" in url
        headers = kwargs["headers"]
        assert headers["UserName"] == "api-user@example.com"
        assert headers["Secret"] == "hunter2"
        assert headers["ApiIntegrationCode"] == "ATINT0000"
        return StubResponse(
            status_code=200,
            _json_body={"items": [{"id": 1, "companyName": "ACME"}], "pageDetails": {}},
        )
    client = AutotaskClient(_make_config(), http_request=stub_request)
    out = client.health_check()
    assert out["items"][0]["companyName"] == "ACME"


def test_health_check_401_raises_auth_error():
    def stub_request(method: str, url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=401, text="Unauthorized")
    client = AutotaskClient(_make_config(), http_request=stub_request)
    with pytest.raises(AutotaskAuthError, match="401"):
        client.health_check()


def test_health_check_5xx_raises_client_error():
    def stub_request(method: str, url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=503, text="Service Unavailable")
    client = AutotaskClient(_make_config(), http_request=stub_request)
    with pytest.raises(AutotaskClientError, match="503"):
        client.health_check()


def test_health_check_network_failure_wraps():
    def stub_request(method: str, url: str, **kwargs: Any) -> StubResponse:
        raise TimeoutError("read timeout")
    client = AutotaskClient(_make_config(), http_request=stub_request)
    with pytest.raises(AutotaskClientError, match="network failure"):
        client.health_check()


def test_health_check_non_json_body_wraps():
    def stub_request(method: str, url: str, **kwargs: Any) -> StubResponse:
        return StubResponse(status_code=200, text="<html>maintenance</html>")
    client = AutotaskClient(_make_config(), http_request=stub_request)
    with pytest.raises(AutotaskClientError, match="not JSON"):
        client.health_check()


# ---------------------------------------------------------------------------
# Companies + CompanyLocations (the site-location proposals' reads)
# ---------------------------------------------------------------------------

ZONE = "https://webservices4.autotask.net/atservicesrest/v1.0/"


def _search(url: str) -> dict[str, Any]:
    from urllib.parse import unquote

    return json.loads(unquote(url.split("?search=", 1)[1]))


class Recorder:
    """An HTTP stub answering queued responses and keeping every URL."""

    def __init__(self, *responses: StubResponse) -> None:
        self.responses = list(responses)
        self.urls: list[str] = []

    def __call__(self, method: str, url: str, **kwargs: Any) -> StubResponse:
        assert method == "GET" and kwargs["headers"]["ApiIntegrationCode"] == "ATINT0000"
        self.urls.append(url)
        return self.responses.pop(0)


def _page(items: list[dict[str, Any]], nxt: Optional[str] = None) -> StubResponse:
    return StubResponse(status_code=200, _json_body={
        "items": items, "pageDetails": {"count": len(items), "nextPageUrl": nxt}})


def test_query_companies_reads_mapped_active_companies_address_fields_only():
    http = Recorder(_page([{"id": 101, "companyName": "Example Bakery"}]))
    client = AutotaskClient(_make_config(), http_request=http)
    out = client.query_companies([102, 101, 101])
    assert out == [{"id": 101, "companyName": "Example Bakery"}]
    (url,) = http.urls
    assert url.startswith(f"{ZONE.rstrip('/')}/V1.0/Companies/query?search=")
    search = _search(url)
    assert search["filter"] == [{"op": "in", "field": "id", "value": [101, 102]},
                                {"op": "eq", "field": "isActive", "value": True}]
    assert "address1" in search["IncludeFields"] and "postalCode" in search["IncludeFields"]
    assert search["MaxRecords"] == 500


def test_many_ids_are_read_in_batches():
    ids = list(range(1, IN_BATCH + 6))
    http = Recorder(_page([{"id": 1}]), _page([{"id": IN_BATCH + 1}]))
    client = AutotaskClient(_make_config(), http_request=http)
    assert [c["id"] for c in client.query_companies(ids)] == [1, IN_BATCH + 1]
    assert [len(_search(u)["filter"][0]["value"]) for u in http.urls] == [IN_BATCH, 5]


def test_pages_are_followed_on_the_zone_only():
    nxt = f"{ZONE}Companies/query/next?paging=abc"
    http = Recorder(_page([{"id": 1}], nxt), _page([{"id": 2}]))
    client = AutotaskClient(_make_config(), http_request=http)
    assert [c["id"] for c in client.query_companies([1, 2])] == [1, 2]
    assert http.urls[1] == nxt
    # A next page somewhere else is never followed (the credential headers
    # would go with it) — and never a silent half answer either.
    http = Recorder(_page([{"id": 1}], "https://elsewhere.example.test/V1.0/next"))
    client = AutotaskClient(_make_config(), http_request=http)
    with pytest.raises(AutotaskClientError, match="not on this zone"):
        client.query_companies([1])
    assert len(http.urls) == 1
    pages = [_page([{"id": n}], f"{ZONE}Companies/query/next?p={n}") for n in range(12)]
    client = AutotaskClient(_make_config(), http_request=Recorder(*pages))
    with pytest.raises(AutotaskClientError, match="more than 10 pages"):
        client.query_companies([1])


def test_company_locations_are_read_by_company():
    http = Recorder(_page([{"id": 12, "companyID": 500, "name": "Riverton"}]))
    client = AutotaskClient(_make_config(), http_request=http)
    out = client.query_company_locations([500])
    assert out[0]["name"] == "Riverton"
    (url,) = http.urls
    assert "/V1.0/CompanyLocations/query?search=" in url
    search = _search(url)
    assert search["filter"][0] == {"op": "in", "field": "companyID", "value": [500]}
    assert "isPrimary" in search["IncludeFields"]


@pytest.mark.parametrize("status, text", [
    (403, "Forbidden"),
    (404, "Not Found"),
    (405, "Method Not Allowed"),
    (500, '{"errors":["User does not have permission to query CompanyLocations"]}'),
])
def test_refused_company_locations(status, text):
    client = AutotaskClient(_make_config(),
                            http_request=Recorder(StubResponse(status_code=status, text=text)))
    with pytest.raises(AutotaskRefusedError) as info:
        client.query_company_locations([500])
    assert info.value.status == status


def test_other_company_location_failures_are_not_a_refusal():
    client = AutotaskClient(_make_config(), http_request=Recorder(
        StubResponse(status_code=503, text="Service Unavailable")))
    with pytest.raises(AutotaskClientError) as info:
        client.query_company_locations([500])
    assert not isinstance(info.value, AutotaskRefusedError) and info.value.status == 503
    client = AutotaskClient(_make_config(), http_request=Recorder(
        StubResponse(status_code=401, text="Unauthorized")))
    with pytest.raises(AutotaskAuthError):
        client.query_company_locations([500])


def test_no_ids_no_call():
    http = Recorder()
    client = AutotaskClient(_make_config(), http_request=http)
    assert client.query_companies([]) == [] and client.query_company_locations([]) == []
    assert http.urls == []
