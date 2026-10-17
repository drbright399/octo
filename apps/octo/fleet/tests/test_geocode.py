"""The on-demand address lookup (US Census geocoder) — with the HTTP call
MOCKED (no network in tests): only the typed address leaves, up to three
matches, (0, 0) / junk dropped, the switch, the rate limit, operator-safe
errors that never echo the address."""
from __future__ import annotations

import io
import json
import logging
import urllib.error
import urllib.parse

import pytest

from apps.octo.fleet import geocode

ADDRESS = "1 Example Road, Example Town, ZZ 00000"


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _census(*matches) -> bytes:
    return json.dumps({"result": {"input": {}, "addressMatches": list(matches)}}).encode()


def _match(lat, lng, text="1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000"):
    return {"matchedAddress": text, "coordinates": {"x": lng, "y": lat}}


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")


def test_only_the_typed_address_is_sent_and_matches_come_back():
    seen = {}

    def opener(req, timeout):
        seen["url"], seen["timeout"] = req.full_url, timeout
        return _Resp(_census(_match(41.25, -100.75), _match(0, 0), _match(41.3, -100.7, ""),
                             _match(41.31, -100.71, "2 EXAMPLE RD"), _match(41.32, -100.72),
                             _match(41.33, -100.73)))

    out = geocode.lookup(ADDRESS, opener=opener)
    url = urllib.parse.urlsplit(seen["url"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == geocode.CENSUS_URL
    assert urllib.parse.parse_qs(url.query) == {
        "address": [ADDRESS], "benchmark": ["Public_AR_Current"], "format": ["json"]}
    assert seen["timeout"] == geocode.TIMEOUT_SEC
    # (0, 0) and a match without an address are dropped; at most three.
    assert [m.as_dict() for m in out] == [
        {"lat": 41.25, "lng": -100.75, "label": "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000"},
        {"lat": 41.31, "lng": -100.71, "label": "2 EXAMPLE RD"},
        {"lat": 41.32, "lng": -100.72, "label": "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000"}]


def test_no_match_is_an_empty_list():
    assert geocode.lookup(ADDRESS, opener=lambda req, timeout: _Resp(_census())) == []
    assert geocode.lookup(ADDRESS, opener=lambda req, timeout: _Resp(b'{"result": null}')) == []


@pytest.mark.parametrize("raise_it", [
    urllib.error.URLError("unreachable"), TimeoutError(), OSError("reset"),
])
def test_unreachable_is_operator_safe_and_never_logs_the_address(raise_it, caplog):
    def opener(req, timeout):
        raise raise_it

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(geocode.GeocodeError) as err:
            geocode.lookup(ADDRESS, opener=opener)
    assert "could not be reached" in str(err.value) and ADDRESS not in str(err.value)
    assert "Example Road" not in caplog.text


def test_junk_and_oversized_answers():
    with pytest.raises(geocode.GeocodeError):
        geocode.lookup(ADDRESS, opener=lambda req, timeout: _Resp(b"<html>"))
    big = b" " * (geocode.MAX_RESPONSE_BYTES + 10)
    with pytest.raises(geocode.GeocodeError):
        geocode.lookup(ADDRESS, opener=lambda req, timeout: _Resp(big))


def test_the_switch(monkeypatch):
    called = []
    for value in ("off", "OFF", "nominatim", "google"):
        monkeypatch.setenv(geocode.GEOCODER_ENV, value)
        assert geocode.provider() is None
        with pytest.raises(geocode.GeocodeError) as err:
            geocode.lookup(ADDRESS, opener=lambda req, timeout: called.append(1))
        assert err.value.kind == "off" and "turned off" in str(err.value)
    assert called == []                                           # nothing left the box
    monkeypatch.delenv(geocode.GEOCODER_ENV)
    assert geocode.provider() == "census"                         # the default


@pytest.mark.parametrize("bad", ["", "abc", "x" * 201, None, 42])
def test_address_validation(bad):
    with pytest.raises(geocode.GeocodeError) as err:
        geocode.clean_address(bad)
    assert err.value.kind == "invalid"


def test_address_is_one_clean_line():
    assert geocode.clean_address("  1 Example Rd\n\tExample Town  ") == "1 Example Rd Example Town"


def test_rate_limit_is_per_operator_and_slides():
    now = [0.0]
    limiter = geocode.RateLimiter(limit=2, window_sec=60.0, clock=lambda: now[0])
    assert limiter.allow(1) and limiter.allow(1)
    assert not limiter.allow(1)
    assert limiter.allow(2)                                       # another operator
    now[0] = 61.0
    assert limiter.allow(1)
