"""Location precedence: the SITE's override (042), else the UniFi console
location (a single-site console, or a multi-site console that is the
tenant's alone), else the TENANT's override (041, the fallback), else no pin.
Never (0, 0), never out of range, never IP-derived."""
from __future__ import annotations

import math

import pytest

from apps.octo.fleet import locations

UNIFI = {"lat": 41.06, "long": -101.0, "radius": 100, "text": "1 Example Road, Example County"}
MANUAL = {"lat": 41.3, "lng": -100.8, "label": "Main office"}
SITE = {"lat": 41.2, "lng": -100.9, "label": "1 Example Ave (corrected)"}


def test_the_site_override_wins_over_everything():
    """A console can report a location states away from the client (its
    setup's guess); the operator's per-site correction always wins."""
    for sites, shared in ((1, False), (3, False), (3, True)):
        loc = locations.resolve(UNIFI, MANUAL, site=SITE, fallback_label="Example Site",
                                console_sites=sites, console_shared=shared)
        assert (loc.lat, loc.lng, loc.source) == (41.2, -100.9, "site"), (sites, shared)
        assert loc.label == "1 Example Ave (corrected)"


def test_the_console_beats_the_tenant_fallback():
    for sites in (1, 3):
        loc = locations.resolve(UNIFI, MANUAL, console_sites=sites, console_shared=False)
        assert loc.source == "unifi", sites
    # …except a multi-site console shared with another tenant: it pins nobody,
    # the tenant fallback does.
    loc = locations.resolve(UNIFI, MANUAL, console_sites=3, console_shared=True)
    assert loc.source == "manual" and loc.label == "Main office"
    # A site override that is not a location (0, 0) is no override.
    loc = locations.resolve(UNIFI, MANUAL, site={"lat": 0, "lng": 0, "label": "x"})
    assert loc.source == "unifi"


def test_the_console_location_without_an_override():
    loc = locations.resolve(UNIFI, None, fallback_label="Example Site")
    assert (loc.lat, loc.lng, loc.source) == (41.06, -101.0, "unifi")
    assert loc.label == "1 Example Road, Example County"
    # A multi-site console is used only when it is this tenant's alone.
    assert locations.resolve(UNIFI, None, console_sites=3, console_shared=False).source == "unifi"
    assert locations.resolve(UNIFI, None, console_sites=3, console_shared=True) is None


def test_manual_when_unifi_has_none():
    for unifi in (None, {}, {"lat": 0, "long": 0, "text": "nowhere"}, {"text": "no coords"},
                  {"lat": 91, "long": 0}, {"lat": math.nan, "long": 1.0}, {"lat": True, "long": 1}):
        loc = locations.resolve(unifi, MANUAL, fallback_label="Example Site")
        assert loc is not None and loc.source == "manual" and loc.label == "Main office", unifi


def test_no_pin_without_either():
    assert locations.resolve(None, None) is None
    assert locations.resolve({}, {"lat": 0.0, "lng": 0.0, "label": "x"}) is None
    assert locations.resolve({"lat": "41", "long": "-101"}, None) is None   # strings: no


def test_label_falls_back_and_is_cleaned():
    loc = locations.resolve({"lat": 41.0, "long": -101.0}, None, fallback_label="Site\x00 A")
    assert loc.label == "Site A"
    assert locations.clean_label("a" * 300) == "a" * 120


@pytest.mark.parametrize("lat,lng,label", [
    (91, 0, "x"), (0, 181, "x"), (0, 0, "x"), (41, -101, ""), (41, -101, "   "),
])
def test_validated_refuses(lat, lng, label):
    with pytest.raises(locations.LocationError):
        locations.validated(lat, lng, label)


def test_validated_rounds():
    assert locations.validated(41.1234567891, -101.987654321, " HQ ") == \
        (41.123457, -101.987654, "HQ")
