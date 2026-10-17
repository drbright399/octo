"""'Open in Datto RMM' links — derivation, validation, encoding.

V1 of this product built such links and "sometimes the link just went to the
RMM home dashboard". The rule under test: from OUR side that cannot happen
silently — a link is exact, or it is absent.

Alert links are BUILT (from the alert's own uid). Device links are not: the
portal addresses a device by a numeric id no payload carries, so the vendor's
`portalUrl` is used — after `device_portal_url()` accepted it. That value is
vendor data; the hostile cases below are why it is validated and rebuilt.

Pure functions + the real adapter class; no network anywhere.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.links import (
    LINK_SPEC,
    derive_portal_base,
    device_portal_url,
    link_ids,
)
from apps.octo.instances import device_links
from apps.octo.instances import vendor_links as vl

# A made-up platform name in Datto's documented '<platform>-api' form.
API_URL = "https://exampleplat-api.centrastage.net"
PORTAL = "https://exampleplat.rmm.datto.com"

API_ALERT = {
    "alertUid": "0a1b2c3d-aaaa-bbbb-cccc-000000000001",
    "alertSourceInfo": {"deviceUid": "dev-uid-0001", "siteUid": "site-uid-0001"},
}


def _links(config: dict, ids: dict | None = None, kinds=vl.LINK_KINDS) -> dict[str, str]:
    built = vl.build_links(config, LINK_SPEC, ids if ids is not None else link_ids(API_ALERT), kinds)
    return {b.kind: b.url for b in built}


# ---------------------------------------------------------------------------
# Portal base: derived from the API URL, or not at all
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("api_url", [
    API_URL, API_URL + "/", "HTTPS://ExamplePlat-API.CentraStage.net", f"  {API_URL}  ",
])
def test_portal_base_is_derived_from_the_documented_api_host_form(api_url):
    assert derive_portal_base(api_url) == PORTAL
    assert DattoSourceAdapter.derive_portal_base({"DATTO_API_URL": api_url}) == PORTAL


@pytest.mark.parametrize("api_url", [
    "https://datto-api.example.test",                      # a proxy / lab host
    "http://exampleplat-api.centrastage.net",              # not https
    "https://exampleplat-api.centrastage.net:8443",        # a port
    "https://exampleplat-api.centrastage.net/api",         # a path
    "https://exampleplat-api.centrastage.net?x=1",
    "https://user@exampleplat-api.centrastage.net",        # userinfo
    "https://exampleplat-api.centrastage.net.example.test",
    "https://evil.example.test/exampleplat-api.centrastage.net",
    "https://exampleplat.centrastage.net",                 # no '-api'
    "https://a-b-api.centrastage.net",                     # not a platform name
    "https://-api.centrastage.net",
    "exampleplat-api.centrastage.net", "", None, 7, ["x"],
])
def test_any_other_api_url_yields_no_base_and_so_no_link(api_url):
    assert derive_portal_base(api_url) is None
    assert _links({}) == {}                                # nothing derived → nothing built


# ---------------------------------------------------------------------------
# Ids come from the vendor's own fields, in either shape
# ---------------------------------------------------------------------------

def test_link_ids_from_both_shapes():
    assert link_ids(API_ALERT) == {
        "alert_uid": "0a1b2c3d-aaaa-bbbb-cccc-000000000001",
        "device_uid": "dev-uid-0001", "site_uid": "site-uid-0001",
    }
    webhook = {"alertUid": "a-1", "device": {"hostname": "WS-1", "uid": "d-1"}, "siteUid": "s-1"}
    assert link_ids(webhook) == {"alert_uid": "a-1", "device_uid": "d-1", "site_uid": "s-1"}


def test_unsubstituted_or_missing_ids_are_absent_and_a_hostname_is_never_an_id():
    webhook = {"alertUid": "[alert_uid]", "device": {"hostname": "WS-1"}, "siteUid": ""}
    assert link_ids(webhook) == {}
    assert link_ids(None) == {} and link_ids({"alertUid": 5}) == {}


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def test_default_links_are_the_alert_only():
    """No device link is ever TEMPLATED from the device uid: the live portal
    uses /device/<numeric id>, which the payload does not carry."""
    assert _links({vl.DERIVED_BASE_KEY: PORTAL}) == {
        "alert": f"{PORTAL}/alert/0a1b2c3d-aaaa-bbbb-cccc-000000000001",
    }
    assert _links({vl.DERIVED_BASE_KEY: PORTAL}, kinds=("device",)) == {}
    assert vl.LINK_KINDS == ("alert",) and LINK_SPEC.paths_verified is True
    assert not hasattr(LINK_SPEC, "default_device_path")


def test_a_missing_id_means_no_link_of_that_kind_not_a_link_to_the_home_page():
    config = {vl.DERIVED_BASE_KEY: PORTAL}
    assert _links(config, {"alert_uid": "a-1"}) == {"alert": f"{PORTAL}/alert/a-1"}
    assert _links(config, {}) == {}
    assert _links(config, {"alert_uid": "", "device_uid": None}) == {}


@pytest.mark.parametrize("hostile", [
    "../../admin", "a/b", "a?token=1", "a#frag", "a@evil.example.test", "a b",
    "%2e%2e%2f", "https://evil.example.test/", "a\\b", "ü",
])
def test_ids_are_percent_encoded_whole(hostile):
    url = _links({vl.DERIVED_BASE_KEY: PORTAL}, {"alert_uid": hostile}).get("alert")
    if url is None:                        # whitespace → refused outright
        assert " " in hostile
        return
    parts = urlsplit(url)
    assert (parts.scheme, parts.hostname) == ("https", "exampleplat.rmm.datto.com")
    assert not parts.query and not parts.fragment and parts.username is None
    assert parts.path.startswith("/alert/") and parts.path.count("/") == 2


@pytest.mark.parametrize("bad_id", ["x" * 129, "a\x00b", "a\nb", " padded ", 12, None, ["a"]])
def test_unusable_ids_build_nothing(bad_id):
    assert _links({vl.DERIVED_BASE_KEY: PORTAL}, {"alert_uid": bad_id, "device_uid": bad_id}) == {}


def test_links_never_carry_a_credential():
    """Structural: the builder is given instance_config + ids only — but an
    instance_config that somehow held a secret must still not leak it."""
    config = {
        vl.DERIVED_BASE_KEY: PORTAL,
        "DATTO_API_KEY": "FIXTURE-PUBLIC-KEY", "DATTO_API_SECRET_KEY": "fixture-private",
    }
    for url in _links(config).values():
        assert "FIXTURE" not in url and "fixture" not in url and "?" not in url


# ---------------------------------------------------------------------------
# Admin overrides: validated on save …
# ---------------------------------------------------------------------------

def test_overrides_replace_the_defaults():
    config = {
        vl.DERIVED_BASE_KEY: PORTAL,
        vl.SETTINGS_KEY: vl.validate_settings({
            "portal_base_url": "https://otherplat.rmm.datto.com/",
            "alert_path_template": "/alerts/{site_uid}/{alert_uid}",
        }, LINK_SPEC),
    }
    assert config[vl.SETTINGS_KEY] == {
        "portal_base_url": "https://otherplat.rmm.datto.com",
        "alert_path_template": "/alerts/{site_uid}/{alert_uid}",
    }
    assert _links(config) == {
        "alert": "https://otherplat.rmm.datto.com/alerts/site-uid-0001/"
                 "0a1b2c3d-aaaa-bbbb-cccc-000000000001",
    }


def test_a_device_path_template_is_not_a_setting_any_more():
    with pytest.raises(ValueError) as err:
        vl.validate_settings({"device_path_template": "/device/{device_uid}"}, LINK_SPEC)
    assert "unknown vendor link setting" in str(err.value)


def test_an_entered_base_enables_links_when_nothing_could_be_derived():
    config = {vl.SETTINGS_KEY: {"portal_base_url": PORTAL}}
    assert _links(config, kinds=("alert",)) == {
        "alert": f"{PORTAL}/alert/0a1b2c3d-aaaa-bbbb-cccc-000000000001",
    }


@pytest.mark.parametrize("base, why", [
    ("http://exampleplat.rmm.datto.com", "https://"),
    ("https://portal.example.test", "under datto.com"),
    ("https://datto.com.example.test", "under datto.com"),
    ("https://evildatto.com", "under datto.com"),
    ("https://user@exampleplat.rmm.datto.com", "user name or password"),
    ("https://exampleplat.rmm.datto.com:8443", "port"),
    ("https://exampleplat.rmm.datto.com/alert", "site only"),
    ("https://exampleplat.rmm.datto.com?next=1", "'?' or '#'"),
    ("https://exampleplat.rmm.datto.com#x", "'?' or '#'"),
    ("https://exampleplat.rmm.datto.com\\@evil.example.test", "plain https://"),
    ("https://example plat.rmm.datto.com", "plain https://"),
    ("javascript:alert(1)", "https://"),
    ("//exampleplat.rmm.datto.com", "https://"),
])
def test_portal_base_override_is_refused(base, why):
    with pytest.raises(ValueError) as err:
        vl.validate_settings({"portal_base_url": base}, LINK_SPEC)
    assert why in str(err.value)


@pytest.mark.parametrize("template, why", [
    ("alert/{alert_uid}", "start with a single '/'"),
    ("//evil.example.test/{alert_uid}", "start with a single '/'"),
    ("/alert/{alert_uid}?token={site_uid}", "may only contain"),
    ("/alert/{alert_uid}#x", "may only contain"),
    ("/@evil.example.test/{alert_uid}", "may only contain"),
    ("/alert/%2e%2e/{alert_uid}", "may only contain"),
    ("/alert/../{alert_uid}", "'.' or '..'"),
    ("/alert/{alert_uid}/{hostname}", "unknown placeholder {hostname}"),
    ("/alert/{alert_uid", "may only contain"),
    ("/alert/{}", "unknown placeholder {}"),
    ("/alerts", "must contain {alert_uid}"),
    ("/device/{device_uid}", "must contain {alert_uid}"),
    ("/" + "a" * 250 + "/{alert_uid}", "longer than"),
])
def test_path_template_override_is_refused(template, why):
    with pytest.raises(ValueError) as err:
        vl.validate_settings({"alert_path_template": template}, LINK_SPEC)
    assert why in str(err.value)


def test_unknown_setting_fields_are_refused():
    with pytest.raises(ValueError):
        vl.validate_settings({"portal_base_url": PORTAL, "derived_portal_base_url": "x"}, LINK_SPEC)
    with pytest.raises(ValueError):
        vl.validate_settings(["not", "a", "dict"], LINK_SPEC)


# ---------------------------------------------------------------------------
# … and AGAIN on every build: a stored value is never trusted
# ---------------------------------------------------------------------------

def test_a_tampered_stored_override_is_ignored_not_used():
    config = {
        vl.DERIVED_BASE_KEY: PORTAL,
        vl.SETTINGS_KEY: {
            "portal_base_url": "https://evil.example.test",
            "alert_path_template": "/x?y={alert_uid}",
            "device_path_template": "/d/{device_uid}",          # no such setting
        },
    }
    assert _links(config) == {
        "alert": f"{PORTAL}/alert/0a1b2c3d-aaaa-bbbb-cccc-000000000001",
    }


def test_a_tampered_derived_base_builds_nothing():
    assert _links({vl.DERIVED_BASE_KEY: "https://evil.example.test"}) == {}
    assert _links({vl.DERIVED_BASE_KEY: "http://exampleplat.rmm.datto.com"}) == {}
    assert _links({vl.DERIVED_BASE_KEY: {"x": 1}}) == {}


# ---------------------------------------------------------------------------
# Device links: the vendor's portalUrl is hostile until proven otherwise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("portal_url", [
    f"{PORTAL}/device/4242",
    f"{PORTAL}/device/4242/WS-EXAMPLE-01",          # the cosmetic host-name segment
    f"{PORTAL}/device/4242/",
    "HTTPS://ExamplePlat.RMM.Datto.com/device/4242",
])
def test_a_good_portal_url_is_rebuilt_from_the_base_and_the_digits(portal_url):
    url = device_portal_url(portal_url, PORTAL)
    assert url == f"{PORTAL}/device/4242"
    assert device_links.checked_url(url, PORTAL) == url      # the framework agrees


HOSTILE_PORTAL_URLS = [
    "https://evil.example.test/device/4242",
    "https://exampleplat.rmm.datto.com.evil.example.test/device/4242",
    "https://evil.example.test/exampleplat.rmm.datto.com/device/4242",
    "https://exampleplat.rmm.datto.com@evil.example.test/device/4242",
    "https://user@exampleplat.rmm.datto.com/device/4242",
    "https://otherplat.rmm.datto.com/device/4242",            # a real-looking OTHER platform
    "https://rmm.datto.com/device/4242",
    "https://exampleplat.rmm.datto.com./device/4242",
    "https://exampleplat.rmm.datto.com:8443/device/4242",
    "https://exampleplat.rmm.datto.com:443/device/4242",
    "http://exampleplat.rmm.datto.com/device/4242",
    "//exampleplat.rmm.datto.com/device/4242",
    "/device/4242",
    "javascript:alert(1)//exampleplat.rmm.datto.com/device/4242",
    "data:text/html,<script>1</script>",
    f"{PORTAL}/device/4242?next=https://evil.example.test",
    f"{PORTAL}/device/4242#https://evil.example.test",
    f"{PORTAL}/device/4242/a/b",
    f"{PORTAL}/device/4242/../../admin",
    f"{PORTAL}/device/dev-uid-0001",                          # a uid is not the portal's id
    f"{PORTAL}/device/",
    f"{PORTAL}/device/-1",
    f"{PORTAL}/device/\u0664\u0662",                          # digits of another script
    f"{PORTAL}/device/" + "9" * 21,
    f"{PORTAL}/web-remote/4242",
    f"{PORTAL}/",
    PORTAL,
    f"{PORTAL}\\@evil.example.test/device/4242",
    f"{PORTAL}/device/4242\r\nLocation: https://evil.example.test",
    f" {PORTAL}/device/4242",
    f"{PORTAL}/device/4242 ",
    f"{PORTAL}/device/42\x0042",
    "https://exampleplat.rmm.datto.com\u2044device/4242",
    f"{PORTAL}/device/4242/" + "a" * 400,
    "", None, 4242, ["https://exampleplat.rmm.datto.com/device/4242"], {"url": "x"},
]


@pytest.mark.parametrize("portal_url", HOSTILE_PORTAL_URLS)
def test_a_hostile_or_odd_portal_url_yields_no_link(portal_url):
    assert device_portal_url(portal_url, PORTAL) is None
    # The framework's host allowlist on its own refuses every one that leaves
    # the portal host (it does not know the vendor's path scheme).
    checked = device_links.checked_url(portal_url, PORTAL)
    if checked is not None:
        assert urlsplit(checked).netloc == "exampleplat.rmm.datto.com"
        assert "?" not in checked and "#" not in checked and "@" not in checked


@pytest.mark.parametrize("base", [
    None, "", "http://exampleplat.rmm.datto.com", "https://exampleplat.rmm.datto.com:8443",
    "https://user@exampleplat.rmm.datto.com", "exampleplat.rmm.datto.com", 7,
])
def test_without_a_sound_portal_base_there_is_no_device_link(base):
    assert device_portal_url(f"{PORTAL}/device/4242", base) is None
    assert device_links.checked_url(f"{PORTAL}/device/4242", base) is None
