"""`vendor_links.build_url` id encoding (2026-10-08: the Fleet's "Open in
UniFi Site Manager" opened "Access denied" — the console host id
'<hex>:<digits>' went into the path as '<hex>%3A<digits>').

A spec may declare characters ONE placeholder's ids keep unencoded, only for
an id of the vendor's strict shape; an id that carries such a character but
not the shape gets NO link; nothing can ever keep '/', '?', '#', '@', '%',
'.', whitespace; '.' / '..' never fill a placeholder. Every other vendor's
ids are encoded whole, exactly as before."""
from __future__ import annotations

import re

import pytest
from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.datto.links import LINK_SPEC as DATTO_SPEC
from apps.octo.adapters.nextdns.adapter import LINK_SPEC as NEXTDNS_SPEC
from apps.octo.adapters.unifi.adapter import LINK_SPEC as UNIFI_SPEC
from apps.octo.adapters.unifi.adapter import UniFiSourceAdapter
from apps.octo.instances import vendor_links
from apps.octo.instances.vendor_links import KeptIdChars, build_links, build_url, encode_id

UNIFI = "https://unifi.ui.com"
# Synthetic, but UniFi's shape: hex, ':', digits.
HOST = "FA4E" + "0" * 52 + "C0DE:1000000042"
TEMPLATE = UNIFI_SPEC.default_alert_path


def _unifi(host_id, ref="default"):
    return build_url(UNIFI, TEMPLATE, {"alert_uid": host_id, "site_uid": ref}, spec=UNIFI_SPEC)


def test_a_unifi_host_id_keeps_its_colon():
    assert _unifi(HOST) == f"{UNIFI}/consoles/{HOST}/network/default/dashboard"
    assert _unifi(HOST.lower()) == f"{UNIFI}/consoles/{HOST.lower()}/network/default/dashboard"
    assert "%3A" not in _unifi(HOST)
    # Without the spec (the old call): encoded whole — the "Access denied" link.
    assert build_url(UNIFI, TEMPLATE, {"alert_uid": HOST, "site_uid": "default"}) == \
        f"{UNIFI}/consoles/{HOST.replace(':', '%3A')}/network/default/dashboard"
    # The template is the verified one.
    assert UNIFI_SPEC.paths_verified is True
    assert UNIFI_SPEC.default_alert_path == "/consoles/{alert_uid}/network/{site_uid}/dashboard"


@pytest.mark.parametrize("hostile", [
    "F1X7" + "0" * 50 + ":100000001",        # not hex
    "AB" * 9 + "A:1",                       # 19 hex digits — too short
    "AB" * 61 + ":1",                       # 122 hex digits — too long
    HOST + "0" * 12,                        # 13+ digits after the colon
    HOST.replace(":", "::"),
    HOST + ":1",
    ":" + HOST,
    HOST + "/../x",
    HOST + "?x=1",
    HOST + "#x",
    "user@" + HOST,
    HOST + " x",
    HOST.replace(":", ": "),
    HOST + "\n",
    "",
])
def test_an_id_with_a_colon_but_not_the_shape_gets_no_link(hostile):
    assert _unifi(hostile) is None


@pytest.mark.parametrize("value, encoded", [
    ("ABCDEF0123", "ABCDEF0123"),           # no colon: as before
    ("a/b", "a%2Fb"),
    ("a?b#c", "a%3Fb%23c"),
    ("a@b", "a%40b"),
    ("a%3Ab", "a%253Ab"),
    ("a b", "a%20b"),
])
def test_ids_without_the_kept_character_are_encoded_whole(value, encoded):
    rule = UNIFI_SPEC.keep_unencoded[0]
    assert encode_id(value, rule) == encoded
    assert encode_id(value) == encoded


@pytest.mark.parametrize("dots", [".", ".."])
def test_dot_ids_never_fill_a_placeholder(dots):
    assert encode_id(dots) is None
    assert build_url("https://fixture.rmm.datto.com", "/alert/{alert_uid}",
                     {"alert_uid": dots}, spec=DATTO_SPEC) is None
    assert _unifi(HOST, ref=dots) is None


def test_the_rule_is_per_placeholder():
    # site_uid has no rule: a ':' there is encoded (UniFi's internal
    # references never carry one).
    assert _unifi(HOST, ref="a:b") == f"{UNIFI}/consoles/{HOST}/network/a%3Ab/dashboard"


def test_other_vendors_are_unchanged():
    # Datto / NextDNS declare nothing: a ':' is encoded, as before.
    assert DATTO_SPEC.keep_unencoded == () and NEXTDNS_SPEC.keep_unencoded == ()
    assert build_url("https://fixture.rmm.datto.com", "/alert/{alert_uid}",
                     {"alert_uid": "ab:12"}, spec=DATTO_SPEC) == \
        "https://fixture.rmm.datto.com/alert/ab%3A12"
    assert build_url("https://my.nextdns.io", "/{alert_uid}/logs",
                     {"alert_uid": "abc123"}, spec=NEXTDNS_SPEC) == \
        "https://my.nextdns.io/abc123/logs"
    (link,) = build_links({"vendor_links": {"portal_base_url": "https://fixture.rmm.datto.com"}},
                          DATTO_SPEC, {"alert_uid": "ab:12"})
    assert link.url.endswith("/alert/ab%3A12")


def _event(payload):
    return CanonicalEvent(vendor_event_id="e1", received_at="2026-10-08T12:00:00.000Z",
                          severity="low", indicator=None, indicator_type=None,
                          source_host=None, summary="x", payload=payload,
                          payload_sha256="0" * 64)


def test_alert_links_and_the_adapters_deep_link_get_the_same_fix():
    # The alerts feed / search drawer (build_links) …
    ids = {"alert_uid": HOST, "site_uid": "default"}
    (link,) = build_links({"derived_portal_base_url": UNIFI}, UNIFI_SPEC, ids)
    assert link.url == f"{UNIFI}/consoles/{HOST}/network/default/dashboard"
    # … and the contract's deep_link() (the search drawer's fallback).
    event = _event({"host_id": HOST, "site_ref": "default"})
    assert UniFiSourceAdapter().deep_link(event, "alert") == link.url
    odd = _event({"host_id": "F1X7" + "0" * 50 + ":1", "site_ref": "default"})
    assert UniFiSourceAdapter().deep_link(odd, "alert") is None


@pytest.mark.parametrize("chars", ["/", "?", "#", "@", "%", ".", " ", "\\", ":/", "", "~"])
def test_a_spec_can_never_keep_a_dangerous_character(chars):
    with pytest.raises(ValueError):
        KeptIdChars("alert_uid", chars, re.compile(r".*"))


def test_a_rule_names_a_known_placeholder_and_a_compiled_shape():
    with pytest.raises(ValueError):
        KeptIdChars("host", ":", re.compile(r".*"))
    with pytest.raises(ValueError):
        KeptIdChars("alert_uid", ":", r".*")  # type: ignore[arg-type]
    assert set(vendor_links.KEEPABLE_ID_CHARS).isdisjoint(set("/?#@%. \t\\"))
