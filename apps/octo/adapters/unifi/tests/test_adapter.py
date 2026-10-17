"""UniFiSourceAdapter — onboarding, discovery, smoke, extraction, routing,
deep links, the card summary, and the migration path from the retired
local-controller adapter (same vendor slug)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from shared_adapter_contract.types import VendorTenantListError

from apps.octo.adapters.unifi import UniFiSourceAdapter, catalogue
from apps.octo.adapters.unifi.adapter import LEGACY_MESSAGE, LINK_SPEC
from apps.octo.adapters.unifi.limiter import reset_limiters
from apps.octo.adapters.unifi.tests.fake_unifi import (
    API_KEY,
    CREDS,
    HOST_A,
    SCOPE_A,
    SCOPE_B,
    SCOPE_C,
    SITE_DEFAULT,
    T0,
    FakeClock,
    FakeUniFiTransport,
    client_factory,
    fake_limiter,
    ips_event,
    lan,
    standard_fleet,
)
from apps.octo.instances.vendor_links import build_links, validate_path_template


@pytest.fixture
def env():
    reset_limiters()
    clock = FakeClock()
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)
    fake_limiter(clock)
    yield clock, transport, UniFiSourceAdapter(client_factory=client_factory(transport))
    reset_limiters()


def _signal(raw):
    site = catalogue.SiteContext(SCOPE_A, HOST_A, SITE_DEFAULT, "default", "Acme Corp", "acme-udm")
    ev = catalogue.normalise(raw)
    return catalogue.signal_payload(
        catalogue.classify(ev.category, ev.subcategory, ev.event, ev.vendor_severity), ev, site)


def test_shape_and_onboarding():
    a = UniFiSourceAdapter()
    assert [f.name for f in a.credential_shape()] == ["UNIFI_API_KEY"]
    assert a.credential_shape()[0].kind == "password"
    shape = a.tenant_mapping_shape()
    assert shape.tenant_noun == "site" and shape.vendor_tenant_id_field == "hostId/siteId"
    assert "NOT unique" in shape.id_help
    assert (a.supports_tenant_discovery, a.tenant_ids_are_slugs, a.reports_vendor_contact,
            a.first_import_auto_start) == (True, False, True, False)
    text = " ".join(s.body for s in a.onboarding().steps)
    assert "no bulk accept" in text.lower() and "location" in text


def test_discovery_is_two_calls_with_console_and_location(env):
    clock, transport, adapter = env
    listing = adapter.list_vendor_tenants(dict(CREDS))
    assert transport.paths() == ["/v1/hosts", "/v1/sites"]
    labels = {t.id: t.label for t in listing.tenants}
    assert set(labels) == {SCOPE_A, SCOPE_B, SCOPE_C}             # one site id, three sites
    assert labels[SCOPE_B] == "Example Bakery — bakery-ucg (200 Example Ave, Shelbyville)"
    transport.key = "fixture-another-key-" + "9" * 24
    with pytest.raises(VendorTenantListError) as e:
        adapter.list_vendor_tenants(dict(CREDS))
    assert e.value.kind == "auth" and API_KEY not in str(e.value)


def test_smoke_and_credential_checks(env):
    clock, transport, adapter = env
    assert adapter.smoke_test(dict(CREDS)).ok
    assert not adapter.smoke_test({}).ok
    bad = adapter.smoke_test({"UNIFI_API_KEY": "two words"})
    assert not bad.ok and "unusual character" in bad.message


def test_a_legacy_local_controller_instance_is_refused_with_the_way_forward(env):
    clock, transport, adapter = env
    legacy = {"UNIFI_CONTROLLER_URL": "https://unifi.example.test", "UNIFI_API_KEY": "k"}
    with pytest.raises(ValueError) as e:
        adapter.start({**legacy, "_instance_id": 1})
    assert str(e.value) == LEGACY_MESSAGE and "Disable this integration" in LEGACY_MESSAGE
    assert adapter.poller is None and transport.calls == []
    assert not adapter.smoke_test(legacy).ok


def test_extract_event_is_typed_timed_and_carries_the_ioc(env):
    clock, transport, adapter = env
    payload = _signal(ips_event(T0 - timedelta(minutes=3)))
    ev = adapter.extract_event(payload)
    assert ev.event_type == "unifi.ips_threat" and ev.severity == "high"
    assert (ev.indicator, ev.indicator_type) == ("203.0.113.66", "ip")
    assert ev.received_at == "2026-10-01T11:57:00.000Z"
    # The live IPS event names no client: the LAN address is the device.
    assert ev.source_host == lan(37)
    assert ev.vendor_event_id == payload["vendor_event_id"]
    assert ev.payload["ocsf"]["class_uid"] == 2004
    assert adapter.extract_event(payload).payload_sha256 == ev.payload_sha256   # stable


def test_routing_is_the_site_and_never_a_default(env):
    clock, transport, adapter = env
    payload = _signal(ips_event(T0))
    assert adapter.route_to_tenant(payload) == SCOPE_A
    assert adapter.route_to_tenant({**payload, "scope": SITE_DEFAULT}) is None   # a bare site id
    assert adapter.route_to_tenant({"_octo_tenant_slug": "acme-corp"}) is None   # legacy stamp
    assert adapter.vendor_tenant_label(payload) == "Acme Corp"


def test_deep_links_name_the_console_and_site(env):
    clock, transport, adapter = env
    payload = _signal(ips_event(T0))
    ev = adapter.extract_event(payload)
    ids = UniFiSourceAdapter.vendor_link_ids(payload)
    assert ids == {"alert_uid": HOST_A, "site_uid": "default"}
    # The fixture host ('F1X7…:…') is not UniFi's '<hex>:<digits>': no link —
    # never one with '%3A', which the portal answers "Access denied".
    assert adapter.deep_link(ev, "alert") is None
    assert build_links({"derived_portal_base_url": "https://unifi.ui.com"}, LINK_SPEC, ids) == []
    # A host id of UniFi's shape keeps its ':' (verified path, 2026-10-08).
    real = "FA4E" + "0" * 52 + "C0DE:1000000042"
    ev = adapter.extract_event({**payload, "host_id": real})
    url = adapter.deep_link(ev, "alert")
    assert url == f"https://unifi.ui.com/consoles/{real}/network/default/dashboard"
    assert adapter.deep_link(ev, "host") is None
    assert LINK_SPEC.paths_verified is True
    validate_path_template(LINK_SPEC.default_alert_path, kind="alert")
    (link,) = build_links({"derived_portal_base_url": "https://unifi.ui.com"}, LINK_SPEC,
                          {**ids, "alert_uid": real})
    assert link.url == url and link.label == "Open in UniFi Site Manager"
    assert UniFiSourceAdapter.vendor_link_ids({"host_id": "../x", "site_ref": "default"}) == {}
