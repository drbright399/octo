"""NextDNSSourceAdapter: the contract surface. One credential; Test
connection and discovery are ONE call each (never per profile); records →
CanonicalEvents with the domain as indicator; the profile's logs page as the
deep link; no tenant auto-create (profile ids are never slugs)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from apps.octo.adapters.nextdns import NextDNSSourceAdapter
from apps.octo.adapters.nextdns import limiter as lim
from apps.octo.adapters.nextdns.tests.fake_nextdns import (
    API_KEY,
    CREDS,
    T0,
    FakeClock,
    FakeNextDNSTransport,
    block_line,
    client_factory,
    fake_limiter,
)
from apps.octo.framework.discovery import discover_adapters
from apps.octo.framework.registry import AdapterRegistry
from apps.octo.instances import vendor_links


@pytest.fixture
def adapter():
    lim.reset_limiters()
    clock = FakeClock()
    transport = FakeNextDNSTransport(clock)
    fake_limiter(clock)
    yield NextDNSSourceAdapter(client_factory=client_factory(transport)), transport
    lim.reset_limiters()


def _payload(**over):
    base = {
        "vendor_event_id": "line-1", "kind": "security_block", "profile_id": "abc123",
        "profile_name": "Acme Corp Office", "log": block_line(T0 - timedelta(minutes=1)),
        "signal": {"level": "high", "reason_id": "threat-intelligence-feeds",
                   "reason_label": "a threat-intelligence domain",
                   "bucket_hour": "2026-09-30T11:00:00Z"},
    }
    base.update(over)
    return base


def test_discovered_and_described():
    registry = AdapterRegistry()
    report = discover_adapters("apps.octo.adapters", registry)
    assert "nextdns" in report.registered
    cls = registry.get_adapter_class("nextdns")
    assert cls.delivery_mode == "poll" and cls.supports_tenant_discovery
    assert cls.tenant_ids_are_slugs is False and cls.reports_vendor_contact
    [field] = cls().credential_shape()
    assert field.name == "NEXTDNS_API_KEY" and field.kind == "password"
    shape = cls().tenant_mapping_shape()
    assert shape.tenant_noun == "profile" and shape.vendor_tenant_id_field == "id"
    onboarding = cls().onboarding()
    assert onboarding.webhook_url is None
    text = " ".join(s.body for s in onboarding.steps)
    assert "never polled" in text and "Ignore" in text and "403" in text


def test_smoke_test_is_one_call(adapter):
    a, transport = adapter
    result = a.smoke_test(dict(CREDS))
    assert result.ok and "5 profile(s)" in result.message
    assert transport.paths() == ["/profiles"]
    bad = a.smoke_test({"NEXTDNS_API_KEY": "fixture-wrong-key-000000"})
    assert not bad.ok and "401" in bad.message and API_KEY not in bad.message
    assert not a.smoke_test({}).ok
    assert "one line" in a.smoke_test({"NEXTDNS_API_KEY": "two\nlines"}).message


def test_discovery_is_one_call_listing_every_profile(adapter):
    a, transport = adapter
    listing = a.list_vendor_tenants(dict(CREDS))
    assert [(t.id, t.label) for t in listing.tenants][:2] == [
        ("abc123", "Acme Corp Office"), ("abc124", "Acme Corp Warehouse")]
    assert len(listing.tenants) == 5 and not listing.truncated
    assert transport.paths() == ["/profiles"]


def test_discovery_failures_are_operator_safe(adapter):
    from shared_adapter_contract.types import VendorTenantListError

    a, transport = adapter
    transport.key = "fixture-rotated"
    with pytest.raises(VendorTenantListError) as exc:
        a.list_vendor_tenants(dict(CREDS))
    assert exc.value.kind == "auth" and API_KEY not in exc.value.message


def test_extract_event(adapter):
    a, _ = adapter
    event = a.extract_event(_payload())
    assert event.event_type == "nextdns.security_block"
    assert event.severity == "high" and event.vendor_event_id == "line-1"
    assert event.indicator == "c2.bad-example.test" and event.indicator_type == "domain"
    assert event.received_at == "2026-09-30T11:59:00.000Z"
    assert event.source_host == "alice-laptop"
    assert event.summary == "NextDNS blocked a threat-intelligence domain — alice-laptop"
    assert a.route_to_tenant(event.payload) == "abc123"
    assert a.route_to_tenant({"profile_id": "../x"}) is None
    again = a.extract_event(_payload())
    assert again.payload_sha256 == event.payload_sha256            # deterministic
    lapsed = a.extract_event({"kind": "protection_lapsed", "profile_id": "abc123",
                              "vendor_event_id": "lapsed:abc123:x",
                              "detected_at": "2026-09-30T15:00:00.000Z"})
    assert (lapsed.severity, lapsed.event_type, lapsed.indicator) == (
        "medium", "nextdns.protection_lapsed", None)
    restored = a.extract_event({"kind": "protection_restored", "profile_id": "abc123"})
    assert restored.severity == "low"


def test_links_open_the_profiles_logs_page(adapter):
    a, _ = adapter
    event = a.extract_event(_payload())
    assert a.deep_link(event, "alert") == "https://my.nextdns.io/abc123/logs"
    assert a.deep_link(event, "device") is None
    ids = NextDNSSourceAdapter.vendor_link_ids(event.payload)
    config = {vendor_links.DERIVED_BASE_KEY: NextDNSSourceAdapter.derive_portal_base({})}
    [link] = vendor_links.build_links(config, NextDNSSourceAdapter.vendor_link_spec(), ids)
    assert link.url == "https://my.nextdns.io/abc123/logs"
    assert link.label == "Open in NextDNS"
    assert NextDNSSourceAdapter.vendor_link_ids({"profile_id": "a/b"}) == {}


def test_health_before_and_after_start(adapter):
    a, _ = adapter
    assert a.health().alive is False


@pytest.mark.asyncio
async def test_the_framework_starts_and_stops_the_poller(world):
    """InstanceManager → adapter.start → the poller's loop runs a cycle on a
    worker thread (discovery only: nothing mapped) → stop is clean."""
    import asyncio

    from apps.octo.adapters.nextdns.tests.fake_nextdns import nextdns_adapter_class
    from apps.octo.instances.manager import InstanceManager

    registry = AdapterRegistry()
    registry.register_adapter_class(nextdns_adapter_class(world.transport, world.clock))
    manager = InstanceManager(adapter_registry=registry)
    manager.start_instance(world.record)
    adapter = manager.running_adapter(world.record.id)
    for _ in range(500):
        if world.transport.calls:
            break
        await asyncio.sleep(0.01)
    assert world.transport.paths() == ["/profiles"]
    for _ in range(500):
        if adapter.health().detail.get("nextdns", {}).get("known") == 5:
            break
        await asyncio.sleep(0.01)
    detail = adapter.health().detail
    assert detail["waiting_for_tenant_mapping"] is True and detail["first_import_at"] is None
    assert detail["nextdns"]["known"] == 5
    manager.nudge(world.record.id)
    manager.stop_instance(world.record.id)
    assert adapter.poller is None
