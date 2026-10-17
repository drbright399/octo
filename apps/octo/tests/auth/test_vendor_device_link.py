"""POST /dashboard/vendor-device-link — "open this device in Datto RMM".

Through the real HTTP route with the REAL Datto adapter, client, instance
manager, tenant map and cache — only the vendor socket is fake.

What the live portal/API showed, and what this therefore pins:
  * a device page is /device/<NUMERIC id>; payloads carry only the device
    UID → the address is looked up at the vendor, ON CLICK, never per row;
  * the vendor's `portalUrl` is vendor data: a hostile value must never
    become a link (the "is this an open redirect?" question, answered with
    the hostile list);
  * the same object has `webRemoteUrl` (a remote-control session): it must
    not reach a response, a log line or the cache;
  * a Viewer cannot call this; an operator can only resolve devices of a
    tenant in their scope whose site maps to that tenant.
"""
from __future__ import annotations

import json
import logging

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.datto.tests.fake_datto import (
    SECRETS,
    WEB_REMOTE_MARKER,
    device_object,
)
from apps.octo.adapters.datto.tests.test_links import HOSTILE_PORTAL_URLS
from apps.octo.adapters.datto.tests.test_presentation import EVENTLOG, api_alert
from apps.octo.db import connect, transaction
from apps.octo.instances import device_links, tenant_map
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)
from apps.octo.tests.auth.test_dashboard_datto_presentation import (  # noqa: F401
    CREDS,
    PORTAL,
    _create_instance,
    _map_site,
    _settings_url,
    _store_legacy_row,
    datto,
)

_RESOLVE = "/api/v1/dashboard/vendor-device-link"
_DEVICE_CALL = ("GET", "/api/v2/device/dev-uid-0001")


def _setup(client, *, map_site: bool = True):
    """admin alice + a running instance + one stored Datto alert in 'acme'."""
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies)
    if map_site:
        _map_site(iid)
    event_id = _store_legacy_row(api_alert(EVENTLOG))
    return cookies, iid, event_id


def _resolve(client, cookies, event_id, slug="acme"):
    return client.post(_RESOLVE, cookies=cookies, json={"client_slug": slug, "event_id": event_id})


def _device_reads(client) -> int:
    return client.datto_transport.calls.count(_DEVICE_CALL)


def _scope_to(operator_id: int, slugs: list[str]) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE operator_roles SET scope_slugs = ? WHERE operator_id = ?",
                (json.dumps(slugs), operator_id),
            )
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Resolve, cache
# ---------------------------------------------------------------------------

def test_resolves_the_numeric_device_page_and_caches_it(datto, caplog):
    caplog.set_level(logging.DEBUG)
    client = datto
    cookies, iid, event_id = _setup(client)
    assert _device_reads(client) == 0                 # nothing until someone clicks

    r = _resolve(client, cookies, event_id)
    assert r.status_code == 200, r.text
    assert r.json() == {
        "url": f"{PORTAL}/device/4242", "label": "Open device in Datto RMM",
        "vendor": "datto", "cached": False,
    }
    assert r.headers["cache-control"] == "no-store"

    again = _resolve(client, cookies, event_id)
    assert again.json()["cached"] is True and again.json()["url"] == f"{PORTAL}/device/4242"
    assert _device_reads(client) == 1                 # ONE vendor read for both

    # The remote-control address and the credentials went nowhere.
    cached = device_links.lookup(iid, _cred_ref(iid), "dev-uid-0001")
    assert cached == device_links.CachedDevice(f"{PORTAL}/device/4242", "site-uid-0001")
    for text in (r.text, again.text, caplog.text, repr(cached)):
        assert WEB_REMOTE_MARKER not in text and "web-remote" not in text
        for secret in SECRETS:
            assert secret not in text
    assert "dev-uid-0001" not in caplog.text          # nor is the device id logged


def _cred_ref(instance_id: int) -> str:
    from apps.octo.instances.manager import get_instance

    return get_instance(instance_id).cred_ref


def test_the_caller_names_an_event_never_a_device(datto):
    client = datto
    cookies, _, event_id = _setup(client)
    for body in (
        {"client_slug": "acme", "event_id": event_id, "device_uid": "dev-uid-0001"},
        {"client_slug": "acme", "device_uid": "dev-uid-0001"},
        {"client_slug": "acme", "event_id": 0},
        {"client_slug": "", "event_id": event_id},
    ):
        assert client.post(_RESOLVE, cookies=cookies, json=body).status_code == 422
    assert client.get(_RESOLVE, cookies=cookies).status_code == 405      # POST only
    assert _device_reads(client) == 0


# ---------------------------------------------------------------------------
# Who may resolve what
# ---------------------------------------------------------------------------

def test_a_viewer_cannot_call_the_resolver(datto):
    client = datto
    _, _, event_id = _setup(client)
    viewer = client.login(
        client.provision_operator("bob", "password1234567", athena_role="viewer")
    )
    r = _resolve(client, viewer, event_id)
    assert r.status_code == 403 and "url" not in r.json()
    client.cookies.clear()                             # and nobody at all: 401
    assert client.post(_RESOLVE, json={"client_slug": "acme", "event_id": event_id}).status_code == 401
    assert _device_reads(client) == 0


def test_an_operator_cannot_resolve_outside_their_scope(datto):
    """Out of scope looks EXACTLY like 'no such event' — no oracle."""
    client = datto
    _, _, event_id = _setup(client)
    client_provisioning.create_client("globex", "Globex")
    carol = client.provision_operator("carol", "password1234567", athena_role="analyst")
    _scope_to(carol["id"], ["globex"])
    cookies = client.login(carol)

    out_of_scope = _resolve(client, cookies, event_id)
    missing = _resolve(client, cookies, 999_999, slug="globex")
    assert out_of_scope.status_code == missing.status_code == 404
    assert out_of_scope.json()["message"] == missing.json()["message"]
    assert _resolve(client, cookies, event_id, slug="../acme").status_code == 404
    assert _device_reads(client) == 0

    _scope_to(carol["id"], ["acme"])
    assert _resolve(client, cookies, event_id).status_code == 200


def test_the_alerts_site_must_map_to_the_tenant(datto):
    """Payload-side check, BEFORE the vendor is asked anything."""
    client = datto
    cookies, iid, event_id = _setup(client, map_site=False)
    r = _resolve(client, cookies, event_id)
    assert r.status_code == 404 and "not mapped to this client" in r.json()["message"]
    client_provisioning.create_client("globex", "Globex")
    _map_site(iid, slug="globex")                      # mapped — to someone else
    assert _resolve(client, cookies, event_id).status_code == 404
    assert _device_reads(client) == 0


def test_the_device_the_vendor_describes_must_belong_to_the_tenant_too(datto):
    """Vendor-side check: the alert says site A (mapped to acme), but Datto
    says the device now lives in a site that is not acme's. Refused — and the
    refusal is served from memory afterwards, not from a second vendor read."""
    client = datto
    cookies, iid, event_id = _setup(client)
    client.datto_transport.devices["dev-uid-0001"] = device_object(site_uid="site-uid-0002")
    for _ in range(2):
        r = _resolve(client, cookies, event_id)
        assert r.status_code == 403, r.text
        assert r.json()["code"] == "ISOLATION_VIOLATION"
        assert "url" not in r.json() and "/device/" not in r.text
    assert _device_reads(client) == 1
    assert "Not asked again" in r.json()["message"]


def test_a_device_that_moved_to_another_tenants_site_is_re_asked_not_refused_from_memory(datto):
    """The cache holds what the vendor said HOURS ago. A device that has moved
    from acme's site to globex's must open for a globex analyst on the next
    click — a fresh vendor read, not the stale site replayed as a refusal —
    and acme's own refusal is remembered for acme only."""
    client = datto
    cookies, iid, event_id = _setup(client)
    assert _resolve(client, cookies, event_id).status_code == 200      # cached: site-uid-0001
    assert _device_reads(client) == 1

    # The device moves to site 2, mapped to globex; a new alert lands there.
    client_provisioning.create_client("globex", "Globex")
    tenant_map.set_mappings(iid, [
        tenant_map.TenantMapping("site-uid-0001", "acme"),
        tenant_map.TenantMapping("site-uid-0002", "globex"),
    ])
    client.datto_transport.devices["dev-uid-0001"] = device_object(site_uid="site-uid-0002")
    moved = api_alert(EVENTLOG)
    moved["alertSourceInfo"] = {**moved["alertSourceInfo"], "siteUid": "site-uid-0002"}
    globex_event = _store_legacy_row(moved, slug="globex")
    dave = client.provision_operator("dave", "password1234567", athena_role="analyst")
    _scope_to(dave["id"], ["globex"])
    globex_cookies = client.login(dave)

    r = _resolve(client, globex_cookies, globex_event, slug="globex")
    assert r.status_code == 200, r.text
    assert r.json()["url"] == f"{PORTAL}/device/4242" and r.json()["cached"] is False
    assert _device_reads(client) == 2                        # re-asked, once

    # acme's old alert: the vendor is asked once more (its cached site no
    # longer maps to acme), says site 2 → refused; the retry is from memory,
    # for acme — while globex keeps opening it from the cache.
    refused = _resolve(client, cookies, event_id)
    assert (refused.status_code, refused.json()["code"]) == (403, "ISOLATION_VIOLATION")
    assert _device_reads(client) == 3
    again = _resolve(client, cookies, event_id)
    assert again.status_code == 403 and "Not asked again" in again.json()["message"]
    assert _device_reads(client) == 3
    globex_again = _resolve(client, globex_cookies, globex_event, slug="globex")
    assert globex_again.status_code == 200 and globex_again.json()["cached"] is True
    assert _device_reads(client) == 3


def test_a_device_the_vendor_places_in_no_site_is_not_an_isolation_violation(datto):
    """GET /device answers without a siteUid: nothing can be mapped. That is
    'the vendor's answer could not be checked' — not 'this device belongs to
    another client', which would send the admin to a tenant mapping that is
    fine. Nothing is cached; the retry is throttled like any failure."""
    client = datto
    cookies, iid, event_id = _setup(client)
    for absent in (None, "", "  "):
        device_links.reset(iid)
        client.datto_transport.devices["dev-uid-0001"] = {**device_object(), "siteUid": absent}
        r = _resolve(client, cookies, event_id)
        assert r.status_code == 503, r.text
        assert r.json()["code"] == "VENDOR_UNREACHABLE"
        assert "did not say which site" in r.json()["message"]
        assert "not mapped to this client" not in r.json()["message"]
        assert device_links.cached_count(iid) == 0
    assert "Not asked again" in _resolve(client, cookies, event_id).json()["message"]
    assert _device_reads(client) == 3


def test_lookups_of_different_devices_do_not_share_a_flight(datto):
    """The single-flight lock dedups a double click on ONE device. It must
    not serialise every operator's click on a slow vendor behind the first:
    one lock per (instance, device), the same lock for the same device."""
    from types import SimpleNamespace

    from apps.octo.api.routers.vendor_device_links import _flight

    request = SimpleNamespace(app=datto.app)
    a = _flight(request, 7, "dev-uid-0001")
    assert _flight(request, 7, "dev-uid-0001") is a
    assert _flight(request, 7, "dev-uid-0002") is not a
    assert _flight(request, 8, "dev-uid-0001") is not a


def test_other_sources_and_payloads_without_a_device_id_have_no_link(datto):
    client = datto
    cookies, _, _ = _setup(client)
    wazuh = _store_legacy_row({"rule": {"id": 1}}, source="wazuh", event_type="auth.failure")
    no_device = _store_legacy_row({"alertUid": "a-2", "siteUid": "site-uid-0001"})
    templated = _store_legacy_row(
        {"alertUid": "a-3", "siteUid": "site-uid-0001", "device": {"uid": "[device_uid]"}},
    )
    for event_id in (wazuh, no_device, templated):
        r = _resolve(client, cookies, event_id)
        assert r.status_code == 404 and r.json()["message"].startswith("No device link")
    assert not [c for c in client.datto_transport.calls if "/device/" in c[1]]


# ---------------------------------------------------------------------------
# The vendor's answer is hostile until proven otherwise
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("portal_url", HOSTILE_PORTAL_URLS)
def test_a_hostile_portal_url_never_becomes_a_link(datto, portal_url, caplog):
    caplog.set_level(logging.DEBUG)
    client = datto
    cookies, iid, event_id = _setup(client)
    client.datto_transport.devices["dev-uid-0001"]["portalUrl"] = portal_url

    r = _resolve(client, cookies, event_id)
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["code"] == "VENDOR_UNREACHABLE" and "did not pass validation" in body["message"]
    assert "url" not in body and "location" not in {k.lower() for k in r.headers}
    assert "evil" not in r.text and "evil" not in caplog.text
    assert device_links.cached_count(iid) == 0         # a refused address is never cached

    # A retry inside the throttle window is answered from memory.
    again = _resolve(client, cookies, event_id)
    assert again.status_code == 503 and "Not asked again" in again.json()["message"]
    assert _device_reads(client) == 1


def test_a_device_the_vendor_no_longer_knows(datto):
    client = datto
    cookies, _, event_id = _setup(client)
    client.datto_transport.devices.clear()
    r = _resolve(client, cookies, event_id)
    assert r.status_code == 404 and "does not know this device" in r.json()["message"]


def test_vendor_refusals_say_so_without_a_link(datto):
    client = datto
    cookies, _, event_id = _setup(client)
    client.datto_transport.forbid_data = True
    r = _resolve(client, cookies, event_id)
    assert (r.status_code, r.json()["code"]) == (424, "VENDOR_ACCESS_FORBIDDEN")
    assert "url" not in r.json()
    for secret in SECRETS:
        assert secret not in r.text


def test_rejected_credentials_stop_lookups_for_every_device_for_a_while(datto):
    """A lookup without a valid token is a credential grant; repeated bad
    grants lock the API user out. After one refusal, a click on ANOTHER device
    is answered from memory — no second grant."""
    client = datto
    cookies, _, event_id = _setup(client)
    other = api_alert(EVENTLOG)
    other["alertSourceInfo"] = {**other["alertSourceInfo"], "deviceUid": "dev-uid-0002"}
    other_id = _store_legacy_row(other)
    transport = client.datto_transport
    transport.stale_token_once, transport.token_status = True, 401

    r = _resolve(client, cookies, event_id)
    assert (r.status_code, r.json()["code"]) == (424, "VENDOR_CREDENTIALS_REJECTED")
    calls = len(transport.calls)
    again = _resolve(client, cookies, other_id)
    assert again.json()["code"] == "VENDOR_CREDENTIALS_REJECTED"
    assert "Not asked again" in again.json()["message"]
    assert len(transport.calls) == calls
    for secret in SECRETS:
        assert secret not in r.text + again.text


def test_an_instance_that_is_not_running_contacts_nobody(datto):
    client = datto
    cookies, iid, event_id = _setup(client)
    client.app.state.instance_manager.stop_instance(iid)
    before = len(client.datto_transport.calls)
    r = _resolve(client, cookies, event_id)
    assert (r.status_code, r.json()["code"]) == (503, "SERVICE_UNAVAILABLE")
    assert "not running" in r.json()["message"]
    assert len(client.datto_transport.calls) == before


def test_the_vendor_read_budget_is_enforced(datto, monkeypatch):
    client = datto
    cookies, _, event_id = _setup(client)
    monkeypatch.setattr(device_links, "VENDOR_READS_PER_MINUTE", 1)
    other = api_alert(EVENTLOG)
    other["alertSourceInfo"] = {**other["alertSourceInfo"], "deviceUid": "dev-uid-0002"}
    client.datto_transport.devices["dev-uid-0002"] = device_object("dev-uid-0002", numeric_id=4343)
    other_id = _store_legacy_row(other)

    assert _resolve(client, cookies, event_id).status_code == 200
    r = _resolve(client, cookies, other_id)
    assert (r.status_code, r.json()["code"]) == (429, "RATE_LIMITED")
    assert _resolve(client, cookies, event_id).json()["cached"] is True   # cache hits are free
    assert not [c for c in client.datto_transport.calls if c[1].endswith("dev-uid-0002")]


# ---------------------------------------------------------------------------
# The cache never outlives what it was validated against
# ---------------------------------------------------------------------------

def test_disabling_the_instance_clears_the_cache_and_the_link(datto):
    client = datto
    cookies, iid, event_id = _setup(client)
    assert _resolve(client, cookies, event_id).status_code == 200
    assert device_links.cached_count(iid) == 1

    r = client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "rotating the key"}, cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert device_links.cached_count(iid) == 0
    assert _resolve(client, cookies, event_id).status_code == 404
    assert _device_reads(client) == 1


def test_changing_the_portal_base_drops_resolved_addresses(datto):
    """The cached address was validated against the OLD base. After an admin
    points the instance at another portal host, the vendor's portalUrl (still
    on the old host) no longer validates: no link."""
    client = datto
    cookies, iid, event_id = _setup(client)
    assert _resolve(client, cookies, event_id).status_code == 200
    r = client.put(_settings_url(iid), cookies=cookies, json={
        "portal_base_url": "https://otherplat.rmm.datto.com",
    })
    assert r.status_code == 200, r.text
    assert device_links.cached_count(iid) == 0
    refused = _resolve(client, cookies, event_id)
    assert refused.status_code == 503 and "did not pass validation" in refused.json()["message"]


def test_a_stale_cached_address_is_rechecked_not_trusted(datto):
    """Even if the cache is NOT cleared (defence in depth): an entry that does
    not sit on the portal base in force now is dropped and looked up again."""
    client = datto
    cookies, iid, event_id = _setup(client)
    device_links.store(iid, _cred_ref(iid), "dev-uid-0001", device_links.CachedDevice(
        "https://evil.example.test/device/1", "site-uid-0001",
    ))
    r = _resolve(client, cookies, event_id)
    assert r.status_code == 200 and r.json() == {
        "url": f"{PORTAL}/device/4242", "label": "Open device in Datto RMM",
        "vendor": "datto", "cached": False,
    }


def test_no_portal_base_means_no_lookup(datto):
    """fake_datto's lab API URL is not in the documented form: nothing can be
    derived, nothing was entered → the vendor is not even asked."""
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, cookies, creds=CREDS))
    event_id = _store_legacy_row(api_alert(EVENTLOG))
    r = _resolve(client, cookies, event_id)
    assert r.status_code == 404 and "portal address is not known" in r.json()["message"]
    assert _device_reads(client) == 0
