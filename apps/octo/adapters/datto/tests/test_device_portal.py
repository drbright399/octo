"""The device page lookup — real DattoClient + real DattoSourceAdapter, only
the socket is fake (fake_datto.py).

Facts from the live portal/API this pins:
  * the portal addresses a device as /device/<NUMERIC id>; alert payloads
    carry only the device UID, so the address comes from the API's device
    object (`portalUrl`) — validated, then rebuilt;
  * the same object carries `webRemoteUrl`, which starts a REMOTE-CONTROL
    session. It must not leave the client: not in a return value, a log line
    or an exception.
"""
from __future__ import annotations

import logging

import pytest

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.client import (
    DEVICE_PORTAL_FIELDS,
    DattoConfig,
    DattoForbiddenError,
    DattoNotFoundError,
)
from apps.octo.adapters.datto.tests.fake_datto import (
    API_KEY,
    API_SECRET,
    PLATFORM_API_URL,
    PLATFORM_PORTAL,
    SECRETS,
    WEB_REMOTE_MARKER,
    FakeDattoTransport,
    client_factory,
    device_object,
    real_client,
)
from apps.octo.adapters.datto.tests.test_links import HOSTILE_PORTAL_URLS
from apps.octo.instances.device_links import DeviceLookupError, DevicePortalLookup

DEVICE_PATH = "/api/v2/device/dev-uid-0001"


def _platform_transport() -> FakeDattoTransport:
    transport = FakeDattoTransport()
    transport.api_hosts.add("exampleplat-api.centrastage.net")
    return transport


def _client(transport: FakeDattoTransport):
    return real_client(transport, DattoConfig(
        api_url=PLATFORM_API_URL, api_key=API_KEY, api_secret_key=API_SECRET,
    ))


class _RunningAdapter(DattoSourceAdapter):
    """The real adapter with a client, as after start() — without a poller,
    which this capability does not involve."""

    def __init__(self, transport: FakeDattoTransport) -> None:
        super().__init__(client_factory=client_factory(transport))
        self._client = _client(transport)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

def test_the_client_returns_three_fields_and_never_the_remote_control_url():
    transport = _platform_transport()
    device = _client(transport).get_device_portal("dev-uid-0001")
    assert device == {
        "uid": "dev-uid-0001", "siteUid": "site-uid-0001",
        "portalUrl": f"{PLATFORM_PORTAL}/device/4242",
    }
    assert tuple(device) == DEVICE_PORTAL_FIELDS
    assert WEB_REMOTE_MARKER not in repr(device)
    assert transport.count(DEVICE_PATH) == 1
    assert transport.hosts == {"exampleplat-api.centrastage.net"}


@pytest.mark.parametrize("bad_uid", [
    "", " dev-uid-0001", "dev/../account", "../account", "dev?x=1", "dev#x", "a b",
    "dev\n", "x" * 129, ".hidden", None, 7, ["dev-uid-0001"],
])
def test_a_uid_that_is_not_shaped_like_one_is_never_put_into_a_request(bad_uid):
    transport = _platform_transport()
    with pytest.raises(ValueError):
        _client(transport).get_device_portal(bad_uid)
    assert transport.calls == []


def test_unknown_device_and_forbidden_are_told_apart():
    transport = _platform_transport()
    client = _client(transport)
    with pytest.raises(DattoNotFoundError):
        client.get_device_portal("no-such-device")
    transport.forbid_data = True
    with pytest.raises(DattoForbiddenError):
        client.get_device_portal("dev-uid-0001")


# ---------------------------------------------------------------------------
# Adapter capability
# ---------------------------------------------------------------------------

def test_the_adapter_resolves_a_device_page(caplog):
    caplog.set_level(logging.DEBUG)
    transport = _platform_transport()
    found = _RunningAdapter(transport).resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert found == DevicePortalLookup(
        portal_url=f"{PLATFORM_PORTAL}/device/4242", vendor_tenant_id="site-uid-0001",
    )
    assert WEB_REMOTE_MARKER not in caplog.text and WEB_REMOTE_MARKER not in repr(found)
    for secret in SECRETS:
        assert secret not in caplog.text


def test_the_cosmetic_hostname_segment_is_dropped():
    transport = _platform_transport()
    transport.devices["dev-uid-0001"] = device_object(
        portal_url=f"{PLATFORM_PORTAL}/device/4242/WS-EXAMPLE-01",
    )
    found = _RunningAdapter(transport).resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert found.portal_url == f"{PLATFORM_PORTAL}/device/4242"


@pytest.mark.parametrize("portal_url", HOSTILE_PORTAL_URLS)
def test_a_hostile_portal_url_from_the_vendor_is_refused(portal_url, caplog):
    caplog.set_level(logging.DEBUG)
    transport = _platform_transport()
    transport.devices["dev-uid-0001"] = device_object(portal_url=portal_url or "")
    transport.devices["dev-uid-0001"]["portalUrl"] = portal_url
    with pytest.raises(DeviceLookupError) as err:
        _RunningAdapter(transport).resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert err.value.kind == "invalid"
    # The refusal never repeats the vendor's string (nor anything secret).
    assert "evil" not in err.value.message and "http" not in err.value.message
    assert "evil" not in caplog.text and WEB_REMOTE_MARKER not in caplog.text


def test_a_portal_url_on_another_platform_than_the_configured_one_is_refused():
    transport = _platform_transport()
    adapter = _RunningAdapter(transport)
    with pytest.raises(DeviceLookupError) as err:
        adapter.resolve_device_portal("dev-uid-0001", "https://otherplat.rmm.datto.com")
    assert err.value.kind == "invalid"


def test_an_answer_about_a_different_device_is_refused():
    transport = _platform_transport()
    transport.devices["dev-uid-0001"] = device_object(uid="dev-uid-9999")
    with pytest.raises(DeviceLookupError) as err:
        _RunningAdapter(transport).resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert err.value.kind == "invalid"


@pytest.mark.parametrize("knob, kind", [
    ("forbid_data", "forbidden"), ("unreachable", "transport"),
])
def test_vendor_failures_are_operator_safe(knob, kind):
    transport = _platform_transport()
    adapter = _RunningAdapter(transport)
    setattr(transport, knob, True)
    with pytest.raises(DeviceLookupError) as err:
        adapter.resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert err.value.kind == kind
    for secret in SECRETS:
        assert secret not in err.value.message


def test_a_403_is_not_blamed_on_the_security_level():
    """Datto also answers 403 while it temporarily blocks this server's
    address after rate limiting — the same rule forbidden_guidance() follows.
    The message must name both causes, and the self-lifting one first."""
    transport = _platform_transport()
    transport.forbid_data = True
    with pytest.raises(DeviceLookupError) as err:
        _RunningAdapter(transport).resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    message = err.value.message
    assert "without saying why" in message
    assert "temporary block" in message and "lifts by itself" in message
    assert "security level" in message
    assert "does not cover this device" not in message


def test_rejected_credentials_unknown_device_and_bad_uid():
    transport = _platform_transport()
    adapter = _RunningAdapter(transport)
    with pytest.raises(DeviceLookupError) as err:
        adapter.resolve_device_portal("no-such-device", PLATFORM_PORTAL)
    assert err.value.kind == "not_found"
    with pytest.raises(DeviceLookupError) as err:
        adapter.resolve_device_portal("../account", PLATFORM_PORTAL)
    assert err.value.kind == "invalid"
    transport.token_status = 401
    fresh = _RunningAdapter(transport)
    with pytest.raises(DeviceLookupError) as err:
        fresh.resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert err.value.kind == "auth"


def test_an_adapter_that_is_not_running_contacts_nobody():
    transport = _platform_transport()
    adapter = DattoSourceAdapter(client_factory=client_factory(transport))
    with pytest.raises(DeviceLookupError) as err:
        adapter.resolve_device_portal("dev-uid-0001", PLATFORM_PORTAL)
    assert err.value.kind == "transport" and "not running" in err.value.message
    assert transport.calls == []
