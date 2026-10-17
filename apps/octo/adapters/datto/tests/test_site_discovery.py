"""Datto site discovery — `DattoClient.list_sites_drained()` pagination and
the adapter's optional `list_vendor_tenants()` capability.

Real client, real adapter; only the socket is fake (see fake_datto.py).

The defect these pin: `list_sites()` read ONE page. Datto pages sites 250 at a
time via pageDetails.nextPageUrl, so an account with more sites than that
silently lost the rest — and the mapping picker would have offered a partial
list as if it were complete.
"""
from __future__ import annotations

import logging

import pytest
from shared_adapter_contract import (
    BaseSourceAdapter,
    VendorTenant,
    VendorTenantListError,
)

from apps.octo.adapters.datto.client import (
    _NO_NEXT_PAGE,
    MAX_SITE_PAGES,
    SITES_PAGE_SIZE,
    DattoClientError,
    DattoForbiddenError,
    _next_page_number,
    forbidden_guidance,
)
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FORBIDDEN_QUOTED,
    FORBIDDEN_TEXT_SHOWN,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
    real_client,
)

API_HOST = "datto-api.example.test"


def _sites(n: int) -> list[dict]:
    return [{"uid": f"site-uid-{i:04d}", "name": f"Example Site {i:04d}"} for i in range(n)]


def _no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# ---------------------------------------------------------------------------
# Client: pagination is drained, capped, and never leaves the API origin
# ---------------------------------------------------------------------------

def test_list_sites_drains_every_page():
    transport = FakeDattoTransport()
    transport.sites = _sites(7)
    transport.sites_page_size = 3            # 3 + 3 + 1
    client = real_client(transport)

    listing = client.list_sites_drained()

    assert [s["uid"] for s in listing.sites] == [s["uid"] for s in transport.sites]
    assert listing.truncated is False
    assert transport.site_pages == [None, 1, 2]
    assert client.list_sites() == transport.sites     # the list-only form agrees


def test_hundreds_of_sites_come_back_complete():
    transport = FakeDattoTransport()
    transport.sites = _sites(612)
    transport.sites_page_size = SITES_PAGE_SIZE
    listing = real_client(transport).list_sites_drained()
    assert len(listing.sites) == 612 and listing.truncated is False
    assert transport.count("/api/v2/account/sites") == 3


def test_next_page_url_is_never_followed_to_another_host():
    """nextPageUrl names a different origin; only its page NUMBER is used, so
    the bearer token is sent to the configured API host and nowhere else."""
    transport = FakeDattoTransport()
    transport.sites = _sites(5)
    transport.sites_page_size = 2
    real_client(transport).list_sites_drained()
    assert transport.hosts == {API_HOST}


def test_page_cap_stops_an_endless_vendor_and_says_truncated(caplog):
    transport = FakeDattoTransport()
    transport.sites_page_size = 1
    transport.endless_sites = True
    with caplog.at_level(logging.WARNING):
        listing = real_client(transport).list_sites_drained(max_pages=4)
    assert transport.count("/api/v2/account/sites") == 4
    assert listing.truncated is True
    assert "stopped early" in caplog.text
    _no_secret(caplog.text)


def test_default_page_cap_is_the_hard_limit():
    transport = FakeDattoTransport()
    transport.sites_page_size = 1
    transport.endless_sites = True
    listing = real_client(transport).list_sites_drained()
    assert transport.count("/api/v2/account/sites") == MAX_SITE_PAGES
    assert listing.truncated is True


def test_a_next_page_that_does_not_advance_stops_instead_of_spinning():
    transport = FakeDattoTransport()
    transport.sites = _sites(6)
    transport.sites_page_size = 2
    transport.stuck_next_page = True         # nextPageUrl always says page=<current>
    listing = real_client(transport).list_sites_drained()
    # page None → "next is 0" → page 0 → "next is 0" again: stop.
    assert transport.count("/api/v2/account/sites") == 2
    assert listing.truncated is True
    assert len({s["uid"] for s in listing.sites}) == len(listing.sites)   # no dupes


def test_forbidden_on_the_first_page_is_the_forbidden_error():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    with pytest.raises(DattoForbiddenError):
        real_client(transport).list_sites_drained()


@pytest.mark.parametrize(
    ("status", "error"), [(403, DattoForbiddenError), (500, DattoClientError)],
)
def test_a_failure_on_a_later_page_raises_and_never_returns_a_partial_list(status, error):
    """Two good pages, then the vendor fails. Handing back what was read so
    far as a COMPLETE list would make the panel accuse every correctly mapped
    site on the later pages of "matching no Datto RMM site"."""
    transport = FakeDattoTransport()
    transport.sites = _sites(7)
    transport.sites_page_size = 3
    transport.fail_sites_from_page = 2
    transport.fail_sites_status = status
    with pytest.raises(error):
        real_client(transport).list_sites_drained()
    assert transport.site_pages == [None, 1]          # page 2 is the one that failed
    with pytest.raises(VendorTenantListError) as exc:
        datto_adapter_class(transport)().list_vendor_tenants(CREDS)
    assert exc.value.kind == ("forbidden" if status == 403 else "transport")


@pytest.mark.parametrize(
    "next_url",
    [
        "https://datto-api.example.test/api/v2/account/sites?cursor=abc",  # no `page`
        "https://datto-api.example.test/api/v2/account/sites?page=abc",
        "https://datto-api.example.test/api/v2/account/sites?page=-1",
        "https://datto-api.example.test/api/v2/account/sites?page=",
        123,                                                                # not a string
        {"href": "x"},
    ],
)
def test_an_unusable_next_page_url_means_truncated_never_complete(next_url):
    """The pagination field names are the part of this client most likely to
    differ from the live API. If the link cannot be used, the honest answer is
    "first page, and there is more" — never "first page, complete"."""
    transport = FakeDattoTransport()
    transport.sites = _sites(5)
    transport.sites_page_size = 2
    transport.override_next_page_url = True
    transport.next_page_url_override = next_url
    listing = real_client(transport).list_sites_drained()
    assert transport.count("/api/v2/account/sites") == 1
    assert len(listing.sites) == 2 and listing.truncated is True
    assert datto_adapter_class(transport)().list_vendor_tenants(CREDS).truncated is True


@pytest.mark.parametrize(
    "body",
    [{}, {"pageDetails": None}, {"pageDetails": {}}, {"pageDetails": {"nextPageUrl": None}},
     {"pageDetails": {"nextPageUrl": ""}}, {"pageDetails": "x"}],
)
def test_no_next_page_named_is_the_end_of_the_list(body):
    assert _next_page_number(body) == _NO_NEXT_PAGE


def test_next_page_number_reads_only_the_page_value():
    url = "https://elsewhere.example.test/x?max=250&page=7"
    assert _next_page_number({"pageDetails": {"nextPageUrl": url}}) == 7
    assert _next_page_number({"pageDetails": {"nextPageUrl": "?page=0"}}) == 0
    for unusable in ("?cursor=a", "?page=abc", "?page=-1", 5):
        assert _next_page_number({"pageDetails": {"nextPageUrl": unusable}}) is None


def test_the_site_page_size_is_inside_the_vendor_limit():
    transport = FakeDattoTransport()       # answers 400 above 250, like Datto
    assert real_client(transport).list_sites_drained().truncated is False


# ---------------------------------------------------------------------------
# Adapter: the optional capability
# ---------------------------------------------------------------------------

def test_capability_is_optional_on_the_base_and_declared_by_datto():
    assert BaseSourceAdapter.supports_tenant_discovery is False
    adapter_cls = datto_adapter_class(FakeDattoTransport())
    assert adapter_cls.supports_tenant_discovery is True

    class _NoDiscovery(BaseSourceAdapter):
        vendor_slug = "fixture"
        credential_shape = tenant_mapping_shape = smoke_test = None
        extract_event = route_to_tenant = severity_map = None
        human_summary = deep_link = None

    with pytest.raises(NotImplementedError):
        _NoDiscovery().list_vendor_tenants({})


def test_list_vendor_tenants_returns_uid_and_name_across_pages():
    transport = FakeDattoTransport()
    transport.sites = _sites(5)
    transport.sites_page_size = 2
    listing = datto_adapter_class(transport)().list_vendor_tenants(CREDS)
    assert listing.truncated is False
    assert listing.tenants[0] == VendorTenant(id="site-uid-0000", label="Example Site 0000")
    assert len(listing.tenants) == 5


def test_sites_without_a_usable_uid_are_skipped_and_a_nameless_one_is_kept():
    transport = FakeDattoTransport()
    transport.sites = [
        {"uid": "site-uid-0001", "name": "Example Site"},
        {"uid": "", "name": "No Uid"},
        {"uid": 42, "name": "Numeric Uid"},
        {"name": "Missing Uid"},
        {"uid": "site-uid-0002"},
        "not-a-dict",
    ]
    listing = datto_adapter_class(transport)().list_vendor_tenants(CREDS)
    assert listing.tenants == [
        VendorTenant(id="site-uid-0001", label="Example Site"),
        VendorTenant(id="site-uid-0002", label="site-uid-0002"),
    ]


def test_forbidden_maps_to_the_same_guidance_as_test_connection():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    adapter = datto_adapter_class(transport)()
    with pytest.raises(VendorTenantListError) as exc:
        adapter.list_vendor_tenants(CREDS)
    assert exc.value.kind == "forbidden"
    # Same instruction as test-connection, in the SAVED-instance variant:
    # discovery only runs for a stored key pair, which must not be regenerated.
    assert exc.value.message == forbidden_guidance(FORBIDDEN_TEXT_SHOWN, saved=True)
    shared = "then Save User."
    assert exc.value.message.split(shared)[0] == adapter.smoke_test(CREDS).message.split(shared)[0]
    assert "Do NOT regenerate the API keys" in exc.value.message
    assert exc.value.message.endswith(FORBIDDEN_QUOTED)
    assert "Setup > Users" in exc.value.message
    _no_secret(exc.value.message, str(exc.value))


@pytest.mark.parametrize(
    ("knob", "value", "kind", "fragment"),
    [
        ("token_status", 401, "auth", "rejected credentials"),
        ("unreachable", True, "transport", "Could not reach Datto"),
        ("data_status", 500, "transport", "HTTP 500"),
    ],
)
def test_other_failures_keep_their_kind(knob, value, kind, fragment):
    transport = FakeDattoTransport()
    setattr(transport, knob, value)
    with pytest.raises(VendorTenantListError) as exc:
        datto_adapter_class(transport)().list_vendor_tenants(CREDS)
    assert exc.value.kind == kind and fragment in exc.value.message
    _no_secret(exc.value.message)


def test_missing_credentials_are_a_clean_error_not_a_crash():
    with pytest.raises(VendorTenantListError) as exc:
        datto_adapter_class(FakeDattoTransport())().list_vendor_tenants({})
    assert "DATTO_API_URL is required" in exc.value.message


def test_mapping_shape_says_which_value_the_id_is():
    shape = datto_adapter_class(FakeDattoTransport())().tenant_mapping_shape()
    assert shape.tenant_noun == "site"
    assert "UID" in shape.id_help and "NAME never matches" in shape.id_help
