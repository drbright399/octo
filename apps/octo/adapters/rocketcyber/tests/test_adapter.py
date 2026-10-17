"""RocketCyberSourceAdapter — wizard shape, smoke test, discovery, extraction,
routing, severity, lifecycle. Real adapter + real client; only the socket is
fake (fake_rocketcyber.py, built from the live API's answers).

The previous version of this file tested an invented incident shape
(priority / category / customerId / endpoint.hostname) and a client stubbed
above the socket — which is how an adapter built against 404ing paths passed.
"""
from __future__ import annotations

import asyncio

import pytest
from shared_adapter_contract.types import VendorTenant, VendorTenantListError

from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
from apps.octo.adapters.rocketcyber.client import DEFAULT_API_URL
from apps.octo.adapters.rocketcyber.presentation import EVENT_TYPE
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    ACCOUNT_PATH,
    API_HOST,
    API_KEY,
    API_URL,
    CREDS,
    INCIDENTS_PATH,
    OLD_CREDS,
    PROVIDER_ID,
    SECRETS,
    FakeRocketCyberTransport,
    incident,
    iso,
    ago,
    resolved,
    rocketcyber_adapter_class,
)


def _adapter(transport: FakeRocketCyberTransport) -> RocketCyberSourceAdapter:
    return rocketcyber_adapter_class(transport)()


def _no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# ---------------------------------------------------------------------------
# Wizard shape
# ---------------------------------------------------------------------------

def test_only_the_api_key_is_required():
    fields = {f.name: f for f in RocketCyberSourceAdapter().credential_shape()}
    assert list(fields) == ["RC_API_KEY", "RC_API_URL", "RC_ACCOUNT_ID"]
    assert fields["RC_API_KEY"].kind == "password" and fields["RC_API_KEY"].required
    assert fields["RC_API_URL"].required is False
    assert fields["RC_ACCOUNT_ID"].required is False
    assert DEFAULT_API_URL in fields["RC_API_URL"].description
    assert "Leave blank" in fields["RC_ACCOUNT_ID"].description


def test_onboarding_explains_key_scope_polling_and_mapping():
    ob = RocketCyberSourceAdapter().onboarding(None)
    assert ob.webhook_url is None
    text = " ".join([ob.summary] + [s.title + " " + s.body for s in ob.steps])
    assert "PROVIDER (MSP) account" in text           # where the key is created
    assert "Read-only" in text and "no write" in text  # what it can do
    assert "no webhooks" in text and "every 5 minutes" in text
    assert "last 14 days" in text and "last 7 days" in text and "last 365 days" in text
    assert "accountId" in text and "never its name" in text
    assert "open → high" in text and "resolved or suppressed → medium" in text
    assert "quarantine" in text and "pending review" in text
    # The first import waits for the mapping step; re-pointing is not retroactive.
    assert "WAITS for this step before its first import" in text and "60 minutes" in text
    assert "routes NEW rows only" in text
    # A growing event count is not a new row.
    assert "growing event count" in text


def test_mapping_shape_names_the_customer_account_id():
    shape = RocketCyberSourceAdapter().tenant_mapping_shape()
    assert shape.tenant_noun == "customer"
    assert shape.vendor_tenant_id_field == "accountId"
    assert "NAME never matches" in shape.id_help


def test_delivery_is_poll_only_with_discovery_and_contact_reporting():
    cls = RocketCyberSourceAdapter
    assert cls.delivery_mode == "poll"
    assert cls.supports_tenant_discovery is True
    assert cls.reports_vendor_contact is True
    assert cls.default_poll_interval_sec == 300.0


# ---------------------------------------------------------------------------
# smoke_test (the wizard's Test connection)
# ---------------------------------------------------------------------------

def test_smoke_test_with_only_the_key_uses_the_default_region():
    transport = FakeRocketCyberTransport()
    transport.api_hosts.add("api-us.rocketcyber.com")   # the fake answers as the default host
    result = _adapter(transport).smoke_test({"RC_API_KEY": API_KEY})
    assert result.ok, result.message
    assert transport.hosts == {"api-us.rocketcyber.com"}
    # The account, its customers, and page 1 of each of the cycle's three reads.
    assert transport.count(ACCOUNT_PATH) == 2 and transport.count(INCIDENTS_PATH) == 3
    assert f"provider account {PROVIDER_ID} (“Example MSP”, read from the API key)" in result.message


def test_smoke_test_ok_with_the_fake_host():
    transport = FakeRocketCyberTransport()
    result = _adapter(transport).smoke_test(CREDS)
    assert result.ok and "incidents are readable" in result.message
    _no_secret(result.message)


def test_smoke_test_old_saved_credentials_still_pass():
    transport = FakeRocketCyberTransport()
    result = _adapter(transport).smoke_test(OLD_CREDS)
    assert result.ok, result.message
    assert "'Provider account ID' you entered" in result.message
    assert transport.incident_queries()[0]["accountId"] == str(PROVIDER_ID)


def test_smoke_test_rejected_key_is_actionable():
    transport = FakeRocketCyberTransport()
    transport.key = "the-vendor-knows-another-key"
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok
    assert result.message.startswith("RocketCyber rejected the API key (HTTP 401)")
    assert "copied whole" in result.message
    # A key of another region is rejected the same way: name the field that
    # fixes that, and the origin actually used.
    assert "'API base URL'" in result.message
    assert f"Athena used https://{API_HOST})" in result.message
    _no_secret(result.message)


def test_smoke_test_refuses_a_key_that_belongs_to_one_customer():
    """The exact mistake the wizard warns about: the key was created INSIDE
    a customer. Its account has no customers; saving it would poll one
    customer silently."""
    transport = FakeRocketCyberTransport()
    transport.provider.update({
        "name": "Acme Corp", "accountPath": "900.1000.2001",
        "type": "customer", "hierarchy": "Customer",
    })
    transport.customers = []
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok
    assert "belongs to a customer account (account 2001)" in result.message
    assert "PROVIDER (MSP) account level" in result.message
    assert transport.count(INCIDENTS_PATH) == 0


def test_smoke_test_refuses_an_account_without_customers_unless_overridden():
    transport = FakeRocketCyberTransport()
    transport.customers = []                  # type/hierarchy say nothing about it
    transport.provider.pop("type")
    transport.provider.pop("hierarchy")
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok and "an account with no customers" in result.message
    assert "'Provider account ID' to connect anyway" in result.message
    # The escape hatch the message names works.
    forced = _adapter(transport).smoke_test({**CREDS, "RC_ACCOUNT_ID": str(PROVIDER_ID)})
    assert forced.ok, forced.message


def test_smoke_test_forbidden_on_a_derived_id_points_at_the_override():
    """accountPath's last segment is not the provider (it names an
    ancestor): the listing for that id is refused. The key is fine — the
    fix is the 'Provider account ID' field, and the message must say so."""
    transport = FakeRocketCyberTransport()
    transport.provider["accountPath"] = "900"
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok
    assert result.message.startswith(
        "RocketCyber accepted the API key but refused to return data for account 900")
    assert "Athena read account 900 from the key's own account answer" in result.message
    assert "enter your provider account ID in 'Provider account ID'" in result.message
    assert "press Test connection again" in result.message


@pytest.mark.parametrize(
    "bad_key",
    [
        API_KEY[:10] + "\n" + API_KEY[10:],           # a pasted line break
        API_KEY[:10] + " " + API_KEY[10:],             # an inner space
        API_KEY[:10] + "\u201c" + API_KEY[10:],        # a typographic quote from a document
        API_KEY + "\u00e9",                            # Latin-1, but not a key character
    ],
)
def test_a_key_with_characters_a_header_cannot_carry_is_refused_before_any_request(bad_key):
    transport = FakeRocketCyberTransport()
    result = _adapter(transport).smoke_test({**CREDS, "RC_API_KEY": bad_key})
    assert not result.ok
    assert "paste the key again as one line" in result.message
    assert transport.calls == []
    assert bad_key not in result.message and API_KEY[10:] not in result.message


def test_smoke_test_forbidden_is_the_guidance():
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok
    assert result.message.startswith("RocketCyber accepted the API key but refused")


def test_smoke_test_transport_is_prefixed():
    transport = FakeRocketCyberTransport()
    transport.unreachable = True
    result = _adapter(transport).smoke_test(CREDS)
    assert not result.ok and result.message.startswith("Could not read from RocketCyber:")


@pytest.mark.parametrize(
    ("creds", "needle"),
    [
        ({}, "RC_API_KEY is required"),
        ({"RC_API_KEY": "   "}, "RC_API_KEY is required"),
        ({"RC_API_KEY": API_KEY, "RC_API_URL": "http://rc-api.example.test/v3"}, "https://"),
        ({"RC_API_KEY": API_KEY, "RC_ACCOUNT_ID": "acct-1"}, "numeric"),
    ],
)
def test_smoke_test_refuses_bad_input_before_any_request(creds, needle):
    transport = FakeRocketCyberTransport()
    result = _adapter(transport).smoke_test(creds)
    assert not result.ok and needle in result.message
    assert transport.calls == []
    _no_secret(result.message)


# ---------------------------------------------------------------------------
# Discovery (the mapping picker)
# ---------------------------------------------------------------------------

def test_discovery_lists_every_customer_and_the_provider_itself():
    transport = FakeRocketCyberTransport()
    listing = _adapter(transport).list_vendor_tenants(CREDS)
    assert listing.truncated is False
    assert listing.tenants == [
        VendorTenant(id=str(PROVIDER_ID), label="Example MSP (provider account)"),
        VendorTenant(id="2001", label="Acme Corp"),
        VendorTenant(id="2002", label="Example Bakery"),
        # Not hidden: it may still have incidents in the window, and hiding it
        # would make its saved mapping look orphaned. Its status is shown.
        VendorTenant(id="2003", label="Example Hardware (inactive)"),
    ]


def test_discovery_ids_are_exactly_what_routing_yields():
    transport = FakeRocketCyberTransport()
    adapter = _adapter(transport)
    ids = {t.id for t in adapter.list_vendor_tenants(CREDS).tenants}
    for account_id in (PROVIDER_ID, 2001, 2002, 2003):
        assert adapter.route_to_tenant(incident(1, account_id=account_id)) in ids


def test_discovery_works_for_an_instance_saved_by_the_old_wizard():
    transport = FakeRocketCyberTransport()
    listing = _adapter(transport).list_vendor_tenants(OLD_CREDS)
    assert [t.id for t in listing.tenants] == ["1000", "2001", "2002", "2003"]
    assert listing.tenants[0].label == "Example MSP (provider account)"


def test_discovery_with_an_override_narrower_than_the_key_names_only_that_account():
    transport = FakeRocketCyberTransport()
    listing = _adapter(transport).list_vendor_tenants({**CREDS, "RC_ACCOUNT_ID": "2001"})
    assert listing.tenants == [VendorTenant(id="2001", label="Account 2001 (configured account)")]


@pytest.mark.parametrize(
    ("knob", "value", "kind", "needle"),
    [
        ("key", "another-key-altogether", "auth", "rejected the stored API key"),
        ("forbid_details", True, "forbidden", "refused to return data"),
        ("unreachable", True, "transport", "Could not read customers"),
        ("force_status", 500, "transport", "HTTP 500"),
    ],
)
def test_discovery_failures_keep_their_kind(knob, value, kind, needle):
    transport = FakeRocketCyberTransport()
    setattr(transport, knob, value)
    with pytest.raises(VendorTenantListError) as exc:
        _adapter(transport).list_vendor_tenants(CREDS)
    assert exc.value.kind == kind and needle in exc.value.message
    _no_secret(exc.value.message)


def test_discovery_without_a_key_is_a_clean_error():
    with pytest.raises(VendorTenantListError) as exc:
        _adapter(FakeRocketCyberTransport()).list_vendor_tenants({})
    assert "RC_API_KEY is required" in exc.value.message


# ---------------------------------------------------------------------------
# Extraction, routing, severity
# ---------------------------------------------------------------------------

def test_extract_event_from_a_real_shaped_incident():
    adapter = RocketCyberSourceAdapter()
    raw = incident(7, psa_id="T20000101.0001", event_count=3)
    event = adapter.extract_event(raw)
    assert event.vendor_event_id == "5007"
    assert event.received_at == raw["updatedAt"]
    assert event.severity == "high"
    assert event.event_type == EVENT_TYPE
    assert event.summary == "RocketCyber · Suspicious PowerShell execution 7"
    assert event.source_host is None and event.indicator is None
    assert event.payload is raw
    assert adapter.psa_ticket(raw) == "T20000101.0001"


def test_extract_event_is_deterministic():
    adapter = RocketCyberSourceAdapter()
    raw = incident(1)
    assert adapter.extract_event(raw) == adapter.extract_event(dict(raw))


def test_a_status_change_is_a_different_event_version():
    adapter = RocketCyberSourceAdapter()
    open_ = incident(1)
    closed = resolved(open_)
    a, b = adapter.extract_event(open_), adapter.extract_event(closed)
    assert a.vendor_event_id == b.vendor_event_id
    assert a.payload_sha256 != b.payload_sha256
    assert (a.severity, b.severity) == ("high", "medium")
    assert b.summary.endswith(" — resolved") and b.received_at >= a.received_at
    assert a.event_type == b.event_type == EVENT_TYPE


@pytest.mark.parametrize(
    ("status", "severity"),
    [("open", "high"), ("OPEN", "high"), ("suppressed", "medium"), ("resolved", "medium"),
     ("escalated", "medium"), ("", "high"), (None, "high"), (5, "high")],
)
def test_severity_follows_status(status, severity):
    raw = incident(1)
    raw["status"] = status
    assert RocketCyberSourceAdapter().severity_map(raw) == severity
    assert RocketCyberSourceAdapter().extract_event(raw).severity == severity


def test_received_at_falls_back_through_published_and_created():
    adapter = RocketCyberSourceAdapter()
    raw = incident(1, created=ago(days=1))
    raw["updatedAt"] = "not a time"
    assert adapter.extract_event(raw).received_at == raw["publishedAt"]
    raw["publishedAt"] = None
    assert adapter.extract_event(raw).received_at == raw["createdAt"]
    raw["createdAt"] = ""
    assert adapter.extract_event(raw).received_at == ""


def test_an_incident_without_an_id_never_gets_an_empty_vendor_id():
    raw = incident(1)
    del raw["id"]
    assert len(RocketCyberSourceAdapter().extract_event(raw).vendor_event_id) == 16


@pytest.mark.parametrize(
    ("value", "expected"),
    [(2001, "2001"), ("2001", "2001"), (" 2001 ", "2001"), (PROVIDER_ID, "1000"),
     (None, None), ("", None), (0, None), (-1, None), (True, None), ("acme", None),
     (2.5, None), ({"id": 1}, None)],
)
def test_route_to_tenant_is_the_customer_account_id(value, expected):
    raw = incident(1)
    raw["accountId"] = value
    assert RocketCyberSourceAdapter().route_to_tenant(raw) == expected


def test_a_forwarder_style_slug_directive_is_not_honoured():
    """Only the API poll feeds this adapter; the vendor's own accountId is
    the routing key — a payload field cannot steer an incident elsewhere."""
    raw = incident(1)
    raw["_octo_tenant_slug"] = "someone-else"
    assert RocketCyberSourceAdapter().route_to_tenant(raw) == "2001"


def test_customer_ids_are_declared_never_to_be_client_slugs():
    """The platform's pass-through step (vendor id == an active client slug)
    is off for this adapter: "2002" is both a customer id and a valid slug."""
    assert RocketCyberSourceAdapter.tenant_ids_are_slugs is False


def test_vendor_tenant_label_is_the_customer_name():
    adapter = RocketCyberSourceAdapter()
    assert adapter.vendor_tenant_label(incident(1)) == "Acme Corp"
    raw = incident(1)
    raw["accountName"] = "  "
    assert adapter.vendor_tenant_label(raw) is None


def test_no_deep_link_is_ever_guessed(monkeypatch):
    monkeypatch.setenv("RC_WEB_URL", "https://portal.example.test")
    adapter = RocketCyberSourceAdapter()
    event = adapter.extract_event(incident(1))
    for link_type in ("alert", "device", "tenant", "host"):
        assert adapter.deep_link(event, link_type) is None


def test_present_event_is_offered_on_the_class():
    shown = RocketCyberSourceAdapter.present_event(resolved(incident(1)))
    assert shown.headline.endswith("— resolved") and shown.site == "Acme Corp"


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_with_only_the_key_builds_the_poller_with_defaults():
    transport = FakeRocketCyberTransport()
    adapter = _adapter(transport)
    adapter.start({"RC_API_KEY": API_KEY, "RC_API_URL": API_URL, "poll_interval_sec": 0.05})
    try:
        poller = adapter._poller
        assert poller is not None and poller._window_days == 14.0
        assert adapter.health().alive is True
        await asyncio.sleep(0.1)
        assert transport.count(INCIDENTS_PATH) >= 1
    finally:
        await adapter._poller.stop()


@pytest.mark.asyncio
async def test_start_with_old_saved_credentials_and_a_junk_account_id_still_runs(caplog):
    """An instance saved by the old wizard cannot be edited: a non-numeric
    RC_ACCOUNT_ID there is ignored (with a warning), never a dead instance."""
    transport = FakeRocketCyberTransport()
    adapter = _adapter(transport)
    adapter.start({**OLD_CREDS, "RC_ACCOUNT_ID": "acct-1000", "poll_interval_sec": 0.05,
                   "initial_cursor": "1970-01-01T00:00:00.000Z"})
    try:
        await asyncio.sleep(0.1)
        assert transport.incident_queries()[0]["accountId"] == str(PROVIDER_ID)
        assert "ignored" in caplog.text
    finally:
        await adapter._poller.stop()


def test_start_without_a_key_raises():
    with pytest.raises(ValueError):
        RocketCyberSourceAdapter().start({"RC_API_URL": API_URL})


@pytest.mark.parametrize(
    ("config", "window", "lookback"),
    [
        ({}, 14.0, 7.0),
        ({"window_days": 30, "initial_lookback_days": 2}, 30.0, 2.0),
        ({"window_days": 3}, 3.0, 3.0),                 # lookback never exceeds the window
        ({"window_days": "junk", "initial_lookback_days": -1}, 14.0, 7.0),
        ({"window_days": 1000}, 14.0, 7.0),
    ],
)
def test_window_and_lookback_config_is_bounded(config, window, lookback, monkeypatch):
    seen = {}
    from apps.octo.adapters.rocketcyber import adapter as adapter_module

    class _Poller:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        async def start(self):
            return None

    monkeypatch.setattr(adapter_module, "RocketCyberPoller", _Poller)
    a = _adapter(FakeRocketCyberTransport())
    a.start({**CREDS, **config})
    assert (seen["window_days"], seen["initial_lookback_days"]) == (window, lookback)
    assert seen["poll_interval_sec"] == 300.0


@pytest.mark.parametrize(
    ("config", "open_lookback", "grace"),
    [
        ({}, 365.0, 3600.0),
        ({"open_lookback_days": 90, "first_import_grace_sec": 0}, 90.0, 0.0),
        ({"open_lookback_days": 5}, 365.0, 3600.0),      # never below the window
        ({"open_lookback_days": "junk", "first_import_grace_sec": -5}, 365.0, 3600.0),
        ({"open_lookback_days": 10**6, "first_import_grace_sec": 10**9}, 365.0, 3600.0),
    ],
)
def test_open_lookback_and_first_import_grace_are_bounded(config, open_lookback, grace, monkeypatch):
    seen = {}
    from apps.octo.adapters.rocketcyber import adapter as adapter_module

    class _Poller:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        async def start(self):
            return None

    monkeypatch.setattr(adapter_module, "RocketCyberPoller", _Poller)
    _adapter(FakeRocketCyberTransport()).start({**CREDS, **config})
    assert (seen["open_lookback_days"], seen["first_import_grace_sec"]) == (open_lookback, grace)


def test_health_inactive_before_start():
    assert RocketCyberSourceAdapter().health().alive is False


def test_rate_limit_hints_name_retry_after():
    assert RocketCyberSourceAdapter().rate_limit_hints().retry_after_header == "Retry-After"


def test_widget_definition_declared():
    assert RocketCyberSourceAdapter().widget_definition().widget_id == "rocketcyber.incidents-feed"


def test_adapter_satisfies_protocol():
    from shared_adapter_contract import SourceAdapter
    a: SourceAdapter = RocketCyberSourceAdapter()  # type: ignore[assignment]
    assert a.vendor_slug == "rocketcyber"


def test_rocketcyber_auto_discovered():
    from apps.octo.framework import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.framework.discovery import discover_adapters
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    report = discover_adapters("apps.octo.adapters", registry)
    assert "rocketcyber" in report.registered and report.failed == []


def test_rocketcyber_class_module_is_package_path():
    assert RocketCyberSourceAdapter.__module__ == "apps.octo.adapters.rocketcyber"


def test_fixture_timestamps_have_the_vendor_shape():
    assert iso(ago()).endswith("Z") and len(iso(ago())) == len("2025-12-29T15:20:15.875Z")
    assert API_HOST in API_URL
