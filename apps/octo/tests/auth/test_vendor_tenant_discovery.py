"""POST /admin/adapters/instances/{id}/vendor-tenants + the mapping save rules,
through the real HTTP routes with the REAL Datto adapter and client (only the
vendor socket is fake — see adapters/datto/tests/fake_datto.py).

The production defect: the tenant-mapping panel was free text, the operator
typed Datto site NAMES as vendor tenant ids, and routing is an exact match on
the alert's siteUid — every alert from those sites would have been dropped.

  - the vendor's sites are offered as [{id, label}], admin+ only
  - adapters without the capability say `supported: false` (no credential read)
  - a vendor failure is an actionable ERROR, never an empty list; it is
    replayed for a few seconds (no vendor call, no audit row), then re-asked
  - the vendor is only ever contacted by a POST (SameSite=Lax cookies are not
    sent on a cross-site POST), and concurrent misses share one vendor call
  - the listing is cached briefly per instance and never outlives a credential
    change or a disable
  - the card payload counts saved mappings that match no vendor site
  - saving mappings stays permissive but refuses what can never work
  - no credential, token, key — or customer name — in any log line or audit row
"""
from __future__ import annotations

import logging
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FORBIDDEN_QUOTED,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
)
from apps.octo.instances import vendor_contact, vendor_tenants
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"
_SITES_PATH = "/api/v2/account/sites"

SITES = [
    {"uid": "site-uid-0002", "name": "Example Bakery"},
    {"uid": "site-uid-0001", "name": "Example Clinic"},
    {"uid": "site-uid-0003", "name": "example hardware"},
]


def _url(instance_id: int) -> str:
    return f"/api/v1/admin/adapters/instances/{instance_id}/vendor-tenants"


def _map_url(instance_id: int, slug: str = "datto") -> str:
    return f"/api/v1/integrations/{slug}/{instance_id}/mappings/tenants"


@pytest.fixture
def datto(instance_endpoint_client):  # noqa: F811
    """(client, cookies, transport, instance_id): the real Datto adapter,
    one saved instance, its poller stopped so every vendor call counted below
    comes from the route under test."""
    vendor_contact.reset()
    vendor_tenants.reset()
    client = instance_endpoint_client
    transport = FakeDattoTransport()
    transport.sites = list(SITES)
    client.app.state.adapter_registry.register_adapter_class(
        datto_adapter_class(transport)
    )
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    created = client.post(_CREATE, json={"credentials": CREDS}, cookies=cookies)
    assert created.status_code == 200, created.text
    client.app.state.instance_manager.stop_all_running()
    transport.calls.clear()
    yield client, cookies, transport, created.json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()
    vendor_contact.reset()
    vendor_tenants.reset()


def _audit_rows(action: str) -> list[tuple]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return conn.execute(
            "SELECT target_id, before_state, after_state FROM audit_log "
            "WHERE action = ? ORDER BY id", (action,),
        ).fetchall()
    finally:
        conn.close()


def _assert_no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


def _make_client(client, cookies, slug: str) -> None:
    r = client.post(
        "/api/v1/admin/clients",
        json={"slug": slug, "display_name": slug.title()}, cookies=cookies,
    )
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["analyst", "viewer"])
def test_below_admin_is_refused_and_the_vendor_is_not_contacted(datto, role):
    client, _cookies, transport, iid = datto
    low = client.login(
        client.provision_operator(f"bob-{role}", "password1234567", athena_role=role)
    )
    r = client.post(_url(iid), cookies=low)
    assert r.status_code == 403, r.text
    assert "tenants" not in r.text
    assert transport.calls == []
    assert vendor_tenants.latest(iid, "anything") is None


def test_no_session_is_refused(datto):
    client, _cookies, transport, iid = datto
    client.cookies.clear()
    assert client.post(_url(iid)).status_code == 401
    assert transport.calls == []


def test_a_get_never_contacts_the_vendor(datto):
    """The session cookie is SameSite=Lax, which a cross-site top-level GET
    navigation still carries: as a GET, a page an admin merely visited could
    decrypt the credentials, hit the vendor and write audit rows in the
    admin's name. Lax never sends the cookie on a cross-site POST."""
    client, cookies, transport, iid = datto
    r = client.get(_url(iid), params={"refresh": "true"}, cookies=cookies)
    assert r.status_code == 405, r.text
    assert transport.calls == []
    assert _audit_rows("adapter_vendor_tenant_list") == []


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def test_lists_the_vendors_sites_as_id_and_label(datto, caplog):
    client, cookies, transport, iid = datto
    with caplog.at_level(logging.DEBUG):
        r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["supported"] is True and body["cached"] is False
    assert body["vendor_display_name"] == "Datto RMM"
    # Sorted by label (case-insensitive) for the picker; ids untouched.
    assert body["tenants"] == [
        {"id": "site-uid-0002", "label": "Example Bakery"},
        {"id": "site-uid-0001", "label": "Example Clinic"},
        {"id": "site-uid-0003", "label": "example hardware"},
    ]
    assert body["truncated"] is False and body["fetched_at"]
    shape = body["tenant_mapping_shape"]
    assert shape["tenant_noun"] == "site" and shape["vendor_tenant_id_field"] == "uid"
    assert "UID" in shape["id_help"]
    assert r.headers["cache-control"] == "no-store"
    _assert_no_secret(r.text, caplog.text)
    # Customer names go to the admin's browser — never to a log line.
    assert "Example Bakery" not in caplog.text


def test_listing_never_returns_a_credential_or_the_webhook_token(datto, caplog, monkeypatch):
    """This route decrypts the instance's credentials to call the vendor. It is
    one of only two instance GETs (see test_no_route_reads_a_credential_back):
    nothing it was given may come back — not in the body, the headers, a log
    line or the audit row — including the shown-once webhook token."""
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    client, cookies, _transport, iid = datto
    client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "fixture: recreate with a webhook token"}, cookies=cookies,
    )
    created = client.post(
        _CREATE,
        json={"credentials": {**CREDS, "DATTO_WEBHOOK_SECRET": ""}, "enable_webhook": True},
        cookies=cookies,
    ).json()
    client.app.state.instance_manager.stop_all_running()
    token = created["generated_webhook_secret"]["header_value"]
    new_id = created["instance"]["id"]

    with caplog.at_level(logging.DEBUG):
        ok = client.post(_url(new_id), cookies=cookies)
        cached = client.post(_url(new_id), cookies=cookies)
    assert ok.status_code == 200 and cached.json()["cached"] is True
    assert set(ok.json()) == {
        "instance_id", "vendor_slug", "vendor_display_name", "supported", "tenants",
        "truncated", "fetched_at", "cached", "tenant_mapping_shape",
    }
    assert all(set(t) == {"id", "label"} for t in ok.json()["tenants"])
    audit_text = str(_audit_rows("adapter_vendor_tenant_list"))
    for text in (ok.text, cached.text, str(ok.headers), caplog.text, audit_text):
        assert token not in text
        assert "DATTO_WEBHOOK_SECRET" not in text and "DATTO_API_SECRET_KEY" not in text
        _assert_no_secret(text)


def test_pagination_reaches_the_route(datto):
    client, cookies, transport, iid = datto
    transport.sites = [
        {"uid": f"site-uid-{i:04d}", "name": f"Example Site {i:04d}"} for i in range(9)
    ]
    transport.sites_page_size = 4
    body = client.post(_url(iid), cookies=cookies).json()
    assert len(body["tenants"]) == 9 and body["truncated"] is False
    assert transport.count(_SITES_PATH) == 3


def test_a_capped_listing_says_truncated(datto, monkeypatch):
    from apps.octo.adapters.datto import client as datto_client

    client, cookies, transport, iid = datto
    monkeypatch.setattr(datto_client, "MAX_SITE_PAGES", 2)
    transport.sites_page_size = 1
    transport.endless_sites = True
    body = client.post(_url(iid), cookies=cookies).json()
    assert body["truncated"] is True and transport.count(_SITES_PATH) == 2


def test_hostile_vendor_labels_are_flattened_and_bounded(datto):
    client, cookies, transport, iid = datto
    transport.sites = [
        {"uid": "site-uid-0001", "name": "Line\nBreak\x00Site " + "x" * 500},
        {"uid": " padded-uid ", "name": "Padded"},
        {"uid": "site-uid-0001", "name": "Duplicate uid"},
    ]
    tenants = client.post(_url(iid), cookies=cookies).json()["tenants"]
    # The Datto adapter strips a uid exactly as its route_to_tenant() does, so
    # the offered id is the one an alert will carry; the duplicate uid is gone.
    assert sorted(t["id"] for t in tenants) == ["padded-uid", "site-uid-0001"]
    label = next(t["label"] for t in tenants if t["id"] == "site-uid-0001")
    assert "\n" not in label and "\x00" not in label
    assert len(label) <= vendor_tenants.MAX_LABEL_CHARS


def test_clean_drops_ids_that_could_never_be_a_routing_key():
    from shared_adapter_contract import VendorTenant, VendorTenantListing

    tenants, truncated = vendor_tenants.clean(VendorTenantListing([
        VendorTenant("site-uid-0001", "Example"),
        VendorTenant(" padded ", "Padded"),
        VendorTenant("", "Blank"),
        VendorTenant("ctl\x00id", "Control"),
        VendorTenant("x" * 300, "Too long"),
        VendorTenant(42, "Not a string"),          # type: ignore[arg-type]
        VendorTenant("site-uid-0002", None),       # type: ignore[arg-type]
    ], truncated=True))
    assert [(t.id, t.label) for t in tenants] == [
        ("site-uid-0001", "Example"), ("site-uid-0002", "site-uid-0002"),
    ]
    assert truncated is True


def test_adapter_without_the_capability_says_unsupported_and_reads_no_credential(
    datto, monkeypatch,
):
    from apps.octo import credentials

    client, cookies, _transport, _iid = datto
    stub = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}}, cookies=cookies,
    ).json()["instance"]["id"]
    monkeypatch.setattr(
        credentials, "load",
        lambda ref: pytest.fail("credentials decrypted for an unsupported adapter"),
    )
    r = client.post(_url(stub), cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["supported"] is False and body["tenants"] == []
    assert body["tenant_mapping_shape"] is None
    assert _audit_rows("adapter_vendor_tenant_list") == []


def test_unknown_instance_is_404(datto):
    client, cookies, _transport, _iid = datto
    r = client.post(_url(987654), cookies=cookies)
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


# ---------------------------------------------------------------------------
# Vendor failures → actionable errors (Part A's exception types)
# ---------------------------------------------------------------------------

def test_forbidden_vendor_is_the_same_actionable_guidance(datto, caplog):
    client, cookies, transport, iid = datto
    transport.forbid_data = True
    with caplog.at_level(logging.DEBUG):
        r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 424, r.text
    body = r.json()
    assert body["code"] == "VENDOR_ACCESS_FORBIDDEN"
    # The same instruction test-connection gives for the same key…
    smoke = client.post(
        "/api/v1/admin/adapters/datto/smoke-test",
        json={"credentials": CREDS}, cookies=cookies,
    ).json()
    shared = "then Save User."
    assert body["message"].split(shared)[0] == smoke["message"].split(shared)[0]
    # …but this key pair is SAVED: regenerating it would force Disable + re-add.
    assert "Do NOT regenerate the API keys" in body["message"]
    assert "(HTTP 403)" in body["message"] and body["message"].endswith(FORBIDDEN_QUOTED)
    assert "Setup > Users" in body["message"] and "API Security Level" in body["message"]
    assert "tenants" not in body            # a failure is never an empty list
    _assert_no_secret(r.text, caplog.text)

    # Never served as a listing, and only remembered for seconds: once the
    # throttle window has passed the next attempt is a real one.
    transport.forbid_data = False
    vendor_tenants.forget_failure(iid)
    again = client.post(_url(iid), cookies=cookies)
    assert again.status_code == 200 and len(again.json()["tenants"]) == 3
    assert again.json()["cached"] is False


@pytest.mark.parametrize(
    ("knob", "value", "status", "window"),
    [
        ("forbid_data", True, 424, vendor_tenants.FAILURE_THROTTLE_SEC),
        ("unreachable", True, 503, vendor_tenants.FAILURE_THROTTLE_SEC),
        ("token_status", 401, 424, vendor_tenants.AUTH_FAILURE_THROTTLE_SEC),
    ],
)
def test_a_failing_vendor_is_not_asked_again_for_a_few_seconds(
    datto, monkeypatch, knob, value, status, window,
):
    """Every miss is a full credential grant at the vendor plus an audit row.
    Unthrottled, a retry loop (or a scripted session) drove hundreds a minute
    — the very thing the poller's backoff exists to prevent."""
    client, cookies, transport, iid = datto
    now = {"t": 1000.0}
    monkeypatch.setattr(vendor_tenants, "_monotonic", lambda: now["t"])
    setattr(transport, knob, value)

    first = client.post(_url(iid), cookies=cookies)
    assert first.status_code == status, first.text
    vendor_calls = len(transport.calls)
    assert vendor_calls >= 1

    for _ in range(25):
        now["t"] += 0.1
        r = client.post(_url(iid), params={"refresh": "true"}, cookies=cookies)
        assert r.status_code == status and r.json()["code"] == first.json()["code"]
        # Same actionable text, and it says it did not look again.
        assert r.json()["message"].startswith(first.json()["message"])
        assert "Not asked again" in r.json()["message"] and "retry in" in r.json()["message"]
    assert len(transport.calls) == vendor_calls           # vendor left alone
    assert len(_audit_rows("adapter_vendor_tenant_list")) == 1
    assert vendor_tenants.latest(iid, _cred_ref(iid)) is None   # never a listing

    # The window passes (and the operator fixed it): a real attempt again.
    now["t"] += window + 1
    setattr(transport, knob, {"forbid_data": False, "unreachable": False, "token_status": 200}[knob])
    ok = client.post(_url(iid), cookies=cookies)
    assert ok.status_code == 200 and ok.json()["cached"] is False
    assert len(transport.calls) > vendor_calls


def test_concurrent_misses_share_one_vendor_call(datto):
    import asyncio

    import httpx

    client, cookies, transport, iid = datto

    async def _burst() -> list[httpx.Response]:
        transport_ = httpx.ASGITransport(app=client.app)
        async with httpx.AsyncClient(
            transport=transport_, base_url="http://testserver", cookies=dict(cookies),
        ) as ac:
            return await asyncio.gather(*(ac.post(_url(iid)) for _ in range(6)))

    responses = asyncio.run(_burst())
    assert [r.status_code for r in responses] == [200] * 6
    assert transport.count(_SITES_PATH) == 1
    assert sorted(r.json()["cached"] for r in responses) == [False] + [True] * 5
    assert len(_audit_rows("adapter_vendor_tenant_list")) == 1


def test_a_mid_drain_vendor_failure_is_an_error_and_nothing_is_stored(datto):
    client, cookies, transport, iid = datto
    transport.sites = [{"uid": f"site-uid-{i:04d}", "name": f"Example {i}"} for i in range(7)]
    transport.sites_page_size = 3
    transport.fail_sites_from_page = 2
    r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 424 and r.json()["code"] == "VENDOR_ACCESS_FORBIDDEN"
    assert "tenants" not in r.json()
    assert vendor_tenants.latest(iid, _cred_ref(iid)) is None


def test_an_unusable_next_page_link_is_truncated_and_accuses_no_mapping(datto):
    client, cookies, transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    assert client.put(
        _map_url(iid),
        json={"mappings": [{
            "vendor_tenant_id": "site-uid-0003", "octo_client_slug": "example-clinic",
        }]},
        cookies=cookies,
    ).status_code == 200
    transport.sites_page_size = 2
    transport.override_next_page_url = True
    transport.next_page_url_override = "https://datto-api.example.test/x?cursor=abc"
    body = client.post(_url(iid), cookies=cookies).json()
    assert body["truncated"] is True and len(body["tenants"]) == 2
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["mappings_unmatched"] is None
    assert not any("do not match" in w for w in card["warnings"])


def test_rejected_credentials_never_look_like_a_console_session_problem(datto):
    client, cookies, transport, iid = datto
    transport.token_status = 401
    r = client.post(_url(iid), cookies=cookies)
    # 401/403 would mean OUR session to the console (and trigger its redirect).
    assert r.status_code == 424, r.text
    assert r.json()["code"] == "VENDOR_CREDENTIALS_REJECTED"
    assert "rejected credentials" in r.json()["message"]
    _assert_no_secret(r.text)


def test_unreachable_vendor_is_a_transport_error(datto):
    client, cookies, transport, iid = datto
    transport.unreachable = True
    r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 503, r.text
    assert r.json()["code"] == "VENDOR_UNREACHABLE"
    assert "Could not reach Datto" in r.json()["message"]
    assert "connection refused" not in r.text      # exception text never surfaces
    _assert_no_secret(r.text)


def test_an_adapter_bug_surfaces_its_class_name_only(datto, monkeypatch, caplog):
    client, cookies, _transport, iid = datto
    adapter_cls = client.app.state.adapter_registry.get_adapter_class("datto")

    def _boom(self, credentials):
        raise RuntimeError(f"fixture leak {credentials['DATTO_API_SECRET_KEY']}")

    monkeypatch.setattr(adapter_cls, "list_vendor_tenants", _boom)
    with caplog.at_level(logging.DEBUG):
        r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 500 and r.json()["code"] == "INTERNAL_ERROR"
    assert "RuntimeError" in r.json()["message"]
    assert "fixture leak" not in r.text and "fixture leak" not in caplog.text
    _assert_no_secret(r.text, caplog.text)


def test_unreadable_stored_credentials_say_so_without_the_reason_text(
    datto, monkeypatch, caplog,
):
    from apps.octo import credentials

    client, cookies, transport, iid = datto

    def _boom(ref):
        raise ValueError(f"fixture: bad ciphertext for {ref}")

    monkeypatch.setattr(credentials, "load", _boom)
    with caplog.at_level(logging.DEBUG):
        r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 500 and r.json()["code"] == "INTERNAL_ERROR"
    assert "could not be read" in r.json()["message"]
    assert "Datto RMM was not contacted" in r.json()["message"]
    assert "bad ciphertext" not in r.text and "bad ciphertext" not in caplog.text
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Cache: cheap to call, never outlives a credential change or a disable
# ---------------------------------------------------------------------------

def test_repeat_calls_are_served_from_the_cache(datto):
    client, cookies, transport, iid = datto
    first = client.post(_url(iid), cookies=cookies).json()
    for _ in range(5):
        again = client.post(_url(iid), cookies=cookies).json()
        assert again["cached"] is True
        assert again["tenants"] == first["tenants"]
        assert again["fetched_at"] == first["fetched_at"]
    assert transport.count(_SITES_PATH) == 1


def test_cache_expires_after_the_ttl(datto, monkeypatch):
    client, cookies, transport, iid = datto
    client.post(_url(iid), cookies=cookies)
    real = vendor_tenants._monotonic
    monkeypatch.setattr(
        vendor_tenants, "_monotonic",
        lambda: real() + vendor_tenants.CACHE_TTL_SEC + 1,
    )
    assert client.post(_url(iid), cookies=cookies).json()["cached"] is False
    assert transport.count(_SITES_PATH) == 2


def test_reload_asks_the_vendor_again_but_a_double_click_does_not(datto, monkeypatch):
    client, cookies, transport, iid = datto
    client.post(_url(iid), cookies=cookies)
    # Seconds-old answer: refresh reuses it.
    r = client.post(_url(iid), params={"refresh": "true"}, cookies=cookies).json()
    assert r["cached"] is True and transport.count(_SITES_PATH) == 1

    real = vendor_tenants._monotonic
    monkeypatch.setattr(
        vendor_tenants, "_monotonic",
        lambda: real() + vendor_tenants.MIN_REFRESH_INTERVAL_SEC + 1,
    )
    transport.sites = SITES + [{"uid": "site-uid-0004", "name": "Example New Site"}]
    # Without refresh the 60 s cache still answers…
    assert len(client.post(_url(iid), cookies=cookies).json()["tenants"]) == 3
    # …Reload sees the site that was just added in Datto.
    r = client.post(_url(iid), params={"refresh": "true"}, cookies=cookies).json()
    assert r["cached"] is False and len(r["tenants"]) == 4


def test_cache_does_not_outlive_a_disable(datto):
    client, cookies, transport, iid = datto
    client.post(_url(iid), cookies=cookies)
    cred_ref = _cred_ref(iid)
    assert vendor_tenants.latest(iid, cred_ref) is not None

    d = client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "fixture: rotating the key"}, cookies=cookies,
    )
    assert d.status_code == 200, d.text
    assert vendor_tenants.latest(iid, cred_ref) is None

    # The disabled instance is refused outright — nothing can re-fill it.
    r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 409 and r.json()["code"] == "CONFLICT"
    assert transport.count(_SITES_PATH) == 1

    # Disable → create is how a credential is changed: the replacement
    # instance gets a REAL listing, not the old one.
    transport.sites = [{"uid": "site-uid-9999", "name": "Example After Rotation"}]
    new = client.post(_CREATE, json={"credentials": CREDS}, cookies=cookies)
    new_id = new.json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()
    before = transport.count(_SITES_PATH)
    body = client.post(_url(new_id), cookies=cookies).json()
    assert body["cached"] is False
    assert [t["id"] for t in body["tenants"]] == ["site-uid-9999"]
    assert transport.count(_SITES_PATH) == before + 1


def _cred_ref(instance_id: int) -> str:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        return reg.execute(
            "SELECT cred_ref FROM adapter_instances WHERE id = ?", (instance_id,),
        ).fetchone()[0]
    finally:
        reg.close()


def test_cache_does_not_outlive_a_credential_change_on_the_same_instance(datto):
    """Credentials are create-only today; the cache is nevertheless bound to
    the row's cred_ref so any future edit path cannot serve a stale listing."""
    from apps.octo import credentials

    client, cookies, transport, iid = datto
    client.post(_url(iid), cookies=cookies)
    assert transport.count(_SITES_PATH) == 1

    new_ref = credentials.store({**CREDS, "DATTO_TIMEOUT_SECONDS": "10"})
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE adapter_instances SET cred_ref = ? WHERE id = ?", (new_ref, iid))
        reg.commit()
    finally:
        reg.close()

    transport.sites = [{"uid": "site-uid-7777", "name": "Example Other Account"}]
    body = client.post(_url(iid), cookies=cookies).json()
    assert body["cached"] is False
    assert [t["id"] for t in body["tenants"]] == ["site-uid-7777"]
    assert transport.count(_SITES_PATH) == 2


def test_create_rollback_forgets_the_listing(datto, monkeypatch):
    """Same reset the dropped-unmapped and vendor-contact state get: a create
    that is rolled back leaves no listing behind for its (dead) instance."""
    from shared_adapter_contract import VendorTenant, VendorTenantListing

    from apps.octo.api.routers import adapters as adapters_router

    client, cookies, _transport, iid = datto
    client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "fixture: free the vendor slot"}, cookies=cookies,
    )
    seen: list[int] = []

    def _listing_then_boom(rec, **_kwargs):
        seen.append(rec.id)
        vendor_tenants.store(
            rec.id, rec.cred_ref,
            VendorTenantListing([VendorTenant("site-uid-0001", "Example")]),
        )
        raise RuntimeError("fixture: response could not be built")

    def _state_then_boom(rec, **kwargs):
        vendor_contact.ContactReporter(rec.id, what="fixture").ok()
        vendor_tenants.remember_failure(
            rec.id, rec.cred_ref, code="VENDOR_UNREACHABLE", kind="transport", message="x",
        )
        return _listing_then_boom(rec, **kwargs)

    monkeypatch.setattr(adapters_router, "_instance_to_out", _state_then_boom)
    r = client.post(_CREATE, json={"credentials": CREDS}, cookies=cookies)
    assert r.status_code == 500 and r.json()["code"] == "INSTANCE_CREATE_INCOMPLETE"
    (rolled_back,) = seen
    assert vendor_tenants.latest(rolled_back, _cred_ref(rolled_back)) is None
    assert vendor_tenants.recent_failure(rolled_back, _cred_ref(rolled_back)) is None
    # …and the vendor-contact half of the same rollback.
    assert vendor_contact.snapshot(rolled_back) == vendor_contact.snapshot(None)


def test_a_listing_is_not_kept_for_an_instance_disabled_while_the_vendor_answered(
    datto, monkeypatch,
):
    from apps.octo.instances.manager import disable_instance

    client, cookies, _transport, iid = datto
    cred_ref = _cred_ref(iid)
    adapter_cls = client.app.state.adapter_registry.get_adapter_class("datto")
    real = adapter_cls.list_vendor_tenants

    def _disable_meanwhile(self, credentials):
        listing = real(self, credentials)
        disable_instance(iid, disabled_by_operator_id=None, reason="fixture: meanwhile")
        return listing

    monkeypatch.setattr(adapter_cls, "list_vendor_tenants", _disable_meanwhile)
    assert client.post(_url(iid), cookies=cookies).status_code == 200
    assert vendor_tenants.latest(iid, cred_ref) is None    # customer names not kept


def test_an_adapters_failure_message_is_bounded_and_flattened_by_the_route(
    datto, monkeypatch,
):
    """Datto's own text is already bounded, so only a stub shows that the
    ROUTE bounds whatever a future adapter raises."""
    from shared_adapter_contract import VendorTenantListError

    from apps.octo.api.routers import adapters as adapters_router

    client, cookies, _transport, iid = datto
    adapter_cls = client.app.state.adapter_registry.get_adapter_class("datto")

    def _huge(self, credentials):
        raise VendorTenantListError("transport", "x\n" * 5000)

    monkeypatch.setattr(adapter_cls, "list_vendor_tenants", _huge)
    r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 503
    message = r.json()["message"]
    assert len(message) <= adapters_router._MAX_VENDOR_MESSAGE_CHARS
    assert "\n" not in message


def test_an_unaudited_listing_is_never_cached(datto, monkeypatch):
    """Cache hits are not audited, so a listing stored BEFORE a failed audit
    write stayed servable — every client name — with no audit row at all."""
    from apps.octo.api.routers import adapters as adapters_router

    client, cookies, _transport, iid = datto
    real_audit = adapters_router._audit_vendor_tenant_list
    broken = {"on": True}

    def _audit(**kwargs):
        if broken["on"]:
            raise sqlite3.OperationalError("database is locked")
        return real_audit(**kwargs)

    monkeypatch.setattr(adapters_router, "_audit_vendor_tenant_list", _audit)
    try:
        failed = client.post(_url(iid), cookies=cookies)
    except sqlite3.OperationalError:       # TestClient re-raises server errors
        failed = None
    assert failed is None or failed.status_code == 500
    assert vendor_tenants.latest(iid, _cred_ref(iid)) is None
    broken["on"] = False
    ok = client.post(_url(iid), cookies=cookies)
    assert ok.status_code == 200 and ok.json()["cached"] is False
    assert len(_audit_rows("adapter_vendor_tenant_list")) == 1


def test_a_vendor_failure_keeps_its_message_when_the_audit_write_fails(
    datto, monkeypatch, caplog,
):
    from apps.octo.api.routers import adapters as adapters_router

    client, cookies, transport, iid = datto
    transport.forbid_data = True

    def _audit(**_kwargs):
        raise sqlite3.OperationalError(f"database is locked {SECRETS[0]}")

    monkeypatch.setattr(adapters_router, "_audit_vendor_tenant_list", _audit)
    with caplog.at_level(logging.DEBUG):
        r = client.post(_url(iid), cookies=cookies)
    assert r.status_code == 424 and "Setup > Users" in r.json()["message"]
    assert "could not be audited (OperationalError)" in caplog.text
    _assert_no_secret(r.text, caplog.text)


def test_the_unmatched_warning_names_at_most_five_ids(datto):
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    wrong = [f"Typed Site Name {i}" for i in range(7)]
    assert client.put(
        _map_url(iid),
        json={"mappings": [
            {"vendor_tenant_id": v, "octo_client_slug": "example-clinic"} for v in wrong
        ]},
        cookies=cookies,
    ).status_code == 200
    client.post(_url(iid), cookies=cookies)
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    (warning,) = [w for w in card["warnings"] if "do not match" in w]
    assert card["mappings_unmatched"] == 7 and warning.startswith("7 of 7 ")
    assert sum(f"'{v}'" in warning for v in wrong) == 5
    assert "(+2 more)" in warning


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def test_vendor_contact_is_audited_without_names_and_cache_hits_are_not(datto):
    client, cookies, transport, iid = datto
    client.post(_url(iid), cookies=cookies)
    client.post(_url(iid), cookies=cookies)          # cache hit
    transport.forbid_data = True
    vendor_tenants.reset(iid)
    client.post(_url(iid), cookies=cookies)          # failure
    client.post(_url(iid), cookies=cookies)          # replayed failure: no row

    rows = _audit_rows("adapter_vendor_tenant_list")
    assert [r[0] for r in rows] == [str(iid), str(iid)]
    ok_state, failed_state = rows[0][2], rows[1][2]
    assert '"outcome":"ok"' in ok_state and '"tenant_count":3' in ok_state
    assert '"outcome":"forbidden"' in failed_state
    for state in (ok_state, failed_state):
        assert "Example" not in state               # customer names stay out
        _assert_no_secret(state)


# ---------------------------------------------------------------------------
# Saved mappings that can never match → the card says so
# ---------------------------------------------------------------------------

def test_card_counts_saved_mappings_that_match_no_vendor_site(datto):
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    _make_client(client, cookies, "example-bakery")
    saved = client.put(
        _map_url(iid),
        json={"mappings": [
            # What the operator did in production: the site NAME as the id.
            {"vendor_tenant_id": "Example Clinic", "octo_client_slug": "example-clinic"},
            {"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "example-bakery"},
        ]},
        cookies=cookies,
    )
    assert saved.status_code == 200, saved.text

    # Not checked yet: the card does not guess, and no vendor call is made to
    # build the payload.
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["mappings_unmatched"] is None
    assert not any("do not match" in w for w in card["warnings"])

    checked_at = client.post(_url(iid), cookies=cookies).json()["fetched_at"]

    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["mappings_unmatched"] == 1
    assert card["mappings_checked_at"] == checked_at
    (warning,) = [w for w in card["warnings"] if "do not match" in w]
    assert warning.startswith(
        "1 of 2 saved tenant mapping(s) do not match any Datto RMM site"
    )
    assert "'Example Clinic'" in warning and "never route" in warning
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert warning in listed["instances"][0]["warnings"]

    # The operator picks the real uid and saves: the warning goes.
    fixed = client.put(
        _map_url(iid),
        json={"mappings": [
            {"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic",
             "vendor_tenant_label": "Example Clinic"},
            {"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "example-bakery"},
        ]},
        cookies=cookies,
    )
    assert fixed.status_code == 200, fixed.text
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["mappings_unmatched"] == 0
    assert not any("do not match" in w for w in card["warnings"])


def test_a_truncated_listing_never_accuses_a_mapping(datto):
    from shared_adapter_contract import VendorTenant, VendorTenantListing

    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    client.put(
        _map_url(iid),
        json={"mappings": [
            {"vendor_tenant_id": "site-uid-5000", "octo_client_slug": "example-clinic"},
        ]},
        cookies=cookies,
    )
    vendor_tenants.store(
        iid, _cred_ref(iid),
        VendorTenantListing([VendorTenant("site-uid-0001", "Example")], truncated=True),
    )
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["mappings_unmatched"] is None
    assert not any("do not match" in w for w in card["warnings"])


# ---------------------------------------------------------------------------
# Saving mappings: permissive, no vendor call, but never obviously broken
# ---------------------------------------------------------------------------

def test_saving_is_permissive_about_unknown_ids_and_never_calls_the_vendor(datto):
    client, cookies, transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    r = client.put(
        _map_url(iid),
        json={"mappings": [{
            "vendor_tenant_id": "a-site-datto-will-only-create-tomorrow",
            "octo_client_slug": "example-clinic",
            "vendor_tenant_label": "  ",
        }]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.json()["mappings"][0]["vendor_tenant_label"] is None
    assert transport.calls == []

    (row,) = _audit_rows("adapter_tenant_map_replace")
    assert row[0] == str(iid)
    assert '"mappings":{}' in row[1]
    assert '"a-site-datto-will-only-create-tomorrow":"example-clinic"' in row[2]


@pytest.mark.parametrize(
    ("mappings", "fragment"),
    [
        ([{"vendor_tenant_id": "   ", "octo_client_slug": "example-clinic"}], "is blank"),
        ([{"vendor_tenant_id": " site-uid-0001", "octo_client_slug": "example-clinic"}],
         "whitespace"),
        ([{"vendor_tenant_id": "site\nuid", "octo_client_slug": "example-clinic"}],
         "control characters"),
        ([{"vendor_tenant_id": "x" * 300, "octo_client_slug": "example-clinic"}],
         "longer than"),
        ([{"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic"},
          {"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic"}],
         "duplicate vendor_tenant_id"),
        ([{"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "Not A Slug"}],
         "is not a client slug"),
        ([{"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "no-such-client"}],
         "does not exist"),
        ([{"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic",
           "match_source": "guessed"}], "match_source"),
        ([{"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic",
           "vendor_tenant_label": "y" * 300}], "vendor_tenant_label"),
    ],
)
def test_obviously_broken_mappings_are_refused_and_nothing_changes(datto, mappings, fragment):
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    good = [{"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "example-clinic"}]
    assert client.put(_map_url(iid), json={"mappings": good}, cookies=cookies).status_code == 200

    r = client.put(_map_url(iid), json={"mappings": mappings}, cookies=cookies)
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "VALIDATION_FAILED" and fragment in r.json()["message"]
    kept = client.get(_map_url(iid), cookies=cookies).json()["mappings"]
    assert [m["vendor_tenant_id"] for m in kept] == ["site-uid-0002"]
    assert len(_audit_rows("adapter_tenant_map_replace")) == 1


def test_mappings_are_refused_for_the_wrong_vendor_a_missing_or_a_disabled_instance(datto):
    client, cookies, _transport, iid = datto
    body = {"mappings": []}
    assert client.put(_map_url(iid, "wazuh"), json=body, cookies=cookies).status_code == 404
    assert client.put(_map_url(987654), json=body, cookies=cookies).status_code == 404
    client.post(
        f"/api/v1/admin/adapters/instances/{iid}/disable",
        json={"reason": "fixture"}, cookies=cookies,
    )
    assert client.put(_map_url(iid), json=body, cookies=cookies).status_code == 409


def test_analyst_cannot_save_mappings(datto):
    client, _cookies, _transport, iid = datto
    low = client.login(
        client.provision_operator("bob", "password1234567", athena_role="analyst")
    )
    assert client.put(_map_url(iid), json={"mappings": []}, cookies=low).status_code == 403


# ---------------------------------------------------------------------------
# Frozen rows: an offboarded tenant's mappings survive every PUT
# ---------------------------------------------------------------------------

def _set_status(slug: str, status: str) -> None:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET status = ? WHERE slug = ?", (status, slug))
        reg.commit()
    finally:
        reg.close()


def _seed_name_matched(iid: int, *, with_manual: bool) -> None:
    from apps.octo.instances import tenant_map

    rows = [tenant_map.TenantMapping("site-uid-0002", "gone-co", "Branch Office", "auto-name")]
    if with_manual:
        rows.insert(0, tenant_map.TenantMapping("site-uid-0001", "example-clinic", None, "manual"))
    tenant_map.set_mappings(iid, rows)


def test_get_carries_each_clients_status_and_name(datto):
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    _make_client(client, cookies, "gone-co")
    # A name-matched row an EARLIER version stored (the mapping routes now
    # refuse to create one — the same-name rule).
    _seed_name_matched(iid, with_manual=True)
    _set_status("gone-co", "offboarded")
    rows = client.get(_map_url(iid), cookies=cookies).json()["mappings"]
    assert rows == [
        {"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic",
         "vendor_tenant_label": None, "match_source": "manual",
         "client_status": "active", "client_display_name": "Example-Clinic",
         "needs_review": False},
        # A frozen row (its tenant left) is read-only: never "to re-review".
        {"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "gone-co",
         "vendor_tenant_label": "Branch Office", "match_source": "auto-name",
         "client_status": "offboarded", "client_display_name": "Gone-Co",
         "needs_review": False},
    ]


@pytest.mark.parametrize("status", ["offboarded", "archived", "disabled"])
def test_put_without_a_frozen_row_keeps_it_verbatim(datto, status):
    """An offboarded tenant's mapping is kept on purpose so the site's traffic
    holds as 'offboarded-tenant'. The panel used to show that row with a
    blank client picker; an operator who "cleaned it up" and saved DELETED
    the mapping — and the next event from that site auto-created a
    look-alike tenant. PUT merges now: a frozen row the body omits stays."""
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    _make_client(client, cookies, "gone-co")
    # A name-matched row an EARLIER version stored (the mapping routes now
    # refuse to create one — the same-name rule).
    _seed_name_matched(iid, with_manual=True)
    _set_status("gone-co", status)

    # The body names only the active row (and a new one): the frozen row survives.
    r = client.put(_map_url(iid), json={"mappings": [
        {"vendor_tenant_id": "site-uid-0001", "octo_client_slug": "example-clinic",
         "vendor_tenant_label": "Example Clinic"},
        {"vendor_tenant_id": "site-uid-0003", "octo_client_slug": "example-clinic"},
    ]}, cookies=cookies)
    assert r.status_code == 200, r.text
    by_id = {m["vendor_tenant_id"]: m for m in r.json()["mappings"]}
    assert set(by_id) == {"site-uid-0001", "site-uid-0002", "site-uid-0003"}
    assert by_id["site-uid-0002"] == {
        "vendor_tenant_id": "site-uid-0002", "octo_client_slug": "gone-co",
        "vendor_tenant_label": "Branch Office", "match_source": "auto-name",
        "client_status": status, "client_display_name": "Gone-Co", "needs_review": False,
    }
    assert by_id["site-uid-0001"]["vendor_tenant_label"] == "Example Clinic"
    # An EMPTY body clears the active map and still not the frozen row.
    r = client.put(_map_url(iid), json={"mappings": []}, cookies=cookies)
    assert [m["vendor_tenant_id"] for m in r.json()["mappings"]] == ["site-uid-0002"]
    from apps.octo.instances import tenant_map
    assert tenant_map.resolve(iid, "site-uid-0002") == "gone-co"
    # The audit's after-state is the EFFECTIVE map, frozen row included.
    last = _audit_rows("adapter_tenant_map_replace")[-1]
    assert '"site-uid-0002":"gone-co"' in last[1] and '"site-uid-0002":"gone-co"' in last[2]


def test_put_round_trips_a_frozen_row_and_refuses_to_re_point_it(datto):
    client, cookies, _transport, iid = datto
    _make_client(client, cookies, "example-clinic")
    _make_client(client, cookies, "gone-co")
    _seed_name_matched(iid, with_manual=False)
    _set_status("gone-co", "offboarded")

    # Sent back as the panel does (verbatim, and even with a match_source the
    # route would not accept for a new row): the STORED row stands unchanged.
    r = client.put(_map_url(iid), json={"mappings": [
        {"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "gone-co",
         "vendor_tenant_label": "Renamed By Client", "match_source": "auto"},
    ]}, cookies=cookies)
    assert r.status_code == 200, r.text
    (row,) = r.json()["mappings"]
    assert row["vendor_tenant_label"] == "Branch Office" and row["match_source"] == "auto-name"
    assert row["client_status"] == "offboarded"

    # Pointing the frozen site at another tenant is a quarantine decision, not a PUT.
    r = client.put(_map_url(iid), json={"mappings": [
        {"vendor_tenant_id": "site-uid-0002", "octo_client_slug": "example-clinic"},
    ]}, cookies=cookies)
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "CONFLICT"
    assert "frozen to 'gone-co'" in r.json()["message"] and "Quarantine" in r.json()["message"]
    from apps.octo.instances import tenant_map
    assert tenant_map.resolve(iid, "site-uid-0002") == "gone-co"
    # The seeded row wrote none; the round trip one; the refusal none.
    assert len(_audit_rows("adapter_tenant_map_replace")) == 1


# ---------------------------------------------------------------------------
# The cache module on its own
# ---------------------------------------------------------------------------

def test_lookup_is_bound_to_the_cred_ref_and_the_ttl(monkeypatch):
    from shared_adapter_contract import VendorTenant, VendorTenantListing

    vendor_tenants.reset()
    listing = VendorTenantListing([VendorTenant("site-uid-0001", "Example")])
    vendor_tenants.store(5, "ref-a", listing)
    assert vendor_tenants.lookup(5, "ref-a") is not None
    assert vendor_tenants.lookup(5, "ref-b") is None          # credential changed
    assert vendor_tenants.lookup(6, "ref-a") is None          # another instance
    real = vendor_tenants._monotonic
    monkeypatch.setattr(
        vendor_tenants, "_monotonic",
        lambda: real() + vendor_tenants.CACHE_TTL_SEC + 1,
    )
    assert vendor_tenants.lookup(5, "ref-a") is None          # expired…
    assert vendor_tenants.latest(5, "ref-a") is not None      # …kept for the card
    assert vendor_tenants.latest(5, "ref-b") is None
    vendor_tenants.reset(5)
    assert vendor_tenants.latest(5, "ref-a") is None
