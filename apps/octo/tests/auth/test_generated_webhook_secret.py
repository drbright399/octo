"""Platform-generated webhook secrets + ingest-hostname webhook URLs, end to end.

Create route (POST /admin/adapters/{slug}/instances):
  - blank token + enable_webhook=true → the platform generates one, vaults it,
    returns it EXACTLY ONCE (Cache-Control: no-store) and it authenticates the
    real webhook receiver
  - it is in no list / integrations payload, no audit row, no log record
  - operator-supplied tokens still work and are never echoed; the 32-char
    floor still applies; legacy callers (no enable_webhook) stay poll-only
  - Resend's secret is vendor-issued: never generated
  - the secret never rides on an error path
Catalog: webhook URLs come from OCTO_PUBLIC_INGEST_BASE_URL, with an explicit
"not configured" state instead of a console-origin fallback.
"""
from __future__ import annotations

import base64
import logging
import sqlite3

import pytest

from apps.octo import credentials, paths
from apps.octo.tests.auth.test_adapter_catalog import _login, _with_test_registry
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    _StubAdapter,
    _StubDatto,
    _register_stub_datto,
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"


def _admin(client) -> dict:
    _register_stub_datto(client)
    return client.login(client.provision_operator("admin1", "password1234567"))


def _stored_credentials(instance_id: int) -> dict:
    from apps.octo.instances.manager import get_instance

    return credentials.load(get_instance(instance_id).cred_ref)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def test_blank_token_with_webhooks_enabled_is_generated_and_vaulted(
    instance_endpoint_client, monkeypatch,
):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    client = instance_endpoint_client
    cookies = _admin(client)

    r = client.post(
        _CREATE,
        json={
            "credentials": {"DATTO_API_KEY": "k", "DATTO_WEBHOOK_SECRET": ""},
            "enable_webhook": True,
        },
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    gen = body["generated_webhook_secret"]
    assert gen["credential_field"] == "DATTO_WEBHOOK_SECRET"
    assert gen["header_name"] == "X-Webhook-Token"
    assert gen["shown_once"] is True
    assert gen["webhook_url"] == "https://ingest.example.test/api/v1/webhooks/datto"
    assert gen["webhook_url_problem"] is None
    token = gen["header_value"]
    assert len(token) >= 48
    # A usable secret → no "webhooks are rejected" warning.
    assert body["instance"]["warnings"] == []
    # The token appears once in the body: in header_value, nowhere else.
    assert r.text.count(token) == 1

    # Vaulted with the rest of the instance credentials…
    stored = _stored_credentials(body["instance"]["id"])
    assert stored["DATTO_WEBHOOK_SECRET"] == token and stored["DATTO_API_KEY"] == "k"

    # …and it is what the public receiver actually verifies against.
    ok = client.post(
        "/api/v1/webhooks/datto",
        json={"alertUid": "a-1", "siteUid": "site-unmapped"},
        headers={"X-Webhook-Token": token},
    )
    assert ok.status_code == 200, ok.text
    bad = client.post(
        "/api/v1/webhooks/datto",
        json={"alertUid": "a-1"},
        headers={"X-Webhook-Token": token[:-1] + ("A" if token[-1] != "A" else "B")},
    )
    assert bad.status_code == 401


def test_two_creates_never_share_a_token(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    tokens = []
    for _ in range(2):
        r = client.post(
            _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
        )
        assert r.status_code == 200, r.text
        tokens.append(r.json()["generated_webhook_secret"]["header_value"])
        client.post(
            f"/api/v1/admin/adapters/instances/{r.json()['instance']['id']}/disable",
            json={"reason": "fixture: replace"}, cookies=cookies,
        )
    assert tokens[0] != tokens[1]


def test_generated_token_is_shown_once_and_never_again(
    instance_endpoint_client, caplog,
):
    """Not in any read-back surface, not in the audit chain, not in the logs."""
    client = instance_endpoint_client
    cookies = _admin(client)

    with caplog.at_level(logging.DEBUG):
        r = client.post(
            _CREATE, json={"credentials": {"DATTO_API_KEY": "k"}, "enable_webhook": True},
            cookies=cookies,
        )
        assert r.status_code == 200, r.text
        token = r.json()["generated_webhook_secret"]["header_value"]
        instance_id = r.json()["instance"]["id"]

        listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies)
        agg = client.get("/api/v1/integrations", cookies=cookies)
        # A second create is refused (one active instance per vendor) — and the
        # refusal neither reveals the stored token nor mints a visible new one.
        dup = client.post(
            _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
        )
        disabled = client.post(
            f"/api/v1/admin/adapters/instances/{instance_id}/disable",
            json={"reason": "fixture: rotate the webhook token"}, cookies=cookies,
        )

    for resp in (listed, agg, dup, disabled):
        assert token not in resp.text
        assert "header_value" not in resp.text
    assert listed.status_code == 200 and dup.status_code == 409
    assert "generated_webhook_secret" not in dup.text

    # Audit chain: every column of every row.
    conn = sqlite3.connect(paths.global_audit_db_path())
    rows = conn.execute("SELECT * FROM audit_log").fetchall()
    conn.close()
    assert any("adapter_instance_create" in str(row) for row in rows)
    assert all(token not in str(row) for row in rows)
    assert all("DATTO_WEBHOOK_SECRET" not in str(row) for row in rows)

    # Logs: message, args and any attached exception text, at DEBUG and up.
    assert caplog.records  # the capture was live
    for record in caplog.records:
        assert token not in record.getMessage()
        assert token not in str(record.args)
        assert token not in str(record.__dict__)
    assert token not in caplog.text


def test_no_route_reads_a_credential_back(instance_endpoint_client):
    """Shown-once only holds if nothing can read it back: the admin-adapters
    router has ONE GET that touches instances (the instance list), and the
    only other route that decrypts stored credentials is the vendor-tenant
    listing — a POST (it contacts the vendor; never a GET, see
    test_a_get_never_contacts_the_vendor) returning vendor site ids and names
    only, pinned by test_vendor_tenant_discovery's
    test_listing_never_returns_a_credential_or_the_webhook_token."""
    client = instance_endpoint_client
    instance_routes = sorted(
        (sorted(route.methods), route.path)
        for route in client.app.routes
        if getattr(route, "path", "").startswith("/api/v1/admin/adapters")
        and "instances" in route.path
    )
    assert instance_routes == [
        (["GET"], "/api/v1/admin/adapters/instances"),
        (["POST"], "/api/v1/admin/adapters/instances/{instance_id}/disable"),
        (["POST"], "/api/v1/admin/adapters/instances/{instance_id}/vendor-tenants"),
        (["POST"], "/api/v1/admin/adapters/{vendor_slug}/instances"),
    ]


# ---------------------------------------------------------------------------
# The operator's own token, the floor, and legacy callers
# ---------------------------------------------------------------------------

def test_operator_supplied_token_is_used_and_never_echoed(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    token = "sample-fixture-token-" + "0123456789ab"  # 32 chars: meets the floor

    r = client.post(
        _CREATE,
        json={"credentials": {"DATTO_WEBHOOK_SECRET": token}, "enable_webhook": True},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    assert r.json()["generated_webhook_secret"] is None
    assert token not in r.text
    assert _stored_credentials(r.json()["instance"]["id"])["DATTO_WEBHOOK_SECRET"] == token


def test_below_floor_token_is_refused_even_when_webhooks_are_enabled(
    instance_endpoint_client,
):
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(
        _CREATE,
        json={"credentials": {"DATTO_WEBHOOK_SECRET": "weak-token-31"}, "enable_webhook": True},
        cookies=cookies,
    )
    assert r.status_code == 422, r.text
    assert "Webhook Token is too short" in r.text
    assert "weak-token-31" not in r.text and "generated_webhook_secret" not in r.text
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed == {"instances": []}


@pytest.mark.parametrize("payload", [
    {"credentials": {"DATTO_API_KEY": "k"}},                          # legacy caller
    {"credentials": {"DATTO_API_KEY": "k"}, "enable_webhook": None},
])
def test_legacy_blank_secret_generates_nothing_and_still_warns(
    instance_endpoint_client, payload,
):
    """No explicit choice on record → a missing secret may be an accident, so
    the loud warning stays — by field LABEL, with the exact recovery path."""
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(_CREATE, json=payload, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["generated_webhook_secret"] is None
    assert "DATTO_WEBHOOK_SECRET" not in _stored_credentials(body["instance"]["id"])
    (warning,) = body["instance"]["warnings"]
    assert "Webhook Token is not set" in warning
    assert "DATTO_WEBHOOK_SECRET" not in warning and "/api/v1/" not in warning
    assert "Settings → Integrations → Stub Datto → Disable, then Add integration again" in warning
    assert body["instance"]["notes"] == []


def test_explicit_poll_only_is_a_choice_not_a_fault(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(
        _CREATE,
        json={
            "credentials": {"DATTO_API_KEY": "k"},
            "enable_webhook": False,
            # A caller cannot pre-seed the server-owned choice key.
            "instance_config": {"webhooks": "on", "poll_interval_sec": 60},
        },
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    inst = r.json()["instance"]
    assert r.json()["generated_webhook_secret"] is None
    assert "DATTO_WEBHOOK_SECRET" not in _stored_credentials(inst["id"])

    from apps.octo.instances.manager import get_instance
    assert get_instance(inst["id"]).instance_config == {
        "webhooks": "off", "poll_interval_sec": 60,
    }
    # Neutral note, no alert — on every read-back surface.
    assert inst["warnings"] == []
    (note,) = inst["notes"]
    assert note.startswith("Poll-only: real-time webhooks are off by choice")
    assert "Settings → Integrations → Stub Datto → Disable" in note
    listed = client.get("/api/v1/admin/adapters/instances", cookies=cookies).json()
    assert listed["instances"][0]["notes"] == [note]
    agg = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert agg["notes"] == [note] and agg["warnings"] == [] and agg["id"] == inst["id"]


def test_armed_webhooks_without_an_ingest_hostname_warn_on_the_card(
    instance_endpoint_client, monkeypatch,
):
    """The wizard says it once; the card must keep saying it afterwards."""
    monkeypatch.delenv("OCTO_PUBLIC_INGEST_BASE_URL", raising=False)
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(_CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies)
    assert r.status_code == 200, r.text
    token = r.json()["generated_webhook_secret"]["header_value"]
    (warning,) = r.json()["instance"]["warnings"]
    assert "no public ingest hostname" in warning and "docker-compose.yml" in warning
    assert token not in warning
    agg = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert agg["warnings"] == [warning]

    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    agg = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert agg["warnings"] == []


def test_poll_only_with_a_token_is_a_contradiction(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    token = "operator-supplied-" + "z" * 30
    r = client.post(
        _CREATE,
        json={"credentials": {"DATTO_WEBHOOK_SECRET": token}, "enable_webhook": False},
        cookies=cookies,
    )
    assert r.status_code == 422, r.text
    assert "enable_webhook is false" in r.text and token not in r.text


def test_enabling_webhooks_on_a_vendor_without_one_is_refused(instance_endpoint_client):
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"k": "v"}, "enable_webhook": True},
        cookies=cookies,
    )
    assert r.status_code == 422 and "no inbound webhook" in r.text


# ---------------------------------------------------------------------------
# Resend: vendor-issued — never generated
# ---------------------------------------------------------------------------

class _StubResend(_StubAdapter):
    vendor_slug = "resend"
    vendor_display_name = "Stub Resend"
    delivery_mode = "push"


def test_resend_secret_is_never_generated(instance_endpoint_client):
    client = instance_endpoint_client
    client.app.state.adapter_registry.register_adapter_class(_StubResend)
    cookies = client.login(client.provision_operator("admin1", "password1234567"))
    url = "/api/v1/admin/adapters/resend/instances"

    # Asking the platform to "enable" it with no secret cannot work: say so.
    r = client.post(url, json={"credentials": {}, "enable_webhook": True}, cookies=cookies)
    assert r.status_code == 422, r.text
    assert "issued by the vendor" in r.text
    assert client.get(
        "/api/v1/admin/adapters/instances", cookies=cookies,
    ).json() == {"instances": []}

    # Pasted vendor secret: stored as given, nothing generated, nothing echoed.
    # Built at runtime — the scheme prefix split, the key part base64 of a
    # visibly fake phrase — so no vendor-shaped literal sits in the source
    # for a secret scanner to match. The value is the same at runtime.
    secret = "whsec" + "_" + base64.b64encode(b"sample-fixture-key").decode()
    r = client.post(
        url, json={"credentials": {"RESEND_WEBHOOK_SECRET": secret}, "enable_webhook": True},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert r.json()["generated_webhook_secret"] is None and secret not in r.text
    stored = _stored_credentials(r.json()["instance"]["id"])
    assert stored == {"RESEND_WEBHOOK_SECRET": secret}


# ---------------------------------------------------------------------------
# Error paths never carry a generated secret
# ---------------------------------------------------------------------------

def test_smoke_failure_generates_and_returns_nothing(instance_endpoint_client, monkeypatch):
    from apps.octo.instances import webhook_auth

    minted: list[str] = []
    real = webhook_auth.generate_token
    monkeypatch.setattr(
        webhook_auth, "generate_token", lambda: minted.append(real()) or minted[-1],
    )
    client = instance_endpoint_client
    cookies = _admin(client)
    _StubDatto.smoke_ok = False
    _StubDatto.smoke_message = "upstream said no"
    try:
        r = client.post(
            _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
        )
    finally:
        del _StubDatto.smoke_ok, _StubDatto.smoke_message
    assert r.status_code == 400, r.text
    assert minted == []  # nothing was even generated
    assert "generated_webhook_secret" not in r.text and "header_value" not in r.text


def test_duplicate_instance_error_does_not_leak_the_new_token(
    instance_endpoint_client, monkeypatch,
):
    from apps.octo.instances import webhook_auth

    minted: list[str] = []
    real = webhook_auth.generate_token
    monkeypatch.setattr(
        webhook_auth, "generate_token", lambda: minted.append(real()) or minted[-1],
    )
    client = instance_endpoint_client
    cookies = _admin(client)
    first = client.post(
        _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
    )
    assert first.status_code == 200
    dup = client.post(
        _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
    )
    assert dup.status_code == 409, dup.text
    assert len(minted) == 2  # one was minted for the refused attempt…
    assert minted[1] not in dup.text and minted[0] not in dup.text  # …and dies unseen


# ---------------------------------------------------------------------------
# No ingest hostname: generation still works, but the URL state is explicit
# ---------------------------------------------------------------------------

def test_create_without_ingest_hostname_reports_it_and_never_uses_the_console(
    instance_endpoint_client, monkeypatch,
):
    monkeypatch.setenv("OCTO_PUBLIC_BASE_URL", "https://console.example.test")
    monkeypatch.delenv("OCTO_PUBLIC_INGEST_BASE_URL", raising=False)
    client = instance_endpoint_client
    cookies = _admin(client)
    r = client.post(
        _CREATE, json={"credentials": {}, "enable_webhook": True}, cookies=cookies,
    )
    assert r.status_code == 200, r.text
    gen = r.json()["generated_webhook_secret"]
    assert gen["webhook_url"] is None
    assert "no public ingest hostname" in gen["webhook_url_problem"].lower()
    assert "console.example.test" not in r.text


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def _catalog(auth_client) -> list[dict]:
    op = auth_client.provision_operator("admin-doc", "pw1234567890", athena_role="admin")
    cookies = _login(auth_client, op)
    from apps.octo.adapters.resend import ResendSourceAdapter

    _with_test_registry(auth_client).register_adapter_class(ResendSourceAdapter)
    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 200, r.text
    return r.json()["adapters"]


def _entry(adapters: list[dict], slug: str) -> dict:
    return next(a for a in adapters if a["vendor_slug"] == slug)


def test_catalog_webhook_url_uses_the_ingest_hostname(auth_client, monkeypatch):
    monkeypatch.setenv("OCTO_PUBLIC_BASE_URL", "https://console.example.test")
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test/")
    adapters = _catalog(auth_client)

    for slug in ("datto", "resend"):
        ob = _entry(adapters, slug)["onboarding"]
        assert ob["webhook_url"] == f"https://ingest.example.test/api/v1/webhooks/{slug}"
        assert ob["webhook_url_problem"] is None
    assert _entry(adapters, "datto")["onboarding"]["steps"][2]["copy_value"] == (
        "https://ingest.example.test/api/v1/webhooks/datto"
    )
    assert "console.example.test" not in str(adapters)


def test_catalog_without_ingest_hostname_says_so_and_never_falls_back(
    auth_client, monkeypatch,
):
    """A console-origin webhook URL is blocked at the access gate — handing it
    to a vendor is worse than handing over nothing."""
    monkeypatch.setenv("OCTO_PUBLIC_BASE_URL", "https://console.example.test")
    monkeypatch.delenv("OCTO_PUBLIC_INGEST_BASE_URL", raising=False)
    adapters = _catalog(auth_client)

    ob = _entry(adapters, "datto")["onboarding"]
    assert ob["webhook_url"] is None
    assert "no public ingest hostname" in ob["webhook_url_problem"].lower()
    assert "cannot work" in ob["webhook_url_problem"]
    # Plain-language fix: WHERE the setting lives and what to do after.
    assert "docker-compose.yml" in ob["webhook_url_problem"]
    assert "recreate" in ob["webhook_url_problem"]
    assert "docs/operations/bundle.md" in ob["webhook_url_problem"]
    assert all(s["copy_value"] is None for s in ob["steps"])
    assert "no public ingest hostname" in ob["steps"][2]["body"]
    assert "console.example.test" not in str(adapters)
    # Poll-only adapters have no webhook, so nothing is "wrong" for them.
    wazuh_ob = _entry(adapters, "wazuh")["onboarding"] or {}
    assert wazuh_ob.get("webhook_url_problem") is None


def test_catalog_declares_who_mints_each_webhook_secret(auth_client):
    fields = {
        f["name"]: f for a in _catalog(auth_client) for f in a["credential_shape"]
    }
    datto = fields["DATTO_WEBHOOK_SECRET"]
    assert datto["secret_origin"] == "platform"
    assert datto["webhook_header"] == "X-Webhook-Token"
    assert datto["required"] is False and "openssl" not in datto["description"]
    resend = fields["RESEND_WEBHOOK_SECRET"]
    assert resend["secret_origin"] == "vendor" and resend["webhook_header"] is None
    assert "cannot" in resend["description"]  # …create it for you
    assert fields["DATTO_API_KEY"]["secret_origin"] is None
