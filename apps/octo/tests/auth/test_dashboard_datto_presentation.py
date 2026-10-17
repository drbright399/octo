"""Datto rows on the dashboard: readable, and linked back to the vendor.

Through the real HTTP routes with the REAL Datto adapter, client, instance
manager and link builder — only the vendor socket is fake
(adapters/datto/tests/fake_datto.py).

The production defects:
  - the feed showed every Datto row as title "alert" with an empty summary;
    the rows ALREADY STORED like that must become readable too, without
    touching them;
  - V1's vendor links "sometimes just went to the RMM home dashboard".

Alert links are built from the payload. Device links are NOT (the portal
addresses a device by a numeric id no payload carries): a row carries a
reference, resolved on click — see test_vendor_device_link.py.
"""
from __future__ import annotations

import json
import sqlite3
import unicodedata
from types import SimpleNamespace

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    PLATFORM_API_URL,
    PLATFORM_PORTAL,
    SECRETS,
    FakeDattoTransport,
    datto_adapter_class,
)
from apps.octo.adapters.datto.tests.test_presentation import (
    COMP_SCRIPT,
    EVENTLOG,
    api_alert,
)
from apps.octo.api.vendor_links import VendorLinkResolver
from apps.octo.instances import device_links, tenant_map, vendor_contact
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"
_FEED = "/api/v1/dashboard/recent-events?min_severity=info"
_DEVICES = "/api/v1/dashboard/devices-attention"

# A made-up platform name in Datto's documented '<platform>-api' host form.
PLATFORM_CREDS = {**CREDS, "DATTO_API_URL": PLATFORM_API_URL}
PORTAL = PLATFORM_PORTAL
ALERT_UID = "0a1b2c3d-aaaa-bbbb-cccc-000000000001"


@pytest.fixture
def datto(instance_endpoint_client):  # noqa: F811
    vendor_contact.reset()
    device_links.reset()
    client = instance_endpoint_client
    transport = FakeDattoTransport()
    transport.api_hosts.add("exampleplat-api.centrastage.net")
    client.datto_transport = transport
    client.app.state.adapter_registry.register_adapter_class(
        datto_adapter_class(transport)
    )
    client_provisioning.create_client("acme", "Acme")
    yield client
    client.app.state.instance_manager.stop_all_running()
    vendor_contact.reset()
    device_links.reset()


def _create_instance(client, cookies, creds=PLATFORM_CREDS) -> int:
    r = client.post(_CREATE, json={"credentials": creds}, cookies=cookies)
    assert r.status_code == 200, r.text
    return r.json()["instance"]["id"]


def _map_site(instance_id: int, site_uid: str = "site-uid-0001", slug: str = "acme") -> None:
    tenant_map.set_mappings(instance_id, [tenant_map.TenantMapping(site_uid, slug)])


def _store_legacy_row(
    payload, *, source="datto", event_type="alert", severity="high",
    summary="", host="WS-EXAMPLE-01", received_at="2026-09-21T14:13:20.000Z",
    slug="acme",
) -> int:
    """A row exactly as the old sink wrote it: event_type 'alert', summary ''."""
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, "
            "severity, summary, payload, payload_sha256) VALUES (?,?,?,?,?,?,?,?)",
            (received_at, source, host, event_type, severity, summary,
             payload if isinstance(payload, str) else json.dumps(payload), "a" * 64),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _stored(event_id: int) -> tuple:
    conn = sqlite3.connect(paths.client_dir("acme") / "events.db")
    try:
        return conn.execute(
            "SELECT received_at, event_type, summary, payload, payload_sha256 "
            "FROM events WHERE id = ?", (event_id,),
        ).fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The feed
# ---------------------------------------------------------------------------

def test_a_stored_row_with_an_empty_summary_is_readable_and_untouched(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, cookies))
    event_id = _store_legacy_row(api_alert(EVENTLOG))
    before = _stored(event_id)

    r = client.get(_FEED, cookies=cookies)
    assert r.status_code == 200, r.text
    (row,) = r.json()["items"]
    assert row["title"] == "Event log · Security 4625 — An account failed to log on"
    assert "Account Name: alice" in row["summary"].split("\n")
    assert row["summary"].endswith("Triggered 5 times")
    assert (row["device"], row["site"]) == ("WS-EXAMPLE-01", "Example Site")
    assert (row["severity"], row["source"], row["client_slug"]) == ("high", "datto", "acme")
    assert row["vendor_links"] == [
        {"kind": "alert", "label": "Open in Datto RMM", "vendor": "datto",
         "url": f"{PORTAL}/alert/{ALERT_UID}"},
    ]
    # The device page is a REFERENCE (resolved on click), never a URL built
    # from the device uid — and building the feed asked the vendor nothing.
    assert row["vendor_device_ref"] == {
        "vendor": "datto", "label": "Open device in Datto RMM",
        "client_slug": "acme", "event_id": event_id,
    }
    assert "dev-uid-0001" not in r.text and "/device/" not in r.text
    assert not [c for c in client.datto_transport.calls if "/device/" in c[1]]
    # Read-time only: the row (ingest idempotency keys included) is as it was.
    assert _stored(event_id) == before
    for secret in SECRETS:
        assert secret not in r.text


def test_other_sources_look_the_same_as_before(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _create_instance(client, cookies)
    _store_legacy_row(
        {"rule": {"description": "sshd brute force"}}, source="wazuh",
        event_type="auth.failure", summary="[authentication_failed] SSH brute force",
        host="web-01",
    )
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["title"] == "auth.failure"
    assert row["summary"] == "[authentication_failed] SSH brute force"
    assert row["device"] == "web-01" and row["site"] is None
    assert row["vendor_links"] == [] and row["vendor_device_ref"] is None


def test_a_stored_summary_from_any_source_gets_the_same_text_hygiene(datto):
    """The sink now keeps EVERY adapter's summary, and only Datto's is a
    presenter's output. A buoy / Wazuh / UniFi row whose vendor text carries
    bidi overrides, zero-width or control characters must reach the feed (and
    from there the drawer, notes, CSV) cleaned like a presented row is."""
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _create_instance(client, cookies)
    nasty = "sshd\x00 brute‮ force​ from\x1b[31m alice\x07\nsecond\x08 line\n\n\n"
    _store_legacy_row(
        {"rule": {"description": nasty}}, source="buoy:x", event_type="ids.brute_force",
        summary=nasty, host="web-01",
    )
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["title"] == "ids.brute_force"
    assert row["summary"] == "sshd brute force from[31m alice\nsecond line"
    assert not any(unicodedata.category(ch) in ("Cc", "Cf") and ch != "\n" for ch in row["summary"])


def test_a_datto_row_without_dattos_shape_keeps_the_summary_it_was_stored_with(datto):
    """Dev synthetic traffic files rows under source 'datto' with a payload
    that is not a Datto alert and a summary that means something. The
    presenter recognises nothing in such a payload; its bare 'Datto alert'
    label must not replace that summary — the row reads as it did before
    presentation existed."""
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, cookies))
    _store_legacy_row(
        {"synthetic": True, "host": "ws-syn-01", "scenario": "Malware signature match on endpoint",
         "severity": "critical"},
        summary="[synthetic] Malware signature match on endpoint", host="ws-syn-01",
    )
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["title"] == "alert"
    assert row["summary"] == "[synthetic] Malware signature match on endpoint"
    assert row["device"] == "ws-syn-01"
    assert row["vendor_links"] == [] and row["vendor_device_ref"] is None
    # With NO stored summary the label is still better than nothing.
    _store_legacy_row({"synthetic": True, "host": "ws-syn-02"}, host="ws-syn-02",
                      received_at="2026-09-21T15:00:00.000Z")
    (bare, _) = client.get(_FEED, cookies=cookies).json()["items"]
    assert bare["title"] == "Datto alert"


# (Malformed JSON cannot be stored at all: events.db has a JSON expression index.)
@pytest.mark.parametrize("payload", ["[1, 2]", '"text"', "null", "{}", '{"alertContext": 7}'])
def test_an_odd_stored_payload_never_blanks_or_breaks_the_feed(datto, payload):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _create_instance(client, cookies)
    _store_legacy_row(payload)
    _store_legacy_row(api_alert(COMP_SCRIPT), received_at="2026-09-21T15:00:00.000Z")

    r = client.get(_FEED, cookies=cookies)
    assert r.status_code == 200, r.text
    newer, odd = r.json()["items"]
    assert newer["title"].startswith("Component monitor — Backup job")
    assert odd["title"] in ("alert", "Datto alert on WS-EXAMPLE-01", "Datto alert")
    assert odd["vendor_links"] == [] and odd["vendor_device_ref"] is None


def test_no_link_when_the_api_url_is_not_in_the_documented_form(datto):
    """fake_datto's API URL is a lab host: nothing can be derived, so there is
    NO link — never a guessed one. The row is still readable."""
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, cookies, creds=CREDS))
    _store_legacy_row(api_alert(EVENTLOG))
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["title"].startswith("Event log · Security 4625")
    assert row["vendor_links"] == [] and row["vendor_device_ref"] is None


def test_no_link_without_an_enabled_instance(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _store_legacy_row(api_alert(EVENTLOG))
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["title"].startswith("Event log") and row["vendor_links"] == []
    assert row["vendor_device_ref"] is None


def test_no_device_ref_when_the_alerts_site_is_not_mapped_to_the_rows_client(datto):
    """A reference is only offered where the click could succeed: the
    resolver refuses a device whose site does not map to the tenant."""
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies)
    _store_legacy_row(api_alert(EVENTLOG))
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert len(row["vendor_links"]) == 1 and row["vendor_device_ref"] is None
    client_provisioning.create_client("globex", "Globex")
    _map_site(iid, slug="globex")
    (row,) = [r for r in client.get(_FEED, cookies=cookies).json()["items"]
              if r["client_slug"] == "acme"]
    assert row["vendor_device_ref"] is None
    _map_site(iid)
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["vendor_device_ref"]["client_slug"] == "acme"


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

def test_a_viewer_never_receives_a_vendor_link(datto):
    client = datto
    admin_cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, admin_cookies))
    _store_legacy_row(api_alert(EVENTLOG))
    payload = api_alert(EVENTLOG)
    request = SimpleNamespace(app=client.app)

    viewer = client.provision_operator("bob", "password1234567", athena_role="viewer")
    analyst = client.provision_operator("carol", "password1234567", athena_role="analyst")

    # The feed itself is analyst+ …
    assert client.get(_FEED, cookies=client.login(viewer)).status_code == 403
    assert client.get(_DEVICES, cookies=client.login(viewer)).status_code == 403
    # … and the one link resolver every endpoint uses refuses a viewer.
    for_viewer = VendorLinkResolver(request, operator_id=viewer["id"])
    assert for_viewer.links(source="datto", client_slug="acme", payload=payload) == []
    assert for_viewer.device_ref(
        source="datto", client_slug="acme", event_id=1, payload=payload,
    ) is None
    assert for_viewer.linkable_sources() == set()

    for_analyst = VendorLinkResolver(request, operator_id=analyst["id"])
    assert [l.kind for l in for_analyst.links(
        source="datto", client_slug="acme", payload=payload,
    )] == ["alert"]
    assert for_analyst.device_ref(
        source="datto", client_slug="acme", event_id=1, payload=payload,
    ) is not None
    rows = client.get(_FEED, cookies=client.login(analyst)).json()["items"]
    assert len(rows[0]["vendor_links"]) == 1 and rows[0]["vendor_device_ref"]


# ---------------------------------------------------------------------------
# Devices needing attention → "open"
# ---------------------------------------------------------------------------

def test_devices_attention_open_target(datto):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    _map_site(_create_instance(client, cookies))
    # Stored LAST but occurred FIRST: "most recent" is by vendor time.
    newest = _store_legacy_row(api_alert(COMP_SCRIPT), received_at=now)
    _store_legacy_row(
        api_alert(EVENTLOG),
        received_at=(datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
    )
    _store_legacy_row({"x": 1}, source="wazuh", event_type="auth.failure",
                      host="web-01", received_at=now)
    # A host whose Datto events carry no device uid: nothing to open.
    _store_legacy_row({"alertUid": "a-2", "siteUid": "site-uid-0001"},
                      host="WS-EXAMPLE-02", received_at=now)

    r = client.get(_DEVICES, cookies=cookies)
    assert r.status_code == 200, r.text
    by_host = {d["host"]: d for d in r.json()["items"]}
    # Rows key on a HOST NAME; the reference names the host's most recent
    # link-capable event, whose stored payload holds the vendor's device uid.
    assert by_host["WS-EXAMPLE-01"]["vendor_device_ref"] == {
        "vendor": "datto", "label": "Open device in Datto RMM",
        "client_slug": "acme", "event_id": newest,
    }
    assert by_host["web-01"]["vendor_device_ref"] is None
    assert by_host["WS-EXAMPLE-02"]["vendor_device_ref"] is None
    assert "/device/" not in r.text
    assert not [c for c in client.datto_transport.calls if "/device/" in c[1]]


# ---------------------------------------------------------------------------
# Admin settings: portal base + path templates
# ---------------------------------------------------------------------------

def _settings_url(instance_id: int) -> str:
    return f"/api/v1/integrations/datto/{instance_id}/vendor-links"


def test_settings_show_what_is_in_use(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies)
    r = client.get(_settings_url(iid), cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["derived_portal_base_url"] == body["portal_base_url"] == PORTAL
    assert body["alert_path_template"] == "/alert/{alert_uid}"
    # No device path template exists: device pages are looked up on click.
    assert not [k for k in body if "device_path" in k or k == "sample_device_url"]
    assert body["device_links_resolved"] is True
    assert body["paths_verified"] is True and body["links_enabled"] is True
    assert body["overrides"] == {} and body["problem"] is None
    assert body["sample_alert_url"] == f"{PORTAL}/alert/ALERT-UID"
    assert body["placeholders"] == ["{alert_uid}", "{device_uid}", "{site_uid}"]
    for secret in SECRETS:
        assert secret not in r.text


def test_settings_say_why_there_are_no_links(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies, creds=CREDS)
    body = client.get(_settings_url(iid), cookies=cookies).json()
    assert body["links_enabled"] is False and body["portal_base_url"] is None
    assert "could not be derived" in body["problem"]
    assert body["sample_alert_url"] is None and body["device_links_resolved"] is False


def test_an_override_changes_the_links_and_is_audited(datto):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies, creds=CREDS)      # nothing derivable
    _store_legacy_row(api_alert(EVENTLOG))

    r = client.put(_settings_url(iid), cookies=cookies, json={
        "portal_base_url": f"{PORTAL}/",
        "alert_path_template": "/alerts/{alert_uid}/details",
    })
    assert r.status_code == 200, r.text
    assert r.json()["overrides"] == {
        "portal_base_url": PORTAL,
        "alert_path_template": "/alerts/{alert_uid}/details",
    }
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert [l["url"] for l in row["vendor_links"]] == [f"{PORTAL}/alerts/{ALERT_UID}/details"]

    audit = sqlite3.connect(paths.global_audit_db_path())
    try:
        actions = [a[0] for a in audit.execute("SELECT action FROM audit_log").fetchall()]
    finally:
        audit.close()
    assert "adapter_vendor_links_update" in actions

    # Blank everything = back to defaults (here: no base → no links).
    assert client.put(_settings_url(iid), cookies=cookies, json={}).json()["overrides"] == {}
    (row,) = client.get(_FEED, cookies=cookies).json()["items"]
    assert row["vendor_links"] == []


@pytest.mark.parametrize("body", [
    {"portal_base_url": "https://portal.example.test"},
    {"portal_base_url": "http://exampleplat.rmm.datto.com"},
    {"alert_path_template": "/alert/{alert_uid}?token=x"},
    {"alert_path_template": "/alert"},
    {"device_path_template": "/device/{device_uid}"},      # not a setting (any more)
])
def test_a_bad_override_is_refused_and_nothing_is_stored(datto, body):
    client = datto
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, cookies)
    r = client.put(_settings_url(iid), cookies=cookies, json=body)
    assert r.status_code == 422, r.text
    assert client.get(_settings_url(iid), cookies=cookies).json()["overrides"] == {}


def test_settings_are_admin_only(datto):
    client = datto
    admin_cookies = client.login(client.provision_operator("alice", "password1234567"))
    iid = _create_instance(client, admin_cookies)
    analyst = client.login(
        client.provision_operator("carol", "password1234567", athena_role="analyst")
    )
    assert client.get(_settings_url(iid), cookies=analyst).status_code == 403
    assert client.put(_settings_url(iid), cookies=analyst, json={}).status_code == 403
    assert client.get(_settings_url(9999), cookies=admin_cookies).status_code == 404
    assert client.get(
        "/api/v1/integrations/stub-adapter/1/vendor-links", cookies=admin_cookies,
    ).status_code == 404
