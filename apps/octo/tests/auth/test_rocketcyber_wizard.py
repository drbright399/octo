"""RocketCyber through the real HTTP routes — catalog, Test connection, save,
customer discovery — with the REAL adapter and client (only the vendor socket
is fake: adapters/rocketcyber/tests/fake_rocketcyber.py, built from the live
API's answers).

The defect: the wizard demanded an account ID and an API URL, and the adapter
behind it read paths that do not exist — onboarding could only ever fail (or,
with a stubbed client, "pass" and then 404 on every poll).

  - the catalog asks for ONE required field (the API key)
  - Test connection passes only after real reads; failures are actionable
  - save refuses what Test connection refuses, persists nothing then
  - the mapping picker lists the provider account and every customer
  - no API key in any response, log line or audit row
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.rocketcyber.poller import RocketCyberPoller
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    ACCOUNT_PATH,
    API_KEY,
    API_URL,
    INCIDENTS_PATH,
    OLD_CREDS,
    PROVIDER_ID,
    SECRETS,
    FakeRocketCyberTransport,
    incident,
    real_client,
    resolved,
    rocketcyber_adapter_class,
)
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import tenant_map, vendor_contact, vendor_tenants
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

_SMOKE = "/api/v1/admin/adapters/rocketcyber/smoke-test"
_CREATE = "/api/v1/admin/adapters/rocketcyber/instances"
# What the new wizard sends: the key, the two optional fields left blank —
# except the URL, which points at the fake (the default is the real vendor).
KEY_ONLY = {"RC_API_KEY": API_KEY, "RC_API_URL": API_URL, "RC_ACCOUNT_ID": ""}


def _tenants_url(instance_id: int) -> str:
    return f"/api/v1/admin/adapters/instances/{instance_id}/vendor-tenants"


@pytest.fixture
def rc(instance_endpoint_client):  # noqa: F811
    """(client, cookies, transport) with the real RocketCyber adapter."""
    vendor_contact.reset()
    vendor_tenants.reset()
    client = instance_endpoint_client
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    client.app.state.adapter_registry.register_adapter_class(
        rocketcyber_adapter_class(transport)
    )
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    yield client, cookies, transport
    client.app.state.instance_manager.stop_all_running()
    vendor_contact.reset()
    vendor_tenants.reset()


def _rows() -> list[tuple]:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        return reg.execute(
            "SELECT id, vendor_slug, status, last_test_at FROM adapter_instances"
        ).fetchall()
    finally:
        reg.close()


def _audit_text() -> str:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return "\n".join(
            " ".join(str(c) for c in row)
            for row in conn.execute("SELECT * FROM audit_log").fetchall()
        )
    finally:
        conn.close()


def _no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def test_the_catalog_asks_for_one_required_field(rc):
    # The catalog entry exactly as GET /catalog serialises it (this fixture's
    # registry also holds a bare stub adapter the full route cannot render).
    from apps.octo.api.routers.adapters import _adapter_to_catalog_entry

    _client, _cookies, transport = rc
    entry = _adapter_to_catalog_entry(rocketcyber_adapter_class(transport)).model_dump()
    assert entry["vendor_slug"] == "rocketcyber"
    fields = {f["name"]: f for f in entry["credential_shape"]}
    assert {n for n, f in fields.items() if f["required"]} == {"RC_API_KEY"}
    assert fields["RC_API_KEY"]["kind"] == "password"
    assert entry["delivery_mode"] == "poll"
    assert entry["onboarding"]["webhook_url"] is None
    assert entry["onboarding"]["webhook_url_problem"] is None
    assert len(entry["onboarding"]["steps"]) == 4
    assert entry["tenant_mapping_shape"]["tenant_noun"] == "customer"


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

def test_test_connection_with_only_the_key_passes_after_real_reads(rc, caplog):
    client, cookies, transport = rc
    with caplog.at_level(logging.DEBUG):
        r = client.post(_SMOKE, json={"credentials": KEY_ONLY}, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True, body
    assert f"provider account {PROVIDER_ID} (“Example MSP”, read from the API key)" in body["message"]
    # The account, its customers, and page 1 of each read a poll cycle makes.
    assert transport.count(ACCOUNT_PATH) == 2 and transport.count(INCIDENTS_PATH) == 3
    assert _rows() == []                       # a test never persists anything
    _no_secret(r.text, caplog.text, _audit_text())


def test_test_connection_with_a_bad_key_says_what_to_check(rc):
    client, cookies, transport = rc
    transport.key = "the-vendor-wants-a-different-key"
    r = client.post(_SMOKE, json={"credentials": KEY_ONLY}, cookies=cookies)
    body = r.json()
    assert body["ok"] is False
    assert body["message"].startswith("RocketCyber rejected the API key (HTTP 401)")
    _no_secret(r.text)


def test_test_connection_that_cannot_tell_the_account_asks_for_the_override(rc):
    client, cookies, transport = rc
    transport.provider["accountPath"] = None
    r = client.post(_SMOKE, json={"credentials": KEY_ONLY}, cookies=cookies)
    assert r.json()["ok"] is False and "Provider account ID" in r.json()["message"]
    fixed = client.post(
        _SMOKE, json={"credentials": {**KEY_ONLY, "RC_ACCOUNT_ID": str(PROVIDER_ID)}},
        cookies=cookies,
    )
    assert fixed.json()["ok"] is True, fixed.json()


# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------

def test_save_with_only_the_key_creates_a_running_instance(rc):
    client, cookies, _transport = rc
    r = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["instance"]["status"] == "running" and body["instance"]["last_test_at"]
    assert "incidents are readable" in body["smoke_test_message"]
    assert "generated_webhook_secret" not in body or body["generated_webhook_secret"] is None
    ((_, slug, _status, last_test_at),) = _rows()
    assert slug == "rocketcyber" and last_test_at
    _no_secret(r.text, _audit_text())


def test_save_is_refused_when_test_connection_would_fail(rc):
    client, cookies, transport = rc
    transport.forbid_incidents = True
    r = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    assert r.status_code == 400
    assert r.json()["code"] == "SMOKE_TEST_FAILED"
    assert r.json()["message"].startswith("Not saved — RocketCyber accepted the API key")
    assert _rows() == []
    _no_secret(r.text)


def test_save_with_what_the_old_wizard_collected_still_works(rc):
    client, cookies, transport = rc
    r = client.post(_CREATE, json={"credentials": OLD_CREDS}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert transport.incident_queries()[0]["accountId"] == str(PROVIDER_ID)


# ---------------------------------------------------------------------------
# Customer discovery (the mapping picker)
# ---------------------------------------------------------------------------

def test_the_mapping_picker_lists_the_provider_and_every_customer(rc, caplog):
    client, cookies, transport = rc
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()
    with caplog.at_level(logging.DEBUG):
        r = client.post(_tenants_url(iid), cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["supported"] is True and body["truncated"] is False
    assert body["tenants"] == [           # sorted by label for the picker
        {"id": "2001", "label": "Acme Corp"},
        {"id": "2002", "label": "Example Bakery"},
        {"id": "2003", "label": "Example Hardware (inactive)"},
        {"id": str(PROVIDER_ID), "label": "Example MSP (provider account)"},
    ]
    assert body["tenant_mapping_shape"]["vendor_tenant_id_field"] == "accountId"
    # Customer names go to the admin's browser — never to a log line.
    assert "Example Bakery" not in caplog.text
    _no_secret(r.text, caplog.text, _audit_text())


def test_a_discovery_failure_is_an_actionable_error_not_an_empty_list(rc):
    client, cookies, transport = rc
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()
    transport.forbid_details = True
    r = client.post(_tenants_url(iid), cookies=cookies)
    assert r.status_code >= 400
    assert "refused to return data" in r.json()["message"]
    _no_secret(r.text)


# ---------------------------------------------------------------------------
# What the stored rows look like on the dashboard
# ---------------------------------------------------------------------------

def test_stored_incidents_are_presented_on_the_dashboard_without_a_guessed_link(rc):
    client, cookies, transport = rc
    transport.incidents = []        # the instance's own first poll finds nothing
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    client.app.state.instance_manager.stop_all_running()
    client_provisioning.create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(iid, [tenant_map.TenantMapping("2001", "acme-corp")])
    transport.incidents = [incident(1, psa_id="T5"), resolved(incident(2))]
    poller = RocketCyberPoller(
        adapter=rocketcyber_adapter_class(transport)(), client=real_client(transport),
        sink=tenant_map.MappingIngestSink(SqliteIngestSink(publish_to_stream=False), iid),
        default_tenant_slug="_unmapped", instance_id=iid,
    )
    asyncio.run(poller._drain_once())

    # The DEFAULT feed (min_severity=medium): a closure shows next to the
    # open rows — otherwise a closed incident keeps looking live there.
    r = client.get("/api/v1/dashboard/recent-events", cookies=cookies)
    assert r.status_code == 200, r.text
    rows = {row["title"]: row for row in r.json()["items"] if row["source"] == "rocketcyber"}
    open_row = rows["RocketCyber · Suspicious PowerShell execution 1"]
    closed = rows["RocketCyber · Suspicious PowerShell execution 2 — resolved"]
    assert (open_row["severity"], closed["severity"]) == ("high", "medium")
    assert open_row["site"] == "Acme Corp" and open_row["device"] is None
    assert open_row["summary"].split("\n")[-1] == "Customer: Acme Corp · 1 event · PSA ticket T5"
    assert "Remediation: • Isolate the device." in open_row["summary"]
    # No documented portal URL exists: no link, never a guessed one.
    assert open_row["vendor_links"] == [] and open_row["vendor_device_ref"] is None
    _no_secret(r.text)


# ---------------------------------------------------------------------------
# The first import waits for the mapping step; saving it starts the import
# ---------------------------------------------------------------------------

def test_saving_the_tenant_mapping_nudges_the_instance_to_import_now(rc, monkeypatch):
    client, cookies, _transport = rc
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    manager = client.app.state.instance_manager
    manager.stop_all_running()
    nudged: list[int] = []
    monkeypatch.setattr(manager, "nudge", lambda instance_id: nudged.append(instance_id) or True)
    client_provisioning.create_client("acme-corp", "Acme Corp")
    r = client.put(
        f"/api/v1/integrations/rocketcyber/{iid}/mappings/tenants",
        json={"mappings": [{"vendor_tenant_id": "2001", "octo_client_slug": "acme-corp"}]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    assert nudged == [iid]


def test_the_integration_card_shows_the_first_import_wait_until_the_mapping_is_saved(rc):
    """v0.11 R1: the first import of a new instance waits for the operator's
    customer mapping (at most `first_import_grace_sec`). GET /integrations
    says so — and until when — from the running adapter's health; saving the
    mapping ends the wait on the next cycle and the card goes quiet."""
    from datetime import datetime, timedelta

    client, cookies, transport = rc
    transport.incidents = [incident(1)]
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    assert created.status_code == 200, created.text
    iid = created.json()["instance"]["id"]
    adapter = client.app.state.instance_manager.running_adapter(iid)
    poller = adapter._poller           # the route runs off-loop: not started yet
    asyncio.run(poller._drain_once())  # one real cycle: reads, then holds
    assert poller.holding_first_import
    assert adapter.health().detail["waiting_for_tenant_mapping"] is True

    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["rocketcyber"]
    configured = datetime.fromisoformat(card["configured_at"].replace("Z", "+00:00"))
    until = datetime.fromisoformat(card["first_import_waiting_until"].replace("Z", "+00:00"))
    assert until - configured == timedelta(hours=1)
    # Nothing imported meanwhile (no tenant auto-created either).
    assert not (paths.client_dir("acme-corp") / "events.db").exists()

    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    r = client.put(
        f"/api/v1/integrations/rocketcyber/{iid}/mappings/tenants",
        json={"mappings": [{"vendor_tenant_id": "2001", "octo_client_slug": "acme-corp"}]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    asyncio.run(poller._drain_once())  # the cycle the save's nudge starts
    assert not poller.holding_first_import
    card = client.get("/api/v1/integrations", cookies=cookies).json()["instances"]["rocketcyber"]
    assert card["first_import_waiting_until"] is None
    conn = sqlite3.connect(paths.client_dir("acme-corp") / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    finally:
        conn.close()


def _waiting_card(client, cookies) -> object:
    return client.get("/api/v1/integrations", cookies=cookies).json()[
        "instances"]["rocketcyber"]["first_import_waiting_until"]


def test_the_wait_ends_on_a_saved_mapping_even_while_reads_fail(rc):
    """The mapping is saved while incident reads fail (wrong account / 403):
    the card must not keep saying "waiting for your customer mapping" —
    the save's nudge settles the wait before the read that fails."""
    from apps.octo.adapters.rocketcyber.client import RocketCyberForbiddenError

    client, cookies, transport = rc
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    poller = client.app.state.instance_manager.running_adapter(iid)._poller
    asyncio.run(poller._drain_once())
    assert _waiting_card(client, cookies) is not None
    transport.forbid_incidents = True
    client_provisioning.create_client("acme-corp", "Acme Corp", kind="client")
    r = client.put(
        f"/api/v1/integrations/rocketcyber/{iid}/mappings/tenants",
        json={"mappings": [{"vendor_tenant_id": "2001", "octo_client_slug": "acme-corp"}]},
        cookies=cookies,
    )
    assert r.status_code == 200, r.text
    with pytest.raises(RocketCyberForbiddenError):
        asyncio.run(poller._drain_once())
    assert not poller.holding_first_import
    assert _waiting_card(client, cookies) is None


def test_the_card_never_shows_a_wait_deadline_that_has_passed(rc):
    """Reads keep failing and nobody saves a mapping: once the deadline has
    passed the card stops promising "automatically at <past time>" — no
    successful poll needed."""
    from datetime import timedelta

    client, cookies, transport = rc
    created = client.post(_CREATE, json={"credentials": KEY_ONLY}, cookies=cookies)
    iid = created.json()["instance"]["id"]
    poller = client.app.state.instance_manager.running_adapter(iid)._poller
    asyncio.run(poller._drain_once())
    until = poller._hold_until
    assert until is not None and _waiting_card(client, cookies) is not None
    transport.forbid_incidents = True
    poller._now = lambda: until + timedelta(hours=2)      # the injected clock
    assert not poller.holding_first_import
    assert _waiting_card(client, cookies) is None
