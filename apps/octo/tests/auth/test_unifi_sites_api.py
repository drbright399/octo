"""UniFi through the real HTTP routes, real sign-in, the REAL adapter / client
/ limiter / poller — only the UniFi socket is fake (fake_unifi.py).

Pinned:
  * the site mapping panel (GET/PUT /integrations/unifi/{id}/sites): admin+
    only, local state only (never a UniFi call), every site keyed
    (hostId, siteId) — three consoles with ONE site id are three rows — with
    its console, LOCATION and WAN; a same-name suggestion on its row only (no
    bulk accept; PUT takes no match source, everything is 'manual'); ignore;
    refusals; audit rows; a retired local-controller mapping kept as it is;
  * the card (/integrations): site counts, the no-deadline wait;
  * the alerts feed: a stored UniFi IPS alert reads with its headline.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.unifi import limiter as lim
from apps.octo.adapters.unifi.tests.fake_unifi import (
    CREDS,
    HOST_A,
    SCOPE_A,
    SCOPE_B,
    SCOPE_C,
    SITE_DEFAULT,
    FakeClock,
    FakeUniFiTransport,
    fake_limiter,
    ips_event,
    lan,
    standard_fleet,
    unifi_adapter_class,
)
from apps.octo.client_provisioning import create_client
from apps.octo.instances import ignored_tenants, tenant_map, vendor_contact, vendor_tenants
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_dashboard_throughput import _login

PW = "pw1234567890"
A, B = "acme-corp", "example-bakery"
# The IPS event's LAN end: the fixture site's address (fake_unifi.lan, RFC 1918
# because the catalogue names the device by it, catalogue.is_local).
LAN_IP = lan(37)


@pytest.fixture
def uf(auth_client, auth_data_root, monkeypatch, tmp_path):
    from apps.octo.credentials import ensure_key_file
    from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.instances import InstanceManager, create_instance

    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "cred-key.env"))
    ensure_key_file()
    lim.reset_limiters()
    vendor_tenants.reset()
    vendor_contact.reset()
    clock = FakeClock(datetime.now(timezone.utc))
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)
    fake_limiter(clock)
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(unifi_adapter_class(transport, clock))
    app = auth_client.app
    app.state.adapter_registry = registry
    app.state.instance_manager = InstanceManager(adapter_registry=registry)
    create_client(A, "Acme Corp")
    create_client(B, "Example Bakery")
    record = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                             credentials_dict=dict(CREDS), instance_config={})
    app.state.instance_manager.start_instance(record)
    yield auth_client, transport, clock, record
    app.state.instance_manager.stop_all_running()
    lim.reset_limiters()
    vendor_tenants.reset()
    vendor_contact.reset()


def _op(client, name: str, role: str) -> dict:
    op = client.provision_operator(name, PW, role=role, athena_role=role)
    _login(client, op)
    return op


def _audit(action: str) -> list[dict]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return [json.loads(r[0]) for r in conn.execute(
            "SELECT after_state FROM audit_log WHERE action = ? ORDER BY id", (action,))]
    finally:
        conn.close()


def _url(record) -> str:
    return f"/api/v1/integrations/unifi/{record.id}/sites"


def _poller(client, record):
    return client.app.state.instance_manager.running_adapter(record.id).poller


def test_the_panel_is_admin_only_and_never_calls_unifi(uf):
    client, transport, _clock, record = uf
    for role in ("viewer", "analyst"):
        _op(client, f"u-{role}", role)
        assert client.get(_url(record)).status_code == 403
        assert client.put(_url(record), json={}).status_code == 403
    _op(client, "admin1", "admin")
    r = client.get(_url(record))
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.json()["discovered"] is False and r.json()["sites"] == []
    assert transport.calls == []


def test_every_site_with_its_console_location_and_a_row_suggestion(uf):
    client, transport, _clock, record = uf
    _op(client, "admin1", "admin")
    _poller(client, record).run_cycle()                        # the poller's fleet poll
    calls = len(transport.calls)
    body = client.get(_url(record)).json()
    assert len(transport.calls) == calls                        # the panel never calls
    by = {s["scope"]: s for s in body["sites"]}
    assert set(by) == {SCOPE_A, SCOPE_B, SCOPE_C}               # ONE site id, three sites
    a = by[SCOPE_A]
    assert (a["host_id"], a["site_id"], a["name"], a["console_name"]) == (
        HOST_A, SITE_DEFAULT, "Acme Corp", "acme-udm")
    assert a["location_text"] == "100 Example St, Springfield"
    assert a["timezone"] == "America/Chicago"
    assert a["wans"] == [{"wan": "WAN", "external_ip": "203.0.113.129", "isp": "Example ISP",
                          "asn": 64500, "shared_external": False}]
    assert a["suggestion"] == {"tenant_slug": A, "tenant_name": "Acme Corp", "rule": "same-name"}
    assert by[SCOPE_B]["suggestion"]["tenant_slug"] == B
    assert by[SCOPE_C]["suggestion"] is None                    # "Default": no client
    assert body["counts"] == {"known": 3, "mapped": 0, "ignored": 0, "unmapped": 3,
                              "gateways_offline": 0, "problems": 0}
    assert "bulk" not in json.dumps(body)


def test_save_maps_and_ignores_as_the_operators_decision(uf):
    client, transport, _clock, record = uf
    _op(client, "admin1", "admin")
    _poller(client, record).run_cycle()
    r = client.put(_url(record), json={
        "mappings": [{"scope": SCOPE_A, "tenant_slug": A}, {"scope": SCOPE_B, "tenant_slug": A}],
        "ignored": [SCOPE_C],
    })
    assert r.status_code == 200, r.text
    stored = {m.vendor_tenant_id: (m.octo_client_slug, m.vendor_tenant_label, m.match_source)
              for m in tenant_map.get_mappings(record.id)}
    assert stored == {SCOPE_A: (A, "Acme Corp", "manual"),       # many sites → one tenant
                      SCOPE_B: (A, "Example Bakery", "manual")}
    assert ignored_tenants.ignored_ids(record.id) == {SCOPE_C}
    body = r.json()
    assert body["counts"]["mapped"] == 2 and body["counts"]["ignored"] == 1
    assert body["counts"]["unmapped"] == 0
    [replace] = _audit("adapter_tenant_map_replace")
    assert replace["mappings"] == {SCOPE_A: A, SCOPE_B: A}
    [ignore] = _audit("adapter_vendor_tenants_ignore")
    assert ignore["ignored"] == [SCOPE_C]
    # A match source in the body is not even read: no bulk name accept exists.
    r = client.put(_url(record), json={"mappings": [
        {"scope": SCOPE_A, "tenant_slug": A, "match_source": "auto-name"}]})
    assert r.status_code == 200
    assert tenant_map.get_mappings(record.id)[0].match_source == "manual"


@pytest.mark.parametrize("body,needle", [
    ({"mappings": [{"scope": SCOPE_A, "tenant_slug": A}], "ignored": [SCOPE_A]},
     "both mapped and ignored"),
    ({"mappings": [{"scope": SITE_DEFAULT, "tenant_slug": A}]}, "is not a UniFi site"),
    ({"mappings": [{"scope": "../x/y", "tenant_slug": A}]}, "is not a UniFi site"),
    ({"mappings": [{"scope": SCOPE_A, "tenant_slug": "no-such"}]}, "does not exist"),
    ({"mappings": [{"scope": SCOPE_A, "tenant_slug": A},
                   {"scope": SCOPE_A, "tenant_slug": B}]}, "listed twice"),
    ({"ignored": ["a b"]}, "is not a UniFi site"),
])
def test_save_refuses_what_can_never_work(uf, body, needle):
    client, _t, _clock, record = uf
    _op(client, "admin1", "admin")
    r = client.put(_url(record), json=body)
    assert r.status_code == 422 and needle in r.json()["message"], r.text
    assert tenant_map.get_mappings(record.id) == []
    assert _audit("adapter_vendor_tenants_ignore") == []


def test_a_retired_local_controller_mapping_is_listed_and_kept(uf):
    client, _t, _clock, record = uf
    _op(client, "admin1", "admin")
    tenant_map.set_mappings(record.id, [TenantMapping(SITE_DEFAULT, A, "old site", "manual")])
    body = client.get(_url(record)).json()
    assert body["legacy"] == [{"vendor_tenant_id": SITE_DEFAULT, "tenant_slug": A,
                               "tenant_name": "Acme Corp"}]
    assert body["sites"] == []
    r = client.put(_url(record), json={"mappings": [{"scope": SCOPE_B, "tenant_slug": B}]})
    assert r.status_code == 200, r.text
    assert {m.vendor_tenant_id for m in tenant_map.get_mappings(record.id)} == {SITE_DEFAULT, SCOPE_B}


def test_the_card_counts_and_the_alerts_feed(uf):
    client, transport, clock, record = uf
    _op(client, "admin1", "admin")
    card = client.get("/api/v1/integrations").json()["instances"]["unifi"]
    assert card["waiting_for_tenant_mapping"] is True and card["first_import_waiting_until"] is None
    assert card["sites"]["mapped"] == 0 and card["profiles"] is None
    transport.site(HOST_A).log.append(ips_event(clock.now() - timedelta(minutes=4), eid="ips-1",
                                                lan_ip=LAN_IP))
    client.put(_url(record), json={"mappings": [{"scope": SCOPE_A, "tenant_slug": A}],
                                   "ignored": [SCOPE_C]})
    _poller(client, record).run_cycle()
    card = client.get("/api/v1/integrations").json()["instances"]["unifi"]
    assert card["waiting_for_tenant_mapping"] is False
    assert {k: card["sites"][k] for k in ("known", "mapped", "ignored", "unmapped", "consoles")} == {
        "known": 3, "mapped": 1, "ignored": 1, "unmapped": 1, "consoles": 3}
    # The alert reads in the feed with its headline (the stored summary).
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        (summary, etype) = conn.execute("SELECT summary, event_type FROM events").fetchone()
    finally:
        conn.close()
    assert etype == "unifi.ips_threat"
    assert summary == f"UniFi IPS blocked ET MALWARE Example Beacon — {LAN_IP}"
