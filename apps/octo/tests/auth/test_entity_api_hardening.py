"""Entity API hardening (review round 2), through the real routes and sign-in:

  * shadow: an analyst's POST /resolve gets the hidden shape (as GET does);
  * an alert of a kind entity resolution never reads is `not_applicable`;
  * an operator-asserted egress another UniFi network of the fleet also uses
    (the running poller's last fleet snapshot, real poller on the fake
    cloud) is flagged `shared_external` and never corroborates;
  * every decision and the switch are audited BEFORE they are written — an
    audit failure leaves nothing changed;
  * an admin renames a site, and the vendor's "Default" never replaces it;
  * the review cards carry the profile's name and the site's location;
  * the tenant-mapping GET says which rows really need re-review (an
    auto-created tenant's own mapping never does)."""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from apps.octo.entity import switch
from apps.octo.entity.db import TenantDB
from apps.octo.tests.auth.test_entity_api import (  # noqa: F401 — the fixture
    A,
    SCOPE,
    T0,
    _audit,
    _event,
    _op,
    ent,
    iso,
)


def test_shadow_post_resolve_shows_nothing_to_an_analyst_and_all_to_an_admin(ent):  # noqa: F811
    client, _uf, _nd = ent
    switch.set_mode(A, "shadow")
    eid = _event()
    _op(client, "ana-s", "analyst")
    r = client.post(f"/api/v1/entity/{A}/events/{eid}/resolve")
    assert r.status_code == 200
    body = r.json()
    assert body["visible"] is False and body["resolved"] is True
    assert body["where"] is None and body["candidates"] == [] and body["why"] == []
    _op(client, "adm-s", "admin")
    body = client.post(f"/api/v1/entity/{A}/events/{eid}/resolve").json()
    assert body["visible"] is True and body["where"]["label"] == "Site A"


def test_an_alert_entity_resolution_never_reads_is_not_applicable(ent):  # noqa: F811
    from apps.octo.entity.tests.conftest import store_event

    client, _uf, _nd = ent
    _op(client, "ana-na", "analyst")
    eid = store_event(A, "datto", "datto.alert", {"vendor_event_id": "dt-1", "alert": {
        "alertUid": "dt-1"}}, iso(T0))
    r = client.get(f"/api/v1/entity/{A}/events/{eid}/resolution")
    assert r.status_code == 200
    assert (r.json()["reason"], r.json()["visible"], r.json()["resolved"]) == \
        ("not_applicable", False, False)
    assert client.post(f"/api/v1/entity/{A}/events/{eid}/resolve").status_code == 404
    assert _audit("entity_resolve") == []                  # nothing was asked of the resolver


def _running_unifi(client, uf, monkeypatch):
    """The REAL UniFi poller on the fake cloud, its fleet read once, as the
    running adapter of the UniFi instance (the instance manager's lookup)."""
    from apps.octo.adapters.unifi import UniFiSourceAdapter
    from apps.octo.adapters.unifi import limiter as lim
    from apps.octo.adapters.unifi.feed import NullConsumer
    from apps.octo.adapters.unifi.poller import UniFiPoller
    from apps.octo.adapters.unifi.tests.fake_unifi import (
        FakeClock,
        FakeUniFiTransport,
        client_factory,
        fake_limiter,
        real_client,
        standard_fleet,
    )
    from apps.octo.ingest import SqliteIngestSink

    lim.reset_limiters()
    clock = FakeClock()
    transport = FakeUniFiTransport(clock)
    standard_fleet(transport)                    # B's WAN: 198.51.100.20 (not acme-corp's)
    poller = UniFiPoller(adapter=UniFiSourceAdapter(client_factory=client_factory(transport)),
                         client=real_client(transport, limiter=fake_limiter(clock)),
                         sink=SqliteIngestSink(publish_to_stream=False), instance_id=uf.id,
                         now=clock.now, consumer=NullConsumer())
    poller._mapped_sites = lambda: {}            # read the fleet only, poll no site
    poller.run_cycle()
    assert poller.fleet_view()
    manager = SimpleNamespace(
        running_adapter=lambda iid: SimpleNamespace(poller=poller) if iid == uf.id else None,
        nudge=lambda iid: None)
    monkeypatch.setattr(client.app.state, "instance_manager", manager, raising=False)
    return poller


def test_an_asserted_egress_another_network_uses_is_shared_external(ent, monkeypatch):  # noqa: F811
    from apps.octo.entity import resolver as rv
    from apps.octo.entity.tests.conftest import nextdns_block, store_event

    client, uf, _nd = ent
    _running_unifi(client, uf, monkeypatch)
    _op(client, "adm-e", "admin")
    site = client.post(f"/api/v1/entity/{A}/sites", json={
        "label": "Warehouse", "anchor": "nextdns", "vendor": "nextdns",
        "vendor_scope_id": "abc123", "reason": "second office, no UniFi"}).json()["site_id"]
    shared = client.post(f"/api/v1/entity/{A}/sites/{site}/egress",
                         json={"addr": "198.51.100.20", "reason": "the landlord's line"})
    assert shared.status_code == 200 and shared.json()["flags"] == ["shared_external"]
    own = client.post(f"/api/v1/entity/{A}/sites/{site}/egress",
                      json={"addr": "203.0.113.129", "reason": "the office line"})
    assert own.json()["flags"] == ["shared_in_tenant"]     # this client's own UniFi site
    alone = client.post(f"/api/v1/entity/{A}/sites/{site}/egress",
                        json={"addr": "198.51.100.44", "reason": "a static address"})
    assert alone.json()["flags"] == []
    # A block from the shared address (after the assertion and the site's
    # link began): the profile's site by POLICY only — never "located +
    # policy, 99".
    from datetime import datetime, timedelta, timezone

    at = datetime.now(timezone.utc) + timedelta(seconds=5)
    eid = store_event(A, "nextdns", "nextdns.security_block",
                      nextdns_block(at, client_ip="198.51.100.20", vid="shared"), iso(at))
    row = rv.Resolver.for_tenant(A, now=lambda: at + timedelta(minutes=40)).resolve_event(eid)
    assert row["site_id"] == site and row["site_basis"] == "policy"
    assert "location_unverified" in row["flags"]


def test_an_audit_failure_leaves_every_decision_unwritten(ent, monkeypatch):  # noqa: F811
    from apps.octo.api.routers import entity as entity_router
    from apps.octo.entity import sites as st

    client, _uf, nd = ent
    with TenantDB.for_tenant(A).write() as conn:
        site_id = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
        p = st.propose(conn, site_id=site_id, vendor="nextdns", instance_id=nd.id,
                       scope_id="abc123", state="suggested", score=85, rule_id="L-EGRESS",
                       rule_version=1, evidence={}, now=iso(T0))
    _op(client, "adm-a", "admin")

    def broken(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(entity_router.audit, "append", broken)
    for call in (
        lambda: client.post(f"/api/v1/entity/{A}/links/site/{p.ref_id}/confirm",
                            json={"reason": "it is"}),
        lambda: client.post(f"/api/v1/entity/{A}/links/site/{p.ref_id}/reject",
                            json={"reason": "it is not"}),
        lambda: client.put(f"/api/v1/entity/{A}/mode", json={"mode": "off", "reason": "pause"}),
        lambda: client.post(f"/api/v1/entity/{A}/sites/{site_id}",
                            json={"label": "Front office", "reason": "two offices"}),
    ):
        with pytest.raises(sqlite3.OperationalError):
            call()
    with TenantDB.for_tenant(A).connect() as conn:
        assert conn.execute("SELECT state FROM site_vendor_ref WHERE id = ?",
                            (p.ref_id,)).fetchone()[0] == "suggested"
        assert conn.execute("SELECT COUNT(*) FROM link_suppression").fetchone()[0] == 0
        assert conn.execute("SELECT label FROM site WHERE site_id = ?",
                            (site_id,)).fetchone()[0] == "Site A"
    assert switch.mode(A, fresh=True) == "on"


def test_an_admin_renames_a_site_and_the_vendors_default_never_replaces_it(ent):  # noqa: F811
    from apps.octo.entity.feeders.unifi import UniFiEntityFeeder

    client, _uf, _nd = ent
    with TenantDB.for_tenant(A).connect() as conn:
        site_id = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
    _op(client, "ana-r", "analyst")
    assert client.post(f"/api/v1/entity/{A}/sites/{site_id}",
                       json={"label": "Front office", "reason": "two offices"}).status_code == 403
    _op(client, "adm-r", "admin")
    r = client.post(f"/api/v1/entity/{A}/sites/{site_id}",
                    json={"label": "  Front   office ", "reason": "two offices"})
    assert r.status_code == 200 and r.json()["label"] == "Front office"
    (row,) = _audit("entity_site_rename")
    assert row["client_slug"] == A
    UniFiEntityFeeder().on_site_report(A, SCOPE, {
        "polled_at": iso(T0.replace(minute=25)), "name": "Default", "report_fresh": True,
        "host_connected": True, "gateway_online": True,
        "wans": [{"wan": "WAN", "external_ip": "203.0.113.129", "nat_kind": "direct"}]})
    sites_ = client.get(f"/api/v1/entity/{A}/sites").json()["sites"]
    assert [s["label"] for s in sites_] == ["Front office"]


def test_review_cards_name_the_profile_and_the_sites_location(ent):  # noqa: F811
    from apps.octo.entity import sites as st

    client, _uf, nd = ent
    with TenantDB.for_tenant(A).write() as conn:
        site_id = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
        conn.execute("UPDATE site SET geo_text = '100 Example St' WHERE site_id = ?", (site_id,))
        st.propose(conn, site_id=site_id, vendor="nextdns", instance_id=nd.id,
                   scope_id="abc123", state="suggested", score=85, rule_id="L-EGRESS",
                   rule_version=1, evidence={"coverage": {"share": 0.93, "queries": 1214,
                                                          "days_from_site": 6,
                                                          "days_with_data": 7}},
                   now=iso(T0))
    _op(client, "ana-v", "analyst")
    (card,) = client.get(f"/api/v1/entity/{A}/review").json()["sites"]
    assert (card["vendor_label"], card["site_location"]) == ("Site A office", "100 Example St")
    assert card["evidence"]["coverage"]["queries"] == 1214


def test_mapping_rows_say_which_really_need_review(ent):  # noqa: F811
    from apps.octo.client_provisioning import create_client
    from apps.octo.instances import create_instance, tenant_map
    from apps.octo.instances.tenant_map import TenantMapping

    client, _uf, _nd = ent
    from apps.octo.adapters.datto.tests.fake_datto import CREDS

    datto = create_instance(vendor_slug="datto", display_name="Datto RMM",
                            credentials_dict=dict(CREDS), instance_config={})
    # A tenant the Datto instance auto-created from its own site …
    create_client("example-clinic", "Example Clinic", origin="auto", kind="client",
                  created_by_instance_id=datto.id)
    tenant_map.set_mappings(datto.id, [
        TenantMapping("site-own", "example-clinic", "Example Clinic", "auto"),
        # … and a mapping an earlier version made from a NAME alone.
        TenantMapping("site-name", A, "Acme Corp", "auto"),
    ])
    _op(client, "adm-m", "admin")
    rows = client.get(f"/api/v1/integrations/datto/{datto.id}/mappings/tenants").json()["mappings"]
    flags = {r["vendor_tenant_id"]: r["needs_review"] for r in rows}
    assert flags == {"site-own": False, "site-name": True}
