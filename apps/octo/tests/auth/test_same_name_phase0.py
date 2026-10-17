"""Phase 0 of the UniFi / entity build — the same-name fix (2026-10-01), on
the real app, real registry, real audit chain, real quarantine store and the
real Datto / RocketCyber adapters (only the ingest delivery is driven here;
no vendor socket at all).

Two businesses can share a name. Pinned:
  * a vendor site / account whose name is the SAME NAME as one client
    (case, accents, punctuation aside — legal suffixes KEPT) is held as
    'name-match-suggested' with that client as a one-click suggestion; it is
    never mapped by itself (Datto site AND RocketCyber account — AT-G0);
  * "Acme Pharmacy, Inc." is not "Acme Pharmacy LLC": the look-alike gets its own
    new tenant (pending review), never the existing client's store;
  * the click (bulk-route with the suggested slug) maps the site 'manual' and
    routes the held events; manual mapping still works;
  * a NEW non-manual mapping is refused by the mapping routes; a stored one
    may only come back unchanged;
  * the mappings an earlier version made by name are listed for re-review in
    ONE operator notice per admin (once per mapping), and on the card.
"""
from __future__ import annotations

import sqlite3

from apps.octo import paths
from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import CREDS as RC_CREDS
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import incident
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import (
    create_instance,
    mapping_review,
    quarantine,
    tenant_autocreate,
    tenant_map,
)
from apps.octo.instances.manager import disable_instance
from apps.octo.instances.tenant_lifecycle import exact_name_key, normalise_name
from apps.octo.tests.auth.test_admin_tenants import (  # noqa: F401
    QUARANTINE,
    _admin,
    _api_alert,
    _events,
    _hold,
    _instance,
    app,
    instance_endpoint_client,
)


def _clients() -> dict[str, str]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {r[0]: r[1] for r in reg.execute("SELECT slug, display_name FROM clients")}
    finally:
        reg.close()


def _notices(kind: str = "mapping_review") -> list[sqlite3.Row]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return reg.execute("SELECT * FROM operator_notices WHERE kind = ? ORDER BY id",
                           (kind,)).fetchall()
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# The name keys
# ---------------------------------------------------------------------------

def test_the_exact_name_key_keeps_legal_suffixes():
    assert exact_name_key("Acme Pharmacy, Inc.") == exact_name_key("ACME PHARMACY INC") == "acme pharmacy inc"
    assert exact_name_key("Acme Pharmacy, Inc.") != exact_name_key("Acme Pharmacy LLC")
    assert exact_name_key("Café Délice") == exact_name_key("cafe   delice")
    assert exact_name_key("Smith & Jones") == "smith and jones"
    assert exact_name_key(None) == "" and exact_name_key("!!!") == ""
    # The LOOSE key (duplicate hints only) still pairs them — for a human.
    assert normalise_name("Acme Pharmacy, Inc.") == normalise_name("Acme Pharmacy LLC")


# ---------------------------------------------------------------------------
# Ingest: held with a suggestion, never linked (AT-G0)
# ---------------------------------------------------------------------------

def test_a_datto_site_with_the_same_name_is_held_and_one_click_maps_it(app):  # noqa: F811
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    d1 = _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="ACME PHARMACY INC"))
    d2 = _hold(iid, _api_alert(2, site_uid="site-uid-0001", site_name="ACME PHARMACY INC"))
    assert (d1.status, d1.reason) == ("quarantined", "name-match-suggested")
    assert d2.status == "quarantined"
    assert tenant_map.get_mappings(iid) == [] and _events("acme-pharmacy") == []

    # The review list carries the suggestion; the detail too.
    r = app.get(QUARANTINE, cookies=cookies)
    assert r.status_code == 200 and "name-match-suggested" in r.json()["reasons"]
    rows = r.json()["rows"]
    assert {(x["suggested_slug"], x["suggested_name"]) for x in rows} == {
        ("acme-pharmacy", "Acme Pharmacy, Inc.")}
    detail = app.get(f"{QUARANTINE}/{rows[0]['id']}", cookies=cookies).json()
    assert detail["suggested_slug"] == "acme-pharmacy"

    # The one click: the site is mapped by the operator ('manual') and the
    # held events are routed.
    r = app.post(f"{QUARANTINE}/bulk-route", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0001",
        "quarantine_reason": "name-match-suggested", "slug": "acme-pharmacy",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["routed"] == 2 and r.json()["mapping_written"] is True
    (m,) = tenant_map.get_mappings(iid)
    assert (m.vendor_tenant_id, m.octo_client_slug, m.match_source) == (
        "site-uid-0001", "acme-pharmacy", "manual")
    assert len(_events("acme-pharmacy")) == 2
    assert mapping_review.unconfirmed(instance_id=iid) == []
    # Routed rows carry no suggestion any more.
    assert app.get(QUARANTINE, cookies=cookies).json()["total"] == 0


def test_a_different_legal_suffix_gets_its_own_tenant(app):  # noqa: F811
    iid = _instance()
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    d = _hold(iid, _api_alert(1, site_uid="site-uid-0002", site_name="Acme Pharmacy LLC"))
    assert (d.status, d.outcome, d.slug) == ("stored", "auto-created", "acme-pharmacy-llc")
    assert _events("acme-pharmacy") == [] and len(_events("acme-pharmacy-llc")) == 1
    assert set(_clients()) == {"acme-pharmacy", "acme-pharmacy-llc"}


def test_a_rocketcyber_account_with_the_same_name_is_held_not_mapped(app):  # noqa: F811
    record = create_instance(vendor_slug="rocketcyber", display_name="RocketCyber",
                             credentials_dict=dict(RC_CREDS))
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    adapter = RocketCyberSourceAdapter()
    env = incident(1, account_id=2042, account_name="Acme Pharmacy Inc")
    d = tenant_autocreate.deliver(
        instance_id=record.id, vendor_slug="rocketcyber", adapter=adapter, envelope=env,
        event=adapter.extract_event(env), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=None, door="poll",
    )
    assert (d.status, d.reason) == ("quarantined", "name-match-suggested")
    assert tenant_map.get_mappings(record.id) == []
    (row,), _total = quarantine.list_rows(instance_id=record.id)
    assert (row.vendor_tenant_id, row.vendor_tenant_label) == ("2042", "Acme Pharmacy Inc")
    assert tenant_autocreate.name_suggestions([row.vendor_tenant_label]) == {
        "Acme Pharmacy Inc": tenant_autocreate.NameSuggestion("acme-pharmacy", "Acme Pharmacy, Inc.")}
    # Manual mapping still works: once mapped, the account routes.
    tenant_map.set_mappings(record.id, [tenant_map.TenantMapping("2042", "acme-pharmacy")])
    env2 = incident(2, account_id=2042, account_name="Acme Pharmacy Inc")
    d = tenant_autocreate.deliver(
        instance_id=record.id, vendor_slug="rocketcyber", adapter=adapter, envelope=env2,
        event=adapter.extract_event(env2), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=None, door="poll",
    )
    assert (d.status, d.outcome, d.slug) == ("stored", "mapped", "acme-pharmacy")


def test_two_same_name_clients_get_no_suggestion(app):  # noqa: F811
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    create_client("acme-pharmacy-2", "ACME PHARMACY INC")
    d = _hold(iid, _api_alert(1, site_uid="site-uid-0003", site_name="Acme Pharmacy Inc"))
    assert d.reason == "ambiguous-name"
    (row,) = app.get(QUARANTINE, cookies=cookies).json()["rows"]
    assert row["suggested_slug"] is None and row["suggested_name"] is None


# ---------------------------------------------------------------------------
# The mapping routes refuse a NEW name-made mapping
# ---------------------------------------------------------------------------

def test_the_generic_mapping_route_refuses_new_non_manual_rows(app):  # noqa: F811
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    url = f"/api/v1/integrations/datto/{iid}/mappings/tenants"
    for source in ("auto-name", "auto-domain", "directory", "auto"):
        r = app.put(url, json={"mappings": [{"vendor_tenant_id": "site-uid-0001",
                                             "octo_client_slug": "acme-corp",
                                             "match_source": source}]}, cookies=cookies)
        assert r.status_code == 422, (source, r.text)
    assert tenant_map.get_mappings(iid) == []
    # A stored name-made row (an earlier version's auto-link) comes back unchanged.
    tenant_map.set_mappings(iid, [tenant_map.TenantMapping("site-uid-0001", "acme-corp",
                                                           "Acme Corp", "auto")])
    r = app.put(url, json={"mappings": [{"vendor_tenant_id": "site-uid-0001",
                                         "octo_client_slug": "acme-corp",
                                         "vendor_tenant_label": "Acme Corp",
                                         "match_source": "auto"}]}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert tenant_map.get_mappings(iid)[0].match_source == "auto"
    # Confirmed: 'manual'.
    r = app.put(url, json={"mappings": [{"vendor_tenant_id": "site-uid-0001",
                                         "octo_client_slug": "acme-corp",
                                         "match_source": "manual"}]}, cookies=cookies)
    assert r.status_code == 200
    assert tenant_map.get_mappings(iid)[0].match_source == "manual"


# ---------------------------------------------------------------------------
# Existing name-made mappings: listed for re-review
# ---------------------------------------------------------------------------

def test_name_made_mappings_are_listed_once_in_one_notice_per_admin(app):  # noqa: F811
    cookies = _admin(app, "admin1")
    _admin(app, "admin2")
    iid = _instance()
    other = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                            credentials_dict={"NEXTDNS_API_KEY": "fixture-nd-key-" + "7" * 24}).id
    create_client("acme-pharmacy", "Acme Pharmacy, Inc.")
    create_client("acme-corp", "Acme Corp")
    # (a) an earlier version's auto-link to a hand-made client;
    # (b) an auto-created tenant's OWN mapping (that tenant IS the site) — not listed;
    # (c) a bulk-accepted NextDNS-style name suggestion on another instance;
    # (d) a confirmed mapping — not listed.
    tenant_map.set_mappings(iid, [
        tenant_map.TenantMapping("site-uid-0001", "acme-pharmacy", "Acme Pharmacy LLC", "auto"),
        tenant_map.TenantMapping("site-uid-0004", "acme-corp", "Acme Corp", "manual"),
    ])
    created = _hold(iid, _api_alert(9, site_uid="site-uid-0009", site_name="Brand New Co"))
    assert created.outcome == "auto-created"
    tenant_map.set_mappings(other, [
        tenant_map.TenantMapping("site-uid-0007", "acme-corp", "Acme Corp East", "auto-name"),
    ])
    found = mapping_review.unconfirmed()
    assert [(m.instance_id, m.vendor_tenant_id, m.client_slug, m.match_source) for m in found] == [
        (iid, "site-uid-0001", "acme-pharmacy", "auto"),
        (other, "site-uid-0007", "acme-corp", "auto-name"),
    ]
    assert not mapping_review.is_confirmed("auto") and mapping_review.is_confirmed("manual")

    ids = mapping_review.notify()
    notices = _notices()
    assert len(ids) == 2 and len(notices) == 2               # one per admin
    n = notices[0]
    assert (n["actor_id"], n["subject_slug"], n["change_request_id"]) == (0, "global", None)
    assert n["title"] == "2 tenant mappings made from a name match — please re-review"
    assert "'Acme Pharmacy LLC' (site-uid-0001) → Acme Pharmacy, Inc. (linked automatically by name)" in n["body"]
    assert "'Acme Corp East' (site-uid-0007) → Acme Corp (accepted from a name suggestion in bulk)" in n["body"]
    assert "Brand New Co" not in n["body"]
    # Once per mapping: a restart does not repeat it.
    assert mapping_review.notify() == [] and len(_notices()) == 2
    # The admin sees it in their inbox and on the card.
    inbox = app.get("/api/v1/admin/notices", cookies=cookies).json()
    assert [x["kind"] for x in inbox["notices"]] == ["mapping_review"]
    lines = mapping_review.card_warnings(iid, "Datto RMM")
    assert lines and "1 Datto RMM tenant mapping was made from a name match" in lines[0]
    # A newly found one raises a new notice listing only it.
    tenant_map.set_mappings(iid, [
        tenant_map.TenantMapping("site-uid-0001", "acme-pharmacy", "Acme Pharmacy LLC", "auto"),
        tenant_map.TenantMapping("site-uid-0002", "acme-corp", "ACME", "auto"),
    ])
    new_ids = mapping_review.notify()
    assert len(new_ids) == 2
    latest = _notices()[-1]
    assert latest["title"].startswith("1 tenant mapping made from a name match")
    assert "site-uid-0002" in latest["body"] and "site-uid-0001" not in latest["body"]
    assert "2 mapping(s) listed in an earlier notice are still unconfirmed" in latest["body"]
    # Confirmed (manual) → no longer listed; a disabled instance's rows neither.
    tenant_map.set_mappings(iid, [
        tenant_map.TenantMapping("site-uid-0001", "acme-pharmacy", "Acme Pharmacy LLC", "manual"),
        tenant_map.TenantMapping("site-uid-0002", "acme-corp", "ACME", "manual"),
    ])
    disable_instance(other, disabled_by_operator_id=None, reason="test")
    assert mapping_review.unconfirmed() == []
    assert mapping_review.card_warnings(iid, "Datto RMM") == []


def test_the_notice_waits_for_an_admin_and_is_never_fatal(app, monkeypatch):  # noqa: F811
    iid = _instance()
    create_client("acme-corp", "Acme Corp")
    tenant_map.set_mappings(iid, [tenant_map.TenantMapping("site-uid-0001", "acme-corp", None, "auto")])
    # No admin yet: nothing is raised — and nothing is marked as told.
    assert mapping_review.notify() == [] and _notices() == []
    _admin(app, "admin1")
    assert len(mapping_review.notify()) == 1
    # An unreadable registry: logged, [] — never raised into startup.
    monkeypatch.setattr(paths, "registry_db_path",
                        lambda: paths.data_root() / "missing" / "registry.db")
    assert mapping_review.notify() == []
