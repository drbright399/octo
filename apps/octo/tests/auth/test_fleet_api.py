"""Fleet v2 through the real HTTP routes and real sign-in: the role matrix
(analyst / admin / super_admin see every site in scope with locations; a
viewer sees ONLY their own tenant's sites — no location, no vendor name, no
other tenant), the drawer's recent alerts (analyst+, one site's own UniFi
alerts), the manual location editors — per site (the drawer) and the tenant
fallback (settings) — admin+, scoped, audited before the write, the address
lookup (admin+, mocked, nothing stored), the regional groups (operators,
scoped), the polled-read audit roll-up."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.unifi.adapter import UniFiSourceAdapter
from apps.octo.client_provisioning import create_client
from apps.octo.entity import switch
from apps.octo.fleet import build, geocode, sources
from apps.octo.fleet.tests.fixtures import (
    FakeManager,
    FakeNextDnsPoller,
    FakeUnifiPoller,
    dns_state,
    fleet_site,
    scope,
    stamp_tier_worker,
)
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import create_instance, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_dashboard_throughput import _login
from apps.octo.threat import store

PW = "pw1234567890"
A, B, C = "acme-corp", "example-bakery", "example-dental"
# Set again by the fixture: a module-level time taken at import is minutes
# old by the time a full suite reaches these tests — and stale data reads
# (correctly) as unknown.
NOW = datetime.now(timezone.utc).replace(microsecond=0)
VENDOR_WORDS = ("unifi", "nextdns", "datto", "rocketcyber", "ubiquiti", "kaseya", "ui.com")


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


@pytest.fixture
def fl(auth_client, auth_data_root, monkeypatch, tmp_path):
    global NOW
    NOW = datetime.now(timezone.utc).replace(microsecond=0)
    from apps.octo.adapters.nextdns.tests.fake_nextdns import CREDS as ND
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS as UF
    from apps.octo.credentials import ensure_key_file

    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "cred-key.env"))
    monkeypatch.setenv(build.CACHE_ENV, "0")
    ensure_key_file()
    switch.reset()
    vendor_contact.reset()
    build.invalidate()
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    create_client(C, "Example Dental", kind="client")
    uf = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                         credentials_dict=dict(UF), instance_config={})
    nd = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                         credentials_dict=dict(ND), instance_config={})
    tenant_map.set_mappings(uf.id, [TenantMapping(scope(1), A, "Acme HQ", "manual"),
                                    TenantMapping(scope(2), A, "Acme Annex", "manual"),
                                    TenantMapping(scope(3), B, "Bakery", "manual")])
    tenant_map.set_mappings(nd.id, [TenantMapping("p-acme", A, "Acme DNS", "manual"),
                                    TenantMapping("p-dental", C, "Dental DNS", "manual")])
    mgr = FakeManager()
    mgr.pollers[uf.id] = FakeUnifiPoller(at=NOW - timedelta(minutes=2), sites={
        scope(1): fleet_site(1, name="Acme HQ"),
        scope(2): fleet_site(2, name="Acme Annex", gateways_offline=1),
        scope(3): fleet_site(3, name="Bakery"),
        scope(9): fleet_site(9, name="Unmapped console"),
    }, outages=[{"vid": "isp:1:64500:x", "open": True, "asn": 64500, "isp": "Example ISP",
                 "since": iso(NOW), "opened_at": iso(NOW), "closed_at": None,
                 "tenant": "msp-internal", "event_id": 1, "sites": 3, "sites_down": 3,
                 "members": [{"scope": scope(n), "tenant": t, "name": f"Site {n}",
                              "since": iso(NOW), "why": "console unreachable",
                              "recovered_at": None}
                             for n, t in ((1, A), (3, B), (4, "example-other"))]}])
    mgr.pollers[nd.id] = FakeNextDnsPoller(states={
        "p-acme": dns_state("p-acme", A, "lapsed", NOW - timedelta(minutes=3),
                            name="Acme DNS"),
        "p-dental": dns_state("p-dental", C, "active", NOW - timedelta(minutes=3)),
    })
    auth_client.app.state.instance_manager = mgr
    store.reset_schema_cache()
    sources.reset_incident_cache()
    stamp_tier_worker()
    yield auth_client, uf, nd
    switch.reset()
    vendor_contact.reset()
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()


def _op(client, name: str, role: str, scope_slugs=None) -> dict:
    op = client.provision_operator(name, PW, role=role, athena_role=role,
                                   scope_slugs=scope_slugs)
    _login(client, op)
    return op


def _audit(action: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id",
                            (action,)).fetchall()
    finally:
        conn.close()


def _sites(client) -> dict:
    r = client.get("/api/v1/fleet/sites")
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Role matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["analyst", "admin", "super_admin"])
def test_operator_roles_see_every_site_with_locations(fl, role):
    client, uf, _nd = fl
    _op(client, f"op-{role}", role)
    body = _sites(client)
    assert body["view"] == "operator"
    names = {s["name"]: s for s in body["sites"]}
    assert set(names) == {"Acme HQ", "Acme Annex", "Bakery", "Example Dental"}
    hq = names["Acme HQ"]
    assert hq["kind"] == "site" and hq["tenant_slug"] == A and hq["tenant_name"] == "Acme Corp"
    assert hq["location"]["source"] == "unifi" and hq["location"]["lat"] == 41.06
    assert hq["vendor_ref"]["host_id"] and hq["vendor_ref"]["instance_id"] == uf.id
    # The fixture consoles' host ids ('F1X7…') are not UniFi's '<hex>:<digits>':
    # no UniFi link (never a '%3A' one) — see test_operators_get_the_open_in_links.
    assert {link["vendor"] for link in hq["links"]} == {"nextdns"}
    assert hq["state"] == "warn" and hq["reason"] == "NextDNS lapsed (Acme DNS)"
    assert names["Acme Annex"]["reason"].startswith("gateway offline")
    assert names["Example Dental"]["kind"] == "tenant"
    assert names["Example Dental"]["location"] is None
    assert body["unmapped_sites"] == 1
    assert {t["slug"] for t in body["tenants"]} == {A, B, C}
    (outage,) = body["isp_outages"]
    assert outage["isp"] == "Example ISP" and len(outage["members"]) == 3
    assert body["counts"]["total"] == 4 and body["counts"]["located"] == 3
    assert _audit("fleet.sites")                                    # the polled-read roll-up


def test_a_viewer_sees_only_their_own_sites_and_no_vendor_or_location(fl):
    client, _uf, _nd = fl
    _op(client, "viewer-acme", "viewer", [A])
    r = client.get("/api/v1/fleet/sites")
    assert r.status_code == 200
    body = r.json()
    assert body["view"] == "client"
    assert sorted(s["name"] for s in body["sites"]) == ["Acme Annex", "Acme HQ"]
    for s in body["sites"]:
        assert s["location"] is None and s["links"] == [] and s["vendor_ref"] is None
        assert s["tenant_slug"] is None and s["console_name"] is None
        assert s["tenant_name"] == "Acme Corp"
    hq = next(s for s in body["sites"] if s["name"] == "Acme HQ")
    assert hq["state"] == "warn" and hq["reason"] == "DNS protection lapsed"
    assert hq["layers"]["security"]["data"] == {"ips_detected_24h": 0, "ips_blocked_24h": 0,
                                                "dns_threats_24h": 0,
                                                "dns_protection": {"lapsed": 1}}
    assert "isp" not in hq["layers"]["network"]["data"]
    assert body["isp_outages"] == [] and body["unmapped_sites"] is None
    assert body["tenants"] == []
    text = r.text.lower()
    for word in VENDOR_WORDS:
        assert word not in text, word
    for other in ("bakery", "dental", "example isp", B, C, "41.06", "-101.0"):
        assert other.lower() not in text, other
    # The drawer's alerts and the location editor are not theirs.
    key = hq["key"]
    assert client.get(f"/api/v1/fleet/sites/{key}/alerts").status_code == 403
    assert client.get(f"/api/v1/fleet/locations/{A}").status_code == 403


# Synthetic, but UniFi's console host id shape: hex, ':', digits.
REAL_SHAPED = "FA4E" + "0" * 52 + "C0DE:1000000042"
DATTO = "https://fixture.rmm.datto.com"


def _open_in_world(client, uf) -> None:
    """Acme gets a UniFi site on a real-shaped console and a Datto site whose
    numeric id the inventory poller learned."""
    from apps.octo.adapters.datto import site_ids
    from apps.octo.adapters.datto.tests.fake_datto import CREDS as DT

    sc = f"{REAL_SHAPED}/site-r01"
    tenant_map.set_mappings(uf.id, [TenantMapping(scope(1), A, "Acme HQ", "manual"),
                                    TenantMapping(scope(2), A, "Acme Annex", "manual"),
                                    TenantMapping(scope(3), B, "Bakery", "manual"),
                                    TenantMapping(sc, A, "Acme Remote", "manual")])
    site = fleet_site(5, name="Acme Remote")
    site["scope"], site["host_id"] = sc, REAL_SHAPED
    client.app.state.instance_manager.pollers[uf.id].sites[sc] = site
    dt = create_instance(vendor_slug="datto", display_name="Datto RMM",
                         credentials_dict=dict(DT), instance_config={
                             "vendor_links": {"portal_base_url": DATTO}})
    tenant_map.set_mappings(dt.id, [TenantMapping("ds-acme", A, "Acme", "manual"),
                                    TenantMapping("ds-acme-2", A, "Acme two", "manual")])
    site_ids.save(dt.id, mapped=["ds-acme", "ds-acme-2"], now=NOW,
                  found={"ds-acme": {"id": "4101", "name": "Acme Main"}})


def test_operators_get_the_open_in_links(fl):
    client, uf, _nd = fl
    _open_in_world(client, uf)
    _op(client, "op-links", "analyst")
    names = {s["name"]: s for s in _sites(client)["sites"]}
    links = [(x["vendor"], x["label"], x["url"], x["verified"])
             for x in names["Acme Remote"]["links"] if x["vendor"] != "nextdns"]
    assert links == [
        ("unifi", "Open in UniFi Site Manager",
         f"https://unifi.ui.com/consoles/{REAL_SHAPED}/network/default/dashboard", True),
        ("datto", "Open in Datto RMM — Acme Main", f"{DATTO}/site/4101/acme-main", True),
        # ds-acme-2's id is not known (yet): the portal home, said so.
        ("datto", "Open Datto RMM (home)", f"{DATTO}/", False),
    ]
    # The other Acme sites carry the tenant's Datto sites too (no entity
    # links): never a UniFi link with '%3A'.
    for name in ("Acme HQ", "Acme Annex"):
        urls = [x["url"] for x in names[name]["links"]]
        assert f"{DATTO}/site/4101/acme-main" in urls
        assert not any("%3A" in u for u in urls)


def test_a_viewer_never_gets_an_open_in_link(fl):
    client, uf, _nd = fl
    _open_in_world(client, uf)
    _op(client, "viewer-links", "viewer", [A])
    r = client.get("/api/v1/fleet/sites")
    assert r.status_code == 200
    body = r.json()
    assert body["view"] == "client"
    assert "Acme Remote" in {s["name"] for s in body["sites"]}
    assert all(s["links"] == [] for s in body["sites"])
    for word in ("rmm.datto.com", "unifi.ui.com", "/site/4101", REAL_SHAPED.lower()):
        assert word not in r.text.lower(), word


def test_a_placeholder_named_tenant_reads_your_organization_for_a_viewer(fl):
    client, uf, _nd = fl
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET display_name = 'unifi site 1a2b3c4d', origin = 'auto', "
                    "created_by_instance_id = ? WHERE slug = ?", (uf.id, A))
        reg.commit()
    finally:
        reg.close()
    _op(client, "viewer-ph", "viewer", [A])
    r = client.get("/api/v1/fleet/sites")
    assert {s["tenant_name"] for s in r.json()["sites"]} == {"Your organization"}
    assert "unifi" not in r.text.lower()


def test_a_legacy_star_viewer_sees_nothing(fl):
    client, _uf, _nd = fl
    _op(client, "viewer-star", "viewer", ["*"])
    body = _sites(client)
    assert body["sites"] == [] and body["view"] == "client"


def test_a_scoped_analyst_sees_only_their_tenants_and_outage_members(fl):
    client, _uf, _nd = fl
    _op(client, "ana-bakery", "analyst", [B])
    body = _sites(client)
    assert [s["name"] for s in body["sites"]] == ["Bakery"]
    assert body["unmapped_sites"] is None
    (outage,) = body["isp_outages"]
    assert [m["tenant"] for m in outage["members"]] == [B]
    assert "tenant" not in outage and "event_id" not in outage
    # Counts over ITS members only: never how many other clients' sites are
    # on that ISP (the fleet-wide incident has 3 sites, 3 down).
    assert outage["sites"] == 1 and outage["sites_down"] == 1


def test_a_star_operator_sees_the_fleet_wide_outage_counts(fl):
    client, _uf, _nd = fl
    _op(client, "ana-star", "analyst")
    (outage,) = _sites(client)["isp_outages"]
    assert outage["sites"] == 3 and outage["sites_down"] == 3 and len(outage["members"]) == 3


LABEL_WITH_CONSOLE = "Default — UniFi Express (1 Example Road, Example County)"


def test_a_viewer_never_gets_the_mapping_label_or_the_console_name(fl):
    """No fleet poll yet (a restart) or a site gone from UniFi's list: the
    name falls back past the poller — a client user must never get the
    mapping label (console + address text) or the console's name."""
    client, uf, _nd = fl
    tenant_map.set_mappings(uf.id, [TenantMapping(scope(1), A, LABEL_WITH_CONSOLE, "manual"),
                                    TenantMapping(scope(2), A, "Annex — udm-annex", "manual"),
                                    TenantMapping(scope(3), B, LABEL_WITH_CONSOLE, "manual")])
    poller = client.app.state.instance_manager.pollers[uf.id]
    poller.at, poller.sites = None, {}
    _op(client, "viewer-acme2", "viewer", [A])
    r = client.get("/api/v1/fleet/sites")
    assert r.status_code == 200, r.text
    assert sorted(s["name"] for s in r.json()["sites"]) == ["Site 1", "Site 2"]
    text = r.text.lower()
    for leak in ("express", "example road", "example county", "default —", "udm-annex",
                 *VENDOR_WORDS):
        assert leak not in text, leak
    # Health present but the site is UniFi's default (named after its
    # console): the console's name never reaches the client either.
    poller.at = NOW
    poller.sites = {scope(1): {**fleet_site(1, name="UniFi Express"),
                               "console_name": "UniFi Express"},
                    scope(2): fleet_site(2, name="Acme Annex")}
    build.invalidate()
    body = client.get("/api/v1/fleet/sites").json()
    assert sorted(s["name"] for s in body["sites"]) == ["Acme Annex", "Site 1"]
    assert "express" not in json.dumps(body).lower()
    # An operator still sees the real names.
    client.cookies.clear()
    _op(client, "ana-names", "analyst")
    names = {s["name"] for s in _sites(client)["sites"]}
    assert "UniFi Express" in names and "Acme Annex" in names


# ---------------------------------------------------------------------------
# The drawer's recent alerts
# ---------------------------------------------------------------------------

def _unifi_alert(slug: str, n: int, kind: str = "wan_down") -> int:
    payload = {
        "vendor_event_id": f"{scope(n)}:e{n}", "kind": kind, "scope": scope(n),
        "host_id": scope(n).split("/")[0], "site_id": "f1x7517e0000000000000001",
        "site_ref": "default", "site_name": f"Example Site {n}", "console_name": f"console-{n}",
        "event": {"id": f"e{n}", "timestamp": iso(NOW - timedelta(minutes=n)),
                  "event": "NETWORK_WAN_FAILED", "title": "WAN failed"},
        "signal": {"level": "medium"},
    }
    event = UniFiSourceAdapter().extract_event(payload)
    return SqliteIngestSink(publish_to_stream=False).ingest(slug, "unifi", event).event_id


def test_site_alerts_are_the_sites_own(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    own = _unifi_alert(A, 1)
    other = _unifi_alert(A, 2)
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        conn.execute("INSERT INTO events (received_at, source, source_host, event_type, "
                     "severity, payload, payload_sha256, summary) VALUES (?, 'nextdns', NULL, "
                     "'nextdns.protection_lapsed', 'medium', '{}', 'x', 'DNS lapsed')",
                     (iso(NOW - timedelta(minutes=5)),))
        conn.commit()
    finally:
        conn.close()
    sites = {s["name"]: s for s in _sites(client)["sites"]}
    r = client.get(f"/api/v1/fleet/sites/{sites['Acme HQ']['key']}/alerts")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    ids = [i["event_id"] for i in items]
    assert own in ids and other not in ids
    (mine,) = [i for i in items if i["event_id"] == own]
    assert mine["title"].startswith("UniFi internet (WAN) connection failed")
    assert mine["tenant_wide"] is False
    (dns,) = [i for i in items if i["source"] == "nextdns"]
    assert dns["tenant_wide"] is True                            # Acme has two sites
    # Out of scope = the same 404 as no such site.
    client.cookies.clear()
    _op(client, "ana-b", "analyst", [B])
    assert client.get(f"/api/v1/fleet/sites/{sites['Acme HQ']['key']}/alerts").status_code == 404
    assert client.get("/api/v1/fleet/sites/u-00000000000000000000/alerts").status_code == 404
    assert client.get("/api/v1/fleet/sites/not-a-key/alerts").status_code == 422


# ---------------------------------------------------------------------------
# The manual location
# ---------------------------------------------------------------------------

def test_the_location_editor_is_admin_scoped_and_audited(fl):
    client, _uf, _nd = fl
    _op(client, "ana-loc", "analyst")
    body = {"lat": 41.3, "lng": -100.7, "label": "Dental office", "reason": "client confirmed"}
    assert client.put(f"/api/v1/fleet/locations/{C}", json=body).status_code == 403
    client.cookies.clear()
    _op(client, "adm", "admin")
    r = client.get(f"/api/v1/fleet/locations/{C}")
    assert r.status_code == 200 and r.json()["effective"] == "none"
    r = client.put(f"/api/v1/fleet/locations/{C}", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["effective"] == "manual"
    assert r.json()["override"]["label"] == "Dental office"
    (row,) = _audit("tenant_location_set")
    assert row["client_slug"] == C and json.loads(row["after_state"])["lat"] == 41.3
    assert row["before_state"] in (None, "null") and row["reason"] == "client confirmed"
    dental = next(s for s in _sites(client)["sites"] if s["name"] == "Example Dental")
    assert dental["location"] == {"lat": 41.3, "lng": -100.7, "label": "Dental office",
                                  "source": "manual"}
    # Acme's consoles report their own locations: the tenant location is a
    # FALLBACK (042 — a wrong console is corrected per site in the drawer),
    # dormant while every site has one; the editor shows what they report.
    before = client.get(f"/api/v1/fleet/locations/{A}").json()
    assert before["effective"] == "unifi"
    client.put(f"/api/v1/fleet/locations/{A}", json={**body, "label": "Acme office"})
    loc = client.get(f"/api/v1/fleet/locations/{A}").json()
    assert loc["effective"] == "unifi" and loc["override"]["label"] == "Acme office"
    assert loc["unifi_sites"] == before["unifi_sites"] and len(loc["unifi_sites"]) == 2
    acme = [s for s in _sites(client)["sites"] if s["tenant_slug"] == A and s["location"]]
    assert acme and all(s["location"]["source"] == "unifi" for s in acme)
    for bad in ({**body, "lat": 0, "lng": 0}, {**body, "lat": 95}, {**body, "label": ""},
                {**body, "reason": ""}, {**body, "extra": 1}):
        assert client.put(f"/api/v1/fleet/locations/{C}", json=bad).status_code == 422
    assert client.put("/api/v1/fleet/locations/no-such-tenant", json=body).status_code == 404
    r = client.request("DELETE", f"/api/v1/fleet/locations/{C}",
                       json={"reason": "moved away"})
    assert r.status_code == 200 and r.json()["effective"] == "none"
    (cleared,) = _audit("tenant_location_clear")
    assert json.loads(cleared["before_state"])["label"] == "Dental office"
    assert client.request("DELETE", f"/api/v1/fleet/locations/{C}",
                          json={"reason": "again"}).status_code == 404
    # A scoped admin cannot place another tenant.
    client.cookies.clear()
    _op(client, "adm-b", "admin", [B])
    assert client.put(f"/api/v1/fleet/locations/{C}", json=body).status_code == 404
    assert client.get(f"/api/v1/fleet/locations/{C}").status_code == 404


# ---------------------------------------------------------------------------
# One site's location (the drawer), the address lookup
# ---------------------------------------------------------------------------

def _key(client, name: str) -> str:
    return next(x["key"] for x in _sites(client)["sites"] if x["name"] == name)


def test_the_site_location_editor_is_admin_scoped_audited_and_locked(fl, monkeypatch):
    client, _uf, _nd = fl
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    _op(client, "ana-site", "analyst")
    hq = _key(client, "Acme HQ")
    body = {"lat": 41.5, "lng": -100.5, "label": "1 Example Rd (verified)",
            "reason": "console reports the wrong state"}
    assert client.get(f"/api/v1/fleet/sites/{hq}/location").status_code == 403
    assert client.put(f"/api/v1/fleet/sites/{hq}/location", json=body).status_code == 403
    client.cookies.clear()
    _op(client, "adm-site", "admin")
    r = client.get(f"/api/v1/fleet/sites/{hq}/location")
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["effective"] == "unifi" and got["override"] is None
    assert got["console"]["label"].startswith("1 Example Road") and got["geocoder"] == "census"
    assert got["current"]["source"] == "unifi" and got["tenant_slug"] == A

    r = client.put(f"/api/v1/fleet/sites/{hq}/location", json=body)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["effective"] == "site" and got["current"] == {
        "lat": 41.5, "lng": -100.5, "label": "1 Example Rd (verified)", "source": "site"}
    assert got["console"] is not None                            # still shown
    (row,) = _audit("site_location_set")
    assert row["target_kind"] == "site_location" and row["target_id"] == hq
    assert row["client_slug"] == A and row["reason"] == "console reports the wrong state"
    assert json.loads(row["after_state"])["site"] == "Acme HQ"
    pins = {x["name"]: x["location"] for x in _sites(client)["sites"]}
    assert pins["Acme HQ"]["source"] == "site"
    assert pins["Acme Annex"]["source"] == "unifi"               # per site, not per tenant

    for bad in ({**body, "lat": 0, "lng": 0}, {**body, "lng": 181}, {**body, "label": ""},
                {**body, "reason": ""}, {**body, "extra": 1}):
        assert client.put(f"/api/v1/fleet/sites/{hq}/location", json=bad).status_code == 422
    assert client.put("/api/v1/fleet/sites/u-00000000000000000000/location",
                      json=body).status_code == 404
    assert client.get("/api/v1/fleet/sites/not-a-key/location").status_code == 422

    r = client.request("DELETE", f"/api/v1/fleet/sites/{hq}/location",
                       json={"reason": "fixed in UniFi"})
    assert r.status_code == 200 and r.json()["effective"] == "unifi"
    (cleared,) = _audit("site_location_clear")
    assert json.loads(cleared["before_state"])["lat"] == 41.5
    assert client.request("DELETE", f"/api/v1/fleet/sites/{hq}/location",
                          json={"reason": "again"}).status_code == 404

    # A scoped admin cannot see or place another tenant's site.
    client.cookies.clear()
    _op(client, "adm-site-b", "admin", [B])
    assert client.get(f"/api/v1/fleet/sites/{hq}/location").status_code == 404
    assert client.put(f"/api/v1/fleet/sites/{hq}/location", json=body).status_code == 404
    # A client user: never a coordinate, never the editor.
    client.cookies.clear()
    _op(client, "view-site", "viewer", [A])
    assert all(x["location"] is None for x in _sites(client)["sites"])
    assert client.get(f"/api/v1/fleet/sites/{hq}/location").status_code == 403


def test_the_address_lookup(fl, monkeypatch):
    client, _uf, _nd = fl
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(geocode, "LIMITER", geocode.RateLimiter(limit=3, window_sec=60.0))
    sent: list[str] = []

    def fake_lookup(address, **_kw):
        sent.append(address)
        return [geocode.Match(41.25, -100.75, "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000")]

    monkeypatch.setattr(geocode, "lookup", fake_lookup)
    address = "1 Example Rd,  Example Town ZZ"
    _op(client, "ana-geo", "analyst")
    assert client.post("/api/v1/fleet/geocode", json={"address": address}).status_code == 403
    client.cookies.clear()
    _op(client, "adm-geo", "admin")
    r = client.post("/api/v1/fleet/geocode", json={"address": address})
    assert r.status_code == 200, r.text
    assert r.json() == {"provider": "census", "matches": [
        {"lat": 41.25, "lng": -100.75, "label": "1 EXAMPLE RD, EXAMPLE TOWN, ZZ, 00000"}]}
    assert sent == ["1 Example Rd, Example Town ZZ"]             # the typed text, cleaned
    assert client.post("/api/v1/fleet/geocode", json={"address": "abc"}).status_code == 422
    assert client.post("/api/v1/fleet/geocode",
                       json={"address": address, "tenant": A}).status_code == 422
    client.post("/api/v1/fleet/geocode", json={"address": address})
    client.post("/api/v1/fleet/geocode", json={"address": address})
    r = client.post("/api/v1/fleet/geocode", json={"address": address})
    assert r.status_code == 429                                   # 3 a minute here
    monkeypatch.setattr(geocode, "LIMITER", geocode.RateLimiter())

    def down(address, **_kw):
        raise geocode.GeocodeError("the address lookup service could not be reached")

    monkeypatch.setattr(geocode, "lookup", down)
    r = client.post("/api/v1/fleet/geocode", json={"address": address})
    assert r.status_code == 503 and "could not be reached" in r.json()["message"]
    monkeypatch.setenv(geocode.GEOCODER_ENV, "off")
    r = client.post("/api/v1/fleet/geocode", json={"address": address})
    assert r.status_code == 409 and "turned off" in r.json()["message"]
    hq = _key(client, "Acme HQ")
    assert client.get(f"/api/v1/fleet/sites/{hq}/location").json()["geocoder"] is None
    # Nothing about the address is kept in the audit log.
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        dump = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM audit_log"))
    finally:
        conn.close()
    assert "Example Rd" not in dump and "EXAMPLE RD" not in dump


def test_regional_groups_are_operator_only_and_scoped(fl):
    client, uf, _nd = fl
    poller = client.app.state.instance_manager.pollers[uf.id]
    for n in (1, 2, 3):
        poller.sites[scope(n)]["stats"].update({"issues_recent": True,
                                                "issues_recent_count": 3})
    build.invalidate()
    _op(client, "adm-reg", "admin")
    got = _sites(client)
    kinds = sorted(g["kind"] for g in got["regional"])
    assert kinds == ["area", "isp"] and all(g["sites"] == 3 for g in got["regional"])
    bakery = next(x for x in got["sites"] if x["name"] == "Bakery")
    assert bakery["state"] == "notice"                           # held: likely regional
    assert got["counts"]["notice"] >= 1
    client.cookies.clear()
    _op(client, "ana-reg-b", "analyst", [B])
    got = _sites(client)
    assert all(g["sites"] == 1 and len(g["keys"]) == 1 for g in got["regional"])
    client.cookies.clear()
    _op(client, "view-reg", "viewer", [B])
    got = _sites(client)
    assert got["regional"] == []
    (site,) = got["sites"]
    assert site["state"] == "notice" and "nearby" not in json.dumps(site)


# ---------------------------------------------------------------------------
# Tier Black slice 1: WAN coverage and the threat layer per caller
# ---------------------------------------------------------------------------

def test_wan2_not_configured_is_operator_only_with_a_fleet_coverage_count(fl):
    client, uf, _nd = fl
    poller = client.app.state.instance_manager.pollers[uf.id]
    for n in (1, 3):
        site = poller.sites[scope(n)]
        site["wans"][0].update({"role": "primary", "configured": True})
        site["wans"].append({"wan": "WAN2", "port_up": False, "plugged": False,
                             "ipv4_present": False, "configured": False, "role": "backup"})
    build.invalidate()
    _op(client, "adm-wan", "admin")
    body = _sites(client)
    bakery = next(s for s in body["sites"] if s["name"] == "Bakery")
    assert bakery["state"] == "notice" and bakery["reason"] == "WAN2 not configured"
    # HQ + Bakery without a backup line; Annex: a single port, none either.
    assert body["coverage"] == {"sites_with_backup": 0, "sites_without_backup": 3,
                                "sites_backup_unknown": 0}
    client.cookies.clear()
    _op(client, "view-wan", "viewer", [B])
    (site,) = _sites(client)["sites"]
    assert site["state"] == "ok" and "wan2" not in json.dumps(site).lower()
    assert "backup" not in json.dumps(site).lower()
    assert _sites(client)["coverage"] is None


def test_an_incident_reaches_a_client_only_once_acknowledged(fl):
    client, _uf, _nd = fl
    hq_key = build.site_key("unifi", scope(1))
    inc = store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key="k1",
                              summary="ws-01 reached relay-young.example.test",
                              scope="device", opened_by="1", site_key=hq_key,
                              device_ref="ws-01", device_label="WS-01").incident
    build.invalidate()
    _op(client, "ana-thr", "analyst", [A])
    body = _sites(client)
    hq = next(s for s in body["sites"] if s["name"] == "Acme HQ")
    assert hq["state"] == "black" and hq["incident"]["id"] == inc.id
    assert hq["reason"].startswith("BLACK: ws-01 reached relay-young.example.test on WS-01")
    assert [t["id"] for t in body["threats"]] == [inc.id]
    client.cookies.clear()
    _op(client, "view-thr", "viewer", [A])
    hq = next(s for s in _sites(client)["sites"] if s["name"] == "Acme HQ")
    assert hq["state"] == "warn"                    # NextDNS lapsed; the Black is hidden
    assert hq["incident"] is None and "relay" not in json.dumps(hq)
    store.ack(A, inc.id, by="1")
    build.invalidate()
    hq = next(s for s in _sites(client)["sites"] if s["name"] == "Acme HQ")
    assert hq["state"] == "black"
    assert hq["reason"].startswith("Urgent security incident: your IT provider is responding")
    assert hq["incident"]["status_neutral"].endswith("is responding")
    assert set(hq["incident"]) == {"ref", "tier", "status_neutral", "opened_at", "actions"}
    hq.pop("key")
    hq["incident"].pop("ref")                        # opaque hex
    text = json.dumps(hq).lower()
    for word in ("ws-01", "relay-young", "b6", "acked"):
        assert word not in text, word


# ---------------------------------------------------------------------------
# v0.17.1 — DNS block tuning (Rick, 2026-10-06) through the API
# ---------------------------------------------------------------------------

def _dns_rollup(slug: str, profile: str, at: datetime, *, high: int, medium: int = 0,
                reasons: dict | None = None) -> None:
    from apps.octo.adapters.nextdns import store as nd_store

    nd_store.upsert_hourly(slug, nd_store.HourlyRow(
        at.strftime("%Y-%m-%dT%H:00:00Z"), profile, 500, 0, high + medium,
        500 - high - medium, high, medium, 0, 0, reasons or {}))


def test_a1_dns_blocks_are_a_counted_notice_vendor_free_for_the_client(fl):
    client, _uf, _nd = fl
    _dns_rollup(C, "p-dental", NOW, high=2, medium=1,
                reasons={"threat-intelligence-feeds": 2, "nrd": 1})
    build.invalidate()
    _op(client, "ana-dns", "analyst", [C])
    (site,) = _sites(client)["sites"]
    assert site["state"] == "notice"                 # a green pin: the count shown
    sec = site["layers"]["security"]
    assert sec["reasons"][0]["text"] == ("3 threats blocked today — top: threat-intelligence "
                                         "domain ×2, newly registered domain ×1")
    client.cookies.clear()
    _op(client, "view-dns", "viewer", [C])
    (site,) = _sites(client)["sites"]
    sec = site["layers"]["security"]
    assert sec["reasons"][0]["text"] == "3 threats blocked by DNS protection today"
    text = json.dumps(site).lower()
    for word in VENDOR_WORDS + ("threat-intelligence", "newly registered", "top:"):
        assert word not in text, word
    assert "dns_top_reasons" not in sec["data"] and "dns_flagged_devices" not in sec["data"]


def test_a5_threats_stopped_this_week_is_the_operators_scoped_headline(fl):
    client, _uf, _nd = fl
    for day in range(3):
        _dns_rollup(A, "p-acme", NOW - timedelta(days=day, hours=1), high=2)
        _dns_rollup(C, "p-dental", NOW - timedelta(days=day, hours=1), high=1, medium=1)
    _dns_rollup(C, "p-dental", NOW - timedelta(days=10), high=50)       # not this week
    _dns_rollup(C, "p-dental", NOW, high=3, reasons={"csam": 3})        # B7's, never here
    build.invalidate()
    _op(client, "root-week", "super_admin")
    assert _sites(client)["threats_stopped_week"] == 12
    client.cookies.clear()
    _op(client, "ana-week", "analyst", [C])
    assert _sites(client)["threats_stopped_week"] == 6                  # its scope only
    client.cookies.clear()
    _op(client, "view-week", "viewer", [C])
    assert _sites(client)["threats_stopped_week"] is None               # unchanged wording
