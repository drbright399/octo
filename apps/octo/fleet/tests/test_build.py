"""The fleet model over a REAL data root (registry, tenant stores) with the
pollers' read side faked (`FakeManager`): what sits on which site, location
precedence through the build, stale = unknown, the per-layer sources, the
time bound, the cache — and a 40-site fixture fleet for a render/perf check.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.datto import site_ids
from apps.octo.adapters.nextdns import store as nd_store
from apps.octo.adapters.unifi import store as uf_store
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch
from apps.octo.fleet import build, locations, sources
from apps.octo.fleet import state as fs
from apps.octo.fleet.tests.fixtures import (
    FakeManager,
    FakeNextDnsPoller,
    FakeUnifiPoller,
    dns_state,
    fleet_site,
    scope,
    stamp_tier_worker,
)
from apps.octo.instances import create_instance, poller_state, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.instances.vendor_contact import ContactReporter
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401
from apps.octo.threat import store

# Set again by the fixture: a module-level time taken at import is minutes
# old by the time a full suite reaches these tests — and stale data reads
# (correctly) as unknown.
NOW = datetime.now(timezone.utc).replace(microsecond=0)
A, B, C, D = "acme-corp", "example-bakery", "example-dental", "example-diner"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


@pytest.fixture
def fleet(bedrock_root, monkeypatch):  # noqa: F811
    global NOW
    NOW = datetime.now(timezone.utc).replace(microsecond=0)
    from apps.octo.adapters.datto.tests.fake_datto import CREDS as DT
    from apps.octo.adapters.nextdns.tests.fake_nextdns import CREDS as ND
    from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import CREDS as RC
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS as UF

    monkeypatch.setenv(build.CACHE_ENV, "0")
    entity_db.reset_schema_cache()
    switch.reset()
    vendor_contact.reset()
    build.invalidate()
    for slug, name in ((A, "Acme Corp"), (B, "Example Bakery"), (C, "Example Dental"),
                       (D, "Example Diner")):
        create_client(slug, name, kind="client")
    uf = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                         credentials_dict=dict(UF), instance_config={})
    nd = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                         credentials_dict=dict(ND), instance_config={})
    rc = create_instance(vendor_slug="rocketcyber", display_name="RocketCyber",
                         credentials_dict=dict(RC), instance_config={})
    # The fake API URL is not Datto's '<platform>-api' form: no derived portal
    # base — an admin-entered one (a fixture host) gives the Datto link.
    dt = create_instance(vendor_slug="datto", display_name="Datto RMM",
                         credentials_dict=dict(DT), instance_config={
                             "vendor_links": {"portal_base_url": "https://fixture.rmm.datto.com"}})
    tenant_map.set_mappings(uf.id, [TenantMapping(scope(1), A, "Acme HQ", "manual"),
                                    TenantMapping(scope(2), A, "Acme Annex", "manual"),
                                    TenantMapping(scope(3), B, "Bakery", "manual")])
    tenant_map.set_mappings(nd.id, [TenantMapping("p-acme1", A, "Acme DNS 1", "manual"),
                                    TenantMapping("p-acme2", A, "Acme DNS 2", "manual"),
                                    TenantMapping("p-dental", C, "Dental DNS", "manual")])
    tenant_map.set_mappings(rc.id, [TenantMapping("rc-1", A, "Acme", "manual")])
    tenant_map.set_mappings(dt.id, [TenantMapping("ds-dental", C, "Dental", "manual")])
    mgr = FakeManager()
    mgr.pollers[uf.id] = FakeUnifiPoller(at=NOW - timedelta(minutes=2), sites={
        scope(1): fleet_site(1, name="Acme HQ"),
        scope(2): fleet_site(2, name="Acme Annex", located=False),
        scope(3): fleet_site(3, name="Bakery"),
        scope(9): fleet_site(9, name="Somebody's home lab"),        # unmapped
    })
    mgr.pollers[nd.id] = FakeNextDnsPoller(states={
        "p-acme1": dns_state("p-acme1", A, "active", NOW - timedelta(minutes=3)),
        "p-acme2": dns_state("p-acme2", A, "active", NOW - timedelta(minutes=3)),
        "p-dental": dns_state("p-dental", C, "lapsed", NOW - timedelta(minutes=3),
                              name="Dental DNS"),
    })
    ContactReporter(rc.id, what="test").ok()
    store.reset_schema_cache()
    sources.reset_incident_cache()
    stamp_tier_worker()
    yield mgr, {"unifi": uf, "nextdns": nd, "rocketcyber": rc, "datto": dt}
    switch.reset()
    vendor_contact.reset()
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()


def _by_name(model: build.FleetModel) -> dict[str, build.SiteEntry]:
    return {e.name: e for e in model.sites}


def _rc_event(slug: str, iid: int, status: str, at: datetime) -> None:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        payload = json.dumps({"id": iid, "status": status, "title": f"Incident {iid}"})
        conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256, summary) VALUES (?, 'rocketcyber', NULL, "
            "'rocketcyber.incident', 'high', ?, ?, ?)",
            (iso(at), payload, f"sha-{iid}-{status}", f"RocketCyber incident {iid} — {status}"))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Sites, layers, sources
# ---------------------------------------------------------------------------

def test_sites_tenants_and_what_sits_where(fleet):
    mgr, inst = fleet
    model = build.build(mgr, now=NOW)
    sites = _by_name(model)
    assert set(sites) == {"Acme HQ", "Acme Annex", "Bakery", "Example Dental"}
    assert model.unmapped_unifi_sites == 1                     # the home lab: counted only
    hq, annex, bakery, dental = (sites[n] for n in ("Acme HQ", "Acme Annex", "Bakery",
                                                    "Example Dental"))
    assert hq.kind == annex.kind == bakery.kind == "unifi" and dental.kind == "tenant"
    assert hq.tenant_sites == 2 and dental.tenant_sites == 1
    # Acme: switch off → both profiles tenant-level, on each site; RC on each.
    for e in (hq, annex):
        sec = e.layers["security"]
        assert [p["profile_id"] for p in sec.data["dns_profiles"]] == ["p-acme1", "p-acme2"]
        assert sec.data["dns_scope"] == "tenant" and sec.data["open_incidents"] == 0
    assert bakery.layers["security"].data.get("dns_profiles") is None
    assert bakery.layers["security"].data.get("open_incidents") is None
    # Dental: NextDNS only, lapsed → a protection gap, Yellow (re-tier row
    # 16); Datto mapped, the switch off — its device list is read anyway
    # (v0.17.2, D) but none has been read yet.
    assert dental.verdict.state == fs.WARN
    assert fs.reason_line(dental.verdict) == "NextDNS lapsed (Dental DNS)"
    assert dental.layers["network"].present is False
    assert dental.layers["endpoints"].present is False
    assert dental.datto_note == "no Datto inventory read yet"
    assert D not in {e.tenant_slug for e in model.sites}       # no source at all
    # Deep links: NextDNS (per profile). UniFi: the fixture consoles' host ids
    # ('F1X7…:…') are not UniFi's '<hex>:<digits>' — no link rather than one
    # with '%3A' (which the portal answers "Access denied"); a real-shaped
    # one: test_unifi_link_keeps_the_host_ids_colon.
    vendors = [link.vendor for link in hq.links]
    assert "unifi" not in vendors and vendors.count("nextdns") == 2
    assert not any("%3A" in link.url for e in model.sites for link in e.links)
    assert any(link.url == "https://my.nextdns.io/p-acme1/logs" for link in hq.links)
    # Sorted worst first.
    assert model.sites[0].verdict.state == fs.WARN
    assert [fs.RANK[e.verdict.state] for e in model.sites] == \
        sorted((fs.RANK[e.verdict.state] for e in model.sites), reverse=True)


def test_location_precedence_through_the_build(fleet):
    mgr, _ = fleet
    locations.set_override(A, 41.3, -100.7, "Acme main office", actor=1)
    locations.set_override(C, 41.4, -100.6, "Dental office", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    # The tenant override is a FALLBACK (042): the console's own location
    # beats it; a site without one takes it.
    assert sites["Acme HQ"].location.source == "unifi"
    assert sites["Acme Annex"].location.source == "manual"       # none reported → fallback
    assert sites["Acme Annex"].location.label == "Acme main office"
    assert sites["Example Dental"].location.source == "manual"   # no UniFi at all
    assert sites["Bakery"].location.source == "unifi"
    locations.clear_override(C)
    assert _by_name(build.build(mgr, now=NOW))["Example Dental"].location is None


def test_a_site_override_wins_and_is_per_site(fleet):
    """A console states away from its client is corrected per SITE; a
    multi-site client's sites are never collapsed onto one point."""
    mgr, _ = fleet
    locations.set_override(A, 41.3, -100.7, "Acme main office", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    hq_key, annex_key = sites["Acme HQ"].key, sites["Acme Annex"].key
    locations.set_site_override(hq_key, A, 41.5, -100.5, "Acme HQ (corrected)", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    hq = sites["Acme HQ"]
    assert (hq.location.lat, hq.location.lng, hq.location.source) == (41.5, -100.5, "site")
    assert hq.unifi["console_location"].source == "unifi"          # still shown to the editor
    assert sites["Acme Annex"].location.source == "manual"         # its own fallback
    locations.set_site_override(annex_key, A, 41.6, -100.4, "Acme Annex", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    assert {(e.location.lat, e.location.source) for e in (sites["Acme HQ"],
                                                          sites["Acme Annex"])} == \
        {(41.5, "site"), (41.6, "site")}
    # A pin set for ANOTHER tenant (the site was re-mapped since) is ignored.
    locations.set_site_override(hq_key, B, 41.7, -100.3, "stale", actor=1)
    assert _by_name(build.build(mgr, now=NOW))["Acme HQ"].location.source == "unifi"
    # A tenant-level entry (no UniFi) takes a site pin too.
    dental = sites["Example Dental"]
    locations.set_site_override(dental.key, C, 41.2, -100.9, "Dental front desk", actor=1)
    assert _by_name(build.build(mgr, now=NOW))["Example Dental"].location.source == "site"
    assert locations.clear_site_override(dental.key) is True
    assert _by_name(build.build(mgr, now=NOW))["Example Dental"].location is None


def test_stale_and_missing_unifi_data_is_unknown(fleet):
    mgr, inst = fleet
    poller = mgr.pollers[inst["unifi"].id]
    poller.at = NOW - timedelta(minutes=20)                      # > 2 polls of 5 min
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Bakery"].layers["network"].state == fs.UNKNOWN
    assert sites["Bakery"].verdict.state == fs.UNKNOWN            # never ok
    # The poller not running: mapped sites are still listed — unknown.
    del mgr.pollers[inst["unifi"].id]
    sites = _by_name(build.build(mgr, now=NOW))
    bakery = next(e for e in sites.values() if e.tenant_slug == B)
    assert bakery.layers["network"].state == fs.UNKNOWN
    assert bakery.verdict.state == fs.UNKNOWN and bakery.location is None


def test_ips_threats_and_rocketcyber_from_the_stores(fleet):
    mgr, _ = fleet
    hour = NOW.strftime("%Y-%m-%dT%H:00:00Z")
    claims = [uf_store.Claim(f"k{n}", hour, "ips_threat", f"10.20.0.{n}|ET X|blocked",
                             iso(NOW), {"n": n}) for n in (1, 2)]
    uf_store.claim(B, scope(3), claims)
    uf_store.claim(B, scope(3), [uf_store.Claim("old", "2020-01-01T00:00:00Z", "ips_threat",
                                                "x|y|detected", "2020-01-01T00:00:00Z", {})])
    nd_store.upsert_hourly(A, nd_store.HourlyRow(hour, "p-acme1", 500, 0, 9, 491, 2, 1, 4, 2,
                                                 {}))
    _rc_event(A, 7, "open", NOW - timedelta(hours=2))
    _rc_event(A, 8, "open", NOW - timedelta(hours=3))
    _rc_event(A, 8, "resolved", NOW - timedelta(hours=1))        # latest version wins
    sites = _by_name(build.build(mgr, now=NOW))
    bakery = sites["Bakery"]
    assert bakery.verdict.state == fs.WARN
    assert fs.reason_line(bakery.verdict) == "2 IPS blocks today"  # the 2020 hit is out
    hq = sites["Acme HQ"]
    sec = hq.layers["security"]
    assert sec.data["dns_threats_24h"] == 3 and sec.data["open_incidents"] == 1
    # v0.17.1 (was N8): 2 HIGH + 1 MEDIUM block → ONE counted notice (a block
    # is DNS protection doing its job); RocketCyber open → Yellow.
    assert hq.verdict.state == fs.WARN
    assert fs.reason_line(hq.verdict) == "1 open RocketCyber incident"
    assert (fs.NOTICE, "3 threats blocked today") in \
        [(r.state, r.text) for r in sec.reasons]


def test_entity_links_put_a_profile_and_datto_on_their_site(fleet):
    mgr, inst = fleet
    switch.set_mode(A, "on")
    switch.set_mode(C, "shadow")
    tdb = entity_db.TenantDB.for_tenant(A)
    now = iso(NOW)
    with tdb.write() as conn:
        for sid, label in (("st_hq", "Acme HQ"), ("st_annex", "Acme Annex")):
            conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                         "updated_at) VALUES (?, ?, 'unifi', ?, 'test', ?)",
                         (sid, label, now, now))
        for sid, vendor, ref in (("st_hq", "unifi", scope(1)), ("st_annex", "unifi", scope(2)),
                                 ("st_hq", "nextdns", "p-acme1")):
            conn.execute(
                "INSERT INTO site_vendor_ref (site_id, vendor, adapter_instance_id, "
                "vendor_scope_id, state, score, rule_id, rule_version, inputs_sha256, "
                "valid_from, decided_by, decided_at, created_at) VALUES (?, ?, 0, ?, "
                "'confirmed', 100, 'operator', 1, 'h', ?, 'operator:1', ?, ?)",
                (sid, vendor, ref, now, now, now))
    # Dental (shadow): its Datto inventory is read.
    with entity_db.TenantDB.for_tenant(C).write() as conn:
        for n, (dtype, online) in enumerate((("Server", 0), ("Desktop", 0), ("Desktop", 1))):
            conn.execute(
                "INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
                "device_type, online, first_seen_at, updated_at) VALUES (?, ?, 'ds-dental', ?, "
                "?, ?, ?, ?)", (inst["datto"].id, f"dev-{n}", f"PC-{n}", dtype, online, now, now))
    sites = _by_name(build.build(mgr, now=NOW))
    hq = sites["Acme HQ"].layers["security"].data
    annex = sites["Acme Annex"].layers["security"].data
    assert [p["profile_id"] for p in hq["dns_profiles"]] == ["p-acme1", "p-acme2"]
    assert [p["profile_id"] for p in annex["dns_profiles"]] == ["p-acme2"]   # unlinked only
    assert hq["dns_scope"] == "tenant" and annex["dns_scope"] == "tenant"
    end = sites["Example Dental"].layers["endpoints"]
    assert end.present and end.state == fs.WARN
    assert end.data == {"agents_total": 3, "agents_online": 1, "agents_offline": 2,
                        "servers_offline": 1}
    (datto,) = [link for link in sites["Example Dental"].links if link.vendor == "datto"]
    # No numeric id learned for the site yet: the portal's home, labelled so.
    assert datto.url == "https://fixture.rmm.datto.com/" and datto.verified is False
    assert datto.label == "Open Datto RMM (home)"


# ---------------------------------------------------------------------------
# "Open in" (2026-10-08: UniFi opened "Access denied", Datto its home page)
# ---------------------------------------------------------------------------

# Synthetic, but UniFi's console host id shape: hex, ':', digits.
REAL_SHAPED = "FA4E" + "0" * 52 + "C0DE:1000000042"
DATTO = "https://fixture.rmm.datto.com"


def test_unifi_link_keeps_the_host_ids_colon(fleet):
    mgr, inst = fleet
    sc = f"{REAL_SHAPED}/site-r01"
    tenant_map.set_mappings(inst["unifi"].id, [TenantMapping(sc, A, "Acme HQ", "manual")])
    mgr.pollers[inst["unifi"].id] = FakeUnifiPoller(at=NOW - timedelta(minutes=1), sites={
        sc: _console_site(sc, 1, "Acme HQ")})
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    (link,) = [x for x in hq.links if x.vendor == "unifi"]
    assert link.url == f"https://unifi.ui.com/consoles/{REAL_SHAPED}/network/default/dashboard"
    assert link.verified is True and link.label == "Open in UniFi Site Manager"


def test_datto_links_open_each_sites_own_page(fleet):
    mgr, inst = fleet
    dt = inst["datto"]
    tenant_map.set_mappings(dt.id, [TenantMapping("ds-dental", C, "Dental", "manual"),
                                    TenantMapping("ds-dental-2", C, "Dental annex", "manual"),
                                    TenantMapping("ds-dental-3", C, "Dental lab", "manual")])
    # Nothing learned yet: the portal home, ONCE (not once per site).
    dental = _by_name(build.build(mgr, now=NOW))["Example Dental"]
    assert [(x.label, x.url, x.verified) for x in dental.links if x.vendor == "datto"] == \
        [("Open Datto RMM (home)", f"{DATTO}/", False)]
    # What the inventory poller stored (the store is re-validated on read).
    poller_state.save(dt.id, site_ids.STATE_KEY, {
        "at": iso(NOW), "mapped": ["ds-dental", "ds-dental-2", "ds-dental-3"], "sites": {
            "ds-dental": {"id": "4101", "name": "Example Dental — Main St."},
            "ds-dental-2": {"id": "4102"},            # no name: the mapping's label
            "ds-dental-3": {"id": "41a"},             # not an id: that one stays home
            "ds-other": {"id": "4199", "name": "Not mapped"}}})
    model = build.build(mgr, now=NOW)
    dental = _by_name(model)["Example Dental"]
    assert [(x.label, x.url, x.verified) for x in dental.links if x.vendor == "datto"] == [
        ("Open in Datto RMM — Dental annex", f"{DATTO}/site/4102/dental-annex", True),
        ("Open in Datto RMM — Example Dental — Main St.",
         f"{DATTO}/site/4101/example-dental-main-st", True),
        ("Open Datto RMM (home)", f"{DATTO}/", False)]
    assert not any("4199" in x.url for e in model.sites for x in e.links)
    # Every id known: no home link at all.
    poller_state.save(dt.id, site_ids.STATE_KEY, {
        "at": iso(NOW), "mapped": ["ds-dental"], "sites": {"ds-dental": {"id": "4101"}}})
    tenant_map.set_mappings(dt.id, [TenantMapping("ds-dental", C, "Dental", "manual")])
    dental = _by_name(build.build(mgr, now=NOW))["Example Dental"]
    assert [x.url for x in dental.links if x.vendor == "datto"] == [f"{DATTO}/site/4101/dental"]


def test_a_datto_site_linked_to_a_unifi_site_is_offered_on_that_site_only(fleet):
    mgr, inst = fleet
    dt = inst["datto"]
    switch.set_mode(A, "on")
    tenant_map.set_mappings(dt.id, [TenantMapping("ds-dental", C, "Dental", "manual"),
                                    TenantMapping("ds-acme-hq", A, "HQ office", "manual"),
                                    TenantMapping("ds-acme-all", A, "Acme", "manual")])
    site_ids.save(dt.id, mapped=["ds-acme-hq", "ds-acme-all"], now=NOW, found={
        "ds-acme-hq": {"id": "4201", "name": "Acme HQ office"},
        "ds-acme-all": {"id": "4202", "name": "Acme"}})
    now = iso(NOW)
    with entity_db.TenantDB.for_tenant(A).write() as conn:
        conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                     "updated_at) VALUES ('st_hq', 'Acme HQ', 'unifi', ?, 'test', ?)",
                     (now, now))
        for vendor, ref in (("unifi", scope(1)), ("datto", "ds-acme-hq")):
            conn.execute(
                "INSERT INTO site_vendor_ref (site_id, vendor, adapter_instance_id, "
                "vendor_scope_id, state, score, rule_id, rule_version, inputs_sha256, "
                "valid_from, decided_by, decided_at, created_at) VALUES ('st_hq', ?, 0, ?, "
                "'confirmed', 100, 'operator', 1, 'h', ?, 'operator:1', ?, ?)",
                (vendor, ref, now, now, now))
    sites = _by_name(build.build(mgr, now=NOW))
    assert [x.url for x in sites["Acme HQ"].links if x.vendor == "datto"] == \
        [f"{DATTO}/site/4202/acme", f"{DATTO}/site/4201/acme-hq-office"]
    assert [x.url for x in sites["Acme Annex"].links if x.vendor == "datto"] == \
        [f"{DATTO}/site/4202/acme"]                                   # the unlinked one only


def test_buoy_layer_on_the_tenants_sites(fleet):
    mgr, _ = fleet
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute("INSERT INTO buoys (slug, hostname, last_heartbeat_at, uptime_sec, "
                    "interval_sec, services_json) VALUES (?, 'buoy-bakery', ?, 100, 60, ?)",
                    (B, iso(NOW), json.dumps({"tailscaled": "active", "suricata": "failed"})))
        reg.execute("INSERT INTO buoys (slug, hostname, last_heartbeat_at, uptime_sec, "
                    "interval_sec, services_json) VALUES (?, 'buoy-diner', ?, 100, 60, ?)",
                    (D, iso(NOW - timedelta(hours=3)), json.dumps({"tailscaled": "active"})))
        reg.commit()
    finally:
        reg.close()
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Bakery"].layers["buoy"].state == fs.WARN
    diner = sites["Example Diner"]                               # a buoy-only tenant
    assert diner.kind == "tenant" and diner.layers["buoy"].state == fs.WARN


# ---------------------------------------------------------------------------
# Time bound, cache, a 40-site fleet
# ---------------------------------------------------------------------------

def test_time_bound_lists_everything_partially(fleet):
    mgr, _ = fleet
    ticks = iter(range(0, 10_000, 100))
    model = build.build(mgr, now=NOW, budget_sec=50, clock=lambda: next(ticks) / 1.0)
    assert model.partial is True
    assert {e.name for e in model.sites} == {"Acme HQ", "Acme Annex", "Bakery",
                                             "Example Dental"}
    late = [e for e in model.sites if e.partial]
    assert late
    for e in late:
        sec = e.layers["security"]
        if sec.present:
            assert sec.state == fs.UNKNOWN and "time budget" in sec.reasons[0].text


def test_the_cache_and_its_invalidation(fleet, monkeypatch):
    mgr, _ = fleet
    monkeypatch.setenv(build.CACHE_ENV, "30")
    build.invalidate()
    first = build.get_model(mgr)
    assert build.get_model(mgr) is first
    build.invalidate()
    assert build.get_model(mgr) is not first


def test_a_40_site_fleet_builds_fast(fleet):
    mgr, inst = fleet
    slugs = []
    mappings = []
    sites = {}
    for n in range(10, 50):
        slug = f"example-client-{n}"
        create_client(slug, f"Example Client {n}", kind="client")
        slugs.append(slug)
        mappings.append(TenantMapping(scope(n), slug, f"Example Site {n}", "manual"))
        kw = {}
        if n % 7 == 0:
            kw["gateways_offline"] = 1
        elif n % 5 == 0:
            kw["devices_offline"] = 2
        sites[scope(n)] = fleet_site(n, located=n % 9 != 0, **kw)
    tenant_map.set_mappings(inst["unifi"].id, mappings)
    mgr.pollers[inst["unifi"].id] = FakeUnifiPoller(at=NOW - timedelta(minutes=1), sites=sites)
    started = time.monotonic()
    model = build.build(mgr, now=NOW)
    took = time.monotonic() - started
    assert len([e for e in model.sites if e.kind == "unifi"]) == 40
    assert not model.partial and took < 3.0, took
    mine = [e for e in model.sites if e.tenant_slug in slugs]
    states = [e.verdict.state for e in mine]
    assert states.count(fs.WARN) == 13                                  # 7s + 5s (not 35)
    assert sum(1 for e in mine if e.location is None) == 4             # 18, 27, 36, 45


# ---------------------------------------------------------------------------
# Review round: NextDNS freshness per state, multi-site consoles, stale
# links, configured intervals
# ---------------------------------------------------------------------------

def _security_reasons(entry: build.SiteEntry) -> list[tuple[str, str]]:
    return [(r.state, r.text) for r in entry.layers["security"].reasons]


def test_nextdns_pending_and_missing_show_their_state_not_unknown(fleet):
    """Shaped like the real poller: a PENDING profile never had a security
    check (`last_check_at` None) — its status read is what is current; a
    MISSING one keeps an old check and is re-probed every few hours."""
    mgr, inst = fleet
    nd = mgr.pollers[inst["nextdns"].id]
    nd.states["p-acme1"] = dns_state("p-acme1", A, "pending", NOW - timedelta(hours=2),
                                     name="Acme DNS 1")
    nd.states["p-acme2"] = dns_state("p-acme2", A, "active", NOW - timedelta(hours=1),
                                     name="Acme DNS 2", missing=True,
                                     checked_at=NOW - timedelta(hours=3))
    nd.states["p-dental"] = dns_state("p-dental", C, "lapsed", NOW - timedelta(hours=1),
                                      name="Dental DNS", missing=True,
                                      checked_at=NOW - timedelta(hours=3))
    assert nd.states["p-acme1"]["last_check_at"] is None
    sites = _by_name(build.build(mgr, now=NOW))
    reasons = _security_reasons(sites["Acme HQ"])
    assert (fs.WARN, "NextDNS pending (Acme DNS 1)") in reasons
    assert (fs.WARN, "NextDNS profile missing (Acme DNS 2)") in reasons
    assert not any(state == fs.UNKNOWN for state, _ in reasons), reasons
    # Lapsed and missing (an active profile NextDNS stopped showing): a
    # protection gap, Yellow.
    assert sites["Example Dental"].verdict.state == fs.WARN
    assert fs.reason_line(sites["Example Dental"].verdict) == "NextDNS lapsed (Dental DNS)"
    # A pending profile whose status read is older than two pending checks
    # (6 h each) IS unknown.
    nd.states["p-acme1"] = dns_state("p-acme1", A, "pending", NOW - timedelta(hours=13),
                                     name="Acme DNS 1")
    reasons = _security_reasons(_by_name(build.build(mgr, now=NOW))["Acme HQ"])
    assert (fs.UNKNOWN, "NextDNS Acme DNS 1: not checked recently") in reasons


def test_a_stretched_nextdns_cycle_is_aged_against_its_real_round(fleet):
    mgr, inst = fleet
    nd = mgr.pollers[inst["nextdns"].id]
    nd.states["p-dental"] = dns_state("p-dental", C, "active", NOW - timedelta(minutes=20),
                                      name="Dental DNS")
    dental = _by_name(build.build(mgr, now=NOW))["Example Dental"]
    assert dental.verdict.state == fs.UNKNOWN                    # 20 min > 2 × 5 min
    nd.security_round_sec = 900.0                                # the cycle stretches
    dental = _by_name(build.build(mgr, now=NOW))["Example Dental"]
    assert dental.verdict.state == fs.OK


HOSTED = "F1X7H0570000000000000000000000000000000000000000000000000:100070000"
OWN = "F1X7C0470000000000000000000000000000000000000000000000000:100071000"


def _console_site(sc: str, n: int, name: str) -> dict:
    site = fleet_site(n, name=name)
    site["scope"], site["host_id"] = sc, sc.split("/")[0]
    return site


def test_a_multi_site_consoles_location_is_not_each_sites(fleet):
    mgr, inst = fleet
    shared_a, shared_b = f"{HOSTED}/site-a01", f"{HOSTED}/site-b01"
    own_1, own_2 = f"{OWN}/site-c01", f"{OWN}/site-c02"
    tenant_map.set_mappings(inst["unifi"].id, [
        TenantMapping(shared_a, A, "Acme remote", "manual"),
        TenantMapping(shared_b, B, "Bakery remote", "manual"),
        TenantMapping(own_1, C, "Dental front", "manual"),
        TenantMapping(own_2, C, "Dental back", "manual")])
    mgr.pollers[inst["unifi"].id] = FakeUnifiPoller(at=NOW - timedelta(minutes=1), sites={
        shared_a: _console_site(shared_a, 61, "Acme remote"),
        shared_b: _console_site(shared_b, 61, "Bakery remote"),
        own_1: _console_site(own_1, 62, "Dental front"),
        own_2: _console_site(own_2, 62, "Dental back")})
    locations.set_override(A, 41.3, -100.7, "Acme remote office", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    # A console shared by two clients: the override wins; no override → no pin.
    assert sites["Acme remote"].location.source == "manual"
    assert sites["Acme remote"].location.label == "Acme remote office"
    assert sites["Bakery remote"].location is None
    # One client's own two-site console: its location is that client's —
    # and it beats the tenant fallback (042).
    assert sites["Dental front"].location.source == "unifi"
    assert sites["Dental back"].location.source == "unifi"
    locations.set_override(C, 41.4, -100.6, "Dental office", actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Dental front"].location.source == "unifi"
    assert sites["Dental front"].unifi["console_sites"] == 2
    # Each site of that console is pinned on its own by a site override.
    locations.set_site_override(sites["Dental back"].key, C, 41.45, -100.55, "Back office",
                                actor=1)
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Dental back"].location.source == "site"
    assert sites["Dental front"].location.source == "unifi"
    # A single-site console beats the tenant fallback; a site pin beats both.
    tenant_map.set_mappings(inst["unifi"].id, [TenantMapping(scope(1), A, "Acme HQ", "manual")])
    mgr.pollers[inst["unifi"].id] = FakeUnifiPoller(at=NOW - timedelta(minutes=1), sites={
        scope(1): fleet_site(1, name="Acme HQ")})
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    assert hq.location.source == "unifi"
    locations.set_site_override(hq.key, A, 41.9, -100.1, "Acme HQ (corrected)", actor=1)
    assert _by_name(build.build(mgr, now=NOW))["Acme HQ"].location.source == "site"


def test_a_link_to_a_site_not_on_the_fleet_leaves_the_profile_tenant_level(fleet):
    mgr, _inst = fleet
    switch.set_mode(A, "on")
    gone = "F1X7G0NE000000000000000000000000000000000000000000000000:100099998/site-x01"
    now = iso(NOW)
    with entity_db.TenantDB.for_tenant(A).write() as conn:
        conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                     "updated_at) VALUES ('st_gone', 'Old office', 'unifi', ?, 'test', ?)",
                     (now, now))
        for vendor, ref in (("unifi", gone), ("nextdns", "p-acme1")):
            conn.execute(
                "INSERT INTO site_vendor_ref (site_id, vendor, adapter_instance_id, "
                "vendor_scope_id, state, score, rule_id, rule_version, inputs_sha256, "
                "valid_from, decided_by, decided_at, created_at) VALUES ('st_gone', ?, 0, ?, "
                "'confirmed', 100, 'operator', 1, 'h', ?, 'operator:1', ?, ?)",
                (vendor, ref, now, now, now))
    sites = _by_name(build.build(mgr, now=NOW))
    for name in ("Acme HQ", "Acme Annex"):
        sec = sites[name].layers["security"].data
        assert [p["profile_id"] for p in sec["dns_profiles"]] == ["p-acme1", "p-acme2"], name
        assert sec["dns_scope"] == "tenant"


def test_rocketcyber_and_datto_freshness_use_the_configured_intervals(fleet, monkeypatch):
    from apps.octo.instances import manager as instance_manager
    from apps.octo.instances import vendor_contact as vc

    mgr, inst = fleet
    rc_id = inst["rocketcyber"].id
    real = vc.snapshot
    monkeypatch.setattr(vc, "snapshot", lambda iid: dict(
        real(iid), last_ok_at=iso(NOW - timedelta(minutes=20))) if iid == rc_id else real(iid))
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    assert (fs.UNKNOWN, "RocketCyber not polled recently") in _security_reasons(hq)
    instance_manager.update_instance_config(rc_id, {"poll_interval_sec": 1800})
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    assert (fs.UNKNOWN, "RocketCyber not polled recently") not in _security_reasons(hq)
    # Datto: an inventory read 70 minutes ago is stale at the 30-minute
    # default (two reads + slack), fresh for an instance that reads its
    # inventory hourly.
    switch.set_mode(C, "shadow")
    at = iso(NOW - timedelta(minutes=70))
    with entity_db.TenantDB.for_tenant(C).write() as conn:
        conn.execute(
            "INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
            "device_type, online, first_seen_at, updated_at) VALUES (?, 'dev-1', 'ds-dental', "
            "'PC-1', 'Desktop', 1, ?, ?)", (inst["datto"].id, at, at))
    end = _by_name(build.build(mgr, now=NOW))["Example Dental"].layers["endpoints"]
    assert end.state == fs.UNKNOWN
    instance_manager.update_instance_config(inst["datto"].id, {"inventory_interval_sec": 3600})
    end = _by_name(build.build(mgr, now=NOW))["Example Dental"].layers["endpoints"]
    assert end.state == fs.OK
    assert sources.rocketcyber_interval(None) == sources.DEFAULT_RC_INTERVAL_SEC
    assert sources.datto_inventory_interval(None) == sources.DATTO_INVENTORY_INTERVAL_SEC


# ---------------------------------------------------------------------------
# The quiet tier: regional collapse
# ---------------------------------------------------------------------------

def _issue_site(n: int, *, asn: int = 64500, located: bool = True, count: int = 1,
                port_up: bool = True) -> dict:
    site = fleet_site(n, name=f"Example Site {n}", asn=asn, located=located, port_up=port_up)
    site["stats"].update({"issues_recent": True, "issues_recent_count": count})
    return site


def _regional_build(mgr, inst, sites: dict[int, dict], *, at=None) -> build.FleetModel:
    tenant_map.set_mappings(inst["unifi"].id, [
        TenantMapping(scope(n), A if n % 2 else B, f"Example Site {n}", "manual")
        for n in sites])
    mgr.pollers[inst["unifi"].id] = FakeUnifiPoller(
        at=at or NOW - timedelta(minutes=1), sites={scope(n): s for n, s in sites.items()})
    return build.build(mgr, now=NOW)


def test_one_isp_blipping_at_three_sites_is_one_regional_notice(fleet):
    mgr, inst = fleet
    # Recurring (would warn) at three UNLOCATED sites on one ASN.
    model = _regional_build(mgr, inst, {n: _issue_site(n, located=False, count=3)
                                        for n in (11, 12, 13)})
    sites = _by_name(model)
    for n in (11, 12, 13):
        net = sites[f"Example Site {n}"].layers["network"]
        assert net.state == fs.NOTICE and net.data["internet_issues_regional"] is True
        assert net.reasons[0].text.startswith("internet trouble on this ISP")
        assert "nearby" not in net.reasons[0].neutral                # no other clients' count
    (group,) = model.regional
    assert group["kind"] == "isp" and group["asn"] == 64500 and len(group["members"]) == 3


def test_three_nearby_sites_on_different_isps_are_an_area(fleet):
    mgr, inst = fleet
    model = _regional_build(mgr, inst, {11: _issue_site(11, asn=64501),
                                        12: _issue_site(12, asn=64502),
                                        13: _issue_site(13, asn=64503)})
    assert [g["kind"] for g in model.regional] == ["area"]
    for n in (11, 12, 13):
        net = _by_name(model)[f"Example Site {n}"].layers["network"]
        assert net.state == fs.NOTICE and "nearby sites" in net.reasons[0].text


def test_two_sites_are_not_regional(fleet):
    mgr, inst = fleet
    model = _regional_build(mgr, inst, {11: _issue_site(11, count=3), 12: _issue_site(12)})
    sites = _by_name(model)
    assert model.regional == []
    assert sites["Example Site 11"].layers["network"].state == fs.WARN     # recurring
    assert sites["Example Site 12"].layers["network"].state == fs.NOTICE   # a blip


def test_the_regional_cap_never_hides_a_wan_down(fleet):
    mgr, inst = fleet
    model = _regional_build(mgr, inst, {11: _issue_site(11, port_up=False),
                                        12: _issue_site(12), 13: _issue_site(13)})
    down = _by_name(model)["Example Site 11"]
    assert down.verdict.state == fs.WARN
    assert down.layers["network"].reasons[0].text == "WAN down"
    assert down.layers["network"].data["internet_issues_regional"] is True


def test_stale_sites_are_never_regional_nor_a_notice(fleet):
    mgr, inst = fleet
    model = _regional_build(mgr, inst, {n: _issue_site(n) for n in (11, 12, 13)},
                            at=NOW - timedelta(minutes=30))
    assert model.regional == []
    for n in (11, 12, 13):
        assert _by_name(model)[f"Example Site {n}"].verdict.state == fs.UNKNOWN


# ---------------------------------------------------------------------------
# Tier Black slice 1: the threat layer through the build
# ---------------------------------------------------------------------------

def _open(slug: str, *, tier: str = "black", key: str, site_key=None, device=None,
          at=None, summary: str = "someone is controlling the screen") -> store.Incident:
    from apps.octo.threat import rules

    rule = rules.human_rule(tier)
    out = store.open_incident(
        slug, tier=tier, rule_id=rule.id, rule_version=rule.version, key=key, summary=summary,
        scope="device" if device else "site" if site_key else "tenant", opened_by="1",
        reason="declared in a test", site_key=site_key, device_ref=device, device_label=device,
        now=at or NOW - timedelta(minutes=10))
    assert out.incident is not None
    return out.incident


def test_an_incident_sits_on_its_home_site_only(fleet):
    mgr, _ = fleet
    hq_key = build.site_key("unifi", scope(1))
    _open(A, key="k-home", site_key=hq_key, device="ws-01")
    sites = _by_name(build.build(mgr, now=NOW))
    hq, annex = sites["Acme HQ"], sites["Acme Annex"]
    assert hq.verdict.state == fs.BLACK and hq.layers["threat"].state == fs.BLACK
    assert fs.reason_line(hq.verdict).startswith(
        "BLACK: someone is controlling the screen on ws-01 (10 min, unacknowledged)")
    assert annex.layers["threat"].state == fs.OK and annex.verdict.state != fs.BLACK
    assert [i.id for i in hq.incidents] and not annex.incidents


def test_an_incident_of_unknown_location_is_painted_on_every_tenant_site(fleet):
    mgr, _ = fleet
    _open(A, tier="red", key="k-unknown", device="ws-02")           # no site key
    _open(A, tier="red", key="k-gone", site_key="u-00000000000000000000")   # not on the fleet
    sites = _by_name(build.build(mgr, now=NOW))
    for name in ("Acme HQ", "Acme Annex"):
        layer = sites[name].layers["threat"]
        assert layer.state == fs.BAD and len(sites[name].incidents) == 2
        assert all(r.text.endswith("— device location unknown") for r in layer.reasons
                   if r.state == fs.BAD)
    assert sites["Bakery"].layers["threat"].state == fs.OK


def test_the_sort_is_rank_derived_unacked_black_first_then_oldest(fleet):
    mgr, _ = fleet
    hq, annex = build.site_key("unifi", scope(1)), build.site_key("unifi", scope(2))
    bakery = build.site_key("unifi", scope(3))
    _open(A, key="k-annex", site_key=annex, at=NOW - timedelta(minutes=50))
    acked = _open(A, key="k-hq", site_key=hq, at=NOW - timedelta(minutes=90))
    store.ack(A, acked.id, by="1", now=NOW - timedelta(minutes=80))
    _open(B, key="k-bakery", site_key=bakery, at=NOW - timedelta(minutes=20))
    model = build.build(mgr, now=NOW)                              # no KeyError on black
    order = [e.name for e in model.sites[:3]]
    # Unacknowledged Blacks first (oldest first), then the acknowledged one.
    assert order == ["Acme Annex", "Bakery", "Acme HQ"]
    assert all(e.verdict.state == fs.BLACK for e in model.sites[:3])
    banner = model.threat_incidents
    assert [t["acked"] for t in banner] == [False, False, True]
    assert banner[0]["site_keys"] == [annex] and banner[0]["tier"] == "black"


def test_a_closed_incident_leaves_a_watch_then_a_notice(fleet):
    mgr, _ = fleet
    hq = build.site_key("unifi", scope(1))
    inc = _open(A, tier="red", key="k-watch", site_key=hq)
    store.close(A, inc.id, by="1", code="remediated", text="cleaned up",
                now=NOW - timedelta(minutes=5))
    model = build.build(mgr, now=NOW)
    assert _by_name(model)["Acme HQ"].layers["threat"].state == fs.WARN    # the watch
    assert model.threat_incidents == []                             # not open: no banner
    store.close(A, _open(A, tier="red", key="k-fp", site_key=hq).id, by="1",
                code="false_positive", text="a printer", now=NOW - timedelta(days=9))
    # A false positive gets no watch; a TP close past its watch is a notice.
    stamp_tier_worker(NOW + timedelta(days=8))
    later = _by_name(build.build(mgr, now=NOW + timedelta(days=8)))["Acme HQ"]
    assert later.layers["threat"].state == fs.NOTICE


def test_an_unreadable_store_keeps_the_last_known_incidents(fleet, monkeypatch):
    mgr, _ = fleet
    hq = build.site_key("unifi", scope(1))
    _open(A, key="k-floor", site_key=hq)
    assert _by_name(build.build(mgr, now=NOW))["Acme HQ"].verdict.state == fs.BLACK

    def broken(slug, now):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "open_and_recent", broken)
    entry = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    assert entry.verdict.state == fs.BLACK                          # never dropped
    assert entry.layers["threat"].data["stale_since"]
    # A tenant never read before reads unknown — never ok.
    sources.reset_incident_cache()
    assert _by_name(build.build(mgr, now=NOW))["Bakery"].layers["threat"].state == fs.UNKNOWN


def test_a_stale_tier_worker_is_unknown_unless_an_incident_is_open(fleet):
    mgr, _ = fleet
    stamp_tier_worker(NOW - timedelta(minutes=30))
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Bakery"].layers["threat"].state == fs.UNKNOWN
    assert sites["Bakery"].verdict.state == fs.UNKNOWN
    _open(B, key="k-open", site_key=build.site_key("unifi", scope(3)))
    sites = _by_name(build.build(mgr, now=NOW))
    assert sites["Bakery"].layers["threat"].state == fs.BLACK
    assert sites["Bakery"].verdict.state == fs.BLACK


def test_n7_inbound_ips_blocks_from_the_ledger_are_a_notice(fleet):
    mgr, _ = fleet
    hour = NOW.strftime("%Y-%m-%dT%H:00:00Z")
    uf_store.claim(B, scope(3), [
        uf_store.Claim("in1", hour, "ips_threat", "aa:bb|2010935|inbound|blocked", iso(NOW),
                       {}),
        uf_store.Claim("in2", hour, "ips_threat", "aa:bb|2010936|inbound|blocked", iso(NOW),
                       {})])
    assert sources.ips_counts(B, NOW - timedelta(hours=24)) == {scope(3): (0, 2, 2)}
    bakery = _by_name(build.build(mgr, now=NOW))["Bakery"]
    assert bakery.layers["security"].state == fs.NOTICE
    assert fs.reason_line(bakery.verdict) == "2 inbound IPS blocks today"


def test_n8_a_known_benign_probe_is_taken_out_of_high(fleet):
    mgr, _ = fleet
    hour = NOW.strftime("%Y-%m-%dT%H:00:00Z")
    # 3 HIGH in the roll-up — 3 of them the known-benign probe (rule 1).
    nd_store.upsert_hourly(A, nd_store.HourlyRow(hour, "p-acme1", 100, 0, 3, 97, 3, 0, 0, 0,
                                                 {}))
    bucket = nd_store.Bucket(key="kb1", hour=hour, profile_id="p-acme1",
                             reason_id="threat-intelligence-feeds", root="kb:1",
                             device="dev-1")
    nd_store.count_hits(A, [(bucket, iso(NOW), f"line-{n}", "goooogle.example")
                            for n in range(3)], arrived=iso(NOW))
    counts = sources.dns_threats(A, ["p-acme1"], NOW - timedelta(hours=24))
    # v0.17.1 (fixer): `total` is the THREAT count — known-benign out, the
    # same number the drawer and the notice show.
    assert counts["p-acme1"] == sources.DnsCounts(total=0, high=0, medium=0, benign=3)
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    assert hq.layers["security"].state == fs.NOTICE
    assert "3 known-benign DNS blocks today" in \
        [r.text for r in hq.layers["security"].reasons]


def test_n8_never_subtracts_a_real_high_block_away(fleet):
    """The known-benign rule files its blocks at LOW: DAY buckets. One that
    began before the window holds hits from before it; the roll-up of the
    current hour may lag the ledger. Neither may turn a real HIGH block into
    a "known-benign" notice."""
    mgr, _ = fleet
    hour = NOW.strftime("%Y-%m-%dT%H:00:00Z")
    today = NOW.strftime("%Y-%m-%dT00:00:00Z")
    yesterday = (NOW - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
    # 21 HIGH in the window's roll-up: 20 probes today + 1 real block.
    nd_store.upsert_hourly(A, nd_store.HourlyRow(hour, "p-acme1", 100, 0, 21, 79, 21, 0, 0,
                                                 0, {}))
    kb = "threat-intelligence-feeds"
    for key, start, n in (("kb-today", today, 20), ("kb-yday", yesterday, 30)):
        bucket = nd_store.Bucket(key=key, hour=start, profile_id="p-acme1", reason_id=kb,
                                 root="kb:1", device="dev-1", span=nd_store.SPAN_DAY)
        nd_store.count_hits(A, [(bucket, iso(NOW), f"{key}-{i}", "goooogle.example")
                                for i in range(n)], arrived=iso(NOW))
    counts = sources.dns_threats(A, ["p-acme1"], NOW - timedelta(hours=24))
    assert counts["p-acme1"].high == 1                     # yesterday's 30 not taken out
    hq = _by_name(build.build(mgr, now=NOW))["Acme HQ"]
    # The real block is COUNTED (v0.17.1: a counted notice, not Yellow).
    assert "1 threat blocked today (+20 known-benign not counted)" in \
        [r.text for r in hq.layers["security"].reasons]
    # A real HIGH the roll-up has not caught yet: the ledger's own count.
    real = nd_store.Bucket(key="real-1", hour=hour, profile_id="p-acme2", reason_id=kb,
                           root="bad.example", device="dev-2")
    nd_store.count_hits(A, [(real, iso(NOW), "real-line", "bad.example")], arrived=iso(NOW))
    counts = sources.dns_threats(A, ["p-acme2"], NOW - timedelta(hours=24))
    assert counts["p-acme2"].high == 1


def test_a_datto_only_tenant_with_entity_off_is_unknown_never_green(fleet):
    """P8 / re-tier row 27: the threat layer is always present, so it must
    never stand in for data — a tenant whose only source is Datto with
    entity resolution off (every tenant today) has NO health layer: unknown
    "no data source reports on this site yet", for the client too."""
    mgr, inst = fleet
    tenant_map.set_mappings(inst["datto"].id, [
        TenantMapping("ds-dental", C, "Dental", "manual"),
        TenantMapping("ds-diner", D, "Diner", "manual")])
    diner = next(e for e in build.build(mgr, now=NOW).sites if e.tenant_slug == D)
    assert diner.layers["threat"].present and diner.layers["threat"].state == fs.OK
    assert not any(diner.layers[n].present for n in fs.HEALTH_LAYERS)
    assert diner.verdict.state == fs.UNKNOWN
    assert fs.reason_line(diner.verdict) == "no data source reports on this site yet"
    # An open incident still outranks it.
    _open(D, key="k-diner", site_key=build.site_key("tenant", D))
    diner = next(e for e in build.build(mgr, now=NOW).sites if e.tenant_slug == D)
    assert diner.verdict.state == fs.BLACK


def test_the_banner_names_who_acknowledged_it(fleet):
    from apps.octo.auth import operators

    mgr, _ = fleet
    op = operators.create_operator(username="alice", email="alice@example.test",
                                   role="analyst", scope_slugs=["*"], actor="system",
                                   reason="fixture")
    inc = _open(A, key="k-named", site_key=build.site_key("unifi", scope(1)))
    store.ack(A, inc.id, by=str(op["operator_id"]), now=NOW - timedelta(minutes=5))
    (item,) = build.build(mgr, now=NOW).threat_incidents
    assert item["acked_by"] == str(op["operator_id"]) and item["acked_by_name"] == "alice"


def test_an_intake_fault_never_reads_as_a_running_correlator(fleet, monkeypatch):
    from apps.octo.threat import intake

    mgr, _ = fleet

    def broken(*_a, **_kw):
        raise RuntimeError("registry busy")

    # Blindness unreadable: the worker's own heartbeat still decides.
    monkeypatch.setattr(intake, "blind_sources", broken)
    bakery = _by_name(build.build(mgr, now=NOW))["Bakery"]
    assert bakery.layers["threat"].state == fs.OK
    # The heartbeat unreadable: stale, never "running".
    monkeypatch.setattr(intake, "worker_fresh", broken)
    bakery = _by_name(build.build(mgr, now=NOW))["Bakery"]
    assert bakery.layers["threat"].state == fs.UNKNOWN
    assert "threat correlator not running" in [r.text for r in bakery.layers["threat"].reasons]
