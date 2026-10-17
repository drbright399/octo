"""Entity resolution through the real HTTP routes and real sign-in: the alert
panel ("Where / Device / Why?"), the review queue, operator decisions (audited,
operator wins), the per-tenant switch, the fallback site + asserted egress,
and the known-benign registry. One tenant per call; a tenant outside the
caller's scope is the same 404 as one that does not exist."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch, tokens
from apps.octo.entity.feeders.unifi import UniFiEntityFeeder
from apps.octo.instances import create_instance, known_benign, tenant_map
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_dashboard_throughput import _login

PW = "pw1234567890"
A, B = "acme-corp", "example-bakery"
HOST = "F1X7A0000000000000000000000000000000000000000000000000A001:100000001"
SCOPE = f"{HOST}/f1x7517e0000000000000001"
T0 = datetime(2026, 10, 1, 14, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@pytest.fixture
def ent(auth_client, auth_data_root, monkeypatch, tmp_path):
    from apps.octo.adapters.nextdns.tests.fake_nextdns import CREDS as ND
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS as UF
    from apps.octo.credentials import ensure_key_file

    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "cred-key.env"))
    ensure_key_file()
    entity_db.reset_schema_cache()
    tokens.reset_cache()
    switch.reset()
    known_benign.reset()
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    uf = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                         credentials_dict=dict(UF), instance_config={})
    nd = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                         credentials_dict=dict(ND), instance_config={})
    tenant_map.set_mappings(uf.id, [TenantMapping(SCOPE, A, "Site A", "manual")])
    tenant_map.set_mappings(nd.id, [TenantMapping("abc123", A, "Site A office", "manual")])
    switch.set_mode(A, "on")
    feeder = UniFiEntityFeeder()
    feeder.on_networks(A, SCOPE, [
        # scan-sensitive: allow[ip-private] synthetic site LAN; the resolver treats doc ranges as public
        {"_id": "n1", "name": "Office", "purpose": "corporate", "ip_subnet": "10.20.0.1/24",
         "dhcpd_dns_enabled": False}])
    for minute in (10, 15, 20):
        at = T0.replace(minute=minute)
        feeder.on_site_report(A, SCOPE, {
            "polled_at": iso(at), "name": "Site A", "report_fresh": True, "host_connected": True,
            "gateway_online": True, "wans": [{"wan": "WAN", "external_ip": "203.0.113.129",
                                              "nat_kind": "direct"}]})
        feeder.on_log_progress(A, SCOPE, {"scanned_to": iso(at)})
        feeder.on_client_snapshot(A, SCOPE, {
            "polled_at": iso(at), "complete": True, "gateway_online": True,
            "clients": [{"id": f"c{n}", "name": f"FRONT-DESK-{n}", "mac": f"00:00:5e:00:53:{n:02x}",
                         "ip": f"10.20.0.{n}", "type": "WIRED",
                         "connected_at": iso(T0.replace(hour=8))} for n in (11, 12)]})
    yield auth_client, uf, nd
    switch.reset()
    known_benign.reset()


def _op(client, name: str, role: str, scope=None) -> dict:
    op = client.provision_operator(name, PW, role=role, athena_role=role, scope_slugs=scope)
    _login(client, op)
    return op


def _event(slug: str = A) -> int:
    from apps.octo.entity.tests.conftest import nextdns_block, store_event

    at = T0.replace(minute=17, second=5)
    return store_event(slug, "nextdns", "nextdns.security_block", nextdns_block(at), iso(at))


def _audit(action: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id",
                            (action,)).fetchall()
    finally:
        conn.close()


def test_the_alert_panel_where_device_and_why(ent):
    client, _uf, _nd = ent
    _op(client, "ana", "analyst")
    eid = _event()
    r = client.get(f"/api/v1/entity/{A}/events/{eid}/resolution")
    assert r.status_code == 200 and r.json()["resolved"] is False      # not swept yet
    r = client.post(f"/api/v1/entity/{A}/events/{eid}/resolve")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["visible"] is True and body["where"]["label"] == "Site A"
    assert body["where"]["basis"] in ("located", "policy", "both")
    assert body["device"]["tier"] == "candidate" and body["device"]["n_candidates"] == 2
    # Device names are shown (not masked); the answer itself stores none.
    assert sorted(c["label"].split(" ")[0] for c in body["candidates"]) == \
        ["FRONT-DESK-11", "FRONT-DESK-12"]
    assert body["why"] and any("public address" in w for w in body["why"])
    assert body["enrichment"]["name"] == "athena.entity_resolution"
    assert _audit("entity_resolve")


def test_shadow_off_scope_and_pre_040_answers(ent, auth_data_root):
    client, _uf, _nd = ent
    _op(client, "ana2", "analyst", scope=[B])
    eid = _event()
    assert client.get(f"/api/v1/entity/{A}/events/{eid}/resolution").status_code == 404
    r = client.get(f"/api/v1/entity/{B}/status")
    assert r.status_code == 200 and r.json()["mode"] == "off"
    # AT-G1: a tenant whose entities.db does not exist answers unresolved, never a 500.
    db = auth_data_root / "clients" / B / "entities.db"
    if db.exists():
        db.unlink()
    r = client.get(f"/api/v1/entity/{B}/events/1/resolution")
    assert r.status_code == 200 and r.json()["resolved"] is False
    assert client.get(f"/api/v1/entity/{B}/review").json()["resolved"] is False
    switch.set_mode(A, "shadow")
    _op(client, "boss", "super_admin")
    from apps.octo.entity.resolver import Resolver

    Resolver.for_tenant(A).resolve_event(eid)
    r = client.get(f"/api/v1/entity/{A}/events/{eid}/resolution")
    assert r.json()["visible"] is False and r.json()["resolved"] is True
    r = client.get(f"/api/v1/entity/{A}/events/{eid}/resolution?include_shadow=true")
    assert r.json()["visible"] is True


def test_viewers_are_refused_and_only_admins_switch_modes(ent):
    client, _uf, _nd = ent
    _op(client, "vee", "viewer", scope=[A])
    assert client.get(f"/api/v1/entity/{A}/status").status_code == 403
    _op(client, "ana3", "analyst")
    r = client.put(f"/api/v1/entity/{A}/mode", json={"mode": "off", "reason": "pause it"})
    assert r.status_code == 403
    _op(client, "adm", "admin")
    r = client.put(f"/api/v1/entity/{A}/mode", json={"mode": "shadow", "reason": "a week of shadow"})
    assert r.status_code == 200 and r.json()["before"] == "on"
    (row,) = _audit("entity_resolution_mode")
    assert json.loads(row["after_state"]) == {"mode": "shadow"} and row["client_slug"] == A


def test_review_queue_confirm_and_reject_are_audited_and_operator_wins(ent):
    from apps.octo.entity import sites as st
    from apps.octo.entity.db import TenantDB

    client, _uf, nd = ent
    op = _op(client, "ana4", "analyst")
    with TenantDB.for_tenant(A).write() as conn:
        site_id = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
        p = st.propose(conn, site_id=site_id, vendor="nextdns", instance_id=nd.id,
                       scope_id="abc123", state="suggested", score=85, rule_id="L-EGRESS",
                       rule_version=1, evidence={"coverage": {"share": 0.93}},
                       now=iso(T0))
    review = client.get(f"/api/v1/entity/{A}/review").json()
    assert [s["id"] for s in review["sites"]] == [p.ref_id] and review["names"] == []
    assert client.post(f"/api/v1/entity/{A}/links/site/{p.ref_id}/reject",
                       json={"reason": "x"}).status_code == 422          # a reason is required
    r = client.post(f"/api/v1/entity/{A}/links/site/{p.ref_id}/confirm",
                    json={"reason": "it is the office profile"})
    assert r.status_code == 200 and r.json()["link"]["state"] == "confirmed"
    assert r.json()["link"]["decided_by"] == f"operator:{op['id']}"
    (row,) = _audit("entity_link_confirm")
    assert row["client_slug"] == A and row["reason"] == "it is the office profile"
    # A rule can no longer touch it.
    with TenantDB.for_tenant(A).connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE site_vendor_ref SET state = 'suggested', decided_by = 'rule:x' "
                         "WHERE id = ?", (p.ref_id,))
    r = client.post(f"/api/v1/entity/{A}/links/site/{p.ref_id}/reject",
                    json={"reason": "wrong after all", "expires_days": 30})
    assert r.status_code == 200 and r.json()["link"]["state"] == "rejected"
    with TenantDB.for_tenant(A).connect() as conn:
        supp = conn.execute("SELECT * FROM link_suppression").fetchall()
    assert len(supp) == 1 and supp[0]["expires_at"]


def test_a_site_without_unifi_and_an_asserted_egress(ent):
    client, _uf, nd = ent
    _op(client, "adm2", "admin")
    r = client.post(f"/api/v1/entity/{B}/sites", json={
        "label": "Bakery", "anchor": "nextdns", "vendor": "nextdns", "vendor_scope_id": "abc123",
        "reason": "no UniFi there"})
    assert r.status_code == 422                       # abc123 is not mapped to B
    r = client.post(f"/api/v1/entity/{A}/sites", json={
        "label": "Warehouse", "anchor": "operator", "reason": "second office, no UniFi"})
    assert r.status_code == 200
    site_id = r.json()["site_id"]
    bad = client.post(f"/api/v1/entity/{A}/sites/{site_id}/egress",
                      # scan-sensitive: allow[ip-private] synthetic LAN address: the refusal under test is RFC 1918
                      json={"addr": "10.1.2.3", "reason": "lan address"})
    assert bad.status_code == 422
    ok = client.post(f"/api/v1/entity/{A}/sites/{site_id}/egress",
                     json={"addr": "198.51.100.44", "reason": "the ISP's static address"})
    assert ok.status_code == 200
    sites_ = client.get(f"/api/v1/entity/{A}/sites").json()["sites"]
    wh = next(s for s in sites_ if s["label"] == "Warehouse")
    assert [e["source"] for e in wh["egress"]] == ["operator"]
    (row,) = _audit("entity_egress_assert")
    assert "198.51.100.44" not in (row["after_state"] or "")   # the class, not the address


def test_known_benign_registry_read_validate_create_disable(ent):
    client, _uf, _nd = ent
    _op(client, "ana5", "analyst")
    rules = client.get("/api/v1/admin/known-benign").json()
    assert [r["label"] for r in rules] == ["Samsung connectivity probe (google typosquat)"]
    assert client.post("/api/v1/admin/known-benign", json={
        "match_kind": "regex", "pattern": "x.example", "reasons": ["dga"], "label": "nope",
        "reason": "analyst try"}).status_code == 403
    _op(client, "adm3", "admin")
    bad = client.post("/api/v1/admin/known-benign", json={
        "match_kind": "regex", "pattern": "(a|b)+.example", "reasons": ["dga"],
        "label": "bad pattern", "reason": "should fail"})
    assert bad.status_code == 422
    ok = client.post("/api/v1/admin/known-benign", json={
        "match_kind": "suffix", "pattern": "probe.example", "reasons": ["typosquatting"],
        "label": "Printer vendor probe", "reason": "known benign printer check"})
    assert ok.status_code == 200 and len(ok.json()) == 2
    rid = ok.json()[1]["id"]
    off = client.put(f"/api/v1/admin/known-benign/{rid}", json={
        "match_kind": "suffix", "pattern": "probe.example", "reasons": ["typosquatting"],
        "label": "Printer vendor probe", "enabled": False, "reason": "not benign after all"})
    assert off.status_code == 200 and off.json()[1]["enabled"] is False
    assert len(_audit("known_benign_rule_create")) == 1
    assert len(_audit("known_benign_rule_update")) == 1


def test_routing_conflicts_resolve_sticks_accept_suppresses_reopen_undoes(ent):
    """Review round 3, item 2, through the routes: Resolve stays resolved on
    the next passes; "Accept as expected" (routing only) suppresses the check
    for the profile; Reopen ends the acceptance. Each is audited."""
    from apps.octo.entity import linkrules
    from apps.octo.entity.db import TenantDB

    client, _uf, _nd = ent
    _op(client, "ana5", "analyst")
    with TenantDB.for_tenant(A).write() as conn:
        for d in range(1, 5):
            day = (T0 - timedelta(days=d)).strftime("%Y-%m-%d")
            conn.execute("INSERT INTO ndns_ip_day (profile_id, day, egress_queries, total_queries, "
                         "egress_ips, read_at) VALUES ('abc123', ?, 0, 5000, '[]', ?)",
                         (day, iso(T0)))
        assert linkrules.routing_sanity(conn, A, iso(T0)) == 1
    (c,) = client.get(f"/api/v1/entity/{A}/review").json()["conflicts"]
    assert c["kind"] == "routing" and c["resolution"] is None
    r = client.post(f"/api/v1/entity/{A}/conflicts/{c['id']}/resolve",
                    json={"reason": "looked at it"})
    assert r.status_code == 200
    with TenantDB.for_tenant(A).write() as conn:
        for minute in range(1, 6):
            assert linkrules.routing_sanity(conn, A, iso(T0 + timedelta(minutes=minute))) == 0
    assert client.get(f"/api/v1/entity/{A}/review").json()["conflicts"] == []
    assert json.loads(_audit("entity_conflict_resolve")[0]["after_state"])["resolution"] == \
        "resolved"
    # A non-routing conflict cannot be accepted.
    with TenantDB.for_tenant(A).write() as conn:
        from apps.octo.entity import sites as st

        other, _ = st.observe_conflict(conn, "site_conflict", "event:nextdns:9",
                                       {"policy_site": "a", "located_site": "b"}, iso(T0))
    r = client.post(f"/api/v1/entity/{A}/conflicts/{other}/accept",
                    json={"reason": "it is fine"})
    assert r.status_code == 409
    # Reopen the routing card (new evidence), then accept it as expected.
    with TenantDB.for_tenant(A).write() as conn:
        st.reopen(conn, c["id"], now=iso(T0))
    r = client.post(f"/api/v1/entity/{A}/conflicts/{c['id']}/accept",
                    json={"reason": "the branch office has no UniFi", "expires_days": 90})
    assert r.status_code == 200 and r.json()["expires_at"]
    review = client.get(f"/api/v1/entity/{A}/review").json()
    assert [x["id"] for x in review["accepted"]] == [c["id"]]
    assert [x["id"] for x in review["conflicts"]] == [other]
    with TenantDB.for_tenant(A).write() as conn:
        assert linkrules.routing_accepted(conn, "abc123", iso(T0)) == "active"
        assert linkrules.routing_sanity(conn, A, iso(T0 + timedelta(days=1))) == 0
    assert _audit("entity_conflict_accept")[0]["reason"] == "the branch office has no UniFi"
    # Stop accepting: the suppression ends now, the card is open (no new notice).
    r = client.post(f"/api/v1/entity/{A}/conflicts/{c['id']}/reopen",
                    json={"reason": "the branch got UniFi"})
    assert r.status_code == 200
    review = client.get(f"/api/v1/entity/{A}/review").json()
    assert review["accepted"] == [] and c["id"] in [x["id"] for x in review["conflicts"]]
    with TenantDB.for_tenant(A).connect() as conn:
        assert linkrules.routing_accepted(conn, "abc123",
                                          iso(datetime.now(timezone.utc))) == "expired"
    assert _audit("entity_conflict_reopen")


def test_switching_off_then_on_restarts_the_sweep_at_the_newest_event(ent):
    """Review round 3, item 4: PUT /mode off → on starts the sweep at the
    newest event (the alerts stored while it was off have no lookups behind
    them) — never at 0, never at an old cursor."""
    from apps.octo.entity.db import TenantDB
    from apps.octo.entity.tests.conftest import nextdns_block, store_event
    from apps.octo.entity.worker import EntityWorker

    client, _uf, _nd = ent
    _op(client, "adm9", "admin")
    _event()
    EntityWorker().run_once()

    def cursor() -> int:
        with TenantDB.for_tenant(A).connect() as conn:
            return conn.execute("SELECT last_event_id FROM resolver_cursor").fetchone()[0]

    first = cursor()
    assert client.put(f"/api/v1/entity/{A}/mode", json={"mode": "off", "reason": "pause"}
                      ).status_code == 200
    at = T0.replace(minute=40)
    while_off = store_event(A, "nextdns", "nextdns.security_block",
                            nextdns_block(at, vid="while-off"), iso(at))
    assert while_off > first and cursor() == first
    assert client.put(f"/api/v1/entity/{A}/mode", json={"mode": "on", "reason": "resume"}
                      ).status_code == 200
    assert cursor() == while_off
