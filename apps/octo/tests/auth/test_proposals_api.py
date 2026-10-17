"""Location proposals through the real HTTP routes and real sign-in: the
role matrix (admin / super_admin only; analysts and client users 403; a
scoped admin sees its tenants' proposals only — the rest is the same 404 as
none), the refresh (Autotask faked, mapped active companies only), the
lookup (mocked geocoder; the address never in the audit log), confirm (the
pin written with its provenance, audited before — and only onto what the
operator reviewed) and reject, and what the Fleet shows afterwards
(operators: "from Autotask, confirmed by …"; client users: nothing).
Made-up companies, Example streets, fictional towns."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.api.routers import proposals as proposals_router
from apps.octo.auth import audit
from apps.octo.client_provisioning import create_client
from apps.octo.entity import switch
from apps.octo.fleet import build, geocode, locations
from apps.octo.fleet.tests.fixtures import FakeManager, FakeUnifiPoller, fleet_site, scope
from apps.octo.instances import create_instance, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.proposals import site_location, store
from apps.octo.proposals.tests.test_site_location import FakeAutotask, company, location
from apps.octo.tests.auth.test_dashboard_throughput import _login

PW = "pw1234567890"
A, B, C = "acme-corp", "example-bakery", "example-dental"
VENDOR_WORDS = ("unifi", "autotask", "census", "proposal")


class Manager(FakeManager):
    """FakeManager plus the running Autotask instance the refresh uses."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[Any] = []
        self.adapters: dict[int, Any] = {}
        self.unifi_id = 0

    def list_running(self) -> list[Any]:
        return list(self.records)

    def running_adapter(self, instance_id: int) -> Any:
        if instance_id in self.adapters:
            return self.adapters[instance_id]
        return super().running_adapter(instance_id)


class _Adapter:
    def __init__(self, client: Any) -> None:
        self.client = client


def _autotask() -> FakeAutotask:
    return FakeAutotask(
        companies=[company(100, "Acme Corp", "1 Example Rd"),
                   company(200, "Example Bakery", "1 Example Road"),
                   company(300, "Example Dental", "5 Example Ln Suite 2", state="Texas",
                           zip_="75001")],
        locations=[location(11, 100, "Acme Annex", "9 Annex Rd")])


UNIFI_MAP = [TenantMapping(scope(1), A, "Acme HQ", "manual"),
             TenantMapping(scope(2), A, "Acme Annex", "manual"),
             TenantMapping(scope(3), B, "Bakery", "manual")]


@pytest.fixture
def px(auth_client, auth_data_root, monkeypatch, tmp_path):
    from apps.octo.adapters.unifi.tests.fake_unifi import CREDS as UF
    from apps.octo.credentials import ensure_key_file

    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "cred-key.env"))
    monkeypatch.setenv(build.CACHE_ENV, "0")
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(proposals_router, "_last_refresh_at", [])
    monkeypatch.setattr(geocode, "LIMITER", geocode.RateLimiter())
    ensure_key_file()
    switch.reset()
    vendor_contact.reset()
    build.invalidate()
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    create_client(C, "Example Dental", kind="client")
    uf = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                         credentials_dict=dict(UF), instance_config={})
    at = create_instance(vendor_slug="autotask", display_name="Autotask",
                         credentials_dict={"AUTOTASK_USERNAME": "api@example.test",
                                           "AUTOTASK_SECRET": "x", "AUTOTASK_INTEGRATION_CODE": "y",
                                           "AUTOTASK_ZONE_URL": "https://zone.example.test/"},
                         instance_config={})
    tenant_map.set_mappings(uf.id, UNIFI_MAP)
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.executemany("INSERT INTO autotask_tenant_company_map (adapter_instance_id, "
                         "tenant_slug, autotask_company_id) VALUES (?, ?, ?)",
                         [(at.id, A, 100), (at.id, B, 200), (at.id, C, 300)])
        conn.commit()
    finally:
        conn.close()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    mgr = Manager()
    mgr.unifi_id = uf.id
    mgr.pollers[uf.id] = FakeUnifiPoller(at=now - timedelta(minutes=2), sites={
        scope(1): fleet_site(1, name="Acme HQ"),
        scope(2): fleet_site(2, name="Acme Annex"),
        scope(3): fleet_site(3, name="Bakery"),
    })
    fake = _autotask()
    mgr.records.append(at)
    mgr.adapters[at.id] = _Adapter(fake)
    auth_client.app.state.instance_manager = mgr
    yield auth_client, fake, mgr
    switch.reset()
    vendor_contact.reset()
    build.invalidate()


def _op(client, name: str, role: str, scope_slugs=None) -> dict:
    client.cookies.clear()
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


def _audit_dump() -> str:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM audit_log"))
    finally:
        conn.close()


def _refresh(client) -> dict:
    proposals_router._last_refresh_at.clear()
    r = client.post("/api/v1/proposals/refresh")
    assert r.status_code == 200, r.text
    return r.json()


def _items(client, **params) -> dict:
    r = client.get("/api/v1/proposals", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _by_ref(body: dict) -> dict[str, dict]:
    return {p["source_ref"]: p for p in body["items"]}


def _site_key(client, name: str) -> str:
    sites = client.get("/api/v1/fleet/sites").json()["sites"]
    return next(s["key"] for s in sites if s["name"] == name)


def _seen(client, ref: str, key: Optional[str] = None) -> dict:
    """What the review shows for one proposal: the confirm's
    `expected_updated_at` / `expected_pin_set_at` for `key` (default: its
    target)."""
    body = _items(client)
    p = _by_ref(body)[ref]
    target = next(t for t in body["targets"][p["tenant_slug"]]
                  if t["key"] == (key or p["target_key"]))
    return {"expected_updated_at": p["updated_at"], "expected_pin_set_at": target["pin_set_at"]}


def test_only_admins_see_or_touch_proposals(px):
    client, _fake, _mgr = px
    for role in ("analyst", "viewer"):
        _op(client, f"{role}-p", role, [A] if role == "viewer" else None)
        assert client.get("/api/v1/proposals").status_code == 403
        assert client.get("/api/v1/proposals/summary").status_code == 403
        assert client.post("/api/v1/proposals/refresh").status_code == 403
        assert client.post("/api/v1/proposals/1/reject",
                           json={"reason": "no thanks"}).status_code == 403
        assert client.get("/api/v1/fleet/geocoder").status_code == 403
    _op(client, "adm-p", "admin")
    assert client.get("/api/v1/proposals").status_code == 200


def test_refresh_lists_grouped_by_tenant_with_targets_and_warnings(px):
    client, fake, _mgr = px
    _op(client, "adm-r", "admin")
    got = _refresh(client)
    assert got["open"] == 4 and got["summary"]["created"] == 4
    assert got["summary"]["locations"] == "read"
    assert fake.calls[0] == ("Companies", [100, 200, 300])          # mapped companies only
    (row,) = _audit("proposals_refresh")                            # before the read
    assert row["client_slug"] == "global" and json.loads(row["after_state"])["instances"]
    body = _items(client)
    assert body["open"] == 4 and body["geocoder"] == "census" and body["autotask"] is True
    assert body["last_refresh"]["locations"] == "read"
    refs = _by_ref(body)
    assert refs["company:100"]["target_key"] is None                    # pick a site
    assert refs["company:100"]["target_mode"] == "pick"
    assert refs["location:11"]["target_name"] == "Acme Annex"
    assert refs["company:200"]["target_name"] == "Bakery"
    assert refs["company:300"]["target_mode"] == "tenant"
    assert refs["company:300"]["label"] == "5 Example Ln Suite 2, Exampleton, TX 75001"
    shared = {f["code"]: f for f in refs["company:200"]["flags"]}["shared_address"]
    assert shared["tenants"] == ["Acme Corp"] and shared["others_hidden"] is False
    assert {t["name"] for t in body["targets"][A]} == {"Acme HQ", "Acme Annex"}
    (dental,) = body["targets"][C]
    assert {k: dental[k] for k in ("key", "name", "kind", "current", "pin_set_at")} == {
        "key": refs["company:300"]["target_key"], "name": "Example Dental", "kind": "tenant",
        "current": None, "pin_set_at": None}
    # Each target says what is there now (the console's location here).
    hq = next(t for t in body["targets"][A] if t["name"] == "Acme HQ")
    assert hq["current"]["source"] == "unifi" and hq["console"]["lat"] == hq["current"]["lat"]
    assert client.get("/api/v1/proposals/summary").json() == {"kind": "site_location",
                                                              "open": 4}
    # Refreshing again at once is throttled; nothing is proposed twice.
    assert client.post("/api/v1/proposals/refresh").status_code == 429
    assert _refresh(client)["summary"]["created"] == 0


def test_a_scoped_admin_sees_its_own_tenants_only(px):
    client, _fake, _mgr = px
    _op(client, "adm-all", "admin")
    _refresh(client)
    acme = _items(client, tenant=A)["items"]
    _op(client, "adm-b", "admin", [B])
    body = _items(client)
    assert [p["tenant_slug"] for p in body["items"]] == [B]
    shared = {f["code"]: f for f in body["items"][0]["flags"]}["shared_address"]
    assert shared["tenants"] == [] and shared["others_hidden"] is True  # never the name
    assert "Acme" not in json.dumps(body)
    assert client.get("/api/v1/proposals/summary").json()["open"] == 1
    for p in acme:
        pid = p["id"]
        assert client.post(f"/api/v1/proposals/{pid}/lookup").status_code == 404
        assert client.post(f"/api/v1/proposals/{pid}/reject",
                           json={"reason": "not mine"}).status_code == 404
        assert client.post(f"/api/v1/proposals/{pid}/confirm",
                           json={"lat": 41.0, "lng": -100.0, "reason": "x" * 5,
                                 "expected_updated_at": p["updated_at"],
                                 "expected_pin_set_at": None}).status_code == 404
    assert client.post("/api/v1/proposals/999/reject",
                       json={"reason": "nope"}).status_code == 404
    # A scoped refresh says nothing about the other tenants' counts.
    assert set(_refresh(client)["summary"]) == {"locations"}


def test_lookup_then_confirm_writes_the_pin_with_its_provenance(px, monkeypatch):
    client, _fake, _mgr = px
    adm = _op(client, "adm-c", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:200"]
    sent: list[str] = []

    def fake_lookup(address, **_kw):
        sent.append(address)
        return [geocode.Match(41.12, -101.0, "1 EXAMPLE RD, EXAMPLETON, IL, 00001")]

    monkeypatch.setattr(geocode, "lookup", fake_lookup)
    r = client.post(f"/api/v1/proposals/{p['id']}/lookup")
    assert r.status_code == 200, r.text
    assert sent == ["1 Example Road, Exampleton, IL 00001"]
    looked = r.json()["proposal"]
    assert looked["matches"][0]["label"].startswith("1 EXAMPLE RD")
    assert looked["matches"][0]["km_from_console"] < 25            # near the console
    assert looked["updated_at"] != p["updated_at"]                  # what the review now shows
    assert "Example R" not in _audit_dump()                         # never the address

    bakery = _site_key(client, "Bakery")
    seen = _seen(client, "company:200")
    assert seen["expected_updated_at"] == looked["updated_at"]
    for bad in ({"match_index": 0}, {"match_index": 0, "reason": ""},
                {"match_index": 0, "reason": "   "}, {"match_index": 0, "reason": " a \n "},
                {"match_index": 3, "reason": "verified"}, {"reason": "verified"},
                {"match_index": 0, "lat": 1.0, "lng": 1.0, "reason": "verified"},
                {"lat": 0.0, "lng": 0.0, "reason": "verified"},
                {"match_index": 0, "reason": "verified", "extra": 1}):
        assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                           json={**seen, **bad}).status_code == 422, bad
    # What the operator reviewed is part of the confirm.
    assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                       json={"match_index": 0, "reason": "verified"}).status_code == 422
    assert _audit("proposal_confirm") == [] and _audit("site_location_set") == []
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={**seen, "match_index": 0, "reason": "  verified with\tthe client "})
    assert r.status_code == 200, r.text
    done = r.json()
    assert done["status"] == "confirmed" and done["decided_by"] == "adm-c"
    assert done["decision_reason"] == "verified with the client"
    assert done["current"]["source"] == "site" and done["current"]["origin"] == "autotask"
    (confirmed,) = _audit("proposal_confirm")
    assert confirmed["target_kind"] == "proposal" and confirmed["client_slug"] == B
    assert confirmed["reason"] == "verified with the client"         # as recorded
    after = json.loads(confirmed["after_state"])
    assert after["target_key"] == bakery and after["lat"] == 41.12 and after["match_index"] == 0
    (pin_row,) = _audit("site_location_set")
    assert pin_row["target_id"] == bakery and json.loads(pin_row["after_state"])["origin"] == \
        "autotask"
    assert confirmed["id"] < pin_row["id"]
    # The Fleet: the pin, its provenance (operators).
    site = next(s for s in client.get("/api/v1/fleet/sites").json()["sites"]
                if s["name"] == "Bakery")
    assert site["location"] == {"lat": 41.12, "lng": -101.0,
                                "label": "1 Example Road, Exampleton, IL 00001",
                                "source": "site"}
    assert site["provenance"]["origin"] == "autotask" and site["provenance"]["by"] == "adm-c"
    editor = client.get(f"/api/v1/fleet/sites/{bakery}/location").json()
    assert editor["override"]["origin"] == "autotask"
    assert editor["override"]["set_by_name"] == "adm-c"
    assert editor["proposals"] == []                              # nothing open for it now
    # Decided: a second decision is a conflict.
    assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                       json={**seen, "match_index": 0, "reason": "again!"}).status_code == 409
    assert client.post(f"/api/v1/proposals/{p['id']}/reject",
                       json={"reason": "too late"}).status_code == 409
    assert client.post(f"/api/v1/proposals/{p['id']}/lookup").status_code == 409
    assert adm


def test_pick_a_site_and_only_the_tenants_own(px):
    client, _fake, _mgr = px
    _op(client, "adm-k", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:100"]
    hq = _site_key(client, "Acme HQ")
    body = {"lat": 41.3, "lng": -100.7, "reason": "front office, verified",
            **_seen(client, "company:100", hq)}
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm", json=body)
    assert r.status_code == 422 and "pick the site" in r.json()["message"]
    bakery = _site_key(client, "Bakery")
    assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                       json={**body, "target_key": bakery}).status_code == 422
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={**body, "target_key": hq, "label": "Acme front office"})
    assert r.status_code == 200, r.text
    assert r.json()["target_key"] == hq and r.json()["target_name"] == "Acme HQ"
    hq_site = next(s for s in client.get("/api/v1/fleet/sites").json()["sites"]
                   if s["name"] == "Acme HQ")
    assert hq_site["location"]["label"] == "Acme front office"


def test_a_confirm_never_overwrites_what_the_operator_did_not_see(px):
    client, _fake, _mgr = px
    _op(client, "adm-s", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:200"]
    bakery = _site_key(client, "Bakery")
    seen = _seen(client, "company:200")
    assert seen["expected_pin_set_at"] is None                          # "no pin" reviewed
    # Another admin pins the Bakery by hand meanwhile.
    r = client.put(f"/api/v1/fleet/sites/{bakery}/location",
                   json={"lat": 41.31, "lng": -100.71, "label": "Bakery (door)",
                         "reason": "checked on site"})
    assert r.status_code == 200, r.text
    body = {"lat": 41.3, "lng": -100.7, "target_key": bakery, "reason": "front office", **seen}
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm", json=body)
    assert r.status_code == 409 and "pin changed" in r.json()["message"]
    assert locations.get_site(bakery, B)["label"] == "Bakery (door)"   # never replaced
    assert _audit("proposal_confirm") == []                          # refused BEFORE the audit
    # A refresh changed the proposal meanwhile (its warnings: the new pin).
    _refresh(client)
    fresh = _seen(client, "company:200")
    assert fresh["expected_pin_set_at"] is not None
    assert fresh["expected_updated_at"] != seen["expected_updated_at"]
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={**body, "expected_pin_set_at": fresh["expected_pin_set_at"]})
    assert r.status_code == 409 and "changed since you loaded it" in r.json()["message"]
    assert _audit("proposal_confirm") == []
    # Reviewed as it is now: confirmed (replacing the hand-set pin knowingly).
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm", json={**body, **fresh})
    assert r.status_code == 200, r.text
    assert locations.get_site(bakery, B)["origin"] == "autotask"
    # A pick-a-site proposal is checked against the site it is confirmed for.
    q = _by_ref(_items(client))["company:100"]
    hq = _site_key(client, "Acme HQ")
    want = _seen(client, "company:100", hq)
    locations.set_site_override(hq, A, 41.3, -100.7, "HQ (door)", actor=1)
    r = client.post(f"/api/v1/proposals/{q['id']}/confirm",
                    json={**want, "lat": 41.3, "lng": -100.7, "target_key": hq,
                          "reason": "front office"})
    assert r.status_code == 409 and locations.get_site(hq, A)["label"] == "HQ (door)"


def test_a_change_that_fails_after_its_audit_says_so(px, monkeypatch):
    client, _fake, _mgr = px
    _op(client, "adm-x", "admin")
    _refresh(client)
    seen = _seen(client, "company:200")
    p = _by_ref(_items(client))["company:200"]

    def raced(*_a, **_k):
        raise store.ProposalError("this proposal was decided or changed meanwhile — reload")

    monkeypatch.setattr(site_location, "confirm", raced)
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={**seen, "lat": 41.2, "lng": -100.9, "reason": "verified on site"})
    assert r.status_code == 409
    (failed,) = _audit("proposal_confirm_failed")
    assert json.loads(failed["after_state"])["error"] == "CONFLICT"
    assert failed["id"] > _audit("site_location_set")[0]["id"]
    assert locations.get_site(_site_key(client, "Bakery"), B) is None

    monkeypatch.setattr(site_location, "reject", raced)
    assert client.post(f"/api/v1/proposals/{p['id']}/reject",
                       json={"reason": "a billing address"}).status_code == 409
    (failed,) = _audit("proposal_reject_failed")
    assert failed["client_slug"] == B and "nothing was written" in failed["reason"]


def test_no_audit_no_change(px, monkeypatch):
    client, fake, _mgr = px
    _op(client, "adm-y", "admin")
    _refresh(client)
    seen = _seen(client, "company:200")
    p = _by_ref(_items(client))["company:200"]
    bakery = _site_key(client, "Bakery")
    calls = len(fake.calls)

    def down(*_a, **_k):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit, "append", down)
    with pytest.raises(RuntimeError):
        client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={**seen, "lat": 41.2, "lng": -100.9, "reason": "verified"})
    with pytest.raises(RuntimeError):
        client.post(f"/api/v1/proposals/{p['id']}/reject", json={"reason": "billing"})
    proposals_router._last_refresh_at.clear()
    with pytest.raises(RuntimeError):
        client.post("/api/v1/proposals/refresh")
    assert store.get(p["id"]).status == "proposed"                    # nothing decided
    assert locations.get_site(bakery, B) is None                      # nothing pinned
    assert len(fake.calls) == calls                                     # Autotask never read


def test_reject_needs_a_reason_and_is_not_proposed_again(px):
    client, _fake, _mgr = px
    _op(client, "adm-j", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:300"]
    for bad in ({}, {"reason": "x"}, {"reason": "     "}, {"reason": "\t\n x \n"}):
        assert client.post(f"/api/v1/proposals/{p['id']}/reject", json=bad).status_code == 422
    assert _audit("proposal_reject") == []
    r = client.post(f"/api/v1/proposals/{p['id']}/reject",
                    json={"reason": "a billing address, not the office"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    (row,) = _audit("proposal_reject")
    assert row["client_slug"] == C and row["reason"] == "a billing address, not the office"
    assert json.loads(row["after_state"]) == {"status": "rejected"}
    assert _refresh(client)["summary"]["kept_rejected"] == 1
    assert "company:300" not in _by_ref(_items(client))
    decided = _by_ref(_items(client, status="decided"))
    assert decided["company:300"]["decision_reason"] == "a billing address, not the office"


def test_the_site_editor_hints_at_open_proposals(px):
    client, _fake, _mgr = px
    _op(client, "adm-h", "admin")
    _refresh(client)
    refs = _by_ref(_items(client))
    bakery = _site_key(client, "Bakery")
    hint = client.get(f"/api/v1/fleet/sites/{bakery}/location").json()["proposals"]
    assert hint == [{"id": refs["company:200"]["id"], "source": "autotask",
                     "label": "1 Example Road, Exampleton, IL 00001", "unassigned": False}]
    # A multi-site client's company address is for no site yet: every one of
    # its sites' editors mentions it (after the site's own).
    hq = client.get(f"/api/v1/fleet/sites/{_site_key(client, 'Acme HQ')}/location").json()
    assert hq["proposals"] == [{"id": refs["company:100"]["id"], "source": "autotask",
                                "label": "1 Example Rd, Exampleton, IL 00001",
                                "unassigned": True}]
    annex = client.get(f"/api/v1/fleet/sites/{_site_key(client, 'Acme Annex')}/location").json()
    assert [(h["id"], h["unassigned"]) for h in annex["proposals"]] == [
        (refs["location:11"]["id"], False), (refs["company:100"]["id"], True)]


def test_a_site_remapped_to_another_client_shows_nothing_of_it(px, monkeypatch):
    client, _fake, mgr = px
    _op(client, "adm-m", "admin")
    _refresh(client)
    bakery = _site_key(client, "Bakery")
    p = _by_ref(_items(client))["company:200"]
    assert p["target_key"] == bakery
    # The Bakery's UniFi site now belongs to Acme, which pins it by hand.
    tenant_map.set_mappings(mgr.unifi_id, UNIFI_MAP[:2] + [
        TenantMapping(scope(3), A, "Acme Depot", "manual")])
    locations.set_site_override(bakery, A, 41.5, -100.5, "Acme depot door", actor=1)
    _op(client, "adm-bk", "admin", [B])
    body = _items(client)
    (mine,) = body["items"]
    assert mine["id"] == p["id"] and mine["target_name"] is None and mine["current"] is None
    assert not {"current_pin_differs", "far_from_console"} & {f["code"] for f in mine["flags"]}
    assert "Acme" not in json.dumps(body) and "41.5" not in json.dumps(body)
    monkeypatch.setattr(geocode, "lookup",
                        lambda a, **_k: [geocode.Match(41.12, -101.0, "1 EXAMPLE RD")])
    looked = client.post(f"/api/v1/proposals/{p['id']}/lookup").json()["proposal"]
    assert "km_from_console" not in looked["matches"][0]
    # And it can only be confirmed where it may: the client's own entry.
    body = _items(client)
    assert [t["key"] for t in body["targets"][B]] == [site_location.tenant_key(B)]


def test_the_lookup_off_rate_limited_and_refresh_without_autotask(px, monkeypatch):
    client, _fake, mgr = px
    _op(client, "adm-l", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:200"]
    monkeypatch.setattr(geocode, "lookup", lambda a, **_k: [])
    monkeypatch.setattr(geocode, "LIMITER", geocode.RateLimiter(limit=1, window_sec=60.0))
    assert client.post(f"/api/v1/proposals/{p['id']}/lookup").status_code == 200
    assert client.post(f"/api/v1/proposals/{p['id']}/lookup").status_code == 429
    monkeypatch.setenv(geocode.GEOCODER_ENV, "off")
    r = client.post(f"/api/v1/proposals/{p['id']}/lookup")
    assert r.status_code == 409 and "turned off" in r.json()["message"]
    assert _items(client)["geocoder"] is None
    # Confirming a typed point still works without a lookup.
    assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                       json={"lat": 41.2, "lng": -100.9, "reason": "pasted from the map",
                             **_seen(client, "company:200")}).status_code == 200
    mgr.records.clear()
    proposals_router._last_refresh_at.clear()
    r = client.post("/api/v1/proposals/refresh")
    assert r.status_code == 409 and "not connected" in r.json()["message"]
    assert _items(client)["autotask"] is False


def test_an_autotask_failure_changes_nothing(px):
    from apps.octo.adapters.autotask.client import AutotaskClientError

    client, fake, _mgr = px
    _op(client, "adm-f", "admin")
    _refresh(client)

    def down(*_a, **_k):
        raise AutotaskClientError("Companies/query HTTP 503", status=503)

    fake.query_companies = down  # type: ignore[method-assign]
    proposals_router._last_refresh_at.clear()
    r = client.post("/api/v1/proposals/refresh")
    assert r.status_code == 503 and "HTTP" not in r.json()["message"]
    assert _items(client)["open"] == 4


def test_no_address_is_logged_and_nothing_is_geocoded_unasked(px, monkeypatch, caplog):
    client, _fake, _mgr = px
    _op(client, "adm-g", "admin")

    def no(*_a, **_k):
        raise AssertionError("the geocoder was called")

    monkeypatch.setattr(geocode, "lookup", no)
    caplog.set_level("INFO")
    _refresh(client)
    body = _items(client)                                    # reading never geocodes
    client.get("/api/v1/proposals/summary")
    p = _by_ref(body)["company:200"]
    monkeypatch.setattr(geocode, "lookup", lambda a, **_k: [geocode.Match(41.1, -101.0, "m")])
    client.post(f"/api/v1/proposals/{p['id']}/lookup")
    assert client.post(f"/api/v1/proposals/{p['id']}/confirm",
                       json={"match_index": 0, "reason": "verified",
                             **_seen(client, "company:200")}).status_code == 200
    text = caplog.text
    for street in ("Example Rd", "Example Road", "Annex Rd", "Example Ln"):
        assert street not in text


def test_client_users_never_see_any_of_it(px, monkeypatch):
    client, _fake, _mgr = px
    _op(client, "adm-v", "admin")
    _refresh(client)
    p = _by_ref(_items(client))["company:200"]
    r = client.post(f"/api/v1/proposals/{p['id']}/confirm",
                    json={"lat": 41.2, "lng": -100.9, "reason": "verified on site",
                          **_seen(client, "company:200")})
    assert r.status_code == 200, r.text
    _op(client, "view-b", "viewer", [B])
    r = client.get("/api/v1/fleet/sites")
    assert r.status_code == 200
    (site,) = r.json()["sites"]
    assert site["location"] is None and site["provenance"] is None
    for word in VENDOR_WORDS:
        assert word not in r.text.lower(), word
    assert client.get("/api/v1/dashboard/octo-location").status_code == 403
