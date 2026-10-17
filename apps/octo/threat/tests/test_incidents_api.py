"""The incidents API through real HTTP routes and real sign-in: the role
matrix cell by cell (viewer / analyst / admin / super_admin), Black close and
reclassify need an admin with step-up (reclassify leaves the Black
immutable and opens a linked Red), there is NO lower / mute / snooze route,
B6 and R8 reason rules, audit-before-write; the client's two actions
(recorded, audited with the client user's id, analysts paged, a
confirmation, nothing executed; a Black "allow" waits for an analyst); 911 /
life-safety assets are carved out of every lockdown request; the viewer
payloads carry no vendor, device or indicator; asset tags, knobs and the
storm brake by role."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths
from apps.octo.client_provisioning import create_client
from apps.octo.fleet import build, sources
from apps.octo.fleet.tests.fixtures import stamp_tier_worker
from apps.octo.tests.auth.conftest import auth_client, auth_data_root  # noqa: F401
from apps.octo.tests.auth.test_dashboard_throughput import _login
from apps.octo.threat import client_view, notify, store
from apps.octo.threat.tests.conftest import (
    FakeMailer,
    audit_rows,
    insert_event,
    notices,
)

PW = "pw1234567890"
A, B = "acme-corp", "example-bakery"
REASON = "the client called: someone is moving the mouse"
FORBIDDEN = ("ws-01", "198.51.100.23", "relay-young.example.test", "b6", "r8", "unifi",
             "nextdns", "datto", "wazuh", "opencanary", "alice")


@pytest.fixture
def api(auth_client, monkeypatch):  # noqa: F811
    monkeypatch.setenv(build.CACHE_ENV, "0")
    fake = FakeMailer()
    monkeypatch.setattr(notify, "MAILER_FACTORY", fake.factory)
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()
    create_client(A, "Acme Corp", kind="client")
    create_client(B, "Example Bakery", kind="client")
    stamp_tier_worker()
    auth_client.mailer = fake
    yield auth_client
    store.reset_schema_cache()
    sources.reset_incident_cache()
    build.invalidate()


def _as(client, name: str, role: str, scope=None, *, elevate: bool = False) -> dict:
    client.cookies.clear()
    op = client.provision_operator(name, PW, role=role, athena_role=role, scope_slugs=scope)
    _login(client, op)
    if elevate:
        r = client.post("/api/v1/search/elevate", json={
            "current_password": PW, "totp_code": pyotp.TOTP(op["totp_secret_b32"]).now()})
        assert r.status_code == 200, r.text
    return op


def _declare(client, *, tenant: str = A, **kw) -> dict:
    body = {"tenant": tenant, "summary": "someone is controlling the screen",
            "reason": REASON, "device_ref": "ws-01", **kw}
    r = client.post("/api/v1/incidents/declare", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _red(client, *, tenant: str = A) -> dict:
    eid = insert_event(tenant, source="wazuh", event_type="wazuh.alert",
                       payload={"rule": {"level": 10}}, source_host="ws-01")
    r = client.post(f"/api/v1/signals/{tenant}/{eid}/confirm",
                    json={"reason": "the hash is on a ransomware family list"})
    assert r.status_code == 200, r.text
    return r.json()


def _url(inc: dict, action: str = "") -> str:
    return f"/api/v1/incidents/{inc['tenant_slug']}/{inc['id']}" + (f"/{action}" if action
                                                                     else "")


# ---------------------------------------------------------------------------
# B6 / R8 — opening, reason rules, audit before write
# ---------------------------------------------------------------------------

def test_b6_declares_black_and_pages_at_once(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    assert inc["tier"] == "black" and inc["rule_id"] == "B6" and inc["open"]
    assert inc["escalation_step"] == 1                                   # T0 paged now
    assert notices("threat_black")
    (row,) = audit_rows("incident.open")
    assert row["client_slug"] == A and json.loads(row["after_state"])["rule"] == "B6"
    assert row["reason"] == REASON
    # A reason is mandatory.
    r = api.post("/api/v1/incidents/declare", json={"tenant": A, "summary": "x y z",
                                                    "reason": "  "})
    assert r.status_code == 422
    # Out of scope is a 404, never a 403 that confirms the tenant exists.
    assert api.post("/api/v1/incidents/declare",
                    json={"tenant": B, "summary": "abc", "reason": REASON}).status_code == 404


def test_r8_needs_a_reason_of_twenty_characters(api):
    _as(api, "ana", "analyst", [A])
    eid = insert_event(A, source="wazuh", event_type="wazuh.alert", payload={}, source_host="h")
    r = api.post(f"/api/v1/signals/{A}/{eid}/confirm", json={"reason": "looks bad"})
    assert r.status_code == 422
    assert audit_rows("incident.open") == []                             # nothing audited
    inc = _red(api)
    assert inc["tier"] == "red" and inc["rule_id"] == "R8"
    assert api.post(f"/api/v1/signals/{A}/999999/confirm",
                    json={"reason": "x" * 25}).status_code == 404


def test_raise_turns_a_red_black_in_the_same_incident(api):
    _as(api, "ana", "analyst", [A])
    red = _red(api)
    api.post(_url(red, "ack"), json={})
    r = api.post(_url(red, "raise"), json={"reason": REASON})
    assert r.status_code == 200
    black = r.json()
    assert black["id"] == red["id"] and black["tier"] == "black" and not black["acked"]
    assert api.post(_url(red, "raise"), json={"reason": REASON}).status_code == 409


# ---------------------------------------------------------------------------
# The role matrix, cell by cell
# ---------------------------------------------------------------------------

def test_a_viewer_reaches_no_operator_route(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    _as(api, "erin", "viewer", [A])
    for method, path, body in (
            ("get", "/api/v1/incidents", None),
            ("get", _url(inc), None),
            ("post", _url(inc, "ack"), {}),
            ("post", _url(inc, "assign"), {"to": 1}),
            ("post", _url(inc, "note"), {"text": "x"}),
            ("post", _url(inc, "contain"), {"receipt": "stopped it"}),
            ("post", _url(inc, "raise"), {"reason": REASON}),
            ("post", _url(inc, "close"), {"code": "remediated", "text": "done"}),
            ("post", _url(inc, "reclassify"), {"reason": REASON}),
            ("post", _url(inc, "lockdown-request"), {"note": "lock it"}),
            ("post", "/api/v1/incidents/declare", {"tenant": A, "summary": "abc",
                                                   "reason": REASON}),
            ("post", "/api/v1/admin/registry/asset-tags",
             {"tenant": A, "device_ref": "x", "tag": "life_safety", "reason": "abc"}),
            ("get", "/api/v1/tiers/rules", None)):
        r = getattr(api, method)(path, json=body) if body is not None else \
            getattr(api, method)(path)
        assert r.status_code == 403, (method, path, r.status_code)


def test_analyst_cells(api):
    me = _as(api, "ana", "analyst", [A])
    other = api.provision_operator("ana2", PW, role="analyst", athena_role="analyst",
                                   scope_slugs=[A])
    black = _declare(api)
    red = _red(api)
    assert api.get("/api/v1/incidents").status_code == 200
    assert api.get(_url(black)).status_code == 200
    assert api.post(_url(black, "ack"), json={"note": "on it"}).json()["acked"] is True
    assert api.post(_url(black, "ack"), json={}).status_code == 409        # once
    assert api.post(_url(black, "assign"), json={"to": me["id"]}).status_code == 200
    assert api.post(_url(black, "assign"), json={"to": other["id"]}).status_code == 403
    assert api.post(_url(black, "note"), json={"text": "called the client"}).status_code == 200
    assert api.post(_url(black, "contain"), json={"receipt": "service stopped"}) \
        .status_code == 200
    # Close a RED: yes. Close a BLACK: no.
    assert api.post(_url(black, "close"), json={"code": "remediated", "text": "done"}) \
        .status_code == 403
    assert api.post(_url(black, "reclassify"), json={"reason": REASON}).status_code == 403
    r = api.post(_url(red, "close"), json={"code": "authorized_activity",
                                           "text": "the vendor's tool, registered"})
    assert r.status_code == 200 and r.json()["status"] == "closed"


def test_admin_assigns_anyone_and_closes_a_black_with_step_up_and_checklist(api):
    _as(api, "ana", "analyst", [A])
    black = _declare(api)
    ana2 = api.provision_operator("ana2", PW, role="analyst", athena_role="analyst",
                                  scope_slugs=[A])
    _as(api, "adm", "admin")                                              # not elevated
    assert api.post(_url(black, "assign"), json={"to": ana2["id"]}).status_code == 200
    body = {"code": "remediated", "text": "rescue point verified, relay blocked"}
    r = api.post(_url(black, "close"), json=body)
    assert r.status_code == 422 and "checklist" in r.json()["message"]
    checklist = {"c2_blocked": "yes", "rescue_point_verified": True,
                 "device_state": "reimaged by the client's vendor",
                 "client_notified_who": "the office manager",
                 "client_notified_when": "2026-10-03 10:12"}
    r = api.post(_url(black, "close"), json={**body, "checklist": checklist})
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    assert audit_rows("incident.close") == []                            # nothing audited
    _as(api, "adm2", "admin", elevate=True)
    r = api.post(_url(black, "close"), json={**body, "checklist": checklist})
    assert r.status_code == 200 and r.json()["status"] == "closed"
    (row,) = audit_rows("incident.close")
    assert json.loads(row["after_state"])["checklist"]["c2_blocked"] == "yes"
    assert notices("threat_registry")                                    # peer review


def test_a_false_positive_close_never_stops_a_person_declaring_black_again(api):
    """G10: a verdict blocks an automated RULE re-firing on its key. A
    person's B6 / R8 record writes none, and a later declaration on the same
    device is heard — "the client calls: someone is controlling my screen"
    three weeks after a false-positive close is a Black, never a 409."""
    _as(api, "ana", "analyst", [A])
    black = _declare(api)
    _as(api, "root", "super_admin", elevate=True)
    r = api.post(_url(black, "close"), json={"code": "false_positive",
                                             "text": "our own technician's session"})
    assert r.status_code == 200 and r.json()["status"] == "false_positive"
    assert audit_rows("verdict.create") == []
    assert json.loads(audit_rows("incident.close")[-1]["after_state"])["verdict"] is False
    assert api.get(f"/api/v1/admin/registry/verdicts?tenant={A}").json()["rows"] == []
    _as(api, "ana3", "analyst", [A])
    r = api.post("/api/v1/incidents/declare", json={
        "tenant": A, "summary": "again", "reason": REASON, "device_ref": "ws-01"})
    assert r.status_code == 200 and r.json()["tier"] == "black" and r.json()["open"]
    # Audited BEFORE the write under the name of what happened: a reopen.
    assert audit_rows("incident.reopen") and r.json()["reopened_count"] == 1
    # An analyst's false-positive close of a Red (R8) writes none either.
    red = _red(api)
    r = api.post(_url(red, "close"), json={"code": "false_positive", "text": "a test file"})
    assert r.status_code == 200 and audit_rows("verdict.create") == []


def _automated_red(key: str = f"{A}|ip:192.0.2.9|deception|") -> dict:
    inc = store.open_incident(A, tier="red", rule_id="R6", rule_version=1, key=key,
                              summary="credential tried on a decoy", scope="device",
                              opened_by=store.SYSTEM_ACTOR, device_ref="ip:192.0.2.9").incident
    return {"tenant_slug": A, "id": inc.id}


def test_a_verdict_is_an_admin_with_step_up_on_an_automated_rule_only(api):
    # An analyst's false-positive close of an automated Red: no verdict.
    _as(api, "ana", "analyst", [A])
    first = _automated_red()
    r = api.post(_url(first, "close"), json={"code": "false_positive",
                                             "text": "the printer's scan job"})
    assert r.status_code == 200 and audit_rows("verdict.create") == []
    # An admin's: step-up first (G10) …
    second = _automated_red(f"{A}|ip:192.0.2.10|deception|")
    _as(api, "adm", "admin")
    r = api.post(_url(second, "close"), json={"code": "false_positive",
                                              "text": "the printer's scan job"})
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    assert audit_rows("incident.close")[-1]["target_id"] != str(second["id"])
    # … then the verdict for that exact key, and every other admin is told.
    _as(api, "adm2", "admin", elevate=True)
    before = len(notices("threat_registry"))
    r = api.post(_url(second, "close"), json={"code": "false_positive",
                                              "text": "the printer's scan job"})
    assert r.status_code == 200
    (row,) = audit_rows("verdict.create")
    assert row["target_id"] == f"{A}|ip:192.0.2.10|deception|"
    assert len(notices("threat_registry")) > before
    # The rule re-firing on that key within 14 days is blocked.
    again = store.open_incident(A, tier="red", rule_id="R6", rule_version=1,
                                key=f"{A}|ip:192.0.2.10|deception|", summary="again",
                                scope="device", opened_by=store.SYSTEM_ACTOR)
    assert again.outcome == "blocked"


def test_reclassify_opens_a_linked_red_and_leaves_the_black_immutable(api):
    _as(api, "ana", "analyst", [A])
    black = _declare(api)
    _as(api, "adm", "admin")
    assert api.post(_url(black, "reclassify"), json={"reason": REASON}).status_code == 401
    _as(api, "adm2", "admin", elevate=True)
    r = api.post(_url(black, "reclassify"), json={"reason": "a vendor's session, unannounced"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["closed"]["tier"] == "black" and out["closed"]["status"] == "closed"
    assert out["closed"]["close_reason_code"] == "reclassified_red"
    assert out["opened"]["tier"] == "red" and out["opened"]["reclassified_from"] == black["id"]
    assert api.get(_url(black)).json()["incident"]["tier"] == "black"


def test_there_is_no_lower_mute_or_snooze_route(api):
    paths_ = {(m, r.path) for r in api.app.routes for m in getattr(r, "methods", set())}
    words = ("lower", "mute", "snooze", "downgrade", "demote", "silence", "dismiss")
    for method, path in paths_:
        if "incident" in path or "signals" in path or "tiers" in path:
            assert not any(w in path for w in words), path
            if "/incidents" in path:
                assert method in ("GET", "POST", "HEAD"), (method, path)
    # And the tier rules have no write route at all.
    assert not any(p == "/api/v1/tiers/rules" and m in ("PUT", "POST", "PATCH", "DELETE")
                   for m, p in paths_)
    # A request body cannot carry a tier down either.
    _as(api, "ana", "analyst", [A])
    black = _declare(api)
    assert api.post(_url(black, "ack"), json={"tier": "red"}).status_code == 422


# ---------------------------------------------------------------------------
# The client's two actions
# ---------------------------------------------------------------------------

def _visible_black(api, **kw) -> dict:
    _as(api, "ana", "analyst", [A])
    inc = _declare(api, **kw)
    api.post(_url(inc, "ack"), json={})                                  # visible at once
    return inc


def test_the_client_sees_nothing_before_ack_or_60_minutes(api):
    _as(api, "ana", "analyst", [A])
    _declare(api)
    _as(api, "erin", "viewer", [A])
    assert api.get("/api/v1/incidents/client").json()["items"] == []
    s = api.get("/api/v1/incidents/summary").json()
    assert s == {"view": "client", "black": 0, "red": 0}
    site = api.get("/api/v1/fleet/sites").json()
    assert site["sites"] == [] or all(x["state"] != "black" for x in site["sites"])


def test_a_client_lockdown_is_recorded_paged_confirmed_never_executed(api):
    inc = _visible_black(api)
    _as(api, "erin", "viewer", [A])
    (item,) = api.get("/api/v1/incidents/client").json()["items"]
    assert item["status_neutral"] == client_view.LINE_BLACK_ACKED
    assert [a["label"] for a in item["actions"]] == [
        "Lock down my network and contact my analyst", "Allow this traffic"]
    before = len(notices("threat_client"))
    r = api.post(f"/api/v1/incidents/client/{item['ref']}/decision", json={"kind": "lockdown"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert "911 / life-safety systems are never blocked" in out["confirmation"]
    assert out["decision"] == {"kind": "lockdown", "status": "recorded",
                               "created_at": out["decision"]["created_at"]}
    (row,) = audit_rows("incident.client_decision")
    after = json.loads(row["after_state"])
    assert after["client_user"] == int(row["actor"]) and after["executes"] is False
    assert len(notices("threat_client")) > before                      # analysts paged
    # The analyst sees the client's decision on the incident.
    _as(api, "ana9", "analyst", [A])
    (d,) = api.get(_url(inc)).json()["decisions"]
    assert d["kind"] == "lockdown" and d["requested_role"] == "client" and d["executed"] == 0


def test_a_black_allow_waits_for_an_analyst_a_red_allow_is_recorded(api):
    black = _visible_black(api)
    _as(api, "erin", "viewer", [A])
    (item,) = api.get("/api/v1/incidents/client").json()["items"]
    r = api.post(f"/api/v1/incidents/client/{item['ref']}/decision", json={"kind": "allow"})
    assert r.json()["decision"]["status"] == "pending_analyst"
    assert "analyst must confirm" in r.json()["confirmation"]
    _as(api, "ana2", "analyst", [A])
    (d,) = api.get(_url(black)).json()["decisions"]
    r = api.post(_url(black, f"decisions/{d['id']}/answer"),
                 json={"confirm": True, "note": "confirmed with the office manager"})
    assert r.status_code == 200 and r.json()["decision"]["status"] == "confirmed"
    assert api.post(_url(black, f"decisions/{d['id']}/answer"),
                    json={"confirm": True, "note": "again"}).status_code == 409
    red = _red(api)
    api.post(_url(red, "ack"), json={})
    _as(api, "erin2", "viewer", [A])
    items = api.get("/api/v1/incidents/client").json()["items"]
    ref = next(i["ref"] for i in items if i["tier"] == "red")
    r = api.post(f"/api/v1/incidents/client/{ref}/decision", json={"kind": "allow"})
    assert r.json()["decision"]["status"] == "recorded"


def test_a_viewer_never_reaches_another_tenants_incident_nor_an_operator_the_client_routes(api):
    inc = _visible_black(api)
    ref = client_view.ref(A, inc["id"])
    _as(api, "bea", "viewer", [B])
    assert api.post(f"/api/v1/incidents/client/{ref}/decision",
                    json={"kind": "lockdown"}).status_code == 404
    _as(api, "ana5", "analyst", [A])
    assert api.get("/api/v1/incidents/client").status_code == 403
    assert api.post(f"/api/v1/incidents/client/{ref}/decision",
                    json={"kind": "lockdown"}).status_code == 403


def test_viewer_payloads_carry_no_vendor_device_or_indicator(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api, summary="ws-01 reached relay-young.example.test (198.51.100.23)",
                   device_label="WS-01")
    api.post(_url(inc, "ack"), json={})
    _as(api, "erin", "viewer", [A])
    for path in ("/api/v1/incidents/client", "/api/v1/incidents/summary",
                 "/api/v1/fleet/sites"):
        r = api.get(path)
        assert r.status_code == 200
        body = r.json()
        if path.endswith("client"):
            for item in body["items"]:
                item.pop("ref")
        if path.endswith("sites"):
            for s in body["sites"]:
                s.pop("key")
                if s.get("incident"):
                    s["incident"].pop("ref")
        text = json.dumps(body).lower()
        for word in FORBIDDEN:
            assert word not in text, (path, word)
        assert "pulse" not in text and "acked" not in text


# ---------------------------------------------------------------------------
# Life-safety first — through the API
# ---------------------------------------------------------------------------

def test_lockdown_requests_carve_out_life_safety_assets(api):
    _as(api, "ana", "analyst", [A])
    r = api.post("/api/v1/admin/registry/asset-tags", json={
        "tenant": A, "device_ref": "dispatch-01", "tag": "life_safety",
        "reason": "911 dispatch console"})
    assert r.status_code == 200                                      # analyst-set
    assert audit_rows("asset_tag.update")
    inc = _declare(api, device_ref="dispatch-01")
    r = api.post(_url(inc, "lockdown-request"), json={
        "note": "isolate everything", "targets": [{"kind": "device", "ref": "dispatch-01"},
                                                  {"kind": "device", "ref": "ws-03"}]})
    assert r.status_code == 200, r.text
    d = r.json()["decision"]
    assert [t["ref"] for t in d["scope"]] == ["ws-03"]
    assert d["excluded"][0]["ref"] == "dispatch-01"
    assert d["notice"] == "911 / life-safety systems are never blocked"
    detail = api.get(_url(inc)).json()
    assert "life_safety" in detail["asset_tags"]
    assert detail["proposed_steps"][0].startswith("911 / life-safety systems are never blocked")
    assert detail["mode"]["mode"] == "propose_only"
    # An analyst may not set a tag that SUPPRESSES detection, nor clear any.
    r = api.post("/api/v1/admin/registry/asset-tags", json={
        "tenant": A, "device_ref": "lab-01", "tag": "lab", "reason": "the test bench"})
    assert r.status_code == 403
    tag_id = api.get(f"/api/v1/admin/registry/asset-tags?tenant={A}").json()["tags"][0]["id"]
    assert api.post(f"/api/v1/admin/registry/asset-tags/{tag_id}/clear",
                    json={"reason": "gone"}).status_code == 403


# ---------------------------------------------------------------------------
# Knobs, rules, the brake
# ---------------------------------------------------------------------------

def test_yellow_knobs_are_bounded_and_audited(api):
    _as(api, "adm", "admin")
    r = api.put("/api/v1/admin/tiers/yellow", json={
        "values": {"ips_inbound_blocked_level": "bad"}, "reason": "make it louder"})
    assert r.status_code == 422                                      # never Red
    r = api.put("/api/v1/admin/tiers/yellow", json={
        "values": {"watch_days": 99}, "reason": "longer"})
    assert r.status_code == 422
    # v0.17.1: the DNS count knob is retired (A1 — the count is always a
    # Notice): not a knob any more.
    r = api.put("/api/v1/admin/tiers/yellow", json={
        "values": {"dns_medium_level": "warn"}, "reason": "make every block yellow"})
    assert r.status_code == 422
    r = api.put("/api/v1/admin/tiers/yellow", json={
        "values": {"watch_days": 14, "ips_inbound_blocked_level": "warn"},
        "reason": "the SOC asked"})
    assert r.status_code == 200 and r.json()["effective"]["watch_days"] == 14
    assert audit_rows("tier_settings.update")


def test_the_rules_list_is_read_only_with_coverage(api):
    _as(api, "ana", "analyst", [A])
    r = api.get("/api/v1/tiers/rules")
    rules_ = {x["id"]: x for x in r.json()["rules"]}
    assert rules_["R6"]["stage"] == "shadow" and rules_["B6"]["stage"] == "live"
    assert rules_["R6"]["coverage"][A]["covered"] is False           # no buoy, no allowlist
    assert set(rules_["R6"]["coverage"]) == {A}                      # scoped
    assert api.put("/api/v1/tiers/rules", json={}).status_code in (404, 405)


def test_the_brake_is_super_admin_with_step_up(api):
    _as(api, "adm", "admin", elevate=True)
    body = {"rule_id": "R6", "hours": 4, "reason": "a storm of would-fires"}
    assert api.post("/api/v1/admin/tiers/brake", json=body).status_code == 403
    _as(api, "root", "super_admin")
    assert api.post("/api/v1/admin/tiers/brake", json=body).status_code == 401
    _as(api, "root2", "super_admin", elevate=True)
    assert api.post("/api/v1/admin/tiers/brake",
                    json={**body, "rule_id": "B6"}).status_code == 422
    assert api.post("/api/v1/admin/tiers/brake",
                    json={**body, "hours": 25}).status_code == 422
    r = api.post("/api/v1/admin/tiers/brake", json=body)
    assert r.status_code == 200 and r.json()["brakes"][0]["rule_id"] == "R6"
    assert audit_rows("rule.brake")
    assert api.post("/api/v1/admin/tiers/brake", json=body).status_code == 409


def test_the_summary_for_operators_counts_unacknowledged_blacks(api):
    _as(api, "ana", "analyst", [A])
    _declare(api)
    _red(api)
    s = api.get("/api/v1/incidents/summary").json()
    assert s["view"] == "operator" and s["black"] == 1 and s["red"] == 1
    assert s["black_unacked"] == 1 and s["items"][0]["tier"] == "black"
    _as(api, "bob", "analyst", [B])                                    # another scope
    s = api.get("/api/v1/incidents/summary").json()
    assert s["black"] == 0 and s["items"] == []


def test_an_audit_failure_writes_nothing(api, monkeypatch):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    from apps.octo.threat import audit as taudit

    def broken(*_a, **_kw):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(taudit, "append", broken)
    with pytest.raises(sqlite3.OperationalError):
        api.post(_url(inc, "ack"), json={})
    assert store.get(A, inc["id"]).acked is False


def test_the_fleet_carries_the_incident_for_operators(api):
    _as(api, "ana", "analyst", [A])
    _declare(api)
    body = api.get("/api/v1/fleet/sites").json()
    (site,) = [s for s in body["sites"] if s["tenant_slug"] == A]
    assert site["state"] == "black" and site["incident"]["tier"] == "black"
    assert site["incident"]["acked"] is False
    assert body["counts"]["black"] == 1
    assert body["threats"][0]["tenant"] == A
    assert "black" in site["layers"]["threat"]["state"]
    now = datetime.now(timezone.utc) + timedelta(minutes=1)
    assert store.get(A, site["incident"]["id"]).age_s(now) >= 60


# ---------------------------------------------------------------------------
# Review fixes (feat/tier-black-slice1-fixed)
# ---------------------------------------------------------------------------

def test_a_client_decision_pages_once_per_ten_minutes(api):
    """The same person's same decision on the same incident again within 10
    minutes — a client pressing twice, or a stolen session in a loop — is
    answered with what was recorded: no new row, no new page."""
    _visible_black(api)
    _as(api, "erin", "viewer", [A])
    (item,) = api.get("/api/v1/incidents/client").json()["items"]
    url = f"/api/v1/incidents/client/{item['ref']}/decision"
    assert api.post(url, json={"kind": "lockdown"}).status_code == 200
    pages = len(notices("threat_client"))
    for _ in range(3):
        r = api.post(url, json={"kind": "lockdown"})
        assert r.status_code == 200 and r.json()["confirmation"].startswith("Already recorded")
    assert len(notices("threat_client")) == pages
    assert len(audit_rows("incident.client_decision")) == 1
    # The OTHER decision is a new one (recorded, paged).
    assert api.post(url, json={"kind": "allow"}).status_code == 200
    assert len(notices("threat_client")) > pages


def test_a_client_lockdown_runs_the_life_safety_invariant_too(api, monkeypatch):
    _visible_black(api)
    from apps.octo.threat import lockdown

    monkeypatch.setattr(lockdown, "never_includes_life_safety", lambda *_a, **_kw: False)
    _as(api, "erin", "viewer", [A])
    (item,) = api.get("/api/v1/incidents/client").json()["items"]
    r = api.post(f"/api/v1/incidents/client/{item['ref']}/decision", json={"kind": "lockdown"})
    assert r.status_code == 503 and "never blocked" in r.json()["message"]
    assert audit_rows("incident.client_decision") == []


def test_b6_refuses_a_site_that_is_not_the_clients(api):
    from apps.octo.fleet.build import site_key

    _as(api, "ana", "analyst", [A, B])
    other = site_key("tenant", B)
    r = api.post("/api/v1/incidents/declare", json={
        "tenant": A, "summary": "abc", "reason": REASON, "site_key": other})
    assert r.status_code == 422 and "not one of this client's sites" in r.json()["message"]
    assert audit_rows("incident.open") == []                             # before any row
    own = _declare(api, site_key=site_key("tenant", A), device_ref=None)
    assert own["scope"] == "site"


def test_r8_counts_twenty_characters_after_whitespace(api):
    _as(api, "ana", "analyst", [A])
    eid = insert_event(A, source="wazuh", event_type="wazuh.alert", payload={}, source_host="h")
    for reason in (" " * 25, "too    short     \t\n   "):
        r = api.post(f"/api/v1/signals/{A}/{eid}/confirm", json={"reason": reason})
        assert r.status_code == 422, reason
    assert audit_rows("incident.open") == []
    r = api.post(f"/api/v1/signals/{A}/{eid}/confirm",
                 json={"reason": "  the hash   is on a ransomware family list  "})
    assert r.status_code == 200
    assert audit_rows("incident.open")[-1]["reason"] == \
        "the hash is on a ransomware family list"


def test_an_incidents_own_record_is_not_a_signal(api):
    """R8 never "confirms" Athena's own `athena.incident` event."""
    _as(api, "ana", "analyst", [A])
    _declare(api)
    conn = sqlite3.connect(str(paths.client_dir(A) / "events.db"))
    try:
        (eid,) = conn.execute("SELECT id FROM events WHERE source = 'athena' "
                              "ORDER BY id LIMIT 1").fetchone()
    finally:
        conn.close()
    r = api.post(f"/api/v1/signals/{A}/{eid}/confirm",
                 json={"reason": "confirming the incident's own record"})
    assert r.status_code == 422


def test_black_close_peer_review_mails_no_detail(api):
    _as(api, "ana", "analyst", [A])
    black = _declare(api, summary="ws-01 reached relay-young.example.test")
    _as(api, "watcher", "admin")                                         # an OTHER admin
    _as(api, "root", "super_admin", elevate=True)
    api.mailer.sent.clear()
    r = api.post(_url(black, "close"), json={"code": "false_positive",
                                             "text": "our technician on ws-01 via 198.51.100.23"})
    assert r.status_code == 200
    assert api.mailer.sent                                               # the peer review
    for _to, subject, body in api.mailer.sent:
        text = f"{subject}\n{body}".lower()
        for word in ("acme", "ws-01", "relay-young", "198.51.100.23", "technician"):
            assert word not in text, word


def test_every_tag_edit_tells_the_other_admins(api):
    """Design 6.7: an edit of a table that can suppress or bound a tier tells
    the other admins — `life_safety` included (it makes an asset immune from
    every lockdown, on an attacker-held host too), every CLEAR, and a tag set
    again after a clear (the notice id carries the row id)."""
    _as(api, "watcher", "admin")
    _as(api, "ana", "analyst", [A])
    body = {"tenant": A, "device_ref": "dispatch-01", "tag": "life_safety",
            "reason": "911 dispatch console"}
    assert api.post("/api/v1/admin/registry/asset-tags", json=body).status_code == 200
    seen = len(notices("threat_registry"))
    assert seen >= 1
    _as(api, "adm", "admin")
    tag_id = api.get(f"/api/v1/admin/registry/asset-tags?tenant={A}").json()["tags"][0]["id"]
    assert api.post(f"/api/v1/admin/registry/asset-tags/{tag_id}/clear",
                    json={"reason": "console replaced"}).status_code == 200
    assert len(notices("threat_registry")) > seen
    seen = len(notices("threat_registry"))
    assert api.post("/api/v1/admin/registry/asset-tags", json=body).status_code == 200
    assert len(notices("threat_registry")) > seen
    # A life-safety tag must name a host or an address (the carve-out
    # compares canonical identities) — refused before any audit row. Free
    # text (no identity at all), as an analyst might type a VLAN's name.
    rows = len(audit_rows("asset_tag.update"))
    r = api.post("/api/v1/admin/registry/asset-tags", json={
        **body, "ref_kind": "path", "device_ref": "the example-vlan"})
    assert r.status_code == 422 and len(audit_rows("asset_tag.update")) == rows


def test_the_canary_allowlist_and_a_revoked_exception_tell_the_admins(api):
    _as(api, "watcher", "admin")
    _as(api, "root", "super_admin", elevate=True)
    seen = len(notices("threat_registry"))
    r = api.post("/api/v1/admin/registry/canary-allowlist", json={
        "tenant": A, "ip": "192.0.2.250", "label": "network discovery",
        "reason": "the RMM's discovery node"})
    assert r.status_code == 200 and len(notices("threat_registry")) > seen
    r = api.post("/api/v1/admin/registry/exceptions", json={
        "tenant": A, "binding_kind": "signature", "binding": "ET EXAMPLE 2",
        "rule_id": "R6", "days": 30, "reason": "the line-of-business updater"})
    assert r.status_code == 200
    exc_id = r.json()["rows"][0]["id"]
    seen = len(notices("threat_registry"))
    r = api.post(f"/api/v1/admin/registry/exceptions/{exc_id}/revoke",
                 json={"reason": "the vendor fixed it"})
    assert r.status_code == 200 and len(notices("threat_registry")) > seen


def test_exception_cells_super_admin_with_step_up_only(api):
    """Role matrix: "Create an exception" — super_admin + step-up; analyst
    and admin refused (cell by cell)."""
    body = {"tenant": A, "binding_kind": "signature", "binding": "ET EXAMPLE 1",
            "rule_id": "R6", "days": 30, "reason": "a noisy signature"}
    _as(api, "ana", "analyst", [A])
    assert api.post("/api/v1/admin/registry/exceptions", json=body).status_code == 403
    _as(api, "adm", "admin", elevate=True)
    assert api.post("/api/v1/admin/registry/exceptions", json=body).status_code == 403
    _as(api, "root", "super_admin")
    assert api.post("/api/v1/admin/registry/exceptions", json=body).status_code == 401
    assert audit_rows("exception.create") == []
    _as(api, "root2", "super_admin", elevate=True)
    assert api.post("/api/v1/admin/registry/exceptions",
                    json={**body, "days": 91}).status_code == 422
    r = api.post("/api/v1/admin/registry/exceptions", json=body)
    assert r.status_code == 200 and audit_rows("exception.create")


def test_a_registry_write_that_fails_after_its_row_says_so(api, monkeypatch):
    from apps.octo.threat import registry

    _as(api, "ana", "analyst", [A])

    def broken(*_a, **_kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(registry, "add_tag", broken)
    r = api.post("/api/v1/admin/registry/asset-tags", json={
        "tenant": A, "device_ref": "dispatch-01", "tag": "life_safety",
        "reason": "911 dispatch console"})
    assert r.status_code == 503
    assert audit_rows("asset_tag.update") and audit_rows("asset_tag.update_failed")


def test_an_analyst_reads_only_threat_notices_of_tenants_in_scope(api):
    from apps.octo.db import connect as _connect
    from apps.octo.db import transaction as _tx

    ana = _as(api, "ana", "analyst", [A])
    _declare(api)                                                        # pages ana (A)
    # A threat notice about B (not in ana's scope) and a non-threat kind,
    # both addressed to ana — e.g. kept from when she was an admin.
    reg = _connect(paths.registry_db_path())
    try:
        with _tx(reg):
            reg.execute("INSERT INTO operator_notices (recipient_id, kind, actor_id, "
                        "subject_slug, title, body, request_id) VALUES "
                        "(?, 'threat_black', 0, ?, 'BLACK at Example Bakery', 'x', 't:2'), "
                        "(?, 'mapping_review', 0, ?, 'review a mapping', 'x', 't:3')",
                        (ana["id"], B, ana["id"], A))
    finally:
        reg.close()
    body = api.get("/api/v1/admin/notices").json()
    assert body["notices"] and all(n["kind"].startswith("threat_") for n in body["notices"])
    assert all(n["subject_slug"] == A for n in body["notices"])
    assert body["open"] == len(body["notices"])
    hidden = [r["id"] for r in notices() if r["recipient_id"] == ana["id"]
              and r["subject_slug"] == B]
    assert api.post(f"/api/v1/admin/notices/{hidden[0]}/acknowledge").status_code == 404


def test_the_client_strip_reads_the_worst_line_they_may_see(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    api.post(_url(inc, "ack"), json={})
    _as(api, "erin", "viewer", [A])
    s = api.get("/api/v1/incidents/summary").json()
    assert s["status_neutral"] == client_view.LINE_BLACK_ACKED           # "…is responding"
    _as(api, "ana2", "analyst", [A])
    api.post(_url(inc, "contain"), json={"receipt": "the relay is blocked"})
    _as(api, "erin2", "viewer", [A])
    s = api.get("/api/v1/incidents/summary").json()
    assert s["status_neutral"] == client_view.LINE_CONTAINED
    assert "alerted" not in json.dumps(s)


# ---------------------------------------------------------------------------
# Evidence windows (Rick, 2026-10-05) — the former legal hold
# ---------------------------------------------------------------------------

def _windows(api, inc: dict) -> list[dict]:
    return api.get(_url(inc)).json()["evidence_windows"]


def test_a_declared_black_holds_an_evidence_window_from_its_first_detection(api):
    _as(api, "ana", "analyst", [A])
    eid = insert_event(A, source="wazuh", event_type="wazuh.alert", payload={"n": 1},
                       received_at="2026-09-28T07:15:00.000Z", source_host="ws-01")
    inc = _declare(api, event_id=eid)
    assert inc["evidence_held"] is True
    (w,) = _windows(api, inc)
    assert (w["kind"], w["start"], w["end"], w["open"], w["held"]) == (
        "incident", "2026-09-28T07:15:00.000Z", None, True, True)
    assert w["tenant_name"] == "Acme Corp" and w["incident_tier"] == "black"
    assert w["events_in_window"] is not None and w["events_in_window"] >= 1
    assert any(t["kind"] == "evidence_window" for t in api.get(_url(inc)).json()["timeline"])
    listed = api.get("/api/v1/incidents/evidence-windows").json()["items"]
    assert [x["id"] for x in listed] == [w["id"]]


def test_an_analyst_widens_a_window_with_a_reason_and_never_shrinks_one(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    (w,) = _windows(api, inc)
    url = _url(inc, f"evidence-window/{w['id']}/widen")
    assert api.post(url, json={"start": "2026-09-01T00:00:00Z"}).status_code == 422  # reason
    r = api.post(url, json={"start": "2026-09-01T00:00:00Z",
                            "reason": "dwell time: the first beacon was on the 1st"})
    assert r.status_code == 200, r.text
    assert r.json()["start"] == "2026-09-01T00:00:00.000Z"
    (row,) = audit_rows("incident.evidence_window_widen")
    after = json.loads(row["after_state"])
    assert after["before"]["start"] == w["start"] and row["reason"].startswith("dwell time")
    r = api.post(url, json={"start": "2026-09-15T00:00:00Z", "reason": "a later start"})
    assert r.status_code == 409 and "only widens" in r.json()["message"]
    # Audited before the write: the refused change says so after its row.
    assert audit_rows("incident.evidence_window_widen_failed")
    # Another tenant's analyst: not even there.
    _as(api, "bea", "analyst", [B])
    assert api.post(url, json={"start": "2026-08-01T00:00:00Z",
                               "reason": "not mine"}).status_code == 404


def test_a_widen_tells_the_admins_and_never_starts_before_2000(api):
    """A widened window holds more of the client until an admin releases it
    — the admins are told (old start → new, about how many events), and a
    slip of the year is refused outright."""
    adm = api.provision_operator("adm9", PW, role="admin", athena_role="admin")
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    (w,) = _windows(api, inc)
    url = _url(inc, f"evidence-window/{w['id']}/widen")

    def told() -> list:
        return [n for n in notices("threat_registry") if n["recipient_id"] == adm["id"]]

    r = api.post(url, json={"start": "1970-01-01T00:00:00Z", "reason": "the year slipped"})
    assert r.status_code == 422 and "2000" in r.json()["message"]
    assert told() == []
    r = api.post(url, json={"start": "2026-09-01T00:00:00Z",
                            "reason": "dwell time: the first beacon was on the 1st"})
    assert r.status_code == 200, r.text
    (n,) = told()
    assert "widened" in n["title"] and f"#{inc['id']}" in n["title"]
    assert w["start"] in n["body"] and "2026-09-01T00:00:00.000Z" in n["body"]
    assert "dwell time" in n["body"]


def test_an_open_ended_evidence_window_is_never_offboarded_or_merged_away(api):
    """A manual window with no end (the former legal hold: "until released")
    keeps whatever of the client arrives — an offboard (quarantined) or a
    merge (stored in the target) would end it without anyone deciding so.
    Refused until it has an end; a bounded window and a closed incident's
    window do not stand in the way."""
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers import admin_tenants
    from apps.octo.db import connect as _connect

    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    store.close(A, inc["id"], by="1", code="remediated", text="cleaned")
    manual = store.add_window(A, inc["id"], start="2026-09-01T00:00:00Z", end=None, by="1",
                              reason="claim CL-0003: keep it all")
    reg = _connect(paths.registry_db_path())
    try:
        for check in (lambda: admin_tenants._check_offboardable(reg, A),
                      lambda: admin_tenants._check_mergeable(reg, A, B)):
            with pytest.raises(APIError) as refused:
                check()
            assert "no end" in refused.value.message
            assert f"#{manual.id}" in refused.value.message
        # Given an end — a bounded window covering it, the open one released.
        store.add_window(A, inc["id"], start="2026-09-01T00:00:00Z",
                         end="2026-10-01T00:00:00Z", by="1", reason="claim CL-0003, bounded")
        store.release_window(A, inc["id"], manual.id, by="1",
                             reason="replaced by the bounded window")
        admin_tenants._check_offboardable(reg, A)
        admin_tenants._check_mergeable(reg, A, B)
    finally:
        reg.close()


def test_adding_or_extending_a_window_is_an_admin_with_step_up(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    body = {"start": "2026-08-01T00:00:00Z", "reason": "claim CL-0001 — keep it all"}
    assert api.post(_url(inc, "evidence-window"), json=body).status_code == 403
    _as(api, "adm", "admin")
    r = api.post(_url(inc, "evidence-window"), json=body)
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    assert audit_rows("incident.evidence_window_add") == []              # nothing audited
    _as(api, "adm2", "admin", elevate=True)
    before = len(notices("threat_registry"))
    r = api.post(_url(inc, "evidence-window"), json=body)
    assert r.status_code == 200, r.text
    manual = r.json()
    assert (manual["kind"], manual["start"], manual["end"], manual["open"]) == (
        "manual", "2026-08-01T00:00:00.000Z", None, True)              # held until released
    assert audit_rows("incident.evidence_window_add")
    assert len(notices("threat_registry")) > before                      # the others told
    # Extend: never a shrink.
    ext = {"window_id": manual["id"], "start": "2026-08-15T00:00:00Z", "reason": "shrink"}
    r = api.post(_url(inc, "evidence-window"), json=ext)
    assert r.status_code == 409 and "never shrinks" in r.json()["message"]
    r = api.post(_url(inc, "evidence-window"),
                 json={**ext, "start": "2026-07-01T00:00:00Z", "reason": "the claim grew"})
    assert r.status_code == 200 and r.json()["start"] == "2026-07-01T00:00:00.000Z"
    assert audit_rows("incident.evidence_window_extend")
    assert api.post(_url(inc, "evidence-window"),
                    json={"start": "yesterday-ish", "reason": "x y z"}).status_code == 422


def test_a_release_is_an_admin_with_step_up_after_the_all_clear_and_the_others_are_told(api):
    _as(api, "ana", "analyst", [A])
    inc = _red(api)
    (w,) = _windows(api, inc)
    url = _url(inc, f"evidence-window/{w['id']}/release")
    body = {"reason": "the claim is settled"}
    assert api.post(url, json=body).status_code == 403                  # an analyst: never
    _as(api, "adm", "admin")
    assert api.post(url, json=body).status_code == 401                  # step-up first
    _as(api, "adm2", "admin", elevate=True)
    r = api.post(url, json=body)                                        # before the all-clear
    assert r.status_code == 409 and "all-clear" in r.json()["message"]
    assert audit_rows("incident.evidence_window_release")               # audited first …
    assert audit_rows("incident.evidence_window_release_failed")        # … and said it failed
    api.post(_url(inc, "close"), json={"code": "remediated", "text": "reimaged the device"})
    (w,) = _windows(api, inc)
    assert w["end"] is not None and w["held"]                           # kept: no expiry
    other = api.provision_operator("adm3", PW, role="admin", athena_role="admin")
    before = [n for n in notices("threat_registry") if n["recipient_id"] == other["id"]]
    r = api.post(url, json=body)
    assert r.status_code == 200 and r.json()["held"] is False
    assert r.json()["release_reason"] == "the claim is settled"
    told = [n for n in notices("threat_registry") if n["recipient_id"] == other["id"]]
    assert len(told) == len(before) + 1 and "Evidence released" in told[-1]["title"]
    assert api.post(url, json=body).status_code == 409                  # once
    assert api.get(_url(inc)).json()["incident"]["evidence_held"] is False
    assert api.get("/api/v1/incidents/evidence-windows").json()["items"] == []
    released = api.get("/api/v1/incidents/evidence-windows?state=released").json()["items"]
    assert [x["id"] for x in released] == [w["id"]]


def test_a_client_user_sees_nothing_of_an_evidence_window(api):
    inc = _visible_black(api)
    (w,) = _windows(api, inc)
    _as(api, "erin", "viewer", [A])
    assert api.get("/api/v1/incidents/evidence-windows").status_code == 403
    for path, body in ((_url(inc, "evidence-window"), {"start": "2026-08-01T00:00:00Z",
                                                       "reason": "abc"}),
                       (_url(inc, f"evidence-window/{w['id']}/widen"),
                        {"start": "2026-08-01T00:00:00Z", "reason": "abc"}),
                       (_url(inc, f"evidence-window/{w['id']}/release"), {"reason": "abc"})):
        assert api.post(path, json=body).status_code == 403, path
    for path in ("/api/v1/incidents/client", "/api/v1/incidents/summary",
                 "/api/v1/fleet/sites"):
        text = json.dumps(api.get(path).json()).lower()
        assert "evidence" not in text and "window" not in text, path


def test_the_detail_says_why_this_device_and_the_freshness_at_open(api):
    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    detail = api.get(_url(inc)).json()
    assert any("named by the person who declared it" in w for w in detail["why_device"])
    sources_ = {f["source"] for f in detail["freshness"]}
    assert "tier_worker" in sources_
    assert all({"label", "last_ok_at", "blind"} <= set(f) for f in detail["freshness"])
    assert detail["incident"]["ready_to_close"] is False


def test_a_client_users_search_never_returns_an_incidents_own_record(api):
    """The `athena.incident` lifecycle events (design 6.3) carry the device,
    the rule and the analyst's summary: an operator's search returns them, a
    client user's never does (nor its payload by id)."""
    _as(api, "ana", "analyst", [A], elevate=True)
    _declare(api)
    found = api.post("/api/v1/search/events", json={"tenants": [A], "limit": 50}).json()
    own = [r for r in found["results"] if r["event_type"] == "athena.incident"]
    assert own and own[0]["source"] == "athena"
    _as(api, "erin", "viewer", [A], elevate=True)
    seen = api.post("/api/v1/search/events", json={"tenants": [A], "limit": 50})
    assert seen.status_code == 200
    assert all(r["event_type"] != "athena.incident" for r in seen.json()["results"])
    assert api.get(f"/api/v1/search/event/{A}/{own[0]['event_id']}").status_code == 404
    # The site's alert list (operators) is signals only, never the record.
    _as(api, "ana2", "analyst", [A])
    (site,) = [s for s in api.get("/api/v1/fleet/sites").json()["sites"]
               if s["tenant_slug"] == A]
    alerts = api.get(f"/api/v1/fleet/sites/{site['key']}/alerts").json()["items"]
    assert all(a["source"] != "athena" for a in alerts)


def test_a_tenant_with_an_open_incident_is_never_offboarded_or_merged_away(api):
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers import admin_tenants
    from apps.octo.db import connect as _connect

    _as(api, "ana", "analyst", [A])
    inc = _declare(api)
    reg = _connect(paths.registry_db_path())
    try:
        with pytest.raises(APIError) as off:
            admin_tenants._check_offboardable(reg, A)
        assert "open BLACK incident" in off.value.message
        with pytest.raises(APIError) as merge:
            admin_tenants._check_mergeable(reg, A, B)
        assert "open BLACK incident" in merge.value.message
        # Closed by a person: both go ahead.
        store.close(A, inc["id"], by="1", code="remediated", text="cleaned")
        admin_tenants._check_offboardable(reg, A)
        admin_tenants._check_mergeable(reg, A, B)
    finally:
        reg.close()
