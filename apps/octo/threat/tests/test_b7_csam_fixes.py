"""B7 — the fixer's round (v0.17.1 reviews: CSAM safety + precision).

  CSAM-1  the same lookup reaches Athena through a buoy's OTHER sensors
          (Pi-hole records NextDNS's answer as an upstream block — a signal,
          an indicator; Suricata logs the query — telemetry). Every general
          surface hides those rows for EVERY role; an admin reads them only
          in the restricted incident's audited detail (defanged). A model
          never sees one — nor a DNS sensor's block too young to be checked;
  CSAM-4  a false-positive close of B7 writes NO verdict: the next lookup
          opens (reopens) a Black and pages again;
  CSAM-5  an admin's free text on a B7 evidence window is never shown
          outside the audited detail;
  P-3     matching is label-bounded and on the exact domain (not its root):
          a sibling on the same host is triaged as usual; enrichment still
          refuses the root.

Fixtures are placeholders only: `csam-placeholder.example.test`, TEST-NET
addresses, fictional devices and people.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.api.indicator_mask import mask_indicator
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.tests._tiering_fixtures import pihole_payload, write_telemetry
from apps.octo.tests.auth.conftest import auth_client, auth_data_root  # noqa: F401
from apps.octo.threat import registry, restricted, store
from apps.octo.threat.tests.conftest import A, audit_rows, insert_event, notices
from apps.octo.threat.tests.test_b7_csam import (
    DOMAIN,
    _iurl,
    _no_secret,
    _open_via_engine,
    b7,
    lookup,
    run,
)
from apps.octo.threat.tests.test_incidents_api import _as, api  # noqa: F401

ORDINARY = "ordinary-site.example.test"


def _ago(**kw) -> str:
    return format_utc_ms(datetime.now(timezone.utc) - timedelta(**kw))


def _indicator(slug: str, value: str, context: str = "") -> int:
    conn = sqlite3.connect(paths.client_dir(slug) / "indicators.db")
    try:
        cur = conn.execute(
            "INSERT INTO indicators (value, type, source, severity, confidence, context, "
            "first_seen, last_seen) VALUES (?, 'domain', 'buoy', 'medium', 0.6, ?, ?, ?)",
            (value, context or None, _ago(minutes=20), _ago(minutes=10)))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _event(*, source: str, event_type: str, payload: dict, summary: str, at: str,
           severity: str = "medium", host: str = "buoy-acme-1") -> int:
    import os

    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (at, source, host, event_type, severity, json.dumps(payload),
             f"sha-{os.urandom(6).hex()}", summary))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _seed_buoy_sensors() -> dict[str, int]:
    """What a buoy tenant's sensors record for ONE CSAM lookup — and for an
    ordinary one beside it."""
    ids = {
        # Pi-hole: NextDNS answered 0.0.0.0 → "upstream blocked" (status 7).
        "pihole": _event(source="buoy:acme", event_type="pihole.query",
                         payload=pihole_payload(7, DOMAIN, client="192.0.2.77"),
                         summary=f"blocked upstream: {DOMAIN} (192.0.2.77)",
                         at=_ago(minutes=40)),
        # Suricata: an alert on the DNS query.
        "suricata": _event(source="suricata", event_type="suricata.alert",
                           payload={"dns": {"rrname": f"img.{DOMAIN}"}, "src_ip": "192.0.2.77"},
                           summary="ET POLICY a DNS lookup", at=_ago(minutes=39),
                           severity="high"),
        "ordinary_pihole": _event(source="buoy:acme", event_type="pihole.query",
                                  payload=pihole_payload(7, ORDINARY),
                                  summary=f"blocked upstream: {ORDINARY}", at=_ago(minutes=38)),
        "ordinary_alert": _event(source="suricata", event_type="suricata.alert",
                                 payload={"dns": {"rrname": ORDINARY}},
                                 summary=f"ET POLICY a lookup of {ORDINARY}",
                                 at=_ago(minutes=37), severity="high"),
        "ind": _indicator(A, DOMAIN),
        "ind_ordinary": _indicator(A, ORDINARY),
    }
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    root = paths.client_dir(A).parent.parent
    write_telemetry(root, A, received_at=_ago(minutes=40), domain=DOMAIN, device="192.0.2.77",
                    event_type="suricata.dns", n=1)
    write_telemetry(root, A, received_at=_ago(minutes=38), domain=ORDINARY, device="192.0.2.78",
                    event_type="suricata.dns", n=2)
    return ids


def _all_surfaces(client) -> dict[str, str]:
    """Every general surface an operator reads, as text."""
    out: dict[str, str] = {}
    since = _ago(hours=6)
    r = client.post("/api/v1/search/events", json={"tenants": [A], "time_from": since})
    assert r.status_code == 200, r.text
    out["events"] = r.text
    r = client.post("/api/v1/search/indicators", json={"tenants": [A]})
    assert r.status_code == 200, r.text
    out["indicators"] = r.text
    r = client.post("/api/v1/search/dns", json={"tenant": A, "domain": DOMAIN})
    assert r.status_code == 200, r.text
    out["dns_search"] = r.text
    r = client.post("/api/v1/search/dns", json={"tenant": A})
    assert r.status_code == 200, r.text
    out["dns_summary_full"] = r.text
    r = client.get("/api/v1/dashboard/dns-summary")
    assert r.status_code == 200, r.text
    out["dns_dashboard"] = r.text
    r = client.get("/api/v1/dashboard/recent-events?min_severity=info&limit=100")
    assert r.status_code == 200, r.text
    out["recent"] = r.text
    r = client.get("/api/v1/dashboard/ti-pulse")
    assert r.status_code == 200, r.text
    out["pulse"] = r.text
    r = client.post("/api/v1/search/export", json={
        "tenants": [A], "time_from": since, "format": "csv", "include_indicators": True})
    assert r.status_code == 200, r.text
    out["export"] = r.text
    return out


def _assert_hidden(texts: dict[str, str]) -> None:
    for name, text in texts.items():
        assert "csam-placeholder" not in text.lower(), name
    # The masked views: the ordinary domain only — not even a masked form.
    pulse = json.loads(texts["pulse"])["items"]
    assert [i["masked_value"] for i in pulse] == [mask_indicator(ORDINARY, "domain")]
    (tenant,) = [t for t in json.loads(texts["dns_dashboard"])["tenants"] if t["tenant"] == A]
    assert [d["masked_domain"] for d in tenant["top_domains"]] == [
        mask_indicator(ORDINARY, "domain")]
    assert [d["masked_domain"] for d in tenant["first_seen"]] == [
        mask_indicator(ORDINARY, "domain")]
    assert tenant["first_seen_count"] == 1
    full = json.loads(texts["dns_summary_full"])
    assert [d["domain"] for d in full["top_domains"]] == [ORDINARY]
    asked = json.loads(texts["dns_search"])
    assert asked["sightings"] == [] and asked["lookups_found"] == []
    # The feed and the export still carry the ordinary rows beside them.
    assert ORDINARY in texts["recent"] and ORDINARY in texts["export"]


# ---------------------------------------------------------------------------
# CSAM-1 — a buoy tenant's other sensors
# ---------------------------------------------------------------------------

def test_csam1_before_the_poll_the_sensor_rows_are_ordinary_rows(api):  # noqa: F811
    """The fixture is real: without restricted evidence the rows show."""
    _seed_buoy_sensors()
    _as(api, "alice", "analyst", [A], elevate=True)
    r = api.post("/api/v1/search/events", json={"tenants": [A], "time_from": _ago(hours=6)})
    assert "csam-placeholder" in r.text


def test_csam1_every_general_surface_hides_them_from_every_role(api):  # noqa: F811
    ids = _seed_buoy_sensors()
    inc = _open_via_engine()
    for name, role in (("alice", "analyst"), ("bob", "admin"), ("carol", "super_admin")):
        _as(api, name, role, [A] if role == "analyst" else None, elevate=True)
        texts = _all_surfaces(api)
        _assert_hidden(texts)
        # The ordinary rows beside them are untouched.
        assert ORDINARY in texts["events"] and ORDINARY in texts["indicators"]
        events = api.post("/api/v1/search/events", json={
            "tenants": [A], "time_from": _ago(hours=6)}).json()
        shown = {r["event_id"] for r in events["results"]}
        assert ids["pihole"] not in shown and ids["suricata"] not in shown
        assert {ids["ordinary_pihole"], ids["ordinary_alert"]} <= shown
        # The count agrees with the rows: nothing hints at a hidden one.
        assert events["total_estimate"] == len(events["results"])
        # The payload drawer: the same answer as no such event — audited.
        r = api.get(f"/api/v1/search/event/{A}/{ids['pihole']}")
        assert r.status_code == 404
        _no_secret(r.text)
        assert api.get(f"/api/v1/search/event/{A}/{ids['ordinary_pihole']}").status_code == 200
    refused = [json.loads(r["after_state"]) for r in audit_rows("search.event_payload")
               if json.loads(r["after_state"]).get("restricted_refused")]
    assert len(refused) == 3
    for row in refused:
        _no_secret(json.dumps(row))
    # The Fleet drawer's alert list (any site of the tenant).
    _as(api, "dave", "analyst", [A])
    sites = api.get("/api/v1/fleet/sites").json()["sites"]
    for s in sites:
        r = api.get(f"/api/v1/fleet/sites/{s['key']}/alerts")
        if r.status_code == 200:
            _no_secret(r.text)
    assert b7() == [store.get(A, inc.id)]


def test_csam1_an_admin_reads_them_in_the_incident_only_defanged_and_audited(api):  # noqa: F811
    ids = _seed_buoy_sensors()
    inc = _open_via_engine()
    _as(api, "ana", "analyst", [A])
    r = api.get(_iurl(inc))
    assert r.status_code == 403
    _no_secret(r.text)
    _as(api, "bob", "admin")
    r = api.get(_iurl(inc))
    assert r.status_code == 200, r.text
    related = r.json()["restricted"]["related"]
    assert {x["event_id"] for x in related} == {ids["pihole"], ids["suricata"]}
    for x in related:
        assert "csam-placeholder[.]example[.]test" in x["payload_defanged"]
    assert DOMAIN not in r.text                                  # never the live form
    (row,) = audit_rows("incident.restricted_view")
    assert json.loads(row["after_state"])["related_shown"] == 2


def test_csam1_an_unreadable_list_hides_rows_fail_closed(api, monkeypatch):  # noqa: F811
    _seed_buoy_sensors()
    _as(api, "alice", "analyst", [A], elevate=True)

    def broken(slug):
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(restricted, "restricted_domains", broken)
    r = api.post("/api/v1/search/events", json={"tenants": [A], "time_from": _ago(hours=6)})
    assert r.status_code == 200 and r.json()["results"] == []


def test_csam1_no_model_for_a_young_dns_sensor_block_even_before_the_poll(troot, monkeypatch):
    """The race: Pi-hole's row arrives seconds after the lookup, the NextDNS
    poll that would mark it restricted runs every 10 minutes. A model never
    sees a DNS sensor's block younger than SENSOR_HOLD."""
    from apps.octo.agent import llm_escalation
    from apps.octo.agent.heuristic_l1 import TriageFeatures

    calls: list[dict] = []
    monkeypatch.setattr(llm_escalation, "_call_octo_llm_triage",
                        lambda payload: calls.append(payload) or {
                            "disposition": "noise", "disposition_reason": "x",
                            "confidence": 0.5})
    young = insert_event(A, source="buoy:acme", event_type="pihole.query",
                         payload=pihole_payload(7, ORDINARY), received_at=_ago(minutes=2),
                         severity="medium")
    young_suricata = insert_event(A, source="suricata", event_type="suricata.alert",
                                  payload={"dns": {"rrname": ORDINARY}},
                                  received_at=_ago(minutes=2), severity="high")
    old = insert_event(A, source="buoy:acme", event_type="pihole.query",
                       payload=pihole_payload(7, ORDINARY), received_at=_ago(minutes=45),
                       severity="medium")
    other = insert_event(A, source="wazuh", event_type="wazuh.alert",
                         payload={"rule": {"level": 7}}, received_at=_ago(minutes=1))
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        rows = {r["id"]: r for r in conn.execute(
            "SELECT id, received_at, source, source_host, event_type, severity, payload, "
            "summary FROM events")}
    finally:
        conn.close()
    feats = TriageFeatures(severity="medium", has_indicator=True)
    assert llm_escalation.escalate_uncertain(rows[young], feats, A) is None
    assert llm_escalation.escalate_uncertain(rows[young_suricata], feats, A) is None
    assert calls == []
    assert llm_escalation.escalate_uncertain(rows[old], feats, A) is not None
    assert llm_escalation.escalate_uncertain(rows[other], feats, A) is not None
    assert len(calls) == 2


def test_csam1_the_operators_model_enrichment_refuses_restricted_content(troot):
    from apps.octo.api.errors import APIError
    from apps.octo.api.routers import agent_query

    now = datetime.now(timezone.utc)
    pihole = insert_event(A, source="buoy:acme", event_type="pihole.query",
                          payload=pihole_payload(7, DOMAIN), received_at=_ago(hours=2),
                          severity="medium")
    plain = insert_event(A, source="wazuh", event_type="wazuh.alert",
                         payload={"rule": {"level": 7}}, received_at=_ago(hours=2))
    young = insert_event(A, source="buoy:acme", event_type="pihole.query",
                         payload=pihole_payload(7, ORDINARY), received_at=_ago(minutes=1),
                         severity="medium")
    lookup(A, now)

    def ask(ref_id: int, note: str = "an alert on a workstation", signals=()) -> None:
        body = agent_query.AgentQueryRequest(
            client_slug=A, ref_kind="event", ref_id=ref_id, query_kind="tell_me_more",
            heuristic_note=note, signals=list(signals))
        agent_query._restricted_or_audit(operator_id=7, body=body, request_id="r-1")

    ask(plain)                                                   # passes
    for args in ((pihole,), (plain, f"the device looked up {DOMAIN}"),
                 (plain, "x", (f"dns:img.{DOMAIN}",)), (young,)):
        with pytest.raises(APIError) as exc:
            ask(*args)
        assert exc.value.code == "PRECONDITION_FAILED"
        assert "csam" not in str(exc.value.message).lower()
    whys = [json.loads(r["after_state"])["why"] for r in audit_rows("octo_llm_query_restricted")]
    assert whys == ["restricted_content", "restricted_content", "restricted_content",
                    "sensor_hold"]


# ---------------------------------------------------------------------------
# P-3 — label-bounded, the exact domain (not the root) for reads and triage
# ---------------------------------------------------------------------------

def test_p3_matching_is_label_bounded_and_on_the_exact_domain(troot):
    from apps.octo.agent import worker

    now = datetime.now(timezone.utc)
    lookup(A, now, domain="a1.imghost-placeholder.example.test")
    with restricted._read(A) as conn:                           # the root is kept too
        roots = {r[0] for r in conn.execute(f"SELECT root FROM {restricted.TABLE}")}
    assert roots == {"a1.imghost-placeholder.example.test"}       # the fixture's root
    gate = restricted.Gate.for_tenant(A)
    assert gate.hits('{"rrname":"a1.imghost-placeholder.example.test"}')
    assert gate.hits("x.a1.imghost-placeholder.example.test.")
    assert gate.hits("https://A1.IMGHOST-placeholder.example.test/path")
    for text in ("b2.imghost-placeholder.example.test", "xa1.imghost-placeholder.example.test",
                 "a1.imghost-placeholder.example.testing", "imghost-placeholder.example.test"):
        assert not gate.hits(text), text
        assert not restricted.text_mentions(text, {"a1.imghost-placeholder.example.test"})
    # The old substring test matched inside a longer name — never again.
    assert not restricted.text_mentions("myt.co.example", {"t.co"})
    assert restricted.text_mentions("see t.co/x", {"t.co"})
    # A sibling on the same host is triaged as usual; the name itself never.
    worker.process_tenant_once(A)                               # watermark at the head
    sibling = insert_event(A, source="suricata", event_type="suricata.alert",
                           payload={"dns": {"rrname": "b2.imghost-placeholder.example.test"}})
    named = insert_event(A, source="suricata", event_type="suricata.alert",
                         payload={"dns": {"rrname": "a1.imghost-placeholder.example.test"}})
    worker.process_tenant_once(A)
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        noted = {r[0] for r in conn.execute("SELECT ref_id FROM agent_notes")}
    finally:
        conn.close()
    assert sibling in noted and named not in noted


def test_p3_enrichment_still_refuses_the_root_and_names_under_it(troot):
    now = datetime.now(timezone.utc)
    restricted.record_nextdns(
        A, profile_id="pfx001", profile_name="Placeholder DNS",
        line={"timestamp": format_utc_ms(now), "domain": "a1.imghost-placeholder.example.test",
              "root": "imghost-placeholder.example.test", "clientIp": "192.0.2.77",
              "device": {"id": "DPLC01", "name": "ws-placeholder-07"}, "status": "blocked",
              "reasons": [{"id": "csam", "name": "Child Sexual Abuse Material"}]},
        line_id="root-line", observed_at=format_utc_ms(now))
    for value in ("imghost-placeholder.example.test", "b2.imghost-placeholder.example.test"):
        with pytest.raises(restricted.RestrictedContent):
            restricted.refuse_enrichment(A, value)               # an RDAP is about the root
    restricted.refuse_enrichment(A, "other-host.example.test")
    # …but reads and triage hide the exact domain only.
    assert not restricted.Gate.for_tenant(A).hits("b2.imghost-placeholder.example.test")


# ---------------------------------------------------------------------------
# CSAM-4 — a false-positive close never silences the device
# ---------------------------------------------------------------------------

def test_csam4_a_false_positive_close_writes_no_verdict_and_the_next_lookup_pages(api):  # noqa: F811
    inc = _open_via_engine()
    _as(api, "bob", "admin", elevate=True)
    r = api.post(_iurl(inc, "close"), json={
        "code": "false_positive", "text": "the address belonged to another device"})
    assert r.status_code == 200, r.text
    assert audit_rows("verdict.create") == []
    assert not registry.verdict_blocks(A, inc.dedupe_key, datetime.now(timezone.utc))
    pages = len(notices("threat_black"))
    # Even a verdict row written before the fix is not honoured for B7.
    from apps.octo.db import connect, transaction

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            registry.add_verdict(reg, slug=A, device_ref=inc.device_ref, key=inc.dedupe_key,
                                 rule_id="B7", incident_id=inc.id, reason="pre-fix verdict",
                                 by=1)
    finally:
        reg.close()
    later = datetime.now(timezone.utc) + timedelta(minutes=5)
    lookup(A, later, n=9)
    run(later)
    (again,) = b7()
    assert again.id == inc.id and again.is_open and again.tier == "black"   # reopened
    assert again.reopened_count == 1
    assert len(notices("threat_black")) > pages                  # paged again
    assert restricted.pending(A) == []
    assert audit_rows("incident.blocked_by_verdict") == []


# ---------------------------------------------------------------------------
# CSAM-5 — an admin's free text on a B7 evidence window
# ---------------------------------------------------------------------------

def test_csam5_window_reasons_and_names_stay_in_the_audited_detail(api):  # noqa: F811
    inc = _open_via_engine()
    reason = "hold for the NCMEC report — lookups from ws-placeholder-07"
    adm = _as(api, "bob", "admin", elevate=True)
    r = api.post(_iurl(inc, "evidence-window"), json={
        "start": _ago(days=2), "end": _ago(days=1), "reason": reason})
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == reason                          # the admin who wrote it
    wid = r.json()["id"]
    for name, role in (("alice", "analyst"), ("bob2", "admin")):
        _as(api, name, role, [A] if role == "analyst" else None)
        r = api.get("/api/v1/incidents/evidence-windows")
        assert r.status_code == 200
        mine = [w for w in r.json()["items"] if w["incident_id"] == inc.id]
        assert mine and all(w["reason"] == "restricted" for w in mine)
        assert all(w["opened_by_name"] is None for w in mine)
        assert all(w["opened_by"] in ("restricted",) for w in mine)
        assert "ncmec" not in r.text.lower() and "ws-placeholder" not in r.text.lower()
        assert str(adm["id"]) not in [w["opened_by"] for w in mine]
    # The audited admin detail shows it.
    _as(api, "bob3", "admin")
    d = api.get(_iurl(inc)).json()
    assert [w["reason"] for w in d["evidence_windows"] if w["id"] == wid] == [reason]
