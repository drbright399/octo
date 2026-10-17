"""B7 — a CSAM lookup is an AUTOMATED, RESTRICTED Black (Rick, 2026-10-06):

  "confirmed CSAM lookups is an automated Black Tier item. That's
  state/federal law enforcement territory that needs to be handled
  immediately."

B1 any CSAM block opens a LIVE Black, one per device (repeats append);
B2 paged at once, neutral text, no domain anywhere in a notice or e-mail;
B3 the evidence window opens from the first lookup; B4 no device action of
any kind; B5 admin / super_admin only — analysts read "restricted incident",
viewers nothing, every view audited; B6 the client notice is an MSP switch,
OFF by default, admin+ and audited; B7 never resolved / fetched / enriched /
previewed (the enrichment gate refuses it); B8 the fixed checklist; B9 the
normal Black close.

Fixtures are placeholders only: the domain is `csam-placeholder.example.test`
(no real domain), the device and people are fictional.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.fleet import build, sources
from apps.octo.fleet import state as fs
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.tests.auth.conftest import auth_client, auth_data_root  # noqa: F401
from apps.octo.threat import (
    brake,
    client_view,
    engine,
    notify,
    registry,
    restricted,
    store,
    windows,
)
from apps.octo.threat.tests.conftest import (
    A,
    B,
    add_operator,
    audit_rows,
    insert_event,
    notices,
)
from apps.octo.threat.tests.test_incidents_api import PW, _as, _url, api  # noqa: F401

DOMAIN = "csam-placeholder.example.test"
DEVICE = "DPLC01"
DEVICE_NAME = "ws-placeholder-07"
SECRETS = (DOMAIN, "csam-placeholder", DEVICE_NAME.lower(), DEVICE.lower(), "csam")


def iso(dt: datetime) -> str:
    return format_utc_ms(dt)


def line(at: datetime, *, domain: str = DOMAIN, device_id: str = DEVICE,
         device_name: str = DEVICE_NAME, extra: tuple[tuple[str, str], ...] = ()) -> dict:
    return {"timestamp": iso(at), "domain": domain, "root": domain, "encrypted": True,
            "protocol": "DNS-over-HTTPS", "clientIp": "192.0.2.77", "client": None,
            "device": {"id": device_id, "name": device_name, "model": "Example Laptop"},
            "status": "blocked",
            "reasons": [*({"id": r, "name": n} for r, n in extra),
                        {"id": "csam", "name": "Child Sexual Abuse Material"}]}


def lookup(slug: str, at: datetime, n: int = 0, **kw) -> int | None:
    return restricted.record_nextdns(slug, profile_id="pfx001", profile_name="Placeholder DNS",
                                     line=line(at, **kw), line_id=f"line-{n}-{iso(at)}",
                                     observed_at=iso(at))


def run(now: datetime) -> dict:
    return engine.TierWorker(now=lambda: now).run_once()


def b7(slug: str = A) -> list[store.Incident]:
    return [i for i in store.list_incidents(slug) if i.rule_id == "B7"]


def _texts(rows) -> str:
    return json.dumps([dict(r) for r in rows], default=str).lower()


# ---------------------------------------------------------------------------
# B1 — automated, LIVE, one per device, repeats append
# ---------------------------------------------------------------------------

def test_b1_one_csam_lookup_opens_a_live_restricted_black(troot):
    now = datetime.now(timezone.utc)
    assert lookup(A, now - timedelta(minutes=2)) is not None
    out = run(now)
    assert out[A]["opened"] == 1
    (inc,) = b7()
    assert inc.tier == "black" and inc.is_open and inc.restricted
    assert inc.opened_by == store.SYSTEM_ACTOR and inc.device_ref == DEVICE
    assert inc.device_label == DEVICE_NAME and inc.scope == "device"
    assert DOMAIN not in inc.summary and DOMAIN not in json.dumps(inc.evidence)
    # Not a shadow would-fire: a real record.
    assert store.would_fires(A, now - timedelta(days=1)) == []
    (row,) = restricted.for_incident(A, inc.id)
    assert row["domain_defanged"] == "csam-placeholder[.]example[.]test"


def test_b1_repeats_append_one_incident_per_device_exactly_once(troot):
    now = datetime.now(timezone.utc)
    lookup(A, now - timedelta(minutes=30), 1)
    run(now - timedelta(minutes=29))
    lookup(A, now - timedelta(minutes=10), 2)
    lookup(A, now - timedelta(minutes=10), 2)                  # the same line twice
    lookup(A, now - timedelta(minutes=5), 3, device_id="DPLC02", device_name="ws-placeholder-08")
    run(now)
    incs = sorted(b7(), key=lambda i: i.id)
    assert len(incs) == 2                                       # one per device
    first, second = incs
    assert len(restricted.for_incident(A, first.id)) == 2      # appended, deduped
    assert len(restricted.for_incident(A, second.id)) == 1
    assert any(n["kind"] == "evidence" and "B7" in n["text"] for n in store.notes(A, first.id))
    assert restricted.pending(A) == []


def test_b1_a_lookup_before_the_first_pass_is_never_skipped_as_backlog(troot):
    now = datetime.now(timezone.utc)
    lookup(A, now - timedelta(hours=3))
    run(now)                                                    # the very first pass
    assert len(b7()) == 1


def test_b1_any_reason_position_and_no_ordinary_alert(troot):
    """A line with csam anywhere among its reasons is restricted evidence,
    never an events-table alert (so never searched, exported, an indicator,
    triaged or sent to a model)."""
    now = datetime.now(timezone.utc)
    lookup(A, now, extra=(("threat-intelligence-feeds", "Threat Intelligence Feeds"),))
    run(now)
    assert len(b7()) == 1
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        rows = conn.execute("SELECT summary, payload, source_host, event_type FROM events")\
            .fetchall()
    finally:
        conn.close()
    text = json.dumps(rows).lower()
    for secret in SECRETS:
        assert secret not in text, secret


# ---------------------------------------------------------------------------
# B2 — paged at once, admins, neutral
# ---------------------------------------------------------------------------

def test_b2_paged_at_once_to_admins_with_a_neutral_text_even_on_a_weekend_night(troot,
                                                                                  mailer):
    ana = add_operator("alice", "analyst", [A])
    adm = add_operator("bob", "admin")
    root = add_operator("carol", "super_admin")
    # Saturday, 03:00 business time: Black never waits for business hours.
    now = datetime(2026, 10, 3, 8, 0, tzinfo=timezone.utc)
    assert not notify.in_business_hours(now)
    lookup(A, now - timedelta(minutes=1))
    run(now)
    (inc,) = b7()
    assert inc.escalation_step >= 1
    pages = notices("threat_black")
    assert {p["recipient_id"] for p in pages} == {adm, root}    # not the analyst
    assert ana not in {p["recipient_id"] for p in notices()}
    for p in pages:
        assert p["title"] == "Restricted Black incident at Acme Corp — open Athena"
    assert mailer.sent and all(s[1] == notify.RESTRICTED_SUBJECT for s in mailer.sent)
    blob = (_texts(notices()) + json.dumps(mailer.sent)).lower()
    for secret in SECRETS:
        assert secret not in blob, secret
    assert "acme corp" not in json.dumps(mailer.sent).lower()   # e-mail: not even the tenant
    # The follow-ups stay neutral too.
    store.ack(A, inc.id, by=str(adm), now=now)
    inc = store.get(A, inc.id)
    sent = notify.acked_followup(inc, now + timedelta(hours=5), last_activity=None,
                                 tenant_name="Acme Corp")
    assert sent
    for secret in SECRETS:
        assert secret not in _texts(notices()), secret


# ---------------------------------------------------------------------------
# B3 — the evidence window opens from the first lookup
# ---------------------------------------------------------------------------

def test_b3_the_evidence_window_starts_at_the_first_lookup(troot):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    first = now - timedelta(hours=3)
    lookup(A, first, 1)
    lookup(A, now - timedelta(hours=1), 2)
    run(now)
    (inc,) = b7()
    (w,) = store.evidence_windows(A, incident_id=inc.id)
    assert w.start == iso(first) and w.is_open and w.held
    # An EARLIER lookup the poller kept late widens it back.
    lookup(A, first - timedelta(hours=2), 3)
    run(now + timedelta(minutes=1))
    (w,) = store.evidence_windows(A, incident_id=inc.id)
    assert w.start == iso(first - timedelta(hours=2))
    with store.read(A) as conn:
        assert windows.first_detection(conn, inc.id, iso(now)) == w.start


# ---------------------------------------------------------------------------
# B4 — nothing is done to the device
# ---------------------------------------------------------------------------

def test_b4_no_device_action_of_any_kind(troot):
    now = datetime.now(timezone.utc)
    lookup(A, now)
    run(now)
    (inc,) = b7()
    with pytest.raises(store.Refused):
        store.record_decision(A, inc.id, kind="lockdown", requested_by="1",
                              requested_role="analyst", status="recorded", scope=[],
                              excluded=[], notice="")
    with pytest.raises(store.Refused):
        store.contain(A, inc.id, by="1", receipt="isolated")
    with pytest.raises(store.Refused):
        store.reclassify(A, inc.id, by="1", reason="looks like a false positive")
    registry_put(True)
    item = client_view.payload(inc, now + timedelta(hours=2))
    assert item is not None and item["actions"] == []
    with pytest.raises(brake.BrakeError, match="never braked"):
        brake.validate("B7", 1)
    assert brake.ceiling("B7", "black", now) == "black"


def registry_put(value: bool) -> None:
    from apps.octo.db import connect, transaction

    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            registry.put_restricted(reg, {registry.CSAM_CLIENT_NOTICE: value}, by=1)
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# B5 — the Fleet and Athena's own records name nothing
# ---------------------------------------------------------------------------

def test_b5_the_fleet_and_the_lifecycle_records_say_restricted_and_nothing_else(troot):
    now = datetime.now(timezone.utc)
    lookup(A, now)
    run(now)
    (inc,) = b7()
    layer = fs.threat_layer([inc], now=now)
    assert layer.state == fs.BLACK
    (r,) = [x for x in layer.reasons if x.incident_id == inc.id]
    assert r.text.startswith("BLACK: restricted incident — admins only")
    for secret in SECRETS:
        assert secret not in r.text.lower() and secret not in r.neutral.lower()
    entry = build.SiteEntry(key="t-x", kind="tenant", tenant_slug=A, tenant_name="Acme Corp",
                            name="Acme Corp", console_name="", location=None,
                            layers={"threat": layer}, verdict=fs.site_verdict({"threat": layer}),
                            incidents=[inc])
    (item,) = build.threat_incidents([entry], now)
    assert item["restricted"] and item["device_label"] is None
    assert item["rule_id"] == "restricted" and item["summary"] == fs.RESTRICTED_TEXT
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM events WHERE source = 'athena'").fetchall()
    finally:
        conn.close()
    assert rows
    for row in rows:
        assert row["source_host"] is None
        assert row["summary"].endswith("Restricted incident")
        text = (row["payload"] + row["summary"]).lower()
        assert '"b7"' not in text
        for secret in SECRETS:
            assert secret not in text, secret


def test_b6_the_client_sees_nothing_unless_the_msp_switch_is_on(troot):
    now = datetime.now(timezone.utc)
    lookup(A, now)
    run(now)
    (inc,) = b7()
    later = now + timedelta(hours=2)                           # past the 60 minutes
    assert registry.csam_client_notice() is False              # OFF by default
    assert not client_view.visible(inc, later)
    assert client_view.payload(inc, later) is None
    registry_put(True)
    assert client_view.visible(inc, later)
    item = client_view.payload(inc, later)
    assert item["status_neutral"] == client_view.LINE_BLACK and item["actions"] == []
    registry_put(False)
    assert not client_view.visible(inc, later)


# ---------------------------------------------------------------------------
# B7 — never resolved, fetched, enriched or previewed
# ---------------------------------------------------------------------------

def test_b7_the_enrichment_gate_refuses_a_restricted_domain(troot, monkeypatch):
    now = datetime.now(timezone.utc)
    lookup(A, now)
    for value in (DOMAIN, f"www.{DOMAIN}", f"https://{DOMAIN}/x?y=1",
                  "csam-placeholder[.]example[.]test", DOMAIN.upper() + "."):
        with pytest.raises(restricted.RestrictedContent):
            restricted.refuse_enrichment(A, value)
    restricted.refuse_enrichment(A, "ordinary.example.test")        # other domains pass
    restricted.refuse_enrichment(B, DOMAIN)                          # another client's list
    # The list unreadable: refused (fail closed).
    monkeypatch.setattr(restricted, "restricted_values",
                        lambda slug: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    with pytest.raises(restricted.RestrictedContent, match="could not be read"):
        restricted.refuse_enrichment(A, "ordinary.example.test")


def test_b7_no_model_and_no_triage_note_for_an_event_that_names_it(troot, monkeypatch):
    from apps.octo.agent import llm_escalation, worker
    from apps.octo.agent.heuristic_l1 import TriageFeatures

    now = datetime.now(timezone.utc)
    lookup(A, now)
    worker.process_tenant_once(A)                               # watermark at the head
    bad = insert_event(A, source="suricata", event_type="suricata.alert",
                       payload={"dns": {"rrname": f"img.{DOMAIN}"}}, severity="high")
    # (Older than `restricted.SENSOR_HOLD`: a younger DNS sensor record is
    # never sent to a model at all — the fixer's race guard.)
    good = insert_event(A, source="suricata", event_type="suricata.alert",
                        payload={"dns": {"rrname": "ordinary.example.test"}}, severity="high",
                        received_at=format_utc_ms(now - timedelta(minutes=45)))
    worker.process_tenant_once(A)
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        noted = {r[0] for r in conn.execute("SELECT ref_id FROM agent_notes")}
    finally:
        conn.close()
    assert good in noted and bad not in noted
    # The model is never called for it (and is for an ordinary one).
    calls: list[dict] = []
    monkeypatch.setattr(llm_escalation, "_call_octo_llm_triage",
                        lambda payload: calls.append(payload) or {
                            "disposition": "noise", "disposition_reason": "x",
                            "confidence": 0.5})
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        rows = {r["id"]: r for r in conn.execute(
            "SELECT id, received_at, source, source_host, event_type, severity, payload, "
            "summary FROM events WHERE id IN (?, ?)", (bad, good))}
    finally:
        conn.close()
    feats = TriageFeatures(severity="high", has_indicator=True)
    assert llm_escalation.escalate_uncertain(rows[bad], feats, A) is None
    assert calls == []
    assert llm_escalation.escalate_uncertain(rows[good], feats, A) is not None
    assert len(calls) == 1 and DOMAIN not in json.dumps(calls)


# ---------------------------------------------------------------------------
# Through the API — B4, B5, B6, B8, B9
# ---------------------------------------------------------------------------

def _open_via_engine() -> store.Incident:
    now = datetime.now(timezone.utc)
    lookup(A, now - timedelta(minutes=1))
    run(now)
    sources.reset_incident_cache()
    build.invalidate()
    (inc,) = b7()
    return inc


def _iurl(inc: store.Incident, action: str = "") -> str:
    return _url({"tenant_slug": inc.slug, "id": inc.id}, action)


def _no_secret(text: str) -> None:
    low = text.lower()
    for secret in SECRETS:
        assert secret not in low, secret


def test_b5_an_analyst_reads_restricted_incident_and_nothing_more_and_is_audited(api):  # noqa: F811
    inc = _open_via_engine()
    ana = _as(api, "alice", "analyst", [A])
    r = api.get("/api/v1/incidents")
    (item,) = [i for i in r.json()["items"] if i["id"] == inc.id]
    assert item["restricted"] and item["summary"] == "Restricted incident"
    assert item["rule_id"] == "restricted" and item["device_ref"] is None
    assert item["device_label"] is None and item["tenant_name"] == "Acme Corp"
    _no_secret(r.text)
    r = api.get(_iurl(inc))
    assert r.status_code == 403
    _no_secret(r.text)
    (row,) = audit_rows("incident.restricted_denied")
    assert row["actor"] == str(ana["id"]) and row["ts"]          # who, when
    assert api.post(_iurl(inc, "ack"), json={}).status_code == 403
    assert api.post(_iurl(inc, "note"), json={"text": "x"}).status_code == 403
    assert len(audit_rows("incident.restricted_denied")) == 3
    for path in ("/api/v1/incidents/summary", "/api/v1/fleet/sites",
                 "/api/v1/incidents/evidence-windows"):
        r = api.get(path)
        assert r.status_code == 200
        _no_secret(r.text)
    windows_ = api.get("/api/v1/incidents/evidence-windows").json()["items"]
    assert [w["incident_summary"] for w in windows_] == ["Restricted incident"]


def test_b5_b8_an_admin_opens_it_audited_with_the_warning_the_checklist_defanged(api):  # noqa: F811
    inc = _open_via_engine()
    adm = _as(api, "bob", "admin")
    # The LIST names it neutrally for an admin too: the detail is read only
    # through the audited detail route.
    r = api.get("/api/v1/incidents")
    (item,) = [i for i in r.json()["items"] if i["id"] == inc.id]
    assert item["summary"] == "Restricted incident" and item["device_label"] is None
    _no_secret(r.text)
    assert audit_rows("incident.restricted_view") == []
    r = api.get(_iurl(inc))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["incident"]["restricted"] and d["incident"]["device_label"] == DEVICE_NAME
    rs = d["restricted"]
    assert rs["warning"] == "DO NOT OPEN — do not visit, resolve or investigate the content"
    assert rs["checklist"] == [
        "Do not open or investigate the content yourself.",
        "Preserve the device as-is.",
        "Contact law enforcement (US: report via the NCMEC CyberTipline).",
        "Inform the client's leadership / legal contact — not the user involved.",
        "Confirm your obligations with legal counsel."]
    assert rs["lookups"] == 1 and rs["client_notice"] is False
    assert rs["evidence"][0]["domain_defanged"] == "csam-placeholder[.]example[.]test"
    assert DOMAIN not in r.text                                 # never the live form
    assert d["proposed_steps"] == [] and d["decisions"] == [] and d["kill_chain"] == []
    assert d["mode"]["mode"] == "restricted"
    (row,) = audit_rows("incident.restricted_view")
    assert row["actor"] == str(adm["id"]) and row["client_slug"] == A
    _no_secret(row["after_state"] or "")
    api.get(_iurl(inc))
    assert len(audit_rows("incident.restricted_view")) == 2     # every view


def test_b4_the_api_offers_no_device_action(api):  # noqa: F811
    inc = _open_via_engine()
    _as(api, "bob", "admin", elevate=True)
    assert api.post(_iurl(inc, "lockdown-request"),
                    json={"note": "isolate the device now"}).status_code == 409
    assert api.post(_iurl(inc, "contain"), json={"receipt": "isolated"}).status_code == 409
    assert api.post(_iurl(inc, "raise"), json={"reason": "already black"}).status_code == 409
    assert api.post(_iurl(inc, "reclassify"),
                    json={"reason": "not a real one"}).status_code == 409
    # An admin may acknowledge and note it.
    assert api.post(_iurl(inc, "ack"), json={}).status_code == 200
    assert api.post(_iurl(inc, "note"), json={"text": "law enforcement contacted"}) \
        .status_code == 200
    # Assigned to an admin only.
    ana2 = api.provision_operator("ana2", PW, role="analyst", athena_role="analyst",
                                  scope_slugs=[A])
    adm2 = api.provision_operator("adm9", PW, role="admin", athena_role="admin")
    assert api.post(_iurl(inc, "assign"), json={"to": ana2["id"]}).status_code == 422
    assert api.post(_iurl(inc, "assign"), json={"to": adm2["id"]}).status_code == 200
    # The client — even with the notice switched on — gets no action.
    _as(api, "root", "super_admin")
    assert api.put("/api/v1/admin/tiers/restricted", json={
        "csam_client_notice": True, "reason": "the MSP informs its clients"}).status_code == 200
    _as(api, "erin", "viewer", [A])
    (item,) = api.get("/api/v1/incidents/client").json()["items"]
    assert item["actions"] == []
    assert api.post(f"/api/v1/incidents/client/{item['ref']}/decision",
                    json={"kind": "lockdown"}).status_code == 404


def test_b6_the_client_notice_switch_is_off_by_default_admin_only_and_audited(api):  # noqa: F811
    inc = _open_via_engine()
    _as(api, "bob", "admin")
    api.post(_iurl(inc, "ack"), json={})                        # visible "after ack"…
    _as(api, "erin", "viewer", [A])
    assert api.get("/api/v1/incidents/client").json()["items"] == []
    assert api.get("/api/v1/incidents/summary").json() == {"view": "client", "black": 0,
                                                           "red": 0}
    sites = api.get("/api/v1/fleet/sites").json()["sites"]
    assert all(s["state"] != "black" for s in sites)
    # The switch: admin+ with an all-tenant scope, a reason, audited, admins told.
    _as(api, "alice", "analyst", [A])
    assert api.put("/api/v1/admin/tiers/restricted", json={
        "csam_client_notice": True, "reason": "x" * 10}).status_code == 403
    _as(api, "dana", "admin", [A])
    assert api.put("/api/v1/admin/tiers/restricted", json={
        "csam_client_notice": True, "reason": "x" * 10}).status_code == 403
    assert audit_rows("tier_settings.restricted_update") == []
    _as(api, "bob2", "admin")
    assert api.get("/api/v1/admin/tiers/restricted").json()["csam_client_notice"] is False
    assert api.put("/api/v1/admin/tiers/restricted", json={
        "csam_client_notice": True}).status_code == 422          # a reason is mandatory
    r = api.put("/api/v1/admin/tiers/restricted", json={
        "csam_client_notice": True, "reason": "the MSP informs its clients"})
    assert r.status_code == 200 and r.json()["csam_client_notice"] is True
    (row,) = audit_rows("tier_settings.restricted_update")
    assert json.loads(row["before_state"]) == {"csam_client_notice": False}
    assert json.loads(row["after_state"]) == {"csam_client_notice": True}
    assert notices("threat_registry")
    # The knobs route never takes it.
    assert api.put("/api/v1/admin/tiers/yellow", json={
        "values": {"csam_client_notice": False}, "reason": "sneak it off"}).status_code == 422
    _as(api, "erin2", "viewer", [A])
    r = api.get("/api/v1/incidents/client")
    (item,) = r.json()["items"]
    assert item["status_neutral"] == client_view.LINE_BLACK_ACKED and item["actions"] == []
    for path in ("/api/v1/incidents/client", "/api/v1/incidents/summary",
                 "/api/v1/fleet/sites"):
        _no_secret(api.get(path).text)


def test_b9_closing_it_is_the_normal_black_close(api):  # noqa: F811
    inc = _open_via_engine()
    checklist = {"c2_blocked": "n/a", "rescue_point_verified": True,
                 "device_state": "preserved as-is for law enforcement",
                 "client_notified_who": "the client's legal contact",
                 "client_notified_when": "2026-10-06 10:00"}
    body = {"code": "remediated", "text": "reported; the device was handed over",
            "checklist": checklist}
    _as(api, "alice", "analyst", [A])
    assert api.post(_iurl(inc, "close"), json=body).status_code == 403
    _as(api, "bob", "admin")
    r = api.post(_iurl(inc, "close"), json=body)
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    _as(api, "bob2", "admin", elevate=True)
    r = api.post(_iurl(inc, "close"), json=body)
    assert r.status_code == 200 and r.json()["status"] == "closed"
    (w,) = store.evidence_windows(A, incident_id=inc.id)
    assert w.end is not None and w.held                         # kept until released
    _no_secret(_texts(notices()))
