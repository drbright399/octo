"""v0.17.2 — ACKNOWLEDGE, EXPECTED and the drawer's enrichment through the
REAL HTTP routes and real sign-in (Rick's decisions A–D, 2026-10-06):

  * an ack (analyst+, an optional note, audited BEFORE the write) takes the
    alert out of "needs attention" and out of the site's Yellow, never
    touches the event, and a NEW hit re-surfaces it;
  * Red / Black are untouched by an ack or an expected condition;
  * EXPECTED (reason ≥ 10, review ≤ 90 days, an optional remote for a network
    alert) labels matching alerts, the admins are told and reminded 7 days
    before the review date, expiry and revocation stop it; never for a CSAM
    block, an alert an incident rests on, a decoy or a malware verdict;
  * the R8 confirmation is a verdict too;
  * a viewer sees nothing new and may do none of it;
  * the enrichment is cache-only on a page load (the worker looks up in the
    background, through a fake here — nothing leaves the test);
  * the Datto device list of a tenant whose entity switch is OFF names the
    local device and counts the endpoints — and no UDF ever reaches a store,
    a log line or an API answer.
"""
# ruff: noqa: F811 — the `fl` fixture is imported from test_fleet_api.
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.fleet import build
from apps.octo.fleet.tests.fixtures import scope
from apps.octo.tests.auth.test_fleet_api import PW, _audit, _op, _sites, fl  # noqa: F401
from apps.octo.threat import store as incident_store
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.keys import AlertKey
from apps.octo.verdicts.tests.helpers import store_ips_hit

A, B = "acme-corp", "example-bakery"
CONFIRM_REASON = "the client confirmed nobody at the bakery runs this"
# The bakery's LAN (POS, server, the second site's POS). The UniFi catalogue tells the
# device from the remote end by RFC 1918 (catalogue.is_local), an expected rule refuses
# a local remote by the same test, and a Datto device is matched to an IPS hit by its LAN
# address: none of these can be a documentation address.
# scan-sensitive: allow[ip-private] synthetic fixture LAN addresses; is_local needs RFC 1918
POS_IP, SRV_IP, POS2_IP = "10.20.0.37", "10.20.0.2", "10.20.1.37"


def _hour_start(now: datetime) -> datetime:
    """A minute inside the hour that holds now-5 min: hits from here on share
    one coalescing bucket."""
    return (now - timedelta(minutes=5)).replace(minute=1, second=0, microsecond=0)


def _bakery(client) -> dict:
    return next(s for s in _sites(client)["sites"] if s["name"] == "Bakery")


def _alerts(client, key: str, *, handled: bool = False) -> dict:
    url = f"/api/v1/fleet/sites/{key}/alerts" + ("?include=acknowledged" if handled else "")
    r = client.get(url)
    assert r.status_code == 200, r.text
    return r.json()


def _verdicts() -> list[sqlite3.Row]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return reg.execute("SELECT * FROM alert_verdict ORDER BY id").fetchall()
    finally:
        reg.close()


def _event(slug: str, eid: int) -> tuple:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return conn.execute("SELECT received_at, source, payload, payload_sha256 FROM events "
                            "WHERE id = ?", (eid,)).fetchone()
    finally:
        conn.close()


def _insert_event(slug: str, *, source: str, event_type: str, payload: dict,
                  host: str | None = None, severity: str = "high",
                  at: datetime | None = None) -> int:
    import os

    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, payload, "
            "payload_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ((at or datetime.now(timezone.utc) - timedelta(minutes=3))
             .strftime("%Y-%m-%dT%H:%M:%S.000Z"), source, host, event_type, severity,
             json.dumps(payload), f"sha-{os.urandom(6).hex()}"))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# A — acknowledge
# ---------------------------------------------------------------------------

def test_an_ack_hides_the_alert_un_yellows_the_site_and_a_new_hit_re_surfaces_it(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    t0 = _hour_start(datetime.now(timezone.utc))
    eid = store_ips_hit(B, scope(3), t0)
    site = _bakery(client)
    assert site["state"] == "warn" and site["reason"] == "1 IPS block today"
    body = _alerts(client, site["key"])
    (item,) = [i for i in body["items"] if i["event_id"] == eid]
    assert item["status"] == "open" and item["can_expect"] and item["network"]
    assert item["hits"] == 1 and body["hidden"] == 0
    before = _event(B, eid)

    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={"note": "  checked with  the client "})
    assert r.status_code == 200, r.text
    (row,) = _audit("alert.ack")
    assert row["reason"] == "checked with the client" and row["client_slug"] == B
    (v,) = _verdicts()
    assert (v["verdict"], v["event_id"], v["hits_at"], v["note"]) == \
        ("ack", eid, 1, "checked with the client")
    assert v["signature_key"].startswith("unifi.ips_threat:") and v["repeat_until"] is None

    body = _alerts(client, site["key"])
    assert eid not in [i["event_id"] for i in body["items"]] and body["hidden"] == 1
    shown = _alerts(client, site["key"], handled=True)
    (item,) = [i for i in shown["items"] if i["event_id"] == eid]
    assert item["status"] == "acknowledged" and item["ack"]["by_name"]
    assert item["ack"]["note"] == "checked with the client"
    site = _bakery(client)
    assert site["state"] == "ok"                                     # out of the Yellow
    sec = site["layers"]["security"]["data"]
    # The count shown stays the fact (every hit); only the Yellow changed.
    assert sec["ips_blocked_24h"] == 1 and sec["ips_hidden_24h"] == 1
    assert not site["layers"]["security"]["reasons"]
    assert _event(B, eid) == before                                  # the event is untouched

    # A NEW hit of the same coalesced alert re-surfaces it.
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=30))
    body = _alerts(client, site["key"])
    (item,) = [i for i in body["items"] if i["event_id"] == eid]
    assert item["status"] == "resurfaced" and item["new_since_ack"] == 1 and item["hits"] == 2
    assert _bakery(client)["state"] == "warn"


def test_acknowledge_repeats_covers_the_next_bucket_of_the_same_alert(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)
    first = store_ips_hit(B, scope(3), now - timedelta(hours=2))
    r = client.post(f"/api/v1/alerts/{B}/{first}/ack", json={"repeat_24h": True})
    assert r.status_code == 200 and r.json()["repeat_until"]
    # The next bucket — hits AFTER the ack (vendor time).
    later = store_ips_hit(B, scope(3), datetime.now(timezone.utc) + timedelta(seconds=2))
    assert later != first
    key = _bakery(client)["key"]
    body = _alerts(client, key)
    assert {first, later}.isdisjoint(i["event_id"] for i in body["items"])
    (item,) = [i for i in _alerts(client, key, handled=True)["items"] if i["event_id"] == later]
    assert item["status"] == "acknowledged" and item["ack"]["by_repeat"] is True
    assert _bakery(client)["state"] == "ok"
    # Another remote is the same alert (one LAN client + signature) — a
    # different SIGNATURE is not.
    other = store_ips_hit(B, scope(3), datetime.now(timezone.utc) + timedelta(seconds=3),
                          signature="ET POLICY Example Other")
    assert other in [i["event_id"] for i in _alerts(client, key)["items"]]


def test_the_ack_is_audited_before_the_write(fl, monkeypatch):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))

    def boom(*_a, **_k):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(vstore, "record", boom)
    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={})
    assert r.status_code == 503
    (ack,) = _audit("alert.ack")
    (failed,) = _audit("alert.ack_failed")
    assert ack["id"] < failed["id"] and _verdicts() == []
    assert _bakery(client)["state"] == "warn"


def test_red_and_black_are_untouched_by_an_ack_or_an_expected_condition(fl, mailer_off):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    r = client.post(f"/api/v1/signals/{B}/{eid}/confirm", json={"reason": CONFIRM_REASON})
    assert r.status_code == 200, r.text
    inc_id = r.json()["id"]
    confirmed = [v for v in _verdicts() if v["verdict"] == "confirmed"]
    assert [(v["event_id"], v["incident_id"]) for v in confirmed] == [(eid, inc_id)]
    assert _audit("alert.confirmed")
    build.invalidate()
    assert _bakery(client)["state"] == "bad"
    held = incident_store.get(B, inc_id)
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={}).status_code == 200
    r = client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                    json={"reason": "backup traffic to the vault"})
    assert r.status_code == 409 and "incident" in r.json()["message"]
    site = _bakery(client)
    assert site["state"] == "bad" and site["incident"]["id"] == inc_id
    after = incident_store.get(B, inc_id)
    assert (after.tier, after.status, after.acked) == (held.tier, held.status, held.acked)
    # A Black declared on the site: an ack of another alert changes nothing.
    other = store_ips_hit(B, scope(3), datetime.now(timezone.utc) - timedelta(minutes=1),
                          signature="ET POLICY Example Other")
    r = client.post("/api/v1/incidents/declare", json={
        "tenant": B, "summary": "someone is controlling my screen", "reason": "client call",
        "site_key": site["key"]})
    assert r.status_code == 200, r.text
    assert client.post(f"/api/v1/alerts/{B}/{other}/ack", json={}).status_code == 200
    build.invalidate()
    assert _bakery(client)["state"] == "black"


@pytest.fixture
def mailer_off(monkeypatch):
    from apps.octo.threat import notify

    monkeypatch.setattr(notify, "MAILER_FACTORY", lambda: None)


# ---------------------------------------------------------------------------
# B — expected
# ---------------------------------------------------------------------------

def test_expected_labels_matching_alerts_until_revoked(fl, mailer_off):
    client, _uf, _nd = fl
    _op(client, "adam", "admin")                        # an admin to be told
    client.cookies.clear()
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)
    eid = store_ips_hit(B, scope(3), now - timedelta(hours=3), remote="198.51.100.20")
    url = f"/api/v1/alerts/{B}/{eid}/expected"
    assert client.post(url, json={"reason": "too short"}).status_code == 422
    assert client.post(url, json={"reason": "Siris backup to the Datto cloud",
                                  "review_days": 91}).status_code == 422
    r = client.post(url, json={"reason": "Siris backup to the Datto cloud",
                               "remote": SRV_IP})
    assert r.status_code == 422 and "local" in r.json()["message"]
    r = client.post(url, json={"reason": "Siris backup to the Datto cloud", "review_days": 30,
                               "remote": "198.51.100.20"})
    assert r.status_code == 200, r.text
    rid = r.json()["rule_id"]
    (row,) = _audit("expected.create")
    assert row["reason"] == "Siris backup to the Datto cloud"
    assert [(v["verdict"], v["rule_id"]) for v in _verdicts()] == [("expected", rid)]
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        told = reg.execute("SELECT o.username FROM operator_notices n JOIN operators o ON "
                           "o.id = n.recipient_id WHERE n.request_id = ?",
                           (f"expected:{rid}",)).fetchall()
    finally:
        reg.close()
    assert [t[0] for t in told] == ["adam"]                          # the OTHER admins
    rules = client.get("/api/v1/alerts/expected").json()["rows"]
    assert [(x["id"], x["status"], x["remote"]) for x in rules] == \
        [(rid, "active", "198.51.100.20")]
    review = datetime.fromisoformat(rules[0]["review_at"].replace("Z", "+00:00"))
    assert timedelta(days=29) < review - now <= timedelta(days=30, minutes=1)

    # A later alert of the same device + signature from the same remote: expected.
    later = store_ips_hit(B, scope(3), now - timedelta(minutes=2), remote="198.51.100.20")
    key = _bakery(client)["key"]
    assert later not in [i["event_id"] for i in _alerts(client, key)["items"]]
    (item,) = [i for i in _alerts(client, key, handled=True)["items"] if i["event_id"] == later]
    assert item["status"] == "expected" and item["rule"]["id"] == rid
    assert _bakery(client)["state"] == "ok"
    # Another remote in the same bucket: not all its remotes are the rule's.
    store_ips_hit(B, scope(3), now - timedelta(minutes=1), remote="203.0.113.99")
    assert later in [i["event_id"] for i in _alerts(client, key)["items"]]
    assert _bakery(client)["state"] == "warn"

    r = client.post(f"/api/v1/alerts/expected/{rid}/revoke", json={"reason": "backup moved"})
    assert r.status_code == 200 and r.json()["rows"][0]["status"] == "revoked"
    assert _audit("expected.revoke")
    assert client.post(f"/api/v1/alerts/expected/{rid}/revoke",
                       json={"reason": "again"}).status_code == 409
    assert eid in [i["event_id"] for i in _alerts(client, key)["items"]]


def test_an_expired_condition_stops_matching(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)
    eid = store_ips_hit(B, scope(3), _hour_start(now))
    item = next(i for i in _alerts(client, _bakery(client)["key"])["items"]
                if i["event_id"] == eid)
    from apps.octo.verdicts import annotate, occurrences

    a = annotate.one(B, occurrences.event_rows(B, [eid])[eid])
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            vstore.add_expected(reg, slug=B, key=a.key, remote=None, label=item["title"],
                                reason="the cold-storage server sleeps", origin_event_id=eid,
                                by=1, now=now - timedelta(days=89),
                                review_at=now - timedelta(minutes=1))
    finally:
        reg.close()
    key = _bakery(client)["key"]
    assert eid in [i["event_id"] for i in _alerts(client, key)["items"]]
    assert _bakery(client)["state"] == "warn"
    assert client.get("/api/v1/alerts/expected").json()["rows"] == []
    (row,) = client.get("/api/v1/alerts/expected?state=all").json()["rows"]
    assert row["status"] == "expired"


def test_expected_is_refused_for_csam_decoys_malware_and_by_the_schema(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    csam = _insert_event(B, source="nextdns", event_type="nextdns.security_block", payload={
        "kind": "security_block", "profile_id": "p-bake",
        "log": {"domain": "x.example.test", "reasons": [{"id": "csam"}]},
        "signal": {"reason_id": "csam", "level": "high"}})
    canary = _insert_event(B, source="buoy", event_type="opencanary.ssh",
                           payload={"src_host": "192.0.2.9", "logtype": 4002})
    malware = _insert_event(B, source="wazuh", event_type="wazuh.alert", payload={
        "rule": {"id": "554", "level": 13, "groups": ["yara"]}, "agent": {"name": "WS-1"}})
    for eid, word in ((csam, "CSAM"), (canary, "R6"), (malware, "R2-W")):
        r = client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                        json={"reason": "known and accepted by the client"})
        assert r.status_code == 409 and word in r.json()["message"], (eid, r.text)
    assert _verdicts() == [] and not _audit("expected.create")
    item = next(i for i in _alerts(client, _bakery(client)["key"])["items"]
                if i["event_id"] == csam)
    assert item["can_expect"] is False and "CSAM" in item["expected_refusal"]
    reg = connect(paths.registry_db_path())
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(reg):
                reg.execute(
                    "INSERT INTO expected_condition (tenant_slug, source, device_key, "
                    "signature_key, label, reason, origin_event_id, created_by, created_at, "
                    "review_at) VALUES (?, 'nextdns', 'p|d', 'nextdns:csam|x.example.test', "
                    "'x', 'never ever expected', 1, 1, '2026-10-06T00:00:00.000Z', "
                    "'2026-11-01T00:00:00.000Z')", (B,))
        with pytest.raises(ValueError):
            vstore.add_expected(reg, slug=B, key=AlertKey("nextdns", "p|d", "nextdns:csam|x",
                                                          "nextdns"),
                                remote=None, label="x", reason="never ever expected",
                                origin_event_id=1, by=1, now=datetime.now(timezone.utc),
                                review_at=datetime.now(timezone.utc) + timedelta(days=1))
    finally:
        reg.close()


def test_expected_conditions_remind_the_admins_seven_days_before_review(fl, mailer_off):
    from apps.octo.threat import engine
    from apps.octo.verdicts import reminders

    client, _uf, _nd = fl
    _op(client, "adam", "admin")
    client.cookies.clear()
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)
    soon = store_ips_hit(B, scope(3), now - timedelta(hours=2))
    later = store_ips_hit(B, scope(3), now - timedelta(minutes=2),
                          signature="ET POLICY Example Other")
    r1 = client.post(f"/api/v1/alerts/{B}/{soon}/expected",
                     json={"reason": "nightly backup verification", "review_days": 6})
    r2 = client.post(f"/api/v1/alerts/{B}/{later}/expected",
                     json={"reason": "vendor update channel", "review_days": 8})
    assert r1.status_code == r2.status_code == 200
    engine.TierWorker().run_once()                         # the fleet-wide pass sends it
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        sent = reg.execute("SELECT kind, request_id FROM operator_notices WHERE request_id "
                           "LIKE 'expected:%:review'").fetchall()
        stamped = reg.execute("SELECT id, reminded_at FROM expected_condition ORDER BY id"
                              ).fetchall()
    finally:
        reg.close()
    rid = r1.json()["rule_id"]
    assert {tuple(s) for s in sent} == {("threat_registry", f"expected:{rid}:review")}
    assert stamped[0]["reminded_at"] and stamped[1]["reminded_at"] is None
    assert reminders.send_due(now) == []                              # once only
    assert _audit("expected.review_reminder")


# ---------------------------------------------------------------------------
# Viewers
# ---------------------------------------------------------------------------

def test_a_viewer_sees_nothing_new_and_may_do_none_of_it(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={}).status_code == 200
    client.cookies.clear()
    _op(client, "vic", "viewer", [B])
    site = _bakery(client)
    assert site["state"] == "ok"                     # the colour is the site's, for everyone
    text = json.dumps(site).lower()
    for word in ("hidden", "acknowledged", "expected", "enrichment", "203.0.113", "signature",
                 "udf"):
        assert word not in text, word
    assert set(site["layers"]["security"]["data"]) <= {
        "ips_detected_24h", "ips_blocked_24h", "dns_threats_24h", "open_incidents",
        "dns_protection"}
    key = site["key"]
    assert client.get(f"/api/v1/fleet/sites/{key}/alerts").status_code == 403
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={}).status_code == 403
    assert client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                       json={"reason": "a viewer may not do this"}).status_code == 403
    assert client.get("/api/v1/alerts/expected").status_code == 403
    assert client.post("/api/v1/alerts/expected/1/revoke",
                       json={"reason": "nope"}).status_code == 403


def test_an_out_of_scope_analyst_gets_the_same_404(fl):
    client, _uf, _nd = fl
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    _op(client, "ana-a", "analyst", [A])
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={}).status_code == 404
    assert client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                       json={"reason": "outside my scope here"}).status_code == 404
    assert client.post(f"/api/v1/alerts/{A}/999999/ack", json={}).status_code == 404


# ---------------------------------------------------------------------------
# C — enrichment (cache-only on a page load; the worker through a fake)
# ---------------------------------------------------------------------------

class FakeIntel:
    calls: list[str] = []

    def lookup(self, ip: str):
        from apps.octo.enrich.netintel import IpIntel

        FakeIntel.calls.append(ip)
        return IpIntel(ip, "scanner-07.ch1.censys-scanner.com", True, "Censys, Inc.",
                       "CENSYS-NET", "203.0.113.0/24", "US", "arin")

    def close(self) -> None:
        pass


def test_ips_enrichment_is_cache_only_and_the_worker_fills_it(fl, monkeypatch):
    from apps.octo.enrich import worker

    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    t0 = _hour_start(datetime.now(timezone.utc))
    eid = store_ips_hit(B, scope(3), t0, remote="203.0.113.66", lan_ip=POS_IP)
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=5), remote="203.0.113.66", lan_ip=POS_IP)
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=9), remote="203.0.113.77", lan_ip=POS_IP)
    monkeypatch.setenv(worker.ENV, "on")
    FakeIntel.calls = []
    w = worker.EnrichmentWorker(intel_factory=FakeIntel)
    worker.set_current(w)
    key = _bakery(client)["key"]
    item = next(i for i in _alerts(client, key)["items"] if i["event_id"] == eid)
    e = item["enrichment"]
    assert (e["kind"], e["direction"], e["action"], e["remote_ip"], e["local_ip"]) == \
        ("unifi_ips", "outbound", "blocked", "203.0.113.66", POS_IP)
    assert e["remote"]["pending"] is True and FakeIntel.calls == []   # never on a page load
    assert e["repeats_24h"] == 2 and e["repeats_approximate"] is False and e["hits"] == 3
    assert w.pending() == ["203.0.113.66"]
    assert w.run_once() == 1 and FakeIntel.calls == ["203.0.113.66"]
    e = next(i for i in _alerts(client, key)["items"] if i["event_id"] == eid)["enrichment"]
    assert e["remote"]["org"] == "Censys, Inc." and e["remote"]["ptr_confirmed"] is True
    assert {"kind": "scanner", "name": "Censys", "basis": "ptr"} in e["remote"]["labels"]
    assert w.pending() == []                                          # cached: not queued again
    monkeypatch.setenv(worker.ENV, "off")
    assert w.enqueue(["198.51.100.200"]) == 0                          # off: nothing queued


def test_datto_alerts_get_a_one_line_summary_and_their_repeats(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)

    def datto(uid: str, minutes: int, text: str, resolved: bool = False) -> int:
        return _insert_event(B, source="datto", event_type="datto.eventlog", host="SRV-01",
                             severity="high", at=now - timedelta(minutes=minutes), payload={
                                 "alertUid": uid, "priority": "High", "resolved": resolved,
                                 "alertSourceInfo": {"deviceUid": "dev-srv-01",
                                                     "deviceName": "SRV-01"},
                                 "alertContext": {"@class": "eventlog_ctx", "logName": "System",
                                                  "source": "Service Control Manager",
                                                  "code": "7031", "description": text}})

    datto("0000aaaa-0000-0000-0000-000000000001", 600, "The Spooler service terminated.")
    newest = datto("0000aaaa-0000-0000-0000-000000000002", 3,
                   "The Spooler service terminated unexpectedly. It has done this 2 times.")
    item = next(i for i in _alerts(client, _bakery(client)["key"])["items"]
                if i["event_id"] == newest)
    e = item["enrichment"]
    assert e["line"] == "Event 7031 · Service Control Manager · System log"
    assert (e["host"], e["resolved"], e["repeats"]) == ("SRV-01", False, 1)
    assert e["since"] and e["details"]
    assert item["tenant_wide"] is False and item["can_expect"] is True


# ---------------------------------------------------------------------------
# D — the Datto device list for every Datto-mapped tenant; never a UDF
# ---------------------------------------------------------------------------

def test_an_off_tenants_datto_list_names_the_device_and_no_udf_ever_leaves(fl, caplog):
    from apps.octo.adapters.datto.inventory import InventoryPoller
    from apps.octo.adapters.datto.tests.fake_datto import (
        CREDS,
        FakeDattoTransport,
        inventory_device,
        real_client,
    )
    from apps.octo.entity import switch
    from apps.octo.entity.feeders.datto import DattoInventoryFeeder
    from apps.octo.instances import create_instance, tenant_map
    from apps.octo.instances.tenant_map import TenantMapping

    client, _uf, _nd = fl
    assert switch.mode(B) == "off"
    rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                          credentials_dict=dict(CREDS), instance_config={})
    tenant_map.set_mappings(rec.id, [TenantMapping("site-bake", B, "Bakery", "manual")])
    transport = FakeDattoTransport()
    transport.site_devices["site-bake"] = [
        inventory_device("dev-b1", "BAKERY-POS", site_uid="site-bake", int_ip=POS_IP),
        inventory_device("dev-b2", "BAKERY-SRV", site_uid="site-bake", int_ip=SRV_IP,
                         category="Server", online=False)]
    caplog.set_level(logging.DEBUG)
    out = InventoryPoller(client=real_client(transport), instance_id=rec.id, spacing_sec=0,
                          consumer=DattoInventoryFeeder()).run_once()
    assert out["sites"] == 1 and out["devices"] == 2
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)), lan_ip=POS_IP)
    site = _bakery(client)
    end = site["layers"]["endpoints"]
    assert end["present"] and end["data"]["agents_total"] == 2         # off, still counted
    assert end["data"]["servers_offline"] == 1 and end["note"] is None
    body = _alerts(client, site["key"])
    e = next(i for i in body["items"] if i["event_id"] == eid)["enrichment"]
    assert (e["local_name"], e["local_name_source"]) == ("BAKERY-POS", "datto")
    texts = [json.dumps(body), json.dumps(_sites(client)), caplog.text]
    client.cookies.clear()
    _op(client, "vic", "viewer", [B])
    texts.append(json.dumps(_sites(client)))
    for text in texts:
        for word in ("udf", "bitlocker", "lastloggedinuser", "web-remote"):
            assert word not in text.lower(), word


def test_the_serial_number_reaches_the_operators_drawer_and_no_client_surface(fl, caplog):
    """v0.17.3 (Rick's decision A): the device audit's serial / manufacturer
    / model name WHICH machine a Datto alert is — in the analyst drawer only.
    The Fleet's sites list (operator or client user), its layers and the log
    never carry a serial, and nothing else of the audit is stored or shown."""
    from apps.octo.adapters.datto.inventory import InventoryPoller
    from apps.octo.adapters.datto.tests.fake_datto import (
        AUDIT_SECRETS,
        CREDS,
        FakeDattoTransport,
        device_audit,
        inventory_device,
        real_client,
    )
    from apps.octo.entity.feeders.datto import DattoInventoryFeeder
    from apps.octo.instances import create_instance, tenant_map
    from apps.octo.instances.tenant_map import TenantMapping

    client, _uf, _nd = fl
    rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                          credentials_dict=dict(CREDS), instance_config={})
    tenant_map.set_mappings(rec.id, [TenantMapping("site-bake", B, "Bakery", "manual"),
                                     TenantMapping("site-bake-2", B, "Bakery 2", "manual")])
    transport = FakeDattoTransport()
    transport.site_devices["site-bake"] = [
        inventory_device("dev-b1", "BAKERY-POS", site_uid="site-bake", int_ip=POS_IP)]
    transport.site_devices["site-bake-2"] = [
        inventory_device("dev-b2", "BAKERY-POS", site_uid="site-bake-2", int_ip=POS2_IP)]
    transport.audits["dev-b1"] = device_audit(serial="EXAMPLE-SN-POS1",
                                              manufacturer="Example Computers Inc.",
                                              model="Example Model 7090")
    transport.audits["dev-b2"] = device_audit(serial="EXAMPLE-SN-POS2")
    caplog.set_level(logging.DEBUG)
    out = InventoryPoller(client=real_client(transport), instance_id=rec.id, spacing_sec=0,
                          consumer=DattoInventoryFeeder()).run_once()
    assert out["audits"] == {"read": 2, "serials": 2, "failed": 0}
    eid = _insert_event(B, source="datto", event_type="datto.eventlog", host="BAKERY-POS",
                        payload={"alertUid": "0000bbbb-0000-0000-0000-000000000001",
                                 "priority": "High",
                                 "alertSourceInfo": {"deviceUid": "dev-b1",
                                                     "deviceName": "BAKERY-POS",
                                                     "siteName": "Bakery"},
                                 "alertContext": {"@class": "eventlog_ctx",
                                                  "logName": "System", "source": "disk",
                                                  "code": "7", "description": "Bad block."}})
    _op(client, "ana", "analyst")
    body = _alerts(client, _bakery(client)["key"])
    e = next(i for i in body["items"] if i["event_id"] == eid)["enrichment"]
    assert (e["serial"], e["manufacturer"], e["model"]) == \
        ("EXAMPLE-SN-POS1", "Example Computers Inc.", "Example Model 7090")
    assert e["shared_hostname"] == 2 and e["shared_serials"] == ["EXAMPLE-SN-POS2"]
    surfaces = {"operator sites": json.dumps(_sites(client)), "log": caplog.text}
    client.cookies.clear()
    _op(client, "vic", "viewer", [B])
    surfaces["client sites"] = json.dumps(_sites(client))
    for name, text in surfaces.items():
        # Not a value — and not even the field on a sites list (the log
        # line says "serials found N": counts only).
        words = ("EXAMPLE-SN-POS", "Example Model 7090", "Example Computers", "dev-b1",
                 "dev-b2") + (("serial",) if name != "log" else ())
        for word in words:
            assert word.lower() not in text.lower(), (name, word)
    for text in [json.dumps(body), *surfaces.values()]:
        for secret in AUDIT_SECRETS:
            assert secret.lower() not in text.lower(), secret
