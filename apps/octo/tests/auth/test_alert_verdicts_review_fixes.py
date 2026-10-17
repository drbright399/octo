"""v0.17.2 review fixes through the REAL HTTP routes and real sign-in:

  * an ack covers no more than the analyst SAW (`seen_hits` / `seen_last`):
    hits that arrived while the form was open re-surface the alert;
  * a RocketCyber incident is acknowledged one at a time — never expected,
    never "repeats for 24 h", by SOURCE (v0.17.3: even when its payload names
    a host); acknowledging its latest version also covers the earlier
    versions in the list; a later version re-surfaces it;
  * a Datto alert's resolution row is not a new alert once its raise was
    acknowledged, and the raise reads resolved;
  * a Datto ransomware detection is never expected; a CSAM lookup is never
    "repeats for 24 h";
  * the revoke route answers the SAME 404 for a rule outside the caller's
    scope and one that does not exist;
  * a client user's counts stay the facts (every hit) while the Yellow goes.
"""
# ruff: noqa: F811 — the `fl` fixture is imported from test_fleet_api.
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from apps.octo.fleet import build
from apps.octo.fleet.tests.fixtures import scope
from apps.octo.tests.auth.test_alert_verdicts_api import (
    A,
    B,
    _alerts,
    _bakery,
    _hour_start,
    _insert_event,
    _verdicts,
)
from apps.octo.tests.auth.test_fleet_api import _audit, _op, fl  # noqa: F401
from apps.octo.verdicts.keys import ROCKETCYBER_REFUSAL, ROCKETCYBER_REPEAT
from apps.octo.verdicts.tests.helpers import store_ips_hit


def _item(client, eid: int, *, handled: bool = False) -> dict:
    body = _alerts(client, _bakery(client)["key"], handled=handled)
    return next(i for i in body["items"] if i["event_id"] == eid)


def test_an_ack_covers_only_the_hits_the_analyst_saw(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    t0 = _hour_start(datetime.now(timezone.utc))
    eid = store_ips_hit(B, scope(3), t0)
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=1))
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=2))
    shown = _item(client, eid)
    assert shown["hits"] == 3
    # While the analyst types the note, a scan adds two more to the bucket.
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=3))
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=4))
    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={
        "note": "one scan, checked", "seen_hits": shown["hits"], "seen_last": shown["last_seen"]})
    assert r.status_code == 200, r.text
    (v,) = _verdicts()
    assert v["hits_at"] == 3 and v["last_seen_at"] == shown["last_seen"]
    (row,) = _audit("alert.ack")
    after = json.loads(row["after_state"])
    assert (after["hits_at"], after["hits_now"]) == (3, 5)              # both, audited
    item = _item(client, eid)
    assert item["status"] == "resurfaced" and item["new_since_ack"] == 2 and item["hits"] == 5
    assert _bakery(client)["state"] == "warn"


def test_seen_values_never_widen_an_ack(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    t0 = _hour_start(datetime.now(timezone.utc))
    eid = store_ips_hit(B, scope(3), t0)
    future = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={"seen_hits": 999, "seen_last": future})
    assert r.status_code == 200, r.text
    (v,) = _verdicts()
    assert v["hits_at"] == 1 and v["last_seen_at"] != future
    store_ips_hit(B, scope(3), t0 + timedelta(seconds=1))
    assert _item(client, eid)["status"] == "resurfaced"
    bad = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={"seen_last": "yesterday"})
    assert bad.status_code == 422


def _rc(iid: int, minutes: int, title: str = "Suspicious PowerShell Detected") -> int:
    return _insert_event(B, source="rocketcyber", event_type="rocketcyber.incident",
                         at=datetime.now(timezone.utc) - timedelta(minutes=minutes),
                         payload={"id": iid, "status": "open", "title": title})


def test_a_rocketcyber_incident_is_acknowledged_one_at_a_time_and_covers_its_versions(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    v1, v2 = _rc(101, 40), _rc(101, 20)
    other = _rc(202, 10)                      # another incident, same title
    build.invalidate()
    item = _item(client, v2)
    # By SOURCE (Rick, 2026-10-07) — the RocketCyber wording, not "no device".
    assert item["can_expect"] is False and item["expected_refusal"] == ROCKETCYBER_REFUSAL
    assert item["can_repeat"] is False
    r = client.post(f"/api/v1/alerts/{B}/{v2}/expected",
                    json={"reason": "a known admin script at this client"})
    assert r.status_code == 409 and r.json()["message"] == ROCKETCYBER_REFUSAL
    r = client.post(f"/api/v1/alerts/{B}/{v2}/ack", json={"repeat_24h": True})
    assert r.status_code == 422 and r.json()["message"] == ROCKETCYBER_REPEAT
    assert _verdicts() == []
    # Acknowledging the LATEST version covers the earlier one in the list.
    assert client.post(f"/api/v1/alerts/{B}/{v2}/ack", json={}).status_code == 200
    (v,) = _verdicts()
    assert v["alert_ref"] == "rocketcyber:101" and v["repeat_until"] is None
    body = _alerts(client, _bakery(client)["key"])
    ids = [i["event_id"] for i in body["items"]]
    assert v1 not in ids and v2 not in ids and other in ids
    # The incident changes: a newer version re-surfaces it.
    v3 = _rc(101, 1)
    assert _item(client, v3)["status"] == "resurfaced"


def test_a_rocketcyber_alert_that_names_a_host_is_still_acknowledge_only(fl):
    """v0.17.3 (Rick, 2026-10-07: "too vague to just do a sweeping expected
    tag on"): the refusal is the SOURCE's — an incident whose payload names
    the host (and its agent, its account) is still acknowledged one at a
    time: no "this is expected", no "repeats for 24 h", through the API too;
    the plain acknowledge works."""
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = _insert_event(B, source="rocketcyber", event_type="rocketcyber.incident",
                        host="BAKERY-POS", payload={
                            "id": 303, "status": "open", "title": "Suspicious PowerShell",
                            "hostname": "BAKERY-POS", "deviceName": "BAKERY-POS",
                            "agent": {"hostname": "BAKERY-POS", "id": "agent-0001"},
                            "device": {"hostname": "BAKERY-POS", "ip": "192.0.2.37"}})
    build.invalidate()
    item = _item(client, eid)
    assert (item["can_expect"], item["can_repeat"]) == (False, False)
    assert item["expected_refusal"] == ROCKETCYBER_REFUSAL
    r = client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                    json={"reason": "the bakery's own admin script, checked"})
    assert (r.status_code, r.json()["message"]) == (409, ROCKETCYBER_REFUSAL)
    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={"repeat_24h": True})
    assert (r.status_code, r.json()["message"]) == (422, ROCKETCYBER_REPEAT)
    assert _verdicts() == [] and _audit("expected.create") == []
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={"note": "seen"}).status_code \
        == 200
    (v,) = _verdicts()
    assert (v["verdict"], v["repeat_until"]) == ("ack", None)
    assert _item(client, eid, handled=True)["status"] == "acknowledged"


def test_a_datto_resolution_is_not_a_new_alert_after_its_raise_was_acknowledged(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    uid = "0000cccc-0000-0000-0000-000000000001"

    def datto(minutes: int, resolved: bool) -> int:
        return _insert_event(B, source="datto", event_type="datto.srvc", host="EXAMPLE-SRV",
                             at=datetime.now(timezone.utc) - timedelta(minutes=minutes),
                             payload={"alertUid": uid, "priority": "High", "resolved": resolved,
                                      "alertSourceInfo": {"deviceUid": "dev-srv",
                                                          "deviceName": "EXAMPLE-SRV"},
                                      "alertContext": {"@class": "srvc_status_ctx",
                                                       "serviceName": "Spooler",
                                                       "status": "Stopped"}})

    raised = datto(30, False)
    build.invalidate()
    assert client.post(f"/api/v1/alerts/{B}/{raised}/ack", json={}).status_code == 200
    resolution = datto(2, True)
    ids = [i["event_id"] for i in _alerts(client, _bakery(client)["key"])["items"]]
    assert raised not in ids and resolution not in ids
    both = {i["event_id"]: i for i in _alerts(client, _bakery(client)["key"], handled=True)["items"]}
    assert both[resolution]["status"] == "acknowledged"
    assert both[raised]["enrichment"]["resolved"] is True             # its resolution is stored


def test_a_ransomware_detection_is_never_expected_and_csam_never_repeat_acked(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    rw = _insert_event(B, source="datto", event_type="datto.ransomware", host="EXAMPLE-PC",
                       payload={"alertUid": "0000dddd-0000-0000-0000-000000000001",
                                "alertSourceInfo": {"deviceUid": "dev-pc"},
                                "alertContext": {"@class": "ransomware_ctx", "state": "Detected",
                                                 "rwextension": ".locked"}})
    r = client.post(f"/api/v1/alerts/{B}/{rw}/expected",
                    json={"reason": "the line-of-business updater renames files"})
    assert r.status_code == 409 and "ransomware" in r.json()["message"]
    csam = _insert_event(B, source="nextdns", event_type="nextdns.security_block", payload={
        "kind": "security_block", "profile_id": "p-bake",
        "log": {"domain": "x.example.test", "device": {"id": "D9"},
                "reasons": [{"id": "threat-intelligence-feeds"}, {"id": "csam"}]},
        "signal": {"reason_id": "threat-intelligence-feeds", "level": "high"}})
    build.invalidate()
    assert _item(client, csam)["can_repeat"] is False
    r = client.post(f"/api/v1/alerts/{B}/{csam}/ack", json={"repeat_24h": True})
    assert r.status_code == 422 and "CSAM" in r.json()["message"]
    assert client.post(f"/api/v1/alerts/{B}/{csam}/ack", json={}).status_code == 200


def test_the_revoke_route_is_never_an_oracle_for_other_clients_rules(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    r = client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                    json={"reason": "Siris backup to the Datto cloud"})
    assert r.status_code == 200, r.text
    rid = r.json()["rule_id"]
    client.cookies.clear()
    _op(client, "ana-a", "analyst", [A])
    theirs = client.post(f"/api/v1/alerts/expected/{rid}/revoke", json={"reason": "probe"})
    missing = client.post(f"/api/v1/alerts/expected/{rid + 999}/revoke",
                          json={"reason": "probe"})
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json()["message"] == missing.json()["message"]
    assert not _audit("expected.revoke")


def test_a_client_user_keeps_the_facts_while_the_yellow_goes(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    assert client.post(f"/api/v1/alerts/{B}/{eid}/ack", json={}).status_code == 200
    client.cookies.clear()
    _op(client, "vic", "viewer", [B])
    site = _bakery(client)
    assert site["state"] == "ok"
    data = site["layers"]["security"]["data"]
    assert data["ips_blocked_24h"] == 1 and "ips_hidden_24h" not in data
