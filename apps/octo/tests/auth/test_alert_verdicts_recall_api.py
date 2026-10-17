"""v0.17.5 — RECALL an acknowledgement and NOTES on it, through the REAL HTTP
routes and real sign-in (Rick, 2026-10-08: he acknowledged a client's alerts,
then learned the context — a partner had removed the DNS agents on purpose —
and could not go back to add it):

  * a recall (analyst+, a reason ≥ 10, audited BEFORE the write) puts the
    alert back in "needs attention" and back into the site's colour — a
    coalesced row, a single event and the alerts a "repeats for 24 h" ack
    covered; the ack row is never touched; acknowledging again is a new ack
    — of this row or of another row of the vendor alert (a Datto raise /
    resolution, a later RocketCyber version): it decides;
  * a note (≤ 500) is shown under the ack (newest last), recalled or not —
    nothing else changes;
  * the drawer's ack payload carries verdict_id, recalled and notes;
  * the same 404 for an unknown verdict, another tenant's and a tenant
    outside the caller's scope; 409 for a second recall and for a recall /
    note on a label that is not an ack;
  * plain validation messages, an empty body ({}) or none at all included —
    nothing audited for a refused request;
  * a viewer may do none of it.
"""
# ruff: noqa: F811 — the `fl` fixture is imported from test_fleet_api.
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from apps.octo import paths
from apps.octo.adapters.rocketcyber.presentation import HEADLINE_PREFIX
from apps.octo.db import connect
from apps.octo.fleet import build, sources
from apps.octo.fleet.tests.fixtures import scope
from apps.octo.tests.auth.test_alert_verdicts_api import (
    A,
    B,
    _alerts,
    _bakery,
    _hour_start,
    _insert_event,
    _verdicts,
    mailer_off,  # noqa: F401 — a fixture
)
from apps.octo.tests.auth.test_fleet_api import _audit, _op, fl  # noqa: F401
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import TenantVerdicts
from apps.octo.verdicts.tests.helpers import store_ips_hit

REASON = "a partner removed the DNS agents on purpose"


def _item(client, eid: int, *, handled: bool = False) -> dict:
    body = _alerts(client, _bakery(client)["key"], handled=handled)
    return next(i for i in body["items"] if i["event_id"] == eid)


def _ids(client) -> list[int]:
    return [i["event_id"] for i in _alerts(client, _bakery(client)["key"])["items"]]


def _followups() -> list[sqlite3.Row]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return reg.execute("SELECT * FROM alert_verdict_followup ORDER BY id").fetchall()
    finally:
        reg.close()


def _ack(client, eid: int, **body) -> int:
    r = client.post(f"/api/v1/alerts/{B}/{eid}/ack", json=body)
    assert r.status_code == 200, r.text
    return int(r.json()["verdict_id"])


def _recall(client, vid: int, reason: str = REASON, slug: str = B):
    return client.post(f"/api/v1/alerts/{slug}/verdicts/{vid}/recall", json={"reason": reason})


def _note(client, vid: int, note: str, slug: str = B):
    return client.post(f"/api/v1/alerts/{slug}/verdicts/{vid}/notes", json={"note": note})


def _rc(iid: int, minutes: int) -> int:
    return _insert_event(B, source="rocketcyber", event_type="rocketcyber.incident",
                         at=datetime.now(timezone.utc) - timedelta(minutes=minutes),
                         payload={"id": iid, "status": "open",
                                  "title": "Suspicious PowerShell Detected"})


# ---------------------------------------------------------------------------
# Recall
# ---------------------------------------------------------------------------

def test_a_recall_puts_a_coalesced_alert_back_in_needs_attention_and_the_colour(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid, note="checked with the client")
    assert eid not in _ids(client) and _bakery(client)["state"] == "ok"
    (ack_row,) = _verdicts()
    before = dict(ack_row)

    r = _recall(client, vid, f"  {REASON}  ")
    assert r.status_code == 200, r.text
    out = r.json()
    assert (out["verdict_id"], out["event_id"], out["kind"], out["tenant_slug"]) == \
        (vid, eid, "recall", B)
    (row,) = _audit("alert.ack_recall")
    assert row["reason"] == REASON and row["client_slug"] == B
    assert json.loads(row["before_state"])["event_id"] == eid
    (f,) = _followups()
    assert (f["kind"], f["verdict_id"], f["text"], f["tenant_slug"]) == ("recall", vid, REASON, B)

    # Back in "needs attention", back in the colour; the ack row untouched.
    item = _item(client, eid)
    assert item["status"] == "open"
    assert item["ack"]["verdict_id"] == vid and item["ack"]["note"] == "checked with the client"
    assert item["ack"]["recalled"]["reason"] == REASON
    assert item["ack"]["recalled"]["by_name"] and item["ack"]["recalled"]["at"]
    assert item["ack"]["notes"] == []
    site = _bakery(client)
    assert site["state"] == "warn" and site["reason"] == "1 IPS block today"
    assert "ips_hidden_24h" not in site["layers"]["security"]["data"] or \
        not site["layers"]["security"]["data"]["ips_hidden_24h"]
    assert [dict(v) for v in _verdicts()] == [before]

    # Final: a second recall is refused (nothing audited, nothing written).
    again = _recall(client, vid)
    assert again.status_code == 409 and again.json()["message"] == vstore.ALREADY_RECALLED
    assert len(_audit("alert.ack_recall")) == 1 and len(_followups()) == 1

    # Acknowledging again is a NEW ack: it decides, and may be recalled.
    vid2 = _ack(client, eid)
    assert vid2 != vid and eid not in _ids(client) and _bakery(client)["state"] == "ok"
    shown = _item(client, eid, handled=True)
    assert shown["status"] == "acknowledged" and shown["ack"]["verdict_id"] == vid2
    assert shown["ack"]["recalled"] is None
    assert _recall(client, vid2, "it happened again — not the partner").status_code == 200
    assert eid in _ids(client)


def test_a_recall_puts_a_single_event_back(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = _rc(101, 20)
    build.invalidate()
    conn = sqlite3.connect(paths.client_dir(B) / "events.db")       # the poller's summary
    conn.execute("UPDATE events SET summary = ? WHERE id = ?",
                 (f"{HEADLINE_PREFIX}: Suspicious PowerShell Detected", eid))
    conn.commit()
    conn.close()

    def counted() -> tuple[int | None, dict[str, int]]:
        """What the Fleet's security layer counts for a RocketCyber-mapped
        tenant (the same evaluator the list reads)."""
        hidden: dict[str, int] = {}
        now = datetime.now(timezone.utc)
        n = sources.rocketcyber_open(B, now, verdicts=TenantVerdicts.load(B, now),
                                     hidden=hidden)
        return n, hidden

    assert counted() == (1, {})
    vid = _ack(client, eid)
    assert eid not in _ids(client)
    assert _item(client, eid, handled=True)["status"] == "acknowledged"
    assert counted() == (0, {"rocketcyber": 1})
    assert _recall(client, vid).status_code == 200
    item = _item(client, eid)
    assert item["status"] == "open" and item["ack"]["recalled"]["reason"] == REASON
    assert counted() == (1, {})                                    # counted again


def test_recalling_a_repeat_ack_returns_every_alert_it_covered(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    now = datetime.now(timezone.utc)
    first = store_ips_hit(B, scope(3), now - timedelta(hours=2))
    vid = _ack(client, first, repeat_24h=True)
    later = store_ips_hit(B, scope(3), datetime.now(timezone.utc) + timedelta(seconds=2))
    assert {first, later}.isdisjoint(_ids(client))
    covered = _item(client, later, handled=True)
    assert covered["ack"]["by_repeat"] is True and covered["ack"]["verdict_id"] == vid
    # Recalled from the row it covers by repeat: the ack is the repeat-ack.
    assert _recall(client, covered["ack"]["verdict_id"]).status_code == 200
    ids = _ids(client)
    assert first in ids and later in ids
    assert _item(client, first)["ack"]["recalled"]["reason"] == REASON
    assert _item(client, later)["status"] == "open"
    assert _bakery(client)["state"] == "warn"


def _datto(uid: str, minutes: int, resolved: bool) -> int:
    return _insert_event(B, source="datto", event_type="datto.srvc", host="EXAMPLE-SRV",
                         at=datetime.now(timezone.utc) - timedelta(minutes=minutes),
                         payload={"alertUid": uid, "priority": "High", "resolved": resolved,
                                  "alertSourceInfo": {"deviceUid": "dev-srv",
                                                      "deviceName": "EXAMPLE-SRV"},
                                  "alertContext": {"@class": "srvc_status_ctx",
                                                   "serviceName": "Spooler",
                                                   "status": "Stopped"}})


def _after_the_recall() -> None:
    """The next ack's time is strictly after the recall's (ms resolution)."""
    time.sleep(0.005)


def test_acknowledging_another_row_after_a_recall_covers_the_recalled_row(fl):
    """Review fix: the raise's ack is recalled (both rows of the Datto alert
    need attention), then the analyst acknowledges the RESOLUTION — a new
    ack, after the recall: it covers the raise again, in the list and in the
    colour. The other order too: the resolution's ack recalled, the raise
    acknowledged again."""
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    raised = _datto("0000cccc-0000-0000-0000-000000000001", 30, False)
    resolution = _datto("0000cccc-0000-0000-0000-000000000001", 2, True)
    build.invalidate()
    vid = _ack(client, raised)
    assert {raised, resolution}.isdisjoint(_ids(client))
    assert _recall(client, vid).status_code == 200
    assert {raised, resolution} <= set(_ids(client))
    _after_the_recall()
    vid2 = _ack(client, resolution)
    assert {raised, resolution}.isdisjoint(_ids(client))
    item = _item(client, raised, handled=True)
    assert item["status"] == "acknowledged" and item["ack"]["verdict_id"] == vid2
    assert item["ack"]["recalled"] is None

    # The other order: the resolution's ack (it covers the most) recalled,
    # the raise acknowledged again — both rows covered by the new ack.
    assert _recall(client, vid2, "the service was stopped by the partner").status_code == 200
    assert {raised, resolution} <= set(_ids(client))
    _after_the_recall()
    vid3 = _ack(client, raised)
    assert {raised, resolution}.isdisjoint(_ids(client))
    assert _item(client, resolution, handled=True)["ack"]["verdict_id"] == vid3


def test_acknowledging_a_later_rocketcyber_version_after_a_recall_covers_the_earlier(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    v1 = _rc(101, 40)
    build.invalidate()
    vid = _ack(client, v1)
    assert _recall(client, vid).status_code == 200
    v2 = _rc(101, 20)
    assert {v1, v2} <= set(_ids(client))
    _after_the_recall()
    vid2 = _ack(client, v2)
    assert {v1, v2}.isdisjoint(_ids(client))
    assert _item(client, v1, handled=True)["ack"]["verdict_id"] == vid2


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

def test_notes_are_shown_under_the_ack_newest_last_and_change_nothing_else(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid, note="seen")
    r = _note(client, vid, "  the partner   removed the agents ")
    assert r.status_code == 200, r.text
    assert r.json()["kind"] == "note"
    assert _note(client, vid, "ticket T20000101.0001").status_code == 200
    (row, _second) = _audit("alert.ack_note")
    assert row["reason"] == "the partner removed the agents" and row["client_slug"] == B
    item = _item(client, eid, handled=True)
    assert item["status"] == "acknowledged" and item["ack"]["note"] == "seen"
    assert [n["note"] for n in item["ack"]["notes"]] == \
        ["the partner removed the agents", "ticket T20000101.0001"]
    assert all(n["by_name"] and n["at"] for n in item["ack"]["notes"])
    assert eid not in _ids(client) and _bakery(client)["state"] == "ok"
    # A recalled ack still takes notes — shown on the open row.
    assert _recall(client, vid).status_code == 200
    assert _note(client, vid, "confirmed with the partner on the phone").status_code == 200
    item = _item(client, eid)
    assert item["status"] == "open" and len(item["ack"]["notes"]) == 3
    assert item["ack"]["notes"][-1]["note"] == "confirmed with the partner on the phone"


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

def test_plain_validation_messages_and_nothing_audited(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid)
    url = f"/api/v1/alerts/{B}/verdicts/{vid}"
    for body in ({}, {"reason": None}, {"reason": "   "}, {"reason": "too short"}):
        r = client.post(f"{url}/recall", json=body)
        assert r.status_code == 422, body
        assert r.json()["message"] == "a reason of at least 10 characters is required"
    r = client.post(f"{url}/recall")                                    # no body at all
    assert (r.status_code, r.json()["message"]) == \
        (422, "a reason of at least 10 characters is required")
    r = client.post(f"{url}/recall", json={"reason": "x" * 501})
    assert (r.status_code, r.json()["message"]) == (422, "a reason is at most 500 characters")
    for body in ({}, {"note": ""}, {"note": " \n "}):
        r = client.post(f"{url}/notes", json=body)
        assert (r.status_code, r.json()["message"]) == (422, "a note is required"), body
    r = client.post(f"{url}/notes")
    assert (r.status_code, r.json()["message"]) == (422, "a note is required")
    r = client.post(f"{url}/notes", json={"note": "y" * 501})
    assert (r.status_code, r.json()["message"]) == (422, "a note is at most 500 characters")
    assert _audit("alert.ack_recall") == [] and _audit("alert.ack_note") == []
    assert _followups() == []


def test_a_label_that_is_not_an_ack_is_409(fl, mailer_off):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    r = client.post(f"/api/v1/alerts/{B}/{eid}/expected",
                    json={"reason": "Siris backup to the Datto cloud"})
    assert r.status_code == 200, r.text
    vid = r.json()["verdict_id"]
    for resp in (_recall(client, vid), _note(client, vid, "context")):
        assert resp.status_code == 409 and resp.json()["message"] == vstore.NOT_AN_ACK
    assert _audit("alert.ack_recall") == [] and _audit("alert.ack_note") == []
    assert _followups() == []


def test_the_same_404_for_unknown_another_tenants_and_out_of_scope(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid)
    shapes = []
    # Another tenant's slug with the verdict (in scope), an unknown id.
    for resp in (_recall(client, vid, slug=A), _note(client, vid, "x", slug=A),
                 _recall(client, vid + 999), _note(client, vid + 999, "x")):
        assert resp.status_code == 404
        shapes.append((resp.json()["code"], resp.json()["message"]))
    # An analyst scoped to the OTHER tenant: the real verdict reads the same.
    client.cookies.clear()
    _op(client, "ana-a", "analyst", [A])
    for resp in (_recall(client, vid), _note(client, vid, "x"), _recall(client, vid + 999)):
        assert resp.status_code == 404
        shapes.append((resp.json()["code"], resp.json()["message"]))
    assert set(shapes) == {("NOT_FOUND", "no such acknowledgement in your scope")}
    assert _audit("alert.ack_recall") == [] and _audit("alert.ack_note") == []
    assert _followups() == []


def test_the_recall_is_audited_before_the_write(fl, monkeypatch):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid)

    def boom(*_a, **_k):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(vstore, "add_followup", boom)
    r = _recall(client, vid)
    assert r.status_code == 503
    (rec,) = _audit("alert.ack_recall")
    (failed,) = _audit("alert.ack_recall_failed")
    assert rec["id"] < failed["id"] and _followups() == []
    assert eid not in _ids(client) and _bakery(client)["state"] == "ok"   # still acked
    r = _note(client, vid, "context")
    assert r.status_code == 503
    (note,) = _audit("alert.ack_note")
    (nfailed,) = _audit("alert.ack_note_failed")
    assert note["id"] < nfailed["id"]


def test_a_recall_that_lost_the_race_is_409_and_audited_as_failed(fl, monkeypatch):
    """Two analysts recall at once: both pass the read, the second write
    finds the recall inside its transaction — 409, its audit row closed by
    `alert.ack_recall_failed`, ONE recall stored."""
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid)
    assert _recall(client, vid).status_code == 200
    stale = vstore.get_verdict(vid)
    assert stale is not None and stale.recalled
    from dataclasses import replace

    monkeypatch.setattr(vstore, "get_verdict", lambda _vid: replace(stale, recalled_at=None))
    r = _recall(client, vid, "a second analyst, a moment later")
    assert r.status_code == 409 and r.json()["message"] == vstore.ALREADY_RECALLED
    assert len(_audit("alert.ack_recall")) == 2 and len(_audit("alert.ack_recall_failed")) == 1
    assert [f["kind"] for f in _followups()] == ["recall"]


def test_a_viewer_may_do_none_of_it(fl):
    client, _uf, _nd = fl
    _op(client, "ana", "analyst")
    eid = store_ips_hit(B, scope(3), _hour_start(datetime.now(timezone.utc)))
    vid = _ack(client, eid)
    assert _note(client, vid, "context for the team").status_code == 200
    client.cookies.clear()
    _op(client, "vic", "viewer", [B])
    assert _recall(client, vid).status_code == 403
    assert _note(client, vid, "a viewer's note").status_code == 403
    site = _bakery(client)
    text = json.dumps(site).lower()
    for word in ("recall", "context for the team", "verdict"):
        assert word not in text, word
    assert [f["kind"] for f in _followups()] == ["note"]
