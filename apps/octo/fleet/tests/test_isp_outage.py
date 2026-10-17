"""The ISP-outage correlator on a real data root (registry, tenants, events
stores, the real UniFi adapter's extract + the real sink) — no network.

Pins (Fleet v2 spec, part 2):
  * 3 sites on one ASN going down within 10 min → ONE `fleet.isp_outage`
    (HIGH, OCSF Incident Finding) in the internal tenant;
  * 2 sites → none; 3 sites over mixed ASNs → none; 1 site → none; onsets
    further apart than the window → none;
  * sites already down when first seen (a start) → none (onset unknown);
  * a fleet-wide wave across >= 3 ASNs → none (suppressed, shown) — and it
    stays suppressed past the window and across a restart; an old cluster
    never opens late;
  * failure points, not sites: one multi-site console (or one shared WAN
    address) counts once; every site of a counted point is listed;
  * each member site's own WAN alerts get a note linking them (the client's
    note: its own provider only — no count, no ASN, no other client); the
    incident lists them; a later site of the same ASN joins;
  * recovery closes it with a note; a relapse within 30 min reopens THE SAME
    incident (a note, no new alert);
  * restart: a new correlator over the stored state raises nothing new; a
    crash between queueing and writing delivers ONCE; a re-delivery after a
    crash between writing and saving is the same row (the sink's guard).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.adapters.unifi import catalogue
from apps.octo.adapters.unifi.adapter import UniFiSourceAdapter
from apps.octo.adapters.unifi.tests.fake_unifi import CREDS
from apps.octo.client_provisioning import create_client
from apps.octo.fleet import isp_outage
from apps.octo.fleet.isp_outage import IspOutageCorrelator
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import create_instance, poller_state
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

T0 = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
POLL = timedelta(minutes=5)
INTERNAL = "msp-internal"
ASN_A, ASN_B, ASN_C = 64500, 64501, 64502


def scope(n: int) -> str:
    return f"F1X7{n:04d}000000000000000000000000000000000000000000000000:10000{n:04d}/" \
           f"f1x7517e0000000000000001"


def tenant(n: int) -> str:
    return f"tenant-{n:02d}"


def site(n: int, *, asn: int = ASN_A, isp: str = "Example ISP", connected: bool = True,
         port_up: bool = True, issues: tuple[str, ...] = (), host: Optional[str] = None,
         ip: Optional[str] = None) -> dict[str, Any]:
    sc = scope(n) if host is None else f"{host}/f1x7517e00000000000000{n:02d}"
    return {
        "scope": sc, "slug": tenant(n), "name": f"Example Site {n}",
        "host_id": sc.split("/")[0],
        "host_connected": connected,
        "wans": [{"wan": "WAN", "asn": asn, "isp": isp, "port_up": port_up,
                  "external_ip": ip or f"203.0.113.{n}"}],
        "stats": {"isp_asn": asn, "isp_name": isp, "internet_issue_keys": list(issues),
                  "wan_issue_keys": {}},
    }


@pytest.fixture
def world(bedrock_root, monkeypatch):  # noqa: F811
    monkeypatch.delenv(isp_outage.MIN_SITES_ENV, raising=False)
    monkeypatch.delenv(isp_outage.WINDOW_ENV, raising=False)
    create_client(INTERNAL, "Example MSP", kind="internal")
    # Only the stores the correlator writes to need to exist: the internal
    # tenant and the tenants whose WAN alerts a test stores.
    for n in range(1, 4):
        create_client(tenant(n), f"Example Client {n}", kind="client")
    record = create_instance(vendor_slug="unifi", display_name="UniFi Network",
                             credentials_dict=dict(CREDS), instance_config={})
    return record


class Ingest:
    """The poller's `_ingest_derived`: the real adapter + the real sink."""

    def __init__(self) -> None:
        self.adapter = UniFiSourceAdapter()
        self.sink = SqliteIngestSink(publish_to_stream=False)
        self.calls = 0
        self.fail_next = 0

    def __call__(self, slug: str, payload: dict[str, Any]) -> Optional[int]:
        self.calls += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            raise sqlite3.OperationalError("database is locked")
        event = self.adapter.extract_event(payload)
        return self.sink.ingest(slug, "unifi", event).event_id


def correlator(record, ingest: Optional[Ingest] = None, **kw: Any) -> IspOutageCorrelator:
    return IspOutageCorrelator(instance_id=record.id, ingest=ingest or Ingest(),
                               build_payload=catalogue.isp_outage_payload, **kw)


def events(slug: str, event_type: str = isp_outage.EVENT_TYPE) -> list[sqlite3.Row]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM events WHERE event_type = ? ORDER BY id",
                            (event_type,)).fetchall()
    finally:
        conn.close()


def notes(slug: str, event_id: int) -> list[str]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return [r[0] for r in conn.execute(
            "SELECT note_text FROM agent_notes WHERE ref_kind = 'event' AND ref_id = ? "
            "ORDER BY id", (event_id,))]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def wan_alert(n: int, at: datetime) -> int:
    """A site's own `unifi.wan_down` alert in ITS tenant (what the system log
    reader stores)."""
    payload = {
        "vendor_event_id": f"{scope(n)}:wan-{n}", "kind": "wan_down", "scope": scope(n),
        "host_id": scope(n).split("/")[0], "site_id": "f1x7517e0000000000000001",
        "site_ref": "default", "site_name": f"Example Site {n}", "console_name": f"udm-{n}",
        "event": {"id": f"wan-{n}", "timestamp": at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                  "category": "INTERNET", "event": "NETWORK_WAN_FAILED", "title": "WAN failed"},
        "signal": {"level": "medium"},
    }
    event = UniFiSourceAdapter().extract_event(payload)
    return SqliteIngestSink(publish_to_stream=False).ingest(tenant(n), "unifi", event).event_id


def healthy_then_down(c: IspOutageCorrelator, ns: list[int], *, asns: Optional[dict] = None,
                      down_at: datetime = T0 + POLL) -> None:
    asns = asns or {}
    c.evaluate([site(n, asn=asns.get(n, ASN_A)) for n in ns], T0, POLL)
    c.evaluate([site(n, asn=asns.get(n, ASN_A), connected=False) for n in ns], down_at, POLL)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def test_three_sites_on_one_asn_make_one_incident(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3])
    rows = events(INTERNAL)
    assert len(rows) == 1
    row = rows[0]
    assert row["severity"] == "high" and row["source"] == "unifi"
    payload = json.loads(row["payload"])
    assert payload["kind"] == "isp_outage" and payload["sites"] == 3
    assert payload["isp"] == {"name": "Example ISP", "asn": ASN_A}
    assert {a["tenant"] for a in payload["affected"]} == {tenant(1), tenant(2), tenant(3)}
    ocsf = payload["ocsf"]
    assert (ocsf["class_uid"], ocsf["class_name"], ocsf["category_uid"]) == \
        (2005, "Incident Finding", 2)
    assert ocsf["severity_id"] == 4 and ocsf["type_uid"] == 200501
    assert len(ocsf["finding_info_list"]) == 3
    assert row["summary"] == "ISP outage: Example ISP — 3 sites"
    # Nothing in the clients' own stores.
    for n in (1, 2, 3):
        assert events(tenant(n)) == []
    snap = c.snapshot()
    assert snap[0]["open"] is True and snap[0]["sites"] == 3 and snap[0]["event_id"] == row["id"]
    # The next poll, still down: still ONE.
    c.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 2 * POLL, POLL)
    assert len(events(INTERNAL)) == 1


def test_two_sites_make_none(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2])
    assert events(INTERNAL) == []
    assert c.snapshot() == []


def test_one_site_makes_none_even_at_min_two(world):
    c = correlator(world, min_sites_n=2)
    healthy_then_down(c, [1])
    assert events(INTERNAL) == []


def test_mixed_asns_make_none(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3], asns={1: ASN_A, 2: ASN_A, 3: ASN_B})
    assert events(INTERNAL) == []
    healthy_then_down(correlator(world), [4, 5, 6], asns={4: ASN_A, 5: ASN_B, 6: ASN_C})
    assert events(INTERNAL) == []


def test_onsets_further_apart_than_the_window_make_none(world):
    c = correlator(world)
    ns = [1, 2, 3]
    c.evaluate([site(n) for n in ns], T0, POLL)
    t = T0
    down: set[int] = set()
    for n in ns:                                     # one site every 15 minutes
        t += timedelta(minutes=15)
        down.add(n)
        prev = t - POLL
        c.evaluate([site(m, connected=m not in (down - {n})) for m in ns], prev, POLL)
        c.evaluate([site(m, connected=m not in down) for m in ns], t, POLL)
    assert events(INTERNAL) == []


def test_sites_already_down_at_start_make_none(world):
    c = correlator(world)
    c.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0, POLL)
    c.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + POLL, POLL)
    assert events(INTERNAL) == []
    # A stale gap (> 2 polls) makes the next observation a first one again.
    c.evaluate([site(n) for n in (1, 2, 3)], T0 + 2 * POLL, POLL)
    c.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 2 * POLL + 20 * POLL, POLL)
    assert events(INTERNAL) == []


def test_a_wan_port_down_counts_for_that_wans_asn(world):
    c = correlator(world)
    ns = [1, 2, 3]
    c.evaluate([site(n) for n in ns], T0, POLL)
    c.evaluate([site(n, port_up=False) for n in ns], T0 + POLL, POLL)
    payload = json.loads(events(INTERNAL)[0]["payload"])
    assert {a["why"] for a in payload["affected"]} == {"WAN down"}


def test_new_internet_issues_count_old_ones_do_not(world):
    c = correlator(world)
    ns = [1, 2, 3]
    # A history of issues from before: not an onset.
    c.evaluate([site(n, issues=("i100",)) for n in ns], T0, POLL)
    c.evaluate([site(n, issues=("i100",)) for n in ns], T0 + POLL, POLL)
    assert events(INTERNAL) == []
    c.evaluate([site(n, issues=("i100", "i101")) for n in ns], T0 + 2 * POLL, POLL)
    assert events(INTERNAL) == []          # issue-only, first poll: pending
    c.evaluate([site(n, issues=("i100", "i101", "i102")) for n in ns], T0 + 3 * POLL, POLL)
    payload = json.loads(events(INTERNAL)[0]["payload"])
    assert {a["why"] for a in payload["affected"]} == {"internet issues"}


def test_a_single_poll_of_new_issues_never_pages(world):
    """Verifier round: three sites each logging ONE new internet-issue entry
    in the same poll (a latency blip) opened a HIGH 'ISP outage' that closed
    on the next poll, and reopened on the next blip. Issue-only trouble now
    has to persist for two polls; a blip raises nothing."""
    c = correlator(world)
    ns = [1, 2, 3]
    c.evaluate([site(n, issues=("i100",)) for n in ns], T0, POLL)
    c.evaluate([site(n, issues=("i100", "i101")) for n in ns], T0 + POLL, POLL)      # blip
    c.evaluate([site(n, issues=("i100", "i101")) for n in ns], T0 + 2 * POLL, POLL)  # gone
    c.evaluate([site(n, issues=("i100", "i101", "i102")) for n in ns], T0 + 3 * POLL, POLL)  # blip
    c.evaluate([site(n, issues=("i100", "i101", "i102")) for n in ns], T0 + 4 * POLL, POLL)  # gone
    assert events(INTERNAL) == []


def test_a_hard_failure_still_counts_on_the_first_poll(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3])        # console unreachable: no waiting
    assert len(events(INTERNAL)) == 1


def test_a_fleet_wide_wave_is_not_an_isp_outage(world):
    c = correlator(world)
    ns = list(range(1, 10))
    asns = {n: (ASN_A, ASN_B, ASN_C)[(n - 1) % 3] for n in ns}
    healthy_then_down(c, ns, asns=asns)
    assert events(INTERNAL) == []
    suppressed = [i for i in c.snapshot() if i.get("suppressed")]
    assert suppressed and suppressed[0]["suppressed"]["asns"] == 3


def test_no_internal_tenant_tracks_without_writing(world):
    c = correlator(world, tenant=lambda: None)
    healthy_then_down(c, [1, 2, 3])
    assert events(INTERNAL) == []
    snap = c.snapshot()
    assert snap[0]["open"] is True and snap[0]["tenant"] is None


# ---------------------------------------------------------------------------
# Grouping, joining, closing, relapse
# ---------------------------------------------------------------------------

def test_site_wan_alerts_are_grouped_and_a_late_site_joins(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3, 4], asns={4: ASN_A})
    (inc,) = events(INTERNAL)
    # The consoles come back online with their own WAN_FAILED lines.
    ids = {n: wan_alert(n, T0 + POLL - timedelta(minutes=1)) for n in (1, 2, 3)}
    c.evaluate([site(n, connected=False) for n in (1, 2, 3, 4)], T0 + 2 * POLL, POLL)
    for n, eid in ids.items():
        (text,) = notes(tenant(n), eid)
        assert text == isp_outage.client_note("Example ISP")
        assert text.startswith("Linked to a provider-wide internet outage on Example ISP")
        # The client's own note: no count, no ASN, no time, no other client.
        assert not any(ch.isdigit() for ch in text), text
        assert "tenant-" not in text and "Example Site" not in text
        assert "AS64500" not in text and "sites" not in text
    listed = [t for t in notes(INTERNAL, inc["id"]) if t.startswith("Grouped under")]
    assert len(listed) == 1 and "3 site WAN alerts" in listed[0]
    # Again: nothing new.
    c.evaluate([site(n, connected=False) for n in (1, 2, 3, 4)], T0 + 3 * POLL, POLL)
    assert all(len(notes(tenant(n), eid)) == 1 for n, eid in ids.items())
    # A fifth site on the same ISP joins the open incident.
    c.evaluate([site(n, connected=False) for n in (1, 2, 3, 4)] + [site(5)],
               T0 + 4 * POLL, POLL)
    c.evaluate([site(n, connected=False) for n in (1, 2, 3, 4, 5)], T0 + 5 * POLL, POLL)
    assert len(events(INTERNAL)) == 1
    assert any(t.startswith("Now 5 sites on Example ISP") for t in notes(INTERNAL, inc["id"]))


def test_recovery_closes_and_a_relapse_reopens_the_same_incident(world):
    c = correlator(world)
    ns = [1, 2, 3]
    healthy_then_down(c, ns)
    (inc,) = events(INTERNAL)
    # One back: 2 still down, 1 of 3 back — stays open.
    c.evaluate([site(1), site(2, connected=False), site(3, connected=False)],
               T0 + 2 * POLL, POLL)
    assert c.snapshot()[0]["open"] is True
    # Two back (1 still down, 2 of 3 back): closed with a note.
    c.evaluate([site(1), site(2), site(3, connected=False)], T0 + 3 * POLL, POLL)
    snap = c.snapshot()[0]
    assert snap["open"] is False and snap["closed_at"]
    closing = [t for t in notes(INTERNAL, inc["id"]) if "are back online" in t]
    assert len(closing) == 1 and closing[0].startswith("2 of the 3 sites")
    assert "1 still down: Example Site 3 (tenant-03)" in closing[0]
    # All down again within 30 minutes: the same incident, no new alert.
    c.evaluate([site(n) for n in ns], T0 + 4 * POLL, POLL)
    c.evaluate([site(n, connected=False) for n in ns], T0 + 5 * POLL, POLL)
    assert len(events(INTERNAL)) == 1
    assert c.snapshot()[0]["open"] is True
    assert any("again" in t for t in notes(INTERNAL, inc["id"]))


# ---------------------------------------------------------------------------
# Restart safety
# ---------------------------------------------------------------------------

def test_restart_raises_nothing_new(world):
    healthy_then_down(correlator(world), [1, 2, 3])
    c2 = correlator(world)                          # a restart: the stored state
    c2.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 2 * POLL, POLL)
    assert len(events(INTERNAL)) == 1
    assert c2.snapshot()[0]["open"] is True
    c2.evaluate([site(n) for n in (1, 2, 3)], T0 + 3 * POLL, POLL)
    assert c2.snapshot()[0]["open"] is False
    (inc,) = events(INTERNAL)
    assert len([t for t in notes(INTERNAL, inc["id"]) if "are back online" in t]) == 1


def test_a_crash_before_the_write_delivers_once(world):
    flaky = Ingest()
    flaky.fail_next = 1
    healthy_then_down(correlator(world, flaky), [1, 2, 3])
    assert events(INTERNAL) == []                     # queued, not written
    stored = poller_state.load(world.id, isp_outage.STATE_KEY)
    assert [i["op"] for i in stored["outbox"]] == ["event"]
    c2 = correlator(world)                            # restart
    c2.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 2 * POLL, POLL)
    assert len(events(INTERNAL)) == 1
    c2.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 3 * POLL, POLL)
    assert len(events(INTERNAL)) == 1
    assert poller_state.load(world.id, isp_outage.STATE_KEY)["outbox"] == []


def test_a_crash_after_the_write_redelivers_the_same_row(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3])
    (row,) = events(INTERNAL)
    # Simulate: the write happened, the state save after it did not (the
    # outbox still holds the signal; its id was never recorded).
    stored = poller_state.load(world.id, isp_outage.STATE_KEY)
    inc = next(iter(stored["incidents"].values()))
    view = {"vid": inc["vid"], "asn": inc["asn"], "isp": inc["isp"], "since": inc["since"],
            "opened_at": inc["opened_at"], "min_sites": 3, "window_min": 10,
            "sites": len(inc["members"]),
            "affected": [{"scope": s, "site_name": m["name"], "tenant": m["slug"],
                          "since": m["since"], "why": m["why"]}
                         for s, m in inc["members"].items()]}
    stored["outbox"] = [{"op": "event", "vid": inc["vid"], "slug": INTERNAL,
                         "payload": catalogue.isp_outage_payload(view)}]
    inc["event_id"] = None
    assert poller_state.save(world.id, isp_outage.STATE_KEY, stored)
    c2 = correlator(world)
    c2.evaluate([site(n, connected=False) for n in (1, 2, 3)], T0 + 2 * POLL, POLL)
    rows = events(INTERNAL)
    assert len(rows) == 1 and rows[0]["id"] == row["id"]
    assert c2.snapshot()[0]["event_id"] == row["id"]


def test_configuration_is_bounded():
    assert isp_outage.min_sites({}) == 3
    assert isp_outage.min_sites({isp_outage.MIN_SITES_ENV: "1"}) == 2
    assert isp_outage.min_sites({isp_outage.MIN_SITES_ENV: "5"}) == 5
    assert isp_outage.min_sites({isp_outage.MIN_SITES_ENV: "x"}) == 3
    assert isp_outage.window({}) == timedelta(minutes=10)
    assert isp_outage.window({isp_outage.WINDOW_ENV: "999"}) == timedelta(minutes=60)


def test_cluster_picks_the_largest_group_within_the_span():
    t = T0
    got = isp_outage.cluster([("a", t), ("b", t + timedelta(minutes=30)),
                              ("c", t + timedelta(minutes=31)),
                              ("d", t + timedelta(minutes=39))], timedelta(minutes=10))
    assert [s for s, _ in got] == ["b", "c", "d"]


def test_members_that_vanish_never_hold_the_incident_open(world):
    c = correlator(world)
    healthy_then_down(c, [1, 2, 3, 4])
    assert c.snapshot()[0]["open"] is True
    # Sites 2-4 are unmapped (no longer observed); site 1 comes back.
    c.evaluate([site(1)], T0 + 2 * POLL, POLL)
    snap = c.snapshot()[0]
    assert snap["open"] is False and snap["closed_at"]


# ---------------------------------------------------------------------------
# Review round: a wave stays suppressed; failure points, not sites
# ---------------------------------------------------------------------------

def _wave_asns(ns: list[int]) -> dict[int, int]:
    return {n: (ASN_A, ASN_B, ASN_C)[(n - 1) % 3] for n in ns}


def test_a_suppressed_wave_never_turns_into_isp_outages_later(world):
    c = correlator(world)
    ns = list(range(1, 10))
    asns = _wave_asns(ns)
    healthy_then_down(c, ns, asns=asns)                  # the wave at T0+5
    for k in range(2, 8):                                # it lasts 30 more minutes
        c.evaluate([site(n, asn=asns[n], connected=False) for n in ns], T0 + k * POLL, POLL)
        assert events(INTERNAL) == [], k
    assert [i for i in c.snapshot() if i.get("open")] == []
    # A restart keeps the verdict (the stored state holds the wave).
    c2 = correlator(world)
    c2.evaluate([site(n, asn=asns[n], connected=False) for n in ns], T0 + 8 * POLL, POLL)
    assert events(INTERNAL) == []
    stored = poller_state.load(world.id, isp_outage.STATE_KEY)
    assert len(stored["suppressed"]) == 9


def test_a_late_site_after_a_wave_does_not_revive_it(world):
    c = correlator(world)
    ns = list(range(1, 10))
    asns = _wave_asns(ns)
    healthy_then_down(c, ns + [10], asns={**asns, 10: ASN_A})
    # Site 10 (ASN A) goes down 7 minutes into the wave, still inside it.
    down = [site(n, asn=asns[n], connected=False) for n in ns]
    c.evaluate(down + [site(10, connected=False)], T0 + POLL + timedelta(minutes=7), POLL)
    for k in range(3, 8):
        c.evaluate(down + [site(10, connected=False)], T0 + k * POLL, POLL)
    assert events(INTERNAL) == []


def test_an_old_cluster_never_opens_late(world):
    """Onsets observed long ago (say, while the internal tenant was being
    fixed up) never open an incident once they are older than the window."""
    c = correlator(world)
    ns = [1, 2, 3]
    healthy_then_down(c, ns, asns={1: ASN_A, 2: ASN_A, 3: ASN_B})
    # Site 3 is re-pointed to ASN A's onset 20 minutes later: an OLD cluster.
    stored = poller_state.load(world.id, isp_outage.STATE_KEY)
    t3 = stored["sites"][scope(3)]["trouble"].pop(str(ASN_B))
    stored["sites"][scope(3)]["trouble"][str(ASN_A)] = t3
    assert poller_state.save(world.id, isp_outage.STATE_KEY, stored)
    c2 = correlator(world)
    c2.evaluate([site(n, connected=False) for n in ns], T0 + POLL + timedelta(minutes=20),
                POLL)
    assert events(INTERNAL) == []


def test_one_multi_site_console_is_one_failure_point(world):
    c = correlator(world)
    hosted = "F1X7H057000000000000000000000000000000000000000000000000:100099999"
    ns = [1, 2, 3]
    c.evaluate([site(n, host=hosted, ip="203.0.113.200") for n in ns], T0, POLL)
    c.evaluate([site(n, host=hosted, ip="203.0.113.200", connected=False) for n in ns],
               T0 + POLL, POLL)
    assert events(INTERNAL) == []                         # one console reboot, not 3 sites
    # Even with every WAN port down on that console: one shared address.
    c.evaluate([site(n, host=hosted, ip="203.0.113.200") for n in ns], T0 + 2 * POLL, POLL)
    c.evaluate([site(n, host=hosted, ip="203.0.113.200", port_up=False) for n in ns],
               T0 + 3 * POLL, POLL)
    assert events(INTERNAL) == []


def test_sites_of_other_consoles_behind_one_address_are_one(world):
    c = correlator(world)
    ns = [1, 2, 3]
    c.evaluate([site(n, ip="203.0.113.77") for n in ns], T0, POLL)
    c.evaluate([site(n, ip="203.0.113.77", port_up=False) for n in ns], T0 + POLL, POLL)
    assert events(INTERNAL) == []


def test_three_failure_points_count_and_every_site_is_listed(world):
    c = correlator(world)
    hosted = "F1X7H057000000000000000000000000000000000000000000000000:100099999"
    shared = [site(n, host=hosted, ip="203.0.113.200") for n in (1, 2)]
    alone = [site(n) for n in (3, 4)]
    c.evaluate(shared + alone, T0, POLL)
    c.evaluate([dict(s, host_connected=False) for s in shared + alone], T0 + POLL, POLL)
    (row,) = events(INTERNAL)                              # 3 points: the console + 2
    payload = json.loads(row["payload"])
    assert payload["sites"] == 4
    assert {a["tenant"] for a in payload["affected"]} == {tenant(n) for n in (1, 2, 3, 4)}
    # Two of the four back = the console's two sites: 2 points still down
    # (< 3) and half the sites back → closed.
    c.evaluate([dict(s) for s in shared] + [dict(s, host_connected=False) for s in alone],
               T0 + 2 * POLL, POLL)
    assert c.snapshot()[0]["open"] is False


def test_the_failure_unit():
    s = site(1)
    assert isp_outage.failure_unit(s, ASN_A, "console unreachable").startswith("h:")
    assert isp_outage.failure_unit(s, ASN_A, "WAN down").startswith("ip:")
    no_ip = dict(s, wans=[{"wan": "WAN", "asn": ASN_A, "port_up": False}])
    assert isp_outage.failure_unit(no_ip, ASN_A, "WAN down").startswith("s:")
    assert isp_outage.failure_unit(no_ip, ASN_A, "WAN down", console_sites=2) == \
        isp_outage.failure_unit(no_ip, ASN_A, "console unreachable")
    # The unit is a digest: no address or console id is stored in clear.
    assert "203.0.113" not in isp_outage.failure_unit(s, ASN_A, "WAN down")


def test_a_backup_line_going_down_is_never_an_isp_outage(world):
    """Owner decision 2026-10-02: a backup WAN is nice-to-have — three sites'
    WAN2 dropping (the backup ISP) must not page as an outage."""
    c = correlator(world)
    ns = [1, 2, 3]

    def with_backup(n, up):
        s = site(n)
        s["wans"].append({"wan": "WAN2", "asn": 64999, "isp": "Backup ISP", "port_up": up})
        return s

    c.evaluate([with_backup(n, True) for n in ns], T0, POLL)
    c.evaluate([with_backup(n, False) for n in ns], T0 + POLL, POLL)
    assert events(INTERNAL) == []
