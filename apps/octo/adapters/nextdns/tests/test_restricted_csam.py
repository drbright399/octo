"""v0.17.1 (Rick, 2026-10-06) at the poller — real pieces, fake socket, one
fake clock:

  * a line carrying a CSAM reason — wherever NextDNS lists it — is NEVER an
    ordinary alert and never in the coalescing ledger: it is kept ONLY as
    restricted evidence (exactly once), for rule B7;
  * the hourly roll-up still counts it (a count, no domain) — the Fleet
    takes it out again (it is never a fleet colour or a "top reason");
  * a device-originated reason (DGA, tunneling, exfiltration, payload
    delivery) comes before any other HIGH reason on its line, so the line is
    filed under it — "the device looks wrong" sees it.

The domain is a placeholder (`csam-placeholder.example.test`): no real
domain appears in a fixture.
"""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo.adapters.nextdns import classification, store
from apps.octo.adapters.nextdns.presentation import EVENT_BLOCK
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line
from apps.octo.threat import restricted

ACME = "acme-corp"
DOMAIN = "csam-placeholder.example.test"


def test_a_csam_line_is_restricted_evidence_only_never_an_alert(world):
    t = world.transport
    t.set_rate("abc123")
    h = T0 - timedelta(hours=2)
    t.add_lines("abc123",
                block_line(h + timedelta(minutes=5), domain=DOMAIN, reason="csam",
                           reason_name="Child Sexual Abuse Material"),
                # csam AFTER another HIGH reason: still restricted.
                block_line(h + timedelta(minutes=6), domain=f"cdn.{DOMAIN}",
                           extra_reasons=(("csam", "Child Sexual Abuse Material"),)),
                block_line(h + timedelta(minutes=7), domain="c2.ordinary-example.test"))
    world.map(abc123=ACME)
    poller = world.poller()
    poller.run_cycle()
    alerts = world.events(ACME, EVENT_BLOCK)
    assert len(alerts) == 1                                     # only the ordinary block
    everything = json.dumps([dict(r) for r in world.events(ACME)]).lower()
    assert "csam" not in everything and "csam-placeholder" not in everything
    buckets = list(store.iter_buckets(ACME))
    assert all(not classification.is_csam(b["reason_id"]) for b in buckets)
    assert all("csam-placeholder" not in (b["root"] or "") for b in buckets)
    rows = restricted.pending(ACME)
    assert len(rows) == 2 and {r["category"] for r in rows} == {"csam"}
    assert {r["device_key"] for r in rows} == {"D1A2B3"}
    # Read again (overlapping windows): kept exactly once.
    poller.run_cycle()
    assert len(restricted.pending(ACME)) == 2
    # The rows are append-only.
    import sqlite3

    from apps.octo import paths

    conn = sqlite3.connect(paths.client_dir(ACME) / "events.db")
    try:
        try:
            conn.execute(f"DELETE FROM {restricted.TABLE}")
            raise AssertionError("a restricted row was deleted")
        except sqlite3.IntegrityError:
            pass
        try:
            conn.execute(f"UPDATE {restricted.TABLE} SET domain = 'x'")
            raise AssertionError("a restricted row was changed")
        except sqlite3.IntegrityError:
            pass
    finally:
        conn.close()


def test_a_device_originated_reason_files_the_line_under_it():
    line = classification.classify_line([
        {"id": "threat-intelligence-feeds"}, {"id": "dga"}])
    assert line.primary.id == "dga"
    line = classification.classify_line([
        {"id": "googlesafebrowsing"}, {"id": "dns-data-exfiltration-x"}])
    assert line.primary.id == "dns-data-exfiltration-x"
    line = classification.classify_line([{"id": "dga"}, {"id": "csam"}])
    assert line.primary.id == "csam"                            # CSAM first of all
    # A MEDIUM device-originated-looking id never beats a HIGH reason.
    line = classification.classify_line([{"id": "nrd"}, {"id": "threat-intelligence-feeds"}])
    assert line.primary.id == "threat-intelligence-feeds"
    assert classification.is_device_originated("tunneling-endpoints")
    assert classification.is_device_originated("domain-generation-algorithms")
    assert not classification.is_device_originated("threat-intelligence-feeds")
    assert classification.line_is_csam([{"id": "blocklist:x"}, {"id": "CSAM"}])
    assert not classification.line_is_csam([{"id": "threat-intelligence-feeds"}])


# ---------------------------------------------------------------------------
# Fixer (review CSAM-2): the id "csam" has never been seen on a live log
# line — a variant spelling must never fall to the LOW fail-safe (an ordinary
# alert with the domain in events.db, no Black, nobody paged).
# ---------------------------------------------------------------------------

def test_csam_variant_ids_and_names_are_all_restricted():
    for rid in ("csam", "CSAM", "csam-list", "blocklist:csam", "nextdns:csam",
                "child-sexual-abuse-material", "child_sexual_abuse", "childsexualabuse"):
        assert classification.is_csam(rid), rid
        assert classification.line_is_csam([{"id": rid}]), rid
        rc = classification.classify_reason(rid)
        assert rc.level == classification.HIGH and rc.label == "a CSAM domain", rid
    # By its NAME only (an id Athena does not know).
    by_name = [{"id": "cp-filter", "name": "Child Sexual Abuse Material"}]
    assert classification.line_is_csam(by_name)
    assert classification.classify_line(by_name).level == classification.HIGH
    assert classification.line_is_csam([{"id": "x-1", "name": "CSAM"}])
    # Not CSAM: words that merely contain the letters.
    for rid in ("threat-intelligence-feeds", "csamx", "mycsam", "cs-am", "dga", ""):
        assert not classification.is_csam(rid), rid
    assert not classification.line_is_csam([{"id": "nrd", "name": "Newly Registered"}])
    # The roll-up files every spelling under "csam" (the Fleet takes it out).
    counts = classification.signal_reason_counts({
        "child-sexual-abuse-material": ("Child Sexual Abuse Material", 2),
        "cp-filter": ("Child Sexual Abuse Material", 1),
        "threat-intelligence-feeds": ("Threat Intelligence Feeds", 4)})
    assert counts == {"csam": 3, "threat-intelligence-feeds": 4}


def test_a_variant_csam_line_is_restricted_evidence_at_the_poller(world):
    t = world.transport
    t.set_rate("abc123")
    h = T0 - timedelta(hours=2)
    t.add_lines("abc123",
                block_line(h + timedelta(minutes=5), domain=DOMAIN,
                           reason="child-sexual-abuse-material",
                           reason_name="Child Sexual Abuse Material"),
                block_line(h + timedelta(minutes=6), domain=f"img.{DOMAIN}",
                           reason="cp-filter", reason_name="Child Sexual Abuse Material"))
    world.map(abc123=ACME)
    world.poller().run_cycle()
    assert world.events(ACME, EVENT_BLOCK) == []
    everything = json.dumps([dict(r) for r in world.events(ACME)]).lower()
    assert "csam-placeholder" not in everything
    assert len(restricted.pending(ACME)) == 2
