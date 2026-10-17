"""The real triage worker notes stored NextDNS alerts with rule 1c's words
(the poller stores them; only the vendor socket is fake)."""
from __future__ import annotations

import sqlite3
from datetime import timedelta

from apps.octo import paths
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, block_line
from apps.octo.agent.worker import process_tenant_once

BLOCKED = ("Blocked by NextDNS before any connection. If this repeats or is "
           "C2/threat-intel, check alice-laptop for the source.")


def test_the_worker_notes_a_stored_nextdns_alert(world):
    process_tenant_once("acme-corp")                 # skip-backlog watermark
    world.transport.set_rate("abc123")
    world.transport.add_lines(
        "abc123",
        block_line(T0 - timedelta(minutes=9), reason="bypass-methods",
                   reason_name="Bypass Methods", device_name="bob-pc", device_id="D9"),
        block_line(T0 - timedelta(minutes=5)),
    )
    world.map(abc123="acme-corp")
    world.poller().run_cycle()
    result = process_tenant_once("acme-corp")
    assert result.processed >= 2
    conn = sqlite3.connect(paths.client_dir("acme-corp") / "events.db")
    try:
        rows = conn.execute(
            "SELECT e.event_type, json_extract(e.payload, '$.signal.reason_id'), n.disposition, "
            "n.note_text FROM agent_notes n JOIN events e ON e.id = n.ref_id "
            "WHERE n.query_kind = 'auto_enrich' ORDER BY e.id").fetchall()
    finally:
        conn.close()
    by_reason = {r[1]: (r[2], r[3]) for r in rows}
    assert by_reason["bypass-methods"][0] == "pattern"
    assert "evade DNS filtering (VPN/proxy/Tor)" in by_reason["bypass-methods"][1]
    assert by_reason["threat-intelligence-feeds"] == (
        "escalate", "[escalate] " + BLOCKED)


def test_the_worker_names_why_a_profile_lapsed(world):
    """A profile NextDNS stops showing to the key: the worker's note says so
    — not "check the site's UniFi DNS" (the cause is read from the payload)."""
    process_tenant_once("acme-corp")
    world.transport.set_rate("abc123")
    world.map(abc123="acme-corp")
    poller = world.poller()
    world.run_for(poller, 600)
    world.transport.profile_status["abc123"] = 404
    world.transport.profiles = [p for p in world.transport.profiles if p["id"] != "abc123"]
    world.run_for(poller, 3600)
    process_tenant_once("acme-corp")
    conn = sqlite3.connect(paths.client_dir("acme-corp") / "events.db")
    try:
        [(note,)] = conn.execute(
            "SELECT n.note_text FROM agent_notes n JOIN events e ON e.id = n.ref_id "
            "WHERE n.query_kind = 'auto_enrich' AND e.event_type = 'nextdns.protection_lapsed'"
        ).fetchall()
    finally:
        conn.close()
    assert "no longer lets Athena's API key see the profile" in note
    assert "UniFi" not in note
