"""A RocketCyber closure (resolved / suppressed, medium) is triaged as a
vendor-reported closure with a no-action note that points at the earlier
open row — never an "uncertain — deferring to LLM/analyst" to-do (v0.11 R2).

End to end on real pieces: the real RocketCyber poller stores the open
incident and, a cycle later, its closure (only the vendor socket is fake);
the real triage worker (`process_tenant_once`) writes its notes.
"""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo import paths
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    FakeRocketCyberTransport,
    incident,
    resolved,
)
from apps.octo.adapters.rocketcyber.tests.test_poller import (  # noqa: F401
    _clean_state,
    _mapped_instance,
    _poller,
)
from apps.octo.agent.worker import process_tenant_once
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


def _notes(slug: str) -> dict[int, tuple[str, str]]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT ref_id, disposition, note_text FROM agent_notes WHERE ref_kind = 'event'")}
    finally:
        conn.close()


def _events(slug: str) -> list[tuple]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return conn.execute(
            "SELECT id, severity, json_extract(payload, '$.id'), json_extract(payload, '$.status') "
            "FROM events ORDER BY id").fetchall()
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_a_closure_is_a_no_action_note_pointing_at_the_open_row(bedrock_root):  # noqa: F811
    record = _mapped_instance()
    transport = FakeRocketCyberTransport()
    opened = incident(1)
    suppressed_one = incident(2)
    transport.incidents = [opened, suppressed_one]
    poller = _poller(transport, record)
    await poller._drain_once()
    transport.incidents = [resolved(opened), dict(suppressed_one, status="suppressed")]
    await poller._drain_once()
    # A closure whose open row was never stored here (history).
    orphan = dict(resolved(incident(3)))
    transport.incidents.append(orphan)
    await poller._drain_once()

    rows = _events("acme-corp")
    by = {(r[2], r[3]): r[0] for r in rows}
    assert [r[1] for r in rows] == ["high", "high", "medium", "medium", "medium"]

    result = process_tenant_once("acme-corp", backfill=True)
    assert result.processed == 5
    notes = _notes("acme-corp")
    # The open rows escalate, as before.
    assert notes[by[(5001, "open")]][0] == "escalate"
    assert notes[by[(5002, "open")]][0] == "escalate"
    # The closures: no action, and which open row they close.
    disp, text = notes[by[(5001, "resolved")]]
    assert disp == "noise"
    assert text == (
        f"[noise] RocketCyber reports incident 5001 resolved — the closure of the open "
        f"incident recorded as event #{by[(5001, 'open')]}. Vendor-reported closure; "
        "no action needed.")
    disp, text = notes[by[(5002, "suppressed")]]
    assert disp == "noise" and f"event #{by[(5002, 'open')]}" in text
    disp, text = notes[by[(5003, "resolved")]]
    assert disp == "noise" and "its open record is not in this tenant's store" in text
    assert not any(d == "uncertain" for d, _ in notes.values())
