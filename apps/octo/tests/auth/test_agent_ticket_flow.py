"""End-to-end: autonomous triage → ticket lifecycle → feed linkage (#119d).

Locks the cross-cutting path the live deploy rides on:
  event ingested → worker triages it (disposition note) → operator opens a
  ticket FROM that event → status transitions → close → and the agent
  triage feed correctly shows the note↔ticket linkage.
"""
from __future__ import annotations

import sqlite3

from apps.octo.agent.worker import process_tenant_once
from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _login,
    _register_client,
)
from apps.octo.tests.auth.test_tickets import _apply_tickets_db_migration


def _insert_event(client_dir, *, severity: str, summary: str) -> int:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, "
            " severity, payload, payload_sha256, summary) "
            "VALUES ('2026-06-02T10:00:00.000Z','wazuh','web-01','wazuh.alert',"
            " ?, '{}', ?, ?)",
            (severity, "a" * 64, summary),
        )
        eid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        return eid
    finally:
        conn.close()


def test_agent_triage_to_ticket_flow(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _apply_tickets_db_migration(cdir)

    # 1. Ingest a high-severity alert.
    event_id = _insert_event(cdir, severity="high", summary="C2 beacon to bad host")

    # 2. The autonomous worker triages it → escalate disposition note.
    result = process_tenant_once("acme", backfill=True)
    assert result.processed == 1
    assert result.by_disposition == {"escalate": 1}

    # 3. Operator opens a ticket FROM that event.
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.post(
        "/api/v1/tickets/acme",
        json={"title": "C2 beacon investigation", "severity": "high",
              "source_event_id": event_id},
    )
    assert r.status_code == 201, r.text
    ticket = r.json()
    tid = ticket["id"]
    assert ticket["source_event_id"] == event_id
    assert ticket["status_history"][0]["to_status"] == "new"

    # 4. Status lifecycle: new → in_progress → resolved.
    for status in ("in_progress", "resolved"):
        rr = auth_client.patch(
            f"/api/v1/tickets/acme/{tid}",
            json={"status": status, "reason": f"moving to {status}"},
        )
        assert rr.status_code == 200, rr.text
        assert rr.json()["status"] == status

    # 5. Operator adds a closing note.
    rn = auth_client.post(
        f"/api/v1/tickets/acme/{tid}/notes",
        json={"body": "Confirmed C2, host isolated, closing."},
    )
    assert rn.status_code == 201, rn.text

    # 6. The agent triage feed shows the event's escalate note, now LINKED
    #    to the ticket (via source_event_id).
    ra = auth_client.get("/api/v1/agent/activity?limit=50")
    assert ra.status_code == 200, ra.text
    items = ra.json()["items"]
    ev_notes = [i for i in items
                if i["ref_kind"] == "event" and i["ref_id"] == event_id]
    assert ev_notes, "the worker's triage note should appear in the feed"
    note = ev_notes[0]
    assert note["note_text"].startswith("[escalate]")        # autonomous disposition
    assert note["linked_ticket_id"] == tid                   # note↔ticket linkage
    assert note["linked_ticket_title"] == "C2 beacon investigation"


def test_uncertain_event_triages_without_ticket_link(auth_client, auth_data_root):
    # A medium single event → uncertain → note exists but no ticket yet,
    # so the feed shows it with no linkage (the analyst-review case).
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _apply_tickets_db_migration(cdir)
    event_id = _insert_event(cdir, severity="medium", summary="ambiguous thing")

    result = process_tenant_once("acme", backfill=True)
    assert result.by_disposition == {"uncertain": 1}

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    items = auth_client.get("/api/v1/agent/activity?limit=50").json()["items"]
    note = next(i for i in items
                if i["ref_kind"] == "event" and i["ref_id"] == event_id)
    assert note["note_text"].startswith("[uncertain]")
    assert note["linked_ticket_id"] is None  # no ticket opened for it
