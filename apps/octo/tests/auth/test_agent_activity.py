"""Coverage for /api/v1/agent/activity (agent_activity router)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _register_client,
    _login,
)


def _insert_agent_note(
    client_dir: Path, *, ref_kind: str, ref_id: int,
    agent_id: str = "octo", note_text: str = "test note",
    confidence: float = 0.7, created_at: str | None = None,
) -> None:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        if created_at:
            conn.execute(
                "INSERT INTO agent_notes "
                "(ref_kind, ref_id, agent_id, note_text, confidence, "
                " audit_request_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ref_kind, ref_id, agent_id, note_text, confidence,
                 "test-req", created_at),
            )
        else:
            conn.execute(
                "INSERT INTO agent_notes "
                "(ref_kind, ref_id, agent_id, note_text, confidence, "
                " audit_request_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (ref_kind, ref_id, agent_id, note_text, confidence,
                 "test-req"),
            )
        conn.commit()
    finally:
        conn.close()


def test_activity_returns_recent_notes_across_scope(auth_client, auth_data_root):
    _register_client("acme"); _register_client("globex")
    for slug in ("acme", "globex"):
        cdir = auth_data_root / "clients" / slug
        _apply_events_db_migration(cdir)
        _insert_agent_note(cdir, ref_kind="event", ref_id=1,
                            note_text=f"{slug} flagged dns-tunnel",
                            confidence=0.81)
        _insert_agent_note(cdir, ref_kind="ticket", ref_id=10,
                            note_text=f"{slug} suggests close-as-noise",
                            confidence=0.92)

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity?limit=10")
    assert r.status_code == 200, r.text
    body = r.json()
    assert {item["client_slug"] for item in body["items"]} >= {"acme", "globex"}
    assert any(i["ref_kind"] == "ticket" for i in body["items"])
    assert any(i["ref_kind"] == "event" for i in body["items"])
    assert body["limit"] == 10


def test_activity_ref_kind_filter(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_agent_note(cdir, ref_kind="event",  ref_id=1, note_text="event-only")
    _insert_agent_note(cdir, ref_kind="ticket", ref_id=2, note_text="ticket-only")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity?ref_kind=ticket")
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(i["ref_kind"] == "ticket" for i in items)
    assert any(i["note_text"] == "ticket-only" for i in items)


def test_activity_viewer_denied(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_agent_note(cdir, ref_kind="event", ref_id=1)

    op = auth_client.provision_operator(
        "alice-viewer", "pw1234567890",
        role="viewer", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity")
    assert r.status_code == 403


def test_activity_scope_enforcement(auth_client, auth_data_root):
    """Caller scoped to acme should never see globex agent activity."""
    _register_client("acme"); _register_client("globex")
    for slug in ("acme", "globex"):
        cdir = auth_data_root / "clients" / slug
        _apply_events_db_migration(cdir)
        _insert_agent_note(cdir, ref_kind="event", ref_id=1,
                            note_text=f"{slug}-secret")

    op = auth_client.provision_operator(
        "alice", "pw1234567890",
        athena_role="admin", scope_slugs=["acme"],
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity")
    assert r.status_code == 200
    items = r.json()["items"]
    slugs_seen = {i["client_slug"] for i in items}
    assert "globex" not in slugs_seen
    assert "acme" in slugs_seen


def test_activity_resolves_cross_links(auth_client, auth_data_root):
    """Event-kind triage entries should surface the derived ticket id+
    title; ticket-kind entries should surface the source_event_id."""
    from apps.octo.tests.auth.test_tickets import (
        _apply_tickets_db_migration, _insert_ticket,
    )

    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _apply_tickets_db_migration(cdir)

    # Insert an event + a ticket derived from that event.
    import sqlite3 as _sql
    e = _sql.connect(cdir / "events.db")
    try:
        e.execute(
            "INSERT INTO events "
            "(received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary) "
            "VALUES ('2026-05-14T10:00:00.000Z','test-source','buoy-1',"
            " 'wazuh.alert','high','{}',?,'high-sev event')",
            ("a" * 64,),
        )
        event_id = e.execute("SELECT last_insert_rowid()").fetchone()[0]
        e.commit()
    finally:
        e.close()

    t = _sql.connect(cdir / "tickets.db")
    try:
        t.execute(
            "INSERT INTO tickets (title, severity, status, source_event_id) "
            "VALUES ('Investigate alert', 'high', 'new', ?)",
            (event_id,),
        )
        ticket_id = t.execute("SELECT last_insert_rowid()").fetchone()[0]
        t.commit()
    finally:
        t.close()

    # Two agent_notes: one on the event, one on the ticket.
    _insert_agent_note(cdir, ref_kind="event",  ref_id=event_id,
                       note_text="dns-tunnel pattern detected",
                       confidence=0.84)
    _insert_agent_note(cdir, ref_kind="ticket", ref_id=ticket_id,
                       note_text="recommend close-as-noise (false-positive cluster)",
                       confidence=0.91)

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity?limit=10")
    assert r.status_code == 200
    items = {(i["ref_kind"], i["ref_id"]): i for i in r.json()["items"]}

    # event entry → resolves to the derived ticket
    ev = items[("event", event_id)]
    assert ev["linked_ticket_id"] == ticket_id
    assert ev["linked_ticket_title"] == "Investigate alert"
    assert ev["linked_event_id"] is None

    # ticket entry → resolves to its source event + carries its own title
    tk = items[("ticket", ticket_id)]
    assert tk["linked_event_id"] == event_id
    assert tk["linked_ticket_title"] == "Investigate alert"
    assert tk["linked_ticket_id"] is None


def test_activity_ordered_newest_first(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_agent_note(cdir, ref_kind="event", ref_id=1,
                       note_text="older",
                       created_at="2026-05-13T12:00:00.000Z")
    _insert_agent_note(cdir, ref_kind="event", ref_id=2,
                       note_text="newer",
                       created_at="2026-05-14T12:00:00.000Z")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/activity")
    items = r.json()["items"]
    assert items[0]["note_text"] == "newer"
    assert items[1]["note_text"] == "older"
