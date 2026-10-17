"""AutotaskPoller integration tests — DB + auth fixtures needed.

Tests for the reconciler (upsert_ticket, upsert_ticket_note) and the
full poll cycle (tick_once with stubbed HTTP)."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from apps.octo.adapters.autotask.poller import (
    NOTE_CURSOR_KEY,
    TICKET_CURSOR_KEY,
    AutotaskPoller,
    load_tenant_routing,
    upsert_ticket,
    upsert_ticket_note,
)
from apps.octo.adapters.autotask.tests.fake_autotask_query import FakeAutotaskQuery
from apps.octo.instances import poller_state
from apps.octo.tests.auth.test_search_events import _login, _register_client


# ---------------------------------------------------------------------------
# load_tenant_routing
# ---------------------------------------------------------------------------

def test_load_tenant_routing_empty_when_no_rows(auth_client, auth_data_root):
    routing = load_tenant_routing(adapter_instance_id=7)
    assert routing == {}


def test_load_tenant_routing_reads_map(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    auth_client.put(
        "/api/v1/integrations/autotask/7/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 100},
            {"tenant_slug": "globex", "autotask_company_id": 200},
        ]},
    )
    routing = load_tenant_routing(adapter_instance_id=7)
    assert routing == {100: "acme", 200: "globex"}


def test_load_tenant_routing_also_reads_the_generic_map(auth_client, auth_data_root):
    """Integrations → Map tenants (the generic editor) writes
    adapter_tenant_map; those mappings must route tickets too. The Autotask
    page's own map wins on a conflict; a non-numeric id is ignored."""
    from apps.octo import paths

    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.executemany(
            "INSERT INTO adapter_tenant_map (adapter_instance_id, vendor_tenant_id, "
            "octo_client_slug) VALUES (?, ?, ?)",
            [(7, "300", "initech"), (7, "100", "umbrella"), (7, "not-a-number", "hooli"),
             (8, "400", "other-instance")],
        )
        reg.commit()
    finally:
        reg.close()
    assert load_tenant_routing(adapter_instance_id=7) == {300: "initech", 100: "umbrella"}
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    auth_client.put(
        "/api/v1/integrations/autotask/7/mappings/companies",
        json={"mappings": [{"tenant_slug": "acme", "autotask_company_id": 100}]},
    )
    assert load_tenant_routing(adapter_instance_id=7) == {300: "initech", 100: "acme"}


def test_the_generic_editor_path_is_not_swallowed_by_the_autotask_router(auth_client):
    """2026-10-05: the Autotask router (registered first) also served
    `/integrations/autotask/{id}/mappings/tenants`, so the generic mapping
    panel's save got a 422 "request failed validation". That path now
    belongs to the generic editor only."""
    from apps.octo.api.routers import autotask_mappings

    paths_ = {getattr(r, "path", "") for r in autotask_mappings.router.routes}
    assert not any(p.endswith("/mappings/tenants") for p in paths_)
    assert any(p.endswith("/mappings/companies") for p in paths_)
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.put("/api/v1/integrations/autotask/7/mappings/tenants",
                        json={"mappings": []})
    assert r.status_code != 422 or "tenant_slug" not in r.text


# ---------------------------------------------------------------------------
# upsert_ticket
# ---------------------------------------------------------------------------

def test_upsert_ticket_inserts_new(auth_client, auth_data_root):
    _register_client("acme")
    outcome = upsert_ticket("acme", {
        "id": 12345,
        "title": "Investigate alert",
        "description": "Customer reports …",
        "priority": 1,          # AW03: 1 = High
        "status": 8,
        "lastActivityDate": "2026-05-14T10:00:00.000Z",
        "companyID": 100,
    })
    assert outcome == "inserted"
    from apps.octo import paths
    db = paths.client_dir("acme") / "tickets.db"
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT autotask_id, title, severity, status, last_autotask_sync_at "
            "  FROM tickets WHERE autotask_id = '12345'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == "12345"
    assert row[1] == "Investigate alert"
    assert row[2] == "high"
    assert row[3] == "in_progress"
    assert row[4] is not None


def test_upsert_ticket_updates_existing(auth_client, auth_data_root):
    _register_client("acme")
    upsert_ticket("acme", {"id": 1, "title": "v1", "priority": 4, "status": 1,
                            "companyID": 100})
    outcome = upsert_ticket("acme", {"id": 1, "title": "v2 — updated",
                                       "priority": 1, "status": 8,
                                       "companyID": 100})
    assert outcome == "updated"
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir("acme") / "tickets.db")
    try:
        row = conn.execute(
            "SELECT title, severity, status FROM tickets WHERE autotask_id = '1'"
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "v2 — updated"
    assert row[1] == "high"
    assert row[2] == "in_progress"


def test_upsert_ticket_complete_stamps_closed_at(auth_client, auth_data_root):
    _register_client("acme")
    upsert_ticket("acme", {
        "id": 999, "title": "done", "priority": 3, "status": 5,   # AW03 5 = Complete
        "lastActivityDate": "2026-05-14T11:00:00.000Z",
        "companyID": 100,
    })
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir("acme") / "tickets.db")
    try:
        row = conn.execute(
            "SELECT status, closed_at FROM tickets WHERE autotask_id = '999'"
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "resolved"
    assert row[1] == "2026-05-14T11:00:00.000Z"


def _ticket_row(slug: str, autotask_id: str) -> sqlite3.Row:
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir(slug) / "tickets.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM tickets WHERE autotask_id = ?",
                            (autotask_id,)).fetchone()
    finally:
        conn.close()


def _history(slug: str, autotask_id: str) -> list[tuple]:
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir(slug) / "tickets.db")
    try:
        return conn.execute(
            "SELECT h.from_status, h.to_status, h.changed_by_operator_id, h.source "
            "  FROM ticket_status_history h JOIN tickets t ON t.id = h.ticket_id "
            " WHERE t.autotask_id = ? ORDER BY h.id",
            (autotask_id,),
        ).fetchall()
    finally:
        conn.close()


def test_upsert_unknown_status_keeps_the_previous_one(auth_client, auth_data_root):
    """An AW03 status id the map does not know never resets a ticket to
    'new' (or anything else): the mirror keeps what it showed."""
    _register_client("acme")
    upsert_ticket("acme", {"id": 31, "title": "t", "priority": 2, "status": 7,
                           "companyID": 100})
    assert _ticket_row("acme", "31")["status"] == "waiting_customer"
    upsert_ticket("acme", {"id": 31, "title": "t", "priority": 2, "status": 4242,
                           "companyID": 100})
    assert _ticket_row("acme", "31")["status"] == "waiting_customer"
    # Escalated (11) is work in progress, never resolved.
    upsert_ticket("acme", {"id": 31, "title": "t", "priority": 2, "status": 11,
                           "companyID": 100})
    assert _ticket_row("acme", "31")["status"] == "in_progress"


def test_status_history_autotask_sync_row(auth_client, auth_data_root):
    """Every status the mirror takes from Autotask is in the ticket's
    history: source 'autotask_sync', no operator. Re-reading an unchanged
    (or unknown) status adds nothing."""
    _register_client("acme")
    base = {"id": 77, "title": "VPN down", "priority": 1, "companyID": 100}
    upsert_ticket("acme", {**base, "status": 1})
    upsert_ticket("acme", {**base, "status": 1})               # unchanged
    upsert_ticket("acme", {**base, "status": 8})
    upsert_ticket("acme", {**base, "status": 999})             # unknown: kept
    upsert_ticket("acme", {**base, "status": 5})
    assert _history("acme", "77") == [
        (None, "new", None, "autotask_sync"),
        ("new", "in_progress", None, "autotask_sync"),
        ("in_progress", "resolved", None, "autotask_sync"),
    ]


# ---------------------------------------------------------------------------
# upsert_ticket_note
# ---------------------------------------------------------------------------

def test_upsert_ticket_note_orphan_when_no_parent(auth_client, auth_data_root):
    _register_client("acme")
    outcome = upsert_ticket_note("acme", {
        "id": 555, "ticketID": 9999, "description": "lonely note",
    })
    assert outcome == "orphan"


def test_upsert_ticket_note_inserts_when_parent_exists(auth_client, auth_data_root):
    _register_client("acme")
    upsert_ticket("acme", {"id": 1, "title": "parent", "priority": 3,
                            "status": 1, "companyID": 100})
    outcome = upsert_ticket_note("acme", {
        "id": 777, "ticketID": 1,
        "title": "First note", "description": "First note body",
    })
    assert outcome == "inserted"
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir("acme") / "tickets.db")
    try:
        row = conn.execute(
            "SELECT autotask_id, title, body FROM ticket_notes "
            " WHERE autotask_id = '777'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[1] == "First note"
    assert row[2] == "First note body"


# ---------------------------------------------------------------------------
# Poller.tick_once
# ---------------------------------------------------------------------------

# The fixtures are dated 2026-05-14; the poller's clock is pinned just after,
# so a first run's 30-day lookback covers them.
_NOW = datetime(2026, 5, 15, tzinfo=timezone.utc)


def _poller(client: Any, instance_id: int, **kw: Any) -> AutotaskPoller:
    kw.setdefault("now", lambda: _NOW)
    kw.setdefault("proposals_every_sec", 0)
    return AutotaskPoller(client=client, adapter_instance_id=instance_id, **kw)


def test_poller_tick_routes_tickets_to_mapped_tenants(auth_client, auth_data_root):
    _register_client("acme")
    _register_client("globex")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    auth_client.put(
        "/api/v1/integrations/autotask/42/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 100},
            {"tenant_slug": "globex", "autotask_company_id": 200},
        ]},
    )

    client = FakeAutotaskQuery(tickets=[
        {"id": 1, "companyID": 100, "title": "acme #1", "priority": 2,
         "status": 1, "lastActivityDate": "2026-05-14T10:00:00.000Z"},
        {"id": 2, "companyID": 200, "title": "globex #1", "priority": 3,
         "status": 1, "lastActivityDate": "2026-05-14T10:01:00.000Z"},
        {"id": 3, "companyID": 999, "title": "unmapped", "priority": 4,
         "status": 1, "lastActivityDate": "2026-05-14T10:02:00.000Z"},
    ])
    poller = _poller(client, 42)
    poller.tick_once()
    assert poller.last_cycle_tickets_inserted == 2
    assert poller.last_cycle_tickets_skipped == 1
    assert poller.ticket_cursor == "2026-05-14T10:02:00.000Z"

    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir("acme") / "tickets.db")
    try:
        acme_count = conn.execute(
            "SELECT COUNT(*) FROM tickets WHERE autotask_id = '1'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert acme_count == 1


def test_poller_tick_routes_notes_to_parent_tenant(auth_client, auth_data_root):
    _register_client("acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    auth_client.put(
        "/api/v1/integrations/autotask/42/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 100},
        ]},
    )

    client = FakeAutotaskQuery(
        tickets=[
            {"id": 1, "companyID": 100, "title": "acme", "priority": 2,
             "status": 1, "lastActivityDate": "2026-05-14T10:00:00.000Z"},
        ],
        notes=[
            {"id": 555, "ticketID": 1, "description": "first note",
             "lastActivityDate": "2026-05-14T10:30:00.000Z"},
        ],
    )
    poller = _poller(client, 42)
    poller.tick_once()
    assert poller.last_cycle_notes_inserted == 1
    assert poller.note_cursor == "2026-05-14T10:30:00.000Z"


def test_poller_tick_no_mapping_skips_everything(auth_client, auth_data_root):
    client = FakeAutotaskQuery(tickets=[
        {"id": 1, "companyID": 100, "title": "x", "priority": 2,
         "status": 1, "lastActivityDate": "2026-05-14T10:00:00.000Z"},
    ])
    poller = _poller(client, 999)
    poller.tick_once()
    assert poller.last_cycle_tickets_inserted == 0
    assert poller.last_cycle_tickets_skipped == 1


# ---------------------------------------------------------------------------
# Slice 0: persisted cursors, the note-cursor stall, status history via tick
# ---------------------------------------------------------------------------

def _map_companies(auth_client, instance_id: int, pairs: list[tuple[str, int]]) -> None:
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.put(
        f"/api/v1/integrations/autotask/{instance_id}/mappings/companies",
        json={"mappings": [{"tenant_slug": s, "autotask_company_id": c} for s, c in pairs]},
    )
    assert r.status_code == 200, r.text


def test_cursor_survives_restart(auth_client, auth_data_root):
    """The cursors are in the registry (`adapter_poller_state`), not only on
    the poller object: a new poller for the same instance — a process
    restart — resumes after the last row read instead of re-seeding."""
    _register_client("acme")
    _map_companies(auth_client, 42, [("acme", 100)])
    client = FakeAutotaskQuery(
        tickets=[{"id": 1, "companyID": 100, "title": "a", "priority": 2, "status": 1,
                  "lastActivityDate": "2026-05-14T10:00:00.000Z"},
                 {"id": 2, "companyID": 555, "title": "unmapped", "priority": 2, "status": 1,
                  "lastActivityDate": "2026-05-14T10:05:00.000Z"}],
        notes=[{"id": 9, "ticketID": 1, "description": "n",
                "lastActivityDate": "2026-05-14T10:07:00.000Z"}],
    )
    first = _poller(client, 42)
    first.tick_once()
    assert first.ticket_cursor == "2026-05-14T10:05:00.000Z"
    assert first.note_cursor == "2026-05-14T10:07:00.000Z"
    assert poller_state.load(42, TICKET_CURSOR_KEY) == "2026-05-14T10:05:00.000Z"
    assert poller_state.load(42, NOTE_CURSOR_KEY) == "2026-05-14T10:07:00.000Z"

    # "Restart": a brand-new poller, and a config cursor that is older (the
    # persisted one wins — a static config value would rewind every boot).
    client.calls.clear()
    second = _poller(client, 42, initial_ticket_cursor="2026-01-01T00:00:00.000Z")
    assert second.ticket_cursor == "2026-05-14T10:05:00.000Z"
    assert second.note_cursor == "2026-05-14T10:07:00.000Z"
    second.tick_once()
    assert client.windows("Tickets")[0] == ("2026-05-14T10:05:00.000Z", None)
    assert client.windows("TicketNotes")[0] == ("2026-05-14T10:07:00.000Z", None)
    assert second.last_cycle_tickets_inserted == 0 and second.last_cycle_tickets_updated == 0
    # Another instance does not share them.
    assert _poller(FakeAutotaskQuery(), 43).ticket_cursor is None


def test_note_cursor_advances_past_unmapped_parent(auth_client, auth_data_root):
    """A note whose ticket is not mirrored (unmapped company / never seen)
    used to `continue` before the cursor moved: a page of them stalled the
    note cursor for good. Now every note read moves it."""
    _register_client("acme")
    _map_companies(auth_client, 42, [("acme", 100)])
    client = FakeAutotaskQuery(
        tickets=[{"id": 1, "companyID": 100, "title": "a", "priority": 2, "status": 1,
                  "lastActivityDate": "2026-05-14T09:00:00.000Z"}],
        notes=[
            {"id": 501, "ticketID": 1, "description": "routed",
             "lastActivityDate": "2026-05-14T10:00:00.000Z"},
            {"id": 502, "ticketID": 777777, "description": "parent never mirrored",
             "lastActivityDate": "2026-05-14T10:10:00.000Z"},
            {"id": 503, "ticketID": None, "description": "no parent id",
             "lastActivityDate": "2026-05-14T10:20:00.000Z"},
        ],
    )
    poller = _poller(client, 42)
    poller.tick_once()
    assert poller.last_cycle_notes_inserted == 1
    assert poller.last_cycle_notes_orphan == 2
    assert poller.note_cursor == "2026-05-14T10:20:00.000Z"
    assert poller_state.load(42, NOTE_CURSOR_KEY) == "2026-05-14T10:20:00.000Z"
    # Only unmapped notes in the batch: the cursor still moves.
    client.rows["TicketNotes"].append(
        {"id": 504, "ticketID": 888888, "description": "x",
         "lastActivityDate": "2026-05-14T10:30:00.000Z"})
    poller.tick_once()
    assert poller.last_cycle_notes_inserted == 0
    assert poller.note_cursor == "2026-05-14T10:30:00.000Z"


def test_poll_writes_status_history_for_mirrored_changes(auth_client, auth_data_root):
    _register_client("acme")
    _map_companies(auth_client, 42, [("acme", 100)])
    client = FakeAutotaskQuery(tickets=[
        {"id": 5, "companyID": 100, "title": "Escalated one", "priority": 4, "status": 1,
         "lastActivityDate": "2026-05-14T10:00:00.000Z"}])
    poller = _poller(client, 42)
    poller.tick_once()
    client.rows["Tickets"][0].update(status=11, lastActivityDate="2026-05-14T11:00:00.000Z")
    poller.tick_once()
    row = _ticket_row("acme", "5")
    assert row["status"] == "in_progress" and row["severity"] == "critical"
    assert _history("acme", "5") == [
        (None, "new", None, "autotask_sync"),
        ("new", "in_progress", None, "autotask_sync"),
    ]


# ---------------------------------------------------------------------------
# Note backfill: a note read before its ticket landed is not lost
# ---------------------------------------------------------------------------

def _notes_of(slug: str, autotask_ticket_id: str) -> list[tuple]:
    from apps.octo import paths
    conn = sqlite3.connect(paths.client_dir(slug) / "tickets.db")
    try:
        return conn.execute(
            "SELECT n.autotask_id, n.body FROM ticket_notes n JOIN tickets t "
            "  ON t.id = n.ticket_id WHERE t.autotask_id = ? ORDER BY n.id",
            (autotask_ticket_id,),
        ).fetchall()
    finally:
        conn.close()


def _orphaned_note_scenario(auth_client) -> FakeAutotaskQuery:
    """Tick 1 reads the tickets, then ticket 2 is created in Autotask and a
    note added to it before the notes are read: the note is an orphan (its
    parent is not here yet) and the note cursor moves past it."""
    _register_client("acme")
    _map_companies(auth_client, 42, [("acme", 100)])
    return FakeAutotaskQuery(
        tickets=[{"id": 1, "companyID": 100, "title": "a", "priority": 2, "status": 1,
                  "lastActivityDate": "2026-05-14T09:00:00.000Z"}],
        notes=[{"id": 701, "ticketID": 2, "description": "first update",
                "lastActivityDate": "2026-05-14T10:00:00.000Z"},
               {"id": 702, "ticketID": 1, "description": "on ticket 1",
                "lastActivityDate": "2026-05-14T10:01:00.000Z"}],
    )


def _ticket_two_lands(client: FakeAutotaskQuery) -> None:
    client.rows["Tickets"].append(
        {"id": 2, "companyID": 100, "title": "new one", "priority": 2, "status": 1,
         "lastActivityDate": "2026-05-14T09:59:00.000Z"})


def test_note_read_before_its_ticket_landed_is_backfilled(auth_client, auth_data_root):
    client = _orphaned_note_scenario(auth_client)
    poller = _poller(client, 42)
    poller.tick_once()
    assert poller.last_cycle_notes_orphan == 1
    assert poller.note_cursor == "2026-05-14T10:01:00.000Z"      # moved past it
    assert client.lookups == []          # the first notes read needs no backfill

    _ticket_two_lands(client)
    poller.tick_once()
    assert poller.last_cycle_tickets_inserted == 1
    assert client.lookups == [("TicketNotes", "ticketID", [2])]  # its notes, by id
    assert poller.last_cycle_note_backfills == 1
    assert _notes_of("acme", "2") == [("701", "first update")]
    assert _notes_of("acme", "1") == [("702", "on ticket 1")]    # nothing misrouted
    assert poller_state.load(42, "note_backfill") == []

    poller.tick_once()                                           # once only
    assert len(client.lookups) == 1


def test_note_backfill_survives_a_failed_read_and_a_restart(auth_client, auth_data_root):
    from apps.octo.adapters.autotask.client import AutotaskClientError

    client = _orphaned_note_scenario(auth_client)
    _poller(client, 42).tick_once()
    _ticket_two_lands(client)
    client.lookup_errors.append(AutotaskClientError("Autotask timed out"))
    first = _poller(client, 42)
    first.tick_once()                    # the backfill read fails: the tick does not
    assert first.last_cycle_tickets_inserted == 1
    assert first.last_cycle_note_backfills == 0
    assert _notes_of("acme", "2") == []
    # Queued in the registry BEFORE the ticket cursor moved past ticket 2.
    assert poller_state.load(42, "note_backfill") == [["2", "acme"]]
    assert first.ticket_cursor == "2026-05-14T09:59:00.000Z"

    second = _poller(client, 42)         # "restart"
    second.tick_once()
    assert second.last_cycle_note_backfills == 1
    assert _notes_of("acme", "2") == [("701", "first update")]
    assert poller_state.load(42, "note_backfill") == []


# ---------------------------------------------------------------------------
# One-time re-read of the rows the OLD static maps wrote
# ---------------------------------------------------------------------------

def _old_map_rows(auth_client) -> FakeAutotaskQuery:
    """Three mirrored tickets idle for months (outside the 30-day first-run
    lookback), still carrying what the factory maps made of them."""
    from apps.octo import paths

    _register_client("acme")
    _map_companies(auth_client, 42, [("acme", 100)])
    old = [("31", 4, 1, "low", "new"),             # AW03 Critical read as low
           ("32", 2, 11, "high", "resolved"),      # Escalated read as resolved
           ("33", 3, 7, "medium", "new")]          # Waiting Customer read as new
    for at_id, priority, status, _sev, _st in old:
        upsert_ticket("acme", {"id": int(at_id), "title": f"T{at_id}", "priority": priority,
                               "status": status, "companyID": 100})
    conn = sqlite3.connect(paths.client_dir("acme") / "tickets.db")
    try:
        for at_id, _p, _s, sev, st in old:
            conn.execute(
                "UPDATE tickets SET severity = ?, status = ?, "
                "       last_autotask_sync_at = '2026-02-01T00:00:00.000Z' "
                " WHERE autotask_id = ?", (sev, st, at_id))
        conn.execute("INSERT INTO tickets (title, severity, status) "
                     "VALUES ('Athena-only', 'low', 'new')")       # not mirrored
        conn.commit()
    finally:
        conn.close()
    return FakeAutotaskQuery(tickets=[
        {"id": int(at_id), "companyID": 100, "title": f"T{at_id}", "priority": p,
         "status": s, "lastActivityDate": "2026-02-01T00:00:00.000Z"}
        for at_id, p, s, _sev, _st in old])


def test_rows_on_the_old_maps_are_re_read_once(auth_client, auth_data_root):
    client = _old_map_rows(auth_client)
    poller = _poller(client, 42)
    poller.tick_once()
    assert client.windows("Tickets")[0][0] == "2026-04-15T00:00:00.000Z"  # lookback
    assert client.lookups == [("Tickets", "id", [31, 32, 33])]
    assert poller.last_cycle_tickets_refreshed == 3
    assert _ticket_row("acme", "31")["severity"] == "critical"
    assert _ticket_row("acme", "32")["status"] == "in_progress"
    assert _ticket_row("acme", "33")["status"] == "waiting_customer"
    assert _ticket_row("acme", "33")["severity"] == "low"
    assert _history("acme", "32")[-1] == ("resolved", "in_progress", None, "autotask_sync")
    state = poller_state.load(42, "static_maps_refresh")
    assert state["version"] == "aw03-slice0" and state["done"] is True

    poller.tick_once()
    _poller(client, 42).tick_once()                # nor after a restart
    assert len(client.lookups) == 1


def test_old_map_re_read_is_bounded_and_resumes(auth_client, auth_data_root, monkeypatch):
    from apps.octo.adapters.autotask import poller as mod
    from apps.octo.adapters.autotask.client import AutotaskClientError

    client = _old_map_rows(auth_client)
    monkeypatch.setattr(mod, "REFRESH_BATCH", 2)
    monkeypatch.setattr(mod, "MAX_REFRESH_BATCHES_PER_TICK", 1)
    client.lookup_errors.append(AutotaskClientError("Autotask timed out"))
    first = _poller(client, 42)
    first.tick_once()                              # a failed read never fails the poll
    assert first.last_cycle_tickets_caught_up is True
    assert _ticket_row("acme", "31")["severity"] == "low"
    first.tick_once()
    assert [ids for _e, _f, ids in client.lookups] == [[31, 32], [31, 32]]
    assert _ticket_row("acme", "31")["severity"] == "critical"
    assert _ticket_row("acme", "33")["status"] == "new"            # next batch, next tick
    assert poller_state.load(42, "static_maps_refresh")["done"] is False

    _poller(client, 42).tick_once()                # restart: resumes after row 32
    assert [ids for _e, _f, ids in client.lookups][-1] == [33]
    assert _ticket_row("acme", "33")["status"] == "waiting_customer"
    assert poller_state.load(42, "static_maps_refresh")["done"] is True
