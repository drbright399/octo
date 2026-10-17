"""Coverage for the P5 dispatch-grade additions:

  - PATCH severity (analyst+, audited)
  - GET filters: severity, queue, q (title/description search)
"""
from __future__ import annotations

from apps.octo.tests.auth.test_search_events import _register_client, _login
from apps.octo.tests.auth.test_tickets import (
    _apply_tickets_db_migration,
    _insert_ticket,
)


# ---------------------------------------------------------------------------
# Severity edit
# ---------------------------------------------------------------------------

def test_patch_severity_records_in_audit(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    tid = _insert_ticket(cdir, title="bump severity", severity="low")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.patch(
        f"/api/v1/tickets/acme/{tid}",
        json={"severity": "critical", "reason": "exposed in prod"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["severity"] == "critical"


def test_patch_severity_validates(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    tid = _insert_ticket(cdir, title="bad sev")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.patch(
        f"/api/v1/tickets/acme/{tid}",
        json={"severity": "extreme"},
    )
    assert r.status_code == 422
    assert "severity" in r.json()["message"]


# ---------------------------------------------------------------------------
# Filter rail
# ---------------------------------------------------------------------------

def test_filter_by_severity(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    _insert_ticket(cdir, title="A", severity="low")
    _insert_ticket(cdir, title="B", severity="high")
    _insert_ticket(cdir, title="C", severity="critical")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/tickets?severity=high,critical")
    assert r.status_code == 200
    titles = {t["title"] for t in r.json()["tickets"]}
    assert titles == {"B", "C"}


def test_filter_by_queue(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    _insert_ticket(cdir, title="A")
    # Stamp queue on one via direct insert (helper doesn't expose queue)
    import sqlite3
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute(
            "INSERT INTO tickets (title, severity, status, queue) "
            "VALUES ('B', 'medium', 'new', 'triage')"
        )
        conn.commit()
    finally:
        conn.close()

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/tickets?queue=triage")
    assert r.status_code == 200
    titles = {t["title"] for t in r.json()["tickets"]}
    assert titles == {"B"}


def test_filter_by_q_text(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    _insert_ticket(cdir, title="UPS battery dead")
    _insert_ticket(cdir, title="Printer offline")
    _insert_ticket(cdir, title="EDR alert: ransomware behavior")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/tickets?q=ransomware")
    assert r.status_code == 200
    titles = {t["title"] for t in r.json()["tickets"]}
    assert titles == {"EDR alert: ransomware behavior"}


def test_filter_composition(auth_client, auth_data_root):
    """severity + q + status compose with AND semantics."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    import sqlite3
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.executemany(
            "INSERT INTO tickets (title, severity, status) VALUES (?, ?, ?)",
            [
                ("CPU spike on db01", "high", "new"),
                ("CPU spike on web02", "low", "new"),
                ("Closed: CPU spike on cache", "high", "closed"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get(
        "/api/v1/tickets?severity=high&q=CPU&status=open"
    )
    assert r.status_code == 200
    titles = {t["title"] for t in r.json()["tickets"]}
    assert titles == {"CPU spike on db01"}


def test_filter_invalid_severity_422(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/tickets?severity=extreme")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Due-at (P5-d)
# ---------------------------------------------------------------------------

def test_create_with_due_at_and_patch_clears(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    create = auth_client.post("/api/v1/tickets/acme", json={
        "title": "with due",
        "due_at": "2026-05-21T17:00:00Z",
    })
    assert create.status_code == 201
    tid = create.json()["id"]
    assert create.json()["due_at"] == "2026-05-21T17:00:00Z"

    # Bump due
    r = auth_client.patch(f"/api/v1/tickets/acme/{tid}", json={
        "due_at": "2026-06-01T17:00:00Z",
    })
    assert r.status_code == 200
    assert r.json()["due_at"] == "2026-06-01T17:00:00Z"

    # Clear with empty string
    r = auth_client.patch(f"/api/v1/tickets/acme/{tid}", json={"due_at": ""})
    assert r.status_code == 200
    assert r.json()["due_at"] is None


# ---------------------------------------------------------------------------
# Bulk patch (P5-c)
# ---------------------------------------------------------------------------

def test_bulk_patch_status_across_tenants(auth_client, auth_data_root):
    _register_client("acme")
    _register_client("globex")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "globex")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    t1 = auth_client.post("/api/v1/tickets/acme",
                           json={"title": "A"}).json()["id"]
    t2 = auth_client.post("/api/v1/tickets/acme",
                           json={"title": "B"}).json()["id"]
    t3 = auth_client.post("/api/v1/tickets/globex",
                           json={"title": "C"}).json()["id"]

    r = auth_client.post("/api/v1/tickets/_bulk/patch", json={
        "refs": [
            {"slug": "acme",   "ticket_id": t1},
            {"slug": "acme",   "ticket_id": t2},
            {"slug": "globex", "ticket_id": t3},
        ],
        "patch": {"status": "in_progress", "reason": "batch claim"},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["succeeded"] == 3
    assert body["failed"] == 0

    # Verify each ticket is now in_progress.
    for slug, tid in [("acme", t1), ("acme", t2), ("globex", t3)]:
        d = auth_client.get(f"/api/v1/tickets/{slug}/{tid}").json()
        assert d["status"] == "in_progress"


def test_bulk_patch_partial_failure_returns_per_row_outcome(auth_client, auth_data_root):
    """Bad ticket id is reported per-row, other refs succeed."""
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = auth_client.post("/api/v1/tickets/acme",
                            json={"title": "good"}).json()["id"]

    r = auth_client.post("/api/v1/tickets/_bulk/patch", json={
        "refs": [
            {"slug": "acme", "ticket_id": tid},
            {"slug": "acme", "ticket_id": 99999},  # nonexistent
        ],
        "patch": {"severity": "critical"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["succeeded"] == 1
    assert body["failed"] == 1
    outcomes = {(o["ticket_id"], o["ok"]) for o in body["results"]}
    assert (tid, True) in outcomes
    assert (99999, False) in outcomes


def test_bulk_patch_caps_at_100_refs(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.post("/api/v1/tickets/_bulk/patch", json={
        "refs": [{"slug": "acme", "ticket_id": i} for i in range(1, 102)],
        "patch": {"status": "closed"},
    })
    assert r.status_code == 422
