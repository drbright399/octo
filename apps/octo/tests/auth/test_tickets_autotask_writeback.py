"""Coverage for the P4-c2 Autotask write-back endpoints.

Hits:
  - create_ticket accepts new push/billing fields + inline charges
  - GET ticket detail surfaces charges + push_state
  - POST /charges adds a line; GET /charges lists; DELETE removes
  - DELETE refuses charges that already have an autotask_charge_id
  - POST /push-to-autotask enqueues outbox row + flips state
  - POST /push-to-autotask refuses if push_to_autotask flag is off
  - retry path: failed → pending on re-POST
  - slice 0: while the PSA writes switch is OFF (the default) both enqueue
    paths answer 409 PSA_WRITES_DISABLED and leave nothing behind (no
    ticket row for the create, no push_state row, no re-queue), and
    GET /tickets/_meta tells the console so

The enqueue-mechanics tests switch writes on first (`_writes_on`).
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.tests.auth.test_search_events import (
    _register_client,
    _login,
)
from apps.octo.tests.auth.test_tickets import (
    _apply_tickets_db_migration,
)


def _autotask_instance(config: dict, *, disabled: bool = False) -> int:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        cur = conn.execute(
            "INSERT INTO adapter_instances (vendor_slug, display_name, cred_ref, "
            "instance_config_json, status, disabled_at) VALUES ('autotask', 'Autotask', "
            "'fixture-cred-ref', ?, ?, ?)",
            (json.dumps(config), "disabled" if disabled else "running",
             "2026-10-05T00:00:00.000Z" if disabled else None),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _writes_on() -> int:
    """The switch a super_admin flips (the audited route is tested in
    test_psa_writes_switch.py); here only its persisted effect matters."""
    return _autotask_instance({"writes_enabled": True})


def _counts(cdir) -> tuple[int, int]:
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        return (conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM autotask_push_state").fetchone()[0])
    finally:
        conn.close()


def test_create_with_push_opts_and_inline_charges(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _writes_on()

    r = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Replaced battery on UPS",
        "description": "swapped APC RBC11 on customer site",
        "severity": "low",
        "push_to_autotask": True,
        "is_billable": True,
        "billing_code_id": "BC-12345",
        "contract_id": "C-987",
        "charges": [
            {
                "name": "APC RBC11 battery",
                "description": "replacement, on-site",
                "unit_cost": 49.0,
                "unit_price": 89.0,
                "quantity": 1.0,
                "is_billable": True,
            },
        ],
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["push_to_autotask"] is True
    assert body["is_billable"] is True
    assert body["billing_code_id"] == "BC-12345"
    assert body["contract_id"] == "C-987"
    assert len(body["charges"]) == 1
    assert body["charges"][0]["name"] == "APC RBC11 battery"
    assert body["charges"][0]["unit_price"] == 89.0
    # No push has been requested yet, so push_state is null.
    assert body["push_state"] is None


def test_charge_add_list_delete_round_trip(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    create = auth_client.post("/api/v1/tickets/acme", json={
        "title": "On-site visit",
    }).json()
    tid = create["id"]

    add = auth_client.post(
        f"/api/v1/tickets/acme/{tid}/charges",
        json={"name": "Travel time", "unit_price": 75.0, "quantity": 0.5},
    )
    assert add.status_code == 201, add.text
    charge = add.json()
    assert charge["name"] == "Travel time"

    lst = auth_client.get(f"/api/v1/tickets/acme/{tid}/charges")
    assert lst.status_code == 200
    assert any(c["id"] == charge["id"] for c in lst.json())

    rm = auth_client.delete(
        f"/api/v1/tickets/acme/{tid}/charges/{charge['id']}",
    )
    assert rm.status_code == 204

    lst2 = auth_client.get(f"/api/v1/tickets/acme/{tid}/charges")
    assert all(c["id"] != charge["id"] for c in lst2.json())


def test_delete_charge_refuses_if_pushed(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Item shipped",
    }).json()["id"]
    add = auth_client.post(
        f"/api/v1/tickets/acme/{tid}/charges",
        json={"name": "USB-C cable", "unit_price": 25.0},
    ).json()

    # Simulate writeback worker stamping the AT-side id.
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute(
            "UPDATE ticket_charges SET autotask_charge_id = 'at-charge-1' "
            "WHERE id = ?", (add["id"],),
        )
        conn.commit()
    finally:
        conn.close()

    rm = auth_client.delete(
        f"/api/v1/tickets/acme/{tid}/charges/{add['id']}",
    )
    assert rm.status_code == 422
    assert "already pushed" in rm.json()["message"].lower()


def test_push_requires_opt_in(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _writes_on()

    tid = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Forgot the flag",
        "push_to_autotask": False,
    }).json()["id"]

    r = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r.status_code == 422
    assert "push_to_autotask=False" in r.json()["message"]


def test_push_enqueues_pending_row(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _writes_on()

    tid = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Push me to AT",
        "push_to_autotask": True,
    }).json()["id"]

    r = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r.status_code == 202, r.text
    state = r.json()
    assert state["state"] == "pending"
    assert state["attempts"] == 0
    assert state["queued_by_operator_id"] == op["id"]

    # Idempotent: re-queuing a pending row is a no-op (state stays pending).
    r2 = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r2.status_code == 202
    assert r2.json()["state"] == "pending"


def test_push_retry_from_failed(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    _writes_on()

    tid = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Retry path",
        "push_to_autotask": True,
    }).json()["id"]
    auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")

    # Simulate the writeback worker marking this row failed.
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute(
            "UPDATE autotask_push_state SET state = 'failed', "
            "attempts = 3, last_error = 'auth refused' "
            "WHERE ticket_id = ?", (tid,),
        )
        conn.commit()
    finally:
        conn.close()

    # Re-POST should reset to pending + clear last_error for retry.
    r = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r.status_code == 202
    assert r.json()["state"] == "pending"
    assert r.json()["last_error"] is None
    # attempts is preserved — the writeback worker bumps it on each
    # actual attempt, not on requeue.
    assert r.json()["attempts"] == 3


def test_push_state_endpoint_returns_null_for_unqueued(auth_client, auth_data_root):
    _register_client("acme")
    _apply_tickets_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Never queued",
    }).json()["id"]

    r = auth_client.get(f"/api/v1/tickets/acme/{tid}/push-state")
    assert r.status_code == 200
    assert r.json() is None


# ---------------------------------------------------------------------------
# Slice 0: the PSA writes switch is OFF by default
# ---------------------------------------------------------------------------

def _super_admin(auth_client, auth_data_root):
    from apps.octo.api.routers.tickets import _ensure_schema

    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    _ensure_schema("acme")                 # the push tables exist up front
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    return cdir, op


@pytest.mark.parametrize("switch", [
    None,                                     # no Autotask instance at all
    {},                                       # the live state: key never set
    {"writes_enabled": False},
    {"writes_enabled": "true"},               # only the JSON true counts
    "disabled-instance-with-writes-on",
])
def test_enqueue_refused_409_when_disabled(auth_client, auth_data_root, switch):
    cdir, op = _super_admin(auth_client, auth_data_root)
    if switch == "disabled-instance-with-writes-on":
        _autotask_instance({"writes_enabled": True}, disabled=True)
    elif switch is not None:
        _autotask_instance(switch)

    # 1. Create WITH push_to_autotask: refused whole — not even the ticket.
    r = auth_client.post("/api/v1/tickets/acme", json={
        "title": "Push me", "severity": "low", "push_to_autotask": True,
        "charges": [{"name": "Part", "unit_price": 5.0}],
    })
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "PSA_WRITES_DISABLED"
    assert _counts(cdir) == (0, 0)

    # 2. A ticket that carries the flag (an older row) cannot be enqueued.
    tid = auth_client.post("/api/v1/tickets/acme", json={"title": "Local only"}).json()["id"]
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute("UPDATE tickets SET push_to_autotask = 1 WHERE id = ?", (tid,))
        conn.commit()
    finally:
        conn.close()
    r = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r.status_code == 409
    assert r.json()["code"] == "PSA_WRITES_DISABLED"
    assert _counts(cdir) == (1, 0)

    # 3. A failed row is not re-queued either.
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute("INSERT INTO autotask_push_state (ticket_id, state, attempts, "
                     "queued_by_operator_id) VALUES (?, 'failed', 2, ?)", (tid, op["id"]))
        conn.commit()
    finally:
        conn.close()
    r = auth_client.post(f"/api/v1/tickets/acme/{tid}/push-to-autotask")
    assert r.status_code == 409
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        assert conn.execute("SELECT state FROM autotask_push_state WHERE ticket_id = ?",
                            (tid,)).fetchone()[0] == "failed"
    finally:
        conn.close()

    # 4. Athena-only tickets are unaffected.
    assert auth_client.post("/api/v1/tickets/acme", json={
        "title": "Still fine", "push_to_autotask": False}).status_code == 201

    # 5. The console is told.
    assert auth_client.get("/api/v1/tickets/_meta").json() == {"psa_writes_enabled": False}


def test_enqueue_allowed_once_the_switch_is_on(auth_client, auth_data_root):
    cdir, _op = _super_admin(auth_client, auth_data_root)
    _writes_on()
    assert auth_client.get("/api/v1/tickets/_meta").json() == {"psa_writes_enabled": True}
    r = auth_client.post("/api/v1/tickets/acme", json={"title": "Go", "push_to_autotask": True})
    assert r.status_code == 201, r.text
    r = auth_client.post(f"/api/v1/tickets/acme/{r.json()['id']}/push-to-autotask")
    assert r.status_code == 202
    assert _counts(cdir) == (1, 1)


def test_tickets_meta_gates(auth_client, auth_data_root):
    _register_client("acme")
    assert auth_client.get("/api/v1/tickets/_meta").status_code == 401
    viewer = auth_client.provision_operator("vic-viewer", "pw1234567890",
                                            role="viewer", athena_role="viewer")
    _login(auth_client, viewer)
    assert auth_client.get("/api/v1/tickets/_meta").status_code == 403
    analyst = auth_client.provision_operator("ann-analyst", "pw1234567890",
                                             role="analyst", athena_role="analyst")
    _login(auth_client, analyst)
    r = auth_client.get("/api/v1/tickets/_meta")
    assert r.status_code == 200 and r.json() == {"psa_writes_enabled": False}
