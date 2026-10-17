"""Coverage for AutotaskPusher (P4-c2-δ).

Exercises tick_once() against a stub client:
  - pending row → create_ticket called → tickets.autotask_id stamped
  - charge rows → create_ticket_charge called per row → autotask_charge_id stamped
  - 401 → state advances to 'failed' with last_error populated
  - state already 'pushed' → no second push (idempotent)
  - autotask_push_log captures both success + error attempts
  - slice 0: the pusher re-reads the PSA writes switch before EVERY send
    (default: the persisted instance switch, failing closed) — switched
    off, nothing is sent and the queued row is left untouched

The mechanics tests pass `writes_enabled=_ON` (the switch is not what they
test); the switch tests use the real registry read.
"""
from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from apps.octo import paths
from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClientError,
)
from apps.octo.adapters.autotask.writeback import AutotaskPusher
from apps.octo.tests.auth.test_search_events import _register_client, _login
from apps.octo.tests.auth.test_tickets import _apply_tickets_db_migration


# ---------------------------------------------------------------------------
# Stub client + helpers
# ---------------------------------------------------------------------------

def _ON() -> bool:  # noqa: N802 — the switch, held on for the mechanics tests
    return True


class _StubClient:
    """Records calls + returns scripted responses. Lets us drive
    tick_once() without an HTTP boundary."""
    def __init__(self) -> None:
        self.ticket_calls: list[dict[str, Any]] = []
        self.charge_calls: list[dict[str, Any]] = []
        self.next_ticket_raise: Exception | None = None
        self.next_charge_raise: Exception | None = None
        self._ticket_id_seq = 5000
        self._charge_id_seq = 6000

    def create_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.ticket_calls.append(payload)
        if self.next_ticket_raise is not None:
            raise self.next_ticket_raise
        self._ticket_id_seq += 1
        return {"itemId": self._ticket_id_seq}

    def create_ticket_charge(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.charge_calls.append(payload)
        if self.next_charge_raise is not None:
            raise self.next_charge_raise
        self._charge_id_seq += 1
        return {"itemId": self._charge_id_seq}


def _map_tenant_to_company(
    adapter_instance_id: int, tenant_slug: str, autotask_company_id: int,
) -> None:
    """Insert a tenant↔company row so load_tenant_routing returns it."""
    reg = paths.registry_db_path()
    conn = sqlite3.connect(reg)
    try:
        conn.execute(
            "INSERT INTO autotask_tenant_company_map "
            "(adapter_instance_id, tenant_slug, autotask_company_id, "
            " autotask_company_name, autotask_homepage_url) "
            "VALUES (?, ?, ?, NULL, NULL)",
            (adapter_instance_id, tenant_slug, autotask_company_id),
        )
        conn.commit()
    finally:
        conn.close()


def _enqueue_push(tenant_dir, ticket_id: int, operator_id: int) -> None:
    conn = sqlite3.connect(tenant_dir / "tickets.db")
    try:
        conn.execute(
            "UPDATE tickets SET push_to_autotask = 1 WHERE id = ?",
            (ticket_id,),
        )
        conn.execute(
            "INSERT INTO autotask_push_state (ticket_id, state, "
            "queued_by_operator_id) VALUES (?, 'pending', ?)",
            (ticket_id, operator_id),
        )
        conn.commit()
    finally:
        conn.close()


def _add_charge(tenant_dir, ticket_id: int, name: str, price: float) -> int:
    conn = sqlite3.connect(tenant_dir / "tickets.db")
    try:
        cur = conn.execute(
            "INSERT INTO ticket_charges "
            "(ticket_id, name, unit_price, quantity, is_billable) "
            "VALUES (?, ?, ?, 1, 1)",
            (ticket_id, name, price),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _make_ticket(auth_client, slug: str, title: str) -> int:
    return auth_client.post(
        f"/api/v1/tickets/{slug}",
        json={"title": title, "push_to_autotask": False},
    ).json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_happy_path_creates_ticket_and_charges(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = _make_ticket(auth_client, "acme", "Replace UPS battery")
    _add_charge(cdir, tid, "APC RBC11", 89.0)
    _add_charge(cdir, tid, "Travel time", 75.0)
    _enqueue_push(cdir, tid, op["id"])
    _map_tenant_to_company(adapter_instance_id=1, tenant_slug="acme",
                            autotask_company_id=42)

    stub = _StubClient()
    stub.next_ticket_response = {"itemId": 5001}
    stub.next_charge_response = {"itemId": 6001}
    pusher = AutotaskPusher(client=stub, adapter_instance_id=1, writes_enabled=_ON)
    pusher.tick_once()

    assert pusher.last_cycle_pushed == 1
    assert pusher.last_cycle_charges_pushed == 2
    assert len(stub.ticket_calls) == 1
    assert stub.ticket_calls[0]["companyID"] == 42
    assert stub.ticket_calls[0]["title"] == "Replace UPS battery"
    assert len(stub.charge_calls) == 2

    # Athena-side stamps.
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        row = conn.execute(
            "SELECT autotask_id, last_autotask_sync_at FROM tickets "
            "WHERE id = ?", (tid,),
        ).fetchone()
        assert row[0] == "5001"
        assert row[1] is not None

        st = conn.execute(
            "SELECT state, attempts, autotask_ticket_id, last_error "
            "FROM autotask_push_state WHERE ticket_id = ?", (tid,),
        ).fetchone()
        assert st[0] == "pushed"
        assert st[1] == 1
        assert st[2] == "5001"
        assert st[3] is None

        # Every charge stamped with its AT-side id.
        for r in conn.execute(
            "SELECT autotask_charge_id FROM ticket_charges WHERE ticket_id = ?",
            (tid,),
        ).fetchall():
            assert r[0] is not None

        # push_log has 1 success row for ticket + 2 for charges.
        logs = conn.execute(
            "SELECT action, outcome FROM autotask_push_log WHERE ticket_id = ?",
            (tid,),
        ).fetchall()
        assert ("create_ticket", "success") in logs
        assert logs.count(("create_charge", "success")) == 2
    finally:
        conn.close()


def test_auth_error_marks_failed(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = _make_ticket(auth_client, "acme", "Will fail")
    _enqueue_push(cdir, tid, op["id"])
    _map_tenant_to_company(adapter_instance_id=2, tenant_slug="acme",
                            autotask_company_id=99)

    stub = _StubClient()
    stub.next_ticket_raise = AutotaskAuthError("creds rejected")
    pusher = AutotaskPusher(client=stub, adapter_instance_id=2, writes_enabled=_ON)
    pusher.tick_once()

    assert pusher.last_cycle_pushed == 0
    assert pusher.last_cycle_failed == 1

    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        st = conn.execute(
            "SELECT state, attempts, last_error FROM autotask_push_state "
            "WHERE ticket_id = ?", (tid,),
        ).fetchone()
        assert st[0] == "failed"
        assert st[1] == 1
        assert "creds rejected" in st[2]

        # error logged
        logs = conn.execute(
            "SELECT outcome, error_code FROM autotask_push_log "
            "WHERE ticket_id = ?", (tid,),
        ).fetchall()
        assert ("error", "AutotaskAuthError") in logs
    finally:
        conn.close()


def test_already_pushed_is_skipped(auth_client, auth_data_root):
    """tick_once should ignore rows already in 'pushed' state."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = _make_ticket(auth_client, "acme", "Already pushed")
    _enqueue_push(cdir, tid, op["id"])
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute(
            "UPDATE autotask_push_state SET state = 'pushed', "
            "autotask_ticket_id = '9999' WHERE ticket_id = ?",
            (tid,),
        )
        conn.commit()
    finally:
        conn.close()
    _map_tenant_to_company(adapter_instance_id=3, tenant_slug="acme",
                            autotask_company_id=42)

    stub = _StubClient()
    AutotaskPusher(client=stub, adapter_instance_id=3, writes_enabled=_ON).tick_once()

    assert len(stub.ticket_calls) == 0


def test_no_routing_means_no_push(auth_client, auth_data_root):
    """When the tenant has no autotask_tenant_company_map row, nothing
    is pushed even if push_state.state='pending'."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    tid = _make_ticket(auth_client, "acme", "Unrouted")
    _enqueue_push(cdir, tid, op["id"])
    # NO _map_tenant_to_company call — adapter_instance_id=4 has no rows.

    stub = _StubClient()
    AutotaskPusher(client=stub, adapter_instance_id=4, writes_enabled=_ON).tick_once()

    assert len(stub.ticket_calls) == 0


# ---------------------------------------------------------------------------
# Slice 0: the writes switch, re-read before every send
# ---------------------------------------------------------------------------

def _autotask_instance(writes: object = None) -> int:
    """A persisted Autotask instance row (no credentials needed: the pusher
    under test gets a stub client)."""
    import json

    cfg = {} if writes is None else {"writes_enabled": writes}
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        cur = conn.execute(
            "INSERT INTO adapter_instances (vendor_slug, display_name, cred_ref, "
            "instance_config_json, status) VALUES ('autotask', 'Autotask', "
            "'fixture-cred-ref', ?, 'running')",
            (json.dumps(cfg),),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _set_switch(instance_id: int, on: bool) -> None:
    from apps.octo.instances.manager import update_instance_config

    update_instance_config(instance_id, {"writes_enabled": on})


def _push_state(cdir, tid: int) -> tuple:
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        state = conn.execute(
            "SELECT state, attempts FROM autotask_push_state WHERE ticket_id = ?", (tid,),
        ).fetchone()
        logs = conn.execute(
            "SELECT COUNT(*) FROM autotask_push_log WHERE ticket_id = ?", (tid,),
        ).fetchone()[0]
        return tuple(state), logs
    finally:
        conn.close()


def _seed_pending(auth_client, auth_data_root, instance_id: int, titles: list[str]):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    tids = []
    for title in titles:
        tid = _make_ticket(auth_client, "acme", title)
        _add_charge(cdir, tid, "Part", 10.0)
        _enqueue_push(cdir, tid, op["id"])
        tids.append(tid)
    _map_tenant_to_company(adapter_instance_id=instance_id, tenant_slug="acme",
                           autotask_company_id=9001)
    return cdir, tids


@pytest.mark.parametrize("writes", [None, False, "true", 1])
def test_pusher_sends_nothing_while_the_persisted_switch_is_off(
        auth_client, auth_data_root, writes):
    iid = _autotask_instance(writes)
    cdir, (tid,) = _seed_pending(auth_client, auth_data_root, iid, ["Queued earlier"])
    stub = _StubClient()
    pusher = AutotaskPusher(client=stub, adapter_instance_id=iid)   # the real switch read
    pusher.tick_once()
    assert pusher.last_cycle_refused is True
    assert stub.ticket_calls == [] and stub.charge_calls == []
    assert _push_state(cdir, tid) == (("pending", 0), 0)          # untouched, no log row

    # Switched on (by the audited route in production): the same row goes.
    _set_switch(iid, True)
    pusher.tick_once()
    assert len(stub.ticket_calls) == 1
    assert _push_state(cdir, tid)[0] == ("pushed", 1)


def test_pusher_for_an_unknown_instance_sends_nothing(auth_client, auth_data_root):
    cdir, (tid,) = _seed_pending(auth_client, auth_data_root, 77, ["No such instance"])
    stub = _StubClient()
    AutotaskPusher(client=stub, adapter_instance_id=77).tick_once()
    AutotaskPusher(client=stub, adapter_instance_id=0).tick_once()
    assert stub.ticket_calls == []
    assert _push_state(cdir, tid) == (("pending", 0), 0)


def test_pusher_stops_mid_cycle_when_the_switch_goes_off(auth_client, auth_data_root):
    """Re-checked before EVERY send: switched off after the first POST, the
    first ticket's charges and the second ticket are not sent."""
    cdir, (first, second) = _seed_pending(auth_client, auth_data_root, 5, ["One", "Two"])
    switch = {"on": True}

    class _FlipsOff(_StubClient):
        def create_ticket(self, payload):
            out = super().create_ticket(payload)
            switch["on"] = False
            return out

    stub = _FlipsOff()
    pusher = AutotaskPusher(client=stub, adapter_instance_id=5,
                            writes_enabled=lambda: switch["on"])
    pusher.tick_once()
    assert len(stub.ticket_calls) == 1 and stub.charge_calls == []
    assert pusher.last_cycle_refused is True
    assert _push_state(cdir, second) == (("pending", 0), 0)


def test_pusher_switch_read_error_fails_closed(auth_client, auth_data_root):
    cdir, (tid,) = _seed_pending(auth_client, auth_data_root, 6, ["Boom"])

    def broken() -> bool:
        raise RuntimeError("registry hiccup")

    stub = _StubClient()
    AutotaskPusher(client=stub, adapter_instance_id=6, writes_enabled=broken).tick_once()
    assert stub.ticket_calls == []
    assert _push_state(cdir, tid) == (("pending", 0), 0)


# ---------------------------------------------------------------------------
# Fixer round: one claim per row, and a closed ticket is never created
# ---------------------------------------------------------------------------

def test_two_pushers_on_one_pending_row_post_it_once(auth_client, auth_data_root,
                                                     monkeypatch):
    """Two pushers (a double-submitted switch-on once built two) selecting the
    same pending row: only the one whose pending→in_flight UPDATE moved the
    row may send it. The other skips it — never a second Autotask ticket."""
    from apps.octo.adapters.autotask import writeback as wb

    cdir, (tid,) = _seed_pending(auth_client, auth_data_root, 8, ["Only once"])
    stub_a, stub_b = _StubClient(), _StubClient()
    pusher_a = AutotaskPusher(client=stub_a, adapter_instance_id=8, writes_enabled=_ON)
    pusher_b = AutotaskPusher(client=stub_b, adapter_instance_id=8, writes_enabled=_ON)

    # Both have selected the row; A claims and sends first, then B runs on
    # the row it selected before A's claim.
    selected = wb._select_pending("acme", max_batch=25)
    assert [r["ticket_id"] for r in selected] == [tid]
    pusher_a.tick_once()
    monkeypatch.setattr(wb, "_select_pending",
                        lambda _slug, max_batch=25: selected)   # B's stale selection
    pusher_b.tick_once()

    assert len(stub_a.ticket_calls) == 1
    assert stub_b.ticket_calls == [] and stub_b.charge_calls == []
    assert pusher_b.last_cycle_pushed == 0 and pusher_b.last_cycle_failed == 0
    state, logs = _push_state(cdir, tid)
    assert state == ("pushed", 1)                       # one claim, one attempt
    assert logs == 2                                    # A's ticket + charge rows


def test_mark_in_flight_claims_a_row_once(auth_client, auth_data_root):
    from apps.octo.adapters.autotask.writeback import _mark_in_flight

    _cdir, (tid,) = _seed_pending(auth_client, auth_data_root, 9, ["Claim me"])
    assert _mark_in_flight("acme", tid) is True
    assert _mark_in_flight("acme", tid) is False        # already in flight


def _set_status(cdir, tid: int, status: str) -> None:
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        conn.execute("UPDATE tickets SET status = ? WHERE id = ?", (status, tid))
        conn.commit()
    finally:
        conn.close()


def test_a_ticket_closed_in_athena_is_not_created_in_autotask(auth_client, auth_data_root):
    """Queued, then closed in Athena before the pusher got to it (or the switch
    was flipped on long after): no POST at all — not a New ticket in the
    dispatch queue for finished work. The row fails with the reason; the
    reopened one beside it goes out as New."""
    cdir, (closed, reopened) = _seed_pending(
        auth_client, auth_data_root, 10, ["Finished already", "Back again"])
    _set_status(cdir, closed, "closed")
    _set_status(cdir, reopened, "reopened")
    stub = _StubClient()
    pusher = AutotaskPusher(client=stub, adapter_instance_id=10, writes_enabled=_ON)
    pusher.tick_once()

    assert [c["title"] for c in stub.ticket_calls] == ["Back again"]
    assert stub.ticket_calls[0]["status"] == 1
    assert len(stub.charge_calls) == 1                  # only the reopened one's
    assert pusher.last_cycle_failed == 1 and pusher.last_cycle_pushed == 1
    conn = sqlite3.connect(cdir / "tickets.db")
    try:
        st = conn.execute(
            "SELECT state, last_error FROM autotask_push_state WHERE ticket_id = ?",
            (closed,)).fetchone()
        log = conn.execute(
            "SELECT action, outcome, error_code FROM autotask_push_log WHERE ticket_id = ?",
            (closed,)).fetchall()
        at_id = conn.execute("SELECT autotask_id FROM tickets WHERE id = ?",
                             (closed,)).fetchone()[0]
    finally:
        conn.close()
    assert st[0] == "failed" and "closed" in st[1]
    assert log == [("create_ticket", "error", "NOT_SENDABLE")]
    assert at_id is None
