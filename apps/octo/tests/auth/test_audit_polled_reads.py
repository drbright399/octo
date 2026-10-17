"""Audit policy (docs/audit-policy.md) on the real app + real audit chain.

  - polled reads (tickets.list, agent.activity.fetch, the System page's
    storage-stats + retention) no longer write a row per call: one `open` row
    per (operator, session, action, UTC hour), then one `close` row with the
    count once the hour is over — written by whoever polls next, or flushed
    (partial) when the app stops;
  - on-demand sensitive reads stay one row per call (ticket detail, step-up
    search, held quarantine payload, raw sanitization rejects), and so do
    writes;
  - the chain verifies throughout — roll-up rows are ordinary appends.

Time is moved with the roll-up's clock; nothing else is faked.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.octo import paths
from apps.octo.auth import audit
from apps.octo.auth.audit_rollup import MAX_SHAPES, OTHER_SHAPES, PolledReadAudit
from apps.octo.db import connect
from apps.octo.instances import quarantine
from apps.octo.tests.auth.test_agent_activity import _insert_agent_note
from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _elevate,
    _login,
    _register_client,
    _seed_minimal,
)
from apps.octo.tests.auth.test_tickets import _apply_tickets_db_migration, _insert_ticket

PW = "pw1234567890"
T0 = datetime(2026, 9, 28, 14, 59, 50, tzinfo=timezone.utc)


class _Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


def _rows(action: str) -> list[dict]:
    conn = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return [
            {**dict(r), "after": json.loads(r["after_state"]) if r["after_state"] else None}
            for r in conn.execute(
                "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,),
            )
        ]
    finally:
        conn.close()


def _chain() -> tuple[bool, int, str | None]:
    conn = connect(paths.global_audit_db_path())
    try:
        return audit.verify(conn)
    finally:
        conn.close()


def _op(client, name: str, role: str, **kw) -> dict:
    """An operator whose ONLY roles are `role` (the fixture's legacy API
    role would otherwise add an admin row)."""
    return client.provision_operator(name, PW, role=role, athena_role=role, **kw)


def _clock(client) -> _Clock:
    clock = _Clock(T0)
    PolledReadAudit.for_app(client.app).clock = clock
    return clock


def _tickets(auth_data_root: Path) -> int:
    _register_client("acme-corp")
    cdir = auth_data_root / "clients" / "acme-corp"
    _apply_tickets_db_migration(cdir)
    _insert_ticket(cdir, title="disk alert", severity="critical")
    return _insert_ticket(cdir, title="patch window", severity="high")


def _dashboard_poll(client) -> None:
    """The dashboard's four ticket requests (three counters + the feed)."""
    for params in ("status=open&page_size=1",
                   "status=open&severity=critical&page_size=1",
                   "status=open&severity=high&page_size=1",
                   "status=open&page_size=20"):
        r = client.get(f"/api/v1/tickets?{params}")
        assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Polled reads roll up
# ---------------------------------------------------------------------------

def test_dashboard_ticket_polling_writes_one_open_row_not_one_per_call(auth_client, auth_data_root):
    _tickets(auth_data_root)
    _clock(auth_client)
    _login(auth_client, _op(auth_client, "alice", "super_admin"))

    for _ in range(5):
        _dashboard_poll(auth_client)

    rows = _rows("tickets.list")
    assert len(rows) == 1, [r["after"] for r in rows]
    (opened,) = rows
    assert opened["after"]["rollup"] == "open"
    assert opened["after"]["window_start"] == "2026-09-28T14:00:00Z"
    assert opened["after"]["window_end"] == "2026-09-28T15:00:00Z"
    assert opened["after"]["tenant_count"] == 1 and opened["after"]["returned"] == 1
    assert len(opened["after"]["session_id_prefix"]) == 8
    assert opened["actor"].startswith("operator:") and opened["client_slug"] == "global"
    assert _chain() == (True, _chain()[1], None)


def test_window_closes_with_the_count_across_the_hour_boundary(auth_client, auth_data_root):
    _tickets(auth_data_root)
    clock = _clock(auth_client)
    _login(auth_client, _op(auth_client, "alice", "super_admin"))

    _dashboard_poll(auth_client)                       # 4 calls at 14:59:50
    auth_client.get("/api/v1/tickets?status=open&q=disk&offset=20&page_size=20")
    clock.at = T0 + timedelta(seconds=15)              # 15:00:05 — next hour
    auth_client.get("/api/v1/tickets?status=open&page_size=1")

    opened, closed, reopened = _rows("tickets.list")
    assert opened["after"]["rollup"] == "open"
    assert closed["after"]["rollup"] == "close" and closed["after"]["partial"] is False
    assert closed["after"]["window_start"] == "2026-09-28T14:00:00Z"
    assert closed["after"]["calls"] == 5
    # 1+1+1+2 rows from the poll, 0 from the paged free-text call.
    assert closed["after"]["rows_returned"] == 5
    assert closed["after"]["first_call_at"] == "2026-09-28T14:59:50.000Z"
    assert closed["after"]["last_call_at"] == "2026-09-28T14:59:50.000Z"
    assert closed["after"]["open_row_id"] == opened["id"]
    assert closed["after"]["open_request_id"] == opened["request_id"]
    assert closed["after"]["session_id_prefix"] == opened["after"]["session_id_prefix"]
    # Shapes name the filters; typed free text only ever as "*".
    assert closed["after"]["shapes"] == {
        "status=open page_size=1": 1,
        "status=open page_size=20": 1,
        "status=open q=* page_size=20 offset=paged": 1,
        "status=open severity=critical page_size=1": 1,
        "status=open severity=high page_size=1": 1,
    }
    assert "disk" not in closed["after_state"]
    assert reopened["after"]["rollup"] == "open"
    assert reopened["after"]["window_start"] == "2026-09-28T15:00:00Z"
    assert closed["id"] < reopened["id"]
    ok, count, err = _chain()
    assert ok and err is None and count >= 3


def test_sessions_are_separate_windows_and_any_poll_closes_an_ended_one(auth_client, auth_data_root):
    """Two sessions → two windows. When the hour turns, the FIRST poll from
    anyone closes every ended window (oldest first) before opening its own."""
    _tickets(auth_data_root)
    clock = _clock(auth_client)
    alice = _op(auth_client, "alice", "super_admin")
    bob = _op(auth_client, "bob", "admin")
    _login(auth_client, alice)
    other = TestClient(auth_client.app, base_url="https://athena.test")
    _login(other, bob)

    auth_client.get("/api/v1/tickets?page_size=1")
    other.get("/api/v1/tickets?page_size=1")
    other.get("/api/v1/tickets?page_size=1")
    assert [r["after"]["rollup"] for r in _rows("tickets.list")] == ["open", "open"]

    clock.at = T0 + timedelta(minutes=5)
    other.get("/api/v1/tickets?page_size=1")           # only bob polls on

    rows = _rows("tickets.list")
    assert [(r["actor"], r["after"]["rollup"]) for r in rows] == [
        (f"operator:{alice['id']}", "open"), (f"operator:{bob['id']}", "open"),
        (f"operator:{alice['id']}", "close"), (f"operator:{bob['id']}", "close"),
        (f"operator:{bob['id']}", "open"),
    ]
    assert rows[2]["after"]["calls"] == 1 and rows[3]["after"]["calls"] == 2
    assert rows[0]["after"]["session_id_prefix"] != rows[1]["after"]["session_id_prefix"]
    assert _chain()[0]


def test_agent_activity_and_system_page_polls_roll_up(auth_client, auth_data_root):
    _register_client("acme-corp")
    cdir = auth_data_root / "clients" / "acme-corp"
    _apply_events_db_migration(cdir)
    _insert_agent_note(cdir, ref_kind="event", ref_id=1)
    _clock(auth_client)
    _login(auth_client, _op(auth_client, "alice", "super_admin"))

    for _ in range(4):
        assert auth_client.get("/api/v1/agent/activity?limit=10").status_code == 200
        assert auth_client.get("/api/v1/admin/data/storage-stats").status_code == 200
        assert auth_client.get("/api/v1/admin/data/retention").status_code == 200

    for action in ("agent.activity.fetch", "admin_data.storage_stats_fetch",
                   "admin_data.retention_fetch"):
        rows = _rows(action)
        assert [r["after"]["rollup"] for r in rows] == ["open"], action
    assert _rows("agent.activity.fetch")[0]["after"]["returned"] == 1
    assert _rows("admin_data.storage_stats_fetch")[0]["after"]["tenant_count"] == 1

    assert PolledReadAudit.for_app(auth_client.app).flush() == 3
    for action in ("agent.activity.fetch", "admin_data.storage_stats_fetch",
                   "admin_data.retention_fetch"):
        closed = _rows(action)[-1]["after"]
        assert (closed["rollup"], closed["calls"], closed["partial"]) == ("close", 4, True)
    assert _rows("agent.activity.fetch")[-1]["after"]["shapes"] == {"limit=10 ref_kind=*": 4}
    assert _chain()[0]


def test_app_shutdown_flushes_the_open_windows(auth_client, auth_data_root):
    """create_app registers the flush on shutdown; after it, nothing is left
    open and a second flush writes nothing."""
    _tickets(auth_data_root)
    _clock(auth_client)
    _login(auth_client, _op(auth_client, "alice", "super_admin"))
    auth_client.get("/api/v1/tickets?page_size=1")

    hooks = [h.__name__ for h in auth_client.app.router.on_shutdown]
    assert "_flush_polled_read_audit" in hooks
    flush = next(h for h in auth_client.app.router.on_shutdown
                 if h.__name__ == "_flush_polled_read_audit")
    import asyncio
    asyncio.run(flush())

    rows = _rows("tickets.list")
    assert [r["after"]["rollup"] for r in rows] == ["open", "close"]
    assert rows[1]["after"]["partial"] is True
    assert "app stopping" in rows[1]["reason"]
    assert PolledReadAudit.for_app(auth_client.app).flush() == 0


def test_denied_polls_write_nothing(auth_client, auth_data_root):
    """A viewer is refused tickets + agent activity before anything is
    recorded; an unauthenticated caller never reaches the route."""
    _tickets(auth_data_root)
    _clock(auth_client)
    assert auth_client.get("/api/v1/tickets").status_code == 401
    _login(auth_client, _op(
        auth_client, "carol", "viewer", scope_slugs=["acme-corp"]))
    assert auth_client.get("/api/v1/tickets").status_code == 403
    assert auth_client.get("/api/v1/agent/activity").status_code == 403
    assert _rows("tickets.list") == [] and _rows("agent.activity.fetch") == []


def test_a_failed_open_row_fails_the_read_and_is_retried(auth_client, auth_data_root, monkeypatch):
    """Failure to audit is fatal: with the audit DB unreachable the record
    raises and remembers nothing, so the next call writes the open row."""
    rollup = PolledReadAudit(clock=_Clock(T0))
    good_root = paths.data_root()
    monkeypatch.setenv("OCTO_DATA_ROOT", str(auth_data_root / "missing"))
    with pytest.raises(FileNotFoundError):
        rollup.record("tickets.list", operator_id=7, session_id="s" * 32,
                      reason="ticket list view", rows=1)
    monkeypatch.setenv("OCTO_DATA_ROOT", str(good_root))
    rollup.record("tickets.list", operator_id=7, session_id="s" * 32,
                  reason="ticket list view", rows=1)
    rollup.record("tickets.list", operator_id=7, session_id="s" * 32,
                  reason="ticket list view", rows=1)
    assert [r["after"]["rollup"] for r in _rows("tickets.list")] == ["open"]
    rollup.flush()
    assert _rows("tickets.list")[-1]["after"]["calls"] == 2


def test_distinct_shapes_are_capped(auth_data_root):
    rollup = PolledReadAudit(clock=_Clock(T0))
    for n in range(MAX_SHAPES + 5):
        rollup.record("tickets.list", operator_id=7, session_id="s" * 32,
                      reason="ticket list view", shape=f"tenant=t{n:02d}")
    rollup.record("tickets.list", operator_id=7, session_id="s" * 32,
                  reason="ticket list view", shape="tenant=t00")
    rollup.flush()
    shapes = _rows("tickets.list")[-1]["after"]["shapes"]
    assert len(shapes) == MAX_SHAPES + 1
    assert shapes[OTHER_SHAPES] == 5 and shapes["tenant=t00"] == 2


# ---------------------------------------------------------------------------
# Sensitive reads and writes stay one row per call
# ---------------------------------------------------------------------------

def test_ticket_detail_and_writes_stay_per_call(auth_client, auth_data_root):
    tid = _tickets(auth_data_root)
    _clock(auth_client)
    _login(auth_client, _op(auth_client, "alice", "super_admin"))
    for _ in range(3):
        assert auth_client.get(f"/api/v1/tickets/acme-corp/{tid}").status_code == 200
    assert len(_rows("tickets.fetch")) == 3
    assert all(r["target_id"] == f"acme-corp/{tid}" for r in _rows("tickets.fetch"))
    for status in ("in_progress", "waiting_customer"):
        r = auth_client.patch(f"/api/v1/tickets/acme-corp/{tid}",
                              json={"status": status, "reason": "working it"})
        assert r.status_code == 200, r.text
    assert len(_rows("tickets.patch")) == 2
    assert _chain()[0]


def test_step_up_search_stays_per_call(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme-corp"])
    _clock(auth_client)
    op = _op(auth_client, "alice", "super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    for _ in range(3):
        assert auth_client.post("/api/v1/search/events", json={"limit": 10}).status_code == 200
    assert len(_rows("search.events")) == 3
    assert len(_rows("step_up_granted")) == 1
    assert _chain()[0]


def _held() -> int:
    quarantine.reset_schema_cache()
    return quarantine.hold(
        instance_id=1, vendor_slug="datto", source="poll", reason="name-unknown",
        payload={"alertUid": "alert-1", "note": "held for review"},
        vendor_tenant_id="site-uid-0001",
    ).id


@pytest.mark.parametrize("role,status,audited", [
    (None, 401, False),
    ("viewer", 403, False),
    ("analyst", 403, False),
    ("admin", 200, True),
    ("super_admin", 200, True),
])
def test_quarantine_payload_view_is_audited_per_call(auth_client, auth_data_root,
                                                      role, status, audited):
    qid = _held()
    if role is not None:
        _login(auth_client, _op(auth_client, "alice", role))
    for _ in range(2):
        r = auth_client.get(f"/api/v1/admin/quarantine/{qid}")
        assert r.status_code == status, r.text
    rows = _rows("quarantine_fetch")
    if not audited:
        assert rows == []
        return
    assert len(rows) == 2
    assert rows[0]["target_kind"] == "quarantine" and rows[0]["target_id"] == str(qid)
    assert rows[0]["after"]["payload_sha256"] == quarantine.get(qid).payload_sha256
    # The payload itself never lands in the audit row.
    assert "held for review" not in rows[0]["after_state"]
    assert _chain()[0]
    quarantine.reset_schema_cache()


@pytest.mark.parametrize("role,status,audited", [
    (None, 401, False),
    ("viewer", 403, False),
    ("analyst", 403, False),
    ("admin", 403, False),
    ("super_admin", 200, True),
])
def test_raw_sanitization_rejects_are_audited_per_call(auth_client, auth_data_root,
                                                        role, status, audited):
    if role is not None:
        _login(auth_client, _op(auth_client, "alice", role))
    for _ in range(2):
        r = auth_client.get("/api/v1/admin/sanitization/rejects?window_hours=24&limit=10")
        assert r.status_code == status, r.text
    rows = _rows("sanitization.rejects_fetch")
    if not audited:
        assert rows == []
        return
    assert len(rows) == 2
    assert rows[0]["after"]["window_hours"] == 24 and rows[0]["after"]["limit"] == 10
    assert _chain()[0]
