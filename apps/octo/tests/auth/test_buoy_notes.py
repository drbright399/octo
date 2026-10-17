"""Buoy notes router — slice 12 backend tests.

Coverage:
  - Migration 020 creates buoy_user_notes + buoy_agent_notes.
  - User notes: scope-gated read/write, author-or-admin delete.
  - Agent notes: admin+ + step-up + action_class CHECK constraint.
  - Cross-tenant isolation.
"""
from __future__ import annotations

import pyotp

from apps.octo import paths
from apps.octo.auth import core as core_auth
from apps.octo.db import connect


# ---------------------------------------------------------------------------
# Helpers — reused from the broader auth test suite style
# ---------------------------------------------------------------------------

def _login(client, op: dict) -> None:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text


def _elevate(client, op: dict) -> None:
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r.status_code == 200, r.text


def _ensure_client(slug: str) -> None:
    """Insert client row so slug exists in registry.db for scope checks."""
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, status, kind) "
            "VALUES (?, ?, 'active', 'client')",
            (slug, slug),
        )
        reg.commit()
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Migration sanity
# ---------------------------------------------------------------------------

def test_migration_020_creates_user_notes_table(auth_client):
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='buoy_user_notes'"
        ).fetchone()
    finally:
        reg.close()
    assert row is not None


def test_migration_020_creates_agent_notes_table(auth_client):
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='buoy_agent_notes'"
        ).fetchone()
    finally:
        reg.close()
    assert row is not None


# ---------------------------------------------------------------------------
# User notes — read/write
# ---------------------------------------------------------------------------

def test_user_notes_list_rejects_unauthenticated(auth_client):
    r = auth_client.get("/api/v1/buoy/alpha/notes/user")
    assert r.status_code in (401, 403)


def test_user_notes_empty_by_default(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)

    r = auth_client.get("/api/v1/buoy/alpha/notes/user")
    assert r.status_code == 200, r.text
    assert r.json() == {"rows": [], "next_cursor": None}


def test_user_notes_create_then_list_roundtrip(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/notes/user", json={
        "body_md": "UPS is on a flaky outlet — expect reboots during storms.",
    })
    assert r.status_code == 200, r.text
    note = r.json()
    assert note["slug"] == "alpha"
    assert note["author_id"] == op["id"]
    assert "flaky outlet" in note["body_md"]

    r2 = auth_client.get("/api/v1/buoy/alpha/notes/user")
    assert r2.status_code == 200
    rows = r2.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["id"] == note["id"]


def test_user_notes_list_orders_newest_first(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)

    for body in ["first", "second", "third"]:
        r = auth_client.post("/api/v1/buoy/alpha/notes/user",
                              json={"body_md": body})
        assert r.status_code == 200, r.text

    r = auth_client.get("/api/v1/buoy/alpha/notes/user")
    rows = r.json()["rows"]
    assert [row["body_md"] for row in rows] == ["third", "second", "first"]


def test_user_notes_scope_gates_read(auth_client):
    """Operator scoped to 'alpha' must not be able to read 'beta' notes."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("beta")
    _login(auth_client, op)

    r = auth_client.get("/api/v1/buoy/beta/notes/user")
    assert r.status_code in (401, 403)
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_user_notes_scope_gates_write(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("beta")
    _login(auth_client, op)

    r = auth_client.post("/api/v1/buoy/beta/notes/user",
                          json={"body_md": "stealing context across tenants"})
    assert r.status_code in (401, 403)


def test_user_notes_pagination_cursor(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)

    for i in range(5):
        auth_client.post("/api/v1/buoy/alpha/notes/user",
                          json={"body_md": f"note {i}"})

    r = auth_client.get("/api/v1/buoy/alpha/notes/user?limit=2")
    assert r.status_code == 200
    page1 = r.json()
    assert len(page1["rows"]) == 2
    assert page1["next_cursor"] is not None

    r2 = auth_client.get(
        f"/api/v1/buoy/alpha/notes/user?limit=2&cursor={page1['next_cursor']}",
    )
    page2 = r2.json()
    assert len(page2["rows"]) == 2
    # No overlap
    page1_ids = {r["id"] for r in page1["rows"]}
    page2_ids = {r["id"] for r in page2["rows"]}
    assert page1_ids.isdisjoint(page2_ids)


# ---------------------------------------------------------------------------
# User notes — delete authorization
# ---------------------------------------------------------------------------

def test_user_notes_author_can_delete_own(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/notes/user",
                          json={"body_md": "mine"})
    note_id = r.json()["id"]

    r2 = auth_client.delete(f"/api/v1/buoy/notes/user/{note_id}")
    assert r2.status_code == 200
    assert r2.json() == {"deleted": True}


def test_user_notes_non_author_non_admin_cannot_delete(auth_client):
    alice = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, alice)
    r = auth_client.post("/api/v1/buoy/alpha/notes/user",
                          json={"body_md": "alice's note"})
    note_id = r.json()["id"]
    auth_client.post("/api/v1/auth/logout")

    bob = auth_client.provision_operator(
        "bob", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _login(auth_client, bob)
    r2 = auth_client.delete(f"/api/v1/buoy/notes/user/{note_id}")
    assert r2.status_code in (401, 403)


def test_user_notes_admin_can_delete_others(auth_client):
    alice = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, alice)
    r = auth_client.post("/api/v1/buoy/alpha/notes/user",
                          json={"body_md": "alice's note"})
    note_id = r.json()["id"]
    auth_client.post("/api/v1/auth/logout")

    boss = auth_client.provision_operator(
        "boss", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    _login(auth_client, boss)
    r2 = auth_client.delete(f"/api/v1/buoy/notes/user/{note_id}")
    assert r2.status_code == 200, r2.text


def test_user_notes_delete_missing_returns_404(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    _login(auth_client, op)
    r = auth_client.delete("/api/v1/buoy/notes/user/99999")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Agent notes — admin+ + step-up + CHECK constraint
# ---------------------------------------------------------------------------

def test_agent_notes_create_rejects_analyst(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/notes/agent", json={
        "action_class": "state-change",
        "body_md": "tried to write as analyst",
    })
    # Either STEP_UP_REQUIRED + 401 (if step-up needed but missing) or 403.
    # Analyst with step-up still loses on the admin-tier check below.
    assert r.status_code in (401, 403)


def test_agent_notes_create_requires_step_up(auth_client):
    op = auth_client.provision_operator(
        "admin1", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)
    # NOTE: no _elevate
    r = auth_client.post("/api/v1/buoy/alpha/notes/agent", json={
        "action_class": "state-change",
        "body_md": "no step-up",
    })
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"


def test_agent_notes_create_success(auth_client):
    op = auth_client.provision_operator(
        "admin1", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/notes/agent", json={
        "action_class": "alert-behavior",
        "body_md": "Wazuh rule 100510 widened to (Generic). 42→0 expected.",
        "correlation_id": "corr-2026-05-18-1455",
        "session_id": "abc123",
    })
    assert r.status_code == 200, r.text
    row = r.json()
    assert row["slug"] == "alpha"
    assert row["action_class"] == "alert-behavior"
    assert row["correlation_id"] == "corr-2026-05-18-1455"
    assert row["session_id"] == "abc123"


def test_agent_notes_rejects_unknown_action_class(auth_client):
    op = auth_client.provision_operator(
        "admin1", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    _ensure_client("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/notes/agent", json={
        "action_class": "freestyle-thought",
        "body_md": "should not record",
    })
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_agent_notes_correlation_id_groups_rows(auth_client):
    """One logical action across multiple buoys should land as N rows
    sharing a correlation_id."""
    op = auth_client.provision_operator(
        "admin1", "Hunter22!Hunter22!",
        role="admin", athena_role="admin", scope_slugs=["*"],
    )
    for slug in ("alpha", "beta", "gamma"):
        _ensure_client(slug)
    _login(auth_client, op)
    _elevate(auth_client, op)

    corr = "corr-fleet-rule-deploy"
    for slug in ("alpha", "beta", "gamma"):
        r = auth_client.post(f"/api/v1/buoy/{slug}/notes/agent", json={
            "action_class": "alert-behavior",
            "body_md": "fleet rule deploy",
            "correlation_id": corr,
        })
        assert r.status_code == 200, r.text

    # Verify each slug shows its own row, all with the same correlation_id.
    for slug in ("alpha", "beta", "gamma"):
        r = auth_client.get(f"/api/v1/buoy/{slug}/notes/agent")
        rows = r.json()["rows"]
        assert len(rows) == 1
        assert rows[0]["correlation_id"] == corr


def test_agent_notes_read_scope_gated(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _ensure_client("beta")
    _login(auth_client, op)

    r = auth_client.get("/api/v1/buoy/beta/notes/agent")
    assert r.status_code in (401, 403)
