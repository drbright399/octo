"""Buoy command queue — slice 7 backend tests.

The auth surface here is the load-bearing part. Coverage:
  - Migration 019 creates buoy_commands.
  - POST /buoy/:slug/command requires session + step-up.
  - Role tier matrix per command_kind (analyst+ / admin+ / super_admin).
  - Scope check (operator can't queue for slug they can't see).
  - Arg validation (unknown command, unknown unit, bad shape).
  - Heartbeat response includes pending commands + flips them to
    'dispatched' atomically.
  - Cross-tenant isolation on heartbeat fetch + result report.
  - Result endpoint marks completed/failed with payload.
  - History endpoint scope-filters + viewer-readable.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pyotp

from apps.octo import paths
from apps.octo.auth import core as core_auth
from apps.octo.db import connect


# ---------------------------------------------------------------------------
# Helpers (mirrors test_buoy_heartbeat.py patterns)
# ---------------------------------------------------------------------------

def _mint_client_token(slug: str, kind: str = "buoy",
                        label: str = "test-buoy") -> str:
    plaintext = core_auth.generate_token()
    prefix = core_auth.token_prefix(plaintext)
    th = core_auth.hash_token(plaintext)
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, status, kind) "
            "VALUES (?, ?, 'active', 'client')",
            (slug, slug),
        )
        reg.execute(
            "INSERT INTO client_tokens "
            "  (slug, token_hash, token_prefix, kind, label, created_by) "
            "VALUES (?, ?, ?, ?, ?, 'test')",
            (slug, th, prefix, kind, label),
        )
        reg.commit()
    finally:
        reg.close()
    return plaintext


def _login(client, op: dict) -> None:
    """Real /password/begin + /password/totp flow → session cookie attached
    to the TestClient. Mirrors test_buoy_heartbeat._login_session_headers."""
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
    """Acquire a step-up window. Required for /buoy/:slug/command."""
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r = client.post("/api/v1/search/elevate", json={
        "current_password": op["password"], "totp_code": code,
    })
    assert r.status_code == 200, r.text


def _heartbeat_body(slug: str, **overrides) -> dict:
    body = {
        "slug": slug,
        "hostname": f"buoy-{slug}",
        "uptime_sec": 3600,
        "interval_sec": 60,
        "services": {"tailscaled": "active"},
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Migration sanity
# ---------------------------------------------------------------------------

def test_migration_019_creates_buoy_commands_table(auth_client):
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT name FROM sqlite_master "
            " WHERE type='table' AND name='buoy_commands'"
        ).fetchone()
    finally:
        reg.close()
    assert row is not None


# ---------------------------------------------------------------------------
# Queue endpoint — auth + step-up gates
# ---------------------------------------------------------------------------

def test_queue_rejects_unauth(auth_client):
    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "ping", "args": {},
    })
    assert r.status_code in (401, 403)


def test_queue_rejects_session_without_step_up(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _login(auth_client, op)
    # NOTE: no _elevate — step-up window not active
    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "ping", "args": {},
    })
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"


# ---------------------------------------------------------------------------
# Queue endpoint — role tier matrix
# ---------------------------------------------------------------------------

def test_queue_role_matrix_analyst(auth_client):
    """analyst+ → ping/refresh/tail-log OK; restart-service/reboot/update denied."""
    op = auth_client.provision_operator(
        "bob", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["alpha"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    # ping → 200
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 200, r.text

    # tail-log → 200
    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "tail-log",
        "args": {"unit": "tailscaled", "lines": "50"},
    })
    assert r.status_code == 200, r.text

    # restart-service → ISOLATION_VIOLATION (needs admin+)
    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "restart-service",
        "args": {"unit": "wazuh-agent"},
    })
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"

    # reboot → ISOLATION_VIOLATION (needs super_admin)
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "reboot", "args": {}})
    assert r.status_code == 403


def test_queue_role_matrix_admin(auth_client):
    """admin+ → restart-service OK; reboot/update denied."""
    op = auth_client.provision_operator(
        "carol", "Hunter22!Hunter22!",
        athena_role="admin", scope_slugs=["alpha"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "restart-service",
        "args": {"unit": "wazuh-agent"},
    })
    assert r.status_code == 200, r.text

    # reboot still denied for admin tier
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "reboot", "args": {}})
    assert r.status_code == 403


def test_queue_role_matrix_super_admin(auth_client):
    """super_admin → everything goes through."""
    op = auth_client.provision_operator(
        "dora", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    for kind, args in [
        ("ping", {}),
        ("reboot", {}),
        ("update", {}),
        ("restart-service", {"unit": "suricata"}),
    ]:
        r = auth_client.post("/api/v1/buoy/alpha/command",
                             json={"command_kind": kind, "args": args})
        assert r.status_code == 200, f"{kind}: {r.text}"


# ---------------------------------------------------------------------------
# Queue endpoint — scope check
# ---------------------------------------------------------------------------

def test_queue_rejects_out_of_scope_slug(auth_client):
    op = auth_client.provision_operator(
        "eve", "Hunter22!Hunter22!",
        athena_role="admin", scope_slugs=["alpha"],
    )
    _mint_client_token("alpha")
    _mint_client_token("beta")
    _login(auth_client, op)
    _elevate(auth_client, op)

    # alpha (in scope) → OK
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 200

    # beta (out of scope) → ISOLATION_VIOLATION
    r = auth_client.post("/api/v1/buoy/beta/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Queue endpoint — arg validation
# ---------------------------------------------------------------------------

def test_queue_rejects_unknown_command_kind(auth_client):
    op = auth_client.provision_operator(
        "frank", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "rm-rf-everything",
        "args": {},
    })
    assert r.status_code in (400, 422)


def test_queue_rejects_non_whitelisted_unit(auth_client):
    op = auth_client.provision_operator(
        "gina", "Hunter22!Hunter22!",
        athena_role="admin", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "restart-service",
        "args": {"unit": "sshd"},   # not in whitelist
    })
    assert r.status_code in (400, 422)


def test_queue_ping_rejects_args(auth_client):
    op = auth_client.provision_operator(
        "hank", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command", json={
        "command_kind": "ping",
        "args": {"surprise": "arg"},
    })
    assert r.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Heartbeat returns pending commands + flips to dispatched
# ---------------------------------------------------------------------------

def test_heartbeat_returns_pending_and_flips_to_dispatched(auth_client):
    op = auth_client.provision_operator(
        "ivy", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    token = _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    # Operator queues two commands
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 200
    cmd1_id = r.json()["id"]
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "refresh", "args": {}})
    assert r.status_code == 200
    cmd2_id = r.json()["id"]

    # Buoy heartbeats — should receive both pending commands
    r = auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body("alpha"),
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    pending = r.json()["pending_commands"]
    assert len(pending) == 2
    pending_ids = {c["id"] for c in pending}
    assert pending_ids == {cmd1_id, cmd2_id}

    # Both should now be 'dispatched' in the DB
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT id, status FROM buoy_commands WHERE id IN (?, ?)",
            (cmd1_id, cmd2_id),
        ).fetchall()
    finally:
        reg.close()
    for r in rows:
        assert r[1] == "dispatched", r

    # Second heartbeat — no new commands queued — pending_commands empty
    r = auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body("alpha"),
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["pending_commands"] == []


def test_heartbeat_does_not_leak_other_tenants_commands(auth_client):
    """A buoy's heartbeat MUST NOT receive another tenant's commands."""
    op = auth_client.provision_operator(
        "jack", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    alpha_token = _mint_client_token("alpha")
    _mint_client_token("beta")
    _login(auth_client, op)
    _elevate(auth_client, op)

    # Queue a command for beta
    r = auth_client.post("/api/v1/buoy/beta/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 200

    # alpha's buoy heartbeats — must NOT see beta's command
    r = auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body("alpha"),
                         headers={"Authorization": f"Bearer {alpha_token}"})
    assert r.status_code == 200
    assert r.json()["pending_commands"] == []


def test_heartbeat_reaps_expired_commands(auth_client):
    """Commands past expires_at flip to 'expired', not delivered."""
    op = auth_client.provision_operator(
        "kim", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    token = _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    assert r.status_code == 200
    cmd_id = r.json()["id"]

    # Backdate expires_at to before now
    reg = connect(paths.registry_db_path())
    try:
        past = (datetime.now(timezone.utc) - timedelta(minutes=10))\
            .strftime("%Y-%m-%dT%H:%M:%S.000Z")
        reg.execute("UPDATE buoy_commands SET expires_at = ? WHERE id = ?",
                    (past, cmd_id))
        reg.commit()
    finally:
        reg.close()

    # Heartbeat should reap → status='expired', NOT delivered
    r = auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body("alpha"),
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["pending_commands"] == []

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute("SELECT status FROM buoy_commands WHERE id = ?",
                          (cmd_id,)).fetchone()
    finally:
        reg.close()
    assert row[0] == "expired"


# ---------------------------------------------------------------------------
# Result endpoint
# ---------------------------------------------------------------------------

def test_result_marks_completed(auth_client):
    op = auth_client.provision_operator(
        "leo", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    token = _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    cmd_id = r.json()["id"]
    # Dispatch by heartbeat
    auth_client.post("/api/v1/buoy/heartbeat",
                     json=_heartbeat_body("alpha"),
                     headers={"Authorization": f"Bearer {token}"})

    # Buoy reports completion
    r = auth_client.post(
        f"/api/v1/buoy/command/{cmd_id}/result",
        json={"ok": True, "exit_code": 0, "stdout_tail": "pong"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "completed"


def test_result_cross_tenant_rejected(auth_client):
    """A buoy can't complete another tenant's command."""
    op = auth_client.provision_operator(
        "mia", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _login(auth_client, op)
    _elevate(auth_client, op)

    alpha_token = _mint_client_token("alpha")
    beta_token = _mint_client_token("beta")

    # Queue + dispatch for alpha
    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    cmd_id = r.json()["id"]
    auth_client.post("/api/v1/buoy/heartbeat",
                     json=_heartbeat_body("alpha"),
                     headers={"Authorization": f"Bearer {alpha_token}"})

    # beta's bearer tries to complete it → ISOLATION_VIOLATION
    r = auth_client.post(
        f"/api/v1/buoy/command/{cmd_id}/result",
        json={"ok": True, "exit_code": 0},
        headers={"Authorization": f"Bearer {beta_token}"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_result_is_idempotent(auth_client):
    op = auth_client.provision_operator(
        "nat", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    token = _mint_client_token("alpha")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/buoy/alpha/command",
                         json={"command_kind": "ping", "args": {}})
    cmd_id = r.json()["id"]
    auth_client.post("/api/v1/buoy/heartbeat",
                     json=_heartbeat_body("alpha"),
                     headers={"Authorization": f"Bearer {token}"})

    r = auth_client.post(
        f"/api/v1/buoy/command/{cmd_id}/result",
        json={"ok": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    # Re-report — should noop, not error
    r = auth_client.post(
        f"/api/v1/buoy/command/{cmd_id}/result",
        json={"ok": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json().get("noop") is True


# ---------------------------------------------------------------------------
# History endpoint — viewer can read own buoy
# ---------------------------------------------------------------------------

def test_history_viewer_sees_own_slug(auth_client):
    admin = auth_client.provision_operator(
        "olive", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, admin)
    _elevate(auth_client, admin)
    # Admin queues a command for alpha
    auth_client.post("/api/v1/buoy/alpha/command",
                     json={"command_kind": "ping", "args": {}})

    # Now a viewer scoped to alpha logs in
    viewer = auth_client.provision_operator(
        "peggy", "Hunter22!Hunter22!",
        role="viewer", athena_role="viewer", scope_slugs=["alpha"],
    )
    _login(auth_client, viewer)

    # Viewer can read alpha's command history
    r = auth_client.get("/api/v1/buoy/alpha/commands")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["commands"]) >= 1
    assert body["commands"][0]["slug"] == "alpha"


def test_history_viewer_blocked_from_other_slug(auth_client):
    viewer = auth_client.provision_operator(
        "quinn", "Hunter22!Hunter22!",
        role="viewer", athena_role="viewer", scope_slugs=["alpha"],
    )
    _login(auth_client, viewer)
    r = auth_client.get("/api/v1/buoy/beta/commands")
    assert r.status_code == 403


def test_history_viewer_loses_an_offboarded_tenant_at_once(auth_client):
    """A viewer is a CLIENT user. Dashboard and search drop a scoped slug
    the moment its tenant stops being active; the buoy routes resolved scope
    with their own copy that skipped the status filter, so a departed
    client's viewer kept reading its buoy command history (and could queue
    nothing only because of the tier gate). Same rule everywhere now:
    the offboarded tenant is simply not theirs — 403, no rows."""
    admin = auth_client.provision_operator(
        "olive", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    _mint_client_token("alpha")
    _login(auth_client, admin)
    _elevate(auth_client, admin)
    assert auth_client.post("/api/v1/buoy/alpha/command",
                            json={"command_kind": "ping", "args": {}}).status_code == 200
    viewer = auth_client.provision_operator(
        "peggy", "Hunter22!Hunter22!",
        role="viewer", athena_role="viewer", scope_slugs=["alpha"],
    )
    auth_client.cookies.clear()
    _login(auth_client, viewer)
    assert len(auth_client.get("/api/v1/buoy/alpha/commands").json()["commands"]) == 1

    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'alpha'")
        reg.commit()
    finally:
        reg.close()
    r = auth_client.get("/api/v1/buoy/alpha/commands")
    assert r.status_code == 403, r.text
    assert "commands" not in r.json()
    # The shared resolver is what every scoped router reads.
    from apps.octo.api.role_gates import resolve_caller_scope
    from apps.octo.api.routers.buoy import _operator_can_see_slug
    assert resolve_caller_scope(viewer["id"]) == []
    assert _operator_can_see_slug(viewer["id"], "alpha") is False
    # The MSP's own ('*') scope is untouched: an admin still sees the history.
    auth_client.cookies.clear()
    _login(auth_client, admin)
    assert auth_client.get("/api/v1/buoy/alpha/commands").status_code == 200
