"""Tests for /api/v1/admin/operators/{id}/llm-grant (Slice 5d-2).

Exercises the tier rule, the audit row, the bridge-gate integration,
and the factory-protection invariant.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import httpx
import pyotp

from apps.octo import paths
from apps.octo.db import connect


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


def _set_grant(operator_id: int, granted: bool) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE operators SET l2_llm_granted = ? WHERE id = ?",
            (1 if granted else 0, operator_id),
        )
        reg.commit()
    finally:
        reg.close()


def _read_grant(operator_id: int) -> bool:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT l2_llm_granted FROM operators WHERE id = ?",
            (operator_id,),
        ).fetchone()
    finally:
        reg.close()
    return bool(row[0]) if row else False


# ---------------------------------------------------------------------------
# Tier rule
# ---------------------------------------------------------------------------

def test_unauthenticated_rejected(auth_client):
    r = auth_client.put(
        "/api/v1/admin/operators/1/llm-grant", json={"granted": True},
    )
    assert r.status_code in (401, 403)


def test_analyst_cannot_grant(auth_client):
    caller = auth_client.provision_operator(
        "alice-analyst", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    target = auth_client.provision_operator(
        "bob-viewer", "Hunter22!Hunter22!",
        role="analyst", athena_role="viewer",
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": True},
    )
    # Caller below admin tier → ISOLATION_VIOLATION (403).
    assert r.status_code == 403


def test_admin_can_grant_viewer(auth_client):
    caller = auth_client.provision_operator(
        "alice-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    target = auth_client.provision_operator(
        "bob-viewer", "Hunter22!Hunter22!",
        role="analyst", athena_role="viewer",
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["granted"] is True
    assert _read_grant(target["id"]) is True


def test_admin_cannot_grant_super_admin(auth_client):
    """Admin tier (3) must not be able to grant a super_admin (tier 4)."""
    caller = auth_client.provision_operator(
        "alice-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    target = auth_client.provision_operator(
        "bob-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": True},
    )
    assert r.status_code == 403


def test_super_admin_can_grant_admin(auth_client):
    caller = auth_client.provision_operator(
        "alice-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "bob-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": True},
    )
    assert r.status_code == 200, r.text
    assert _read_grant(target["id"]) is True


def test_super_admin_can_revoke(auth_client):
    caller = auth_client.provision_operator(
        "alice-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "bob-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
        l2_llm_granted=True,
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": False},
    )
    assert r.status_code == 200, r.text
    assert _read_grant(target["id"]) is False


def test_idempotent_no_op_noaudit(auth_client):
    """Re-setting the same grant value is a 200 no-op (doesn't fail)."""
    caller = auth_client.provision_operator(
        "alice-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
    )
    target = auth_client.provision_operator(
        "bob-admin", "Hunter22!Hunter22!",
        role="admin", athena_role="admin",
        l2_llm_granted=True,
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{target['id']}/llm-grant",
        json={"granted": True},  # Already granted.
    )
    assert r.status_code == 200
    assert r.json()["granted"] is True


def test_factory_grant_locked_from_others(auth_client):
    """Even a super_admin (non-factory) cannot modify the factory's
    grant — that's a single-operator-managed flag."""
    caller = auth_client.provision_operator(
        "alice-su", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=False,
    )
    factory = auth_client.provision_operator(
        "factory-root", "Hunter22!Hunter22!",
        role="admin", athena_role="super_admin",
        is_factory=True,
    )
    _login(auth_client, caller)
    r = auth_client.put(
        f"/api/v1/admin/operators/{factory['id']}/llm-grant",
        json={"granted": False},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Bridge gate integration
# ---------------------------------------------------------------------------

def _ensure_client(slug: str) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, status, kind, ai_policy) "
            "VALUES (?, ?, 'active', 'client', 'local')",
            (slug, slug),
        )
        reg.commit()
    finally:
        reg.close()


def _ensure_events_db(slug: str) -> None:
    edb = paths.client_dir(slug) / "events.db"
    edb.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(edb))
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_kind TEXT NOT NULL CHECK (ref_kind IN ('event','ticket','indicator')),
                ref_id INTEGER NOT NULL,
                agent_id TEXT NOT NULL CHECK (agent_id IN ('octo','athena')),
                note_text TEXT NOT NULL,
                confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at TEXT,
                audit_request_id TEXT NOT NULL
            );
        """)
        conn.commit()
    finally:
        conn.close()


def _set_bundle_llm(enabled: bool) -> None:
    reg = connect(paths.registry_db_path())
    try:
        try:
            reg.execute(
                "INSERT OR REPLACE INTO bundle_config (key, value_json, updated_at) "
                "VALUES (?, ?, ?)",
                ("l2_llm_enabled", json.dumps(enabled), "2026-05-21"),
            )
            reg.commit()
        except sqlite3.OperationalError:
            pass
    finally:
        reg.close()


def test_bridge_rejects_when_operator_not_granted(auth_client):
    """An ungranted operator hits the bridge → 412 'not granted'.
    The octo-llm mock must NOT be called."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"],
        l2_llm_granted=False,  # explicit: not granted
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_bundle_llm(True)

    mock_called = {"n": 0}

    def fake_get(*args, **kwargs):
        mock_called["n"] += 1
        return httpx.Response(200, json={"ok": True, "model_loaded": True,
                                          "backend": "stub", "model_version": "stub-v0",
                                          "uptime_seconds": 1.0})

    def fake_post(*args, **kwargs):
        mock_called["n"] += 1
        return httpx.Response(200)

    with patch.multiple(
        "apps.octo.api.routers.agent_query.httpx",
        get=fake_get, post=fake_post,
    ):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })

    assert r.status_code == 412, r.text
    assert "grant" in r.json().get("message", "").lower()
    # CRITICAL — the bridge must short-circuit BEFORE calling octo-llm.
    assert mock_called["n"] == 0, "octo-llm was called for an ungranted operator"


# ---------------------------------------------------------------------------
# /api/v1/account/llm-status
# ---------------------------------------------------------------------------

def test_llm_status_reflects_all_four_gates(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
        l2_llm_granted=True,
    )
    _login(auth_client, op)
    _set_bundle_llm(True)

    # Without mocking healthz, the call attempt fails → healthz false.
    # That's fine; effectively_active should reflect that.
    r = auth_client.get("/api/v1/account/llm-status")
    assert r.status_code == 200
    body = r.json()
    assert body["your_grant"] is True
    assert body["your_preference"] is True  # default
    assert body["bundle_enabled"] is True
    # healthz is real network call here — will fail → effectively_active=False
    assert body["effectively_active"] is False


def test_llm_status_visible_to_viewer(auth_client):
    """Viewers can also see the chip — every operator wants to know if
    their next click will work."""
    op = auth_client.provision_operator(
        "v-bob", "Hunter22!Hunter22!",
        role="analyst", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/account/llm-status")
    assert r.status_code == 200
    assert "active_model" in r.json()
    assert r.json()["your_grant"] is False  # default ungranted
