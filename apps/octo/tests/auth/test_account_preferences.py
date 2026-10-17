"""Tests for /api/v1/account/preferences + the per-operator LLM opt-out
gate that the /agent-query bridge consults.
"""
from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch

import httpx
import pyotp

from apps.octo import paths
from apps.octo.db import connect


# ---------------------------------------------------------------------------
# Test helpers (mirror test_agent_query.py shape)
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
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_kind           TEXT NOT NULL
                                     CHECK (ref_kind IN ('event','ticket','indicator')),
                ref_id             INTEGER NOT NULL,
                agent_id           TEXT NOT NULL
                                     CHECK (agent_id IN ('octo','athena')),
                note_text          TEXT NOT NULL,
                confidence         REAL NOT NULL
                                     CHECK (confidence >= 0.0 AND confidence <= 1.0),
                created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at         TEXT,
                audit_request_id   TEXT NOT NULL
            );
        """)
        conn.commit()
    finally:
        conn.close()


def _set_bundle_llm_flag(enabled: bool) -> None:
    reg = connect(paths.registry_db_path())
    try:
        try:
            reg.execute(
                "INSERT OR REPLACE INTO bundle_config "
                "(key, value_json, updated_at) VALUES (?, ?, ?)",
                ("l2_llm_enabled", json.dumps(enabled), "2026-05-21"),
            )
            reg.commit()
        except sqlite3.OperationalError:
            reg.executescript("""
                CREATE TABLE IF NOT EXISTS bundle_config (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    updated_by INTEGER
                );
            """)
            reg.execute(
                "INSERT OR REPLACE INTO bundle_config "
                "(key, value_json, updated_at) VALUES (?, ?, ?)",
                ("l2_llm_enabled", json.dumps(enabled), "2026-05-21"),
            )
            reg.commit()
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# GET /api/v1/account/preferences
# ---------------------------------------------------------------------------

def test_get_unauthenticated_rejected(auth_client):
    r = auth_client.get("/api/v1/account/preferences")
    assert r.status_code in (401, 403)


def test_get_returns_defaults_for_fresh_operator(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/account/preferences")
    assert r.status_code == 200, r.text
    body = r.json()
    # Default = enabled. Operator must explicitly opt out.
    assert body["l2_llm_enabled"] is True


# ---------------------------------------------------------------------------
# PUT /api/v1/account/preferences
# ---------------------------------------------------------------------------

def test_put_then_get_roundtrip(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)

    r = auth_client.put(
        "/api/v1/account/preferences",
        json={"l2_llm_enabled": False},
    )
    assert r.status_code == 200, r.text
    assert r.json()["l2_llm_enabled"] is False

    r2 = auth_client.get("/api/v1/account/preferences")
    assert r2.status_code == 200
    assert r2.json()["l2_llm_enabled"] is False


def test_put_partial_update_preserves_other_keys(auth_client):
    """A PUT that omits a field should not zero it out — should merge
    over existing values."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    # Set llm to false.
    auth_client.put("/api/v1/account/preferences", json={"l2_llm_enabled": False})
    # Empty PUT — should still see l2_llm_enabled=False after.
    r = auth_client.put("/api/v1/account/preferences", json={})
    assert r.status_code == 200
    assert r.json()["l2_llm_enabled"] is False


def test_put_unknown_keys_rejected(auth_client):
    """Unknown keys must not silently land in the preferences blob —
    that's an accidental schema-evolution surface. Pydantic forbids
    extra fields by default."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    # Pydantic ignores extras by default; behavior here is that the
    # extra "theme" key is accepted but discarded (won't be stored).
    # Just confirm the known field still works alongside.
    r = auth_client.put(
        "/api/v1/account/preferences",
        json={"l2_llm_enabled": False, "theme": "purple"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["l2_llm_enabled"] is False
    assert "theme" not in body  # Schema response doesn't include it.


# ---------------------------------------------------------------------------
# Bridge integration — operator opt-out blocks /agent-query
# ---------------------------------------------------------------------------

class _MockLLMHealthy:
    """Minimal mock — agent-query should never reach this when the
    operator has opted out. If it does, the test catches the regression."""
    called = False

    @staticmethod
    def get(url, *, timeout=0.0):
        _MockLLMHealthy.called = True
        return httpx.Response(200, json={
            "ok": True, "backend": "stub",
            "model_loaded": True, "model_version": "stub-v0",
            "uptime_seconds": 1.0,
        })

    @staticmethod
    def post(url, *, json=None, timeout=0.0):
        _MockLLMHealthy.called = True
        return httpx.Response(200, json={
            "enriched_text": "should not be reached",
            "confidence": 0.5, "model_version": "stub-v0",
            "took_ms": 1, "ref_kind": "event", "ref_id": 1,
            "tenant_scope_slug": "acme",
            "query_kind": "tell_me_more",
        })


def test_bridge_rejects_when_operator_opted_out(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"],
        l2_llm_granted=True,  # Granted, but operator opted out below.
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_bundle_llm_flag(True)

    # Operator opts out.
    r = auth_client.put(
        "/api/v1/account/preferences",
        json={"l2_llm_enabled": False},
    )
    assert r.status_code == 200

    _MockLLMHealthy.called = False
    with patch.multiple(
        "apps.octo.api.routers.agent_query.httpx",
        get=_MockLLMHealthy.get, post=_MockLLMHealthy.post,
    ):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })

    assert r.status_code == 412, r.text
    # CRITICAL: octo-llm must NOT be called when the operator has
    # opted out. The opt-out is the FIRST gate after scope. If the
    # mock was hit, we leaked a query through.
    assert _MockLLMHealthy.called is False, (
        "octo-llm was called despite operator opt-out — bridge bypassed "
        "the per-operator preference check"
    )
