"""Tests for the /api/v1/agent-query bridge endpoint (Slice 4).

Validates the fail-closed contract: octo-core's bridge endpoint
never breaks the operator UI even when octo-llm is disabled,
unhealthy, errored, or unreachable. On the happy path, the
enrichment writes back to per-tenant agent_notes and an audit row
lands.

Octo-llm is mocked at the httpx layer so tests don't depend on a
real sibling container.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import httpx
import pyotp
import pytest

from apps.octo import paths
from apps.octo.db import connect


# The agent-query route limiter (apps.octo.api.routers._rate_limiter.LIMITER,
# 30 calls/min per tenant) and the API middleware limiter live for the whole
# process: a file run earlier in the same session (the cross-tenant suite
# fills the tenant and bundle buckets) would turn these calls into 429s.
# Both are cleared before and after every test. LIMITER is re-initialized in
# place: agent_query.py holds a reference to that very object.
def _clear_rate_limiters() -> None:
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.api.routers._rate_limiter import LIMITER
    reset_limiter()
    LIMITER.__init__()


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    _clear_rate_limiters()
    yield
    _clear_rate_limiters()


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
    """Create the tenant's events.db with the agent_notes table.
    Mirrors what migrations 002 + 011 produce."""
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


def _set_llm_flag(enabled: bool) -> None:
    """Toggle bundle_config.l2_llm_enabled."""
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
            # Migration 022 (bundle_config) hasn't run in this fixture.
            # Force it.
            reg.executescript("""
                CREATE TABLE IF NOT EXISTS bundle_config (
                    key             TEXT PRIMARY KEY,
                    value_json      TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    updated_at      TEXT NOT NULL,
                    updated_by      INTEGER
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
# Mock helpers
# ---------------------------------------------------------------------------

class _MockOctoLLM:
    """Patches httpx.get + httpx.post used by the agent_query router.

    Build with `.healthy()` or `.unhealthy()` etc.; pass into
    `_patch_octo_llm` context.
    """
    def __init__(
        self,
        *,
        healthy: bool = True,
        enrich_status: int = 200,
        enrich_body: Optional[dict] = None,
        enrich_raises: Optional[Exception] = None,
    ):
        self.healthy = healthy
        self.enrich_status = enrich_status
        self.enrich_body = enrich_body or {
            "enriched_text": "[stub-v0 ask:tell-more] mocked enrichment text",
            "confidence": 0.5,
            "model_version": "stub-v0",
            "took_ms": 12,
            "ref_kind": "event",
            "ref_id": 1,
            "tenant_scope_slug": "acme",
            "query_kind": "tell_me_more",
        }
        self.enrich_raises = enrich_raises
        self.enrich_calls: list[dict] = []

    def get(self, url: str, *, timeout: float = 0.0) -> httpx.Response:
        if "/v1/healthz" in url:
            if self.healthy:
                return httpx.Response(200, json={
                    "ok": True, "backend": "stub",
                    "model_loaded": True, "model_version": "stub-v0",
                    "uptime_seconds": 1.0,
                })
            return httpx.Response(503, json={"ok": False})
        return httpx.Response(404)

    def post(self, url: str, *, json=None, timeout: float = 0.0) -> httpx.Response:
        if self.enrich_raises is not None:
            raise self.enrich_raises
        if "/v1/enrich-note" in url:
            self.enrich_calls.append(json)
            return httpx.Response(self.enrich_status, json=self.enrich_body)
        return httpx.Response(404)


def _patch_octo_llm(mock: _MockOctoLLM):
    """Context manager that patches httpx.get + httpx.post in the
    agent_query module."""
    return patch.multiple(
        "apps.octo.api.routers.agent_query.httpx",
        get=mock.get, post=mock.post,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_unauthenticated_rejected(auth_client):
    r = auth_client.post("/api/v1/agent-query", json={
        "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
        "query_kind": "tell_me_more", "heuristic_note": "x",
    })
    assert r.status_code in (401, 403)


def test_llm_disabled_returns_412(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _login(auth_client, op)
    _set_llm_flag(False)

    r = auth_client.post("/api/v1/agent-query", json={
        "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
        "query_kind": "tell_me_more", "heuristic_note": "x",
    })
    # APIError("PRECONDITION_FAILED") → HTTP 412
    assert r.status_code == 412, r.text
    assert "disabled" in r.json()["message"].lower()


def test_llm_unhealthy_returns_503(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM(healthy=False)
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })
    # APIError("SERVICE_UNAVAILABLE") → HTTP 503
    assert r.status_code == 503, r.text


def test_llm_5xx_returns_503(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM(enrich_status=500)
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })
    assert r.status_code == 503, r.text


def test_llm_timeout_returns_503(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM(enrich_raises=httpx.TimeoutException("simulated"))
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })
    assert r.status_code == 503, r.text


def test_scope_violation_blocks(auth_client):
    """Analyst whose scope_slugs is ['beta'] cannot query for 'acme'."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["beta"],
    )
    _ensure_client("acme")
    _ensure_client("beta")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM()
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "tell_me_more", "heuristic_note": "x",
        })
    # APIError("ISOLATION_VIOLATION") → 403
    assert r.status_code == 403, r.text


def test_happy_path_writes_agent_note_row(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM()
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 42,
            "query_kind": "tell_me_more",
            "heuristic_note": "Three failed SSH brute-force attempts in 30s",
        })
    assert r.status_code == 200, r.text
    body = r.json()
    note = body["note"]
    assert note["agent_id"] == "octo"
    assert "mocked enrichment" in note["note_text"]
    assert note["query_kind"] == "tell_me_more"
    assert note["ref_kind"] == "event"
    assert note["ref_id"] == 42

    # Verify the row landed in events.db AND the query_kind persisted
    # (Slice 7d — earlier the kind was only in the response, not the
    # DB row).
    edb = paths.client_dir("acme") / "events.db"
    conn = sqlite3.connect(str(edb))
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM agent_notes WHERE ref_id = ?", (42,),
        ).fetchone()[0]
        row = conn.execute(
            "SELECT query_kind FROM agent_notes WHERE ref_id = ?", (42,),
        ).fetchone()
    finally:
        conn.close()
    assert n == 1
    assert row[0] == "tell_me_more"


def test_query_kind_lazy_column_add_on_pre_028_events_db(auth_client):
    """events.db files created before migration 028 don't have the
    query_kind column. The bridge must lazy-ALTER on first insert
    rather than fail."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    # Manually construct events.db WITHOUT the query_kind column
    # (simulates pre-028 dev state).
    edb = paths.client_dir("acme") / "events.db"
    edb.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(edb))
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_kind TEXT NOT NULL
                  CHECK (ref_kind IN ('event','ticket','indicator')),
                ref_id INTEGER NOT NULL,
                agent_id TEXT NOT NULL CHECK (agent_id IN ('octo','athena')),
                note_text TEXT NOT NULL,
                confidence REAL NOT NULL
                  CHECK (confidence >= 0.0 AND confidence <= 1.0),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at TEXT,
                audit_request_id TEXT NOT NULL
            );
        """)
        conn.commit()
        # Confirm no query_kind column yet.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_notes)").fetchall()}
        assert "query_kind" not in cols
    finally:
        conn.close()

    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM()
    with _patch_octo_llm(mock):
        r = auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 100,
            "query_kind": "recognized_patterns",
            "heuristic_note": "Test",
        })
    assert r.status_code == 200, r.text

    # Column should now exist + the value should be persisted.
    conn = sqlite3.connect(str(edb))
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_notes)").fetchall()}
        assert "query_kind" in cols
        row = conn.execute(
            "SELECT query_kind FROM agent_notes WHERE ref_id = ?", (100,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == "recognized_patterns"


def test_happy_path_forwards_query_kind_to_octo_llm(auth_client):
    """The bridge must pass query_kind through verbatim — otherwise
    octo-llm's prompt template dispatch breaks."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _ensure_events_db("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    mock = _MockOctoLLM()
    with _patch_octo_llm(mock):
        auth_client.post("/api/v1/agent-query", json={
            "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
            "query_kind": "recognized_patterns",
            "heuristic_note": "x",
        })
    assert len(mock.enrich_calls) == 1
    sent = mock.enrich_calls[0]
    assert sent["query_kind"] == "recognized_patterns"
    assert sent["tenant_scope_slug"] == "acme"


def test_auto_enrich_not_allowed_through_bridge(auth_client):
    """auto_enrich is reserved for the autonomous background path.
    Operator-triggered requests using it must reject at the
    schema layer (closed enum on AgentQueryRequest.query_kind)."""
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        role="analyst", athena_role="analyst", scope_slugs=["acme"], l2_llm_granted=True,
    )
    _ensure_client("acme")
    _login(auth_client, op)
    _set_llm_flag(True)

    r = auth_client.post("/api/v1/agent-query", json={
        "client_slug": "acme", "ref_kind": "event", "ref_id": 1,
        "query_kind": "auto_enrich", "heuristic_note": "x",
    })
    # 422 (pydantic validation) since auto_enrich isn't in the
    # router's QueryKind literal.
    assert r.status_code == 422, r.text
