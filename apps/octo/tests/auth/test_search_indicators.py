"""Indicator (IOC) search — /api/v1/search/indicators.

Parallels the events search tests at a higher level — same security
shape (step-up + scope) tested at the same matrix. Indicator-specific
filters (type/severity/confidence/promoted) get their own coverage.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pyotp
import pytest

from apps.octo import paths


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _apply_indicators_db_migration(client_dir: Path) -> None:
    """Apply migration 002 indicators section to a fresh client dir."""
    client_dir.mkdir(parents=True, exist_ok=True)
    migrations_dir = Path(__file__).resolve().parents[2] / "migrations"
    sql_002 = (migrations_dir / "002-initialize-client-dbs.sql").read_text()
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in sql_002.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    conn = sqlite3.connect(client_dir / "indicators.db")
    try:
        conn.executescript("\n".join(sections["indicators"]))
        conn.commit()
    finally:
        conn.close()


def _insert_indicator(client_dir: Path, value: str, type_: str = "ip",
                        source: str = "test", severity: str = "medium",
                        confidence: float = 0.7, context: str | None = None,
                        promoted: bool = False) -> None:
    conn = sqlite3.connect(client_dir / "indicators.db")
    try:
        conn.execute(
            "INSERT INTO indicators "
            "(value, type, source, severity, confidence, context, promoted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (value, type_, source, severity, confidence, context,
             "2026-05-13T00:00:00.000Z" if promoted else None),
        )
        conn.commit()
    finally:
        conn.close()


def _register_client(slug: str) -> None:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, kind) VALUES (?, ?, 'client')",
            (slug, slug),
        )
        reg.commit()
    finally:
        reg.close()


def _login(client, op: dict) -> None:
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
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


def _seed_indicators(auth_data_root: Path, slug: str) -> None:
    _register_client(slug)
    cdir = auth_data_root / "clients" / slug
    _apply_indicators_db_migration(cdir)
    # Mix of types, severities, confidences, promotion states
    _insert_indicator(cdir, "203.0.113.4",    "ip",     severity="high",     confidence=0.9, promoted=True)
    _insert_indicator(cdir, "198.51.100.5",   "ip",     severity="medium",   confidence=0.6)
    _insert_indicator(cdir, "evil.example",   "domain", severity="high",     confidence=0.85, context="phishing campaign Q2")
    _insert_indicator(cdir, "abc123" * 10 + "abcd", "sha256",  severity="critical", confidence=0.99, promoted=True)
    _insert_indicator(cdir, "CVE-2026-0001",  "cve",    severity="critical", confidence=1.0, promoted=True)
    _insert_indicator(cdir, "low-noise.example", "domain", severity="low",   confidence=0.3)


# ---------------------------------------------------------------------------
# Step-up gate
# ---------------------------------------------------------------------------

def test_indicators_requires_step_up(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "limit": 10,
    })
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"


# ---------------------------------------------------------------------------
# Cross-tenant isolation — same critical security shape as /events
# ---------------------------------------------------------------------------

def test_scoped_viewer_cannot_query_other_tenant_indicators(
        auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    _seed_indicators(auth_data_root, "globex")
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["globex"], "limit": 10,
    })
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_scoped_viewer_mixed_request_intersects(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    _seed_indicators(auth_data_root, "globex")
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme", "globex"], "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenants_searched"] == ["acme"]
    assert all(row["client_slug"] == "acme" for row in body["results"])


# ---------------------------------------------------------------------------
# Filters specific to indicators
# ---------------------------------------------------------------------------

def test_filter_by_type(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "types": ["domain"], "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(row["type"] == "domain" for row in body["results"])
    assert len(body["results"]) >= 1


def test_filter_by_confidence_range(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "confidence_min": 0.8, "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(row["confidence"] >= 0.8 for row in body["results"])


def test_filter_promoted_only(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "promoted_only": True, "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(row["promoted_at"] is not None for row in body["results"])
    # Seed has 3 promoted indicators
    assert len(body["results"]) == 3


def test_free_text_searches_value_and_context(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    # "phishing" only appears in the `context` of the evil.example row
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "query": "phishing", "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) == 1
    assert body["results"][0]["value"] == "evil.example"


def test_invalid_type_400(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "types": ["mythical-beast"], "limit": 10,
    })
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_confidence_min_greater_than_max_400(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "confidence_min": 0.9, "confidence_max": 0.2,
        "limit": 10,
    })
    assert r.status_code == 422


def test_deleted_indicators_excluded_by_default(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    # Soft-delete one
    cdir = auth_data_root / "clients" / "acme"
    conn = sqlite3.connect(cdir / "indicators.db")
    conn.execute(
        "UPDATE indicators SET deleted_at = ?, deleted_by = ?, delete_reason = ? "
        "WHERE value = ?",
        ("2026-05-13T00:00:00.000Z", "test", "false positive", "low-noise.example"),
    )
    conn.commit(); conn.close()
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "limit": 50,
    })
    body = r.json()
    values = [row["value"] for row in body["results"]]
    assert "low-noise.example" not in values
    # include_deleted=true brings it back
    r2 = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "include_deleted": True, "limit": 50,
    })
    values2 = [row["value"] for row in r2.json()["results"]]
    assert "low-noise.example" in values2


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def test_search_indicators_writes_audit_row(auth_client, auth_data_root):
    _seed_indicators(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["acme"], "promoted_only": True, "limit": 50,
    })
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT action, after_state FROM audit_log "
            "WHERE action = 'search.indicators' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "search.indicators audit row missing"
    after = json.loads(row["after_state"])
    assert after["tenants"] == ["acme"]
    assert after["filters"]["promoted_only"] is True
    assert "rows_returned" in after
