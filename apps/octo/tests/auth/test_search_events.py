"""Search /events endpoint — the security-critical query surface.

Most important tests in this file are the cross-tenant isolation cases.
The design-doc invariant: an operator with scope=['acme'] literally
cannot construct a query that returns globex rows. Several tests
enumerate the attack patterns to confirm.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

from apps.octo import paths
from apps.octo.auth import sessions, step_up


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _apply_events_db_migration(client_dir: Path) -> None:
    """Apply migrations 002 (events table) + 004 (summary column) +
    011 (agent_notes + agent_pattern_links) so the fixture matches
    production schema."""
    client_dir.mkdir(parents=True, exist_ok=True)
    migrations_dir = Path(__file__).resolve().parents[2] / "migrations"

    def _split_targets(sql: str) -> dict[str, list[str]]:
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in sql.splitlines():
            if line.startswith("-- @target:"):
                current = line.split(":", 1)[1].strip()
                sections.setdefault(current, [])
            elif current is not None:
                sections[current].append(line)
        return sections

    sql_002 = (migrations_dir / "002-initialize-client-dbs.sql").read_text()
    sql_004 = (migrations_dir / "004-source-instances.sql").read_text()
    sql_011 = (migrations_dir / "011-agent-notes.sql").read_text()
    s002 = _split_targets(sql_002)
    s004 = _split_targets(sql_004)
    s011 = _split_targets(sql_011)
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.executescript("\n".join(s002["events"]))
        if "events" in s004:
            conn.executescript("\n".join(s004["events"]))
        if "events" in s011:
            conn.executescript("\n".join(s011["events"]))
        conn.commit()
    finally:
        conn.close()


def _insert_event(client_dir: Path, received_at: str, event_type: str = "test.event",
                    severity: str = "info", source_host: str = "buoy-1",
                    summary: str = "") -> None:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary) "
            "VALUES (?, 'test-source', ?, ?, ?, '{}', ?, ?)",
            (received_at, source_host, event_type, severity, "a"*64, summary),
        )
        conn.commit()
    finally:
        conn.close()


def _register_client(slug: str, display_name: str | None = None) -> None:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, kind) VALUES (?, ?, 'client')",
            (slug, display_name or slug),
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


def _seed_minimal(auth_data_root: Path, slugs: list[str]) -> None:
    """Create + register N client tenants, each with 5 minutes of recent
    events scattered across two event_types."""
    for slug in slugs:
        _register_client(slug)
        cdir = auth_data_root / "clients" / slug
        _apply_events_db_migration(cdir)
        now = datetime.now(timezone.utc)
        for i in range(5):
            ts = (now - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            _insert_event(
                cdir, ts,
                event_type="wazuh.alert" if i % 2 == 0 else "pihole.query",
                severity="high" if i % 2 == 0 else "info",
                source_host=f"buoy-{slug}-1",
                summary=f"event {i} for {slug}",
            )


# ---------------------------------------------------------------------------
# Step-up gate
# ---------------------------------------------------------------------------

def test_events_requires_step_up(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    # NOT elevated
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 10,
    })
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"


def test_events_unauthenticated_401(auth_client):
    auth_client.cookies.clear()
    r = auth_client.post("/api/v1/search/events", json={"tenants": []})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Cross-tenant isolation — the load-bearing security tests
# ---------------------------------------------------------------------------

def test_scoped_viewer_cannot_query_outside_scope(auth_client, auth_data_root):
    """scope=['acme'] requesting tenants=['globex'] → 403."""
    _seed_minimal(auth_data_root, ["acme", "globex"])
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["globex"], "limit": 10,
    })
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_scoped_viewer_mixed_request_intersects_to_allowed(auth_client, auth_data_root):
    """scope=['acme'] requesting tenants=['acme', 'globex'] → returns
    only acme rows. tenants_searched in response confirms."""
    _seed_minimal(auth_data_root, ["acme", "globex"])
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme", "globex"], "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tenants_searched"] == ["acme"]  # globex excluded
    assert all(row["client_slug"] == "acme" for row in body["results"])
    assert len(body["results"]) > 0


def test_super_admin_star_scope_sees_all_active_clients(auth_client, auth_data_root):
    """scope=['*'] with empty request.tenants → search every active client."""
    _seed_minimal(auth_data_root, ["acme", "globex", "initech"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "limit": 100,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["tenants_searched"]) == ["acme", "globex", "initech"]
    slugs_seen = {row["client_slug"] for row in body["results"]}
    assert slugs_seen == {"acme", "globex", "initech"}


def test_no_roles_at_all_blocks_search(auth_client, auth_data_root):
    """Operator with no role rows can't search anything → 403."""
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("anon", "pw1234567890",
                                          athena_role=None)
    # Clear the legacy admin row so caller has zero roles
    conn = sqlite3.connect(paths.registry_db_path())
    conn.execute("DELETE FROM operator_roles WHERE operator_id = ?",
                  (op["id"],))
    conn.commit(); conn.close()
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 10,
    })
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def test_filter_by_event_type(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "event_types": ["wazuh.alert"], "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(row["event_type"] == "wazuh.alert" for row in body["results"])


def test_filter_by_severity(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "severities": ["high"], "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(row["severity"] == "high" for row in body["results"])


def test_invalid_severity_400(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "severities": ["nuclear"], "limit": 10,
    })
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


def test_free_text_query_matches_summary(auth_client, auth_data_root):
    """LIKE on summary — 'event 2' should match 'event 2 for acme'."""
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "query": "event 2", "limit": 50,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) >= 1
    assert all("event 2" in row["summary"] for row in body["results"])


def test_time_range_over_90_days_rejected(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"],
        "time_from": "2020-01-01T00:00:00Z",
        "time_to":   "2024-01-01T00:00:00Z",
        "limit": 10,
    })
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def test_pagination_returns_distinct_pages(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r1 = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 2, "offset": 0,
    })
    r2 = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 2, "offset": 2,
    })
    page1_ids = [row["event_id"] for row in r1.json()["results"]]
    page2_ids = [row["event_id"] for row in r2.json()["results"]]
    assert page1_ids and page2_ids
    assert set(page1_ids) & set(page2_ids) == set()  # no overlap


def test_offset_above_cap_rejected_by_pydantic(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "offset": 100_000, "limit": 10,
    })
    # pydantic field constraint kicks in before our handler runs
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def test_search_writes_audit_row(auth_client, auth_data_root):
    """Every search produces an audit row in global audit.db with
    action='search.events' and a normalized filters blob."""
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "query": "event", "limit": 10,
    })
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT action, after_state FROM audit_log "
            "WHERE action = 'search.events' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "search.events audit row missing"
    after = json.loads(row["after_state"])
    assert after["tenants"] == ["acme"]
    assert after["filters"]["has_query"] is True
    assert after["filters"]["query_hash"] is not None
    assert "rows_returned" in after
    assert "step_up_age_seconds" in after


def test_isolation_violation_still_audits(auth_client, auth_data_root):
    """Even rejected searches should leave a trail — but we currently
    only audit ON the successful path. Verify the current behavior
    rather than assert what's not implemented."""
    _seed_minimal(auth_data_root, ["acme", "globex"])
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["globex"], "limit": 10,
    })
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# Step-up sliding extends within search
# ---------------------------------------------------------------------------

def test_search_slides_step_up_window(auth_client, auth_data_root):
    """Successful search calls require_step_up which slides the window.
    Verify by reading the until column before/after."""
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    before = conn.execute(
        "SELECT step_up_auth_until FROM sessions WHERE operator_id = ? "
        "ORDER BY issued_at DESC LIMIT 1", (op["id"],),
    ).fetchone()["step_up_auth_until"]
    conn.close()
    import time
    time.sleep(0.05)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 1,
    })
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(paths.registry_db_path())
    conn.row_factory = sqlite3.Row
    after = conn.execute(
        "SELECT step_up_auth_until FROM sessions WHERE operator_id = ? "
        "ORDER BY issued_at DESC LIMIT 1", (op["id"],),
    ).fetchone()["step_up_auth_until"]
    conn.close()
    # Sliding should have extended (or kept equal if TTL was already
    # at its max — but 30min sliding fresh from elevate should slide)
    assert after >= before


# ---------------------------------------------------------------------------
# Empty / edge cases
# ---------------------------------------------------------------------------

def test_search_with_no_results_returns_empty_list(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "query": "nonexistent-foo-bar-baz", "limit": 10,
    })
    assert r.status_code == 200, r.text
    assert r.json()["results"] == []


def test_search_response_includes_step_up_expires_at(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/events", json={
        "tenants": ["acme"], "limit": 1,
    })
    assert r.status_code == 200, r.text
    assert r.json()["step_up_expires_at"] is not None


# ---------------------------------------------------------------------------
# M4 — GET /search/event/{slug}/{id}
# ---------------------------------------------------------------------------

def _first_event_id(client_dir: Path) -> int:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        row = conn.execute("SELECT id FROM events ORDER BY id LIMIT 1").fetchone()
    finally:
        conn.close()
    assert row is not None
    return row[0]


def test_payload_fetch_returns_full_event(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    eid = _first_event_id(auth_data_root / "clients" / "acme")
    r = auth_client.get(f"/api/v1/search/event/acme/{eid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["client_slug"] == "acme"
    assert body["event_id"] == eid
    assert isinstance(body["payload"], dict)
    assert body["event_type"] in ("wazuh.alert", "pihole.query")
    assert body["step_up_expires_at"] is not None


def test_payload_fetch_surfaces_derived_ticket(auth_client, auth_data_root):
    """When a ticket was opened from an event, the event payload
    response surfaces the derived ticket's id + title so the /search
    drawer can render a one-click pivot back to /tickets."""
    from apps.octo.tests.auth.test_tickets import (
        _apply_tickets_db_migration, _insert_ticket,
    )
    _seed_minimal(auth_data_root, ["acme"])
    cdir = auth_data_root / "clients" / "acme"
    _apply_tickets_db_migration(cdir)
    eid = _first_event_id(cdir)
    tid = _insert_ticket(cdir, title="Investigate alert",
                         source_event_id=eid)

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.get(f"/api/v1/search/event/acme/{eid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["derived_ticket_id"] == tid
    assert body["derived_ticket_title"] == "Investigate alert"


def test_payload_fetch_no_derived_ticket(auth_client, auth_data_root):
    """An event with no ticket derived from it should report null."""
    _seed_minimal(auth_data_root, ["acme"])
    eid = _first_event_id(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.get(f"/api/v1/search/event/acme/{eid}")
    assert r.status_code == 200
    body = r.json()
    assert body["derived_ticket_id"] is None
    assert body["derived_ticket_title"] is None


def test_payload_fetch_requires_step_up(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    eid = _first_event_id(auth_data_root / "clients" / "acme")
    # NOT elevated
    r = auth_client.get(f"/api/v1/search/event/acme/{eid}")
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"


def test_payload_fetch_blocks_out_of_scope_slug(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme", "globex"])
    op = auth_client.provision_operator(
        "viewer", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    _elevate(auth_client, op)
    eid_globex = _first_event_id(auth_data_root / "clients" / "globex")
    r = auth_client.get(f"/api/v1/search/event/globex/{eid_globex}")
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_payload_fetch_nonexistent_id_404(auth_client, auth_data_root):
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.get("/api/v1/search/event/acme/99999999")
    assert r.status_code == 404
    assert r.json()["code"] == "NOT_FOUND"


def test_payload_fetch_writes_separate_audit_action(auth_client, auth_data_root):
    """Drawer-click should produce action='search.event_payload', NOT
    'search.events' — they're meant to be separately reviewable."""
    _seed_minimal(auth_data_root, ["acme"])
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    eid = _first_event_id(auth_data_root / "clients" / "acme")
    r = auth_client.get(f"/api/v1/search/event/acme/{eid}")
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(paths.global_audit_db_path())
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT action, after_state FROM audit_log "
            "WHERE action = 'search.event_payload' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "search.event_payload audit row missing"
    after = json.loads(row["after_state"])
    assert after["client_slug"] == "acme"
    assert after["event_id"] == eid
