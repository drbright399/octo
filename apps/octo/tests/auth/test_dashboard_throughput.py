"""GET /api/v1/dashboard/throughput — aggregates events.db across scope_slugs."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest

from apps.octo import paths


def _apply_events_db_migration(client_dir: Path) -> None:
    """Mirror what lifecycle.provision() does — apply migration 002's
    @target:events section to a fresh client dir's events.db."""
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
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.executescript("\n".join(sections["events"]))
        conn.commit()
    finally:
        conn.close()


def _insert_event(client_dir: Path, received_at_iso: str, source: str = "test") -> None:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, event_type, severity, payload, payload_sha256) "
            "VALUES (?, ?, 'test.event', 'info', '{}', ?)",
            (received_at_iso, source, "a" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def _register_client(slug: str, display_name: str | None = None) -> None:
    """Insert a row into registry.db::clients so the throughput endpoint's
    '*' scope expansion picks the slug up."""
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
    """Password+TOTP sign-in. Cookies are stored on the TestClient."""
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text


def test_throughput_super_admin_sees_all_clients(auth_client, auth_data_root):
    """Super admin (scope='*') sums events across every active client."""
    # Two clients, each gets two events inside the last hour
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    bucket_t = now.replace(minute=0)
    inside = (bucket_t + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")

    for slug in ("acme", "globex"):
        _register_client(slug)
        cdir = auth_data_root / "clients" / slug
        _apply_events_db_migration(cdir)
        _insert_event(cdir, inside)
        _insert_event(cdir, inside)

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_hours": 1, "bucket_minutes": 60})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window_hours"] == 1
    assert body["bucket_minutes"] == 60
    assert body["scope_slugs"] == ["*"]
    # Window of 1 hour, 60-min buckets → exactly 1 point
    assert len(body["points"]) == 1
    # 4 inserts (2 per client × 2 clients) inside the bucket
    assert body["points"][0]["v"] == 4


def test_throughput_scoped_viewer_filters_to_their_slugs(
        auth_client, auth_data_root):
    """Viewer with scope=['acme'] sees acme events but not globex."""
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    inside = (now.replace(minute=0) + timedelta(minutes=5)) \
        .isoformat().replace("+00:00", "Z")

    for slug in ("acme", "globex"):
        _register_client(slug)
        cdir = auth_data_root / "clients" / slug
        _apply_events_db_migration(cdir)
        _insert_event(cdir, inside)

    # Provision an acme-scoped viewer
    op = auth_client.provision_operator(
        "viewer-acme", "pw1234567890",
        athena_role="viewer", scope_slugs=["acme"])
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_hours": 1, "bucket_minutes": 60})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scope_slugs"] == ["acme"]
    # Only 1 acme event in the bucket — globex's event is filtered out
    assert body["points"][0]["v"] == 1


def test_throughput_unauthenticated_is_401(auth_client):
    """No session cookie → blocked at session_identity dep."""
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/dashboard/throughput")
    assert r.status_code == 401


def test_throughput_empty_buckets_initialized_to_zero(auth_client, auth_data_root):
    """No events anywhere → endpoint still returns the full bucket grid
    with v=0 (a flat-line, not an empty response)."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    # Note: NO events inserted

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_hours": 6, "bucket_minutes": 60})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["points"]) == 6
    assert all(p["v"] == 0 for p in body["points"])


def test_throughput_window_minutes_supports_sub_hour(auth_client, auth_data_root):
    """window_minutes=15, bucket_minutes=1 → 15 one-minute buckets."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_minutes": 15, "bucket_minutes": 1})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window_minutes"] == 15
    assert body["window_hours"] == 0  # sub-hour
    assert body["bucket_minutes"] == 1
    assert len(body["points"]) == 15


def test_throughput_window_minutes_takes_precedence_over_hours(
        auth_client, auth_data_root):
    """Caller passing both: window_minutes wins."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_minutes": 30, "window_hours": 24,
                                  "bucket_minutes": 1})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window_minutes"] == 30  # not 1440 from window_hours


def test_throughput_points_sorted_oldest_first(auth_client, auth_data_root):
    """Sparkline reads left-to-right past→now → points must sort ascending."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)

    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/throughput",
                         params={"window_hours": 6, "bucket_minutes": 60})
    points = r.json()["points"]
    timestamps = [p["t"] for p in points]
    assert timestamps == sorted(timestamps)
