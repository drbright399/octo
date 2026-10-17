"""GET /api/v1/dashboard/recent-events — analyst-visible alert feed."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from apps.octo.tests.auth.test_dashboard_throughput import (
    _apply_events_db_migration,
    _login,
    _register_client,
)


def _ensure_summary_column(client_dir: Path) -> None:
    """Migration 002 doesn't have events.summary; 004 adds it. The
    helper in test_dashboard_throughput only applies 002, so we
    forward-add the column when missing."""
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        if "summary" not in cols:
            conn.execute(
                "ALTER TABLE events ADD COLUMN summary TEXT NOT NULL DEFAULT ''"
            )
            conn.commit()
    finally:
        conn.close()


def _insert_event_with_severity(
    client_dir: Path,
    *,
    received_at: str,
    severity: str,
    source: str = "wazuh",
    event_type: str = "auth.failure",
    summary: str = "",
) -> None:
    _ensure_summary_column(client_dir)
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, event_type, severity, summary, "
            " payload, payload_sha256) "
            "VALUES (?, ?, ?, ?, ?, '{}', ?)",
            (received_at, source, event_type, severity, summary, "a" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def test_recent_events_filters_below_min_severity(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event_with_severity(cdir, received_at="2026-05-14T12:00:00Z",
                                  severity="info", event_type="probe.info")
    _insert_event_with_severity(cdir, received_at="2026-05-14T12:01:00Z",
                                  severity="high", event_type="auth.brute")
    _insert_event_with_severity(cdir, received_at="2026-05-14T12:02:00Z",
                                  severity="critical", event_type="rw.attempt")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    # Default min_severity=medium → drops the info row.
    r = auth_client.get("/api/v1/dashboard/recent-events")
    assert r.status_code == 200
    titles = {e["title"] for e in r.json()["items"]}
    assert "probe.info" not in titles
    assert {"auth.brute", "rw.attempt"} <= titles


def test_recent_events_orders_newest_first(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event_with_severity(cdir, received_at="2026-05-14T08:00:00Z",
                                  severity="critical", event_type="old.event")
    _insert_event_with_severity(cdir, received_at="2026-05-14T14:00:00Z",
                                  severity="critical", event_type="new.event")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/recent-events")
    items = r.json()["items"]
    assert items[0]["title"] == "new.event"
    assert items[1]["title"] == "old.event"


def test_recent_events_carries_min_severity_param(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert_event_with_severity(cdir, received_at="2026-05-14T12:00:00Z",
                                  severity="low", event_type="low.thing")
    _insert_event_with_severity(cdir, received_at="2026-05-14T12:01:00Z",
                                  severity="critical", event_type="crit.thing")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/dashboard/recent-events?min_severity=critical")
    titles = {e["title"] for e in r.json()["items"]}
    assert titles == {"crit.thing"}


def test_recent_events_validates_bad_min_severity(auth_client, auth_data_root):
    _register_client("acme")
    _apply_events_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/recent-events?min_severity=extreme")
    assert r.status_code == 422


def test_recent_events_scoped_to_tenants_in_scope(auth_client, auth_data_root):
    """Analyst scoped to 'acme' shouldn't see events from 'globex'."""
    _register_client("acme")
    _register_client("globex")
    _apply_events_db_migration(auth_data_root / "clients" / "acme")
    _apply_events_db_migration(auth_data_root / "clients" / "globex")
    _insert_event_with_severity(
        auth_data_root / "clients" / "acme",
        received_at="2026-05-14T12:00:00Z",
        severity="high", event_type="acme.event",
    )
    _insert_event_with_severity(
        auth_data_root / "clients" / "globex",
        received_at="2026-05-14T12:00:00Z",
        severity="high", event_type="globex.event",
    )

    op = auth_client.provision_operator(
        "anlst1", "pw1234567890",
        role="analyst", athena_role="analyst",
        scope_slugs=["acme"],
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/dashboard/recent-events")
    titles = {e["title"] for e in r.json()["items"]}
    assert titles == {"acme.event"}


def test_recent_events_viewer_denied(auth_client, auth_data_root):
    _register_client("acme")
    _apply_events_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "viewer1", "pw1234567890",
        role="viewer", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/recent-events")
    assert r.status_code == 403
