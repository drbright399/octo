"""GET /api/v1/dashboard/devices-attention — host-attention ranking."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from apps.octo.tests.auth.test_dashboard_throughput import (
    _apply_events_db_migration,
    _login,
    _register_client,
)


def _now_iso() -> str:
    """ISO-8601 UTC, second-precision. Computed at call-time so the
    'fresh' default never ages out of the dashboard's 24h lookback
    window as the calendar advances (previous hardcoded default
    rotted on 2026-05-15)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _insert(
    cdir: Path, *, host: str, severity: str, event_type: str,
    received_at: str | None = None,
) -> None:
    if received_at is None:
        received_at = _now_iso()
    conn = sqlite3.connect(cdir / "events.db")
    try:
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256) "
            "VALUES (?, 'wazuh', ?, ?, ?, '{}', ?)",
            (received_at, host, event_type, severity, "a" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def test_devices_attention_ranks_critical_first(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert(cdir, host="srv-db-01", severity="medium", event_type="cpu.spike")
    _insert(cdir, host="srv-db-01", severity="medium", event_type="cpu.spike")
    _insert(cdir, host="srv-web-02", severity="critical", event_type="auth.brute_force")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.get("/api/v1/dashboard/devices-attention")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    # critical row ranks first regardless of count
    assert items[0]["host"] == "srv-web-02"
    assert items[0]["severity"] == "critical"
    assert items[1]["host"] == "srv-db-01"
    assert items[1]["severity"] == "medium"


def test_devices_attention_reason_carries_event_types(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    _insert(cdir, host="srv-1", severity="high", event_type="auth.failure")
    _insert(cdir, host="srv-1", severity="high", event_type="ids.malware")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/devices-attention")
    item = r.json()["items"][0]
    assert "2 high events" in item["reason"]
    assert "auth.failure" in item["reason"]
    assert "ids.malware" in item["reason"]


def test_devices_attention_drops_null_hosts(auth_client, auth_data_root):
    """Events without a source_host shouldn't surface."""
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    conn = sqlite3.connect(cdir / "events.db")
    try:
        # Two with no host, one with.
        conn.execute(
            "INSERT INTO events "
            "(received_at, source, event_type, severity, "
            " payload, payload_sha256) "
            "VALUES ('2026-05-14T15:00:00Z', 'wazuh', 'fleet.event', "
            "        'critical', '{}', ?)",
            ("a" * 64,),
        )
        conn.commit()
    finally:
        conn.close()
    _insert(cdir, host="srv-1", severity="high", event_type="x.y")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/devices-attention")
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["host"] == "srv-1"


def test_devices_attention_lookback_filter(auth_client, auth_data_root):
    _register_client("acme")
    cdir = auth_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    # Old event — outside default 24h window
    _insert(cdir, host="srv-old", severity="critical",
            event_type="ancient.alert",
            received_at="2025-01-01T00:00:00Z")
    _insert(cdir, host="srv-fresh", severity="high",
            event_type="fresh.alert")

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/devices-attention")
    hosts = {it["host"] for it in r.json()["items"]}
    assert "srv-old" not in hosts
    assert "srv-fresh" in hosts


def test_devices_attention_viewer_denied(auth_client, auth_data_root):
    _register_client("acme")
    _apply_events_db_migration(auth_data_root / "clients" / "acme")
    op = auth_client.provision_operator(
        "viewer1", "pw1234567890",
        role="viewer", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/devices-attention")
    assert r.status_code == 403
