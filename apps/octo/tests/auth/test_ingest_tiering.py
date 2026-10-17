"""The ingest routes file every event as a signal or as telemetry.

Real router, real bearer tokens, real per-tenant files. Pins:
  * the buoy forwarder's Pi-hole shape: an answered lookup → telemetry.db,
    a blocked one → events.db (its shifted status_label ignored);
  * Suricata metadata → telemetry, a Suricata alert → signal; Wazuh via the
    alerts path is a signal and keeps its idempotency (replay = idempotent);
  * the /events path has no dedup (identical telemetry repeats and counts);
  * freshness still sees buoy traffic that is all telemetry — in process and,
    after a restart, from telemetry.db;
  * a telemetry-store failure never fails the request (202, events.db).
"""
from __future__ import annotations

import os
import sqlite3

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.instances import freshness
from apps.octo.tests.auth.test_ingest import _mint, _post, _wazuh_alert

SLUG = "acme-corp"


@pytest.fixture
def client(auth_data_root):
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.api.routers import ingest as ingest_module
    from apps.octo.ingest import sink, telemetry

    reset_limiter()
    ingest_module._token_cache.clear()
    telemetry.reset_schema_cache()
    sink.reset_telemetry_fallbacks()
    freshness.reset()
    client_provisioning.create_client(SLUG, "Acme Corp", kind="client")
    with TestClient(create_app()) as tc:
        yield tc
    freshness.reset()


def _pihole(status: int, label: str, domain: str = "example.test") -> dict:
    """What buoy-forwarder v2's pihole adapter posts."""
    return {
        "event_type": "pihole.query",
        "severity": "low" if "blocked" in label else "info",
        "source_host": "buoy-acme-1",
        "data": {
            "raw_query": {"id": 7, "timestamp": 1759140000, "type": 1, "status": status,
                          "domain": domain, "client": "192.0.2.10", "client_name": None,
                          "forward": "198.51.100.53", "status_label": label},
            "_buoy": "buoy-acme-1", "_adapter": "pihole", "_adapter_version": "1.0",
        },
    }


def _count(name: str, table: str) -> int:
    path = paths.client_db_path(SLUG, name)
    if not path.exists():
        return 0
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_pihole_answered_is_telemetry_blocked_is_a_signal(client):
    token = _mint(SLUG)
    # Status 2 = FORWARDED (the forwarder labels it "blocked-gravity").
    r1 = _post(client, f"/{SLUG}/events", token, _pihole(2, "blocked-gravity"))
    # Status 1 = GRAVITY block (the forwarder labels it "allowed").
    r2 = _post(client, f"/{SLUG}/events", token, _pihole(1, "allowed", "ads.example.test"))
    assert (r1.status_code, r2.status_code) == (202, 202)
    assert r1.json()["tier"] == "telemetry" and r2.json()["tier"] == "signal"
    assert _count("telemetry", "telemetry_raw") == 1
    assert _count("events", "events") == 1


def test_suricata_metadata_and_alerts(client):
    token = _mint(SLUG)
    dns = {"event_type": "suricata.dns", "severity": "info", "source_host": "buoy-acme-1",
           "data": {"raw_eve": {"event_type": "dns", "src_ip": "192.0.2.10",
                                "dns": {"type": "query", "rrname": "example.test"}}}}
    alert = {"event_type": "suricata.alert", "severity": "high", "source_host": "buoy-acme-1",
             "data": {"raw_eve": {"event_type": "alert", "alert": {"severity": 1}}}}
    assert _post(client, f"/{SLUG}/events", token, dns).json()["tier"] == "telemetry"
    assert _post(client, f"/{SLUG}/events", token, alert).json()["tier"] == "signal"
    # The /events path has no dedup: identical telemetry repeats and counts.
    assert _post(client, f"/{SLUG}/events", token, dns).json()["tier"] == "telemetry"
    assert _count("telemetry", "telemetry_raw") == 2
    conn = sqlite3.connect(paths.client_db_path(SLUG, "telemetry"))
    try:
        assert conn.execute("SELECT SUM(count) FROM telemetry_hourly").fetchone()[0] == 2
    finally:
        conn.close()


def test_wazuh_alerts_stay_signals_and_idempotent(client):
    token = _mint(SLUG)
    first = _post(client, f"/{SLUG}/wazuh/alerts", token, {"payload": _wazuh_alert()})
    again = _post(client, f"/{SLUG}/wazuh/alerts", token, {"payload": _wazuh_alert()})
    assert first.status_code == again.status_code == 202
    assert again.json()["idempotent"] is True
    assert again.json()["event_id"] == first.json()["event_id"]
    assert _count("events", "events") == 1
    assert _count("telemetry", "telemetry_raw") == 0


def test_freshness_sees_telemetry_only_traffic(client):
    token = _mint(SLUG)
    assert _post(client, f"/{SLUG}/events", token, _pihole(3, "forwarded-cached")).status_code == 202
    assert freshness.tenant_last_event(SLUG) is not None
    assert freshness.first_posted_telemetry_id(SLUG) == 1
    assert freshness.first_posted_event_id(SLUG) is None
    # After a restart: memory is gone, the telemetry store still answers.
    freshness.reset()
    stored = freshness.tenant_last_event(SLUG)
    assert stored is not None and stored.endswith("Z")
    assert freshness.newest_stored_event(SLUG, source="buoy:test-forwarder") == stored
    assert freshness.newest_stored_event(SLUG, source="buoy:someone-else") is None


def test_a_telemetry_store_failure_never_fails_the_request(client):
    token = _mint(SLUG)
    tdb = paths.client_db_path(SLUG, "telemetry")
    os.chmod(tdb, 0o444)
    try:
        r = _post(client, f"/{SLUG}/events", token, _pihole(2, "x"))
    finally:
        os.chmod(tdb, 0o644)
    assert r.status_code == 202, r.text
    assert r.json()["tier"] == "signal"          # stored in events.db instead
    assert _count("events", "events") == 1
