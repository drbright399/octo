"""Ingestion endpoints — client-token bearer auth + persistence.

Covers the ADR-0003 fresh-build ingest surface (the router the legacy ingest service
service is retired in favor of):

  POST /api/v1/ingest/{slug}/events                — buoy-forwarder contract
  POST /api/v1/ingest/{slug}/{source_type}/alerts  — wazuh-shim contract

  - bearer gates: missing → AUTH_MISSING, garbage → AUTH_INVALID,
    cross-tenant → ISOLATION_VIOLATION, disabled → CLIENT_DISABLED,
    offboarded → CLIENT_NOT_FOUND (existence hidden), oversize → 413
  - wazuh alert lands: event row w/ event_type='wazuh.alert', summary,
    severity from rule.level, source labeled from the token
  - idempotent replay: same envelope → idempotent=true, same event_id,
    no duplicate row
  - generic event lands with caller-declared event_type preserved
  - unprovisioned client (registry row, no events.db) → CLIENT_NOT_FOUND
  - token TTL cache: revocation takes effect late on a hot token (documented
    trade), immediately on a cold one
"""
from __future__ import annotations

import json

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.auth import core as core_auth
from apps.octo.db import connect


SLUG = "acme-corp"
OTHER = "globex"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _mint(slug: str, label: str = "test-forwarder") -> str:
    plaintext = core_auth.generate_token()
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
            "VALUES (?, ?, ?, 'buoy', ?, 'test')",
            (slug, core_auth.hash_token(plaintext),
             core_auth.token_prefix(plaintext), label),
        )
        reg.commit()
    finally:
        reg.close()
    return plaintext


def _set_status(slug: str, status: str) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET status = ? WHERE slug = ?",
                    (status, slug))
        reg.commit()
    finally:
        reg.close()


def _event_rows(slug: str) -> list:
    db = connect(paths.client_db_path(slug, "events"), read_only=True)
    try:
        return db.execute(
            "SELECT id, source, event_type, severity, payload FROM events "
            "ORDER BY id"
        ).fetchall()
    finally:
        db.close()


def _wazuh_alert(alert_id: str = "1757601000.12345") -> dict:
    return {
        "id": alert_id,
        "timestamp": "2026-09-12T13:00:00.000+0000",
        "rule": {
            "level": 10,
            "id": "5720",
            "description": "Multiple authentication failures",
            "groups": ["syslog", "authentication_failures"],
        },
        "agent": {"name": "buoy-acme", "labels": {"_octo_tenant_slug": SLUG}},
        "data": {"srcip": "203.0.113.9"},
    }


@pytest.fixture
def ingest_client(auth_data_root):
    """TestClient over a bootstrapped tmp data root, with a fresh token
    cache and rate limiter, and one provisioned tenant."""
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.api.routers import ingest as ingest_module

    reset_limiter()
    ingest_module._token_cache.clear()

    client_provisioning.create_client(SLUG, "Acme Corp")
    with TestClient(create_app()) as tc:
        yield tc


def _post(tc, path, token, body):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return tc.post(f"/api/v1/ingest{path}", headers=headers, json=body)


# ---------------------------------------------------------------------------
# Auth gates
# ---------------------------------------------------------------------------

def test_missing_bearer_is_401(ingest_client):
    r = _post(ingest_client, f"/{SLUG}/events", None,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_MISSING"


def test_empty_bearer_credential_is_401_not_500(ingest_client):
    # "Authorization: Bearer " (scheme, no credential) used to IndexError
    # inside the rate-limit middleware → 500 on ANY route, pre-auth.
    from starlette.requests import Request
    from apps.octo.api.rate_limit import get_limiter  # noqa: F401
    from apps.octo.api import rate_limit

    scope = {"type": "http", "method": "POST", "path": "/x",
             "headers": [(b"authorization", b"Bearer ")],
             "client": ("198.51.100.7", 1234)}
    mw = rate_limit.RateLimitMiddleware.__new__(rate_limit.RateLimitMiddleware)
    assert mw._caller_key(Request(scope)) == "ip:198.51.100.7"

    r = ingest_client.post(
        f"/api/v1/ingest/{SLUG}/events",
        headers={"Authorization": "Bearer "},
        json={"event_type": "t.e", "data": {}},
    )
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_MISSING"


def test_garbage_bearer_is_401(ingest_client):
    r = _post(ingest_client, f"/{SLUG}/events", "not-a-real-token",
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_INVALID"


def test_cross_tenant_token_is_403(ingest_client):
    client_provisioning.create_client(OTHER, "Globex")
    token_other = _mint(OTHER)
    r = _post(ingest_client, f"/{SLUG}/events", token_other,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_disabled_client_is_423(ingest_client):
    token = _mint(SLUG)
    _set_status(SLUG, "disabled")
    r = _post(ingest_client, f"/{SLUG}/events", token,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 423
    assert r.json()["code"] == "CLIENT_DISABLED"


def test_offboarded_client_hides_existence_404(ingest_client):
    token = _mint(SLUG)
    _set_status(SLUG, "offboarded")
    r = _post(ingest_client, f"/{SLUG}/events", token,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 404
    assert r.json()["code"] == "CLIENT_NOT_FOUND"


def test_oversize_content_length_is_413(ingest_client):
    token = _mint(SLUG)
    r = ingest_client.post(
        f"/api/v1/ingest/{SLUG}/events",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Length": "2000000",
            "Content-Type": "application/json",
        },
        content=b"{}",
    )
    assert r.status_code == 413
    assert r.json()["code"] == "PAYLOAD_TOO_LARGE"


def test_unprovisioned_client_is_404(ingest_client):
    # registry row + token exist, but no events.db was provisioned
    token = _mint("no-dbs-yet")
    r = _post(ingest_client, "/no-dbs-yet/events", token,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 404
    assert r.json()["code"] == "CLIENT_NOT_FOUND"


# ---------------------------------------------------------------------------
# Wazuh alerts path (shim contract)
# ---------------------------------------------------------------------------

def test_wazuh_alert_ingests(ingest_client):
    token = _mint(SLUG, label="wazuh-shim test")
    r = _post(ingest_client, f"/{SLUG}/wazuh/alerts", token,
              {"payload": _wazuh_alert()})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["idempotent"] is False
    assert isinstance(body["event_id"], int)
    assert "authentication failures" in (body["summary"] or "").lower()

    rows = _event_rows(SLUG)
    assert len(rows) == 1
    assert rows[0]["event_type"] == "wazuh.alert"
    assert rows[0]["source"] == "buoy:wazuh-shim test"
    payload = json.loads(rows[0]["payload"])
    assert payload["rule"]["id"] == "5720"


def test_wazuh_alert_replay_is_idempotent(ingest_client):
    token = _mint(SLUG, label="wazuh-shim test")
    alert = {"payload": _wazuh_alert()}
    r1 = _post(ingest_client, f"/{SLUG}/wazuh/alerts", token, alert)
    r2 = _post(ingest_client, f"/{SLUG}/wazuh/alerts", token, alert)
    assert r1.status_code == 202 and r2.status_code == 202
    assert r2.json()["idempotent"] is True
    assert r2.json()["event_id"] == r1.json()["event_id"]
    assert len(_event_rows(SLUG)) == 1


def test_distinct_alerts_both_land(ingest_client):
    token = _mint(SLUG, label="wazuh-shim test")
    _post(ingest_client, f"/{SLUG}/wazuh/alerts", token,
          {"payload": _wazuh_alert("a1")})
    _post(ingest_client, f"/{SLUG}/wazuh/alerts", token,
          {"payload": _wazuh_alert("a2")})
    assert len(_event_rows(SLUG)) == 2


def test_unsupported_source_type_is_422(ingest_client):
    token = _mint(SLUG)
    r = _post(ingest_client, f"/{SLUG}/splunk/alerts", token,
              {"payload": {"anything": 1}})
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_FAILED"


# ---------------------------------------------------------------------------
# Generic events path (buoy-forwarder contract)
# ---------------------------------------------------------------------------

def test_generic_event_preserves_event_type(ingest_client):
    token = _mint(SLUG, label="forwarder-v2 test")
    r = _post(
        ingest_client, f"/{SLUG}/events", token,
        {
            "event_type": "suricata.alert",
            "severity": "low",
            "source_host": "sensor-1",
            "data": {"_adapter": "suricata", "raw_eve": {"event_type": "alert"}},
        },
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["ok"] is True and body["tier"] == "signal"
    rows = _event_rows(SLUG)
    assert len(rows) == 1
    assert body["event_id"] == rows[0]["id"]
    assert rows[0]["event_type"] == "suricata.alert"
    assert rows[0]["severity"] == "low"
    assert rows[0]["source"] == "buoy:forwarder-v2 test"
    payload = json.loads(rows[0]["payload"])
    assert payload["_adapter"] == "suricata"


def test_a_decoys_tried_secret_is_never_stored(ingest_client):
    """Tier Black R6: someone may type a REAL password into a decoy that
    looks like a real server. An older forwarder still sends it — the route
    stores its length only; the tried user name is kept."""
    token = _mint(SLUG, label="forwarder-v2 test")
    secret = "Winter2026!fixture"
    r = _post(ingest_client, f"/{SLUG}/events", token, {
        "event_type": "opencanary.ssh", "severity": "high", "source_host": "buoy-1",
        "data": {"raw_canary": {"logtype": 4002, "src_host": "192.0.2.31",
                                "logdata": {"honeypot_user_attempt": "admin",
                                            "honeypot_pw_attempt": secret}}}})
    assert r.status_code == 202, r.text
    (row,) = _event_rows(SLUG)
    assert secret not in row["payload"]
    logdata = json.loads(row["payload"])["raw_canary"]["logdata"]
    assert logdata == {"honeypot_user_attempt": "admin",
                       "honeypot_pw_attempt": f"[redacted: {len(secret)} chars]"}


def _telemetry_rows(slug: str) -> list:
    db = connect(paths.client_db_path(slug, "telemetry"), read_only=True)
    try:
        return db.execute(
            "SELECT id, source, event_type, severity, domain, payload FROM telemetry_raw "
            "ORDER BY id"
        ).fetchall()
    finally:
        db.close()


def test_generic_dns_telemetry_goes_to_the_telemetry_store(ingest_client):
    """Answered DNS (suricata.dns metadata) is TELEMETRY: telemetry.db, with
    its event_type preserved, nothing in events.db."""
    token = _mint(SLUG, label="forwarder-v2 test")
    r = _post(
        ingest_client, f"/{SLUG}/events", token,
        {
            "event_type": "suricata.dns",
            "severity": "info",
            "source_host": "sensor-1",
            "data": {"_adapter": "suricata", "query": "example.com"},
        },
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["tier"] == "telemetry" and body["event_id"] is None
    assert _event_rows(SLUG) == []
    [row] = _telemetry_rows(SLUG)
    assert body["telemetry_id"] == row["id"]
    assert (row["source"], row["event_type"], row["severity"], row["domain"]) == (
        "buoy:forwarder-v2 test", "suricata.dns", "info", "example.com")
    assert json.loads(row["payload"])["_adapter"] == "suricata"


# ---------------------------------------------------------------------------
# Token cache semantics (documented trade)
# ---------------------------------------------------------------------------

def test_revocation_is_immediate_for_cold_token(ingest_client):
    token = _mint(SLUG)
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE client_tokens SET revoked_at = '2026-01-01T00:00:00Z'")
        reg.commit()
    finally:
        reg.close()
    r = _post(ingest_client, f"/{SLUG}/events", token,
              {"event_type": "t.e", "data": {}})
    assert r.status_code == 401


def test_revocation_lags_within_ttl_for_hot_token(ingest_client):
    """A cache-hot token stays valid up to the TTL after revocation — the
    documented trade for not re-running PBKDF2 per request. Client
    lifecycle gates (disable/offboard) are NOT cached and cut immediately."""
    token = _mint(SLUG)
    ok = _post(ingest_client, f"/{SLUG}/events", token,
               {"event_type": "t.e", "data": {}})
    assert ok.status_code == 202
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE client_tokens SET revoked_at = '2026-01-01T00:00:00Z'")
        reg.commit()
    finally:
        reg.close()
    still = _post(ingest_client, f"/{SLUG}/events", token,
                  {"event_type": "t.e", "data": {}})
    assert still.status_code == 202  # hot-cache window
    # the hard stop still works instantly:
    _set_status(SLUG, "disabled")
    cut = _post(ingest_client, f"/{SLUG}/events", token,
                {"event_type": "t.e", "data": {}})
    assert cut.status_code == 423
