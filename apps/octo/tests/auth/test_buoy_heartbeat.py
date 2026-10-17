"""Buoy heartbeat endpoint + buoy-fleet dashboard endpoint.

Slice-1 tests for the buoy fleet status pipeline:
  - POST /api/v1/buoy/heartbeat
      - bearer-auth (rejects missing/invalid)
      - body slug must match bearer's resolved slug (cross-tenant guard)
      - upsert: second heartbeat updates the same row
      - services + load + memory fields persist verbatim
      - migration 018 created the buoys table at fixture boot
  - GET  /api/v1/dashboard/buoy-fleet
      - viewer+ session-auth required
      - super_admin sees every row
      - scope-limited operator only sees rows in scope_slugs
      - health derivation (green/yellow/red/stale)
"""
from __future__ import annotations

import json
import time

from apps.octo import paths
from apps.octo.auth import core as core_auth
from apps.octo.db import connect


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mint_client_token(slug: str, kind: str = "buoy",
                        label: str = "test-buoy") -> str:
    """Insert a client_tokens row + the matching clients row, return the
    plaintext bearer. Mirrors what the operator wizard would do at
    onboarding."""
    plaintext = core_auth.generate_token()
    prefix = core_auth.token_prefix(plaintext)
    th = core_auth.hash_token(plaintext)
    reg = connect(paths.registry_db_path())
    try:
        # client row may exist already; INSERT OR IGNORE keeps it simple
        reg.execute(
            "INSERT OR IGNORE INTO clients (slug, display_name, status, kind) "
            "VALUES (?, ?, 'active', 'client')",
            (slug, slug),
        )
        reg.execute(
            "INSERT INTO client_tokens "
            "  (slug, token_hash, token_prefix, kind, label, created_by) "
            "VALUES (?, ?, ?, ?, ?, 'test')",
            (slug, th, prefix, kind, label),
        )
        reg.commit()
    finally:
        reg.close()
    return plaintext


def _heartbeat_body(slug: str, **overrides) -> dict:
    body = {
        "slug": slug,
        "hostname": f"buoy-{slug}",
        "uptime_sec": 3600,
        "interval_sec": 60,
        "load_1": 0.1,
        "load_5": 0.2,
        "load_15": 0.3,
        "mem_used_mb": 1200,
        "mem_total_mb": 4096,
        "disk_used_pct": 34,
        "services": {
            "tailscaled": "active",
            "wazuh-agent": "active",
            "opencanary": "active",
        },
        "last_event_at": "2026-05-15T18:00:00.000Z",
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------------------
# Migration 018 sanity
# ---------------------------------------------------------------------------

def test_migration_018_creates_buoys_table(auth_client):
    """Bootstrap fixture applies the chain; buoys table must exist."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT name FROM sqlite_master "
            " WHERE type='table' AND name='buoys'"
        ).fetchone()
    finally:
        reg.close()
    assert row is not None


# ---------------------------------------------------------------------------
# POST /buoy/heartbeat
# ---------------------------------------------------------------------------

def test_heartbeat_rejects_missing_bearer(auth_client):
    r = auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body("alpha"))
    assert r.status_code == 401


def test_heartbeat_rejects_invalid_bearer(auth_client):
    r = auth_client.post(
        "/api/v1/buoy/heartbeat",
        json=_heartbeat_body("alpha"),
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert r.status_code == 401


def test_heartbeat_rejects_cross_tenant_slug(auth_client):
    """Token bound to slug X may not heartbeat as slug Y."""
    token = _mint_client_token("alpha")
    r = auth_client.post(
        "/api/v1/buoy/heartbeat",
        json=_heartbeat_body("beta"),   # claims to be beta
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "ISOLATION_VIOLATION"


def test_heartbeat_accepts_valid_and_upserts(auth_client):
    token = _mint_client_token("alpha")
    body1 = _heartbeat_body("alpha", uptime_sec=100, disk_used_pct=30)
    r1 = auth_client.post("/api/v1/buoy/heartbeat", json=body1,
                          headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200, r1.text
    j1 = r1.json()
    assert j1["accepted"] is True
    assert j1["slug"] == "alpha"
    assert "next_expected_by" in j1

    # Second heartbeat — same slug, different metrics — should UPSERT,
    # not produce a duplicate row.
    body2 = _heartbeat_body("alpha", uptime_sec=200, disk_used_pct=42)
    r2 = auth_client.post("/api/v1/buoy/heartbeat", json=body2,
                          headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        rows = reg.execute(
            "SELECT slug, uptime_sec, disk_used_pct, services_json "
            "FROM buoys WHERE slug = 'alpha'"
        ).fetchall()
    finally:
        reg.close()
    assert len(rows) == 1
    assert rows[0][1] == 200       # uptime_sec was updated
    assert rows[0][2] == 42        # disk_used_pct was updated
    services = json.loads(rows[0][3])
    # Post-2026-05-19 contract: server normalizes legacy flat-shape
    # `{ unit: state_string }` into dict-of-dicts before persisting.
    assert services["tailscaled"] == {"state": "active"}


def test_heartbeat_persists_legacy_services_normalized_to_dict(auth_client):
    """Pre-2026-05-19 daemons send `{ unit: state_string }`. Server
    normalizes to the dict-of-dicts shape so the dashboard read
    endpoint sees a uniform format."""
    token = _mint_client_token("alpha")
    services_legacy = {
        "tailscaled":  "active",
        "wazuh-agent": "failed",
        "opencanary":  "active",
        "suricata":    "active",
        "pihole-FTL":  "inactive",
    }
    body = _heartbeat_body("alpha", services=services_legacy)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT services_json FROM buoys WHERE slug = 'alpha'"
        ).fetchone()
    finally:
        reg.close()
    stored = json.loads(row[0])
    assert stored == {
        unit: {"state": state} for unit, state in services_legacy.items()
    }


def test_heartbeat_persists_extended_services_shape(auth_client):
    """Post-2026-05-19 daemons send the rich dict-of-dicts shape with
    version/stat/last_activity. Server preserves documented keys,
    drops nulls, drops unknown keys."""
    token = _mint_client_token("alpha")
    services_extended = {
        "tailscaled":  {"state": "active", "version": "1.86.2",
                        "stat": None, "last_activity": "2026-05-19T14:00:00Z"},
        "wazuh-agent": {"state": "failed", "version": "4.9.2",
                        "extra_key_dropped": "yes"},
    }
    body = _heartbeat_body("alpha", services=services_extended)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT services_json FROM buoys WHERE slug = 'alpha'"
        ).fetchone()
    finally:
        reg.close()
    stored = json.loads(row[0])
    assert stored["tailscaled"] == {
        "state": "active", "version": "1.86.2",
        "last_activity": "2026-05-19T14:00:00Z",
    }
    assert stored["wazuh-agent"] == {"state": "failed", "version": "4.9.2"}


# ---------------------------------------------------------------------------
# GET /dashboard/buoy-fleet
# ---------------------------------------------------------------------------

def test_fleet_requires_auth(auth_client):
    r = auth_client.get("/api/v1/dashboard/buoy-fleet")
    assert r.status_code in (401, 403)


def test_fleet_super_admin_sees_every_buoy(auth_client):
    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    # Two heartbeats from two tenants.
    for slug in ("alpha", "beta"):
        token = _mint_client_token(slug)
        auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body(slug),
                         headers={"Authorization": f"Bearer {token}"})

    session_headers = _login_session_headers(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=session_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    seen = sorted(b["slug"] for b in body["buoys"])
    assert seen == ["alpha", "beta"]
    assert body["scope_slugs"] == ["*"]


def test_fleet_scoped_operator_sees_only_assigned(auth_client):
    op = auth_client.provision_operator(
        "bob", "Hunter22!Hunter22!",
        athena_role="analyst", scope_slugs=["alpha"],
    )
    for slug in ("alpha", "beta"):
        token = _mint_client_token(slug)
        auth_client.post("/api/v1/buoy/heartbeat",
                         json=_heartbeat_body(slug),
                         headers={"Authorization": f"Bearer {token}"})

    session_headers = _login_session_headers(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=session_headers)
    assert r.status_code == 200
    body = r.json()
    seen = [b["slug"] for b in body["buoys"]]
    assert seen == ["alpha"]              # beta filtered out
    assert body["scope_slugs"] == ["alpha"]


def test_fleet_health_derivation(auth_client):
    """Health rollup: all-green → green; one bad service + tailnet up → yellow;
    tailnet down → red. Stale is exercised in a separate test using interval
    manipulation."""
    op = auth_client.provision_operator(
        "carol", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )

    cases = [
        ("greenco", {"tailscaled": "active", "wazuh-agent": "active"}, "green"),
        ("yellowco", {"tailscaled": "active", "wazuh-agent": "failed"}, "yellow"),
        ("redco",   {"tailscaled": "inactive", "wazuh-agent": "active"}, "red"),
    ]
    for slug, services, _expected in cases:
        token = _mint_client_token(slug)
        auth_client.post(
            "/api/v1/buoy/heartbeat",
            json=_heartbeat_body(slug, services=services),
            headers={"Authorization": f"Bearer {token}"},
        )

    session_headers = _login_session_headers(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=session_headers)
    assert r.status_code == 200
    by_slug = {b["slug"]: b for b in r.json()["buoys"]}
    for slug, _services, expected in cases:
        assert by_slug[slug]["health"] == expected, slug


def test_fleet_retired_units_are_grey_not_a_fault(auth_client):
    """v0.11 B1: enablement travels with the heartbeat and is stored; a unit
    disabled on purpose is listed as retired and leaves the buoy green; an
    enabled unit that is down still makes it yellow."""
    op = auth_client.provision_operator(
        "erin", "Hunter22!Hunter22!", athena_role="super_admin", scope_slugs=["*"],
    )
    up = {"state": "active", "enabled": "enabled"}
    cases = [
        ("retiredco", {"tailscaled": up, "suricata": up,
                       "octo-forwarder": {"state": "inactive", "enabled": "disabled"}},
         "green", ["octo-forwarder"]),
        ("brokenco", {"tailscaled": up,
                      "suricata": {"state": "failed", "enabled": "enabled"},
                      "octo-forwarder": {"state": "inactive", "enabled": "masked"}},
         "yellow", ["octo-forwarder"]),
        ("static-downco", {"tailscaled": up,
                           "pihole-FTL": {"state": "inactive", "enabled": "static"}},
         "yellow", []),
    ]
    for slug, services, _h, _r in cases:
        token = _mint_client_token(slug)
        r = auth_client.post(
            "/api/v1/buoy/heartbeat", json=_heartbeat_body(slug, services=services),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, r.text
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=_login_session_headers(auth_client, op))
    by_slug = {b["slug"]: b for b in r.json()["buoys"]}
    for slug, _services, health, retired in cases:
        assert by_slug[slug]["health"] == health, slug
        assert by_slug[slug]["retired_services"] == retired, slug
    assert by_slug["retiredco"]["services"]["octo-forwarder"]["enabled"] == "disabled"


def test_fleet_a_disabled_security_unit_is_yellow_not_retired(auth_client, monkeypatch):
    """B1 hardened: the buoy saying "disabled" is not enough — wazuh-agent
    and suricata switched off with `systemctl disable --now` keep the buoy
    yellow and are not listed as retired (only the operator's list is)."""
    from apps.octo.api import buoy_health

    monkeypatch.delenv("OCTO_BUOY_RETIRED_UNITS", raising=False)
    op = auth_client.provision_operator(
        "fay", "Hunter22!Hunter22!", athena_role="super_admin", scope_slugs=["*"],
    )
    up = {"state": "active", "enabled": "enabled"}
    off = {"state": "inactive", "enabled": "disabled"}
    token = _mint_client_token("blindco")
    r = auth_client.post(
        "/api/v1/buoy/heartbeat",
        json=_heartbeat_body("blindco", services={
            "tailscaled": up, "wazuh-agent": off, "suricata": off, "octo-forwarder": off}),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=_login_session_headers(auth_client, op))
    row = {b["slug"]: b for b in r.json()["buoys"]}["blindco"]
    assert row["health"] == "yellow"
    assert row["retired_services"] == ["octo-forwarder"]
    # The rule itself: the tailnet unit can never be retired.
    assert buoy_health.retired_allowlist({"OCTO_BUOY_RETIRED_UNITS": "tailscaled, x"}) == {"x"}
    assert buoy_health.retired_allowlist({}) == {"octo-forwarder"}
    assert buoy_health.retired_allowlist({"OCTO_BUOY_RETIRED_UNITS": ""}) == frozenset()


def test_the_live_fleet_event_reads_the_dict_shape(auth_client):
    """The SSE fleet event's health used to compare dict entries with
    "active" — every current heartbeat read "red" there."""
    from apps.octo.api.routers.buoy import _derive_health

    up = {"state": "active", "enabled": "enabled"}
    assert _derive_health({"tailscaled": up, "suricata": up}) == "green"
    assert _derive_health({"tailscaled": up,
                           "octo-forwarder": {"state": "inactive",
                                              "enabled": "disabled"}}) == "green"
    assert _derive_health({"tailscaled": "active", "suricata": "failed"}) == "yellow"
    assert _derive_health({"tailscaled": {"state": "inactive"}}) == "red"


def test_fleet_health_stale_when_no_recent_heartbeat(auth_client):
    """Manually backdate last_heartbeat_at to simulate a stale buoy."""
    op = auth_client.provision_operator(
        "dora", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    token = _mint_client_token("stale-co")
    auth_client.post(
        "/api/v1/buoy/heartbeat",
        json=_heartbeat_body("stale-co", interval_sec=60),
        headers={"Authorization": f"Bearer {token}"},
    )

    # Backdate the row to ~10 minutes ago — way past 5× 60s = 5 min red threshold.
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE buoys SET last_heartbeat_at = "
            "  strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-600 seconds') "
            "WHERE slug = 'stale-co'"
        )
        reg.commit()
    finally:
        reg.close()

    session_headers = _login_session_headers(auth_client, op)
    r = auth_client.get("/api/v1/dashboard/buoy-fleet",
                        headers=session_headers)
    assert r.status_code == 200
    row = next(b for b in r.json()["buoys"] if b["slug"] == "stale-co")
    assert row["health"] == "red"
    assert row["staleness_sec"] >= 300


# ---------------------------------------------------------------------------
# Migration 021 — geographic coords (lat/lng) for the Fleet map view.
# ---------------------------------------------------------------------------

def test_heartbeat_accepts_and_persists_lat_lng(auth_client):
    """Daemon sends LAT/LNG → server persists → dashboard surfaces them."""
    token = _mint_client_token("alpha")
    body = _heartbeat_body("alpha", lat=39.099724, lng=-94.578331)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT lat, lng FROM buoys WHERE slug='alpha'"
        ).fetchone()
    finally:
        reg.close()
    assert row[0] == 39.099724
    assert row[1] == -94.578331


def test_heartbeat_without_lat_lng_keeps_them_null(auth_client):
    """Pre-021 daemons (no LAT/LNG configured) work fine — coords stay
    null and the buoy renders without a map dot."""
    token = _mint_client_token("alpha")
    body = _heartbeat_body("alpha")  # no lat/lng overrides
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT lat, lng FROM buoys WHERE slug='alpha'"
        ).fetchone()
    finally:
        reg.close()
    assert row[0] is None
    assert row[1] is None


def test_heartbeat_lat_lng_persist_across_heartbeats_without_value(auth_client):
    """If a buoy reports lat/lng once, then later heartbeats omit them
    (e.g. operator removed LAT/LNG from heartbeat.env), the stored value
    is preserved rather than nulled. COALESCE protects against accidental
    config-rollback wiping the geo data."""
    token = _mint_client_token("alpha")
    # First heartbeat carries coords.
    r1 = auth_client.post("/api/v1/buoy/heartbeat",
                          json=_heartbeat_body("alpha", lat=10.0, lng=20.0),
                          headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200
    # Second heartbeat omits coords.
    r2 = auth_client.post("/api/v1/buoy/heartbeat",
                          json=_heartbeat_body("alpha"),
                          headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT lat, lng FROM buoys WHERE slug='alpha'"
        ).fetchone()
    finally:
        reg.close()
    assert row[0] == 10.0
    assert row[1] == 20.0


def test_heartbeat_rejects_out_of_range_lat(auth_client):
    token = _mint_client_token("alpha")
    body = _heartbeat_body("alpha", lat=200.0, lng=0.0)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 422


def test_heartbeat_rejects_out_of_range_lng(auth_client):
    token = _mint_client_token("alpha")
    body = _heartbeat_body("alpha", lat=0.0, lng=-200.0)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 422


def test_dashboard_surfaces_lat_lng(auth_client):
    """The buoy-fleet dashboard endpoint returns lat/lng on each row
    so the Fleet map view can render markers without a second fetch."""
    token = _mint_client_token("alpha")
    body = _heartbeat_body("alpha", lat=39.099724, lng=-94.578331)
    r = auth_client.post("/api/v1/buoy/heartbeat", json=body,
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

    op = auth_client.provision_operator(
        "alice", "Hunter22!Hunter22!",
        athena_role="super_admin", scope_slugs=["*"],
    )
    session_headers = _login_session_headers(auth_client, op)
    r2 = auth_client.get("/api/v1/dashboard/buoy-fleet",
                         headers=session_headers)
    assert r2.status_code == 200
    row = next(b for b in r2.json()["buoys"] if b["slug"] == "alpha")
    assert row["lat"] == 39.099724
    assert row["lng"] == -94.578331


# ---------------------------------------------------------------------------
# Session login helper — mirrors what other dashboard tests do.
# ---------------------------------------------------------------------------

def _login_session_headers(auth_client, op) -> dict:
    """Run the real /login/password + /login/totp flow against a
    provisioned operator and return headers suitable for cookie-auth
    requests. Encapsulated here so each test stays tight."""
    import pyotp
    r = auth_client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge_id"]
    totp = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = auth_client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": totp,
    })
    assert r2.status_code == 200, r2.text
    # TestClient automatically picks up the Set-Cookie; no header needed.
    # We return {} so callers can pass it explicitly without an if.
    return {}
