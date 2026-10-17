"""Coverage for GET /api/v1/agent/status (Task #119e)."""
from __future__ import annotations

from apps.octo.tests.auth.test_search_events import _login


class _StubWorker:
    """Minimal stand-in exposing the status() contract the endpoint uses."""
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def status(self) -> dict:
        return self._payload


def test_status_disabled_when_no_worker(auth_client):
    # create_app() in tests doesn't wire the worker (OCTO_TRIAGE_WORKER
    # unset), so app.state has no triage_worker → 'disabled' / offline.
    op = auth_client.provision_operator("alice", "pw1234567890",
                                        athena_role="analyst")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "disabled"
    assert body["online"] is False
    assert body["calibration_state"] == "uncalibrated"  # advisory by default


def test_status_reflects_running_worker(auth_client):
    auth_client.app.state.triage_worker = _StubWorker({
        "state": "idle", "online": True,
        "last_tick_at": "2026-06-01T19:00:00.000000Z",
        "last_run": {"processed": 42, "by_disposition": {"noise": 40, "escalate": 2}},
        "last_error": None, "consecutive_errors": 0, "interval_seconds": 15,
    })
    op = auth_client.provision_operator("alice", "pw1234567890",
                                        athena_role="analyst")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "idle"
    assert body["online"] is True
    assert body["last_run"]["processed"] == 42
    assert body["last_run"]["by_disposition"]["escalate"] == 2


def test_status_error_state_surfaces(auth_client):
    auth_client.app.state.triage_worker = _StubWorker({
        "state": "error", "online": True,
        "last_tick_at": "2026-06-01T19:00:00.000000Z",
        "last_run": None, "last_error": "database is locked",
        "consecutive_errors": 3, "interval_seconds": 15,
    })
    op = auth_client.provision_operator("alice", "pw1234567890",
                                        athena_role="analyst")
    _login(auth_client, op)
    body = auth_client.get("/api/v1/agent/status").json()
    assert body["state"] == "error"
    assert body["consecutive_errors"] == 3
    assert body["last_error"] == "database is locked"


def test_dev_synthetic_route_absent_outside_dev(auth_client):
    # The dev synthetic-traffic router is only mounted on a dev data-root
    # with OCTO_DEV_SYNTHETIC=1. The test app is neither, so the route must
    # not exist at all (prod-gating proof).
    op = auth_client.provision_operator("alice", "pw1234567890",
                                        athena_role="analyst")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/dev/synthetic-traffic")
    assert r.status_code == 404, r.text


def test_status_requires_analyst_tier(auth_client):
    # Viewer (tier 1) is below analyst (tier 2) → denied. Set BOTH the
    # OCTO role and the Console role to viewer (mirrors the activity-feed
    # viewer-denied test) so the tier actually resolves below analyst.
    op = auth_client.provision_operator("vic", "pw1234567890",
                                        role="viewer", athena_role="viewer")
    _login(auth_client, op)
    r = auth_client.get("/api/v1/agent/status")
    assert r.status_code == 403, r.text
