"""The PSA writes kill switch route (slice 0 of the PSA write design).

  GET /api/v1/admin/psa/instances/{id}/settings   admin+
  PUT /api/v1/admin/psa/instances/{id}/settings   super_admin + step-up,
      audited BEFORE the write, persisted in the registry instance row

Pins: who may flip it (admin 403, super_admin without step-up 401); the body
(a real boolean and a reason, nothing else); the audit row lands before the
write and a failed audit changes nothing; a failed write gets its `_failed`
twin; the persisted value is what every reader — the enqueue paths, the
console meta, a restarted adapter — sees; a no-op flip is not audited.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.adapters.autotask.writes_switch import (
    instance_writes_enabled,
    psa_writes_enabled,
)
from apps.octo.tests.auth.test_search_events import _elevate, _login, _register_client

REASON = "Zack verified the AW03 maps on the sandbox company"


def _instance(vendor: str = "autotask", config: dict | None = None, *,
              disabled: bool = False) -> int:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        cur = conn.execute(
            "INSERT INTO adapter_instances (vendor_slug, display_name, cred_ref, "
            "instance_config_json, status, disabled_at) VALUES (?, ?, 'fixture-cred-ref', ?, ?, ?)",
            (vendor, vendor, json.dumps(config or {"poll_interval_sec": 30}),
             "disabled" if disabled else "running",
             "2026-10-05T00:00:00.000Z" if disabled else None),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _config(iid: int) -> dict:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        return json.loads(conn.execute(
            "SELECT instance_config_json FROM adapter_instances WHERE id = ?", (iid,),
        ).fetchone()[0])
    finally:
        conn.close()


def _audit_rows(action_prefix: str = "psa.instance.") -> list[tuple]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return conn.execute(
            "SELECT action, actor, target_kind, target_id, before_state, after_state, reason "
            "  FROM audit_log WHERE action LIKE ? ORDER BY id",
            (action_prefix + "%",),
        ).fetchall()
    finally:
        conn.close()


def _url(iid: int) -> str:
    return f"/api/v1/admin/psa/instances/{iid}/settings"


def _super_admin(auth_client, *, elevate: bool = True) -> dict:
    op = auth_client.provision_operator("sam-super", "pw1234567890", athena_role="super_admin")
    _login(auth_client, op)
    if elevate:
        _elevate(auth_client, op)
    return op


def test_writes_toggle_gates_admin_403_and_step_up_401(auth_client, auth_data_root):
    iid = _instance()
    admin = auth_client.provision_operator("ada-admin", "pw1234567890",
                                           role="admin", athena_role="admin")
    _login(auth_client, admin)
    r = auth_client.get(_url(iid))
    assert r.status_code == 200 and r.json()["writes_enabled"] is False
    _elevate(auth_client, admin)
    r = auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert r.status_code == 403

    analyst = auth_client.provision_operator("ann-analyst", "pw1234567890",
                                             role="analyst", athena_role="analyst")
    _login(auth_client, analyst)
    assert auth_client.get(_url(iid)).status_code == 403

    _super_admin(auth_client, elevate=False)
    r = auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"

    assert "writes_enabled" not in _config(iid)
    assert _audit_rows() == []
    assert psa_writes_enabled() is False


@pytest.mark.parametrize("body", [
    {"writes_enabled": True},                                   # no reason
    {"writes_enabled": True, "reason": "  "},                   # blank reason
    {"writes_enabled": "true", "reason": REASON},               # not a boolean
    {"writes_enabled": 1, "reason": REASON},
    {"writes_enabled": True, "reason": REASON, "kinds": ["create_ticket"]},  # slice 1, not yet
])
def test_writes_toggle_body_is_strict(auth_client, auth_data_root, body):
    iid = _instance()
    _super_admin(auth_client)
    r = auth_client.put(_url(iid), json=body)
    assert r.status_code == 422, r.text
    assert "writes_enabled" not in _config(iid)
    assert _audit_rows() == []


def test_writes_toggle_audited_then_persisted_and_seen_everywhere(auth_client, auth_data_root):
    _register_client("acme")
    iid = _instance()
    op = _super_admin(auth_client)

    r = auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert r.status_code == 200, r.text
    assert r.json()["writes_enabled"] is True
    assert _config(iid) == {"poll_interval_sec": 30, "writes_enabled": True}
    rows = _audit_rows()
    assert len(rows) == 1
    action, actor, target_kind, target_id, before, after, reason = rows[0]
    assert action == "psa.instance.writes_toggle"
    assert actor == str(op["id"]) and target_kind == "adapter_instance"
    assert target_id == str(iid) and reason == REASON
    assert json.loads(before)["writes_enabled"] is False
    assert json.loads(after)["writes_enabled"] is True
    # Every reader sees the persisted switch.
    assert instance_writes_enabled(iid) is True and psa_writes_enabled() is True
    assert auth_client.get("/api/v1/tickets/_meta").json() == {"psa_writes_enabled": True}

    # Same value again: nothing to write, nothing audited.
    r = auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert r.status_code == 200 and len(_audit_rows()) == 1

    # And off again.
    r = auth_client.put(_url(iid), json={"writes_enabled": False, "reason": "rolling back"})
    assert r.status_code == 200 and r.json()["writes_enabled"] is False
    assert _config(iid)["writes_enabled"] is False
    assert [row[0] for row in _audit_rows()] == ["psa.instance.writes_toggle"] * 2
    assert psa_writes_enabled() is False
    r = auth_client.post("/api/v1/tickets/acme", json={"title": "x", "push_to_autotask": True})
    assert r.status_code == 409 and r.json()["code"] == "PSA_WRITES_DISABLED"


def test_writes_toggle_failed_audit_changes_nothing(auth_client, auth_data_root, monkeypatch):
    from apps.octo.auth import audit

    iid = _instance()
    _super_admin(auth_client)

    def refuse(*_a, **_k):
        raise RuntimeError("audit chain unavailable")

    monkeypatch.setattr(audit, "append", refuse)
    with pytest.raises(RuntimeError):
        auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert "writes_enabled" not in _config(iid)
    assert psa_writes_enabled() is False


def test_writes_toggle_failed_write_has_its_failed_twin(auth_client, auth_data_root, monkeypatch):
    from apps.octo.api.routers import admin_psa

    iid = _instance()
    _super_admin(auth_client)

    def broken(*_a, **_k):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(admin_psa, "update_instance_config", broken)
    with pytest.raises(sqlite3.OperationalError):
        auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert [r[0] for r in _audit_rows()] == [
        "psa.instance.writes_toggle", "psa.instance.writes_toggle_failed"]
    assert "writes_enabled" not in _config(iid)


def test_writes_toggle_only_for_an_active_psa_instance(auth_client, auth_data_root):
    other = _instance("datto")
    gone = _instance("autotask", disabled=True)
    _super_admin(auth_client)
    body = {"writes_enabled": True, "reason": REASON}
    assert auth_client.put(_url(other), json=body).status_code == 404
    assert auth_client.put(_url(9999), json=body).status_code == 404
    assert auth_client.put(_url(gone), json=body).status_code == 409
    assert _audit_rows() == []


def test_writes_toggle_applies_to_the_running_adapter(auth_client, auth_data_root):
    """The route tells the live adapter at once (OFF stops its pusher)."""
    iid = _instance()

    class _Live:
        def __init__(self) -> None:
            self.applied: list[bool] = []
            self.pusher_running = False

        def apply_writes_enabled(self, enabled: bool) -> bool:
            self.applied.append(enabled)
            self.pusher_running = enabled
            return True

    live = _Live()

    class _Manager:
        def running_adapter(self, instance_id: int):
            return live if instance_id == iid else None

    auth_client.app.state.instance_manager = _Manager()
    _super_admin(auth_client)
    r = auth_client.put(_url(iid), json={"writes_enabled": True, "reason": REASON})
    assert r.json()["applied_live"] is True and r.json()["pusher_running"] is True
    r = auth_client.put(_url(iid), json={"writes_enabled": False, "reason": "stop it"})
    assert r.json()["applied_live"] is True and r.json()["pusher_running"] is False
    assert live.applied == [True, False]


def test_concurrent_identical_flips_audit_write_and_apply_once(auth_client, auth_data_root):
    """A double-submitted "switch on" (two PUTs at once on the threadpool):
    the read-compare-audit-write-apply sequence is serialised, so the second
    PUT sees the first one's write and is the no-op it should be — one audit
    row, one write, one apply (one pusher)."""
    import threading
    import time

    from apps.octo.api.routers import admin_psa

    iid = _instance()

    class _Live:
        def __init__(self) -> None:
            self.applied: list[bool] = []
            self.pusher_running = False

        def apply_writes_enabled(self, enabled: bool) -> bool:
            self.applied.append(enabled)
            self.pusher_running = enabled
            return True

    live = _Live()

    class _Manager:
        def running_adapter(self, instance_id: int):
            return live if instance_id == iid else None

    auth_client.app.state.instance_manager = _Manager()
    _super_admin(auth_client)
    responses: list = []

    def put() -> None:
        responses.append(auth_client.put(
            _url(iid), json={"writes_enabled": True, "reason": REASON}))

    # Hold the route's lock so both requests are in flight before either runs.
    admin_psa._SETTINGS_LOCK.acquire()
    try:
        threads = [threading.Thread(target=put) for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(0.3)
        assert _audit_rows() == [] and responses == []      # both waiting
    finally:
        admin_psa._SETTINGS_LOCK.release()
    for t in threads:
        t.join(timeout=30)

    assert [r.status_code for r in responses] == [200, 200]
    assert all(r.json()["writes_enabled"] is True for r in responses)
    assert [row[0] for row in _audit_rows()] == ["psa.instance.writes_toggle"]
    assert live.applied == [True]
    assert _config(iid)["writes_enabled"] is True
