"""client_tokens.last_used_at debounce — measured from the last WRITE.

The bug: `note_token_used` compared each use with the PREVIOUS use. A buoy
heartbeating every 60 s is never 5 minutes past its previous heartbeat, so
after the first write its last_used_at froze for as long as it stayed
healthy — the liveliest tokens looked the most dead. On the ingest routes,
where the flush empties the pending samples, the same comparison found no
previous sample and wrote on EVERY request instead.

Driven through the real routes (heartbeat, ingest) on the real app; only
auth.core's clock is the test's.
"""
from __future__ import annotations

import time
import types

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.auth import core as core_auth
from apps.octo.db import connect
from apps.octo.tests.auth.test_buoy_heartbeat import _heartbeat_body, _mint_client_token

SENTINEL = "2000-01-01T00:00:00.000Z"


@pytest.fixture(autouse=True)
def _fresh_debounce_state():
    """The debounce is process state keyed by token id, and every temp
    registry numbers its tokens from 1 again."""
    def clear() -> None:
        for name in ("_pending_last_used", "_last_used_written", "_last_used_seen"):
            getattr(core_auth, name, {}).clear()

    clear()
    yield
    clear()


@pytest.fixture
def clock(monkeypatch):
    """auth.core's wall clock, under the test's control (starts at now)."""
    now = [time.time()]
    monkeypatch.setattr(core_auth, "time", types.SimpleNamespace(time=lambda: now[0]))
    return now


def test_frequent_use_still_writes_once_per_interval(clock):
    """Every 60 s for 10 minutes: due again at +300 s and +600 s from the
    last write. The sample-to-sample rule answered False to all of these."""
    token_id = 910_001
    assert core_auth.note_token_used(token_id) is True
    due = []
    for _ in range(10):
        clock[0] += 60
        due.append(core_auth.note_token_used(token_id))
    assert due == [False, False, False, False, True, False, False, False, False, True]


def test_a_burst_claims_one_write(clock):
    token_id = 910_002
    answers = [core_auth.note_token_used(token_id) for _ in range(50)]
    assert answers.count(True) == 1
    assert core_auth.last_use_seen(token_id) == clock[0]


def _last_used(token_prefix: str) -> str | None:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute(
            "SELECT last_used_at FROM client_tokens WHERE token_prefix = ?", (token_prefix,),
        ).fetchone()
    finally:
        reg.close()
    return row["last_used_at"] if row else None


def _set_last_used(token_prefix: str, value: str) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE client_tokens SET last_used_at = ? WHERE token_prefix = ?",
            (value, token_prefix),
        )
    finally:
        reg.close()


def test_heartbeating_buoy_keeps_last_used_at_moving(auth_client, clock):
    """Regression: the route-level symptom. After the first write the row is
    reset to a sentinel; four more minutes of heartbeats must not write, the
    fifth minute must."""
    slug = "acme-corp"
    token = _mint_client_token(slug)
    prefix = core_auth.token_prefix(token)
    headers = {"Authorization": f"Bearer {token}"}

    r = auth_client.post("/api/v1/buoy/heartbeat", json=_heartbeat_body(slug), headers=headers)
    assert r.status_code == 200, r.text
    assert _last_used(prefix) is not None
    _set_last_used(prefix, SENTINEL)

    for _ in range(4):
        clock[0] += 60
        auth_client.post("/api/v1/buoy/heartbeat", json=_heartbeat_body(slug), headers=headers)
    assert _last_used(prefix) == SENTINEL          # debounced, not per heartbeat

    clock[0] += 60
    auth_client.post("/api/v1/buoy/heartbeat", json=_heartbeat_body(slug), headers=headers)
    written = _last_used(prefix)
    assert written != SENTINEL and written > SENTINEL


@pytest.fixture
def ingest_client(auth_data_root):
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app
    from apps.octo.api.rate_limit import reset_limiter
    from apps.octo.api.routers import ingest as ingest_module

    reset_limiter()
    ingest_module._token_cache.clear()
    client_provisioning.create_client("acme-corp", "Acme Corp")
    with TestClient(create_app()) as tc:
        yield tc


def test_service_token_writes_once_per_interval_not_per_request(ingest_client, clock):
    token = _mint_client_token("acme-corp", kind="service", label="shim")
    prefix = core_auth.token_prefix(token)
    headers = {"Authorization": f"Bearer {token}"}

    def post(i: int) -> None:
        r = ingest_client.post(
            "/api/v1/ingest/acme-corp/events", headers=headers,
            json={"event_type": "probe", "severity": "info", "data": {"n": i}},
        )
        assert r.status_code == 202, r.text

    post(0)
    assert _last_used(prefix) is not None
    _set_last_used(prefix, SENTINEL)
    for i in range(1, 6):
        clock[0] += 30
        post(i)                                    # +150 s: not due
    assert _last_used(prefix) == SENTINEL
    clock[0] += 150
    post(99)                                       # +300 s since the write
    assert _last_used(prefix) != SENTINEL
