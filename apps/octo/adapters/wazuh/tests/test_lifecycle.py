"""WazuhSourceAdapter lifecycle wiring — start / stop / smoke_test / health.

Covers the wire-up between the adapter, the WazuhClient (mocked), the
WazuhPoller, and the IngestSink. Real-Wazuh HTTP is mocked at the
client-factory boundary.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.adapters.wazuh.client import (
    WazuhAuthError,
    WazuhClient,
    WazuhClientError,
    WazuhConfig,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeClient:
    """Stands in for WazuhClient. Behavior driven by constructor kwargs."""

    def __init__(
        self,
        config: WazuhConfig,
        *,
        auth_outcome: str = "ok",  # "ok" | "401" | "transport"
        batches: list[list[dict[str, Any]]] | None = None,
    ) -> None:
        self.config = config
        self._auth_outcome = auth_outcome
        self._batches = list(batches or [])
        self.auth_calls = 0
        self.fetch_cursors: list[str] = []

    def authenticate(self) -> str:
        self.auth_calls += 1
        if self._auth_outcome == "401":
            raise WazuhAuthError("rejected by stub")
        if self._auth_outcome == "transport":
            raise WazuhClientError("network down (stub)")
        return "stub-jwt-token"

    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.fetch_cursors.append(since_iso)
        if not self._batches:
            return []
        return self._batches.pop(0)


def _client_factory(outcome: str = "ok"):
    """Return a factory that produces _FakeClients with the given outcome."""
    def factory(config: WazuhConfig) -> WazuhClient:  # type: ignore[return-value]
        return _FakeClient(config, auth_outcome=outcome)  # type: ignore[return-value]
    return factory


class _RecorderSink:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, CanonicalEvent]] = []
    def ingest(self, tenant_slug: str, source: str, event: CanonicalEvent):
        self.calls.append((tenant_slug, source, event))


VALID_CREDS = {
    "WAZUH_MANAGER_URL": "https://wazuh.test:55000",
    "WAZUH_API_KEY": "secret-api-password",
    "WAZUH_INDEXER_URL": "https://wazuh.test:9200",
    "WAZUH_INDEXER_USER": "admin",
    "WAZUH_INDEXER_PASSWORD": "indexer-pass",
}


# ---------------------------------------------------------------------------
# smoke_test
# ---------------------------------------------------------------------------

def test_smoke_test_returns_ok_when_authenticate_succeeds():
    adapter = WazuhSourceAdapter(client_factory=_client_factory("ok"))
    r = adapter.smoke_test(VALID_CREDS)
    assert r.ok is True
    assert "reachable" in r.message.lower() or "valid" in r.message.lower()


def test_smoke_test_returns_failure_when_credentials_rejected():
    adapter = WazuhSourceAdapter(client_factory=_client_factory("401"))
    r = adapter.smoke_test(VALID_CREDS)
    assert r.ok is False
    assert "rejected" in r.message.lower() or "credentials" in r.message.lower()


def test_smoke_test_returns_failure_when_transport_fails():
    adapter = WazuhSourceAdapter(client_factory=_client_factory("transport"))
    r = adapter.smoke_test(VALID_CREDS)
    assert r.ok is False
    assert "could not reach" in r.message.lower()


def test_smoke_test_requires_manager_url_field():
    adapter = WazuhSourceAdapter()
    r = adapter.smoke_test({"WAZUH_API_KEY": "x"})
    assert r.ok is False
    assert "MANAGER_URL" in r.message


def test_smoke_test_requires_api_key_field():
    """API key is the second required field — wizard must collect both."""
    adapter = WazuhSourceAdapter(client_factory=_client_factory("ok"))
    r = adapter.smoke_test({"WAZUH_MANAGER_URL": "https://wazuh.test:55000"})
    assert r.ok is False
    assert "API_KEY" in r.message


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_constructs_poller_and_schedules_task():
    """start() with valid config builds the poller + schedules its loop."""
    sink = _RecorderSink()
    adapter = WazuhSourceAdapter(
        sink=sink,
        client_factory=_client_factory("ok"),
    )
    adapter.start({
        **VALID_CREDS,
        "default_tenant_slug": "acme-msp",
        "poll_interval_sec": 0.05,
    })
    # Internal state visible
    assert adapter._poller is not None
    assert adapter._default_tenant_slug == "acme-msp"
    # Let the loop spin a couple of times (empty batches → no ingest)
    await asyncio.sleep(0.15)
    await adapter._poller.stop()


@pytest.mark.asyncio
async def test_start_is_idempotent():
    """Two start() calls produce one poller, not two."""
    adapter = WazuhSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    first_poller = adapter._poller
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is first_poller
    await adapter._poller.stop()


def test_start_without_event_loop_defers_scheduling():
    """Calling start() outside an asyncio context sets up state but
    doesn't crash. The poller object exists; framework will schedule
    when entering async context."""
    adapter = WazuhSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is not None
    # No asyncio loop active — task scheduling was skipped, but state ready


def test_start_raises_on_invalid_config():
    adapter = WazuhSourceAdapter(client_factory=_client_factory("ok"))
    with pytest.raises(ValueError, match="MANAGER_URL"):
        adapter.start({})


@pytest.mark.asyncio
async def test_stop_clears_poller_state():
    adapter = WazuhSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is not None
    adapter.stop()
    # Give the create_task a tick to schedule the stop
    await asyncio.sleep(0.05)
    assert adapter._poller is None
    assert adapter._client is None


def test_stop_when_not_started_is_noop():
    """Stop on a never-started adapter doesn't crash."""
    adapter = WazuhSourceAdapter()
    adapter.stop()  # no exception
    assert adapter._poller is None


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def test_health_reports_inactive_before_start():
    adapter = WazuhSourceAdapter()
    h = adapter.health()
    assert h.alive is False
    assert h.last_event_at is None


def test_health_reports_alive_after_start():
    adapter = WazuhSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    h = adapter.health()
    assert h.alive is True
    # No events seen yet → last_event_at is None (sentinel cursor doesn't count)
    assert h.last_event_at is None


def test_health_surfaces_cursor_when_events_have_been_seen():
    adapter = WazuhSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({
        **VALID_CREDS,
        "default_tenant_slug": "x",
        "initial_cursor": "2026-05-11T10:00:00.000Z",
    })
    h = adapter.health()
    assert h.alive is True
    assert h.last_event_at == "2026-05-11T10:00:00.000Z"
