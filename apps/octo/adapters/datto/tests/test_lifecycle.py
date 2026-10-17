"""DattoSourceAdapter lifecycle — start / stop / smoke_test / health."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.client import (
    DattoAuthError,
    DattoClient,
    DattoClientError,
    DattoConfig,
)
from apps.octo.adapters.datto.tests.fake_datto import (
    CREDS,
    FORBIDDEN_QUOTED,
    SECRETS,
    TOKEN_PATH,
    FakeDattoTransport,
    client_factory,
)


class _FakeClient:
    def __init__(
        self,
        config: DattoConfig,
        *,
        auth_outcome: str = "ok",
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
            raise DattoAuthError("rejected by stub")
        if self._auth_outcome == "transport":
            raise DattoClientError("network down (stub)")
        return "stub-token"

    def fetch_alerts_since(self, since_iso: str, *, max_results: int = 500):
        self.fetch_cursors.append(since_iso)
        if not self._batches:
            return []
        return self._batches.pop(0)


def _client_factory(outcome: str = "ok"):
    def factory(config: DattoConfig) -> DattoClient:  # type: ignore[return-value]
        return _FakeClient(config, auth_outcome=outcome)  # type: ignore[return-value]
    return factory


class _RecorderSink:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, CanonicalEvent]] = []
    def ingest(self, tenant_slug: str, source: str, event: CanonicalEvent):
        self.calls.append((tenant_slug, source, event))


VALID_CREDS = {
    "DATTO_API_URL": "https://exampleplat-api.centrastage.net",
    "DATTO_API_KEY": "public-key-from-wizard",
    "DATTO_API_SECRET_KEY": "secret-key-from-wizard",
}


# ---------------------------------------------------------------------------
# smoke_test
# ---------------------------------------------------------------------------

# The three vendor-facing outcomes run the REAL client over a fake transport
# (tests/fake_datto.py) — a stub client that only knew authenticate() is what
# let "token issued, every read 403" pass as a healthy connection.

def test_smoke_test_returns_ok_when_the_api_user_can_read():
    transport = FakeDattoTransport()
    adapter = DattoSourceAdapter(client_factory=client_factory(transport))
    r = adapter.smoke_test(CREDS)
    assert r.ok is True
    assert transport.count("/api/v2/account/alerts/open") == 1


def test_smoke_test_returns_failure_when_credentials_rejected():
    transport = FakeDattoTransport()
    transport.token_status = 401
    adapter = DattoSourceAdapter(client_factory=client_factory(transport))
    r = adapter.smoke_test(CREDS)
    assert r.ok is False
    assert "rejected" in r.message.lower() or "credentials" in r.message.lower()


def test_smoke_test_returns_failure_when_transport_fails():
    transport = FakeDattoTransport()
    transport.unreachable = True
    adapter = DattoSourceAdapter(client_factory=client_factory(transport))
    r = adapter.smoke_test(CREDS)
    assert r.ok is False
    assert "could not reach" in r.message.lower()


def test_smoke_test_fails_when_authenticated_but_forbidden():
    """The production defect: Datto issues the token, then answers every data
    endpoint 403. That must FAIL the test, with a message the operator can
    act on, and nothing secret in it."""
    transport = FakeDattoTransport()
    transport.forbid_data = True
    adapter = DattoSourceAdapter(client_factory=client_factory(transport))
    r = adapter.smoke_test(CREDS)
    assert r.ok is False
    assert transport.count(TOKEN_PATH) == 1
    assert r.message.startswith("Datto accepted the API key, but this API user")
    assert "(HTTP 403)" in r.message and r.message.endswith(FORBIDDEN_QUOTED)
    assert "Setup > Users" in r.message and "API Security Level" in r.message
    # In the wizard the key is not saved yet, but regenerating is still wrong.
    assert "regenerate or keep" not in r.message and "Test connection again" in r.message
    for secret in SECRETS:
        assert secret not in r.message


def test_smoke_test_requires_api_url():
    adapter = DattoSourceAdapter(client_factory=_client_factory("ok"))
    r = adapter.smoke_test({"DATTO_API_KEY": "x", "DATTO_API_SECRET_KEY": "y"})
    assert r.ok is False
    assert "API_URL" in r.message


def test_smoke_test_requires_api_key():
    adapter = DattoSourceAdapter(client_factory=_client_factory("ok"))
    r = adapter.smoke_test({
        "DATTO_API_URL": "https://exampleplat-api.centrastage.net",
        "DATTO_API_SECRET_KEY": "y",
    })
    assert r.ok is False
    assert "API_KEY" in r.message


def test_smoke_test_requires_api_secret_key():
    adapter = DattoSourceAdapter(client_factory=_client_factory("ok"))
    r = adapter.smoke_test({
        "DATTO_API_URL": "https://exampleplat-api.centrastage.net",
        "DATTO_API_KEY": "x",
    })
    assert r.ok is False
    assert "SECRET" in r.message


# ---------------------------------------------------------------------------
# start / stop
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_constructs_poller_and_schedules_task():
    adapter = DattoSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "acme-msp",
                    "poll_interval_sec": 0.05})
    assert adapter._poller is not None
    assert adapter._default_tenant_slug == "acme-msp"
    await asyncio.sleep(0.15)
    await adapter._poller.stop()


@pytest.mark.asyncio
async def test_start_is_idempotent():
    adapter = DattoSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    first = adapter._poller
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is first
    await adapter._poller.stop()


def test_start_without_loop_defers_scheduling():
    adapter = DattoSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is not None


def test_start_raises_on_invalid_config():
    adapter = DattoSourceAdapter(client_factory=_client_factory("ok"))
    with pytest.raises(ValueError, match="API_URL"):
        adapter.start({})


@pytest.mark.asyncio
async def test_stop_clears_poller_state():
    adapter = DattoSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    assert adapter._poller is not None
    adapter.stop()
    await asyncio.sleep(0.05)
    assert adapter._poller is None
    assert adapter._client is None


def test_stop_when_not_started_is_noop():
    adapter = DattoSourceAdapter()
    adapter.stop()
    assert adapter._poller is None


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def test_health_reports_inactive_before_start():
    adapter = DattoSourceAdapter()
    h = adapter.health()
    assert h.alive is False
    assert h.last_event_at is None


def test_health_reports_alive_after_start():
    adapter = DattoSourceAdapter(
        sink=_RecorderSink(),
        client_factory=_client_factory("ok"),
    )
    adapter.start({**VALID_CREDS, "default_tenant_slug": "x"})
    h = adapter.health()
    assert h.alive is True
