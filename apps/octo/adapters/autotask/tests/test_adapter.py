"""AutotaskSourceAdapter unit tests — registration, smoke-test, deep-link.

Pure-unit: stubs the client + zone resolver via the adapter's factory
injection points so no network IO happens."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from apps.octo.adapters.autotask import AutotaskSourceAdapter
from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskConfig,
    AutotaskZoneError,
)
from shared_adapter_contract.types import CanonicalEvent


# ---------------------------------------------------------------------------
# Metadata + discovery
# ---------------------------------------------------------------------------

def test_vendor_metadata():
    a = AutotaskSourceAdapter()
    assert a.vendor_slug == "autotask"
    assert a.vendor_display_name == "Autotask PSA"
    assert a.vendor_category == "psa"
    assert a.auth_model == "api-key"
    assert a.delivery_mode == "poll"


def test_credential_shape_has_three_required_fields():
    fields = AutotaskSourceAdapter().credential_shape()
    names = {f.name for f in fields}
    assert names == {
        "AUTOTASK_USERNAME",
        "AUTOTASK_SECRET",
        "AUTOTASK_INTEGRATION_CODE",
    }
    # All three are required + the two secrets are password-kind
    for f in fields:
        assert f.required is True
    by_name = {f.name: f for f in fields}
    assert by_name["AUTOTASK_SECRET"].kind == "password"
    assert by_name["AUTOTASK_INTEGRATION_CODE"].kind == "password"
    assert by_name["AUTOTASK_USERNAME"].kind == "text"


def test_tenant_mapping_shape_points_at_companies():
    shape = AutotaskSourceAdapter().tenant_mapping_shape()
    assert shape.fetch_method == "api"
    assert "Companies" in (shape.fetch_endpoint or "")
    assert shape.vendor_tenant_id_field == "id"
    assert shape.vendor_tenant_label_field == "companyName"


def test_auto_discovered_at_framework_level():
    from apps.octo.framework import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.framework.discovery import discover_adapters
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    report = discover_adapters("apps.octo.adapters", registry)
    assert "autotask" in report.registered


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

class _StubClient:
    """Tiny client stub with overridable health_check + a captured config."""
    def __init__(self, config: AutotaskConfig, *, raises: Exception | None = None,
                 envelope: dict[str, Any] | None = None) -> None:
        self.config = config
        self._raises = raises
        self._envelope = envelope or {
            "items": [{"id": 1, "companyName": "ACME"}],
            "pageDetails": {},
        }

    def health_check(self) -> dict[str, Any]:
        if self._raises is not None:
            raise self._raises
        return self._envelope


def _make_adapter(client: _StubClient) -> AutotaskSourceAdapter:
    return AutotaskSourceAdapter(
        client_factory=lambda cfg: _StubClient(  # bind config but reuse stub
            cfg, raises=client._raises, envelope=client._envelope,
        ),
    )


def _make_creds(zone: str = "https://webservices4.autotask.net/atservicesrest/v1.0/") -> dict[str, Any]:
    return {
        "AUTOTASK_USERNAME": "api-user@example.com",
        "AUTOTASK_SECRET": "hunter2",
        "AUTOTASK_INTEGRATION_CODE": "ATINT0000",
        # Skip zone discovery in tests by pre-supplying the resolved URL.
        "AUTOTASK_ZONE_URL": zone,
    }


def test_smoke_test_happy_path():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(cfg))
    result = adapter.smoke_test(_make_creds())
    assert result.ok is True
    assert "Connected to Autotask" in result.message
    assert result.sample_payload == {"id": 1, "companyName": "ACME"}


def test_smoke_test_missing_username_fails():
    adapter = AutotaskSourceAdapter()
    result = adapter.smoke_test({
        "AUTOTASK_SECRET": "x", "AUTOTASK_INTEGRATION_CODE": "y",
    })
    assert result.ok is False
    assert "AUTOTASK_USERNAME" in result.message


def test_smoke_test_zone_discovery_failure_surfaces():
    # Force zone resolution by NOT pre-supplying AUTOTASK_ZONE_URL
    creds = {
        "AUTOTASK_USERNAME": "api-user@example.com",
        "AUTOTASK_SECRET": "hunter2",
        "AUTOTASK_INTEGRATION_CODE": "ATINT0000",
    }
    with patch(
        "apps.octo.adapters.autotask.adapter.resolve_zone",
        side_effect=AutotaskZoneError("API user not recognized"),
    ):
        result = AutotaskSourceAdapter().smoke_test(creds)
    assert result.ok is False
    assert "Zone discovery failed" in result.message


def test_smoke_test_auth_error_surfaces():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(
        cfg, raises=AutotaskAuthError("401 — verify creds"),
    ))
    result = adapter.smoke_test(_make_creds())
    assert result.ok is False
    assert "401" in result.message


def test_smoke_test_generic_client_error_surfaces():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(cfg, raises=AutotaskClientError("503")))
    result = adapter.smoke_test(_make_creds())
    assert result.ok is False
    assert "Health check failed" in result.message


# ---------------------------------------------------------------------------
# Deep link
# ---------------------------------------------------------------------------

def test_deep_link_built_from_zone_url_after_start():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(cfg))
    adapter.start(_make_creds())

    event = CanonicalEvent(
        vendor_event_id="42", received_at="2026-05-14T10:00:00Z",
        severity="high", indicator=None, indicator_type=None,
        source_host=None, summary="probe", payload={}, payload_sha256="x"*64,
    )
    url = adapter.deep_link(event, "alert")
    assert url == "https://ww4.autotask.net/Mvc/ServiceDesk/TicketDetail.mvc?ticketId=42"


def test_deep_link_none_before_start():
    adapter = AutotaskSourceAdapter()
    event = CanonicalEvent(
        vendor_event_id="42", received_at="2026-05-14T10:00:00Z",
        severity="high", indicator=None, indicator_type=None,
        source_host=None, summary="probe", payload={}, payload_sha256="x"*64,
    )
    assert adapter.deep_link(event, "alert") is None


def test_deep_link_none_for_non_alert_link_types():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(cfg))
    adapter.start(_make_creds())
    event = CanonicalEvent(
        vendor_event_id="42", received_at="2026-05-14T10:00:00Z",
        severity="high", indicator=None, indicator_type=None,
        source_host=None, summary="probe", payload={}, payload_sha256="x"*64,
    )
    assert adapter.deep_link(event, "device") is None
    assert adapter.deep_link(event, "tenant") is None
    assert adapter.deep_link(event, "host") is None


# ---------------------------------------------------------------------------
# Data-side stubs (P4-c1 will replace these)
# ---------------------------------------------------------------------------

def test_data_side_methods_not_yet_implemented():
    adapter = AutotaskSourceAdapter()
    with pytest.raises(NotImplementedError, match="P4-c1"):
        adapter.extract_event({})
    with pytest.raises(NotImplementedError, match="P4-c1"):
        adapter.route_to_tenant({})
    with pytest.raises(NotImplementedError, match="P4-c1"):
        adapter.severity_map({})
    event = CanonicalEvent(
        vendor_event_id="0", received_at="", severity="info",
        indicator=None, indicator_type=None, source_host=None,
        summary="", payload={}, payload_sha256="0"*64,
    )
    with pytest.raises(NotImplementedError, match="P4-c1"):
        adapter.human_summary(event)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_health_alive_only_after_start():
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    adapter = _make_adapter(_StubClient(cfg))
    assert adapter.health().alive is False
    adapter.start(_make_creds())
    assert adapter.health().alive is True
    adapter.stop()
    assert adapter.health().alive is False


# ---------------------------------------------------------------------------
# PSA writes kill switch (slice 0): no pusher unless writes_enabled is TRUE
# ---------------------------------------------------------------------------

class _SpyPusher:
    def __init__(self, **kw: Any) -> None:
        self.kw = kw
        self.started = 0
        self.stopped = 0

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1


class _SpyPusherFactory:
    """Records every construction: the proof that NO pusher object exists."""
    def __init__(self) -> None:
        self.built: list[_SpyPusher] = []

    def __call__(self, **kw: Any) -> _SpyPusher:
        p = _SpyPusher(**kw)
        self.built.append(p)
        return p


class _InertPoller:
    def __init__(self, **_kw: Any) -> None:
        pass

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None


def _switch_adapter(spy: _SpyPusherFactory) -> AutotaskSourceAdapter:
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    stub = _StubClient(cfg)
    return AutotaskSourceAdapter(
        client_factory=lambda c: _StubClient(c, envelope=stub._envelope),
        poller_factory=_InertPoller,
        pusher_factory=spy,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, False, "true", "True", 1, "1", "yes"])
async def test_pusher_not_started_when_writes_disabled(value):
    """Default OFF; and only the JSON value `true` counts as on. With a
    running loop (where start() schedules workers), the pusher factory is
    never even called."""
    import asyncio

    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    config = _make_creds()
    if value is not None:
        config["writes_enabled"] = value
    adapter.start(config)
    await asyncio.sleep(0.01)
    assert spy.built == []
    assert adapter._pusher is None
    assert adapter.writes_enabled is False and adapter.pusher_running is False
    adapter.stop()


@pytest.mark.asyncio
async def test_pusher_started_when_writes_enabled_true():
    import asyncio

    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    adapter.start({**_make_creds(), "writes_enabled": True})
    await asyncio.sleep(0.01)
    assert len(spy.built) == 1 and spy.built[0].started == 1
    assert adapter.writes_enabled is True and adapter.pusher_running is True
    adapter.stop()
    await asyncio.sleep(0.01)
    assert spy.built[0].stopped == 1


@pytest.mark.asyncio
async def test_registry_row_off_beats_a_start_config_that_says_on(monkeypatch):
    """The merged start config lets credentials win a key collision: a
    `writes_enabled` smuggled into the credential blob must not turn writes
    on. For a persisted instance the registry row has the last word."""
    import asyncio

    from apps.octo.adapters.autotask import adapter as adapter_mod

    asked: list[int] = []
    monkeypatch.setattr(adapter_mod, "instance_writes_enabled",
                        lambda iid: asked.append(iid) or False)
    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    adapter.start({**_make_creds(), "writes_enabled": True, "_instance_id": 5})
    await asyncio.sleep(0.01)
    assert asked == [5]
    assert spy.built == [] and adapter._pusher is None
    adapter.stop()


@pytest.mark.asyncio
async def test_apply_writes_enabled_live_off_then_on():
    import asyncio

    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    adapter.start({**_make_creds(), "writes_enabled": True})
    await asyncio.sleep(0.01)
    first = spy.built[0]

    assert adapter.apply_writes_enabled(False) is True
    await asyncio.sleep(0.01)
    assert first.stopped == 1
    assert adapter._pusher is None and adapter.writes_enabled is False

    assert adapter.apply_writes_enabled(False) is True        # idempotent
    assert adapter.apply_writes_enabled(True) is True
    await asyncio.sleep(0.01)
    assert len(spy.built) == 2 and spy.built[1].started == 1
    adapter.stop()


@pytest.mark.asyncio
async def test_apply_on_refused_while_the_persisted_switch_is_off(monkeypatch):
    import asyncio

    from apps.octo.adapters.autotask import adapter as adapter_mod

    persisted = {"on": False}
    monkeypatch.setattr(adapter_mod, "instance_writes_enabled", lambda _iid: persisted["on"])
    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    adapter.start({**_make_creds(), "_instance_id": 5})
    assert adapter.apply_writes_enabled(True) is False
    assert spy.built == [] and adapter.writes_enabled is False
    persisted["on"] = True
    assert adapter.apply_writes_enabled(True) is True
    await asyncio.sleep(0.01)
    assert len(spy.built) == 1 and spy.built[0].started == 1
    adapter.stop()


def test_apply_writes_enabled_before_start_is_a_no_op():
    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    assert adapter.apply_writes_enabled(True) is True
    assert spy.built == []


def test_concurrent_switch_on_builds_one_pusher():
    """Two (here: eight) "switch on" calls at once — a double-submitted PUT on
    two threadpool threads — must not build a pusher each: the first would be
    orphaned (unstoppable) and both would send the same rows."""
    import threading
    import time as _time

    class _SlowFactory(_SpyPusherFactory):
        def __call__(self, **kw: Any) -> _SpyPusher:
            _time.sleep(0.05)                       # widen the check-then-build gap
            return super().__call__(**kw)

    spy = _SlowFactory()
    cfg = AutotaskConfig(
        username="x", secret="x", integration_code="x",
        zone_url="https://webservices4.autotask.net/atservicesrest/v1.0/",
    )
    stub = _StubClient(cfg)
    adapter = AutotaskSourceAdapter(
        client_factory=lambda c: _StubClient(c, envelope=stub._envelope),
        poller_factory=_InertPoller, pusher_factory=spy,
        start_poller=False, start_pusher=False,
    )
    adapter.start(_make_creds())                    # writes OFF: no pusher yet
    assert spy.built == []
    barrier = threading.Barrier(8)
    results: list[bool] = []

    def flip() -> None:
        barrier.wait()
        results.append(adapter.apply_writes_enabled(True))

    threads = [threading.Thread(target=flip) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert results == [True] * 8
    assert len(spy.built) == 1
    assert adapter._pusher is spy.built[0]
    adapter.stop()


@pytest.mark.asyncio
async def test_unconfirmed_stop_keeps_the_pusher_in_its_slot(monkeypatch):
    """A switch-off whose stop could not be confirmed must not drop the
    pusher (it may still be running): a later switch-on reuses it instead of
    starting a twin beside it."""
    import asyncio

    from apps.octo.adapters.autotask import adapter as adapter_mod

    spy = _SpyPusherFactory()
    adapter = _switch_adapter(spy)
    adapter.start({**_make_creds(), "writes_enabled": True})
    await asyncio.sleep(0.01)
    assert len(spy.built) == 1

    monkeypatch.setattr(adapter_mod, "stop_poller", lambda *_a, **_k: False)
    assert adapter.apply_writes_enabled(False) is False
    assert adapter.writes_enabled is False
    assert adapter._pusher is spy.built[0] and adapter.pusher_running is True

    assert adapter.apply_writes_enabled(True) is True
    assert len(spy.built) == 1                      # no twin
    monkeypatch.undo()
    adapter.stop()
