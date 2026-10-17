"""Tests for the SQLite-backed RegistryBackend.

Verifies CRUD parity with InMemoryRegistryBackend, that the schema
survives reopens (durability), and that the AdapterRegistry can be
constructed against a SQLite backend without behavior drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apps.octo.framework.lifecycle import AdapterLifecycleState
from apps.octo.framework.registry import AdapterInstance, AdapterRegistry
from apps.octo.framework.sqlite_registry import SCHEMA_VERSION, SqliteRegistryBackend


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _instance(
    *,
    vendor_slug: str = "datto-rmm",
    tenant_slug: str = "client_a",
    instance_id: str = "i1",
    state: AdapterLifecycleState = AdapterLifecycleState.CONFIGURED,
    credentials_ref: str = "vault:datto/i1",
    tenant_mapping: dict | None = None,
    rate_limit_overrides: dict | None = None,
) -> AdapterInstance:
    return AdapterInstance(
        instance_key=f"{vendor_slug}:{tenant_slug}:{instance_id}",
        vendor_slug=vendor_slug,
        tenant_slug=tenant_slug,
        instance_id=instance_id,
        state=state,
        credentials_ref=credentials_ref,
        tenant_mapping=tenant_mapping or {"vendor_id": "abc123"},
        rate_limit_overrides=rate_limit_overrides or {"requests_per_second": 5.0},
        created_at="2026-05-04T15:00:00.000Z",
        last_state_change_at="2026-05-04T15:00:00.000Z",
        state_change_reason="initial",
    )


# ---------------------------------------------------------------------------
# CRUD parity
# ---------------------------------------------------------------------------

def test_get_returns_none_when_absent(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    assert backend.get_instance("ghost-key") is None
    backend.close()


def test_put_then_get_round_trips(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    inst = _instance()
    backend.put_instance(inst)
    fetched = backend.get_instance(inst.instance_key)
    assert fetched is not None
    assert fetched == inst
    backend.close()


def test_put_upsert_replaces_state_fields(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    inst = _instance(state=AdapterLifecycleState.CONFIGURED)
    backend.put_instance(inst)
    activated = inst.with_state(AdapterLifecycleState.ACTIVE, reason="go-live")
    backend.put_instance(activated)
    fetched = backend.get_instance(inst.instance_key)
    assert fetched is not None
    assert fetched.state == AdapterLifecycleState.ACTIVE
    assert fetched.state_change_reason == "go-live"
    backend.close()


def test_delete_is_idempotent(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance())
    backend.delete_instance(_instance().instance_key)
    backend.delete_instance(_instance().instance_key)
    assert backend.get_instance(_instance().instance_key) is None
    backend.close()


def test_list_filtering_by_vendor(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance(vendor_slug="datto-rmm", instance_id="i1"))
    backend.put_instance(_instance(vendor_slug="unifi", instance_id="i2"))
    results = backend.list_instances(vendor_slug="datto-rmm")
    assert len(results) == 1
    assert results[0].vendor_slug == "datto-rmm"
    backend.close()


def test_list_filtering_by_tenant(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance(tenant_slug="client_a", instance_id="i1"))
    backend.put_instance(_instance(tenant_slug="client_b", instance_id="i2"))
    results = backend.list_instances(tenant_slug="client_a")
    assert len(results) == 1
    assert results[0].tenant_slug == "client_a"
    backend.close()


def test_list_filtering_by_state(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance(
        instance_id="i1", state=AdapterLifecycleState.CONFIGURED,
    ))
    backend.put_instance(_instance(
        instance_id="i2", state=AdapterLifecycleState.ACTIVE,
    ))
    backend.put_instance(_instance(
        instance_id="i3", state=AdapterLifecycleState.PAUSED,
    ))
    active = backend.list_instances(state=AdapterLifecycleState.ACTIVE)
    assert len(active) == 1
    assert active[0].instance_id == "i2"
    backend.close()


def test_list_combined_filters(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance(
        vendor_slug="datto-rmm", tenant_slug="client_a", instance_id="i1",
        state=AdapterLifecycleState.ACTIVE,
    ))
    backend.put_instance(_instance(
        vendor_slug="datto-rmm", tenant_slug="client_b", instance_id="i2",
        state=AdapterLifecycleState.ACTIVE,
    ))
    backend.put_instance(_instance(
        vendor_slug="unifi", tenant_slug="client_a", instance_id="i3",
        state=AdapterLifecycleState.ACTIVE,
    ))
    results = backend.list_instances(
        vendor_slug="datto-rmm",
        tenant_slug="client_a",
        state=AdapterLifecycleState.ACTIVE,
    )
    assert len(results) == 1
    assert results[0].instance_id == "i1"
    backend.close()


def test_list_no_filters_returns_all_sorted_by_key(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    # Insert out of order to verify ORDER BY instance_key
    backend.put_instance(_instance(vendor_slug="zzz", instance_id="i1"))
    backend.put_instance(_instance(vendor_slug="aaa", instance_id="i1"))
    results = backend.list_instances()
    assert [r.vendor_slug for r in results] == ["aaa", "zzz"]
    backend.close()


# ---------------------------------------------------------------------------
# JSON column round-trip
# ---------------------------------------------------------------------------

def test_tenant_mapping_round_trips(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    mapping = {"siteUid": "abc-123", "subTenantId": "sub-456"}
    backend.put_instance(_instance(tenant_mapping=mapping))
    fetched = backend.get_instance(_instance().instance_key)
    assert fetched is not None
    assert fetched.tenant_mapping == mapping
    backend.close()


def test_rate_limit_overrides_round_trips(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    overrides = {"requests_per_second": 0.5, "burst": 10}
    backend.put_instance(_instance(rate_limit_overrides=overrides))
    fetched = backend.get_instance(_instance().instance_key)
    assert fetched is not None
    assert fetched.rate_limit_overrides == overrides
    backend.close()


# ---------------------------------------------------------------------------
# Durability across reopens
# ---------------------------------------------------------------------------

def test_data_survives_close_and_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    backend1 = SqliteRegistryBackend(db_path)
    backend1.put_instance(_instance())
    backend1.close()

    backend2 = SqliteRegistryBackend(db_path)
    fetched = backend2.get_instance(_instance().instance_key)
    assert fetched is not None
    assert fetched.vendor_slug == "datto-rmm"
    backend2.close()


def test_schema_version_stamped_on_first_open(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    backend = SqliteRegistryBackend(db_path)
    # Force schema init
    backend.put_instance(_instance())
    # Read PRAGMA user_version
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        conn.close()
        backend.close()


def test_close_is_idempotent(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    backend.put_instance(_instance())
    backend.close()
    backend.close()  # no-op


# ---------------------------------------------------------------------------
# Integration: AdapterRegistry against SqliteRegistryBackend
# ---------------------------------------------------------------------------

class _StubAdapter:
    vendor_slug = "datto-rmm"
    vendor_display_name = "Datto RMM"
    vendor_logo_path = "logos/datto-rmm.svg"
    contract_version = "1.0"
    auth_model = "api_key"
    delivery_mode = "pull"
    availability = "ga"
    compliance_categories: list[str] = []

    def credential_shape(self): return []
    def tenant_mapping_shape(self): return None
    def smoke_test(self, c): return None
    def start(self, c): pass
    def stop(self): pass
    def health(self): return None
    def extract_event(self, e): return None
    def route_to_tenant(self, e): return None
    def severity_map(self, e): return "info"
    def human_summary(self, e): return ""
    def rate_limit_hints(self): return None
    def widget_definition(self): return None
    def deep_link(self, e, t): return None


def test_registry_with_sqlite_backend_full_lifecycle(tmp_path: Path) -> None:
    backend = SqliteRegistryBackend(tmp_path / "registry.db")
    registry = AdapterRegistry(backend=backend)
    registry.register_adapter_class(_StubAdapter)

    inst = registry.configure_instance(
        vendor_slug="datto-rmm",
        tenant_slug="client_a",
        instance_id="i1",
        credentials_ref="vault:x",
    )
    registry.activate(inst.instance_key, reason="go-live")
    registry.pause(inst.instance_key, reason="maintenance")
    registry.resume(inst.instance_key, reason="back online")
    registry.remove(inst.instance_key, reason="customer offboarded")

    final = backend.get_instance(inst.instance_key)
    assert final is not None
    assert final.state == AdapterLifecycleState.REMOVED
    assert final.state_change_reason == "customer offboarded"
    backend.close()


def test_registry_state_persists_across_registry_rebuild(tmp_path: Path) -> None:
    """Restart simulation: persist via registry-1, read via registry-2 same DB."""
    db_path = tmp_path / "registry.db"

    backend1 = SqliteRegistryBackend(db_path)
    registry1 = AdapterRegistry(backend=backend1)
    registry1.register_adapter_class(_StubAdapter)
    inst = registry1.configure_instance(
        vendor_slug="datto-rmm",
        tenant_slug="client_a",
        instance_id="i1",
        credentials_ref="vault:x",
    )
    registry1.activate(inst.instance_key, reason="go-live")
    backend1.close()

    # New registry, same DB
    backend2 = SqliteRegistryBackend(db_path)
    registry2 = AdapterRegistry(backend=backend2)
    registry2.register_adapter_class(_StubAdapter)  # adapter classes re-discover

    fetched = registry2.get_instance(inst.instance_key)
    assert fetched is not None
    assert fetched.state == AdapterLifecycleState.ACTIVE
    # Lifecycle still works post-rebuild
    registry2.pause(fetched.instance_key, reason="post-restart maintenance")
    assert (
        backend2.get_instance(fetched.instance_key).state
        == AdapterLifecycleState.PAUSED
    )
    backend2.close()
