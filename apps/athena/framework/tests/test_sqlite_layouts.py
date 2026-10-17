"""Tests for SQLite-backed LayoutRepository — CRUD parity + durability."""

from __future__ import annotations

from pathlib import Path

import pytest
from shared_widget_contract import (
    LayoutGrid,
    LayoutItem,
    LayoutPosition,
    LayoutSize,
)

from apps.athena.framework.layouts import LayoutService
from apps.athena.framework.sqlite_layouts import (
    SCHEMA_VERSION,
    SqliteLayoutRepository,
)
from apps.athena.framework.widget_registry import WidgetRegistryImpl


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _layout(*ids: str, version: int = 1) -> LayoutGrid:
    items = [
        LayoutItem(
            widget_id=widget_id,
            position=LayoutPosition(x=i * 4, y=0),
            size=LayoutSize(w=4, h=3),
            hidden=False,
            operator_config={"refresh_sec": 30},
        )
        for i, widget_id in enumerate(ids)
    ]
    return LayoutGrid(version=version, grid=items)


def _adapter_widget(widget_id: str, vendor_slug: str = "datto-rmm"):
    from shared_widget_contract import WidgetDefinition
    return WidgetDefinition(
        widget_id=widget_id,
        title=widget_id,
        description="",
        default_size="medium",
        default_position="auto",
        data_query="q",
        render_component_ref="default-alert-feed",
        categories=["source-adapter"],
        min_role="viewer",
        refresh_interval_sec=15,
    )


# ---------------------------------------------------------------------------
# CRUD parity
# ---------------------------------------------------------------------------

def test_get_returns_none_when_absent(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    assert repo.get(operator_id=1, tenant_slug="client_a") is None
    repo.close()


def test_put_then_get_round_trips(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    layout = _layout("w1", "w2")
    repo.put(operator_id=1, tenant_slug="client_a", layout=layout)
    fetched = repo.get(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.widget_ids() == ["w1", "w2"]
    # Items + nested fields preserved
    assert fetched.grid[0].position.x == 0
    assert fetched.grid[1].position.x == 4
    assert fetched.grid[0].size.w == 4
    assert fetched.grid[0].operator_config == {"refresh_sec": 30}
    repo.close()


def test_put_upsert_replaces_layout(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1"))
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w2", "w3"))
    fetched = repo.get(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.widget_ids() == ["w2", "w3"]
    repo.close()


def test_delete_is_idempotent(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.delete(operator_id=1, tenant_slug="client_a")  # no-op when absent
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1"))
    repo.delete(operator_id=1, tenant_slug="client_a")
    repo.delete(operator_id=1, tenant_slug="client_a")  # second delete: no-op
    assert repo.get(operator_id=1, tenant_slug="client_a") is None
    repo.close()


def test_per_tenant_isolation(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1"))
    repo.put(operator_id=1, tenant_slug="client_b", layout=_layout("w2"))
    a = repo.get(operator_id=1, tenant_slug="client_a")
    b = repo.get(operator_id=1, tenant_slug="client_b")
    assert a.widget_ids() == ["w1"]
    assert b.widget_ids() == ["w2"]
    repo.close()


def test_per_operator_isolation(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("op1_widget"))
    repo.put(operator_id=2, tenant_slug="client_a", layout=_layout("op2_widget"))
    assert repo.get(operator_id=1, tenant_slug="client_a").widget_ids() == ["op1_widget"]
    assert repo.get(operator_id=2, tenant_slug="client_a").widget_ids() == ["op2_widget"]
    repo.close()


def test_list_for_operator_returns_all_tenants(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("wa"))
    repo.put(operator_id=1, tenant_slug="client_b", layout=_layout("wb"))
    repo.put(operator_id=2, tenant_slug="client_a", layout=_layout("wc"))
    layouts = repo.list_for_operator(operator_id=1)
    assert set(layouts.keys()) == {"client_a", "client_b"}
    assert layouts["client_a"].widget_ids() == ["wa"]
    assert layouts["client_b"].widget_ids() == ["wb"]
    repo.close()


def test_list_for_operator_empty_when_none(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    assert repo.list_for_operator(operator_id=999) == {}
    repo.close()


# ---------------------------------------------------------------------------
# Item field preservation (hidden, operator_config)
# ---------------------------------------------------------------------------

def test_hidden_flag_round_trips(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    layout = LayoutGrid(version=1, grid=[
        LayoutItem(
            widget_id="w1",
            position=LayoutPosition(x=0, y=0),
            size=LayoutSize(w=4, h=3),
            hidden=True,
            operator_config={},
        ),
    ])
    repo.put(operator_id=1, tenant_slug="client_a", layout=layout)
    fetched = repo.get(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.grid[0].hidden is True
    repo.close()


def test_operator_config_complex_round_trips(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    config = {
        "severity_filter": ["high", "critical"],
        "show_resolved": False,
        "refresh_sec": 15,
        "nested": {"key": "value"},
    }
    layout = LayoutGrid(version=1, grid=[
        LayoutItem(
            widget_id="w1",
            position=LayoutPosition(x=0, y=0),
            size=LayoutSize(w=4, h=3),
            operator_config=config,
        ),
    ])
    repo.put(operator_id=1, tenant_slug="client_a", layout=layout)
    fetched = repo.get(operator_id=1, tenant_slug="client_a")
    assert fetched.grid[0].operator_config == config
    repo.close()


# ---------------------------------------------------------------------------
# Durability across reopens
# ---------------------------------------------------------------------------

def test_data_survives_close_and_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "layouts.db"
    r1 = SqliteLayoutRepository(db_path)
    r1.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1", "w2"))
    r1.close()

    r2 = SqliteLayoutRepository(db_path)
    fetched = r2.get(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.widget_ids() == ["w1", "w2"]
    r2.close()


def test_schema_version_stamped(tmp_path: Path) -> None:
    db_path = tmp_path / "layouts.db"
    repo = SqliteLayoutRepository(db_path)
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1"))
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        conn.close()
        repo.close()


def test_updated_at_diagnostic(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    assert repo.updated_at(operator_id=1, tenant_slug="client_a") is None
    repo.put(operator_id=1, tenant_slug="client_a", layout=_layout("w1"))
    ts = repo.updated_at(operator_id=1, tenant_slug="client_a")
    assert ts is not None
    assert ts.endswith("Z")
    repo.close()


def test_close_idempotent(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    repo.close()
    repo.close()


# ---------------------------------------------------------------------------
# Integration: LayoutService against SqliteLayoutRepository
# ---------------------------------------------------------------------------

def _registry_with(*widget_ids: str) -> WidgetRegistryImpl:
    reg = WidgetRegistryImpl()
    for wid in widget_ids:
        reg.register_adapter_widget(_adapter_widget(wid), vendor_slug="datto-rmm")
    reg._set_adapter_active_for_tenant(
        vendor_slug="datto-rmm", tenant_slug="client_a", active=True,
    )
    return reg


def test_service_against_sqlite_repository(tmp_path: Path) -> None:
    repo = SqliteLayoutRepository(tmp_path / "layouts.db")
    service = LayoutService(
        registry=_registry_with("w1", "w2"),
        repository=repo,
    )
    layout = _layout("w1", "w2")
    persisted = service.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=layout,
    )
    assert persisted.widget_ids() == ["w1", "w2"]

    fetched = service.get_layout(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.widget_ids() == ["w1", "w2"]
    repo.close()


def test_service_state_persists_across_rebuild(tmp_path: Path) -> None:
    """Restart simulation: persist via service-1, read via service-2 same DB."""
    db_path = tmp_path / "layouts.db"

    # Service 1 persists a valid layout
    repo1 = SqliteLayoutRepository(db_path)
    service1 = LayoutService(
        registry=_registry_with("w1"),
        repository=repo1,
    )
    service1.save_layout(
        operator_id=1, operator_role="viewer",
        tenant_slug="client_a", layout=_layout("w1"),
    )
    repo1.close()

    # Service 2 — same DB, fresh registry + repo (simulating Athena restart)
    repo2 = SqliteLayoutRepository(db_path)
    service2 = LayoutService(
        registry=_registry_with("w1"),
        repository=repo2,
    )
    fetched = service2.get_layout(operator_id=1, tenant_slug="client_a")
    assert fetched is not None
    assert fetched.widget_ids() == ["w1"]
    repo2.close()
