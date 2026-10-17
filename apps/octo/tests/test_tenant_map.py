"""Generic tenant map — store round-trip + MappingIngestSink behavior."""
from __future__ import annotations

import sqlite3

from apps.octo import paths
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import MappingIngestSink, TenantMapping


def _temp_registry(tmp_path, monkeypatch):
    db = tmp_path / "registry.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE adapter_tenant_map ("
        " adapter_instance_id INTEGER NOT NULL,"
        " vendor_tenant_id TEXT NOT NULL,"
        " octo_client_slug TEXT NOT NULL,"
        " vendor_tenant_label TEXT,"
        " match_source TEXT NOT NULL DEFAULT 'manual',"
        " updated_at TEXT, updated_by_operator_id INTEGER,"
        " PRIMARY KEY (adapter_instance_id, vendor_tenant_id))"
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(paths, "registry_db_path", lambda: db)
    return db


def test_set_get_resolve_roundtrip(tmp_path, monkeypatch):
    _temp_registry(tmp_path, monkeypatch)
    n = tenant_map.set_mappings(
        7,
        [
            TenantMapping("site-abc", "acme-corp", "Acme Site", "manual"),
            TenantMapping("site-xyz", "globex", None, "auto-domain"),
        ],
        operator_id=1,
    )
    assert n == 2
    rows = tenant_map.get_mappings(7)
    assert {r.vendor_tenant_id for r in rows} == {"site-abc", "site-xyz"}
    assert tenant_map.resolve(7, "site-abc") == "acme-corp"
    assert tenant_map.resolve(7, "site-xyz") == "globex"
    assert tenant_map.resolve(7, "unknown") is None
    assert tenant_map.resolve(7, None) is None
    assert tenant_map.resolve(None, "site-abc") is None


def test_set_mappings_replaces(tmp_path, monkeypatch):
    _temp_registry(tmp_path, monkeypatch)
    tenant_map.set_mappings(7, [TenantMapping("a", "client-a")])
    tenant_map.set_mappings(7, [TenantMapping("b", "client-b")])
    rows = tenant_map.get_mappings(7)
    assert len(rows) == 1 and rows[0].vendor_tenant_id == "b"


def test_a_failing_replace_leaves_the_previous_mappings_intact(tmp_path, monkeypatch):
    """Connections are autocommit: without an explicit transaction a failure
    on the 2nd INSERT left the OLD rows deleted and only the first new row
    committed — sites silently unmapped, their alerts dropped — while the
    route had already audited the full new set."""
    import pytest

    _temp_registry(tmp_path, monkeypatch)
    tenant_map.set_mappings(
        7, [TenantMapping("site-1", "client-a"), TenantMapping("site-2", "client-b")],
    )
    with pytest.raises(sqlite3.IntegrityError):
        tenant_map.set_mappings(7, [
            TenantMapping("site-3", "client-c"),
            TenantMapping("site-3", "client-d"),       # PK collision mid-replace
        ])
    rows = tenant_map.get_mappings(7)
    assert [(r.vendor_tenant_id, r.octo_client_slug) for r in rows] == [
        ("site-1", "client-a"), ("site-2", "client-b"),
    ]
    # Another instance's rows were never in play.
    tenant_map.set_mappings(8, [TenantMapping("site-1", "client-z")])
    assert tenant_map.resolve(7, "site-1") == "client-a"


def test_resolve_graceful_without_table(tmp_path, monkeypatch):
    # No table → OperationalError caught → None (ingest unaffected when unmapped).
    db = tmp_path / "empty.db"
    sqlite3.connect(db).close()
    monkeypatch.setattr(paths, "registry_db_path", lambda: db)
    assert tenant_map.resolve(7, "anything") is None


class _FakeInner:
    def __init__(self):
        self.calls = []

    def ingest(self, tenant_slug, source, event):
        self.calls.append((tenant_slug, source, event))


def test_mapping_sink_swaps_mapped_slug(monkeypatch):
    monkeypatch.setattr(
        tenant_map, "resolve",
        lambda iid, vid: "acme-corp" if vid == "site-abc" else None,
    )
    inner = _FakeInner()
    sink = MappingIngestSink(inner, 7)
    sink.ingest("site-abc", "datto", "EV")
    sink.ingest("globex", "datto", "EV2")  # unmapped → passes through
    assert inner.calls == [
        ("acme-corp", "datto", "EV"),
        ("globex", "datto", "EV2"),
    ]


def test_mapping_sink_passthrough_when_no_instance():
    inner = _FakeInner()
    MappingIngestSink(inner, None).ingest("acme", "datto", "EV")
    assert inner.calls == [("acme", "datto", "EV")]
