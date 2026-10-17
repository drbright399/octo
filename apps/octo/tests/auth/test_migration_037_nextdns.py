"""Migration 037 (NextDNS): forward, rollback, forward again — on the
registry AND on a tenant's telemetry.db — losing nothing.

Pins:
  registry
    - adapter_ignored_vendor_tenants: keyed (instance, vendor tenant id),
      cascades with its instance, bounded id length;
    - rollback keeps every ignore choice (…_rolled_back_037, appended on a
      second rollback), version back to 36; re-forward restores the newest
      kept row per (instance, tenant) whose instance still exists.
  telemetry
    - nextdns_hourly (hour × profile, REPLACE semantics are the writer's)
      and nextdns_signal_buckets with their indexes; version 37;
    - rollback keeps both tables' rows under *_rolled_back_037, version 36;
      re-forward (the lazy ensure_db path) gives fresh empty tables.
"""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.auth import bootstrap
from apps.octo.db import connect
from apps.octo.ingest import telemetry
from apps.octo.migration import apply_migration, list_migrations


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _build_v36(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 37:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 36
    return conn


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _instance(conn, slug: str = "nextdns") -> int:
    cur = conn.execute(
        "INSERT INTO adapter_instances (vendor_slug, display_name, cred_ref) "
        "VALUES (?, 'NextDNS', 'v1:fixture')", (slug,))
    return int(cur.lastrowid)


def _ignored(conn) -> list[tuple]:
    return [tuple(r) for r in conn.execute(
        "SELECT adapter_instance_id, vendor_tenant_id, vendor_tenant_label "
        "FROM adapter_ignored_vendor_tenants ORDER BY 1, 2")]


def test_registry_forward_rollback_forward(tmp_path):
    conn = _build_v36(tmp_path / "registry.db")
    iid = _instance(conn)
    forward, rollback = _migration(37), _migration(37, "rollback")

    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 37
    conn.execute("INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                 "vendor_tenant_id, vendor_tenant_label) VALUES (?, 'tst001', 'Test Profile')",
                 (iid,))
    with pytest.raises(sqlite3.IntegrityError):         # one row per tenant
        conn.execute("INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                     "vendor_tenant_id) VALUES (?, 'tst001')", (iid,))
    with pytest.raises(sqlite3.IntegrityError):         # bounded id
        conn.execute("INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                     "vendor_tenant_id) VALUES (?, '')", (iid,))
    with pytest.raises(sqlite3.IntegrityError):         # a real instance
        conn.execute("INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                     "vendor_tenant_id) VALUES (999, 'x')")

    apply_migration(conn, rollback, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 36
    assert "adapter_ignored_vendor_tenants" not in _tables(conn)
    assert conn.execute(
        "SELECT COUNT(*) FROM adapter_ignored_vendor_tenants_rolled_back_037").fetchone()[0] == 1

    apply_migration(conn, forward, target="registry")
    assert _ignored(conn) == [(iid, "tst001", "Test Profile")]
    # A second round trip appends to the kept copy; the newest wins.
    conn.execute("UPDATE adapter_ignored_vendor_tenants SET vendor_tenant_label = 'Renamed'")
    apply_migration(conn, rollback, target="registry")
    assert conn.execute(
        "SELECT COUNT(*) FROM adapter_ignored_vendor_tenants_rolled_back_037").fetchone()[0] == 2
    apply_migration(conn, forward, target="registry")
    assert _ignored(conn) == [(iid, "tst001", "Renamed")]
    # Deleting the instance drops its ignore choices.
    conn.execute("DELETE FROM adapter_instances WHERE id = ?", (iid,))
    assert _ignored(conn) == []
    conn.close()


def test_registry_restore_skips_rows_of_instances_that_are_gone(tmp_path):
    conn = _build_v36(tmp_path / "registry.db")
    iid = _instance(conn)
    apply_migration(conn, _migration(37), target="registry")
    conn.execute("INSERT INTO adapter_ignored_vendor_tenants (adapter_instance_id, "
                 "vendor_tenant_id) VALUES (?, 'tst001')", (iid,))
    apply_migration(conn, _migration(37, "rollback"), target="registry")
    conn.execute("DELETE FROM adapter_instances WHERE id = ?", (iid,))
    apply_migration(conn, _migration(37), target="registry")
    assert _ignored(conn) == []
    conn.close()


def test_first_forward_is_empty(tmp_path):
    conn = _build_v36(tmp_path / "registry.db")
    apply_migration(conn, _migration(37), target="registry")
    assert _ignored(conn) == []
    assert conn.execute(
        "SELECT COUNT(*) FROM adapter_ignored_vendor_tenants_rolled_back_037").fetchone()[0] == 0
    conn.close()


def test_telemetry_forward_rollback_forward(tmp_path):
    telemetry.reset_schema_cache()
    tenant = tmp_path / "clients" / "acme-corp"
    tenant.mkdir(parents=True)
    path = tenant / "telemetry.db"
    assert telemetry.ensure_db(path) == [36, 37, 39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 46
    assert {"nextdns_hourly", "nextdns_signal_buckets"} <= _tables(conn)
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_nextdns_hourly_arrival", "idx_nextdns_buckets_arrival",
            "idx_nextdns_buckets_event", "idx_nextdns_buckets_open"} <= indexes
    conn.execute("INSERT INTO nextdns_hourly (hour, profile_id, queries, fetched_at) "
                 "VALUES ('2026-09-30T10:00:00Z', 'abc123', 5, 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO nextdns_hourly (hour, profile_id, fetched_at) "
                     "VALUES ('2026-09-30T10:00:00Z', 'abc123', 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO nextdns_hourly (hour, profile_id, queries, fetched_at) "
                     "VALUES ('h', 'p', -1, 'x')")
    conn.execute("INSERT INTO nextdns_signal_buckets (bucket_key, hour, profile_id, reason_id, "
                 "first_seen, last_seen) VALUES ('k1', 'h', 'abc123', 'dga', 'a', 'b')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO nextdns_signal_buckets (bucket_key, hour, profile_id, "
                     "reason_id, first_seen, last_seen, noted) "
                     "VALUES ('k2', 'h', 'p', 'r', 'a', 'b', 2)")
    conn.commit()

    # A real downgrade takes 046 and 039 (UniFi) off first.
    apply_migration(conn, _migration(46, "rollback"), target="telemetry")
    apply_migration(conn, _migration(39, "rollback"), target="telemetry")
    apply_migration(conn, _migration(37, "rollback"), target="telemetry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 36
    assert not {"nextdns_hourly", "nextdns_signal_buckets"} & _tables(conn)
    assert conn.execute("SELECT COUNT(*) FROM nextdns_hourly_rolled_back_037").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM nextdns_signal_buckets_rolled_back_037").fetchone()[0] == 1
    # The 036 tables are untouched by 037's rollback.
    assert {"telemetry_raw", "telemetry_hourly", "first_seen_domains"} <= _tables(conn)
    conn.close()

    telemetry.reset_schema_cache()
    assert telemetry.ensure_db(path) == [37, 39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM nextdns_hourly").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM nextdns_hourly_rolled_back_037").fetchone()[0] == 1
    conn.close()


def test_telemetry_section_never_reaches_the_registry(tmp_path):
    conn = _build_v36(tmp_path / "registry.db")
    apply_migration(conn, _migration(37), target="registry")
    assert not {"nextdns_hourly", "nextdns_signal_buckets"} & _tables(conn)
    conn.close()
