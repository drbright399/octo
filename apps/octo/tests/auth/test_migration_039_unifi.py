"""Migration 039 (the UniFi connector) on a tenant's telemetry.db: forward,
rollback, forward again — nothing destroyed. No registry section (sites map
through 030's adapter_tenant_map, ignores through 037)."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.ingest import telemetry
from apps.octo.migration import apply_migration, list_migrations


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def test_039_is_telemetry_only():
    sql = _migration(39).sql
    assert "-- @target: telemetry" in sql and "-- @target: registry" not in sql
    assert "-- @target: telemetry" in _migration(39, "rollback").sql


def test_telemetry_forward_rollback_forward(tmp_path):
    telemetry.reset_schema_cache()
    tenant = tmp_path / "clients" / "acme-corp"
    tenant.mkdir(parents=True)
    path = tenant / "telemetry.db"
    assert telemetry.ensure_db(path) == [36, 37, 39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 46
    assert {"unifi_hourly", "unifi_signal_buckets", "unifi_syslog_cursor"} <= _tables(conn)
    conn.execute("INSERT INTO unifi_hourly (hour, scope, kind, events) VALUES ('h', 's', 'k', 3)")
    with pytest.raises(sqlite3.IntegrityError):              # one row per hour × site × kind
        conn.execute("INSERT INTO unifi_hourly (hour, scope, kind) VALUES ('h', 's', 'k')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO unifi_hourly (hour, scope, kind, events) VALUES ('h2','s','k',-1)")
    conn.execute("INSERT INTO unifi_signal_buckets (bucket_key, hour, scope, kind, first_seen, "
                 "last_seen, pending_payload) VALUES ('b1', 'h', 's', 'ips_threat', 'a', 'b', '{}')")
    conn.execute("INSERT INTO unifi_syslog_cursor (scope, hwm_ms, scanned_to_ms, updated_at) "
                 "VALUES ('s', 5, 6, 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO unifi_syslog_cursor (scope, hwm_ms, scanned_to_ms, updated_at) "
                     "VALUES ('s2', -1, 0, 'x')")
    conn.commit()

    # v0.17.2 (046) sits on top: rolled back first.
    apply_migration(conn, _migration(46, "rollback"), target="telemetry")
    apply_migration(conn, _migration(39, "rollback"), target="telemetry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 37
    assert not {"unifi_hourly", "unifi_signal_buckets", "unifi_syslog_cursor"} & _tables(conn)
    for table in ("unifi_hourly", "unifi_signal_buckets", "unifi_syslog_cursor"):
        assert conn.execute(f"SELECT COUNT(*) FROM {table}_rolled_back_039").fetchone()[0] == 1
    assert {"nextdns_hourly", "telemetry_raw"} <= _tables(conn)     # 037 / 036 untouched
    conn.close()

    telemetry.reset_schema_cache()
    assert telemetry.ensure_db(path) == [39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM unifi_hourly").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM unifi_hourly_rolled_back_039").fetchone()[0] == 1
    conn.close()
