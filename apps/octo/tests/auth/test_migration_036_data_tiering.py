"""Migration 036 (data tiering + retention bookkeeping): forward, rollback,
forward again — on the registry AND on a tenant's telemetry.db — losing
nothing.

Pins:
  registry
    - two new retention classes seeded at their operational baselines
      (telemetry_raw 7/7, telemetry_rollup 180/180), editable; existing class
      rows untouched;
    - retention_runs with its CHECKs (trigger, status, archive flag);
    - rollback keeps the run history (retention_runs_rolled_back_036) and
      the two class rows WITH a super_admin's edit
      (bundle_config_retention_rolled_back_036), both appended to on a second
      rollback; version back to 35; re-forward RESTORES the kept edit (the
      newest kept row per class), defaults only for a class never kept;
    - adapter_poller_state: kept by the rollback, restored by re-forward
      (the newest kept value per instance and key).
  telemetry
    - auto_vacuum = INCREMENTAL (set before any table), WAL, the three
      tables + indexes, UNIQUE roll-up key, unique origin_event_id;
    - rollback keeps every row of all three tables under *_rolled_back_036
      (appending), version 0; re-forward (the lazy ensure_db path) gives
      fresh empty tables beside the preserved copies.
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


def _build_v35(db_path) -> sqlite3.Connection:
    conn = connect(db_path)
    by_number = {m.number: m for m in list_migrations()}
    for num in bootstrap._registry_migration_numbers():
        if num >= 36:
            break
        apply_migration(conn, by_number[num], target=None if num == 1 else "registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 35
    return conn


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _classes(conn) -> dict[str, tuple]:
    return {
        r[0]: tuple(r[1:]) for r in conn.execute(
            "SELECT data_class, retention_days, legal_baseline_days, editable "
            "FROM bundle_config_retention"
        )
    }


def test_registry_forward_rollback_forward(tmp_path):
    conn = _build_v35(tmp_path / "registry.db")
    before = _classes(conn)
    assert "telemetry_raw" not in before
    forward, rollback = _migration(36), _migration(36, "rollback")

    # ---- forward ---------------------------------------------------------
    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 36
    after = _classes(conn)
    assert after["telemetry_raw"] == (7, 7, 1)
    assert after["telemetry_rollup"] == (180, 180, 1)
    assert {k: v for k, v in after.items() if k in before} == before
    conn.execute(
        "INSERT INTO retention_runs (run_id, started_at, trigger, status, archive_enabled) "
        "VALUES ('r-1', '2026-09-29T09:00:00.000Z', 'scheduler', 'ok', 1)"
    )
    for bad in (
        "INSERT INTO retention_runs (run_id, started_at, trigger, status) "
        "VALUES ('r-2', 'x', 'cron', 'ok')",
        "INSERT INTO retention_runs (run_id, started_at, trigger, status) "
        "VALUES ('r-3', 'x', 'script', 'done')",
        "INSERT INTO retention_runs (run_id, started_at, trigger, status, archive_enabled) "
        "VALUES ('r-4', 'x', 'script', 'ok', 2)",
        "INSERT INTO retention_runs (run_id, started_at, trigger, status) "
        "VALUES ('r-1', 'x', 'script', 'ok')",   # run_id unique
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(bad)
    # A super_admin's edit that the rollback must keep.
    conn.execute("UPDATE bundle_config_retention SET retention_days = 30, updated_by = 1 "
                 "WHERE data_class = 'telemetry_raw'")
    conn.commit()

    # ---- rollback --------------------------------------------------------
    apply_migration(conn, rollback, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 35
    assert "retention_runs" not in _tables(conn)
    assert _classes(conn) == before
    kept_runs = conn.execute(
        "SELECT run_id, trigger, status FROM retention_runs_rolled_back_036").fetchall()
    assert [tuple(r) for r in kept_runs] == [("r-1", "scheduler", "ok")]
    kept_classes = {
        r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT data_class, retention_days, updated_by "
            "FROM bundle_config_retention_rolled_back_036")
    }
    assert kept_classes == {"telemetry_raw": (30, 1), "telemetry_rollup": (180, None)}

    # ---- forward again ---------------------------------------------------
    apply_migration(conn, forward, target="registry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 36
    # The super_admin's 30 days comes back — the defaults would have made
    # the first nightly run after the re-upgrade delete raw rows 8-30 days old.
    assert _classes(conn)["telemetry_raw"] == (30, 7, 1)
    assert conn.execute(
        "SELECT updated_by FROM bundle_config_retention WHERE data_class = 'telemetry_raw'"
    ).fetchone()[0] == 1
    assert _classes(conn)["telemetry_rollup"] == (180, 180, 1)
    assert {k: v for k, v in _classes(conn).items() if k in before} == before
    assert conn.execute("SELECT COUNT(*) FROM retention_runs").fetchone()[0] == 0
    # A second edit, a second rollback and re-upgrade: the NEWEST kept wins.
    conn.execute("UPDATE bundle_config_retention SET retention_days = 90, updated_by = 2 "
                 "WHERE data_class = 'telemetry_raw'")
    conn.commit()
    conn.execute(
        "INSERT INTO retention_runs (run_id, started_at, trigger, status) "
        "VALUES ('r-9', '2026-09-30T09:00:00.000Z', 'script', 'partial')"
    )
    conn.commit()
    # A second rollback APPENDS to the preserved copies.
    apply_migration(conn, rollback, target="registry")
    assert conn.execute(
        "SELECT COUNT(*) FROM retention_runs_rolled_back_036").fetchone()[0] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM bundle_config_retention_rolled_back_036").fetchone()[0] == 4
    apply_migration(conn, forward, target="registry")
    assert _classes(conn)["telemetry_raw"] == (90, 7, 1)
    conn.close()


def test_registry_first_forward_seeds_defaults_with_empty_kept_copies(tmp_path):
    """A first upgrade (nothing ever rolled back): the restore step finds
    empty kept copies and the defaults are seeded."""
    conn = _build_v35(tmp_path / "registry.db")
    apply_migration(conn, _migration(36), target="registry")
    assert _classes(conn)["telemetry_raw"] == (7, 7, 1)
    assert _classes(conn)["telemetry_rollup"] == (180, 180, 1)
    for kept in ("bundle_config_retention_rolled_back_036",
                 "adapter_poller_state_rolled_back_036"):
        assert conn.execute(f"SELECT COUNT(*) FROM {kept}").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM adapter_poller_state").fetchone()[0] == 0
    conn.close()


def _telemetry_row(n: int, **kw) -> telemetry.TelemetryRow:
    base = dict(
        received_at=f"2026-09-2{n % 9}T10:00:00.000Z", source="buoy:acme",
        event_type="pihole.query", severity="info", source_host="buoy-acme-1",
        domain=f"d{n}.example.test", device="192.0.2.10", payload='{"n":%d}' % n,
        payload_truncated=False, payload_sha256=f"{n:064x}",
    )
    base.update(kw)
    return telemetry.TelemetryRow(**base)


def test_telemetry_forward_rollback_forward(tmp_path):
    telemetry.reset_schema_cache()
    tenant = tmp_path / "clients" / "acme-corp"
    tenant.mkdir(parents=True)
    path = tenant / "telemetry.db"

    # ---- forward (the lazy path; 037 — NextDNS — and 039 — UniFi — follow)
    assert telemetry.ensure_db(path) == [36, 37, 39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2        # INCREMENTAL
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 46
    assert {"telemetry_raw", "telemetry_hourly", "first_seen_domains"} <= _tables(conn)
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_telemetry_raw_received", "idx_telemetry_raw_sha", "idx_telemetry_raw_origin",
            "idx_telemetry_hourly_domain", "idx_first_seen_domains_first",
            "idx_first_seen_domains_last"} <= indexes
    store = telemetry.TelemetryStore(tmp_path)
    store.write("acme-corp", [_telemetry_row(1), _telemetry_row(2, origin_event_id=77)])
    # UNIQUE roll-up key and unique origin id.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO telemetry_hourly (hour, event_type, domain, device, count, "
                     "first_seen, last_seen) SELECT hour, event_type, domain, device, 1, "
                     "first_seen, last_seen FROM telemetry_hourly LIMIT 1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO telemetry_raw (received_at, source, event_type, payload, "
                     "payload_sha256, origin_event_id) VALUES ('x','s','e','{}','h',77)")
    conn.close()

    # ---- rollback (a real downgrade takes 046, 039, then 037 off first) ---
    conn = sqlite3.connect(path)
    apply_migration(conn, _migration(46, "rollback"), target="telemetry")
    apply_migration(conn, _migration(39, "rollback"), target="telemetry")
    apply_migration(conn, _migration(37, "rollback"), target="telemetry")
    apply_migration(conn, _migration(36, "rollback"), target="telemetry")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    tables = _tables(conn)
    assert not {"telemetry_raw", "telemetry_hourly", "first_seen_domains"} & tables
    assert conn.execute("SELECT COUNT(*) FROM telemetry_raw_rolled_back_036").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM telemetry_hourly_rolled_back_036").fetchone()[0] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM first_seen_domains_rolled_back_036").fetchone()[0] == 2
    kept = conn.execute(
        "SELECT payload, payload_sha256, received_at, origin_event_id "
        "FROM telemetry_raw_rolled_back_036 ORDER BY id").fetchall()
    assert kept[1] == ('{"n":2}', f"{2:064x}", "2026-09-22T10:00:00.000Z", 77)
    conn.close()

    # ---- forward again (lazy) ---------------------------------------------
    telemetry.reset_schema_cache()
    assert telemetry.ensure_db(path) == [36, 37, 39, 46]
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM telemetry_raw").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM telemetry_raw_rolled_back_036").fetchone()[0] == 2
    conn.close()
    store.write("acme-corp", [_telemetry_row(3)])
    conn = sqlite3.connect(path)
    apply_migration(conn, _migration(37, "rollback"), target="telemetry")
    apply_migration(conn, _migration(36, "rollback"), target="telemetry")
    assert conn.execute("SELECT COUNT(*) FROM telemetry_raw_rolled_back_036").fetchone()[0] == 3
    conn.close()


def test_telemetry_sections_never_reach_the_registry_or_client_dbs(tmp_path):
    """The registry apply takes only the registry section; the events and
    indicators provisioning takes only theirs."""
    conn = _build_v35(tmp_path / "registry.db")
    apply_migration(conn, _migration(36), target="registry")
    assert not {"telemetry_raw", "telemetry_hourly", "first_seen_domains"} & _tables(conn)
    conn.close()
    from apps.octo.client_provisioning import _target_section

    sql = _migration(36).sql
    events = _target_section(sql, "events")
    assert "ingested_at" in events and "telemetry" not in events
    assert _target_section(sql, "indicators").strip() == ""
    assert "telemetry_raw" in _target_section(sql, "telemetry")


def _columns(conn, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _indexes(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}


def test_events_arrival_column_forward_rollback_forward(tmp_path):
    """The events section: a NEW tenant's events.db (provisioning) is born
    with events.ingested_at + its index; the rollback keeps every stamp
    (events_arrival_rolled_back_036, appended to) and removes the column;
    forward again restores it — and the telemetry columns ride along."""
    from apps.octo.client_provisioning import _provision_db

    path = tmp_path / "events.db"
    _provision_db(path, "events")
    conn = sqlite3.connect(path)
    assert "ingested_at" in _columns(conn, "events")
    assert "idx_events_ingested_at" in _indexes(conn)
    conn.execute(
        "INSERT INTO events (received_at, source, event_type, severity, payload, "
        " payload_sha256, ingested_at) VALUES ('2025-01-01T00:00:00.000Z', 'rocketcyber', "
        " 'rocketcyber.incident', 'high', '{}', 'a', '2026-09-29T10:00:00.000Z')")
    conn.execute(
        "INSERT INTO events (received_at, source, event_type, severity, payload, "
        " payload_sha256) VALUES ('2025-01-02T00:00:00.000Z', 'wazuh', 'wazuh.alert', "
        " 'high', '{}', 'b')")          # stored before 036: no stamp
    conn.commit()

    apply_migration(conn, _migration(36, "rollback"), target="events")
    assert "ingested_at" not in _columns(conn, "events")
    assert "idx_events_ingested_at" not in _indexes(conn)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    assert conn.execute(
        "SELECT event_id, ingested_at, payload_sha256 FROM events_arrival_rolled_back_036"
    ).fetchall() == [(1, "2026-09-29T10:00:00.000Z", "a")]
    assert "idx_events_arrival_rolled_back_036" in _indexes(conn)

    apply_migration(conn, _migration(36), target="events")
    assert "ingested_at" in _columns(conn, "events")
    assert "idx_events_ingested_at" in _indexes(conn)
    conn.execute("UPDATE events SET ingested_at = '2026-09-30T00:00:00.000Z' WHERE id = 2")
    conn.commit()
    apply_migration(conn, _migration(36, "rollback"), target="events")
    assert conn.execute(
        "SELECT COUNT(*) FROM events_arrival_rolled_back_036").fetchone()[0] == 2
    conn.close()


def test_telemetry_arrival_columns_and_indexes(tmp_path):
    telemetry.reset_schema_cache()
    tenant = tmp_path / "clients" / "acme-corp"
    tenant.mkdir(parents=True)
    path = tenant / "telemetry.db"
    telemetry.ensure_db(path)
    conn = sqlite3.connect(path)
    assert "ingested_at" in _columns(conn, "telemetry_raw")
    assert "last_arrival" in _columns(conn, "telemetry_hourly")
    assert {"idx_telemetry_raw_ingested", "idx_telemetry_hourly_arrival"} <= _indexes(conn)
    conn.close()
    store = telemetry.TelemetryStore(tmp_path, clock=lambda: "2026-09-29T11:00:00.000Z")
    store.write("acme-corp", [_telemetry_row(1)])
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT ingested_at FROM telemetry_raw").fetchall() == [
        ("2026-09-29T11:00:00.000Z",)]
    assert conn.execute("SELECT last_arrival FROM telemetry_hourly").fetchall() == [
        ("2026-09-29T11:00:00.000Z",)]
    apply_migration(conn, _migration(36, "rollback"), target="telemetry")
    assert conn.execute(
        "SELECT ingested_at FROM telemetry_raw_rolled_back_036").fetchall() == [
        ("2026-09-29T11:00:00.000Z",)]
    assert conn.execute(
        "SELECT last_arrival FROM telemetry_hourly_rolled_back_036").fetchall() == [
        ("2026-09-29T11:00:00.000Z",)]
    conn.close()


def test_registry_adapter_poller_state_forward_rollback_forward(tmp_path):
    """adapter_poller_state (R3): one JSON value per (instance, key); the
    rollback keeps its rows (appending), forward again RESTORES the newest
    kept value per key — RocketCyber's history marks survive a round trip."""
    conn = _build_v35(tmp_path / "registry.db")
    forward, rollback = _migration(36), _migration(36, "rollback")
    apply_migration(conn, forward, target="registry")
    conn.execute("INSERT INTO adapter_poller_state VALUES (7, 'history_skipped', '{}', 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO adapter_poller_state VALUES (7, 'history_skipped', '[]', 'y')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO adapter_poller_state VALUES (7, '', '[]', 'y')")
    conn.commit()
    apply_migration(conn, rollback, target="registry")
    assert "adapter_poller_state" not in _tables(conn)
    assert [tuple(r) for r in conn.execute(
        "SELECT instance_id, key FROM adapter_poller_state_rolled_back_036")] == [
        (7, "history_skipped")]
    apply_migration(conn, forward, target="registry")
    assert [tuple(r) for r in conn.execute(
        "SELECT instance_id, key, value_json FROM adapter_poller_state")] == [
        (7, "history_skipped", "{}")]
    # The poller moves on; a second round trip restores the NEWER value.
    conn.execute("UPDATE adapter_poller_state SET value_json = '{\"ids\":[5]}', "
                 "updated_at = 'z' WHERE instance_id = 7")
    conn.execute("INSERT INTO adapter_poller_state VALUES (8, 'history_skipped', '[]', 'z')")
    conn.commit()
    apply_migration(conn, rollback, target="registry")
    apply_migration(conn, forward, target="registry")
    assert [tuple(r) for r in conn.execute(
        "SELECT instance_id, key, value_json FROM adapter_poller_state ORDER BY instance_id")] == [
        (7, "history_skipped", '{"ids":[5]}'), (8, "history_skipped", "[]")]
    conn.close()
