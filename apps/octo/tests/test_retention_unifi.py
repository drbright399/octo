"""The retention job prunes the UniFi telemetry-tier tables (migration 039)
with the hourly roll-up class: `unifi_hourly`, `unifi_signal_buckets` and a
long-unmapped site's `unifi_syslog_cursor` go when their `last_arrival` is
older than the telemetry_rollup cutoff (180 days); the alerts (events.db)
are the 'events' class's and are untouched here. Dry run counts, deletes
nothing."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.retention.job import ROLLUP_TABLES, RetentionJob
from apps.octo.tests._tiering_fixtures import NOW, ago, db, insert_event, make_root, rows

A = "acme-corp"
SCOPE = "F1X7A0000000000000000000000000000000000000000000000000A001:100000001/f1x7517e0000000000000001"


@pytest.fixture
def root(tmp_path, monkeypatch):
    return make_root(tmp_path, monkeypatch, tenants=(A,))


def _seed(root) -> None:
    conn = sqlite3.connect(db(root, A, "telemetry"))
    for n, (hour, arrived) in enumerate((("2026-03-01T10:00:00Z", ago(days=200)),
                                         ("2026-06-01T10:00:00Z", ago(days=120)))):
        conn.execute(
            "INSERT INTO unifi_hourly (hour, scope, kind, ocsf_class_uid, events, last_arrival) "
            "VALUES (?, ?, 'firewall_block', 4001, 12, ?)", (hour, SCOPE, arrived))
        conn.execute(
            "INSERT INTO unifi_signal_buckets (bucket_key, hour, scope, kind, subject, event_id, "
            " hits, first_seen, last_seen, last_arrival) "
            "VALUES (?, ?, ?, 'ips_threat', 's', 1, 3, ?, ?, ?)",
            (f"k-{hour}", hour, SCOPE, arrived, arrived, arrived))
        conn.execute(
            "INSERT INTO unifi_syslog_cursor (scope, hwm_ms, scanned_to_ms, updated_at, "
            " last_arrival) VALUES (?, 1, 1, ?, ?)", (f"{SCOPE}{n}", arrived, arrived))
    conn.commit()
    conn.close()


def test_unifi_tables_are_rollup_tables():
    tables = {t for t, _k in ROLLUP_TABLES}
    assert {"unifi_hourly", "unifi_signal_buckets", "unifi_syslog_cursor"} <= tables


def test_unifi_rollups_age_out_with_the_rollup_class(root):
    _seed(root)
    alert = insert_event(root, A, event_type="unifi.ips_threat", payload={"n": 1},
                         received_at=ago(days=200), severity="high")
    dry = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script", dry_run=True)
    [t] = [t for t in dry.tenants if t.slug == A]
    assert t.classes["telemetry_rollup"].planned == 3
    assert len(rows(db(root, A, "telemetry"), "SELECT * FROM unifi_hourly")) == 2

    report = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script")
    [t] = [t for t in report.tenants if t.slug == A]
    assert t.classes["telemetry_rollup"].deleted == 3
    for table in ("unifi_hourly", "unifi_signal_buckets"):
        assert rows(db(root, A, "telemetry"), f"SELECT hour FROM {table}") == [
            ("2026-06-01T10:00:00Z",)], table
    assert rows(db(root, A, "telemetry"), "SELECT scope FROM unifi_syslog_cursor") == [
        (f"{SCOPE}1",)]
    assert rows(db(root, A, "events"), "SELECT id FROM events WHERE id = ?", (alert,))
