"""The retention job prunes the NextDNS telemetry-tier tables (migration
037) with the hourly roll-up class: `nextdns_hourly` and
`nextdns_signal_buckets` go when their `last_arrival` is older than the
telemetry_rollup cutoff (180 days); the alerts they counted (events.db) are
the 'events' class's and are untouched here. Dry run counts, deletes
nothing."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo.retention.job import RetentionJob
from apps.octo.tests._tiering_fixtures import NOW, ago, db, insert_event, make_root, rows

A = "acme-corp"


@pytest.fixture
def root(tmp_path, monkeypatch):
    return make_root(tmp_path, monkeypatch, tenants=(A,))


def _seed(root) -> None:
    conn = sqlite3.connect(db(root, A, "telemetry"))
    for hour, arrived in (("2026-03-01T10:00:00Z", ago(days=200)),
                          ("2026-06-01T10:00:00Z", ago(days=120))):
        conn.execute(
            "INSERT INTO nextdns_hourly (hour, profile_id, queries, fetched_at, last_arrival) "
            "VALUES (?, 'abc123', 900, ?, ?)", (hour, arrived, arrived))
        conn.execute(
            "INSERT INTO nextdns_signal_buckets (bucket_key, hour, profile_id, reason_id, "
            " event_id, hits, first_seen, last_seen, last_arrival) "
            "VALUES (?, ?, 'abc123', 'dga', 1, 3, ?, ?, ?)",
            (f"k-{hour}", hour, arrived, arrived, arrived))
    conn.commit()
    conn.close()


def test_nextdns_rollups_age_out_with_the_rollup_class(root):
    _seed(root)
    alert = insert_event(root, A, event_type="nextdns.security_block", payload={"n": 1},
                         received_at=ago(days=200), severity="high")
    dry = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script", dry_run=True)
    [t] = [t for t in dry.tenants if t.slug == A]
    assert t.classes["telemetry_rollup"].planned == 2
    assert len(rows(db(root, A, "telemetry"), "SELECT * FROM nextdns_hourly")) == 2

    report = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script")
    [t] = [t for t in report.tenants if t.slug == A]
    assert t.classes["telemetry_rollup"].deleted == 2
    assert rows(db(root, A, "telemetry"), "SELECT hour FROM nextdns_hourly") == [
        ("2026-06-01T10:00:00Z",)]
    assert rows(db(root, A, "telemetry"), "SELECT hour FROM nextdns_signal_buckets") == [
        ("2026-06-01T10:00:00Z",)]
    # The alert itself is an event (365 d): still there.
    assert rows(db(root, A, "events"), "SELECT id FROM events WHERE id = ?", (alert,))
