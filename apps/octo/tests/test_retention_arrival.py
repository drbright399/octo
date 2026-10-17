"""Retention by ARRIVAL time (owner decision 2026-09-29).

A row's retention age is measured from when Athena received and stored it
(`events.ingested_at`, `telemetry_raw.ingested_at`,
`telemetry_hourly.last_arrival`), never from the vendor's timestamp
(`received_at`, which stays stored and shown). Real classes throughout — the
sink, the store, the move, the job, the RocketCyber poller; injected clocks,
nothing sleeps, only the vendor socket is fake.

Pins:
  * the sink stamps arrival on signals and telemetry; received_at untouched;
  * an event with a 400-day-old vendor time that arrived today survives the
    nightly run; one that ARRIVED 400 days ago goes;
  * a pre-036 row (no arrival) makes the tenant PENDING: sweep skipped, its
    signals and telemetry not pruned (blocked, run partial, said why) — the
    other tenant is enforced;
  * the backfill (the move script's run) moves telemetry keeping its arrival
    estimate, stamps the rows left with their received_at (never later than
    now), builds the index; afterwards the nightly run enforces by arrival;
    its dry run counts what it would stamp and writes nothing;
  * raw telemetry is pruned and archived by ARRIVAL day; a roll-up by its
    last arrival;
  * a tenant merge copy keeps the arrival;
  * RocketCyber: an open incident created 364 days ago, first imported now,
    survives the run two days later (by vendor time it would have gone).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.ingest import SqliteIngestSink, arrival
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.retention.archive import ColdArchive
from apps.octo.retention.job import RetentionJob
from apps.octo.tests._tiering_fixtures import (
    NOW, ago, db, file_digests, insert_event, iso, live_signal, make_root, pihole_payload,
    rows, write_telemetry,
)
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

A, B = "acme-corp", "globex"


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = make_root(tmp_path, monkeypatch, tenants=(A, B))
    # Tenants are provisioned by the wall clock, which is later than the
    # frozen NOW; onboard them long before the rows these tests write so the
    # onboarding floor (arrival rule 4) stays out of the way unless a test
    # sets it on purpose (`_onboard`).
    _onboard(r, A, ago(days=1000))
    _onboard(r, B, ago(days=1000))
    return r


def _onboard(root, slug: str, when: str) -> None:
    conn = sqlite3.connect(root / "registry.db")
    try:
        conn.execute("UPDATE clients SET onboarded_at = ? WHERE slug = ?", (when, slug))
        conn.commit()
    finally:
        conn.close()


def _job(root, **kw) -> RetentionJob:
    kw.setdefault("archive_from_env", False)
    return RetentionJob(data_root=root, now=lambda: NOW, **kw)


def _ids(root, slug, name, table, key="id") -> set:
    return {r[0] for r in rows(db(root, slug, name), f"SELECT {key} FROM {table}")}


def _event(payload: dict, received_at: str, severity: str = "high"):
    from shared_adapter_contract.types import CanonicalEvent
    import hashlib

    return CanonicalEvent(
        vendor_event_id=str(payload.get("n", "x")), received_at=received_at,
        severity=severity, summary="s", source_host="web-01", payload=payload,
        indicator=None, indicator_type=None,
        payload_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
    )


# ---------------------------------------------------------------------------
# The sink stamps arrival
# ---------------------------------------------------------------------------

def test_the_sink_stamps_arrival_and_keeps_the_vendor_time(root):
    arrived = iso(NOW)
    sink = SqliteIngestSink(root, publish_to_stream=False, clock=lambda: arrived)
    old = sink.ingest(A, "wazuh", _event({"n": 1}, ago(days=400)), event_type="wazuh.alert")
    dns = sink.ingest(A, "buoy:acme", _event(pihole_payload(2), ago(minutes=1), "info"),
                      event_type="pihole.query", dedup=False)
    assert rows(db(root, A, "events"), "SELECT id, received_at, ingested_at FROM events") == [
        (old.event_id, ago(days=400), arrived)]
    assert rows(db(root, A, "telemetry"),
                "SELECT id, received_at, ingested_at FROM telemetry_raw") == [
        (dns.event_id, ago(minutes=1), arrived)]


def test_a_pre_036_events_db_gets_the_column_on_the_first_write(root):
    conn = sqlite3.connect(db(root, B, "events"))
    conn.execute("DROP INDEX idx_events_ingested_at")
    conn.execute("ALTER TABLE events DROP COLUMN ingested_at")
    conn.commit()
    assert not arrival.has_column(conn)
    conn.close()
    SqliteIngestSink(root, publish_to_stream=False, clock=lambda: iso(NOW)).ingest(
        B, "wazuh", _event({"n": 2}, ago(days=3)), event_type="wazuh.alert")
    conn = sqlite3.connect(db(root, B, "events"))
    try:
        assert arrival.has_column(conn)
        assert not arrival.has_index(conn)      # the index is the backfill's job
        assert conn.execute("SELECT ingested_at FROM events").fetchall() == [(iso(NOW),)]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Signals age by arrival
# ---------------------------------------------------------------------------

def test_signals_age_from_arrival_not_from_the_vendor_time(root):
    late_history = insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                                received_at=ago(days=400), ingested_at=ago(days=1),
                                severity="high")
    arrived_long_ago = insert_event(root, A, event_type="wazuh.alert", payload={"n": 2},
                                    received_at=ago(days=10), ingested_at=ago(days=400),
                                    severity="high")
    report = _job(root).run(trigger="scheduler")
    assert report.status == "ok", report.as_dict()
    events = next(t for t in report.tenants if t.slug == A).classes["events"]
    assert (events.planned, events.deleted) == (1, 1)
    assert _ids(root, A, "events", "events") == {late_history}
    assert arrived_long_ago not in _ids(root, A, "events", "events")


# ---------------------------------------------------------------------------
# Backfill pending → nothing of the tenant's signals or telemetry is pruned
# ---------------------------------------------------------------------------

def _pre_036_tenant(root) -> dict:
    """acme-corp as a pre-036 bundle left it: signals and answered DNS in
    events.db without arrival times, and raw telemetry that already
    expired."""
    s = {
        "signal_old": insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                                   received_at=ago(days=400), severity="high", stamped=False),
        "signal_new": insert_event(root, A, event_type="wazuh.alert", payload={"n": 2},
                                   received_at=ago(days=20), severity="high", stamped=False),
        "future": insert_event(root, A, event_type="wazuh.alert", payload={"n": 3},
                               received_at=iso(NOW + timedelta(days=900)), severity="high",
                               stamped=False),
        "dns_old": insert_event(root, A, event_type="pihole.query",
                                payload=pihole_payload(2, "old.example.test", n=1),
                                received_at=ago(days=30), stamped=False),
        "dns_new": insert_event(root, A, event_type="pihole.query",
                                payload=pihole_payload(2, "new.example.test", n=2),
                                received_at=ago(days=2), stamped=False),
        "raw": write_telemetry(root, A, received_at=ago(days=30), domain="raw.example.test"),
    }
    # As a tenant provisioned before 036: no arrival index.
    conn = sqlite3.connect(db(root, A, "events"))
    conn.execute("DROP INDEX idx_events_ingested_at")
    conn.commit()
    conn.close()
    return s


def test_a_pending_backfill_gates_the_tenant_and_says_why(root):
    s = _pre_036_tenant(root)
    b_old = insert_event(root, B, event_type="wazuh.alert", payload={"n": 9},
                         received_at=ago(days=400), severity="high")
    live_signal(root, B)
    before = file_digests(root / "clients" / A)
    report = _job(root).run(trigger="scheduler")
    assert report.status == "partial"
    assert "arrival backfill pending for acme-corp" in report.note
    a = next(t for t in report.tenants if t.slug == A)
    assert a.arrival["pending"] is True
    assert a.sweep.get("skipped") is True
    for name in ("events", "telemetry_raw", "telemetry_rollup", "first_seen_domains"):
        assert a.classes[name].status == "blocked", name
        assert a.classes[name].deleted == 0
    # Classes on Athena's own clock still run.
    assert a.classes["agent_notes"].status == "ok"
    # Nothing of acme-corp's events or telemetry was touched …
    assert _ids(root, A, "events", "events") == {
        s["signal_old"], s["signal_new"], s["future"], s["dns_old"], s["dns_new"]}
    assert _ids(root, A, "telemetry", "telemetry_raw") == {s["raw"]}
    assert before.keys() <= file_digests(root / "clients" / A).keys()
    # … while globex (nothing pending) was enforced.
    assert b_old not in _ids(root, B, "events", "events")
    last = json.loads(rows(root / "registry.db",
                           "SELECT summary_json FROM retention_runs")[-1][0])
    assert last["tenants"][A]["arrival"]["pending"] is True


def test_the_backfill_moves_stamps_and_clears_the_gate(root):
    s = _pre_036_tenant(root)
    # Dry run of the move script's run: counts, writes nothing.
    before = file_digests(root)
    preview = _job(root, sweep_days=None).run(
        dry_run=True, trigger="script", slugs=[A],
        classes=("telemetry_raw", "telemetry_rollup", "first_seen_domains"))
    assert file_digests(root) == before
    sweep = next(t for t in preview.tenants if t.slug == A).sweep
    assert (sweep["moved"], sweep["arrival_stamped"]) == (2, 3)
    assert sweep["arrival_index_built"] is True

    real = _job(root, sweep_days=None).run(
        trigger="script", slugs=[A],
        classes=("telemetry_raw", "telemetry_rollup", "first_seen_domains"))
    t = next(t for t in real.tenants if t.slug == A)
    assert (t.sweep["moved"], t.sweep["arrival_stamped"], t.sweep["error"]) == (2, 3, None)
    # Moved rows keep their arrival ESTIMATE (their received_at): the old one
    # and the pre-existing expired raw row are pruned in the same run.
    assert rows(db(root, A, "telemetry"), "SELECT domain, ingested_at FROM telemetry_raw") == [
        ("new.example.test", ago(days=2))]
    # Left in events.db: signals, stamped with received_at — never later
    # than now (a vendor time 900 days ahead is not an arrival).
    assert rows(db(root, A, "events"), "SELECT id, ingested_at FROM events ORDER BY id") == [
        (s["signal_old"], ago(days=400)), (s["signal_new"], ago(days=20)),
        (s["future"], iso(NOW))]
    conn = sqlite3.connect(db(root, A, "events"))
    try:
        assert arrival.has_index(conn) and not arrival.pending(conn)
    finally:
        conn.close()

    # The gate is clear: the nightly run enforces acme-corp by arrival.
    nightly = _job(root).run(trigger="scheduler")
    assert nightly.status == "ok", nightly.as_dict()
    assert _ids(root, A, "events", "events") == {s["signal_new"], s["future"]}


def test_the_job_builds_the_index_when_nothing_is_left_to_stamp(root):
    conn = sqlite3.connect(db(root, A, "events"))
    conn.execute("DROP INDEX idx_events_ingested_at")
    conn.commit()
    conn.close()
    insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                 received_at=ago(days=3), severity="high")
    dry = _job(root).run(dry_run=True, trigger="script")
    assert next(t for t in dry.tenants if t.slug == A).arrival == {
        "pending": False, "index_to_build": True}
    report = _job(root).run(trigger="scheduler")
    assert next(t for t in report.tenants if t.slug == A).arrival == {
        "pending": False, "index_built": True}
    conn = sqlite3.connect(db(root, A, "events"))
    try:
        assert arrival.has_index(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Estimates: a 036 round trip gets the real arrival back; id order floors it
# ---------------------------------------------------------------------------

def _v035_insert(root, slug, *, payload: dict, received_at: str, severity="low") -> int:
    """A row as the code BEFORE 036 writes it (events.db has no arrival column)."""
    import hashlib

    text = json.dumps(payload, separators=(",", ":"))
    conn = sqlite3.connect(db(root, slug, "events"))
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary) VALUES (?, 'wazuh', 'web-01', 'wazuh.alert', "
            " ?, ?, ?, '')",
            (received_at, severity, text, hashlib.sha256(text.encode()).hexdigest()))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _backfill(root, slugs=(A,)):
    return _job(root, sweep_days=None).run(
        trigger="backfill", slugs=list(slugs),
        classes=("telemetry_raw", "telemetry_rollup", "first_seen_domains"))


def test_a_036_round_trip_keeps_the_real_arrival_through_the_backfill(root):
    """v0.11 → rollback → re-upgrade → backfill → nightly: the late-history
    signal keeps the arrival the rollback saved (10 days ago), not its
    400-day-old vendor time — the nightly run keeps it."""
    from apps.octo.migration import apply_migration, list_migrations

    rollback = next(m for m in list_migrations(kind="rollback") if m.number == 36)
    late = insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                        received_at=ago(days=400), ingested_at=ago(days=10), severity="low")
    live = insert_event(root, A, event_type="wazuh.alert", payload={"n": 2},
                        received_at=ago(days=9), severity="low")
    conn = sqlite3.connect(db(root, A, "events"))
    apply_migration(conn, rollback, target="events")
    conn.close()
    # Downgraded: pre-036 code stores more (no arrival column) — one of them
    # history with an old vendor time, stored after the live row.
    during = _v035_insert(root, A, payload={"n": 3}, received_at=ago(days=500))
    # A kept stamp for an id whose row is now a DIFFERENT one (an events.db
    # restored from an older backup reuses ids): never applied to it.
    conn = sqlite3.connect(db(root, A, "events"))
    conn.execute("INSERT INTO events_arrival_rolled_back_036 VALUES (?, ?, 'other-sha')",
                 (during, ago(days=600)))
    conn.commit()
    conn.close()
    # Re-upgrade: the sink's first write re-adds the column (old rows NULL).
    SqliteIngestSink(root, publish_to_stream=False, clock=lambda: iso(NOW)).ingest(
        A, "wazuh", _event({"n": 4}, ago(minutes=1)), event_type="wazuh.alert")
    assert _job(root).run(trigger="script").tenants[0].arrival["pending"] is True
    # A tenant merge copy made now estimates exactly as the backfill will.
    from apps.octo.api.routers.admin_tenants import _CopiedEvents, _copy_events

    assert _copy_events(A, B, _CopiedEvents(B)) == (4, 0)
    assert [r[0] for r in rows(db(root, B, "events"),
                               "SELECT ingested_at FROM events ORDER BY id")] == [
        ago(days=10), ago(days=9), ago(days=9), iso(NOW)]

    report = _backfill(root)
    t = next(t for t in report.tenants if t.slug == A)
    assert (t.sweep["arrival_stamped"], t.sweep["error"]) == (3, None)
    assert dict(rows(db(root, A, "events"), "SELECT id, ingested_at FROM events")) | {} == {
        late: ago(days=10),      # the kept stamp (same id, same payload)
        live: ago(days=9),       # the kept stamp
        during: ago(days=9),     # stored after `live`: never earlier than it
        max(late, live, during) + 1: iso(NOW),
    }
    nightly = _job(root).run(trigger="scheduler")
    assert nightly.status == "ok", nightly.as_dict()
    assert {late, live, during} <= _ids(root, A, "events", "events")


def test_the_id_order_floor_keeps_pre_036_late_history(root):
    """Pre-036: a still-open low alert with a 14-month-old vendor time was
    stored three weeks ago, between live rows. Its estimate is the live
    rows' arrival (the floor), so the first nightly run keeps it; the old
    live row before it still ages by its own time; a vendor time in the
    future only lengthens (capped at now)."""
    old_live = insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                            received_at=ago(days=400), severity="low", stamped=False)
    live = insert_event(root, A, event_type="wazuh.alert", payload={"n": 2},
                        received_at=ago(days=21), severity="low", stamped=False)
    late = insert_event(root, A, event_type="wazuh.alert", payload={"n": 3},
                        received_at=ago(days=425), severity="low", stamped=False)
    future = insert_event(root, A, event_type="wazuh.alert", payload={"n": 4},
                          received_at=iso(NOW + timedelta(days=30)), severity="low",
                          stamped=False)
    after = insert_event(root, A, event_type="wazuh.alert", payload={"n": 5},
                         received_at=ago(days=20), severity="low", stamped=False)
    _backfill(root)
    assert rows(db(root, A, "events"), "SELECT id, ingested_at FROM events ORDER BY id") == [
        (old_live, ago(days=400)), (live, ago(days=21)), (late, ago(days=21)),
        (future, iso(NOW)), (after, iso(NOW))]
    _job(root).run(trigger="scheduler")
    assert _ids(root, A, "events", "events") == {live, late, future, after}


def test_the_onboarding_floor_keeps_first_imported_history(root):
    """A tenant onboarded 8 days ago whose FIRST rows were old alerts listed
    oldest-first (vendor times 400 and 390 days back) — no lower id exists,
    so only the onboarding floor stops the first enforcing run from deleting
    them. The backfill and a merge copy both stamp them with the onboarding
    time; rows that arrived later keep their own time."""
    _onboard(root, A, ago(days=8))
    head = [insert_event(root, A, event_type="wazuh.alert", payload={"n": n},
                         received_at=ago(days=d), severity="low", stamped=False)
            for n, d in ((1, 400), (2, 390))]
    live = insert_event(root, A, event_type="wazuh.alert", payload={"n": 3},
                        received_at=ago(days=7), severity="low", stamped=False)
    recent = insert_event(root, A, event_type="wazuh.alert", payload={"n": 4},
                          received_at=ago(minutes=5), severity="low", stamped=False)

    from apps.octo.api.routers.admin_tenants import _CopiedEvents, _copy_events

    assert _copy_events(A, B, _CopiedEvents(B), subject_onboarded_at=ago(days=8)) == (4, 0)
    assert [r[0] for r in rows(db(root, B, "events"),
                               "SELECT ingested_at FROM events ORDER BY id")] == [
        ago(days=8), ago(days=8), ago(days=7), ago(minutes=5)]

    report = _backfill(root)
    t = next(t for t in report.tenants if t.slug == A)
    assert (t.sweep["arrival_stamped"], t.sweep["error"]) == (4, None)
    assert rows(db(root, A, "events"), "SELECT id, ingested_at FROM events ORDER BY id") == [
        (head[0], ago(days=8)), (head[1], ago(days=8)), (live, ago(days=7)),
        (recent, ago(minutes=5))]
    nightly = _job(root).run(trigger="scheduler")
    assert nightly.status == "ok", nightly.as_dict()
    assert set(head) | {live, recent} <= _ids(root, A, "events", "events")


def test_the_onboarding_floor_is_read_safely():
    assert arrival.onboarded_floor("2026-09-19T10:00:00+00:00") == "2026-09-19T10:00:00.000Z"
    assert arrival.onboarded_floor("2026-09-19T10:00:00.123Z") == "2026-09-19T10:00:00.123Z"
    assert arrival.onboarded_floor(datetime(2026, 9, 19, 10, tzinfo=timezone.utc)) == (
        "2026-09-19T10:00:00.000Z")
    for bad in (None, "", "not a time", 0, True):
        assert arrival.onboarded_floor(bad) is None


def test_the_onboarding_floor_is_optional(root, tmp_path):
    assert arrival.tenant_onboarded_at(root, A) == ago(days=1000)
    assert arrival.tenant_onboarded_at(root, "no-such-tenant") is None
    assert arrival.tenant_onboarded_at(tmp_path / "missing", A) is None
    (tmp_path / "junk").mkdir()
    (tmp_path / "junk" / "registry.db").write_bytes(b"not a database")
    assert arrival.tenant_onboarded_at(tmp_path / "junk", A) is None


def test_the_estimator_never_goes_earlier_than_received_at_or_later_than_now():
    est = arrival.Estimator("2026-09-29T12:00:00.000Z", floor="2026-09-01T00:00:00.000Z")
    assert est.estimate("2025-01-01T00:00:00.000Z") == "2026-09-01T00:00:00.000Z"
    assert est.estimate("2026-09-10T00:00:00.000Z") == "2026-09-10T00:00:00.000Z"
    # A kept stamp is the row's real arrival (still floored).
    assert est.estimate("2025-01-01T00:00:00.000Z",
                        preserved="2026-09-11T00:00:00.000Z") == "2026-09-11T00:00:00.000Z"
    assert est.stamped("2027-01-01T00:00:00.000Z") == "2026-09-29T12:00:00.000Z"
    assert est.estimate("2025-01-01T00:00:00.000Z") == "2026-09-29T12:00:00.000Z"
    assert arrival.match_preserved([("s1", "a"), ("s2", "b"), ("s0", "a")], "a") == "s1"
    assert arrival.match_preserved([("s1", "b")], "a") is None
    assert arrival.match_preserved(None, "a") is None


# ---------------------------------------------------------------------------
# Telemetry ages by arrival too
# ---------------------------------------------------------------------------

def test_raw_telemetry_is_pruned_and_archived_by_arrival_day(root, tmp_path):
    # A sensor with a wrong clock (30 days slow) that delivered yesterday,
    # and one 30 days FAST that delivered 9 days ago.
    slow = write_telemetry(root, A, received_at=ago(days=30), ingested_at=ago(days=1),
                           domain="slow.example.test")
    fast = write_telemetry(root, A, received_at=iso(NOW + timedelta(days=30)),
                           ingested_at=ago(days=9), domain="fast.example.test", n=1)
    (tmp_path / "archive").mkdir()
    archive = ColdArchive(tmp_path / "archive")
    report = _job(root, archive=archive).run(trigger="scheduler")
    assert report.status == "ok", report.as_dict()
    assert _ids(root, A, "telemetry", "telemetry_raw") == {slow}
    day = ago(days=9)[:10]
    [line] = archive.read_day(A, day)
    assert (line["id"], line["ingested_at"]) == (fast, ago(days=9))
    assert line["received_at"] == iso(NOW + timedelta(days=30))


def test_the_rollup_ages_by_its_last_arrival(root):
    conn = sqlite3.connect(db(root, A, "telemetry"))
    conn.executemany(
        "INSERT INTO telemetry_hourly (hour, event_type, domain, device, count, first_seen, "
        " last_seen, last_arrival) VALUES (?, 'pihole.query', ?, '192.0.2.10', 1, ?, ?, ?)",
        [
            # an old hour forwarded as a backlog last week: kept
            ("2026-01-01T10:00:00Z", "backlog.example.test", "2026-01-01T10:00:00.000Z",
             "2026-01-01T10:00:00.000Z", ago(days=7)),
            # a future hour (fast clock) that arrived 200 days ago: gone
            ("2027-06-01T10:00:00Z", "future.example.test", "2027-06-01T10:00:00.000Z",
             "2027-06-01T10:00:00.000Z", ago(days=200)),
        ])
    conn.commit()
    conn.close()
    live_signal(root, B)
    report = _job(root).run(trigger="scheduler")
    rollup = next(t for t in report.tenants if t.slug == A).classes["telemetry_rollup"]
    assert rollup.deleted == 1
    assert _ids(root, A, "telemetry", "telemetry_hourly", "domain") == {"backlog.example.test"}


# ---------------------------------------------------------------------------
# A merge copy keeps the arrival
# ---------------------------------------------------------------------------

def test_a_merge_copy_keeps_the_arrival(root):
    from apps.octo.api.routers.admin_tenants import _CopiedEvents, _copy_events

    stamped = insert_event(root, A, event_type="wazuh.alert", payload={"n": 1},
                           received_at=ago(days=50), ingested_at=ago(days=5), severity="high")
    unstamped = insert_event(root, A, event_type="wazuh.alert", payload={"n": 2},
                             received_at=ago(days=60), severity="high", stamped=False)
    assert stamped and unstamped
    copied, skipped = _copy_events(A, B, _CopiedEvents(B))
    assert (copied, skipped) == (2, 0)
    # The unstamped row was stored AFTER a row that arrived 5 days ago (a
    # higher id): it cannot have arrived earlier — its estimate is that
    # floor, not its 60-day-old vendor time.
    assert rows(db(root, B, "events"),
                "SELECT received_at, ingested_at FROM events ORDER BY id") == [
        (ago(days=50), ago(days=5)), (ago(days=60), ago(days=5))]


# ---------------------------------------------------------------------------
# RocketCyber: an old open incident imported today survives the nightly run
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rocketcyber_old_open_incident_survives_the_nightly_run(bedrock_root):  # noqa: F811
    from apps.octo import paths
    from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
    from apps.octo.adapters.rocketcyber.poller import RocketCyberPoller
    from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
        CREDS, FakeRocketCyberTransport, client_factory, incident, real_client,
    )
    from apps.octo.client_provisioning import create_client
    from apps.octo.instances import create_instance, tenant_map
    from apps.octo.instances.tenant_map import MappingIngestSink, TenantMapping

    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    record = create_instance(
        vendor_slug="rocketcyber", display_name="RocketCyber",
        credentials_dict=dict(CREDS), instance_config={"poll_interval_sec": 0.01},
    )
    # A long-running integration (saved 400 days ago): a customer mapped
    # today brings an incident opened 364 days ago that is still open.
    reg = sqlite3.connect(paths.registry_db_path())
    reg.execute("UPDATE adapter_instances SET configured_at = ? WHERE id = ?",
                (format_utc_ms(t0 - timedelta(days=400)), record.id))
    reg.commit()
    reg.close()
    create_client("acme-corp", "Acme Corp", kind="client")
    tenant_map.set_mappings(record.id, [TenantMapping("2001", "acme-corp")])
    transport = FakeRocketCyberTransport()
    opened = t0 - timedelta(days=364)
    transport.incidents = [incident(1, created=opened, updated=opened)]
    poller = RocketCyberPoller(
        adapter=RocketCyberSourceAdapter(client_factory=client_factory(transport)),
        client=real_client(transport),
        sink=MappingIngestSink(
            SqliteIngestSink(publish_to_stream=False, clock=lambda: format_utc_ms(t0)),
            record.id),
        default_tenant_slug="_unmapped", instance_id=record.id, now=lambda: t0,
    )
    await poller._drain_once()
    events_db = paths.client_dir("acme-corp") / "events.db"
    [(row_id, received, ingested)] = rows(
        events_db, "SELECT id, received_at, ingested_at FROM events")
    assert received == format_utc_ms(opened)          # the vendor's time, as shown
    assert ingested == format_utc_ms(t0)              # arrival

    nightly = t0 + timedelta(days=2)
    cutoff = format_utc_ms(nightly - timedelta(days=365))
    assert received < cutoff        # by the vendor's time it would go tonight
    # Script runs: the arrival rule is the point here — a SCHEDULED run
    # would (rightly) refuse the year-long jump of the second clock.
    report = RetentionJob(data_root=paths.data_root(), now=lambda: nightly,
                          archive_from_env=False).run(trigger="script")
    assert report.status == "ok", report.as_dict()
    assert [r[0] for r in rows(events_db, "SELECT id FROM events")] == [row_id]
    # It goes a year after it ARRIVED.
    later = RetentionJob(data_root=paths.data_root(),
                         now=lambda: t0 + timedelta(days=366),
                         archive_from_env=False).run(trigger="script")
    assert later.status == "ok"
    assert rows(events_db, "SELECT id FROM events") == []


def test_the_script_names_a_tenant_waiting_for_the_backfill(root, capsys):
    import scripts.enforce_retention as script

    _pre_036_tenant(root)
    # Exit 1: the run is partial — a tenant needs the backfill first.
    assert script.main(["--data-root", str(root), "--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "partial — arrival backfill pending for acme-corp" in out
    assert "events 0 [waiting for the one-off backfill]" in out
    assert "move_telemetry_out_of_events.py" in out
