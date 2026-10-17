"""The in-app nightly trigger (`apps.octo.retention.scheduler`).

Driven with an injected clock through `tick()` — the thread's only job is to
call it — against the REAL job on a real data root. Pins: env parsing,
next-run arithmetic, catch-up only for a bundle that has run before, one run
per due time, a failing run never kills the schedule, and the app wiring
(off unless OCTO_RETENTION_SCHEDULE is set).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.retention import scheduler as sched
from apps.octo.retention.job import RetentionJob, last_run
from apps.octo.tests._tiering_fixtures import insert_event, live_signal, make_root


def _t(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)


@pytest.mark.parametrize("env,expected", [
    ({}, False), ({"OCTO_RETENTION_SCHEDULE": "0"}, False),
    ({"OCTO_RETENTION_SCHEDULE": "1"}, True), ({"OCTO_RETENTION_SCHEDULE": "true"}, True),
    ({"OCTO_RETENTION_SCHEDULE": "YES"}, True),
])
def test_schedule_enabled(env, expected):
    assert sched.schedule_enabled(env) is expected


@pytest.mark.parametrize("raw,hour", [(None, 9), ("3", 3), ("23", 23), ("24", 9),
                                      ("-1", 9), ("nine", 9)])
def test_schedule_hour(raw, hour):
    env = {} if raw is None else {"OCTO_RETENTION_HOUR_UTC": raw}
    assert sched.schedule_hour(env) == hour


def test_next_scheduled_is_strictly_after_now():
    assert sched.next_scheduled(_t("2026-09-29T08:59"), 9) == _t("2026-09-29T09:00")
    assert sched.next_scheduled(_t("2026-09-29T09:00"), 9) == _t("2026-09-30T09:00")
    assert sched.next_scheduled(_t("2026-09-29T23:30"), 9) == _t("2026-09-30T09:00")


def test_first_run_catch_up_only_after_a_missed_night():
    now = _t("2026-09-29T15:00")
    # Never ran: wait for the scheduled hour (dry-run first).
    assert sched.first_run_at(now, 9, None) == _t("2026-09-30T09:00")
    # Ran this morning: tomorrow.
    assert sched.first_run_at(now, 9, "2026-09-29T09:00:00.000Z") == _t("2026-09-30T09:00")
    # Last run 30 h ago: soon after start.
    assert sched.first_run_at(now, 9, "2026-09-28T09:00:00.000Z") == now + timedelta(
        seconds=sched.STARTUP_DELAY_SEC)
    # An unreadable stamp is treated as no information.
    assert sched.first_run_at(now, 9, "garbage") == _t("2026-09-30T09:00")


def test_tick_runs_the_real_job_once_per_due_time(tmp_path, monkeypatch):
    root = make_root(tmp_path, monkeypatch, tenants=("acme-corp",))
    old = insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                       received_at="2025-01-01T00:00:00.000Z", severity="high")
    live_signal(root, "acme-corp", _t("2026-09-29T07:59"))   # ingest is live
    clock = {"now": _t("2026-09-29T08:00")}
    runs: list = []

    def run_job():
        report = RetentionJob(data_root=root, archive_from_env=False,
                              now=lambda: clock["now"]).run(trigger="scheduler")
        runs.append(report)
        return report

    s = sched.RetentionScheduler(hour_utc=9, registry_db=root / "registry.db",
                                 run_job=run_job, now=lambda: clock["now"])
    assert s.plan_first() == _t("2026-09-29T09:00")
    assert s.tick() is False and runs == []
    clock["now"] = _t("2026-09-29T09:00")
    assert s.tick() is True
    assert len(runs) == 1 and runs[0].status == "ok"
    assert s.next_run_at == _t("2026-09-30T09:00")
    assert s.tick() is False                                  # not twice
    rec = last_run(root / "registry.db")
    assert rec["trigger"] == "scheduler" and rec["deleted_total"] == 1
    assert s.status()["next_run_at"] == "2026-09-30T09:00:00Z"
    assert s.last_result["status"] == "ok"
    import sqlite3
    conn = sqlite3.connect(root / "clients" / "acme-corp" / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE id = ?", (old,)).fetchone()[0] == 0
    finally:
        conn.close()
    # After a restart the next plan comes from the run on record.
    again = sched.RetentionScheduler(hour_utc=9, registry_db=root / "registry.db",
                                     run_job=run_job, now=lambda: _t("2026-09-29T10:00"))
    assert again.plan_first() == _t("2026-09-30T09:00")


def test_a_failing_run_is_logged_and_rescheduled():
    clock = {"now": _t("2026-09-29T09:00")}

    def boom():
        raise RuntimeError("disk on fire")

    s = sched.RetentionScheduler(hour_utc=9, run_job=boom, now=lambda: clock["now"])
    s.next_run_at = clock["now"]
    assert s.tick() is True
    assert s.last_result == {"status": "failed"}
    assert s.next_run_at == _t("2026-09-30T09:00")


def test_the_app_wires_it_only_when_enabled(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from apps.octo.api import create_app

    make_root(tmp_path, monkeypatch, tenants=())
    monkeypatch.delenv("OCTO_RETENTION_SCHEDULE", raising=False)
    assert getattr(create_app().state, "retention_scheduler", None) is None
    monkeypatch.setenv("OCTO_RETENTION_SCHEDULE", "1")
    monkeypatch.setenv("OCTO_RETENTION_HOUR_UTC", "4")
    app = create_app()
    s = app.state.retention_scheduler
    assert s.hour_utc == 4
    with TestClient(app):
        assert s.next_run_at is not None and s.next_run_at.hour == 4
    assert s._thread is None                                   # stopped on shutdown


# ---------------------------------------------------------------------------
# Deploy safety (v0.11 follow-up T1)
# ---------------------------------------------------------------------------

def test_the_compose_template_ships_the_schedule_off():
    """The schedule is switched on LAST (docs/operations/bundle.md, "Upgrade
    order"); a rendered template never starts pruning on its own."""
    from pathlib import Path

    path = (Path(__file__).resolve().parents[3] / "ops" / "octo-bundle"
            / "docker-compose.yml.template")
    if not path.is_file():
        pytest.skip("deploy files (ops/) are not part of a public copy")
    template = path.read_text()
    lines = [ln.strip() for ln in template.splitlines()
             if ln.strip().startswith("OCTO_RETENTION_SCHEDULE:")]
    assert lines == ['OCTO_RETENTION_SCHEDULE: "0"']
    env = {"OCTO_RETENTION_SCHEDULE": lines[0].split(":", 1)[1].strip().strip('"')}
    assert sched.schedule_enabled(env) is False


def test_the_first_scheduled_run_refuses_to_prune_before_the_backfill(tmp_path, monkeypatch):
    """A bundle switched on before the one-off move: its first scheduled run
    moves and prunes nothing of the tenant's telemetry or signals (rows
    without an arrival time = backfill never ran), and says so."""
    import sqlite3

    from apps.octo.tests._tiering_fixtures import NOW, ago, db, pihole_payload, rows, write_telemetry

    root = make_root(tmp_path, monkeypatch, tenants=("acme-corp",))
    old_dns = insert_event(root, "acme-corp", event_type="pihole.query",
                           payload=pihole_payload(2, "old.example.test"),
                           received_at=ago(days=30), stamped=False)
    old_alert = insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                             received_at=ago(days=400), severity="high", stamped=False)
    raw = write_telemetry(root, "acme-corp", received_at=ago(days=30))
    # Ingest is live (the scheduled run's clock check): a lookup just now.
    live = write_telemetry(root, "acme-corp", received_at=ago(minutes=1),
                           domain="live.example.test", n=7)
    conn = sqlite3.connect(db(root, "acme-corp", "events"))
    conn.execute("DROP INDEX idx_events_ingested_at")   # provisioned before 036
    conn.commit()
    conn.close()

    s = sched.RetentionScheduler(
        hour_utc=9, registry_db=root / "registry.db", now=lambda: NOW,
        run_job=lambda: RetentionJob(data_root=root, now=lambda: NOW,
                                     archive_from_env=False).run(trigger="scheduler"),
    )
    s.next_run_at = NOW          # due now
    assert s.tick() is True
    assert s.last_result["status"] == "partial"
    assert s.last_result["deleted_total"] == 0
    assert {r[0] for r in rows(db(root, "acme-corp", "events"), "SELECT id FROM events")} == {
        old_dns, old_alert}
    assert [r[0] for r in rows(db(root, "acme-corp", "telemetry"),
                               "SELECT id FROM telemetry_raw ORDER BY id")] == [raw, live]
    run = last_run(root / "registry.db")
    assert "arrival backfill pending for acme-corp" in (run["error"] or "")


# ---------------------------------------------------------------------------
# Clock check: a scheduled run never trusts a clock that jumped forward
# ---------------------------------------------------------------------------

def _count(path, sql: str) -> int:
    import sqlite3

    conn = sqlite3.connect(path)
    try:
        return int(conn.execute(sql).fetchone()[0])
    finally:
        conn.close()


def test_a_scheduled_run_refuses_a_clock_that_jumped_forward(tmp_path, monkeypatch):
    """Last run 2026-09-29; the host clock steps to 2027-10-01 (bad NTP, a VM
    restored with the wrong time) and the scheduler ticks: nothing is
    deleted, nothing recorded, the refusal is logged and shown; a deliberate
    script run at that clock is not checked."""
    from apps.octo.tests._tiering_fixtures import ago, db, file_digests

    root = make_root(tmp_path, monkeypatch, tenants=("acme-corp",))
    kept = insert_event(root, "acme-corp", event_type="wazuh.alert", payload={"n": 1},
                        received_at=ago(days=100), severity="high")
    live_signal(root, "acme-corp", _t("2026-09-29T08:59"))
    first = RetentionJob(data_root=root, archive_from_env=False,
                         now=lambda: _t("2026-09-29T09:00")).run(trigger="scheduler")
    assert first.status == "ok"
    registry = root / "registry.db"
    runs_before = _count(registry, "SELECT COUNT(*) FROM retention_runs")
    audit_before = _count(root / "global" / "audit.db", "SELECT COUNT(*) FROM audit_log")
    files_before = file_digests(root / "clients")

    jumped = _t("2027-10-01T09:00")
    s = sched.RetentionScheduler(
        hour_utc=9, registry_db=registry, now=lambda: jumped,
        run_job=lambda: RetentionJob(data_root=root, archive_from_env=False,
                                     now=lambda: jumped).run(trigger="scheduler"),
    )
    s.next_run_at = jumped
    assert s.tick() is True
    assert s.last_result["status"] == "failed"
    assert "clock check" in s.last_result["note"]
    assert "367.0 days after the last retention run" in s.status()["last_failure"]
    assert _count(registry, "SELECT COUNT(*) FROM retention_runs") == runs_before
    assert _count(root / "global" / "audit.db", "SELECT COUNT(*) FROM audit_log") == audit_before
    assert file_digests(root / "clients") == files_before
    assert _count(db(root, "acme-corp", "events"),
                  f"SELECT COUNT(*) FROM events WHERE id = {kept}") == 1
    # Still refused the next night (the refused run is not the reference).
    s.next_run_at = jumped
    assert s.tick() is True and s.last_result["status"] == "failed"
    # A deliberate catch-up (a script run) is not checked.
    script = RetentionJob(data_root=root, archive_from_env=False,
                          now=lambda: jumped).run(trigger="script")
    assert script.status == "ok"
    assert _count(db(root, "acme-corp", "events"),
                  f"SELECT COUNT(*) FROM events WHERE id = {kept}") == 0


def test_the_first_scheduled_run_checks_the_clock_against_the_newest_arrival(
        tmp_path, monkeypatch):
    """No run on record: the newest arrival is the reference. Nothing arrived
    for two days (or the clock jumped) → refused; live ingest → it runs."""
    root = make_root(tmp_path, monkeypatch, tenants=("acme-corp",))
    live_signal(root, "acme-corp", _t("2026-09-27T09:00"))
    now = _t("2026-09-29T09:00")
    report = RetentionJob(data_root=root, archive_from_env=False,
                          now=lambda: now).run(trigger="scheduler")
    assert report.status == "failed"
    assert "no retention run on record" in report.note and "2.0 days" in report.note
    assert last_run(root / "registry.db") is None
    # A dry run is never refused (it writes nothing).
    assert RetentionJob(data_root=root, archive_from_env=False,
                        now=lambda: now).run(trigger="scheduler", dry_run=True).status == "ok"
    live_signal(root, "acme-corp", _t("2026-09-29T08:30"))
    assert RetentionJob(data_root=root, archive_from_env=False,
                        now=lambda: now).run(trigger="scheduler").status == "ok"


def test_the_backfill_run_is_not_the_last_retention_run(tmp_path, monkeypatch):
    """The move script's run (trigger 'backfill') is recorded but is not "the
    last retention run": switching the schedule on two days later waits for
    the scheduled hour (no catch-up 5 minutes after `up -d`), the System
    page still says retention never ran, and the first scheduled run is
    not refused by the clock check."""
    from apps.octo.tests._tiering_fixtures import NOW

    root = make_root(tmp_path, monkeypatch, tenants=("acme-corp",))
    registry = root / "registry.db"
    RetentionJob(data_root=root, archive_from_env=False, now=lambda: NOW,
                 sweep_days=None).run(
        trigger="backfill", classes=("telemetry_raw", "telemetry_rollup", "first_seen_domains"))
    assert last_run(registry) is None
    assert last_run(registry, include_backfill=True)["trigger"] == "backfill"
    later = NOW + timedelta(days=2)                     # 2026-10-01 12:00
    live_signal(root, "acme-corp", later - timedelta(minutes=5))
    clock = {"now": later}
    s = sched.RetentionScheduler(
        hour_utc=9, registry_db=registry, now=lambda: clock["now"],
        run_job=lambda: RetentionJob(data_root=root, archive_from_env=False,
                                     now=lambda: clock["now"]).run(trigger="scheduler"),
    )
    assert s.plan_first() == _t("2026-10-02T09:00")   # not later + 5 min
    clock["now"] = _t("2026-10-02T09:00")
    live_signal(root, "acme-corp", clock["now"] - timedelta(minutes=1))
    assert s.tick() is True and s.last_result["status"] == "ok"
    assert last_run(registry)["trigger"] == "scheduler"
