"""In-app nightly trigger for the retention job.

Decision (2026-09-29): the job runs from a daemon thread inside octo-core,
not from the host cron that runs nightly-backup.sh. Retention was "policy
only" for months precisely because enforcing it depended on something
outside the product; a bundle that is up enforces its own retention, with no
host step to forget on a re-home or a new install. The host cron remains
free to run `scripts/enforce_retention.py` (dry runs, a manual run) — the
two can never overlap: both take the same run lock, and the loser reports
`skipped` without touching anything.

  OCTO_RETENTION_SCHEDULE   "1" / "true" enables the thread. Default OFF in
                            code (tests, dev and a bare import never prune)
                            AND in the bundle's compose template: the
                            operator switches it on as the last step of the
                            upgrade order (archive mount → deploy → move dry
                            run → move → enforce dry run → schedule).
  OCTO_RETENTION_HOUR_UTC   hour of day (0-23, UTC) to run. Default 9 =
                            after a typical nightly backup on the bundle
                            host, before US business hours — so the
                            backup taken before a prune still holds the
                            pruned rows for its retention window.

Catch-up: when the newest enforcing run on record is older than
`CATCH_UP_AFTER_HOURS` (a host that was down at the scheduled hour), the next
run is `STARTUP_DELAY_SEC` after start instead of tomorrow. A bundle that has
NEVER run retention waits for the scheduled hour — a fresh deploy never
prunes minutes after it starts; dry-run first (`enforce_retention.py
--dry-run`). The one-off backfill's run (trigger `backfill`) does not count:
switching the schedule on days after the move waits for the scheduled hour.

Clock check: a scheduled run whose clock is more than 3 days after the last
retention run on record — or, with none, more than a day after the newest
arrival of any row — refuses and does nothing (`RetentionJob._clock_refusal`;
a clock stepped forward would move every cutoff with it). It is logged as an
error and shown on Settings → System (`status()["last_failure"]`); a
deliberate catch-up is a script run.

The first run cannot prune telemetry the operator has not moved: the job
refuses, per tenant, to prune the signals and telemetry of a tenant whose
one-off backfill (`move_telemetry_out_of_events.py`) has not run
(`apps.octo.retention.job`, step 0 — "arrival backfill pending"). Running
the backfill from here instead was rejected: it moves and prunes months of
data, possibly without an archive, with nobody reading its preview.
"""
from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from apps.octo.ingest.timestamps import normalize_timestamp

logger = logging.getLogger(__name__)

DEFAULT_HOUR_UTC = 9
CATCH_UP_AFTER_HOURS = 26
STARTUP_DELAY_SEC = 300


def schedule_enabled(env: Optional[dict] = None) -> bool:
    e = os.environ if env is None else env
    return str(e.get("OCTO_RETENTION_SCHEDULE", "0")).strip().lower() in ("1", "true", "yes")


def schedule_hour(env: Optional[dict] = None) -> int:
    e = os.environ if env is None else env
    try:
        hour = int(str(e.get("OCTO_RETENTION_HOUR_UTC", DEFAULT_HOUR_UTC)).strip())
    except ValueError:
        return DEFAULT_HOUR_UTC
    return hour if 0 <= hour <= 23 else DEFAULT_HOUR_UTC


def next_scheduled(now: datetime, hour_utc: int) -> datetime:
    """The next `hour_utc`:00 UTC strictly after `now`."""
    now = now.astimezone(timezone.utc)
    candidate = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def first_run_at(
    now: datetime, hour_utc: int, last_started_at: Optional[str],
) -> datetime:
    """When the first run after a start should happen (see catch-up)."""
    scheduled = next_scheduled(now, hour_utc)
    if not last_started_at:
        return scheduled
    canonical = normalize_timestamp(last_started_at, naive_is_utc=True)
    if not canonical:
        return scheduled
    last = datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if now - last > timedelta(hours=CATCH_UP_AFTER_HOURS):
        return min(scheduled, now + timedelta(seconds=STARTUP_DELAY_SEC))
    return scheduled


class RetentionScheduler:
    """Daemon thread: sleep until the next run time, run the job, repeat.
    `now` and `wait` are injectable (tests drive `tick()` directly)."""

    def __init__(
        self,
        *,
        hour_utc: int = DEFAULT_HOUR_UTC,
        registry_db: Optional[Path] = None,
        run_job: Optional[Callable[[], object]] = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.hour_utc = hour_utc
        self._registry_db = registry_db
        self._run_job = run_job or _default_run
        self._now = now
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.next_run_at: Optional[datetime] = None
        self.last_result: Optional[dict] = None

    def _last_started(self) -> Optional[str]:
        from apps.octo.retention.job import last_run

        row = last_run(self._registry_db)
        return row["started_at"] if row else None

    def plan_first(self) -> datetime:
        self.next_run_at = first_run_at(self._now(), self.hour_utc, self._last_started())
        return self.next_run_at

    def tick(self) -> bool:
        """Run the job if it is due; schedule the next run. Returns whether it
        ran. Never raises (a failed run is logged and retried tomorrow)."""
        if self.next_run_at is None:
            self.plan_first()
        now = self._now()
        if now < self.next_run_at:
            return False
        try:
            report = self._run_job()
            summary = report.as_dict() if hasattr(report, "as_dict") else {}
            self.last_result = {
                "status": summary.get("status"), "run_id": summary.get("run_id"),
                "deleted_total": summary.get("deleted_total"),
                # A refused run (clock check, unreadable policy) is not in
                # retention_runs: this is where Settings → System reads why.
                "note": summary.get("note") or None,
            }
            logger.info(
                "[retention] scheduled run %s: %s, %s row(s) deleted",
                summary.get("run_id"), summary.get("status"), summary.get("deleted_total"),
            )
        except Exception:  # noqa: BLE001
            logger.exception("[retention] scheduled run failed")
            self.last_result = {"status": "failed"}
        self.next_run_at = next_scheduled(self._now(), self.hour_utc)
        return True

    # ----- thread -----

    def start(self) -> None:
        if self._thread is not None:
            return
        self.plan_first()
        self._thread = threading.Thread(
            target=self._loop, name="retention-scheduler", daemon=True,
        )
        self._thread.start()
        logger.info("[retention] scheduler on: next run %s", self.next_run_at)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            wait = (self.next_run_at - self._now()).total_seconds() if self.next_run_at else 60
            # Wake at least hourly: a clock jump never strands the schedule.
            if self._stop.wait(max(1.0, min(wait, 3600.0))):
                return
            self.tick()

    def status(self) -> dict:
        last = self.last_result or {}
        return {
            "enabled": True,
            "hour_utc": self.hour_utc,
            "next_run_at": self.next_run_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            if self.next_run_at else None,
            "last_result": self.last_result,
            # Why the last scheduled run of this process failed (None = it
            # did not) — e.g. the clock check refused it and did nothing.
            "last_failure": (last.get("note") or "failed (see the server log)")
            if last.get("status") == "failed" else None,
        }


def _default_run():
    from apps.octo.retention.job import RetentionJob

    return RetentionJob().run(trigger="scheduler")
