"""Autonomous Triage L1 worker (Task #119b).

A decoupled background worker that polls each tenant's events.db for events
past a per-tenant watermark, runs the deterministic heuristic L1 engine,
and records octo's disposition as an agent_note (query_kind='auto_enrich',
disposition=...). It does NOT mutate event severity, create tickets, or
suppress — autonomous *actions* are a separate, gated slice. This worker
only records octo's recommendation on every alert.

Design (confirmed with Rick 2026-06-01):
  * Polling + per-tenant watermark (not on-ingest-inline) — never blocks
    the ingest write path on triage work; survives restarts; drains
    backlog in bounded batches.
  * Heuristic L1 is always-on and deterministic — no LLM, no consent
    question (pure per-tenant data). The LLM-on-uncertain escalation
    (119c) plugs in via the `decide` callable; default here is
    heuristic-only.

The per-tenant step (`process_tenant_once`) is a plain synchronous
function so it's unit-testable without the event loop. The async loop is a
thin wrapper that fans it across active tenants off-thread.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from apps.octo import paths
from apps.octo.agent import notes as agent_notes
from apps.octo.agent import triage_state
from apps.octo.agent.features import build_features, ensure_recurrence_index
from apps.octo.agent.heuristic_l1 import TriageDecision, TriageFeatures, triage
from apps.octo.db import connect, ensure_wal

logger = logging.getLogger(__name__)

# A decision function: given the gathered features + the raw event row +
# the tenant slug, return a triage decision. The default is pure heuristic;
# 119c supplies one that consults the LLM when the heuristic is uncertain.
DecideFn = Callable[[TriageFeatures, sqlite3.Row, str], TriageDecision]

DEFAULT_BATCH_SIZE = 500
DEFAULT_INTERVAL_SECONDS = 15

# Triage floor — the worker only triages events AT/ABOVE this severity.
# Everything below (recurring info/low telemetry "noise") is left untriaged
# in events.db for later audit (that's Athena's job, not L1's) — it is NOT
# noted. Confirmed intended design with Rick 2026-06-02; also the thing that
# keeps high-volume telemetry tenants from drowning the feed + the worker.
DEFAULT_MIN_SEVERITY = "medium"
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Athena's own records in events.db (`threat.store.EVENT_SOURCE`): never triaged.
ATHENA_SOURCE = "athena"


def _min_severity_rank() -> int:
    return _SEVERITY_RANK.get(
        os.environ.get("OCTO_TRIAGE_MIN_SEVERITY", DEFAULT_MIN_SEVERITY).lower(), 2
    )
# Confidence calibration state. Every confidence the agent emits today —
# heuristic constants AND the LLM's — is UNCALIBRATED (no eval set has been
# run against ground truth). Surfaced so the UI flags confidence as
# advisory, not a number to gate decisions on. Flip to "calibrated" only
# when the eval harness ships (post-launch / NB6). Single source of truth.
CALIBRATION_STATE = "uncalibrated"
# Wait out transient locks from the live ingest writers (events.db may be in
# rollback-journal mode where a writer briefly blocks others) rather than
# erroring. Generous because ingest commits are short.
BUSY_TIMEOUT_MS = 15000


def _set_busy_timeout(conn: sqlite3.Connection) -> None:
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")


def heuristic_decide(
    features: TriageFeatures, event_row: sqlite3.Row, slug: str,
) -> TriageDecision:
    """Default decider — pure heuristic L1, no LLM (119b)."""
    return triage(features)


@dataclass
class ProcessResult:
    tenant: str
    processed: int
    last_event_id: int
    by_disposition: dict[str, int]


def process_tenant_once(
    slug: str,
    *,
    decide: DecideFn = heuristic_decide,
    batch_size: int = DEFAULT_BATCH_SIZE,
    backfill: bool = False,
) -> ProcessResult:
    """Triage one batch of untriaged events for a single tenant.

    Reads events with id > watermark (ascending), decides each, writes an
    autonomous agent_note, and advances the watermark. Returns a summary.
    Synchronous + self-contained → directly unit-testable.

    Skip-backlog (the default): the FIRST time a tenant is seen, the
    watermark is initialized to the current max event id and nothing is
    triaged that tick — so the agent only annotates events that arrive
    AFTER it's enabled, never retroactively chewing months of history
    (which at fleet scale is millions of events). Pass backfill=True (or
    set OCTO_TRIAGE_BACKFILL=1 on the worker) to start at 0 and process
    the existing backlog instead.
    """
    events_db = paths.client_dir(slug) / "events.db"
    if not events_db.exists():
        return ProcessResult(slug, 0, 0, {})

    indicators_db = paths.client_dir(slug) / "indicators.db"

    events_conn = connect(events_db, read_only=True)
    _set_busy_timeout(events_conn)
    indicators_conn = (
        connect(indicators_db, read_only=True) if indicators_db.exists() else None
    )
    if indicators_conn is not None:
        _set_busy_timeout(indicators_conn)
    # Separate writable handle for notes + watermark.
    state_conn = connect(events_db)
    _set_busy_timeout(state_conn)
    try:
        # Put events.db in WAL so the worker + live ingest coexist without
        # the writer-blocks-reader contention of rollback-journal mode.
        # Persistent in the file header, so this one call covers ingest too.
        ensure_wal(state_conn)
        # One-time per-tenant setup (each commits; cheap when already present).
        ensure_recurrence_index(state_conn)
        agent_notes.ensure_agent_schema(state_conn)
        triage_state.ensure_table(state_conn)

        existing = triage_state.get_watermark_or_none(state_conn)
        if existing is None and not backfill:
            # First-ever run for this tenant: skip the backlog — start the
            # watermark at the current max so only NEW events get triaged.
            max_row = events_conn.execute(
                "SELECT COALESCE(MAX(id), 0) AS m FROM events"
            ).fetchone()
            max_id = int(max_row["m"]) if max_row else 0
            triage_state.set_watermark(state_conn, max_id)
            return ProcessResult(slug, 0, max_id, {})
        watermark = existing if existing is not None else 0
        rows = events_conn.execute(
            "SELECT id, received_at, source, source_host, event_type, "
            "       severity, payload, summary "
            "FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (watermark, batch_size),
        ).fetchall()

        # PHASE 1 — reads only, NO write lock held. Compute every decision
        # first so we never hold a write transaction while reading (which,
        # in rollback-journal mode, contends with the live ingest writers).
        # Events below the severity floor are skipped entirely (no note) —
        # the watermark still advances past them so they're never re-read.
        floor = _min_severity_rank()
        decisions: list[tuple[int, TriageDecision]] = []
        by_disposition: dict[str, int] = {}
        skipped = 0
        # RESTRICTED (rule B7, CSAM — v0.17.1): an event that mentions a
        # domain the tenant holds as restricted evidence is never enriched —
        # no note, no model. The list unreadable: nothing is triaged this
        # tick (fail closed; the watermark stays, the batch is read again).
        from apps.octo.threat import restricted

        try:
            # The exact domains (not their roots: a root can be a whole
            # hosting provider), matched at DNS-label boundaries.
            blocked = restricted.restricted_domains(slug)
        except (sqlite3.Error, OSError):
            logger.warning("triage %s: the restricted-evidence list could not be read — "
                           "nothing triaged this tick", slug)
            return ProcessResult(slug, 0, watermark, {})
        for row in rows:
            if _SEVERITY_RANK.get(row["severity"], 0) < floor:
                skipped += 1
                continue
            if row["source"] == ATHENA_SOURCE:
                # Athena's OWN incident records (`athena.incident`, Tier
                # Black): a person or a rule already decided them — never
                # triaged again (and never handed to a model).
                skipped += 1
                continue
            if restricted.text_mentions(
                    f"{row['summary'] or ''} {row['payload'] or ''} {row['source_host'] or ''}",
                    blocked):
                skipped += 1
                continue
            features = build_features(
                row, events_conn=events_conn, indicators_conn=indicators_conn,
            )
            try:
                decision = decide(features, row, slug)
            except Exception:  # noqa: BLE001 — one bad event mustn't stall the batch
                logger.exception(
                    "triage decide failed for tenant=%s event_id=%s; "
                    "recording uncertain", slug, row["id"],
                )
                decision = TriageDecision(
                    disposition="uncertain",
                    suggested_severity=features.severity,
                    confidence=0.0,
                    rationale="Triage error; deferred to analyst.",
                )
            decisions.append((int(row["id"]), decision))
            by_disposition[decision.disposition] = (
                by_disposition.get(decision.disposition, 0) + 1
            )

        # PHASE 2 — write the whole batch + advance the watermark in ONE
        # short transaction. Atomic (notes + watermark commit together, so a
        # crash can't leave events triaged-but-not-watermarked → no duplicate
        # notes on restart) and fast (one fsync). The write lock is held only
        # for the inserts, not during the reads above.
        # Advance the watermark past the ENTIRE batch read (including
        # below-floor events that were skipped) so nothing is re-scanned.
        batch_last_id = int(rows[-1]["id"]) if rows else watermark
        if rows:
            state_conn.execute("BEGIN IMMEDIATE")
            try:
                for ev_id, decision in decisions:
                    agent_notes.insert_agent_note_row(
                        state_conn,
                        ref_kind="event",
                        ref_id=ev_id,
                        agent_id="octo",
                        note_text=decision.note_text(),
                        confidence=decision.confidence,
                        request_id=f"triage-{uuid.uuid4().hex}",
                        query_kind="auto_enrich",
                        disposition=decision.disposition,
                    )
                triage_state.bump_watermark(state_conn, batch_last_id)
                state_conn.execute("COMMIT")
            except Exception:
                state_conn.execute("ROLLBACK")
                raise

        return ProcessResult(slug, len(rows), batch_last_id, by_disposition)
    finally:
        events_conn.close()
        if indicators_conn is not None:
            indicators_conn.close()
        state_conn.close()


def _active_tenant_slugs() -> list[str]:
    """All active tenants from the registry. Empty list if registry absent."""
    reg_path = paths.registry_db_path()
    if not reg_path.exists():
        return []
    reg = connect(reg_path, read_only=True)
    try:
        rows = reg.execute(
            "SELECT slug FROM clients WHERE status = 'active' ORDER BY slug"
        ).fetchall()
        return [r["slug"] for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        reg.close()


class AutonomousTriageWorker:
    """Background loop that runs `process_tenant_once` across all active
    tenants every `interval` seconds. Mirrors the HostMetricsSampler
    start/stop shape so it wires into the app startup the same way.
    """

    def __init__(
        self,
        *,
        decide: DecideFn = heuristic_decide,
        interval_seconds: Optional[int] = None,
        batch_size: Optional[int] = None,
    ) -> None:
        self._decide = decide
        self._interval = interval_seconds or int(
            os.environ.get("OCTO_TRIAGE_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS)
        )
        self._batch_size = batch_size if batch_size is not None else int(
            os.environ.get("OCTO_TRIAGE_BATCH_SIZE", DEFAULT_BATCH_SIZE)
        )
        self._backfill = os.environ.get(
            "OCTO_TRIAGE_BACKFILL", "0").lower() in ("1", "true")
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        # --- status (read by GET /api/v1/agent/status) ---
        # State transitions happen on the event loop (in _run/_tick), and
        # status() is read on the same loop, so plain attributes are safe —
        # no lock needed.
        self._state: str = "idle"            # idle | triaging | error
        self._last_tick_at: Optional[str] = None
        self._last_run: Optional[dict] = None  # {processed, by_disposition}
        self._last_error: Optional[str] = None
        self._consecutive_errors: int = 0

    def status(self) -> dict:
        """Snapshot for the status endpoint. `online` = the loop is alive;
        `state` is the finer idle/triaging/error detail."""
        running = self._task is not None and not self._task.done()
        return {
            "state": self._state if running else "error",
            "online": running,
            "last_tick_at": self._last_tick_at,
            "last_run": self._last_run,
            "last_error": self._last_error,
            "consecutive_errors": self._consecutive_errors,
            "interval_seconds": self._interval,
            "calibration_state": CALIBRATION_STATE,
        }

    @staticmethod
    def is_enabled() -> bool:
        """Worker runs only when OCTO_TRIAGE_WORKER is explicitly truthy.

        Default-off in code so it never spawns during tests or a bare
        import; the product turns it ON explicitly — start-dev-backend.sh
        sets it for dev, and the bundle's compose sets it for prod. This
        mirrors the OCTO_LLM_DEV convention (a dev switch is set where the
        process starts, never inferred)."""
        return os.environ.get("OCTO_TRIAGE_WORKER", "0").lower() in ("1", "true")

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        logger.info(
            "autonomous triage worker started (interval=%ss, batch=%s)",
            self._interval, self._batch_size,
        )
        while not self._stop.is_set():
            try:
                await self._tick()
                self._consecutive_errors = 0
                self._last_error = None
                self._state = "idle"
            except Exception as exc:  # noqa: BLE001 — never let the loop die
                logger.exception("triage worker tick failed")
                self._state = "error"
                self._consecutive_errors += 1
                self._last_error = str(exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass

    async def _tick(self) -> None:
        self._state = "triaging"
        slugs = await asyncio.to_thread(_active_tenant_slugs)
        processed = 0
        by_disposition: dict[str, int] = {}
        for slug in slugs:
            if self._stop.is_set():
                break
            result = await asyncio.to_thread(
                process_tenant_once, slug,
                decide=self._decide, batch_size=self._batch_size,
                backfill=self._backfill,
            )
            processed += result.processed
            for disp, n in result.by_disposition.items():
                by_disposition[disp] = by_disposition.get(disp, 0) + n
            if result.processed:
                logger.info(
                    "triaged tenant=%s n=%s dispositions=%s",
                    result.tenant, result.processed, result.by_disposition,
                )
        self._last_tick_at = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        self._last_run = {"processed": processed, "by_disposition": by_disposition}
