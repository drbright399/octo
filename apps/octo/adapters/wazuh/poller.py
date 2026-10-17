"""WazuhPoller — adapter background task.

Polls the Wazuh indexer for new alerts, runs each through
`WazuhSourceAdapter.extract_event()`, hands the resulting CanonicalEvent
to the IngestSink (which writes per-client SQLite + publishes to SSE).

Lifecycle is owned by `WazuhSourceAdapter.start()` / `.stop()`. Runs on
an asyncio task; the actual HTTP calls happen on a thread executor so
`requests` doesn't block the event loop.

Position tracking: the poller persists the `last_seen_at` cursor in
the framework's AdapterRegistry instance config so a restart resumes
from where it left off (no event re-processing, no event loss).

Every poll outcome is REPORTED (`vendor_contact.ContactReporter`), as the
Datto poller does: a failed poll moves the instance row to 'error', the next
good one back to 'running', and the source-health view reads the last good
contact instead of "awaiting first poll" forever.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from apps.octo.adapters.wazuh.client import (
    WazuhAuthError,
    WazuhClient,
    WazuhClientError,
    WazuhConfig,
)
from apps.octo.ingest import IngestSink
from apps.octo.instances.vendor_contact import (
    ContactReporter,
    FailureKind,
    poll_failure_detail,
)

logger = logging.getLogger(__name__)

# Conservative default: poll every 10s. Adapter instance config can
# override per-MSP based on event volume + freshness tolerance.
DEFAULT_POLL_INTERVAL_SEC = 10.0
DEFAULT_MAX_BATCH = 500


class WazuhPoller:
    """Run loop that drains the indexer + feeds the ingest sink.

    Stateless except for the cursor; the sink owns persistence + fanout.
    """

    def __init__(
        self,
        *,
        adapter,                          # WazuhSourceAdapter (avoid circular import)
        client: WazuhClient,
        sink: IngestSink,
        default_tenant_slug: str,         # fallback for un-mapped alerts
        initial_cursor: str = "1970-01-01T00:00:00.000Z",
        poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
        max_batch: int = DEFAULT_MAX_BATCH,
        instance_id: Optional[int] = None,
        reporter: Optional[ContactReporter] = None,
    ) -> None:
        self._adapter = adapter
        self._client = client
        self._sink = sink
        self._default_tenant_slug = default_tenant_slug
        self._cursor: str = initial_cursor
        self._poll_interval = poll_interval_sec
        self._max_batch = max_batch
        # Instance-row status follows the poll outcome (no instance id → the
        # reporter is inert, e.g. a poller built directly in a test).
        self._reporter = reporter or ContactReporter(instance_id, what="wazuh-poller")
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    @property
    def cursor(self) -> str:
        """Latest seen timestamp — caller can persist this externally to
        survive process restarts."""
        return self._cursor

    async def start(self) -> None:
        """Launch the poll loop as an asyncio task."""
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="wazuh-poller")

    async def stop(self) -> None:
        """Signal stop + await graceful exit. Idempotent."""
        if self._task is None:
            return
        self._stopping.set()
        try:
            await asyncio.wait_for(self._task, timeout=15.0)
        except asyncio.TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    async def _run(self) -> None:
        """Main loop: drain, sleep, drain, sleep, until stopped."""
        logger.info(
            "[wazuh-poller] starting (interval=%.1fs, max_batch=%d)",
            self._poll_interval, self._max_batch,
        )
        try:
            while not self._stopping.is_set():
                try:
                    await self._drain_once()
                except WazuhAuthError as exc:
                    # Auth failures are operator-actionable; back off harder
                    # so we don't hammer the manager with bad creds.
                    logger.warning("[wazuh-poller] auth failed: %s", exc)
                    await self._report_failure("auth")
                    await self._sleep_or_stop(60.0)
                    continue
                except WazuhClientError as exc:
                    logger.warning("[wazuh-poller] transport error: %s", exc)
                    await self._report_failure("transport")
                    await self._sleep_or_stop(min(30.0, self._poll_interval * 3))
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "[wazuh-poller] unexpected error: %s", exc,
                    )
                    await self._report_failure("internal", exc)
                    await self._sleep_or_stop(self._poll_interval)
                    continue
                # Off the loop: a transition is a registry write.
                await asyncio.to_thread(self._reporter.ok)
                await self._sleep_or_stop(self._poll_interval)
        finally:
            logger.info("[wazuh-poller] stopped (cursor=%s)", self._cursor)

    async def _report_failure(
        self, kind: FailureKind, exc: Optional[BaseException] = None,
    ) -> None:
        await asyncio.to_thread(
            self._reporter.failed, kind, poll_failure_detail("Wazuh", kind, exc),
        )

    async def _drain_once(self) -> None:
        """Pull one batch and ingest each. Updates cursor when batch
        is non-empty."""
        alerts = await asyncio.to_thread(
            self._client.fetch_alerts_since,
            self._cursor,
            max_results=self._max_batch,
        )
        if not alerts:
            return
        for raw in alerts:
            self._ingest_one(raw)
        last = alerts[-1].get("timestamp")
        if isinstance(last, str) and last > self._cursor:
            self._cursor = last

    def _ingest_one(self, raw_envelope: dict[str, Any]) -> None:
        """Extract → route → ingest. Per-event failures are logged but
        don't stop the batch."""
        try:
            event = self._adapter.extract_event(raw_envelope)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[wazuh-poller] extract failed for envelope id=%s: %s",
                raw_envelope.get("id"), exc,
            )
            return
        tenant_slug = (
            self._adapter.route_to_tenant(raw_envelope)
            or self._default_tenant_slug
        )
        try:
            self._sink.ingest(tenant_slug, "wazuh", event)
        except FileNotFoundError as exc:
            # The tenant isn't provisioned in OCTO yet. Surface clearly
            # but don't crash the loop — the operator may be mid-onboarding.
            logger.warning(
                "[wazuh-poller] tenant %r missing — alert dropped (%s)",
                tenant_slug, exc,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[wazuh-poller] ingest failed for tenant=%s id=%s: %s",
                tenant_slug, raw_envelope.get("id"), exc,
            )

    async def _sleep_or_stop(self, seconds: float) -> None:
        """asyncio-friendly sleep that wakes early on stop signal."""
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            return
