"""DattoPoller — Datto RMM adapter background task.

Polls the Datto Alerts API for new open alerts, runs each through
`DattoSourceAdapter.extract_event()`, hands the resulting CanonicalEvent
to the IngestSink (which writes per-client SQLite + publishes to SSE).

Same shape as WazuhPoller — cursor-based pull, per-event failure
isolation, asyncio task with sync-from-async drain. Datto's API
returns alert timestamps as epoch seconds (we convert to ISO before
storing the cursor).

Every poll outcome is REPORTED (`vendor_contact.ContactReporter`): a failed
poll moves the instance row to 'error' with an operator-actionable detail, the
next good poll moves it back to 'running'. A poller that only logs its
failures leaves the Integrations card claiming a health nobody observed.

N0 — THE BACKSTOP (Tier Black slice 1). The poller reads the OPEN list only;
an alert an auto-resolving monitor opened and resolved between two polls is
never on it. Every `backstop_every_sec` (5 min) it also reads the alerts
RESOLVED since its own cursor (`/api/v2/account/alerts/resolved`, read-only)
and ingests those the open list never showed (by alertUid — a resolved
version of an alert already stored is not stored twice). The cursor and the
uids seen are kept in `adapter_poller_state` (a restart neither misses the
gap nor re-stores). A first start begins at "now": never a backlog. A
backstop failure is recorded, never fatal to the open poll.
THE CAP: an open list at its cap (`max_batch`) on every poll means alerts
beyond it are not being read; `intake_health()` says since when — detection
blindness (FR2) reads it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo.adapters.datto.client import (
    DattoAuthError,
    DattoClient,
    DattoClientError,
    DattoForbiddenError,
    forbidden_guidance,
)
from apps.octo.ingest import IngestSink
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import tenant_autocreate
from apps.octo.instances.vendor_contact import (
    ContactReporter,
    FailureBackoff,
    FailureKind,
)

logger = logging.getLogger(__name__)

# clock skew allowance before a vendor timestamp counts as "from the future"
_CURSOR_FUTURE_SLACK_SEC = 300

DEFAULT_POLL_INTERVAL_SEC = 30.0
DEFAULT_MAX_BATCH = 500
DEFAULT_BACKSTOP_EVERY_SEC = 300.0
BACKSTOP_STATE_KEY = "datto.resolved_backstop"
SEEN_UIDS_MAX = 5000

# Forbidden / rejected credentials stay that way until a human acts in Datto
# RMM, so retrying every minute forever only hammers the vendor (and can lock
# the API user out). Back off 60s → 120s → 240s → 300s, reset on the first
# success, and never stop: a fixed permission is picked up within 5 minutes.
CREDENTIAL_BACKOFF_BASE_SEC = 60.0
CREDENTIAL_BACKOFF_CEILING_SEC = 300.0

_RETRY_NOTE = (
    " Athena keeps retrying on its own (at most every "
    f"{int(CREDENTIAL_BACKOFF_CEILING_SEC // 60)} minutes); this clears as "
    "soon as a poll succeeds."
)

# Replacing a saved integration (Disable + Add again) drops its tenant mappings
# and its webhook token, so that advice is only given once the rejection has
# PERSISTED — one 401 can be a vendor-side blip.
AUTH_FAILURES_BEFORE_REPLACE_ADVICE = 3


class DattoPoller:
    """Run loop that drains Datto alerts + feeds the ingest sink."""

    def __init__(
        self,
        *,
        adapter,                          # DattoSourceAdapter
        client: DattoClient,
        sink: IngestSink,
        default_tenant_slug: str,
        initial_cursor: str = "1970-01-01T00:00:00.000Z",
        poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
        max_batch: int = DEFAULT_MAX_BATCH,
        instance_id: Optional[int] = None,
        reporter: Optional[ContactReporter] = None,
        credential_backoff: Optional[FailureBackoff] = None,
        backstop_every_sec: float = DEFAULT_BACKSTOP_EVERY_SEC,
        clock=time.monotonic,
    ) -> None:
        self._adapter = adapter
        self._client = client
        self._sink = sink
        self._default_tenant_slug = default_tenant_slug
        self._cursor: str = initial_cursor
        self._poll_interval = poll_interval_sec
        self._max_batch = max_batch
        # Attributes dropped-unmapped counts to this instance's health card.
        self._instance_id = instance_id
        # Instance-row status follows the poll outcome (no instance id → the
        # reporter is inert, e.g. a poller built directly in a test).
        self._reporter = reporter or ContactReporter(instance_id, what="datto-poller")
        self._credential_backoff = credential_backoff or FailureBackoff(
            base_sec=CREDENTIAL_BACKOFF_BASE_SEC,
            ceiling_sec=CREDENTIAL_BACKOFF_CEILING_SEC,
        )
        self._auth_failures = 0
        # N0 backstop + the open-list cap (see the module docstring).
        self._clock = clock
        self._backstop_every = float(backstop_every_sec)
        self._last_backstop = clock()
        self._resolved_cursor: Optional[str] = None
        self._seen_uids: "OrderedDict[str, None]" = OrderedDict()
        self._backstop_loaded = False
        self._backstop_ok_at: Optional[str] = None
        self._backstop_error: Optional[str] = None
        self._capped_since: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()

    @property
    def cursor(self) -> str:
        return self._cursor

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="datto-poller")

    def poll_now(self) -> None:
        """Cut the current wait short — from ANY thread. Used when something
        else just proved the vendor side works again (a successful site
        discovery), so the card need not sit out a 5-minute backoff."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._wake.set)

    async def stop(self) -> None:
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
        logger.info(
            "[datto-poller] starting (interval=%.1fs, max_batch=%d)",
            self._poll_interval, self._max_batch,
        )
        try:
            while not self._stopping.is_set():
                # Cleared BEFORE the poll: a wake that arrives while it is in
                # flight still shortens the wait that follows.
                self._wake.clear()
                try:
                    await self._drain_once()
                except DattoForbiddenError as exc:
                    # Before DattoClientError (its base): authenticated but
                    # not authorized is NOT a transport blip.
                    delay = self._credential_backoff.next()
                    logger.warning(
                        "[datto-poller] forbidden: %s (retry in %.0fs)", exc, delay,
                    )
                    await self._report_failure(
                        "forbidden",
                        forbidden_guidance(
                            exc.vendor_error, saved=True, retry_note=_RETRY_NOTE,
                        ),
                    )
                    await self._sleep_or_stop(delay)
                    continue
                except DattoAuthError as exc:
                    delay = self._credential_backoff.next()
                    logger.warning(
                        "[datto-poller] auth failed: %s (retry in %.0fs)", exc, delay,
                    )
                    self._auth_failures += 1
                    if self._auth_failures < AUTH_FAILURES_BEFORE_REPLACE_ADVICE:
                        advice = (
                            " Nothing to do yet: a single rejection can be a "
                            "vendor-side blip. If it persists, this message "
                            "will say what to change."
                        )
                    else:
                        advice = (
                            " The stored API key pair no longer works — it "
                            "may have been regenerated or the API user "
                            "disabled in Datto RMM (Setup > Users). Stored "
                            "keys cannot be edited: Disable this integration, "
                            "then Add integration again with a current key "
                            "pair (map your sites again afterwards)."
                        )
                    await self._report_failure(
                        "auth", f"{exc}.{advice}{_RETRY_NOTE}",
                    )
                    await self._sleep_or_stop(delay)
                    continue
                except DattoClientError as exc:
                    logger.warning("[datto-poller] transport error: %s", exc)
                    await self._report_failure(
                        "transport",
                        f"Could not read alerts from Datto: {exc}. Retrying "
                        "automatically; this clears as soon as a poll succeeds.",
                    )
                    await self._sleep_or_stop(min(60.0, self._poll_interval * 3))
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "[datto-poller] unexpected error: %s", exc,
                    )
                    # Class name only — an arbitrary exception's text is not
                    # vetted for what it may embed.
                    await self._report_failure(
                        "internal",
                        "The Datto poll failed inside Athena "
                        f"({type(exc).__name__}); see the server log. Retrying "
                        "automatically.",
                    )
                    await self._sleep_or_stop(self._poll_interval)
                    continue
                self._credential_backoff.reset()
                self._auth_failures = 0
                await asyncio.to_thread(self._reporter.ok)
                await self._sleep_or_stop(self._poll_interval)
        finally:
            logger.info("[datto-poller] stopped (cursor=%s)", self._cursor)

    async def _report_failure(self, kind: FailureKind, detail: str) -> None:
        # Off the loop: a transition is a registry write. No-op otherwise.
        await asyncio.to_thread(self._reporter.failed, kind, detail)

    async def _drain_once(self) -> None:
        alerts = await asyncio.to_thread(
            self._client.fetch_alerts_since,
            self._cursor,
            max_results=self._max_batch,
        )
        self._note_cap(len(alerts))
        for raw in alerts:
            self._remember(raw.get("alertUid"))
        if self._clock() - self._last_backstop >= self._backstop_every:
            self._last_backstop = self._clock()
            await asyncio.to_thread(self.backstop_once)
        if not alerts:
            return
        stored = sum(1 for raw in alerts if self._ingest_one(raw))
        if stored != len(alerts):
            # Replays (a restart re-reads the lookback window; an open alert is
            # re-listed) are collapsed by the sink's idempotency guard.
            logger.debug(
                "[datto-poller] batch of %d: %d stored, rest duplicate/skipped",
                len(alerts), stored,
            )
        # Datto alert timestamps may be epoch seconds OR ISO strings,
        # depending on endpoint version. Trust whichever the envelope
        # carries — the adapter normalizes to ISO at extract time, but
        # for cursor advance we need a comparable scalar.
        last = self._latest_timestamp(alerts)
        # Never adopt a cursor from the future: one alert with a bad clock
        # (year 2099) would make every later poll ask for "after 2099" and
        # silently stop the feed. Canonical UTC strings compare lexically.
        ceiling = format_utc_ms(
            datetime.now(timezone.utc) + timedelta(seconds=_CURSOR_FUTURE_SLACK_SEC)
        )
        if last and self._cursor < last <= ceiling:
            self._cursor = last
        elif last and last > ceiling:
            logger.warning(
                "[datto] ignoring future-dated alert timestamp %s as poll cursor", last,
            )

    # ----- N0: the open-list cap and the resolved-alerts backstop -----

    def _note_cap(self, n: int) -> None:
        if n >= self._max_batch:
            if self._capped_since is None:
                self._capped_since = format_utc_ms(datetime.now(timezone.utc))
                logger.warning(
                    "[datto-poller] the open-alert list is at its cap (%d): alerts beyond it "
                    "are not read this poll", self._max_batch,
                )
        else:
            self._capped_since = None

    def _remember(self, uid: Any) -> None:
        if not isinstance(uid, str) or not uid:
            return
        self._seen_uids[uid] = None
        self._seen_uids.move_to_end(uid)
        while len(self._seen_uids) > SEEN_UIDS_MAX:
            self._seen_uids.popitem(last=False)

    def _load_backstop(self) -> None:
        if self._backstop_loaded:
            return
        self._backstop_loaded = True
        state = None
        if self._instance_id is not None:
            from apps.octo.instances import poller_state

            state = poller_state.load(self._instance_id, BACKSTOP_STATE_KEY)
        if isinstance(state, dict):
            cursor = state.get("cursor")
            if isinstance(cursor, str) and cursor:
                self._resolved_cursor = cursor
            for uid in state.get("seen") or []:
                self._remember(uid)
        if self._resolved_cursor is None:
            # A first start begins NOW: never a backlog of resolved history.
            self._resolved_cursor = format_utc_ms(datetime.now(timezone.utc))

    def backstop_once(self) -> int:
        """Read the alerts resolved since the backstop cursor and ingest the
        ones the open list never showed. Returns how many were stored. Never
        raises (a failure is recorded for `intake_health`)."""
        fetch = getattr(self._client, "fetch_resolved_alerts_since", None)
        if not callable(fetch):
            return 0
        try:
            self._load_backstop()
            resolved = fetch(self._resolved_cursor, max_results=self._max_batch)
            stored = 0
            for raw in resolved:
                uid = raw.get("alertUid") if isinstance(raw, dict) else None
                if not isinstance(uid, str) or uid in self._seen_uids:
                    continue
                if self._ingest_one(raw):
                    stored += 1
                self._remember(uid)
            last = self._latest_timestamp(resolved)
            ceiling = format_utc_ms(
                datetime.now(timezone.utc) + timedelta(seconds=_CURSOR_FUTURE_SLACK_SEC))
            if last and (self._resolved_cursor or "") < last <= ceiling:
                self._resolved_cursor = last
            if self._instance_id is not None:
                from apps.octo.instances import poller_state

                poller_state.save(self._instance_id, BACKSTOP_STATE_KEY, {
                    "cursor": self._resolved_cursor, "seen": list(self._seen_uids)})
            self._backstop_ok_at = format_utc_ms(datetime.now(timezone.utc))
            self._backstop_error = None
            if stored:
                logger.info("[datto-poller] backstop: %d alert(s) resolved between polls "
                            "stored", stored)
            return stored
        except Exception as exc:  # noqa: BLE001 — never fatal to the open poll
            self._backstop_error = type(exc).__name__
            logger.warning("[datto-poller] resolved-alerts backstop failed (%s)",
                           type(exc).__name__)
            return 0

    def intake_health(self) -> dict[str, Any]:
        """What detection blindness (FR2) reads: since when the open list has
        been at its cap (None: it is not), the backstop's last success and
        last failure class."""
        return {"capped_since": self._capped_since, "max_batch": self._max_batch,
                "backstop_ok_at": self._backstop_ok_at,
                "backstop_error": self._backstop_error,
                "resolved_cursor": self._resolved_cursor}

    @staticmethod
    def _latest_timestamp(alerts: list[dict[str, Any]]) -> str | None:
        # Route every timestamp through the adapter's _to_iso so the cursor
        # normalizer handles exactly what extract_event does (epoch s/ms + ISO).
        # Otherwise an epoch-ms batch raises here and the cursor never advances.
        # _to_iso yields "" for anything unparseable, so a garbage timestamp is
        # skipped and can never become the cursor. Imported lazily to avoid the
        # adapter<->poller circular import.
        from apps.octo.adapters.datto.adapter import _to_iso
        latest: str | None = None
        for a in alerts:
            ts_iso = _to_iso(a.get("timestamp") or a.get("alertTimestamp"))
            if not ts_iso:
                continue
            if latest is None or ts_iso > latest:
                latest = ts_iso
        return latest

    def _ingest_one(self, raw_envelope: dict[str, Any]) -> bool:
        """True only when a NEW row was stored (not a duplicate, not held)."""
        try:
            event = self._adapter.extract_event(raw_envelope)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[datto-poller] extract failed for alert id=%s: %s",
                raw_envelope.get("alertUid"), exc,
            )
            return False
        if self._instance_id is not None:
            return self._deliver(raw_envelope, event)
        # No instance (a poller built directly, outside the framework): the
        # sink is the whole story — route by vendor id, else the default.
        tenant_slug = (
            self._adapter.route_to_tenant(raw_envelope)
            or self._default_tenant_slug
        )
        try:
            outcome = self._sink.ingest(tenant_slug, "datto", event)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[datto-poller] ingest failed for tenant=%s id=%s: %s",
                tenant_slug, raw_envelope.get("alertUid"), exc,
            )
            return False
        return not getattr(outcome, "duplicate", False)

    def _deliver(self, raw_envelope: dict[str, Any], event: Any) -> bool:
        """The platform resolves the tenant (map → same-name suggestion (held)
        → auto-create → quarantine); nothing is dropped. An open alert is re-listed every
        cycle, so a held one is logged once (its first hold), and it is
        re-tried every poll — stored as soon as its site resolves."""
        try:
            delivery = tenant_autocreate.deliver(
                instance_id=self._instance_id,
                vendor_slug="datto",
                adapter=self._adapter,
                envelope=raw_envelope,
                event=event,
                sink=self._sink,
                default_tenant_slug=(
                    None if self._default_tenant_slug in (None, "", "_unmapped")
                    else self._default_tenant_slug
                ),
                door="poll",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "[datto-poller] ingest failed for alert id=%s: %s",
                raw_envelope.get("alertUid"), exc,
            )
            return False
        if delivery.status == "quarantined":
            if delivery.quarantine_created:
                logger.warning(
                    "[datto-poller] HELD alert id=%s in quarantine (%s) — it could "
                    "not be attributed to a tenant. It stays held until a human "
                    "routes or discards it under Settings → Tenants → Quarantine.",
                    event.vendor_event_id, delivery.reason,
                )
            return False
        if delivery.outcome in ("auto-created", "auto-linked"):
            logger.info(
                "[datto-poller] alert id=%s routed to %r (%s)",
                event.vendor_event_id, delivery.slug, delivery.outcome,
            )
        return delivery.status == "stored"

    async def _sleep_or_stop(self, seconds: float) -> None:
        """Wait `seconds`, less when stopped or woken (`poll_now`)."""
        waiters = [
            asyncio.ensure_future(self._stopping.wait()),
            asyncio.ensure_future(self._wake.wait()),
        ]
        try:
            await asyncio.wait(
                waiters, timeout=seconds, return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            for waiter in waiters:
                waiter.cancel()
