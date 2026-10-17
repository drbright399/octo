"""RocketCyberPoller — the RocketCyber adapter's background task.

RocketCyber's API has no updated-since filter (and no webhooks), and an
incident CHANGES after it is created: open → resolved / suppressed, sometimes
weeks later. A creation-time cursor would therefore never see a resolution.
The model instead:

  * every cycle reads, each with an explicit status filter (what an
    unfiltered listing returns was never observed):
      - every OPEN incident created in the last `open_lookback_days` (365);
      - every RESOLVED and every SUPPRESSED incident created in the last
        `window_days` (14);
  * an incident is delivered when it is NEW, or when its status or
    resolvedAt differs from what was last delivered for it. Event-count
    growth, a PSA ticket being attached, a SOC edit to the write-up are NOT
    a new version: an ongoing detection would otherwise store (and the
    triage worker escalate) a fresh high row every cycle;
  * an incident last delivered OPEN that is in no listing any more was
    closed — possibly long after it left the 14-day window — so it is looked
    up again by its creation date (resolved + suppressed, a 3-day createdAt
    range, `MAX_RECHECK_DAYS_PER_CYCLE` dates per cycle): its closure
    arrives however long it stayed open. Not found there (deleted, or a
    status this adapter does not read) → it stops being tracked;
  * what was last delivered is the map id → (status, resolvedAt, createdAt).
    It is SEEDED on start from the rows already stored for this instance's
    tenants, so a restart neither re-stores an incident that only changed in
    ways that are not a new version (the PSA ticket attached while Athena was
    down: a new payload and updatedAt, so the sink would not collapse it) nor
    forgets which incidents are still open. It is bounded: an entry is kept
    while listed or while open, and by `MAX_TRACKED_INCIDENTS`;
  * each delivered version is its own stored event (received_at =
    updatedAt), labelled by presentation ("… — resolved"); an exact repeat is
    collapsed by the sink's (source, payload_sha256, received_at) guard;
  * a PSA TICKET attached after the version was stored (RocketCyber fills
    `psaId` minutes later — not a new version) is RECORDED on the stored row
    as a note (agent_notes: agent 'octo', query_kind 'vendor_update', no
    disposition), never a new alert row: the stored payload, its sha and
    received_at — the row's identity — are never touched. Once per
    (row, ticket); the latest stored row of each incident is remembered and
    seeded on start like the signatures;
  * HISTORY: the first sight of an incident whose NEWEST timestamp
    (createdAt, updatedAt, resolvedAt) is before `configured − initial_
    lookback_days` (7) is remembered, not delivered — a new instance does not
    replay months of history. `configured` is the instance's persisted
    creation time, not process start, and an incident that changed recently
    is never history: a restart cannot turn a status change into history.
    What was skipped as history is PERSISTED (`instances.poller_state`, key
    `history_skipped`: id → signature + createdAt, only while tracked) and
    seeded on start like the stored versions — a restart used to forget it,
    and the next change of such an incident's updatedAt (a PSA ticket, an
    event count) stored it as a brand-new HIGH row;
  * FIRST IMPORT: a new instance (saved less than `first_import_grace_sec`
    ago) reads but does not deliver until an operator has saved a tenant
    mapping for it, or that grace has passed — otherwise its first cycle,
    seconds after save, would auto-create a tenant (or hold a same-name one) for every
    customer before the wizard's mapping step could be used. Saving the
    mapping nudges the poller, so the import starts at once.

Routing is the platform's: `tenant_autocreate.deliver` (map → same-name
suggestion (held) → auto-create → quarantine; RocketCyber's numeric customer ids are never taken
as a client slug). An incident held in quarantine is NOT remembered, so it is
offered again every cycle (the hold itself is idempotent) and stored as soon
as its customer resolves — the way Datto re-lists a held open alert.

Every poll outcome is REPORTED (`vendor_contact.ContactReporter`); failures
back off (`FailureBackoff`), and HTTP 429 waits for the vendor's Retry-After.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.rocketcyber.client import (
    DEFAULT_OPEN_LOOKBACK_DAYS,
    MAX_OPEN_LOOKBACK_DAYS,
    MAX_RETRY_AFTER_SEC,
    IncidentListing,
    RocketCyberAuthError,
    RocketCyberClient,
    RocketCyberClientError,
    RocketCyberForbiddenError,
    RocketCyberRateLimitError,
    forbidden_guidance,
    poll_queries,
    recheck_range,
)
from apps.octo.adapters.rocketcyber.presentation import HEADLINE_PREFIX
from apps.octo.ingest import IngestSink
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp
from apps.octo.instances import poller_state, tenant_autocreate, tenant_map
from apps.octo.instances.manager import get_instance
from apps.octo.instances.vendor_contact import (
    ContactReporter,
    FailureBackoff,
    FailureKind,
)

logger = logging.getLogger(__name__)

# RocketCyber is slow-moving (a SOC raises a handful of incidents a day across
# a whole provider) and its rate limits are not documented: five minutes.
DEFAULT_POLL_INTERVAL_SEC = 300.0
DEFAULT_WINDOW_DAYS = 14.0
MAX_WINDOW_DAYS = 90.0
DEFAULT_INITIAL_LOOKBACK_DAYS = 7.0
# A new instance waits this long (from its save) for an operator's tenant
# mapping before its first import — unless the mapping is saved sooner.
DEFAULT_FIRST_IMPORT_GRACE_SEC = 3600.0
MAX_FIRST_IMPORT_GRACE_SEC = 86_400.0
# More than the page cap can ever list (20 × 500): the map is normally pruned
# each cycle to what is listed or still open; this bounds it regardless.
MAX_TRACKED_INCIDENTS = 20_000
# Closed-incident lookups (one creation date each: two reads) per cycle. A
# closure is rare; a backlog (e.g. after downtime) drains over a few cycles.
MAX_RECHECK_DAYS_PER_CYCLE = 10
RECHECK_MAX_PAGES = 4
# Restart seeding reads at most this many stored rows per tenant.
SEED_MAX_ROWS_PER_TENANT = 200_000
# This instance's stored incident versions, found through the events table's
# partial summary index (`summary != ''` must be spelled out for SQLite to use
# it): every RocketCyber headline starts with HEADLINE_PREFIX, so a tenant's
# other — far more numerous — events are never scanned.
_SEED_SQL = (
    "SELECT id, received_at, json_extract(payload, '$.id'), "
    "json_extract(payload, '$.status'), json_extract(payload, '$.resolvedAt'), "
    "json_extract(payload, '$.createdAt'), json_extract(payload, '$.psaId') "
    "FROM events WHERE summary != '' AND summary >= ? AND summary < ? "
    "AND source = ? LIMIT ?"
)
_SEED_PARAMS = (
    HEADLINE_PREFIX,
    HEADLINE_PREFIX[:-1] + chr(ord(HEADLINE_PREFIX[-1]) + 1),
    "rocketcyber",
    SEED_MAX_ROWS_PER_TENANT,
)

# Rejected / forbidden keys stay that way until a human acts; transport faults
# usually clear by themselves. Both back off from 60 s to 15 min, reset on the
# first success, and never stop. A successful customer discovery (the mapping
# panel's Reload) cuts the wait short (`poll_now`).
CREDENTIAL_BACKOFF_BASE_SEC = 60.0
CREDENTIAL_BACKOFF_CEILING_SEC = 900.0
TRANSPORT_BACKOFF_BASE_SEC = 60.0
TRANSPORT_BACKOFF_CEILING_SEC = 900.0

_RETRY_NOTE = (
    " Athena keeps retrying on its own (at most every "
    f"{int(CREDENTIAL_BACKOFF_CEILING_SEC // 60)} minutes); this clears as "
    "soon as a poll succeeds."
)

# Replacing a saved integration drops its tenant mappings, so that advice is
# only given once the rejection has PERSISTED — one 401 can be a blip.
AUTH_FAILURES_BEFORE_REPLACE_ADVICE = 3

# A vendor timestamp further ahead of our clock than this is not taken as
# "the newest event" (health).
_FUTURE_SLACK_SEC = 300

Signature = tuple[str, Optional[str]]
# id → (the signature last delivered, the incident's normalised createdAt).
Tracked = tuple[Signature, str]

# `instances.poller_state` key of the persisted history-skipped incidents.
HISTORY_STATE_KEY = "history_skipped"

# A PSA ticket attached after an incident version was stored is recorded as
# a note of this kind on the stored row (never a new alert row).
PSA_NOTE_KIND = "vendor_update"
_PSA_MAX = 64


def _psa_id(raw: Any) -> Optional[str]:
    """The incident's PSA ticket id as text ("" / missing / junk → None)."""
    value = raw.get("psaId") if isinstance(raw, dict) else None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = " ".join(str(value).split())[:_PSA_MAX]
    return text if text and text.isprintable() else None


def _incident_id(raw: Any) -> Optional[int]:
    value = raw.get("id") if isinstance(raw, dict) else raw
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def signature(raw: dict[str, Any]) -> Signature:
    """What makes a version of an incident worth delivering again: its
    status and resolution time. NOT its event count (an ongoing detection's
    count grows every few minutes — each one a new high row the triage
    worker escalates), nor its PSA ticket or write-up."""
    status = raw.get("status")
    resolved = raw.get("resolvedAt")
    return (
        status.strip().lower() if isinstance(status, str) else "",
        resolved if isinstance(resolved, str) and resolved else None,
    )


def _created(raw: dict[str, Any]) -> str:
    return normalize_timestamp(raw.get("createdAt"), naive_is_utc=True)


def _newest(raw: dict[str, Any]) -> str:
    """The latest of the incident's own timestamps ("" when none parses)."""
    stamps = [
        normalize_timestamp(raw.get(key), naive_is_utc=True)
        for key in ("createdAt", "updatedAt", "resolvedAt")
    ]
    return max((s for s in stamps if s), default="")


def _day(created: str) -> Optional[date]:
    try:
        return date.fromisoformat(created[:10]) if created else None
    except ValueError:
        return None


class RocketCyberPoller:
    """Run loop: rolling-window incident read → change detection → delivery."""

    def __init__(
        self,
        *,
        adapter,                          # RocketCyberSourceAdapter
        client: RocketCyberClient,
        sink: IngestSink,
        default_tenant_slug: str,
        poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
        window_days: float = DEFAULT_WINDOW_DAYS,
        initial_lookback_days: float = DEFAULT_INITIAL_LOOKBACK_DAYS,
        open_lookback_days: float = DEFAULT_OPEN_LOOKBACK_DAYS,
        first_import_grace_sec: float = 0.0,
        instance_id: Optional[int] = None,
        reporter: Optional[ContactReporter] = None,
        credential_backoff: Optional[FailureBackoff] = None,
        transport_backoff: Optional[FailureBackoff] = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._adapter = adapter
        self._client = client
        self._sink = sink
        self._default_tenant_slug = default_tenant_slug
        self._poll_interval = poll_interval_sec
        self._window_days = window_days
        self._open_lookback_days = max(
            window_days, min(MAX_OPEN_LOOKBACK_DAYS, open_lookback_days),
        )
        self._now = now
        self._lookback = timedelta(days=max(0.0, initial_lookback_days))
        # Incidents whose newest timestamp is before this, first seen now,
        # are history. Re-anchored on the instance's persisted creation time
        # by `_prepare` (process start is only the fallback).
        self._history_before = format_utc_ms(now() - self._lookback)
        self._first_import_grace = timedelta(
            seconds=max(0.0, min(MAX_FIRST_IMPORT_GRACE_SEC, first_import_grace_sec)),
        )
        # Set by `_prepare` while a new instance waits for its mapping.
        self._hold_until: Optional[datetime] = None
        self._hold_logged = False
        self._prepared = False
        self._instance_id = instance_id
        self._reporter = reporter or ContactReporter(instance_id, what="rocketcyber-poller")
        self._credential_backoff = credential_backoff or FailureBackoff(
            base_sec=CREDENTIAL_BACKOFF_BASE_SEC,
            ceiling_sec=CREDENTIAL_BACKOFF_CEILING_SEC,
        )
        self._transport_backoff = transport_backoff or FailureBackoff(
            base_sec=TRANSPORT_BACKOFF_BASE_SEC,
            ceiling_sec=TRANSPORT_BACKOFF_CEILING_SEC,
        )
        self._auth_failures = 0
        # id → (the signature last DELIVERED — stored / duplicate — or
        # skipped as history, its createdAt). Insertion-ordered: the oldest
        # entry goes first when full.
        self._seen: dict[int, Tracked] = {}
        # Tracked ids that were skipped as HISTORY (never stored): persisted
        # so a restart still knows them (`HISTORY_STATE_KEY`).
        self._history_ids: set[int] = set()
        self._persisted_history: Optional[dict[str, list]] = None
        # id → (tenant slug, events.db id of its latest STORED version, the
        # PSA ticket that row is known to carry — in its payload or noted).
        self._stored_ref: dict[int, tuple[str, int, Optional[str]]] = {}
        self._last_event_at: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stopping = asyncio.Event()
        self._wake = asyncio.Event()

    @property
    def last_event_at(self) -> Optional[str]:
        """Vendor timestamp of the newest incident version stored."""
        return self._last_event_at

    @property
    def tracked(self) -> int:
        return len(self._seen)

    @property
    def holding_first_import(self) -> bool:
        """True while a new instance waits for its tenant mapping — never past
        the wait's deadline (the card must not promise a time that has gone
        by while reads fail; the poll error is what it shows then)."""
        until = self._hold_until
        return until is not None and self._now() < until

    @property
    def first_import_at(self) -> Optional[str]:
        """While the first import waits for the tenant mapping: when it starts
        on its own (canonical UTC ms) — it starts sooner the moment a mapping
        is saved. None when not waiting (or the deadline has passed)."""
        until = self._hold_until
        return format_utc_ms(until) if self.holding_first_import and until else None

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="rocketcyber-poller")

    def poll_now(self) -> None:
        """Cut the current wait short — from ANY thread."""
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

    # ----- the loop -----

    async def _run(self) -> None:
        logger.info(
            "[rocketcyber-poller] starting (interval=%.1fs, window=%.1f days, "
            "open incidents %.0f days)",
            self._poll_interval, self._window_days, self._open_lookback_days,
        )
        try:
            while not self._stopping.is_set():
                self._wake.clear()
                try:
                    await self._drain_once()
                except RocketCyberForbiddenError as exc:
                    # Before RocketCyberClientError (its base).
                    delay = self._credential_backoff.next()
                    logger.warning(
                        "[rocketcyber-poller] forbidden: %s (retry in %.0fs)", exc, delay,
                    )
                    account = self._client_account()
                    await self._report_failure(
                        "forbidden",
                        forbidden_guidance(
                            exc.vendor_error,
                            account_id=exc.account_id,
                            overridden=bool(account and account.overridden),
                            saved=True,
                            retry_note=_RETRY_NOTE,
                        ),
                    )
                    await self._sleep_or_stop(delay)
                    continue
                except RocketCyberAuthError as exc:
                    delay = self._credential_backoff.next()
                    logger.warning(
                        "[rocketcyber-poller] auth failed: %s (retry in %.0fs)", exc, delay,
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
                            " The stored API key no longer works — it may have "
                            "been deleted or regenerated in the RocketCyber "
                            "console. Stored keys cannot be edited: Disable this "
                            "integration, then Add integration again with a "
                            "current key (map your customers again afterwards)."
                        )
                    await self._report_failure("auth", f"{exc}.{advice}{_RETRY_NOTE}")
                    await self._sleep_or_stop(delay)
                    continue
                except RocketCyberRateLimitError as exc:
                    asked = exc.retry_after_sec
                    delay = (
                        max(1.0, min(MAX_RETRY_AFTER_SEC, asked)) if asked is not None
                        else self._transport_backoff.next()
                    )
                    logger.warning(
                        "[rocketcyber-poller] rate limited (retry in %.0fs)", delay,
                    )
                    await self._report_failure(
                        "transport",
                        "RocketCyber is rate limiting Athena's requests (HTTP 429). "
                        f"The next poll waits {int(delay)} s"
                        + (" as RocketCyber asked" if asked is not None else "")
                        + "; this clears by itself.",
                    )
                    await self._sleep_or_stop(delay)
                    continue
                except RocketCyberClientError as exc:
                    delay = self._transport_backoff.next()
                    logger.warning(
                        "[rocketcyber-poller] transport error: %s (retry in %.0fs)",
                        exc, delay,
                    )
                    await self._report_failure(
                        "transport",
                        f"Could not read incidents from RocketCyber: {exc}. "
                        "Retrying automatically (backing off up to "
                        f"{int(TRANSPORT_BACKOFF_CEILING_SEC // 60)} minutes); this "
                        "clears as soon as a poll succeeds.",
                    )
                    await self._sleep_or_stop(delay)
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "[rocketcyber-poller] unexpected error: %s", type(exc).__name__,
                    )
                    # Class name only — an arbitrary exception's text is not
                    # vetted for what it may embed.
                    await self._report_failure(
                        "internal",
                        "The RocketCyber poll failed inside Athena "
                        f"({type(exc).__name__}); see the server log. Retrying "
                        "automatically.",
                    )
                    await self._sleep_or_stop(self._poll_interval)
                    continue
                self._credential_backoff.reset()
                self._transport_backoff.reset()
                self._auth_failures = 0
                await asyncio.to_thread(self._reporter.ok)
                await self._sleep_or_stop(self._poll_interval)
        finally:
            logger.info(
                "[rocketcyber-poller] stopped (tracking %d incident(s))", len(self._seen),
            )

    def _client_account(self):
        return getattr(self._client, "account", None)

    async def _report_failure(self, kind: FailureKind, detail: str) -> None:
        await asyncio.to_thread(self._reporter.failed, kind, detail)

    # ----- one cycle -----

    async def _drain_once(self) -> None:
        if not self._prepared:
            await asyncio.to_thread(self._prepare)
        if self._hold_until is not None:
            # Settle the wait BEFORE the read: a saved mapping or a passed
            # deadline ends it even when the read below fails (a revoked
            # key, 429, an outage) — the card then stops saying "waiting
            # for your customer mapping" and shows the poll error.
            await asyncio.to_thread(self._still_holding)
        listing = await asyncio.to_thread(self._fetch_cycle)
        if self._hold_until is not None and await asyncio.to_thread(self._still_holding):
            return
        listed = {i for i in (_incident_id(raw) for raw in listing.incidents) if i is not None}
        # Delivered on the loop thread, like Datto's poller: the sink's live
        # (SSE) publish needs the running loop.
        counts = self._process(listing)
        if not listing.truncated:
            await self._recheck_closed(listed, counts)
        await asyncio.to_thread(self._persist_history)
        if counts["delivered"] or counts["held"] or counts["failed"] or counts["vanished"]:
            logger.info(
                "[rocketcyber-poller] %d incident(s) listed: %d delivered, "
                "%d unchanged, %d history, %d held, %d failed, %d no longer "
                "found (untracked)",
                len(listing.incidents), counts["delivered"], counts["unchanged"],
                counts["history"], counts["held"], counts["failed"], counts["vanished"],
            )

    def _fetch_cycle(self) -> IncidentListing:
        """This cycle's reads (`poll_queries`), merged by id — a later read
        wins: an incident resolved between two reads is taken as resolved."""
        merged: dict[int, dict[str, Any]] = {}
        anonymous: list[dict[str, Any]] = []
        truncated = False
        for query in poll_queries(
            self._now(),
            window_days=self._window_days,
            open_lookback_days=self._open_lookback_days,
        ):
            listing = self._client.fetch_incidents(
                created_from=query.created_from,
                created_to=query.created_to,
                status=query.status,
            )
            truncated = truncated or listing.truncated
            for raw in listing.incidents:
                iid = _incident_id(raw)
                if iid is None:
                    anonymous.append(raw)
                else:
                    merged[iid] = raw
        return IncidentListing(list(merged.values()) + anonymous, truncated)

    def _process(self, listing: IncidentListing) -> dict[str, int]:
        counts = {
            "delivered": 0, "unchanged": 0, "history": 0, "held": 0, "failed": 0,
            "vanished": 0,
        }
        listed: set[int] = set()
        for raw in listing.incidents:
            iid = _incident_id(raw)
            if iid is not None:
                listed.add(iid)
            self._consider(raw, iid, counts)
        if not listing.truncated:
            # Forget what no read lists any more — except incidents last
            # delivered OPEN: their closure is still to come
            # (`_recheck_closed`).
            self._seen = {
                k: v for k, v in self._seen.items() if k in listed or v[0][0] == "open"
            }
        return counts

    def _consider(self, raw: dict[str, Any], iid: Optional[int], counts: dict[str, int]) -> None:
        sig = signature(raw)
        if iid is not None:
            tracked = self._seen.get(iid)
            if tracked is not None and tracked[0] == sig:
                counts["unchanged"] += 1
                self._record_psa(iid, raw)
                return
            if tracked is None and self._is_history(raw):
                self._remember(iid, sig, _created(raw))
                self._history_ids.add(iid)
                counts["history"] += 1
                return
        outcome = self._ingest_one(raw)
        if outcome in ("stored", "duplicate"):
            counts["delivered"] += 1
            if iid is not None:
                self._remember(iid, sig, _created(raw))
                self._history_ids.discard(iid)        # a stored version now
        elif outcome == "quarantined":
            counts["held"] += 1
        else:
            counts["failed"] += 1

    async def _recheck_closed(self, listed: set[int], counts: dict[str, int]) -> None:
        """Incidents last delivered OPEN that no read lists any more were
        closed (or deleted). Those older than the resolved / suppressed
        window are found again by their creation date, and their closure is
        delivered like any change. Oldest dates first, a bounded number per
        cycle; an incident not found at all stops being tracked."""
        waiting: dict[int, date] = {}
        for iid, (sig, created) in list(self._seen.items()):
            if sig[0] != "open" or iid in listed:
                continue
            day = _day(created)
            if day is None:
                self._seen.pop(iid, None)
                counts["vanished"] += 1
            else:
                waiting[iid] = day
        reads = 0
        while waiting and reads < MAX_RECHECK_DAYS_PER_CYCLE:
            # Oldest date first. A read spans a day either side, so it can
            # settle a neighbouring date's incidents too.
            day = min(waiting.values())
            reads += 1
            found, complete = await asyncio.to_thread(self._read_closed_around, day)
            for raw in found:
                iid = _incident_id(raw)
                if iid is not None and iid in waiting:
                    del waiting[iid]
                    self._consider(raw, iid, counts)
            for iid in [i for i, d in waiting.items() if d == day]:
                del waiting[iid]
                if complete:
                    # Not open, resolved or suppressed around its creation
                    # date: deleted, or a status this adapter does not read.
                    self._seen.pop(iid, None)
                    counts["vanished"] += 1
                # else: a truncated read proves nothing — looked up again
                # next cycle.

    def _read_closed_around(self, day: date) -> tuple[list[dict[str, Any]], bool]:
        """Resolved and suppressed incidents created around `day`, and
        whether both reads were complete (not stopped at the page cap)."""
        created_from, created_to = recheck_range(day)
        found: list[dict[str, Any]] = []
        complete = True
        for status in ("resolved", "suppressed"):
            listing = self._client.fetch_incidents(
                created_from=created_from, created_to=created_to,
                status=status, max_pages=RECHECK_MAX_PAGES,
            )
            found.extend(listing.incidents)
            complete = complete and not listing.truncated
        return found, complete

    def _is_history(self, raw: dict[str, Any]) -> bool:
        newest = _newest(raw)
        return bool(newest) and newest < self._history_before

    def _remember(self, iid: int, sig: Signature, created: str) -> None:
        self._seen.pop(iid, None)
        self._seen[iid] = (sig, created)
        while len(self._seen) > MAX_TRACKED_INCIDENTS:
            self._seen.pop(next(iter(self._seen)))

    # ----- start-up state (off the loop thread) -----

    def _prepare(self) -> None:
        """Once, before the first read: anchor the history rule on the
        instance's persisted creation time, decide whether its first import
        waits for a tenant mapping, and seed the map from what this instance
        already stored. Never raises: each part falls back to the behaviour
        of a poller without that knowledge."""
        self._prepared = True
        if self._instance_id is None:
            return
        now = self._now()
        configured: Optional[datetime] = None
        try:
            record = get_instance(self._instance_id)
            stamp = normalize_timestamp(
                getattr(record, "configured_at", None), naive_is_utc=True,
            )
            if stamp:
                configured = min(
                    now, datetime.fromisoformat(stamp.replace("Z", "+00:00")),
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[rocketcyber-poller] could not read the instance row (%s); the "
                "history bound is anchored on process start", type(exc).__name__,
            )
        if configured is not None:
            self._history_before = format_utc_ms(configured - self._lookback)
            if self._first_import_grace and configured + self._first_import_grace > now:
                self._hold_until = configured + self._first_import_grace
        try:
            seeded = self._stored_versions(now)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[rocketcyber-poller] could not read stored incidents (%s); "
                "change tracking starts from what was skipped as history",
                type(exc).__name__,
            )
            seeded = {}
        for iid, tracked in seeded.items():
            if iid not in self._seen:
                self._seen[iid] = tracked
        # What was skipped as history (never stored) — persisted, see HISTORY.
        self._seed_history()
        while len(self._seen) > MAX_TRACKED_INCIDENTS:
            self._seen.pop(next(iter(self._seen)))

    def _tenant_slugs(self) -> set[str]:
        record = get_instance(self._instance_id)
        slugs = tenant_map.instance_tenant_slugs(record) if record is not None else set()
        if self._default_tenant_slug not in (None, "", "_unmapped"):
            slugs.add(self._default_tenant_slug)
        return {s for s in slugs if isinstance(s, str) and paths.SLUG_RE.match(s)}

    def _stored_versions(self, now: datetime) -> dict[int, Tracked]:
        """The latest STORED version of every incident this instance
        delivered that a cycle can still list (created within the open
        lookback), as id → (signature, createdAt) — read through the summary
        index (`_SEED_SQL`). A tenant whose DB cannot be read is skipped (the
        sink's exact-repeat guard still applies there)."""
        cutoff = format_utc_ms(now - timedelta(days=self._open_lookback_days + 1))
        latest: dict[int, tuple[str, int, Tracked]] = {}
        refs: dict[int, tuple[str, int, Optional[str]]] = {}
        for slug in sorted(self._tenant_slugs()):
            db = paths.client_dir(slug) / "events.db"
            if not db.exists():
                continue
            try:
                conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10.0)
            except sqlite3.Error:
                continue
            try:
                rows = conn.execute(_SEED_SQL, _SEED_PARAMS)
                for row_id, received, raw_id, status, resolved, created, psa in rows:
                    iid = _incident_id(raw_id)
                    if iid is None:
                        continue
                    created_at = normalize_timestamp(created, naive_is_utc=True)
                    if created_at and created_at < cutoff:
                        continue
                    key = (str(received or ""), int(row_id))
                    held = latest.get(iid)
                    if held is not None and (held[0], held[1]) >= key:
                        continue
                    sig = signature({"status": status, "resolvedAt": resolved})
                    latest[iid] = (key[0], key[1], (sig, created_at))
                    refs[iid] = (slug, int(row_id), _psa_id({"psaId": psa}))
            except sqlite3.Error as exc:
                logger.warning(
                    "[rocketcyber-poller] could not read stored incidents of one "
                    "tenant (%s); skipped", type(exc).__name__,
                )
            finally:
                conn.close()
        # The latest stored row per incident (PSA tickets are noted there);
        # a note already written for a ticket is found again by psa_note.
        for iid, ref in refs.items():
            self._stored_ref.setdefault(iid, ref)
        # Oldest version first: the map evicts from its front when full.
        ordered = sorted(latest.items(), key=lambda item: (item[1][0], item[1][1]))
        return {iid: entry[2] for iid, entry in ordered}

    def _history_marks(self) -> dict[str, list]:
        """The persisted form: id → [status, resolvedAt, createdAt] of every
        history-skipped incident still tracked (bounded by the map)."""
        self._history_ids &= set(self._seen)
        return {
            str(iid): [self._seen[iid][0][0], self._seen[iid][0][1], self._seen[iid][1]]
            for iid in sorted(self._history_ids)
        }

    def _persist_history(self) -> None:
        """Write the history marks when they changed (normally once, after
        the first connect). Never raises."""
        if self._instance_id is None:
            return
        marks = self._history_marks()
        if marks == self._persisted_history:
            return
        if poller_state.save(self._instance_id, HISTORY_STATE_KEY, marks):
            self._persisted_history = marks

    def _seed_history(self) -> None:
        """Restore the persisted history marks (ids not already seeded from
        a stored version — a stored version wins)."""
        marks = poller_state.load(self._instance_id, HISTORY_STATE_KEY)
        if not isinstance(marks, dict):
            return
        for key, value in marks.items():
            try:
                iid = int(key)
                status, resolved_at, created = value
            except (TypeError, ValueError):
                continue
            if iid <= 0 or iid in self._seen:
                continue
            self._seen[iid] = (
                (str(status or ""), resolved_at if isinstance(resolved_at, str) else None),
                str(created or ""),
            )
            self._history_ids.add(iid)
        self._persisted_history = self._history_marks()

    def _record_psa(self, iid: int, raw: dict[str, Any]) -> None:
        """A PSA ticket the stored row does not carry yet → one note on that
        row. Never raises; the row itself is never touched."""
        psa = _psa_id(raw)
        ref = self._stored_ref.get(iid)
        if psa is None or ref is None or ref[2] == psa:
            return
        slug, row_id, _known = ref
        if psa_note(slug, row_id, iid, psa):
            self._stored_ref[iid] = (slug, row_id, psa)

    def _still_holding(self) -> bool:
        """A new instance's first import waits until an operator saved a
        tenant mapping (any mapping not written by auto-create) or the grace
        has passed."""
        until = self._hold_until
        if until is None:
            return False
        reason = ""
        if self._now() >= until:
            reason = "the wait for a tenant mapping ended"
        else:
            try:
                mappings = tenant_map.get_mappings(self._instance_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[rocketcyber-poller] could not read the tenant map (%s); "
                    "still waiting", type(exc).__name__,
                )
                return True
            if any(m.match_source != "auto" for m in mappings):
                reason = "a tenant mapping was saved"
        if not reason:
            if not self._hold_logged:
                self._hold_logged = True
                logger.info(
                    "[rocketcyber-poller] first import waits for the tenant "
                    "mapping (at most until %s)", format_utc_ms(until),
                )
            return True
        self._hold_until = None
        logger.info("[rocketcyber-poller] first import starts: %s", reason)
        return False

    def _note_stored(self, event: Any) -> None:
        ts = getattr(event, "received_at", "") or ""
        ceiling = format_utc_ms(self._now() + timedelta(seconds=_FUTURE_SLACK_SEC))
        if ts and ts <= ceiling and (self._last_event_at is None or ts > self._last_event_at):
            self._last_event_at = ts

    def _ingest_one(self, raw: dict[str, Any]) -> str:
        """'stored' | 'duplicate' | 'quarantined' | 'failed'."""
        try:
            event = self._adapter.extract_event(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[rocketcyber-poller] extract failed for incident id=%s: %s",
                _incident_id(raw), type(exc).__name__,
            )
            return "failed"
        if self._instance_id is not None:
            return self._deliver(self._instance_id, raw, event)
        # No instance (a poller built directly, outside the framework): no
        # tenant map, so everything goes to the default tenant. A customer's
        # numeric accountId is NEVER used as a client slug ("2002" is a valid
        # slug of some other client).
        tenant_slug = self._default_tenant_slug
        try:
            outcome = self._sink.ingest(tenant_slug, "rocketcyber", event)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[rocketcyber-poller] ingest failed for incident id=%s: %s",
                _incident_id(raw), type(exc).__name__,
            )
            return "failed"
        self._remember_row(raw, tenant_slug, getattr(outcome, "event_id", None))
        if getattr(outcome, "duplicate", False):
            return "duplicate"
        self._note_stored(event)
        return "stored"

    def _remember_row(self, raw: dict[str, Any], slug: Optional[str],
                      row_id: Optional[int]) -> None:
        iid = _incident_id(raw)
        if iid is None or not slug or not isinstance(row_id, int):
            return
        known = self._stored_ref.get(iid)
        psa = _psa_id(raw)
        if known is not None and known[1] == row_id:
            # The same stored row (a duplicate): keep what is known of it.
            psa = known[2] or psa
        self._stored_ref[iid] = (slug, row_id, psa)

    def _deliver(self, instance_id: int, raw: dict[str, Any], event: Any) -> str:
        try:
            delivery = tenant_autocreate.deliver(
                instance_id=instance_id,
                vendor_slug="rocketcyber",
                adapter=self._adapter,
                envelope=raw,
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
                "[rocketcyber-poller] ingest failed for incident id=%s: %s",
                event.vendor_event_id, type(exc).__name__,
            )
            return "failed"
        if delivery.status == "quarantined":
            if delivery.quarantine_created:
                logger.warning(
                    "[rocketcyber-poller] HELD incident id=%s in quarantine (%s) — "
                    "it could not be attributed to a tenant. It stays held until a "
                    "human routes or discards it under Settings → Tenants → "
                    "Quarantine.",
                    event.vendor_event_id, delivery.reason,
                )
            return "quarantined"
        if delivery.outcome in ("auto-created", "auto-linked"):
            logger.info(
                "[rocketcyber-poller] incident id=%s routed to %r (%s)",
                event.vendor_event_id, delivery.slug, delivery.outcome,
            )
        if delivery.ingested:
            self._remember_row(raw, delivery.slug, delivery.event_id)
        if delivery.status == "stored":
            self._note_stored(event)
        return delivery.status

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


def psa_note(slug: str, row_id: int, incident_id: int, psa: str) -> bool:
    """Record on the stored row `row_id` of `slug` that RocketCyber attached
    PSA ticket `psa` to incident `incident_id` — ONE note per (row, ticket):
    an existing one is found, not duplicated. True when the note exists
    afterwards. Never raises (a failure is logged; the next cycle retries)."""
    import uuid

    from apps.octo.agent import notes as agent_notes

    marker = f"PSA ticket {psa} "
    db = paths.client_dir(slug) / "events.db"
    try:
        conn = sqlite3.connect(db, timeout=10.0)
        try:
            agent_notes.ensure_agent_schema(conn)
            with conn:
                if conn.execute("SELECT 1 FROM events WHERE id = ?", (row_id,)).fetchone() is None:
                    return False
                if conn.execute(
                    "SELECT 1 FROM agent_notes WHERE ref_kind = 'event' AND ref_id = ? "
                    "AND query_kind = ? AND instr(note_text, ?) > 0",
                    (row_id, PSA_NOTE_KIND, marker),
                ).fetchone() is None:
                    agent_notes.insert_agent_note_row(
                        conn, ref_kind="event", ref_id=row_id, agent_id="octo",
                        note_text=(
                            f"RocketCyber attached PSA ticket {psa} to incident "
                            f"{incident_id} after this alert was stored. Recorded here — "
                            "the alert keeps its first report, and no new alert row "
                            "was created."
                        ),
                        confidence=1.0, request_id=f"rocketcyber-psa-{uuid.uuid4().hex}",
                        query_kind=PSA_NOTE_KIND,
                    )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning(
            "[rocketcyber-poller] could not record the PSA ticket of incident id=%s "
            "(%s); retried next cycle", incident_id, type(exc).__name__,
        )
        return False
    return True
