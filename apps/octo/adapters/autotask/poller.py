"""AutotaskPoller — read-only ingest worker (P4-c1).

Pulls Tickets + TicketNotes from Autotask on a cadence and upserts
them into each tenant's `<slug>/tickets.db`. UNLIKE the source-adapter
event-ingest path used by Datto/Wazuh/etc., Autotask data lands
DIRECTLY in tickets.db — not events.db — because tickets aren't
events in the SIEM sense.

Watermark: `lastActivityDate` per entity (the "cursor"). Persisted per
instance in the registry's `adapter_poller_state` (keys `ticket_cursor`,
`note_cursor`) every time it advances, and restored on start — a restart
continues where the last poll stopped instead of re-seeding.

Catch-up (slice 0 of the PSA write design): each entity is read with
`query_all` (every page of the answer, up to the page cap) for the window
"lastActivityDate after the cursor". When that window is longer than the
cap, the poller does NOT advance past rows it has not seen: it splits the
window in half (by time) until a half fits, reads that half whole, moves the
cursor to its end, and goes on from there. A tick reads a bounded number of
windows; the rest is picked up on the next tick from the persisted cursor.
A window that ends within SETTLE_LAG of the local clock never puts the
cursor at its (local-clock) end: the cursor moves to the newest
lastActivityDate actually read, Autotask's own clock, as for the open window.
Notes are read only once the tickets have caught up, so a note is never
routed before its ticket had the chance to land. The cursor moves past every
row read — routed or not (an unmapped company, an unknown parent ticket).

A note can still be read before its ticket exists here (the ticket was
created between the tickets read and the notes read): it is an orphan, and
the note cursor moves past it. So every NEWLY mirrored ticket gets its notes
read once by ticket id (the note backfill; queued in the registry before the
ticket cursor moves, drained a bounded number per tick).

The static maps changed in slice 0, and a mirrored row is only re-read when
its ticket changes again in Autotask: once per map version every mirrored
row last synced before this poller started is re-read by id (bounded batches
per tick, progress in the registry) so an idle ticket stops showing the old
map's priority / status.

A first run (nothing persisted) starts `initial_lookback_days` ago (default
30), not at the beginning of the PSA's history.

Tenant routing: `companyID` on each Autotask ticket → tenant slug via
`autotask_tenant_company_map` (registry.db, populated in P4-b1).
Tickets whose companyID has no mapping are SKIPPED with a warning;
the operator surfaces this in Settings → Integrations → Autotask as
a "X tickets ignored" hint (UI lands in P4-b2).

Picklist translation: static AW03 maps (TODO(zack): verify) until slice 1
replaces them with the picklist mirror. A per-instance cache passed by the
caller wins. An unknown status keeps the status Athena already had. Every
mirrored status change lands in `ticket_status_history` (source
'autotask_sync').

Every poll cycle's outcome is reported to the instance row
(`vendor_contact.ContactReporter`), as the source pollers do.

Once a day the poll also refreshes the SITE-LOCATION PROPOSALS
(`apps.octo.proposals.site_location`): the mapped, active companies'
addresses and their CompanyLocations — a couple of bounded reads, never a
geocoder call. An operator confirms each one; nothing here pins a site.
"""
from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.autotask.client import (
    IN_BATCH,
    MAX_PAGES,
    MAX_RECORDS,
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskPageCapError,
)
from apps.octo.instances import poller_state
from apps.octo.instances.vendor_contact import (
    ContactReporter,
    FailureKind,
    poll_failure_detail,
)

logger = logging.getLogger(__name__)


DEFAULT_POLL_INTERVAL_SEC = 30.0
DEFAULT_MAX_BATCH = 500
PROPOSALS_EVERY_SEC = 24 * 3600.0
PROPOSALS_FIRST_CHECK_SEC = 600.0
PROPOSALS_RECHECK_SEC = 3600.0

# Cursor persistence (registry `adapter_poller_state`, per instance).
TICKET_CURSOR_KEY = "ticket_cursor"
NOTE_CURSOR_KEY = "note_cursor"

# Catch-up bounds. A window that still exceeds the page cap once it is no
# wider than MIN_WINDOW is read with the larger FLOOR_MAX_PAGES allowance
# (thousands of rows touched within one second is a bulk edit, not history).
DEFAULT_INITIAL_LOOKBACK_DAYS = 30.0
MAX_WINDOWS_PER_TICK = 16
MIN_WINDOW = timedelta(seconds=1)
FLOOR_MAX_PAGES = 200
# A closed window ending later than this before the LOCAL clock may still
# gain rows (a clock ahead of Autotask's; a bulk edit still being written):
# the cursor then follows the rows actually read, not the window's end.
SETTLE_LAG = timedelta(seconds=120)

# Note backfill for newly mirrored tickets (registry `adapter_poller_state`).
NOTE_BACKFILL_KEY = "note_backfill"
MAX_NOTE_BACKFILLS_PER_TICK = 50
MAX_PENDING_NOTE_BACKFILLS = 5000

# One-time re-read of the mirrored rows when the static maps change.
STATIC_MAPS_VERSION = "aw03-slice0"
STATIC_MAPS_STATE_KEY = "static_maps_refresh"
MAX_REFRESH_BATCHES_PER_TICK = 25
REFRESH_BATCH = IN_BATCH


# ---------------------------------------------------------------------------
# Static picklist translations — the AW03 values (this bundle's Autotask).
#
# TODO(zack): verify every id against the live AW03 picklists. Slice 1
# replaces these static maps with the picklist mirror
# (`autotask_picklist_values` + Zack's `autotask_picklist_cache` labels);
# until then a per-instance cache passed by the caller still wins.
#
# The factory defaults these replaced were wrong for AW03: priority 4 is
# Critical here (it read as "low"), and status 11 is Escalated (it read as
# "resolved"), so an escalated ticket showed as done.
# ---------------------------------------------------------------------------

# Autotask Tickets.priority on AW03: 1 High, 2 Medium, 3 Low, 4 Critical,
# 5 Informational.
_AW03_PRIORITY_TO_SEVERITY: dict[int, str] = {
    4: "critical",
    1: "high",
    2: "medium",
    3: "low",
    5: "info",
}

# Autotask Tickets.status on AW03. An id not listed here is UNKNOWN: the
# ticket keeps the status Athena already had (a brand-new mirror row starts
# as "new") — never a guess that could close or reopen it.
_AW03_STATUS_TO_ATHENA: dict[int, str] = {
    1: "new",
    **{v: "in_progress" for v in (8, 10, 11, 21, 22, 26, 28, 29)},
    **{v: "waiting_customer" for v in (7, 19, 23, 24, 25)},
    **{v: "waiting_vendor" for v in (9, 17)},
    **{v: "resolved" for v in (5, 20, 27)},
}


def autotask_priority_to_severity(
    value_id: Optional[int],
    *,
    cache: Optional[dict[int, str]] = None,
    previous: Optional[str] = None,
) -> str:
    """Translate Autotask Tickets.priority integer → Athena severity.

    The per-instance picklist cache (when provided) wins, then the AW03
    static map. An unknown or missing value keeps `previous` (the severity
    the mirror row already has) and is 'medium' only for a new row."""
    if value_id is not None:
        if cache is not None and value_id in cache:
            return cache[value_id]
        if value_id in _AW03_PRIORITY_TO_SEVERITY:
            return _AW03_PRIORITY_TO_SEVERITY[value_id]
    return previous or "medium"


def autotask_status_to_athena(
    value_id: Optional[int],
    *,
    cache: Optional[dict[int, str]] = None,
    previous: Optional[str] = None,
) -> str:
    """Translate Autotask Tickets.status integer → Athena status.

    Same lookup order as the priority mapper. An unknown or missing value
    keeps `previous` — the status Athena already shows — instead of falling
    back to 'new' (which reopened finished tickets); 'new' only for a row
    that has no status yet."""
    if value_id is not None:
        if cache is not None and value_id in cache:
            return cache[value_id]
        if value_id in _AW03_STATUS_TO_ATHENA:
            return _AW03_STATUS_TO_ATHENA[value_id]
    return previous or "new"


# ---------------------------------------------------------------------------
# Tenant routing
# ---------------------------------------------------------------------------

def load_tenant_routing(adapter_instance_id: int) -> dict[int, str]:
    """`{autotask_company_id: tenant_slug}` for this instance from BOTH
    mapping stores: the generic editor's `adapter_tenant_map` (numeric
    vendor tenant ids — what Integrations → Map tenants writes) and the
    Autotask page's `autotask_tenant_company_map`, which wins on a conflict.
    Empty dict when neither has rows — the poller treats that as "no
    tenants configured, skip every ticket"."""
    reg_path = paths.registry_db_path()
    if not reg_path.exists():
        return {}
    try:
        conn = sqlite3.connect(f"file:{reg_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            routing: dict[int, str] = {}
            try:
                generic = conn.execute(
                    "SELECT vendor_tenant_id, octo_client_slug "
                    "  FROM adapter_tenant_map "
                    " WHERE adapter_instance_id = ?",
                    (adapter_instance_id,),
                ).fetchall()
            except sqlite3.OperationalError:
                generic = []            # pre-030 registry
            for r in generic:
                try:
                    company = int(str(r["vendor_tenant_id"]).strip())
                except (TypeError, ValueError):
                    continue            # not an Autotask company id
                if company >= 0 and r["octo_client_slug"]:
                    routing[company] = r["octo_client_slug"]
            rows = conn.execute(
                "SELECT tenant_slug, autotask_company_id "
                "  FROM autotask_tenant_company_map "
                " WHERE adapter_instance_id = ?",
                (adapter_instance_id,),
            ).fetchall()
            routing.update({r["autotask_company_id"]: r["tenant_slug"] for r in rows})
            return routing
        finally:
            conn.close()
    except sqlite3.OperationalError:
        # Pre-migration-015 registry. Treat as empty.
        return {}


# ---------------------------------------------------------------------------
# Reconciler — write Autotask data into the local tickets.db
# ---------------------------------------------------------------------------

def _ensure_local_tickets_db_at_latest(slug: str) -> None:
    """Borrow the lazy-init from the tickets router so we don't have
    a parallel copy. Idempotent — applies migrations 013 + 014 if
    the DB is behind, no-op otherwise."""
    from apps.octo.api.routers.tickets import _ensure_schema
    _ensure_schema(slug)


def upsert_ticket(
    tenant_slug: str,
    autotask_ticket: dict[str, Any],
    *,
    priority_cache: Optional[dict[int, str]] = None,
    status_cache: Optional[dict[int, str]] = None,
) -> str:
    """Upsert one Autotask Ticket payload into the tenant's tickets.db.

    Returns 'inserted' or 'updated' or 'skipped' so the caller (poller)
    can log a digest per-cycle. UPSERT is keyed by autotask_id —
    re-pulling the same ticket updates the local row rather than
    duplicating.

    Every status the mirror takes from Autotask is written to
    `ticket_status_history` with source 'autotask_sync' (the first one with
    from_status NULL, as for an operator-opened ticket) in the same
    transaction as the row. An unchanged or unknown status writes nothing.
    """
    _ensure_local_tickets_db_at_latest(tenant_slug)
    db = paths.client_dir(tenant_slug) / "tickets.db"

    autotask_id = autotask_ticket.get("id")
    if autotask_id is None:
        return "skipped"
    title = (autotask_ticket.get("title") or "")[:500] or f"Autotask #{autotask_id}"
    description = (autotask_ticket.get("description") or "")[:8000]
    raw_status = autotask_ticket.get("status")
    history_reason = f"Autotask status {raw_status}"[:200]
    # `dueDateTime` arrives as ISO in REST v1; preserve as-is.
    # closed_at is null in Autotask (they don't surface a separate
    # close timestamp) — we set it locally only when our status maps
    # to a terminal state.

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        # Check whether we already have this ticket locally (by autotask_id).
        existing = conn.execute(
            "SELECT id, status, severity FROM tickets WHERE autotask_id = ?",
            (str(autotask_id),),
        ).fetchone()
        previous_status = existing["status"] if existing is not None else None
        severity = autotask_priority_to_severity(
            autotask_ticket.get("priority"), cache=priority_cache,
            previous=existing["severity"] if existing is not None else None,
        )
        status = autotask_status_to_athena(
            raw_status, cache=status_cache, previous=previous_status,
        )
        closed_at = None
        if status in ("closed", "resolved"):
            # Use lastActivityDate as a proxy for "when did this close"
            closed_at = autotask_ticket.get("lastActivityDate")
        if existing is None:
            cur = conn.execute(
                "INSERT INTO tickets "
                "(autotask_id, title, description, severity, status, "
                " closed_at, last_autotask_sync_at) "
                "VALUES (?, ?, ?, ?, ?, ?, "
                "        strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                (str(autotask_id), title, description, severity, status,
                 closed_at),
            )
            _status_history_row(conn, cur.lastrowid, None, status, history_reason)
            conn.commit()
            return "inserted"
        else:
            conn.execute(
                "UPDATE tickets "
                "   SET title = ?, description = ?, "
                "       severity = ?, status = ?, "
                "       closed_at = COALESCE(closed_at, ?), "
                "       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),"
                "       last_autotask_sync_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                " WHERE autotask_id = ?",
                (title, description, severity, status, closed_at,
                 str(autotask_id)),
            )
            if status != previous_status:
                _status_history_row(conn, existing["id"], previous_status, status,
                                    history_reason)
            conn.commit()
            return "updated"
    finally:
        conn.close()


def _status_history_row(
    conn: sqlite3.Connection, ticket_id: Optional[int], from_status: Optional[str],
    to_status: str, reason: str,
) -> None:
    """One `ticket_status_history` row for a status the poller mirrored. No
    operator: the change was made in Autotask (source 'autotask_sync')."""
    conn.execute(
        "INSERT INTO ticket_status_history "
        "(ticket_id, from_status, to_status, changed_by_operator_id, reason, source) "
        "VALUES (?, ?, ?, NULL, ?, 'autotask_sync')",
        (ticket_id, from_status, to_status, reason),
    )


def upsert_ticket_note(
    tenant_slug: str,
    autotask_note: dict[str, Any],
) -> str:
    """Upsert one Autotask TicketNote into the tenant's tickets.db.

    Resolves the parent ticket by autotask_id (= autotask_note.ticketID).
    If the parent isn't in our local DB yet (= we haven't polled it
    in this cycle), skip and return 'orphan' so the poller can retry
    next cycle when the ticket arrives.
    """
    _ensure_local_tickets_db_at_latest(tenant_slug)
    db = paths.client_dir(tenant_slug) / "tickets.db"

    autotask_note_id = autotask_note.get("id")
    autotask_ticket_id = autotask_note.get("ticketID")
    if autotask_note_id is None or autotask_ticket_id is None:
        return "skipped"

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        # Find the local ticket by autotask_id.
        parent = conn.execute(
            "SELECT id FROM tickets WHERE autotask_id = ?",
            (str(autotask_ticket_id),),
        ).fetchone()
        if parent is None:
            return "orphan"
        local_ticket_id = parent["id"]

        # Dedup by autotask_id on the note side too.
        existing = conn.execute(
            "SELECT id FROM ticket_notes WHERE autotask_id = ?",
            (str(autotask_note_id),),
        ).fetchone()
        body = (autotask_note.get("description") or "")[:32000]
        title = (autotask_note.get("title") or None)
        if title is not None:
            title = title[:250]
        if existing is None:
            conn.execute(
                "INSERT INTO ticket_notes "
                "(ticket_id, autotask_id, title, body, note_type, publish, "
                " author_operator_id, pushed_to_autotask_at) "
                "VALUES (?, ?, ?, ?, 'internal', 'internal', NULL, "
                "        strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                (local_ticket_id, str(autotask_note_id), title, body),
            )
            conn.commit()
            return "inserted"
        else:
            conn.execute(
                "UPDATE ticket_notes "
                "   SET title = ?, body = ?, "
                "       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),"
                "       last_activity_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                " WHERE autotask_id = ?",
                (title, body, str(autotask_note_id)),
            )
            conn.commit()
            return "updated"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Cursor timestamps
# ---------------------------------------------------------------------------

def parse_activity_ts(value: Any) -> Optional[datetime]:
    """An Autotask timestamp ('2026-05-14T10:00:00.123Z'; any fraction
    length; 'Z', an offset, or none — Autotask answers in UTC) → an aware UTC
    datetime. None when the value is not a timestamp."""
    if not isinstance(value, str) or "T" not in value:
        return None
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    date_part, _, time_part = text.partition("T")
    # Python takes at most 6 fraction digits; .NET answers can carry 7.
    if "." in time_part:
        head, _, rest = time_part.partition(".")
        digits = len(rest) - len(rest.lstrip("0123456789"))
        time_part = f"{head}.{rest[:min(digits, 6)]}{rest[digits:]}" if digits else head + rest
    try:
        dt = datetime.fromisoformat(f"{date_part}T{time_part}")
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_activity_ts(dt: datetime) -> str:
    """UTC, millisecond precision, 'Z' — the shape Autotask answers in."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _latest_activity(items: list[dict[str, Any]], floor: Optional[str]) -> Optional[str]:
    """The newest `lastActivityDate` among `items` (as Autotask wrote it), or
    `floor` when none is newer. Compared as instants, not as strings."""
    best, best_dt = floor, parse_activity_ts(floor)
    for raw in items:
        value = raw.get("lastActivityDate")
        dt = parse_activity_ts(value)
        if dt is not None and (best_dt is None or dt > best_dt):
            best, best_dt = value, dt
    return best


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

class AutotaskPoller:
    """Run loop: pull Tickets + TicketNotes deltas from Autotask, reconcile
    into per-tenant tickets.db. One persisted cursor per entity.
    """

    def __init__(
        self,
        *,
        client: AutotaskClient,
        adapter_instance_id: int,
        initial_ticket_cursor: Optional[str] = None,
        initial_note_cursor: Optional[str] = None,
        poll_interval_sec: float = DEFAULT_POLL_INTERVAL_SEC,
        max_batch: int = DEFAULT_MAX_BATCH,
        reporter: Optional[ContactReporter] = None,
        proposals_every_sec: float = PROPOSALS_EVERY_SEC,
        proposals_first_check_sec: float = PROPOSALS_FIRST_CHECK_SEC,
        proposals_due: Optional[Callable[[int, float], bool]] = None,
        proposals_refresh: Optional[Callable[[AutotaskClient, int], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
        max_pages: int = MAX_PAGES,
        max_windows_per_tick: int = MAX_WINDOWS_PER_TICK,
        initial_lookback_days: float = DEFAULT_INITIAL_LOOKBACK_DAYS,
        persist_cursors: Optional[bool] = None,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._client = client
        self._instance_id = adapter_instance_id
        # The daily location proposals (apps.octo.proposals.site_location):
        # mapped active companies' addresses only, never geocoded here. 0
        # turns it off. The first check waits for the other pollers' first
        # round (the Fleet's site names); after that, hourly checks of the
        # persisted last run — a restart never re-runs a fresh one.
        self._proposals_every = max(0.0, float(proposals_every_sec))
        self._proposals_due = proposals_due
        self._proposals_refresh = proposals_refresh
        self._clock = clock
        self._proposals_next = clock() + max(0.0, float(proposals_first_check_sec))
        self.last_proposals_summary: Optional[dict[str, Any]] = None
        # 0 is "no persisted instance" here (a poller built in a test): inert.
        self._reporter = reporter or ContactReporter(
            adapter_instance_id or None, what="autotask-poller",
        )
        self._poll_interval = poll_interval_sec
        self._max_batch = max_batch
        self._page_size = max(1, min(int(max_batch), MAX_RECORDS))
        self._max_pages = max(1, int(max_pages))
        self._max_windows = max(1, int(max_windows_per_tick))
        self._lookback = timedelta(days=max(0.0, float(initial_lookback_days)))
        self._now = now or (lambda: datetime.now(timezone.utc))
        # Cursors survive a restart (registry `adapter_poller_state`). 0 is
        # "no persisted instance" (a poller built in a test): nothing stored.
        self._persist = (bool(adapter_instance_id) and adapter_instance_id > 0
                         if persist_cursors is None else bool(persist_cursors))
        self._cursors: dict[str, Optional[str]] = {
            TICKET_CURSOR_KEY: initial_ticket_cursor,
            NOTE_CURSOR_KEY: initial_note_cursor,
        }
        # Newly mirrored tickets whose notes are still to be read by ticket
        # id: {autotask ticket id: tenant slug}, oldest first.
        self._note_backfill: dict[str, str] = {}
        self._note_backfill_dirty = False
        # The one-time re-read of mirrored rows after a static-map change.
        # Rows synced after this instant (wall clock, the shape of
        # `last_autotask_sync_at`) are already on the current maps.
        self._started_wall = format_activity_ts(datetime.now(timezone.utc))
        self._maps_state: dict[str, Any] = {}
        self._restore_cursors()
        # The window width that last fit under the cap, per entity, while a
        # catch-up is in progress (in memory only: a restart re-probes).
        self._widths: dict[str, timedelta] = {}
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        # Counters for surfacing in the integration-status UI later.
        self.last_cycle_tickets_inserted = 0
        self.last_cycle_tickets_updated = 0
        self.last_cycle_tickets_skipped = 0
        self.last_cycle_notes_inserted = 0
        self.last_cycle_notes_updated = 0
        self.last_cycle_notes_orphan = 0
        self.last_cycle_tickets_caught_up = False
        self.last_cycle_notes_caught_up = False
        self.last_cycle_windows = 0
        self.last_cycle_note_backfills = 0
        self.last_cycle_tickets_refreshed = 0

    @property
    def ticket_cursor(self) -> Optional[str]:
        return self._cursors[TICKET_CURSOR_KEY]

    @property
    def note_cursor(self) -> Optional[str]:
        return self._cursors[NOTE_CURSOR_KEY]

    # ----- cursor persistence -----

    def _restore_cursors(self) -> None:
        """A persisted cursor wins over the start config's (a static value
        would rewind every restart). One that is not a timestamp is ignored."""
        if not self._persist:
            return
        for key in (TICKET_CURSOR_KEY, NOTE_CURSOR_KEY):
            stored = poller_state.load(self._instance_id, key)
            if isinstance(stored, str) and parse_activity_ts(stored) is not None:
                self._cursors[key] = stored
            elif stored is not None:
                logger.warning("Autotask poller: stored %s is not a timestamp — ignored", key)
        pending = poller_state.load(self._instance_id, NOTE_BACKFILL_KEY)
        if isinstance(pending, list):
            for pair in pending:
                if (isinstance(pair, list) and len(pair) == 2
                        and isinstance(pair[0], str) and pair[0].isdigit()
                        and isinstance(pair[1], str) and pair[1]):
                    self._note_backfill[pair[0]] = pair[1]
        maps_state = poller_state.load(self._instance_id, STATIC_MAPS_STATE_KEY)
        if isinstance(maps_state, dict):
            self._maps_state = maps_state

    def _advance(self, key: str, value: Optional[str]) -> None:
        """Move a cursor and persist it (fail-soft: a registry hiccup leaves
        the in-memory cursor right and is retried at the next advance)."""
        if value is None or value == self._cursors[key]:
            return
        self._cursors[key] = value
        if self._persist and paths.registry_db_path().exists():
            poller_state.save(self._instance_id, key, value)

    # ----- catch-up -----

    def _read(self, entity: str, lo: str, hi: Optional[str], *,
              max_pages: Optional[int] = None) -> list[dict[str, Any]]:
        filt: list[dict[str, Any]] = [
            {"op": "gt", "field": "lastActivityDate", "value": lo}]
        if hi is not None:
            filt.append({"op": "lte", "field": "lastActivityDate", "value": hi})
        self.last_cycle_windows += 1
        return self._client.query_all(
            entity, {"filter": filt, "MaxRecords": self._page_size},
            max_pages=max_pages or self._max_pages,
        )

    def _catch_up(
        self, entity: str, key: str, handle: Callable[[dict[str, Any]], None],
        *, before_advance: Optional[Callable[[], None]] = None,
    ) -> bool:
        """Hand every `entity` row whose lastActivityDate is after the cursor
        to `handle`, oldest window first, advancing (and persisting) the
        cursor as each window completes. True when it reached the present;
        False when this tick's read budget ran out first (the next tick
        continues from the persisted cursor).

        A window longer than the page cap is never read in part: it is halved
        (by time) until it fits. After a window that fit, the next one starts
        at its end with the same width (doubled when it came back at most
        half full); the open window ("after the cursor", no end) is tried
        again once a window would reach the present. Every row read moves the
        cursor, whether `handle` could route it or not.

        Two positions: `pos`, how far this tick has READ (the next window
        starts there), and the cursor, from where it is SAFE to resume. A
        closed window that ended SETTLE_LAG or more before the local clock
        moves both to its end. One that ends closer to "now" moves only
        `pos`; the cursor moves to the newest lastActivityDate read (and, once
        such a window was read, stays on read rows for the rest of the tick),
        so neither a local clock ahead of Autotask's nor rows a bulk edit is
        still writing can put it past a row never read.

        `before_advance` runs before every cursor move (the note backfill
        queue is saved before the ticket cursor passes the tickets it
        names)."""
        start = self._cursors[key]
        if parse_activity_ts(start) is None:
            start = format_activity_ts(self._now() - self._lookback)
        pos = start                                 # read up to here
        safe = start                                # resumable from here
        settled = True

        def move_cursor(value: Optional[str]) -> None:
            if before_advance is not None:
                before_advance()
            self._advance(key, value)

        width: Optional[timedelta] = self._widths.get(key)  # None: try open
        cap_rows = self._page_size * self._max_pages
        reads = 0
        while reads < self._max_windows:
            reads += 1
            lo_dt = parse_activity_ts(pos)
            now = self._now()
            top = (lo_dt + width
                   if lo_dt is not None and width is not None and lo_dt + width < now
                   else None)                       # None: the open window
            span = (top if top is not None else now) - lo_dt if lo_dt is not None else None
            floor = span is None or span <= MIN_WINDOW
            hi = format_activity_ts(top) if top is not None else None
            try:
                items = self._read(entity, pos, hi,
                                   max_pages=FLOOR_MAX_PAGES if floor else None)
            except AutotaskPageCapError:
                if floor:
                    raise                           # a bulk edit beyond the floor: loud
                width = span / 2
                self._widths[key] = width
                continue
            for raw in items:
                handle(raw)
            if top is None:                         # the open window: caught up
                self._widths.pop(key, None)
                move_cursor(_latest_activity(items, safe))
                return True
            pos = hi                                # a closed window, read whole
            if settled and top <= now - SETTLE_LAG:
                safe = hi
            else:
                settled = False
                safe = _latest_activity(items, safe) or safe
            move_cursor(safe)
            if width is not None and len(items) * 2 <= cap_rows:
                width = width * 2
            self._widths[key] = width
        return False

    # ----- note backfill (newly mirrored tickets) -----

    def _queue_note_backfill(self, autotask_ticket_id: Any, tenant_slug: str) -> None:
        if isinstance(autotask_ticket_id, bool) or not isinstance(autotask_ticket_id, int):
            return
        self._note_backfill[str(autotask_ticket_id)] = tenant_slug
        while len(self._note_backfill) > MAX_PENDING_NOTE_BACKFILLS:
            dropped = next(iter(self._note_backfill))
            del self._note_backfill[dropped]
            logger.warning("Autotask poller: note backfill queue full — ticket %s's "
                           "older notes are not read", dropped)
        self._note_backfill_dirty = True

    def _save_note_backfill(self) -> None:
        """Persist the backfill queue (only when it changed). Fail-soft, as
        the cursors are."""
        if not self._note_backfill_dirty:
            return
        self._note_backfill_dirty = False
        if self._persist and paths.registry_db_path().exists():
            poller_state.save(self._instance_id, NOTE_BACKFILL_KEY,
                              [[k, v] for k, v in self._note_backfill.items()])

    def _drain_note_backfill(self) -> None:
        """Read the notes of up to MAX_NOTE_BACKFILLS_PER_TICK newly mirrored
        tickets by ticket id. A ticket leaves the queue once its notes were
        read; a transport failure keeps it (and the rest) for the next tick;
        an auth failure fails the tick as any other read does."""
        done = 0
        try:
            for ticket_id, slug in list(self._note_backfill.items()):
                if done >= MAX_NOTE_BACKFILLS_PER_TICK:
                    break
                try:
                    notes = self._client.query_all("TicketNotes", {
                        "filter": [{"op": "eq", "field": "ticketID", "value": int(ticket_id)}],
                        "MaxRecords": self._page_size,
                    }, max_pages=FLOOR_MAX_PAGES)
                except AutotaskAuthError:
                    raise
                except AutotaskPageCapError:
                    logger.warning("Autotask poller: ticket %s has more notes than a "
                                   "backfill reads — its older notes are not mirrored",
                                   ticket_id)
                    notes = []
                except AutotaskClientError as exc:
                    logger.warning("Autotask poller: note backfill not read (%s) — "
                                   "retried next tick", type(exc).__name__)
                    break
                for raw in notes:
                    outcome = upsert_ticket_note(slug, raw)
                    if outcome == "inserted":
                        self.last_cycle_notes_inserted += 1
                    elif outcome == "updated":
                        self.last_cycle_notes_updated += 1
                del self._note_backfill[ticket_id]
                self._note_backfill_dirty = True
                self.last_cycle_note_backfills += 1
                done += 1
        finally:
            self._save_note_backfill()

    # ----- one-time re-read after a static-map change -----

    def _save_maps_state(self) -> None:
        if self._persist and paths.registry_db_path().exists():
            poller_state.save(self._instance_id, STATIC_MAPS_STATE_KEY, self._maps_state)

    def _refresh_mirrored_rows(self, routing: dict[int, str]) -> None:
        """Re-read, by id, every mirrored ticket last synced before this
        poller started, once per STATIC_MAPS_VERSION: a ticket nobody touches
        in Autotask is otherwise never read again and keeps the priority /
        status the OLD maps gave it (an AW03 Critical shown as "low", an
        Escalated one as resolved). Bounded per tick; progress (per tenant,
        by local row id) survives a restart. A transport failure is retried
        next tick and never fails the poll."""
        state = self._maps_state
        if state.get("version") == STATIC_MAPS_VERSION and state.get("done") is True:
            return
        if not routing:
            # Nothing mapped (or the map unreadable this tick): nothing to
            # re-read now — never "done" on an empty answer.
            return
        if state.get("version") != STATIC_MAPS_VERSION or not isinstance(state.get("after"), dict):
            state = {"version": STATIC_MAPS_VERSION, "since": self._started_wall,
                     "done": False, "after": {}}
            self._maps_state = state
            self._save_maps_state()
        since = str(state.get("since") or self._started_wall)
        batches = 0
        for slug in sorted(set(routing.values())):
            after = state["after"].get(slug, 0)
            after = after if isinstance(after, int) else 0
            while True:
                rows = _mirrored_rows_synced_before(slug, after, since, REFRESH_BATCH)
                if not rows:
                    break
                if batches >= MAX_REFRESH_BATCHES_PER_TICK:
                    return                          # the rest next tick
                ids = [int(a) for _, a in rows if str(a).isdigit()]
                if ids:
                    batches += 1
                    try:
                        found = self._client.query_all("Tickets", {
                            "filter": [{"op": "in", "field": "id", "value": ids}],
                            "MaxRecords": MAX_RECORDS,
                        }, max_pages=2)
                    except AutotaskAuthError:
                        raise
                    except AutotaskClientError as exc:
                        logger.warning("Autotask poller: mirrored rows not re-read (%s) "
                                       "— retried next tick", type(exc).__name__)
                        return
                    for raw in found:
                        if upsert_ticket(slug, raw) == "updated":
                            self.last_cycle_tickets_refreshed += 1
                after = rows[-1][0]
                state["after"][slug] = after
                self._save_maps_state()
        state["done"] = True
        self._save_maps_state()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        try:
            await asyncio.wait_for(self._task, timeout=self._poll_interval + 5.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self.tick_once)
            except AutotaskAuthError as e:
                logger.error("Autotask poller auth failure (will retry): %s", e)
                await self._report_failure("auth")
            except AutotaskClientError as e:
                logger.error("Autotask poller client error (will retry): %s", e)
                await self._report_failure("transport")
            except Exception as e:  # noqa: BLE001
                logger.exception("Autotask poller crashed in tick_once")
                await self._report_failure("internal", e)
            else:
                await asyncio.to_thread(self._reporter.ok)
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._poll_interval,
                )
            except asyncio.TimeoutError:
                pass

    async def _report_failure(
        self, kind: FailureKind, exc: Optional[BaseException] = None,
    ) -> None:
        # The client's error text can quote Autotask's response body: the
        # row gets a fixed sentence (the log above keeps the detail).
        await asyncio.to_thread(
            self._reporter.failed, kind, poll_failure_detail("Autotask", kind, exc),
        )

    def tick_once(self) -> None:
        """One synchronous polling cycle: catch the tickets up, then (only
        once they have reached the present) the notes, reconciling into the
        tenants' tickets.db. Runnable from a test without an event loop."""
        routing = load_tenant_routing(self._instance_id)
        # Reset per-cycle counters
        self.last_cycle_tickets_inserted = 0
        self.last_cycle_tickets_updated = 0
        self.last_cycle_tickets_skipped = 0
        self.last_cycle_notes_inserted = 0
        self.last_cycle_notes_updated = 0
        self.last_cycle_notes_orphan = 0
        self.last_cycle_tickets_caught_up = False
        self.last_cycle_notes_caught_up = False
        self.last_cycle_windows = 0
        self.last_cycle_note_backfills = 0
        self.last_cycle_tickets_refreshed = 0
        # Notes already read once: a newly mirrored ticket may have had some
        # of them read as orphans (it did not exist here yet), and the note
        # cursor has moved past those — read its notes by ticket id. Before
        # the first notes read there is nothing to recover: that read starts
        # at the lookback and finds them.
        backfill_notes = self._cursors[NOTE_CURSOR_KEY] is not None

        # ----- Tickets -----
        # The cursor tracks "where am I in the upstream stream", not "what
        # have I ingested": an unmapped company's ticket moves it too (and
        # counts as skipped for the operator to investigate).
        def ticket(raw: dict[str, Any]) -> None:
            company_id = raw.get("companyID")
            tenant_slug = routing.get(company_id) if isinstance(company_id, int) else None
            if tenant_slug is None:
                self.last_cycle_tickets_skipped += 1
                return
            outcome = upsert_ticket(tenant_slug, raw)
            if outcome == "inserted":
                self.last_cycle_tickets_inserted += 1
                if backfill_notes:
                    self._queue_note_backfill(raw.get("id"), tenant_slug)
            elif outcome == "updated":
                self.last_cycle_tickets_updated += 1

        self.last_cycle_tickets_caught_up = self._catch_up(
            "Tickets", TICKET_CURSOR_KEY, ticket,
            before_advance=self._save_note_backfill)

        # ----- TicketNotes -----
        # Notes need ticket-id → company-id resolution to route. We
        # don't have that lookup table fast here — but every note
        # whose ticket already landed in any tenant's tickets.db (=
        # we polled the parent earlier or this cycle) is fan-out-able
        # by walking all in-scope tenants and trying the upsert. The
        # upsert returns 'orphan' when the parent isn't local, so
        # cheap dedup handles the rest. A note whose parent is not
        # local (unmapped company, or a ticket never mirrored) is
        # counted as an orphan and the cursor moves past it all the
        # same — it used to stop the cursor, so a batch of them stalled
        # every later note.
        def note(raw: dict[str, Any]) -> None:
            ticket_id = raw.get("ticketID")
            if not isinstance(ticket_id, int) or isinstance(ticket_id, bool):
                self.last_cycle_notes_orphan += 1
                return
            tenant_slug = _find_tenant_for_autotask_ticket(
                str(ticket_id), routing.values(),
            )
            if tenant_slug is None:
                self.last_cycle_notes_orphan += 1
                return
            outcome = upsert_ticket_note(tenant_slug, raw)
            if outcome == "inserted":
                self.last_cycle_notes_inserted += 1
            elif outcome == "updated":
                self.last_cycle_notes_updated += 1
            elif outcome == "orphan":
                self.last_cycle_notes_orphan += 1

        # While the tickets are still catching up, a note's parent may not
        # have landed yet: the notes wait for the tickets.
        if self.last_cycle_tickets_caught_up:
            self.last_cycle_notes_caught_up = self._catch_up(
                "TicketNotes", NOTE_CURSOR_KEY, note)

        # ----- Notes of newly mirrored tickets (read once by ticket id) -----
        if self._note_backfill:
            self._drain_note_backfill()

        # ----- Mirrored rows still on the old static maps (once) -----
        if self.last_cycle_tickets_caught_up:
            self._refresh_mirrored_rows(routing)

        self.maybe_refresh_location_proposals()

    def maybe_refresh_location_proposals(self) -> bool:
        """The daily Autotask → site-location proposals (a few Companies /
        CompanyLocations reads; no geocoding). Checked at most hourly; runs
        when the persisted last run is a day old. Never breaks the ticket
        poll: a failure is logged (its class only) and retried at the next
        check. True when a refresh ran."""
        if self._proposals_every <= 0 or not self._instance_id:
            return False
        now = self._clock()
        if now < self._proposals_next:
            return False
        self._proposals_next = now + min(PROPOSALS_RECHECK_SEC, self._proposals_every)
        from apps.octo.proposals import site_location

        due = self._proposals_due or site_location.due
        run = self._proposals_refresh or site_location.refresh_scheduled
        try:
            if not due(self._instance_id, self._proposals_every):
                return False
            self.last_proposals_summary = run(self._client, self._instance_id)
        except Exception as exc:  # noqa: BLE001 — proposals never stop the ticket poll
            logger.warning("Autotask location proposals not refreshed (%s)",
                           type(exc).__name__)
            return False
        return True


def _mirrored_rows_synced_before(
    tenant_slug: str, after_id: int, since: str, limit: int,
) -> list[tuple[int, str]]:
    """`(local id, autotask_id)` of the tenant's mirrored tickets with a local
    id above `after_id` whose last sync is older than `since` (or unknown),
    oldest id first. Empty when the tenant has no tickets.db yet."""
    db = paths.client_dir(tenant_slug) / "tickets.db"
    if not db.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT id, autotask_id FROM tickets "
                " WHERE autotask_id IS NOT NULL AND id > ? "
                "   AND (last_autotask_sync_at IS NULL OR last_autotask_sync_at < ?) "
                " ORDER BY id ASC LIMIT ?",
                (int(after_id), since, int(limit)),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return []
    return [(int(r[0]), str(r[1])) for r in rows]


def _find_tenant_for_autotask_ticket(
    autotask_ticket_id: str,
    tenant_slugs,
) -> Optional[str]:
    """Walk in-scope tenants looking for a local ticket whose
    autotask_id matches. Cheap because per-tenant tickets.db has an
    indexed lookup on autotask_id."""
    for slug in tenant_slugs:
        db = paths.client_dir(slug) / "tickets.db"
        if not db.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                row = conn.execute(
                    "SELECT 1 FROM tickets WHERE autotask_id = ?",
                    (autotask_ticket_id,),
                ).fetchone()
            finally:
                conn.close()
            if row is not None:
                return slug
        except sqlite3.OperationalError:
            continue
    return None
