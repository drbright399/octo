"""IngestSink — adapter output → per-client storage + live event stream.

The shape every adapter writes into. Decouples extraction (adapter
concern) from persistence + fanout (framework concern).

Per-client storage lives in `<data_root>/clients/<slug>/events.db` +
`indicators.db`, schemas defined in migration 002 — and, since migration 036,
`telemetry.db`: every event is classified at ingest
(`apps.octo.ingest.tiering`) and TELEMETRY (answered DNS, TLS / HTTP / flow
metadata) goes to the telemetry store instead of events.db. Signals — every
alert, and anything the classifier does not positively recognise — keep
the events.db path unchanged.

Every stored row — signal or telemetry — is stamped with its ARRIVAL time
(`events.ingested_at` / `telemetry_raw.ingested_at`, the sink's clock), which
is what retention ages it by (owner decision 2026-09-29,
`apps.octo.ingest.arrival`); `received_at` stays the vendor's time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional, Protocol

from shared_adapter_contract.types import CanonicalEvent

from apps.octo import paths
from apps.octo.ingest import arrival
from apps.octo.ingest import telemetry as telemetry_store
from apps.octo.ingest import tiering
from apps.octo.ingest.presentation import clean_text
from apps.octo.ingest.timestamps import utcnow_iso

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestOutcome:
    """What one `ingest()` call did. `event_id` is the stored row's id — the
    EXISTING row's id when `duplicate` is true (nothing was written). Which
    store it is in: `tier` 'signal' → events.db, 'telemetry' → telemetry.db
    (`telemetry_raw.id`). `fallback` = a telemetry event that was stored in
    events.db because the telemetry store refused the write."""

    event_id: int
    duplicate: bool = False
    tier: str = tiering.SIGNAL
    fallback: bool = False


# Telemetry-store failures that fell back to events.db — RECENT ones, per
# tenant: counts per UTC hour for the last `FAULT_WINDOW_HOURS` (+1) hours,
# and the last error class + when. Memory only. A process-lifetime counter
# kept warning for weeks after a fault had cleared; what the console shows
# is what happened in the last day (the nightly sweep moves such rows into
# telemetry.db, and the DNS summary + Settings → System report the count).
FAULT_WINDOW_HOURS = 24
_fallbacks: dict[str, dict[str, int]] = {}          # slug → {'YYYY-MM-DDTHH': n}
_fallback_last: dict[str, tuple[str, str]] = {}     # slug → (error class, at)
_fallback_lock = threading.Lock()
_fallback_logged_at: dict[str, float] = {}
_FALLBACK_LOG_EVERY_SEC = 300.0


def _window_start_hour(now_iso: str, window_hours: int) -> str:
    try:
        now = datetime.strptime(now_iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        now = datetime.now(timezone.utc)
    return (now - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H")


def telemetry_fallbacks(
    *, window_hours: int = FAULT_WINDOW_HOURS, now: Optional[str] = None,
) -> dict[str, dict[str, object]]:
    """{slug: {count, last_error, last_at, window_hours}} for every tenant with
    a refused telemetry write in the last `window_hours` (hour granularity:
    the current hour and the `window_hours` before it). `now`: canonical UTC
    ms (tests); default the clock."""
    start = _window_start_hour(now or utcnow_iso(), window_hours)
    out: dict[str, dict[str, object]] = {}
    with _fallback_lock:
        for slug, buckets in _fallbacks.items():
            n = sum(c for hour, c in buckets.items() if hour >= start)
            if n <= 0:
                continue
            err, at = _fallback_last.get(slug, ("", ""))
            out[slug] = {"count": n, "last_error": err, "last_at": at,
                         "window_hours": window_hours}
    return out


def reset_telemetry_fallbacks() -> None:
    with _fallback_lock:
        _fallbacks.clear()
        _fallback_last.clear()
        _fallback_logged_at.clear()


def _note_fallback(slug: str, exc: BaseException, at: Optional[str] = None) -> None:
    now = time.monotonic()
    at = at or utcnow_iso()
    oldest = _window_start_hour(at, FAULT_WINDOW_HOURS + 1)
    with _fallback_lock:
        buckets = _fallbacks.setdefault(slug, {})
        buckets[at[:13]] = buckets.get(at[:13], 0) + 1
        for hour in [h for h in buckets if h < oldest]:
            del buckets[hour]
        _fallback_last[slug] = (type(exc).__name__, at)
        last_log = _fallback_logged_at.get(slug)
        loud = last_log is None or now - last_log >= _FALLBACK_LOG_EVERY_SEC
        if loud:
            _fallback_logged_at[slug] = now
    if loud:
        logger.warning(
            "[ingest] telemetry store refused a write for tenant %r (%s); stored "
            "in events.db instead — the nightly retention sweep moves it later",
            slug, type(exc).__name__,
        )


# events.db files whose dedup lookup index this process has already ensured.
# New client DBs get the index from migration 002; this covers DBs provisioned
# before it was added there (it used to be created lazily by the ingest router).
_dedup_index_ensured: set[str] = set()
_dedup_index_lock = threading.Lock()

# events.db files known to have the `summary` column (migration 004). Every
# provisioned client DB has it; a DB built from migration 002 alone does not,
# and ingest must keep working there, so the column is probed once per file.
_summary_column_present: set[str] = set()

# The column is an operator-facing one-liner, not a second payload.
_MAX_STORED_SUMMARY = 500


class IngestSink(Protocol):
    """Where a canonical event lands after extraction.

    Implementations MUST be safe to call from multiple adapter threads
    concurrently — the SQLite default uses one connection per call
    (short-lived) to avoid threading complications.
    """

    def ingest(
        self,
        tenant_slug: str,
        source: str,
        event: CanonicalEvent,
        event_type: Optional[str] = None,
    ) -> Optional[IngestOutcome]: ...


class SqliteIngestSink:
    """Default sink — writes to per-client SQLite + publishes to SSE.

    Per-tenant isolation is at the file level (one DB per client per
    artifact). That's the OCTO per-DB multi-tenancy invariant (see
    docs/architecture.md § Data isolation).

    The publish-to-SSE step is best-effort: if the broker queue is full
    for a slow subscriber, the broker drops oldest. We do not block
    persistence on subscriber slowness.
    """

    def __init__(
        self,
        data_root: Path | None = None,
        *,
        publish_to_stream: bool = True,
        clock: Optional[Callable[[], str]] = None,
    ) -> None:
        """`clock` returns "now" in the canonical UTC ms format — the arrival
        stamp of every row written (tests inject one)."""
        self._data_root = (
            Path(data_root).resolve() if data_root is not None else paths.data_root()
        )
        self._publish_to_stream = publish_to_stream
        self._clock = clock or utcnow_iso

    def ingest(
        self,
        tenant_slug: str,
        source: str,
        event: CanonicalEvent,
        event_type: Optional[str] = None,
        *,
        dedup: bool = True,
    ) -> IngestOutcome:
        """Persist + fanout. Raises on persistence failure (caller decides
        retry semantics); SSE publish failures are swallowed by the broker.

        ``event_type``: a caller-declared type wins (the ingest router passes
        e.g. ``wazuh.alert``, ``suricata.dns``); otherwise the event's own
        (``TypedCanonicalEvent.event_type``, e.g. ``datto.eventlog``);
        otherwise "alert", the historical hardcode.

        Idempotency lives HERE because every writer (pollers, webhooks, the
        ingest router) passes through: an event whose
        ``(source, payload_sha256, received_at)`` is already stored is not
        written, counted or published again — the outcome carries the existing
        row id with ``duplicate=True``. It is a lookup guard, not a UNIQUE
        index: ``received_at`` is the VENDOR's timestamp, so a legitimately
        identical payload at a different time still stores. ``dedup=False`` is
        for receive-time-stamped telemetry that may genuinely repeat.

        Tiering (migration 036): an event `tiering.classify` files as
        TELEMETRY goes to the tenant's telemetry.db under the same identity
        rules (outcome ``tier='telemetry'``, ``event_id`` = its
        telemetry_raw id); it is not published on the alerts stream and
        records no indicator. If that store refuses the write, the event is
        stored in events.db as before (``fallback=True``).
        """
        declared = event_type or getattr(event, "event_type", "") or "alert"
        fell_back = False
        if tiering.classify(declared, event.payload, event.severity).is_telemetry:
            stored = self._write_telemetry(
                tenant_slug, source, event, declared, dedup=dedup,
            )
            if stored is not None:
                return stored
            fell_back = True
        outcome = self._write_event(
            tenant_slug, source, event, declared, dedup=dedup,
        )
        if fell_back:
            outcome = replace(outcome, fallback=True)
        if outcome.duplicate:
            return outcome
        if event.indicator and event.indicator_type:
            self._upsert_indicator(tenant_slug, source, event)
        if self._publish_to_stream:
            self._publish(tenant_slug, source, event)
        return outcome

    # ----- private -----

    def _write_telemetry(
        self, tenant_slug: str, source: str, event: CanonicalEvent,
        event_type: str, *, dedup: bool,
    ) -> Optional[IngestOutcome]:
        """Raw row + roll-up + first-seen in one telemetry.db transaction.
        None = the store refused (locked past its timeout, damaged, full…):
        the caller stores the event in events.db instead, so the request
        never fails for the telemetry store's sake. An unprovisioned tenant
        raises FileNotFoundError exactly as the events path does."""
        if not self._events_db_path(tenant_slug).exists():
            raise FileNotFoundError(
                f"events.db missing for tenant {tenant_slug!r}; "
                "client must be provisioned via lifecycle before ingest"
            )
        vendor_ts = event.received_at or ""
        arrived = self._clock()
        domain, device = tiering.extract_dimensions(event_type, event.payload)
        row = telemetry_store.row_for_ingest(
            source=source, event_type=event_type, severity=event.severity,
            source_host=event.source_host,
            received_at=vendor_ts or arrived, payload=event.payload,
            payload_sha256=event.payload_sha256, domain=domain, device=device,
            ingested_at=arrived,
            device_name=tiering.extract_device_name(event_type, event.payload),
        )
        try:
            [written] = telemetry_store.TelemetryStore(self._data_root).write(
                tenant_slug, [row], dedup=dedup, identity_includes_time=bool(vendor_ts),
            )
        except (sqlite3.Error, OSError) as exc:
            _note_fallback(tenant_slug, exc, arrived)
            return None
        return IngestOutcome(
            event_id=written.telemetry_id, duplicate=written.duplicate,
            tier=tiering.TELEMETRY,
        )

    def _client_db_path(self, tenant_slug: str, name: str) -> Path:
        """`clients/<slug>/<name>.db` under this sink's data root, through
        the path layer's containment check (`paths.resolve_inside`, spec
        §2.3) — this sink is every writer's door, so it does not lean on
        each caller having checked the slug. A name that cannot be a tenant
        slug is a tenant that was never provisioned: FileNotFoundError, the
        same answer (and HTTP mapping) as a missing events.db."""
        try:
            paths.validate_slug(tenant_slug)
        except paths.SlugError:
            raise FileNotFoundError(
                f"no provisioned tenant {tenant_slug!r}; "
                "client must be provisioned via lifecycle before ingest"
            ) from None
        return paths.client_db_path(tenant_slug, name, root=self._data_root)

    def _events_db_path(self, tenant_slug: str) -> Path:
        return self._client_db_path(tenant_slug, "events")

    def _indicators_db_path(self, tenant_slug: str) -> Path:
        return self._client_db_path(tenant_slug, "indicators")

    @contextmanager
    def _connect(self, db_path: Path) -> Iterator[sqlite3.Connection]:
        # 10 s busy timeout: the dedup guard takes the write lock up front, so
        # concurrent writers queue here instead of failing fast.
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL so ingest writes don't block the triage worker's reads (and
        # vice versa). Persistent in the file header — set here on the
        # ingest side too so it holds even when the worker isn't running.
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_dedup_index(self, db_path: Path) -> None:
        key = str(db_path)
        if key in _dedup_index_ensured:
            return
        with _dedup_index_lock:
            if key in _dedup_index_ensured:
                return
            with self._connect(db_path) as conn:
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_events_payload_sha256 "
                    "ON events(payload_sha256)"
                )
            _dedup_index_ensured.add(key)

    def _write_event(
        self, tenant_slug: str, source: str, event: CanonicalEvent,
        event_type: str = "alert", *, dedup: bool = True,
    ) -> IngestOutcome:
        db_path = self._events_db_path(tenant_slug)
        if not db_path.exists():
            raise FileNotFoundError(
                f"events.db missing for tenant {tenant_slug!r}; "
                "client must be provisioned via lifecycle before ingest"
            )
        payload_json = json.dumps(event.payload, separators=(",", ":"))
        # An event may arrive with NO usable vendor timestamp (received_at "":
        # field missing, unparseable, or an unsubstituted "$Timestamp"). It is
        # stamped with receive-time HERE — and then receive-time must NOT be
        # part of its identity, or every re-poll / vendor retry of the same
        # alert stores again (~2,880 rows/day per such alert at a 30 s poll).
        # With no vendor timestamp the payload itself is the identity.
        vendor_ts = event.received_at or ""
        # The arrival stamp — what retention ages the row by (036).
        arrived = self._clock()
        stored_ts = vendor_ts or arrived
        if dedup:
            self._ensure_dedup_index(db_path)
        with self._connect(db_path) as conn:
            # `events.ingested_at` on an events.db provisioned before 036: a
            # schema-only ALTER (instant whatever the table's size), probed
            # on every write (one PRAGMA on a connection that parsed the
            # schema anyway). The index is NOT built here — `arrival`.
            arrival.add_column(conn)
            if dedup:
                # Take the write lock BEFORE the lookup so two concurrent
                # deliveries of one alert (webhook + poll, or a vendor retry)
                # can't both miss and both insert.
                conn.execute("BEGIN IMMEDIATE")
                if vendor_ts:
                    row = conn.execute(
                        """
                        SELECT id FROM events
                         WHERE payload_sha256 = ? AND source = ? AND received_at = ?
                         ORDER BY id DESC LIMIT 1
                        """,
                        (event.payload_sha256, source, vendor_ts),
                    ).fetchone()
                else:
                    row = conn.execute(
                        """
                        SELECT id FROM events
                         WHERE payload_sha256 = ? AND source = ?
                         ORDER BY id DESC LIMIT 1
                        """,
                        (event.payload_sha256, source),
                    ).fetchone()
                if row is not None:
                    return IngestOutcome(event_id=row["id"], duplicate=True)
            values = [
                stored_ts, source, event.source_host, event_type,
                event.severity, payload_json, event.payload_sha256, arrived,
            ]
            columns = (
                "received_at, source, source_host, event_type, "
                "severity, payload, payload_sha256, ingested_at"
            )
            # The adapter's human summary was computed and then DROPPED here:
            # every adapter-written row had summary '' (a blank dashboard row,
            # nothing for search's text filter to match).
            if self._has_summary_column(conn, db_path):
                # Generic telemetry sets summary = its event_type: storing
                # that twice says nothing. What IS stored is vendor-derived
                # text from ANY adapter, and it reaches feeds, exports and
                # the triage model as-is from here — so it gets the same
                # hygiene a presenter's output does (control / format
                # characters gone, bounded) before it is written.
                summary = event.summary or ""
                columns += ", summary"
                values.append(
                    "" if summary == event_type
                    else clean_text(summary, _MAX_STORED_SUMMARY)
                )
            cur = conn.execute(
                f"INSERT INTO events ({columns}) "
                f"VALUES ({', '.join('?' * len(values))})",
                values,
            )
            return IngestOutcome(event_id=int(cur.lastrowid), duplicate=False)

    @staticmethod
    def _has_summary_column(conn: sqlite3.Connection, db_path: Path) -> bool:
        key = str(db_path)
        if key in _summary_column_present:
            return True
        present = any(
            row[1] == "summary" for row in conn.execute("PRAGMA table_info(events)")
        )
        if present:
            _summary_column_present.add(key)
        return present

    def _upsert_indicator(
        self, tenant_slug: str, source: str, event: CanonicalEvent,
    ) -> None:
        """Increment hit count for existing indicator OR insert new row.

        Severity here is the EVENT severity, not the indicator's own
        reputation. Indicator severity is updated only on UPSERT; otherwise
        existing severity is preserved (operators / Layer 1 / Deep L2 may
        have annotated it).
        """
        db_path = self._indicators_db_path(tenant_slug)
        if not db_path.exists():
            # Indicators DB optional for ingest — log + continue, not fatal
            return
        # Map CanonicalEvent indicator_type ('ip' | 'ipv6' | 'domain' | ...)
        # to the indicators.db CHECK list. ipv6 is allowed but our adapter
        # currently only sets 'ip'; future-proof the mapping.
        indicator_type = event.indicator_type or "other"
        # Map any 'asn' or other non-CHECK-list type to 'other'
        allowed = {"ip", "ipv6", "domain", "url", "md5", "sha1", "sha256",
                    "email", "cidr", "cve", "other"}
        if indicator_type not in allowed:
            indicator_type = "other"
        # Indicator severity must be one of the indicator CHECK values
        # (no 'info' in the indicator table). Map 'info' → 'low'.
        ind_sev = event.severity if event.severity != "info" else "low"

        with self._connect(db_path) as conn:
            existing = conn.execute(
                "SELECT id, hits FROM indicators "
                "WHERE value = ? AND type = ? AND deleted_at IS NULL",
                (event.indicator, indicator_type),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE indicators SET hits = hits + 1, "
                    "last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
                    "WHERE id = ?",
                    (existing["id"],),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO indicators (
                        value, type, source, severity, confidence, context
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.indicator,
                        indicator_type,
                        source,
                        ind_sev,
                        0.5,  # default confidence; Layer 1 may tune later
                        event.summary,
                    ),
                )

    def _publish(
        self, tenant_slug: str, source: str, event: CanonicalEvent,
    ) -> None:
        """Best-effort SSE fanout. Schedule on the running event loop if
        any; otherwise no-op (test environments without a loop)."""
        from apps.octo.api import event_stream

        payload = {
            "tenant": tenant_slug,
            "source": source,
            "vendor_event_id": event.vendor_event_id,
            "received_at": event.received_at or utcnow_iso(),
            "severity": event.severity,
            "summary": event.summary,
            "source_host": event.source_host,
            "indicator": event.indicator,
            "indicator_type": event.indicator_type,
        }
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — skip the SSE publish silently. Persistence
            # already succeeded above. SSE is a presentation-layer concern.
            return
        loop.create_task(event_stream.publish("alerts", payload))
        loop.create_task(event_stream.publish(f"alerts.{tenant_slug}", payload))
