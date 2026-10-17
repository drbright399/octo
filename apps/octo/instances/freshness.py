"""Receive-clock freshness — when Athena last RECEIVED an event from a
source, on Athena's own clock (never the vendor's timestamp on the event).

Recorded where new events come in:

  * `tenant_autocreate.deliver`            Datto poll + every vendor webhook
  * `tenant_map.MappingIngestSink.ingest`  Wazuh / RocketCyber / UniFi pollers
  * the ingest router                      shim + buoy-forwarder posts (tenant,
                                           and the posting token's last
                                           ACCEPTED post — `record_token_post`)

Three clocks are kept:

  * per adapter instance: in memory, and `adapter_instances.last_event_at` in
    the registry — written at most once per `WRITE_INTERVAL_SEC` per instance,
    counted from the last WRITE (not the last event), so a 500-alert batch
    writes once and a steady stream writes once per interval instead of
    freezing. The persisted value can trail the newest event by up to one
    interval; readers in this process use the in-memory value.
  * per tenant: in memory only — the registry has no column for it and this
    release adds no migration. After a restart, `tenant_last_event` falls back
    to the tenant's newest stored event (one index read of its events.db),
    which is the vendor's timestamp for adapter events: never later than
    receipt, so the fallback can only make a feed look OLDER than it is.
  * per ingest token: when a post by that token was last ACCEPTED (stored,
    or an idempotent replay of a stored event), and when it last made an
    authenticated ingest request at all — in memory only. A token's
    `last_used_at` is set on every authenticated request, before the body is
    validated, so it cannot tell a working shim from one whose every post is
    refused; the pair here can. After a restart, readers fall back to the
    newest stored event carrying the token's source label
    (`newest_stored_event`) that no post in THIS process stored: the lowest
    events id an accepted post stored here is kept per tenant
    (`first_posted_event_id`), and every such post is already in memory by
    token id — so a newer event under the label is another token's (two
    live tokens may share a label: a rotation overlap). An id, not a time:
    an alert's stored time is the vendor's, and can predate this process.

Telemetry (migration 036) counts like any event: a buoy's answered-DNS
posts land in the tenant's telemetry.db, not its events.db, and are just as
much "Athena heard from this source". The stored-event fallbacks therefore
read BOTH stores (newest of the two), and a post's stored row is tracked per
store (`first_posted_event_id` / `first_posted_telemetry_id` — the two id
spaces are independent).

Only NEW events count for an instance or a tenant. A duplicate (an open alert re-listed every poll, a
vendor retry, a shim replay) is not news. An event held in quarantine counts
for its instance (it was received) but for no tenant.

Never raises into the ingest path, and the registry write waits at most
`_WRITE_TIMEOUT_SEC` for a busy registry: a skipped write is retried at the
next interval, and the in-memory value is current regardless.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.ingest.timestamps import format_utc_ms, normalize_timestamp, utcnow_iso

logger = logging.getLogger(__name__)

WRITE_INTERVAL_SEC = 30.0
_WRITE_TIMEOUT_SEC = 1.0
# A stored vendor timestamp further ahead of our clock than this is not taken
# as "the newest event" (one bad vendor clock would keep a tenant fresh for
# years) — the same allowance the Datto poller gives its cursor.
_FUTURE_SLACK_SEC = 300

_lock = threading.Lock()
_instance_last: dict[int, str] = {}
# time.monotonic() of each instance's last registry write (or claimed write).
_instance_written: dict[int, float] = {}
_tenant_last: dict[str, str] = {}
_token_last: dict[int, str] = {}
_token_request: dict[int, str] = {}
# Per token: requests since its last ACCEPTED post in this process — the
# refusals in a row (each request is counted when it arrives, and the count
# goes back to 0 when one is accepted).
_token_requests_since_post: dict[int, int] = {}
# Per tenant: the lowest events.id a post accepted in this process stored.
_first_posted_id: dict[str, int] = {}
# Per tenant: the same for telemetry_raw.id (telemetry.db, migration 036).
_first_posted_telemetry_id: dict[str, int] = {}


def reset() -> None:
    """Forget everything (tests; process-local state, like vendor_contact)."""
    with _lock:
        _instance_last.clear()
        _instance_written.clear()
        _tenant_last.clear()
        _token_last.clear()
        _token_request.clear()
        _token_requests_since_post.clear()
        _first_posted_id.clear()
        _first_posted_telemetry_id.clear()


def record_event(*, instance_id: Optional[int] = None, slug: Optional[str] = None) -> None:
    """A NEW event arrived — from adapter instance `instance_id` (None for the
    ingest router) into tenant `slug` (None when it was held in quarantine).
    Never raises."""
    try:
        _record(instance_id, slug)
    except Exception as exc:  # noqa: BLE001 — freshness must never fail ingest
        logger.warning(
            "[freshness] could not record an event for instance=%s (%s)",
            instance_id, type(exc).__name__,
        )


def _record(instance_id: Optional[int], slug: Optional[str]) -> None:
    now_iso = utcnow_iso()
    due = False
    with _lock:
        if slug:
            if now_iso > _tenant_last.get(slug, ""):
                _tenant_last[slug] = now_iso
        if instance_id is not None:
            if now_iso > _instance_last.get(instance_id, ""):
                _instance_last[instance_id] = now_iso
            mono = time.monotonic()
            written = _instance_written.get(instance_id)
            if written is None or mono - written >= WRITE_INTERVAL_SEC:
                # Claimed before the write: a concurrent event in the same
                # window must not write too.
                _instance_written[instance_id] = mono
                due = True
    if due:
        _write_instance_last_event(instance_id, now_iso)


def record_token_request(token_id: int) -> None:
    """Ingest token `token_id` made an authenticated ingest request — its
    body not yet validated, so it may still be refused. Never raises."""
    _stamp_token(_token_request, token_id, "request")
    try:
        with _lock:
            _token_requests_since_post[token_id] = _token_requests_since_post.get(token_id, 0) + 1
    except Exception as exc:  # noqa: BLE001 — freshness must never fail ingest
        logger.warning(
            "[freshness] could not count a request for token id=%s (%s)",
            token_id, type(exc).__name__,
        )


def record_token_post(
    token_id: int, *, slug: Optional[str] = None, stored_event_id: Optional[int] = None,
    stored_telemetry_id: Optional[int] = None,
) -> None:
    """A post by ingest token `token_id` was ACCEPTED — stored, or recognised
    as a replay of a stored event (the sender is working either way). Call
    only after the store succeeded; pass the NEW row's `slug` and its id —
    `stored_event_id` for an events.db row, `stored_telemetry_id` for a
    telemetry.db row (not a replay's: that row is older). Never raises."""
    _stamp_token(_token_last, token_id, "post")
    try:
        with _lock:
            _token_requests_since_post[token_id] = 0
    except Exception:  # noqa: BLE001 — freshness must never fail ingest
        pass
    if slug is None:
        return
    try:
        with _lock:
            for store, row_id in ((_first_posted_id, stored_event_id),
                                  (_first_posted_telemetry_id, stored_telemetry_id)):
                if row_id is None:
                    continue
                known = store.get(slug)
                if known is None or row_id < known:
                    store[slug] = int(row_id)
    except Exception as exc:  # noqa: BLE001 — freshness must never fail ingest
        logger.warning(
            "[freshness] could not record a stored post for token id=%s (%s)",
            token_id, type(exc).__name__,
        )


def _stamp_token(clock: dict[int, str], token_id: int, what: str) -> None:
    try:
        now_iso = utcnow_iso()
        with _lock:
            if now_iso > clock.get(token_id, ""):
                clock[token_id] = now_iso
    except Exception as exc:  # noqa: BLE001 — freshness must never fail ingest
        logger.warning(
            "[freshness] could not record a %s for token id=%s (%s)",
            what, token_id, type(exc).__name__,
        )


def _write_instance_last_event(instance_id: int, at: str) -> None:
    path = paths.registry_db_path()
    try:
        conn = sqlite3.connect(
            f"file:{path}?mode=rw", uri=True, timeout=_WRITE_TIMEOUT_SEC,
        )
    except sqlite3.Error as exc:
        logger.warning(
            "[freshness] registry unavailable; instance id=%s last_event_at not "
            "written (%s)", instance_id, type(exc).__name__,
        )
        return
    try:
        # Never moves backwards (two writers racing across a window).
        conn.execute(
            "UPDATE adapter_instances SET last_event_at = ? "
            "WHERE id = ? AND (last_event_at IS NULL OR last_event_at < ?)",
            (at, instance_id, at),
        )
        conn.commit()
    except sqlite3.Error as exc:
        logger.warning(
            "[freshness] instance id=%s last_event_at not written (%s); retried "
            "at the next interval", instance_id, type(exc).__name__,
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def instance_last_event(instance_id: int, persisted: Optional[str]) -> Optional[str]:
    """The newest receive time for an instance: this process's memory or the
    row's `last_event_at` (pass it in), whichever is later."""
    with _lock:
        mem = _instance_last.get(instance_id)
    candidates = [v for v in (mem, persisted) if v]
    return max(candidates) if candidates else None


def tenant_last_event(slug: str) -> Optional[str]:
    """The newest event for a tenant: received in this process, else the
    newest stored one (see the module docstring). None when there is none."""
    with _lock:
        mem = _tenant_last.get(slug)
    if mem:
        return mem
    return newest_stored_event(slug)


def token_last_post(token_id: int) -> Optional[str]:
    """When a post by `token_id` was last accepted IN THIS PROCESS (None
    when none has been since start — see `newest_stored_event`)."""
    with _lock:
        return _token_last.get(token_id)


def token_last_request(token_id: int) -> Optional[str]:
    """When `token_id` last made an authenticated ingest request IN THIS
    PROCESS, accepted or not (None when none since start)."""
    with _lock:
        return _token_request.get(token_id)


def token_requests_since_post(token_id: int) -> int:
    """Requests token `token_id` made in this process since its last
    accepted post here (all of them when none was accepted) — once the
    latest is known to be refused, every one of them was."""
    with _lock:
        return _token_requests_since_post.get(token_id, 0)


def first_posted_event_id(slug: str) -> Optional[int]:
    """The lowest events.id in `slug` stored by an ingest post accepted IN
    THIS PROCESS (None when none since start). Every row from there on that
    a post stored is some token's in-memory post."""
    with _lock:
        return _first_posted_id.get(slug)


def first_posted_telemetry_id(slug: str) -> Optional[int]:
    """`first_posted_event_id` for the tenant's telemetry.db rows."""
    with _lock:
        return _first_posted_telemetry_id.get(slug)


def newest_stored_event(
    slug: str, *, source: Optional[str] = None, not_before: Optional[str] = None,
    before_id: Optional[int] = None, before_telemetry_id: Optional[int] = None,
) -> Optional[str]:
    """`received_at` of the tenant's newest stored event, signal OR telemetry
    (the later of events.db and telemetry.db) — only events whose `source` is
    `source`, none older than `not_before`, and none with an id of
    `before_id` (events.db) / `before_telemetry_id` (telemetry.db) or more,
    when given (the source filter is not indexed: `not_before` bounds the
    walk). A vendor timestamp further ahead of our clock than
    `_FUTURE_SLACK_SEC` is skipped. None when there is none or neither store
    can be read."""
    from apps.octo.ingest import telemetry as telemetry_store

    ceiling = format_utc_ms(
        datetime.now(timezone.utc) + timedelta(seconds=_FUTURE_SLACK_SEC)
    )
    found = [
        v for v in (
            _newest_in_events(slug, source=source, not_before=not_before,
                              before_id=before_id, ceiling=ceiling),
            telemetry_store.newest_received_at(
                slug, source=source, not_before=not_before,
                before_id=before_telemetry_id, ceiling=ceiling,
                timeout=_WRITE_TIMEOUT_SEC,
            ),
        ) if v
    ]
    normalized = [normalize_timestamp(v, naive_is_utc=True) for v in found]
    normalized = [v for v in normalized if v]
    return max(normalized) if normalized else None


def _newest_in_events(
    slug: str, *, source: Optional[str], not_before: Optional[str],
    before_id: Optional[int], ceiling: str,
) -> Optional[str]:
    try:
        db = paths.client_dir(slug) / "events.db"
    except ValueError:
        return None
    if not db.exists():
        return None
    sql = "SELECT received_at FROM events WHERE received_at <= ?"
    params: list[Any] = [ceiling]
    if before_id is not None:
        sql += " AND id < ?"
        params.append(int(before_id))
    if not_before:
        sql += " AND received_at >= ?"
        params.append(not_before)
    if source is not None:
        sql += " AND source = ?"
        params.append(source)
    else:
        # Athena's own incident records (`athena.incident`) are not data
        # arriving: a tenant whose feeds stopped never reads fresh because
        # an incident on it changed.
        sql += " AND source <> 'athena'"
    sql += " ORDER BY received_at DESC LIMIT 1"
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=_WRITE_TIMEOUT_SEC)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    return row[0]


def age_seconds(iso: Optional[str], *, now: Optional[datetime] = None) -> Optional[int]:
    """Whole seconds since `iso` (0 for a moment in the future); None when
    `iso` is empty or unparseable."""
    canonical = normalize_timestamp(iso, naive_is_utc=True) if iso else ""
    if not canonical:
        return None
    then = datetime.strptime(canonical, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return max(0, int((current - then).total_seconds()))
