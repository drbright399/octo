"""Webhook receipt bookkeeping — has a vendor's request ever REACHED us?

A vendor's own "test webhook" once answered 403 to the operator although the
request never arrived here: something in front of the ingest hostname (CDN bot
protection, a WAF rule, an access gate) stopped the vendor's cloud-originated
POST. The receivers in ``api/routers/webhooks.py`` never answer 403 (only
2xx/401/422/429, or a 5xx when storing fails), but nothing in the product said
"no webhook has ever reached me", so the 403 read as the product's fault. This module is how every
integration card can tell the two apart — for ANY webhook-capable adapter, not
one vendor:

  * never reached      → look at the edge, not at Athena
  * reached, rejected  → say why, by a coarse reason class
  * accepted           → say when

Two tiers, on purpose:

  PERSISTED  (`adapter_webhook_receipts`, migration 032): last accepted at,
             last rejected at + its reason class. This is what makes "never"
             TRUE across restarts — a deploy must not turn "received an hour
             ago" into "nothing has reached Athena".
  IN MEMORY  counts, and the rolling last-hour window per reason class. They
             reset on restart and are worded that way.

Rejected requests come from the open internet, so recording one never costs a
disk write: `record_*` only touches memory (and never raises — bookkeeping
must not block or fail a webhook response). A background flusher owned by the
app writes every dirty receipt in ONE transaction, then waits out
``FLUSH_INTERVAL_SEC`` before it will write again. A flood of bad requests is
therefore one small write per interval, and memory stays bounded (per-minute
buckets, a fixed set of reason classes, keys that only ever come from the
instances table or the static route table).

Nothing request-derived is stored: no body, header, address or token — only
timestamps, counters and a reason class from the closed set below.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional

from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import format_utc_ms

logger = logging.getLogger(__name__)

# bad_token      — shared token / signature missing or wrong
# replay_window  — signed timestamp malformed or outside the tolerance
# malformed      — verified, but the body is not a JSON object / is too large
#                  (and names no event id a doorbell fetch could use)
# unmapped       — (historic: rows persisted before v0.8 — a held webhook is
#                  now recorded as accepted and counted by the quarantine line)
# rate_limited   — answered 429 by the rate limiter before the route ran
# not_configured — the instance has no usable secret (or the vault is unreadable)
# store_failed   — verified, but storing the event failed here (5xx; vendor retries)
# unresolvable   — verified, the body was not JSON but named an event id, and
#                  that event could not be fetched from the vendor (202; DROPPED)
RejectReason = Literal[
    "bad_token", "replay_window", "malformed", "unmapped", "rate_limited",
    "not_configured", "store_failed", "unresolvable",
]
REJECT_REASONS: tuple[str, ...] = (
    "bad_token", "replay_window", "malformed", "unmapped", "rate_limited",
    "not_configured", "store_failed", "unresolvable",
)

# Vendors whose webhook body is an operator-written TEMPLATE the vendor fills
# in without JSON-escaping (Datto RMM: [alert_message]). For them a broken
# body has one fix — the ID-only template from the Setup guide — and the
# card says so. Other vendors send their own JSON; a broken body there is
# something else.
TEMPLATED_BODY_VENDORS: frozenset[str] = frozenset({"datto"})

RECENT_WINDOW_SEC = 3600
FLUSH_INTERVAL_SEC = 60.0

_BUCKET_SEC = 60
_WEBHOOK_PATH_PREFIX = "/api/v1/webhooks/"

# Indirection so tests can move time without sleeping.
_clock = time.time


def _iso(epoch: float) -> str:
    return format_utc_ms(datetime.fromtimestamp(epoch, timezone.utc))


@dataclass
class _Receipt:
    accepted: int = 0
    rejected: int = 0
    first_accepted_at: Optional[str] = None
    last_accepted_at: Optional[str] = None
    last_rejected_at: Optional[str] = None
    last_reject_reason: Optional[str] = None
    # minute index → reason → count. Bounded: old minutes are pruned on write.
    recent: dict[int, dict[str, int]] = field(default_factory=dict)
    dirty: bool = False


_lock = threading.Lock()
_instances: dict[int, _Receipt] = {}
# Rejections that happen BEFORE an instance is resolved (the rate limiter runs
# ahead of routing), keyed by the vendor slug in the path. v1 allows one active
# instance per vendor, so they fold into that instance's snapshot.
_vendors: dict[str, _Receipt] = {}
_counting_since: float = _clock()


# ---------------------------------------------------------------------------
# Recording — memory only, never raises
# ---------------------------------------------------------------------------

def _prune(entry: _Receipt, now: float) -> None:
    oldest = int((now - RECENT_WINDOW_SEC) // _BUCKET_SEC)
    for minute in [m for m in entry.recent if m < oldest]:
        del entry.recent[minute]


def _note_rejected(entry: _Receipt, reason: str, now: float) -> None:
    entry.rejected += 1
    entry.last_rejected_at = _iso(now)
    entry.last_reject_reason = reason
    bucket = entry.recent.setdefault(int(now // _BUCKET_SEC), {})
    bucket[reason] = bucket.get(reason, 0) + 1
    _prune(entry, now)
    entry.dirty = True


def record_accepted(instance_id: Optional[int]) -> None:
    """A verified webhook was ingested for this instance."""
    if instance_id is None:
        return
    try:
        now = _clock()
        with _lock:
            entry = _instances.setdefault(instance_id, _Receipt())
            entry.accepted += 1
            entry.last_accepted_at = _iso(now)
            if entry.first_accepted_at is None:
                entry.first_accepted_at = entry.last_accepted_at
            entry.dirty = True
        _wake_flusher()
    except Exception:  # noqa: BLE001 — bookkeeping never fails a webhook
        logger.debug("[webhook-receipt] record_accepted failed", exc_info=True)


def record_rejected(instance_id: Optional[int], reason: RejectReason) -> None:
    """A request reached this instance's webhook route and was not ingested.
    With no instance to attribute it to there is no card to show it on, so it
    is not kept (the receiver has already logged it)."""
    if instance_id is None or reason not in REJECT_REASONS:
        return
    try:
        now = _clock()
        with _lock:
            _note_rejected(_instances.setdefault(instance_id, _Receipt()), reason, now)
        _wake_flusher()
    except Exception:  # noqa: BLE001
        logger.debug("[webhook-receipt] record_rejected failed", exc_info=True)


def webhook_vendor_for_path(path: str) -> Optional[str]:
    """The vendor slug when `path` is exactly a vendor's inbound webhook URL,
    else None. Exact on purpose: sub-routes (a job-output relay posted to by
    endpoints, not by the vendor's cloud) say nothing about whether the
    VENDOR can reach the ingest hostname, and an arbitrary path segment must
    never become a dictionary key."""
    from apps.octo.instances.webhook_auth import WEBHOOK_SECRET_FIELDS

    if not path.startswith(_WEBHOOK_PATH_PREFIX):
        return None
    slug = path[len(_WEBHOOK_PATH_PREFIX):].rstrip("/")
    return slug if slug in WEBHOOK_SECRET_FIELDS else None


def record_rate_limited(path: str) -> None:
    """Called by the rate-limit middleware when it answers 429. The route has
    not run, so only the vendor slug in the path is known. No lookup of any
    kind happens here — a throttled flood must stay cheap."""
    try:
        slug = webhook_vendor_for_path(path)
        if slug is None:
            return
        now = _clock()
        with _lock:
            _note_rejected(_vendors.setdefault(slug, _Receipt()), "rate_limited", now)
        _wake_flusher()
    except Exception:  # noqa: BLE001
        logger.debug("[webhook-receipt] record_rate_limited failed", exc_info=True)


def reset(instance_id: Optional[int] = None, vendor_slug: Optional[str] = None) -> None:
    """Forget one instance's in-memory receipts (on disable — pass its vendor
    slug too, so path-level counts do not carry over to a replacement) or all
    of them (tests; also restarts the "counting since" clock). Persisted rows
    are history and are left alone."""
    global _counting_since
    with _lock:
        if instance_id is None and vendor_slug is None:
            _instances.clear()
            _vendors.clear()
            _counting_since = _clock()
            return
        if instance_id is not None:
            _instances.pop(instance_id, None)
        if vendor_slug is not None:
            _vendors.pop(vendor_slug, None)


# ---------------------------------------------------------------------------
# Persistence — throttled, off the request path
# ---------------------------------------------------------------------------

_UPSERT = """
INSERT INTO adapter_webhook_receipts (
    adapter_instance_id, first_accepted_at, last_accepted_at,
    last_rejected_at, last_reject_reason, updated_at
)
SELECT id, ?, ?, ?, ?, ? FROM adapter_instances
 WHERE {match} AND disabled_at IS NULL
ON CONFLICT(adapter_instance_id) DO UPDATE SET
    first_accepted_at = COALESCE(
        adapter_webhook_receipts.first_accepted_at, excluded.first_accepted_at),
    last_accepted_at = COALESCE(
        excluded.last_accepted_at, adapter_webhook_receipts.last_accepted_at),
    last_reject_reason = CASE
        WHEN excluded.last_rejected_at IS NULL
            THEN adapter_webhook_receipts.last_reject_reason
        WHEN adapter_webhook_receipts.last_rejected_at IS NOT NULL
             AND adapter_webhook_receipts.last_rejected_at > excluded.last_rejected_at
            THEN adapter_webhook_receipts.last_reject_reason
        ELSE excluded.last_reject_reason END,
    last_rejected_at = CASE
        WHEN excluded.last_rejected_at IS NULL
            THEN adapter_webhook_receipts.last_rejected_at
        WHEN adapter_webhook_receipts.last_rejected_at IS NOT NULL
             AND adapter_webhook_receipts.last_rejected_at > excluded.last_rejected_at
            THEN adapter_webhook_receipts.last_rejected_at
        ELSE excluded.last_rejected_at END,
    updated_at = excluded.updated_at
"""


def _registry_path(db_path: Optional[Path]) -> Path:
    if db_path is not None:
        return Path(db_path)
    from apps.octo import paths

    return paths.registry_db_path()


def flush(db_path: Optional[Path] = None) -> int:
    """Write every dirty receipt in ONE transaction; returns how many were
    handed to the database. Never raises, never creates a database, and only
    ever touches rows of instances that exist and are not disabled. On
    failure the receipts stay dirty, so the next flush retries."""
    with _lock:
        by_id = {
            iid: (e.first_accepted_at, e.last_accepted_at,
                  e.last_rejected_at, e.last_reject_reason)
            for iid, e in _instances.items() if e.dirty
        }
        by_vendor = {
            slug: (None, None, e.last_rejected_at, e.last_reject_reason)
            for slug, e in _vendors.items() if e.dirty
        }
        for entry in (*_instances.values(), *_vendors.values()):
            entry.dirty = False
    if not by_id and not by_vendor:
        return 0

    def _still_dirty() -> None:
        with _lock:
            for iid in by_id:
                if iid in _instances:
                    _instances[iid].dirty = True
            for slug in by_vendor:
                if slug in _vendors:
                    _vendors[slug].dirty = True

    try:
        path = _registry_path(db_path)
        if not path.exists():
            _still_dirty()
            return 0
        now = _iso(_clock())
        conn = connect(path)
        try:
            with transaction(conn):
                for iid, values in by_id.items():
                    conn.execute(_UPSERT.format(match="id = ?"), (*values, now, iid))
                for slug, values in by_vendor.items():
                    conn.execute(
                        _UPSERT.format(match="vendor_slug = ?"), (*values, now, slug),
                    )
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 — bookkeeping; retried next flush
        _still_dirty()
        logger.warning(
            "[webhook-receipt] could not persist webhook receipts (%s) — will "
            "retry; the in-memory state is unaffected", type(exc).__name__,
        )
        return 0
    return len(by_id) + len(by_vendor)


def _any_dirty() -> bool:
    with _lock:
        return any(e.dirty for e in (*_instances.values(), *_vendors.values()))


class _Flusher:
    """Daemon thread: sleep until something is dirty, flush once, then hold
    off for `interval_sec` — so writes happen at most once per interval no
    matter how many requests arrive, and the FIRST receipt after a quiet
    spell is persisted at once."""

    def __init__(self, db_path: Path, interval_sec: float) -> None:
        self._db_path = db_path
        self._interval = max(0.0, float(interval_sec))
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="webhook-receipt-flusher", daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=10.0)
        flush(self._db_path)  # whatever arrived during the last hold-off

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait()
            if self._stop.is_set():
                return
            self._wake.clear()
            flush(self._db_path)
            if _any_dirty():
                # The write failed (locked / unavailable registry): try again
                # after the hold-off even if no further request arrives.
                self._wake.set()
            self._stop.wait(self._interval)


_flusher: Optional[_Flusher] = None
_flusher_lock = threading.Lock()


def _wake_flusher() -> None:
    flusher = _flusher
    if flusher is not None:
        flusher.wake()


def start_flusher(
    db_path: Optional[Path] = None, *, interval_sec: float = FLUSH_INTERVAL_SEC,
) -> None:
    """Start the background flusher (app startup). Bound to ONE registry path
    for its whole life, so receipts recorded later can never be written into
    whatever database a changed environment happens to point at."""
    global _flusher
    with _flusher_lock:
        if _flusher is not None:
            _flusher.stop()
        _flusher = _Flusher(_registry_path(db_path), interval_sec)
        _flusher.start()


def stop_flusher() -> None:
    """Stop the flusher and write what is pending (app shutdown). Idempotent."""
    global _flusher
    with _flusher_lock:
        flusher, _flusher = _flusher, None
    if flusher is not None:
        flusher.stop()


def _persisted(instance_id: int, db_path: Optional[Path]) -> dict:
    """The stored row for one instance, {} when there is none. Never raises:
    a registry that predates migration 032 simply has nothing stored."""
    try:
        path = _registry_path(db_path)
        if not path.exists():
            return {}
        conn = connect(path, read_only=True)
        try:
            row = conn.execute(
                "SELECT last_accepted_at, last_rejected_at, last_reject_reason "
                "FROM adapter_webhook_receipts WHERE adapter_instance_id = ?",
                (instance_id,),
            ).fetchone()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return {}
    if row is None:
        return {}
    return {
        "last_accepted_at": row[0],
        "last_rejected_at": row[1],
        "last_reject_reason": row[2],
    }


# ---------------------------------------------------------------------------
# Read-back
# ---------------------------------------------------------------------------

def snapshot(
    instance_id: Optional[int],
    vendor_slug: Optional[str] = None,
    *,
    db_path: Optional[Path] = None,
) -> dict:
    """What is known about one instance's inbound webhooks: the persisted
    timestamps merged with this process's memory (whichever is newer), plus
    the in-memory counts. `ever_reached` is the persisted-or-observed answer
    to "has ANY request — accepted or rejected — reached this route?"."""
    now = _clock()
    with _lock:
        entries = []
        if instance_id is not None and instance_id in _instances:
            entries.append(_instances[instance_id])
        if vendor_slug is not None and vendor_slug in _vendors:
            entries.append(_vendors[vendor_slug])
        oldest = int((now - RECENT_WINDOW_SEC) // _BUCKET_SEC)
        by_reason: dict[str, int] = {}
        for entry in entries:
            for minute, reasons in entry.recent.items():
                if minute < oldest:
                    continue
                for reason, count in reasons.items():
                    by_reason[reason] = by_reason.get(reason, 0) + count
        accepted = sum(e.accepted for e in entries)
        rejected = sum(e.rejected for e in entries)
        last_accepted = max((e.last_accepted_at for e in entries if e.last_accepted_at), default=None)
        last_rejected, last_reason = max(
            ((e.last_rejected_at, e.last_reject_reason) for e in entries if e.last_rejected_at),
            default=(None, None),
        )
        counting_since = _counting_since

    stored = _persisted(instance_id, db_path) if instance_id is not None else {}
    # Both sides are the canonical fixed-width UTC form, so text order IS
    # time order.
    if stored.get("last_accepted_at") and (last_accepted or "") < stored["last_accepted_at"]:
        last_accepted = stored["last_accepted_at"]
    if stored.get("last_rejected_at") and (last_rejected or "") < stored["last_rejected_at"]:
        last_rejected = stored["last_rejected_at"]
        last_reason = stored.get("last_reject_reason")

    return {
        "last_accepted_at": last_accepted,
        "last_rejected_at": last_rejected,
        "last_reject_reason": last_reason,
        "ever_reached": bool(last_accepted or last_rejected),
        "accepted_since_start": accepted,
        "rejected_since_start": rejected,
        "counting_since": _iso(counting_since),
        "rejected_recent": sum(by_reason.values()),
        "rejected_recent_by_reason": {
            r: by_reason[r] for r in REJECT_REASONS if by_reason.get(r)
        },
        # The window cannot reach back past this process's start.
        "recent_window": (
            "hour" if now - counting_since >= RECENT_WINDOW_SEC else "since_start"
        ),
    }


# ---------------------------------------------------------------------------
# Operator-facing wording — one source for the card AND the setup guide
# ---------------------------------------------------------------------------

# Calm, generic guidance for "the vendor says it failed, Athena saw nothing".
# No vendor, CDN product or deployment is named: this ships to every bundle.
EDGE_GUIDANCE: tuple[str, ...] = (
    "If the vendor's own webhook test reports 403, \"blocked\", a timeout or "
    "an HTML error page while this still says none has reached Athena, the "
    "request is being stopped BEFORE Athena. This webhook URL never answers "
    "403: it answers 2xx, 401, 422 or 429 (a 5xx only if storing the event "
    "failed), always as JSON.",
    "Check what sits in front of the ingest hostname — CDN, WAF, bot "
    "protection, access gate. Two common culprits: WAF managed rule sets "
    "(an OWASP-style anomaly score on a machine-to-machine JSON POST) and bot "
    "protection, which classes a vendor's cloud as automated. Ask whoever "
    "runs the edge to open its security events for this hostname: the "
    "blocked request's ID names the exact rule, and the fix is a scoped "
    "exception for this hostname and the webhook path only — not a "
    "zone-wide change. Some CDN free tiers cannot exempt a single hostname "
    "from bot protection at all.",
    "Confirm the vendor was given the INGEST hostname (the webhook URL under "
    "'Setup guide'), not the console hostname — the console sits behind the "
    "operator sign-in gate.",
    "A request sent from inside your own network proves nothing about what "
    "the vendor's cloud may reach. The edge requirements are listed in the "
    "bundle deploy guide (docs/operations/bundle.md, 'Edge requirements for "
    "the ingest hostname').",
)

EDGE_STEP_TITLE = "If the vendor's webhook test fails: did it reach Athena?"


def edge_step_body() -> str:
    """The shared setup-guide step appended for EVERY webhook-capable adapter."""
    return (
        "This integration's card shows 'Last webhook received' — or says that "
        "no webhook has reached Athena yet — and counts requests that arrived "
        "but were rejected, with the reason. Read it next to the vendor's "
        "test result. " + " ".join(EDGE_GUIDANCE)
    )


def _reason_text(reason: str, vendor_slug: str) -> str:
    from apps.octo.instances.webhook_auth import (
        SECRET_SPECS, WEBHOOK_SECRET_FIELDS, field_label,
    )

    secret_field = WEBHOOK_SECRET_FIELDS.get(vendor_slug, "")
    spec = SECRET_SPECS.get(secret_field)
    if reason == "bad_token":
        if spec is not None and spec.kind == "token":
            return (
                f"the {spec.header} header was missing or did not verify — "
                "re-copy the header value into the vendor exactly as it was "
                "shown when this integration was created"
            )
        return (
            "the signature did not verify — the "
            f"{field_label(secret_field) if secret_field else 'signing secret'} "
            "stored here is not the one the vendor signs this endpoint with"
        )
    if reason == "malformed" and vendor_slug in TEMPLATED_BODY_VENDORS:
        return (
            "the request verified, but its body was not a JSON object (or was "
            "over the size limit) and named no alert id — the vendor does not "
            "JSON-escape free-text variables such as [alert_message], so a "
            "message with a quote or a line break breaks the body; switch the "
            "webhook body to the ID-only template from the Setup guide"
        )
    return {
        "replay_window": (
            "the signed timestamp was malformed or more than 5 minutes from this "
            "server's clock — check the server's time sync (a replayed request "
            "is refused the same way)"
        ),
        "malformed": (
            "the request verified, but its body was not a JSON object (or was "
            "over the size limit) — check the payload template's quotes and "
            "commas"
        ),
        "unresolvable": (
            "the request verified and named an alert id, but its body was not "
            "valid JSON and the alert could not be fetched from the vendor's "
            "API in time — the event was DROPPED. Check this integration's "
            "status (it must be running and able to read alerts), and switch "
            "the webhook body to the ID-only template from the Setup guide so "
            "the body always parses on its own"
        ),
        "unmapped": (
            "the request verified, but the event could not be attributed to a "
            "tenant and is HELD in quarantine pending review — route it under "
            "Settings → Tenants → Quarantine"
        ),
        "rate_limited": (
            "the sender exceeded the per-minute request limit and was answered "
            "429 — requests are accepted again within a minute"
        ),
        "not_configured": (
            "this integration has no usable webhook secret, so nothing can be "
            "verified — see the warning on this card"
        ),
        "store_failed": (
            "the request verified, but storing the event failed inside Athena "
            "(answered 5xx, so the vendor retries) — check the server log"
        ),
    }.get(reason, "rejected")


def describe(snap: dict, vendor_slug: str, *, usable: bool) -> dict:
    """Server-authored lines for the card, from a `snapshot`:

    recent_rejections   one line per reason class seen in the rolling window
    last_reject_detail  why the most recent rejected request was refused (kept
                        across restarts, when the window above is empty)
    guidance            the calm edge checklist — ONLY while nothing has ever
                        reached this instance and it could accept if it did
    """
    window = (
        "in the last hour" if snap["recent_window"] == "hour"
        else "since the service last started"
    )
    lines = [
        f"{count} rejected {window}: {_reason_text(reason, vendor_slug)}."
        for reason, count in snap["rejected_recent_by_reason"].items()
    ]
    reason = snap["last_reject_reason"]
    return {
        "recent_rejections": lines,
        "last_reject_detail": _reason_text(reason, vendor_slug) if reason else None,
        "guidance": (
            list(EDGE_GUIDANCE) if usable and not snap["ever_reached"] else []
        ),
    }
