"""Dropped-unmapped bookkeeping — make silent event loss visible.

LEGACY counter. An event whose vendor tenant id resolved to no client used to
be DROPPED on both the webhook and the poll path; every drop was counted here
and shown on the Integrations card. Since the tenant-lifecycle work
(`instances.tenant_autocreate`, `instances.quarantine`) nothing is dropped:
an unmapped site is auto-created (a site with the same name as a client
is held with a suggestion — a name never links), and what cannot be
attributed is HELD in quarantine — the card's "pending review" and "held"
counts come from those modules. No ingest path calls `record_drop` any more;
the module stays so that any future path that genuinely discards an event
has a place to say so, and so the card fields it feeds keep their shape.

In-memory and process-local by design: the counter answers "is this feed
losing events right now?", resets on restart, and stores nothing but vendor
tenant ids — never event content.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from apps.octo.ingest.timestamps import utcnow_iso

# Bounded: a mis-templated webhook can present an unbounded number of distinct
# "tenant ids"; keep only the most recent few, truncated.
MAX_TENANT_IDS = 10
_MAX_ID_CHARS = 64


# A poller re-lists an OPEN alert on every cycle, so the same alert is dropped
# again every few seconds until its site is mapped. Count each alert once —
# "515 dropped" for 8 alerts tells the operator nothing. Bounded, oldest out.
MAX_SEEN_EVENT_KEYS = 5000


@dataclass
class _Drops:
    count: int = 0
    last_at: Optional[str] = None
    tenant_ids: list[str] = field(default_factory=list)  # most recent last
    seen_event_keys: dict[str, None] = field(default_factory=dict)  # insertion-ordered


_lock = threading.Lock()
_drops: dict[int, _Drops] = {}


def record_drop(
    instance_id: Optional[int],
    vendor_tenant_id: Optional[str],
    *,
    event_key: Optional[str] = None,
) -> int:
    """Count one dropped event; returns the instance's running total (0 when
    there is no instance id to attribute it to). With `event_key` (the vendor's
    own event id) a repeat of an already-counted event is not counted again —
    see `is_repeat_drop` to decide whether it is worth a log line."""
    if instance_id is None:
        return 0
    tid = str(vendor_tenant_id or "?")[:_MAX_ID_CHARS]
    with _lock:
        entry = _drops.setdefault(instance_id, _Drops())
        if event_key is not None:
            key = str(event_key)[:_MAX_ID_CHARS]
            if key in entry.seen_event_keys:
                return entry.count
            entry.seen_event_keys[key] = None
            while len(entry.seen_event_keys) > MAX_SEEN_EVENT_KEYS:
                entry.seen_event_keys.pop(next(iter(entry.seen_event_keys)))
        entry.count += 1
        entry.last_at = utcnow_iso()
        if tid in entry.tenant_ids:
            entry.tenant_ids.remove(tid)
        entry.tenant_ids.append(tid)
        del entry.tenant_ids[:-MAX_TENANT_IDS]
        return entry.count


def is_repeat_drop(instance_id: Optional[int], event_key: Optional[str]) -> bool:
    """True if this vendor event was already counted as dropped."""
    if instance_id is None or event_key is None:
        return False
    with _lock:
        entry = _drops.get(instance_id)
        return entry is not None and str(event_key)[:_MAX_ID_CHARS] in entry.seen_event_keys


def snapshot(instance_id: Optional[int]) -> dict:
    """`{dropped, last_dropped_at, vendor_tenant_ids}` for one instance."""
    with _lock:
        entry = _drops.get(instance_id) if instance_id is not None else None
        if entry is None:
            return {"dropped": 0, "last_dropped_at": None, "vendor_tenant_ids": []}
        return {
            "dropped": entry.count,
            "last_dropped_at": entry.last_at,
            "vendor_tenant_ids": list(entry.tenant_ids),
        }


def unmapped_warnings(instance_id: Optional[int]) -> list[str]:
    """Operator-facing warning for the Integrations card; [] when clean."""
    snap = snapshot(instance_id)
    if not snap["dropped"]:
        return []
    ids = ", ".join(snap["vendor_tenant_ids"])
    return [
        f"{snap['dropped']} event(s) DROPPED since the last restart (latest "
        f"{snap['last_dropped_at']}): vendor tenant id(s) {ids} do not map to a "
        "provisioned client. Unmapped events are not stored anywhere — "
        "complete the tenant mapping to stop the loss."
    ]


def reset(instance_id: Optional[int] = None) -> None:
    """Forget one instance's counters (on disable) or all of them (tests)."""
    with _lock:
        if instance_id is None:
            _drops.clear()
        else:
            _drops.pop(instance_id, None)
