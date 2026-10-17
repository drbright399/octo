"""Vendor tenant discovery — what the vendor itself calls its tenants, so the
mapping UI can offer them instead of asking the operator to type an id.

Why this exists: the mapping panel was free text, an operator typed Datto
site NAMES where the routing key is the site UID, and routing
(`tenant_map.resolve`) is an exact match — so every alert from those sites
would have been dropped. Adapters that can list their tenants declare
`supports_tenant_discovery` and implement `list_vendor_tenants(credentials)`
(see `shared_adapter_contract.base`); this module is the adapter-agnostic
half: a short cache, output hygiene, and the "saved mapping matches nothing"
check.

ON DEMAND ONLY. Nothing here runs on a timer or in a poll loop: the vendor is
contacted when an admin opens the mapping panel (or presses Reload), and at
most once per `CACHE_TTL_SEC` per instance however often that happens.

Cache rules
  * keyed by instance id AND the row's `cred_ref`: a lookup with a different
    cred_ref misses, so a list fetched with one credential set is never
    served for another (credentials are create-only today; this also covers
    any future edit path);
  * `reset(instance_id)` on disable and on create rollback, like the
    dropped-unmapped and vendor-contact state;
  * a failure is never served as a LISTING, and is remembered only briefly
    (`FAILURE_THROTTLE_SEC`): inside that window the same error is answered
    without contacting the vendor again, because every attempt is a full
    credential grant and the poller's own backoff exists precisely so a
    failing key cannot hammer the vendor into locking the API user out. After
    fixing the vendor side the operator's next attempt is a real one within
    seconds, not minutes;
  * process-local, in memory, gone on restart. Tenant labels are customer
    names: they are held here and returned to admins, never logged or audited.

The last successful listing is also kept PAST the TTL (until reset/restart)
for one purpose: `unmatched_mappings()`, which lets the Integrations card say
"N saved mappings match no vendor tenant" without contacting the vendor.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo.ingest.timestamps import utcnow_iso

CACHE_TTL_SEC = 60.0
# A forced reload (the panel's Reload button) still reuses an answer younger
# than this, so a double-click is one vendor call.
MIN_REFRESH_INTERVAL_SEC = 5.0

# How long a vendor FAILURE is answered from memory. Rejected credentials wait
# longer: repeated bad grants are what gets an API user locked out.
FAILURE_THROTTLE_SEC = 20.0
AUTH_FAILURE_THROTTLE_SEC = 60.0

MAX_ID_CHARS = 256
MAX_LABEL_CHARS = 200
# The warning names a few offending ids, never an unbounded list.
_MAX_IDS_IN_WARNING = 5


@dataclass(frozen=True)
class DiscoveredTenant:
    id: str
    label: str


@dataclass(frozen=True)
class Discovery:
    tenants: tuple[DiscoveredTenant, ...]
    truncated: bool
    fetched_at: str


@dataclass(frozen=True)
class _Entry:
    cred_ref: str
    discovery: Discovery
    stored_mono: float


@dataclass(frozen=True)
class RecentFailure:
    code: str            # API error code the route answered with
    kind: str            # forbidden / auth / transport / …
    message: str         # operator-safe, exactly as first answered
    retry_in_sec: int    # whole seconds until the vendor is asked again


@dataclass(frozen=True)
class _Failure:
    cred_ref: str
    code: str
    kind: str
    message: str
    stored_mono: float


_lock = threading.Lock()
_entries: dict[int, _Entry] = {}
_failures: dict[int, _Failure] = {}


def _monotonic() -> float:
    return time.monotonic()


def _flat(value: Any, limit: int) -> str:
    """Vendor text → one printable line, bounded. Non-strings become ""."""
    if not isinstance(value, str):
        return ""
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def clean(listing: Any) -> tuple[tuple[DiscoveredTenant, ...], bool]:
    """Normalize an adapter's `VendorTenantListing`: ids kept EXACTLY (they
    are routing keys — only blank, over-long or non-printable ones are
    dropped), labels flattened and bounded, duplicates removed, sorted by
    label for the picker."""
    seen: set[str] = set()
    out: list[DiscoveredTenant] = []
    for t in getattr(listing, "tenants", None) or []:
        tid = getattr(t, "id", None)
        if not isinstance(tid, str) or not tid.strip() or len(tid) > MAX_ID_CHARS:
            continue
        if tid != tid.strip() or not tid.isprintable() or tid in seen:
            continue
        seen.add(tid)
        out.append(DiscoveredTenant(
            id=tid, label=_flat(getattr(t, "label", None), MAX_LABEL_CHARS) or tid,
        ))
    out.sort(key=lambda d: (d.label.lower(), d.id))
    return tuple(out), bool(getattr(listing, "truncated", False))


def store(instance_id: int, cred_ref: str, listing: Any) -> Discovery:
    tenants, truncated = clean(listing)
    discovery = Discovery(tenants=tenants, truncated=truncated, fetched_at=utcnow_iso())
    with _lock:
        _entries[instance_id] = _Entry(cred_ref, discovery, _monotonic())
        _failures.pop(instance_id, None)
    return discovery


def remember_failure(
    instance_id: int, cred_ref: str, *, code: str, kind: str, message: str,
) -> None:
    """Note a vendor failure so the next few seconds of retries do not each
    become a vendor call (see `recent_failure`). `message` must already be
    operator-safe — it is replayed verbatim."""
    with _lock:
        _failures[instance_id] = _Failure(cred_ref, code, kind, message, _monotonic())


def recent_failure(instance_id: int, cred_ref: str) -> Optional[RecentFailure]:
    """The failure to replay instead of contacting the vendor, or None once
    its window has passed (or it belongs to another cred_ref)."""
    with _lock:
        entry = _failures.get(instance_id)
        if entry is None or entry.cred_ref != cred_ref:
            return None
        window = (
            AUTH_FAILURE_THROTTLE_SEC if entry.kind == "auth"
            else FAILURE_THROTTLE_SEC
        )
        remaining = window - (_monotonic() - entry.stored_mono)
        if remaining <= 0:
            _failures.pop(instance_id, None)
            return None
    return RecentFailure(
        entry.code, entry.kind, entry.message, max(1, int(remaining + 0.999)),
    )


def lookup(
    instance_id: int, cred_ref: str, *, max_age_sec: float = CACHE_TTL_SEC,
) -> Optional[Discovery]:
    """The cached listing, if it was fetched with THIS cred_ref and is no
    older than `max_age_sec`; else None."""
    with _lock:
        entry = _entries.get(instance_id)
    if entry is None or entry.cred_ref != cred_ref:
        return None
    if _monotonic() - entry.stored_mono > max_age_sec:
        return None
    return entry.discovery


def forget_failure(instance_id: int) -> None:
    """Drop the remembered failure only (the listing, if any, stays)."""
    with _lock:
        _failures.pop(instance_id, None)


def latest(instance_id: Optional[int], cred_ref: str) -> Optional[Discovery]:
    """The last successful listing regardless of age (same cred_ref only)."""
    if instance_id is None:
        return None
    return lookup(instance_id, cred_ref, max_age_sec=float("inf"))


def reset(instance_id: Optional[int] = None) -> None:
    """Forget one instance's listing (on disable) or all of them (tests)."""
    with _lock:
        if instance_id is None:
            _entries.clear()
            _failures.clear()
        else:
            _entries.pop(instance_id, None)
            _failures.pop(instance_id, None)


# ---------------------------------------------------------------------------
# Saved mappings that can never match
# ---------------------------------------------------------------------------

def unmatched_mappings(instance_id: Optional[int], cred_ref: str) -> Optional[dict]:
    """`{count, total, vendor_tenant_ids, checked_at}` — saved mappings whose
    vendor tenant id is not one the vendor listed. None when that cannot be
    known: no listing since restart, or the listing was truncated (absence
    from a prefix proves nothing). Reads the local mapping table only."""
    import sqlite3

    from apps.octo.instances import tenant_map

    discovery = latest(instance_id, cred_ref)
    if discovery is None or discovery.truncated or instance_id is None:
        return None
    try:
        mappings = tenant_map.get_mappings(instance_id)
    except sqlite3.OperationalError:  # tenant-map migration not applied yet
        return None
    known = {t.id for t in discovery.tenants}
    missing = [m.vendor_tenant_id for m in mappings if m.vendor_tenant_id not in known]
    return {
        "count": len(missing),
        "total": len(mappings),
        "vendor_tenant_ids": [_flat(v, 64) for v in missing[:_MAX_IDS_IN_WARNING]],
        "checked_at": discovery.fetched_at,
    }


def tenant_noun(adapter_cls: Any) -> str:
    """What the vendor calls one tenant ('site'), from the adapter's
    tenant_mapping_shape; 'tenant' when it does not say."""
    try:
        shape = adapter_cls().tenant_mapping_shape() if adapter_cls else None
    except Exception:  # noqa: BLE001 — wording only
        shape = None
    return getattr(shape, "tenant_noun", None) or "tenant"


_UNSET: Any = object()


def unmatched_warnings(
    rec: Any, adapter_cls: Any, vendor_display_name: str, *, found: Any = _UNSET,
) -> list[str]:
    """Operator-facing warning for the Integrations card; [] when clean or
    unknown. `rec` is the InstanceRecord; pass an `unmatched_mappings()`
    result as `found` to reuse it."""
    if found is _UNSET:
        found = unmatched_mappings(rec.id, rec.cred_ref)
    if not found or not found["count"]:
        return []
    noun = tenant_noun(adapter_cls)
    ids = ", ".join(f"'{v}'" for v in found["vendor_tenant_ids"])
    more = found["count"] - len(found["vendor_tenant_ids"])
    if more > 0:
        ids += f" (+{more} more)"
    return [
        f"{found['count']} of {found['total']} saved tenant mapping(s) do not "
        f"match any {vendor_display_name} {noun} (checked "
        f"{found['checked_at']}): {ids}. Events will never route to them — "
        f"open Tenant mapping and pick the right {noun} for each."
    ]
