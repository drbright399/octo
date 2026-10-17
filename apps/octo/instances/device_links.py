"""Vendor portal DEVICE links — resolved through the vendor, never templated.

An alert link can be built from the alert's own id (`vendor_links`). A device
link cannot: Datto's portal addresses a device by a NUMERIC id
(``/device/<number>``) that no alert payload carries — payloads only hold the
device UID. The vendor API answers a device lookup with a ready-made portal
address, so the device link is RESOLVED: one vendor read, when an operator
clicks Open.

ON DEMAND ONLY. Nothing here runs per feed row, per poll or on a timer — the
vendor rate-limits its API, and a dashboard refresh must cost it nothing.

This module is the vendor-neutral half:

  * what an adapter hands back (`DevicePortalLookup`) and how it fails
    (`DeviceLookupError`);
  * the framework's own check of the resolved address (`checked_url`) — run
    after the adapter's, and again on every cache read, against the portal
    base in force NOW (a cached value is never trusted);
  * a bounded per-instance cache (device uid → address + the vendor tenant the
    device belongs to), a short failure memory and a per-instance budget of
    vendor reads.

An adapter opts in by offering, on a RUNNING instance:

    resolve_device_portal(device_uid, portal_base) -> DevicePortalLookup

It uses the instance's own client (the poller's — token already cached), so
an operator click never decrypts a credential.

Cache rules (same as `vendor_tenants`): keyed by instance id AND cred_ref;
`reset(instance_id)` on disable, on create rollback and when an admin changes
the portal link settings; process-local, gone on restart.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

CACHE_TTL_SEC = 6 * 3600.0
MAX_CACHED_DEVICES_PER_INSTANCE = 2048
# A failed lookup is answered from memory for this long: a click-retry loop
# must not become a stream of vendor reads.
FAILURE_THROTTLE_SEC = 20.0
# Rejected credentials are remembered for the WHOLE instance, and longer: a
# lookup with no valid token is a credential grant, and repeated bad grants
# are what gets an API user locked out (same rule as `vendor_tenants`).
AUTH_FAILURE_THROTTLE_SEC = 60.0
MAX_REMEMBERED_FAILURES_PER_INSTANCE = 256
_WHOLE_INSTANCE = ""        # failure key; never a device uid (those are non-empty)
# Vendor reads per instance per minute, all operators together. A person
# clicking Open never gets near it; a script does.
VENDOR_READS_PER_MINUTE = 30
_WINDOW_SEC = 60.0

MAX_URL_CHARS = 300

LOOKUP_FAILURE_KINDS = ("not_found", "forbidden", "auth", "transport", "invalid")


@dataclass(frozen=True)
class DevicePortalLookup:
    """What an adapter returns for one device. `portal_url` has passed the
    ADAPTER's validation; the framework checks it again (`checked_url`)."""

    portal_url: str
    vendor_tenant_id: Optional[str]
    """The vendor tenant (Datto: siteUid) the device belongs to NOW, as the
    vendor says — the caller must map it to the requesting tenant."""


class DeviceLookupError(Exception):
    """`kind` ∈ LOOKUP_FAILURE_KINDS; `message` is operator-safe (static text
    and status codes only — never vendor body text, never a URL)."""

    def __init__(self, kind: str, message: str) -> None:
        self.kind = kind if kind in LOOKUP_FAILURE_KINDS else "transport"
        self.message = message
        super().__init__(message)


def supports_device_links(adapter_cls: Any) -> bool:
    return callable(getattr(adapter_cls, "resolve_device_portal", None))


# ---------------------------------------------------------------------------
# The framework's own check of a resolved address
# ---------------------------------------------------------------------------

def checked_url(url: Any, portal_base: Optional[str]) -> Optional[str]:
    """`url` when it is exactly an https address on `portal_base`'s host with
    a path and nothing else (no userinfo, port, query, fragment, whitespace
    or backslash) — else None. Deliberately ignorant of the vendor's path
    scheme: that is the adapter's check; this one is the host allowlist."""
    if not isinstance(url, str) or not isinstance(portal_base, str) or not portal_base:
        return None
    if len(url) > MAX_URL_CHARS or "\\" in url or "?" in url or "#" in url:
        return None
    if not url.isprintable() or any(ch.isspace() for ch in url):
        return None
    try:
        parts, base = urlsplit(url), urlsplit(portal_base)
        if parts.port is not None or base.port is not None:
            return None
    except ValueError:
        return None
    host = (base.hostname or "").lower()
    if (
        parts.scheme != "https" or base.scheme != "https" or not host
        or base.netloc.lower() != host      # a base with userinfo is no base
        or "@" in parts.netloc or parts.username or parts.password
        or parts.netloc.lower() != host
        or parts.query or parts.fragment
        or not parts.path.startswith("/") or parts.path.startswith("//")
    ):
        return None
    return url


# ---------------------------------------------------------------------------
# Cache, failure memory, vendor-read budget — per instance
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CachedDevice:
    portal_url: str
    vendor_tenant_id: str
    """Never blank: a device the vendor did not place in a site is not
    cached (nothing could map it), see the resolver."""


@dataclass(frozen=True)
class RecentFailure:
    code: str
    message: str
    retry_in_sec: int


@dataclass
class _InstanceState:
    cred_ref: str
    devices: "OrderedDict[str, tuple[CachedDevice, float]]"
    failures: "OrderedDict[str, tuple[str, str, float]]"
    reads: "deque[float]"


_lock = threading.Lock()
_state: dict[int, _InstanceState] = {}


def _monotonic() -> float:
    return time.monotonic()


def _for(instance_id: int, cred_ref: str) -> _InstanceState:
    """Caller holds `_lock`. A different cred_ref starts from nothing."""
    state = _state.get(instance_id)
    if state is None or state.cred_ref != cred_ref:
        state = _state[instance_id] = _InstanceState(
            cred_ref, OrderedDict(), OrderedDict(), deque(),
        )
    return state


def lookup(instance_id: int, cred_ref: str, device_uid: str) -> Optional[CachedDevice]:
    with _lock:
        state = _state.get(instance_id)
        if state is None or state.cred_ref != cred_ref:
            return None
        hit = state.devices.get(device_uid)
        if hit is None:
            return None
        if _monotonic() - hit[1] > CACHE_TTL_SEC:
            state.devices.pop(device_uid, None)
            return None
        state.devices.move_to_end(device_uid)
        return hit[0]


def store(
    instance_id: int, cred_ref: str, device_uid: str, device: CachedDevice,
) -> None:
    with _lock:
        state = _for(instance_id, cred_ref)
        state.devices[device_uid] = (device, _monotonic())
        state.devices.move_to_end(device_uid)
        state.failures.pop(device_uid, None)
        while len(state.devices) > MAX_CACHED_DEVICES_PER_INSTANCE:
            state.devices.popitem(last=False)


def forget(instance_id: int, device_uid: str) -> None:
    """Drop one device (its cached address stopped validating)."""
    with _lock:
        state = _state.get(instance_id)
        if state is not None:
            state.devices.pop(device_uid, None)


def _failure_key(device_uid: str, for_client: Optional[str]) -> str:
    # A refusal that depends on WHO asked (the device's site is not mapped to
    # the requesting client) is remembered for that client only: another
    # tenant's analyst must get their own answer, not a replay. The uid comes
    # from a stored payload and is NOT shape-checked before it gets here, so
    # the two parts are joined as a tuple repr rather than with a separator
    # a crafted uid could contain.
    return device_uid if for_client is None else repr((device_uid, for_client))


def remember_failure(
    instance_id: int, cred_ref: str, device_uid: str, *, code: str, message: str,
    whole_instance: bool = False, for_client: Optional[str] = None,
) -> None:
    """`message` must already be operator-safe — it is replayed verbatim.
    `whole_instance` (rejected credentials): replayed for EVERY device.
    `for_client`: replayed only to requests for that client."""
    key = _WHOLE_INSTANCE if whole_instance else _failure_key(device_uid, for_client)
    with _lock:
        state = _for(instance_id, cred_ref)
        state.failures[key] = (code, message, _monotonic())
        state.failures.move_to_end(key)
        while len(state.failures) > MAX_REMEMBERED_FAILURES_PER_INSTANCE:
            state.failures.popitem(last=False)


def recent_failure(
    instance_id: int, cred_ref: str, device_uid: str, *, for_client: Optional[str] = None,
) -> Optional[RecentFailure]:
    with _lock:
        state = _state.get(instance_id)
        if state is None or state.cred_ref != cred_ref:
            return None
        keys = [(_WHOLE_INSTANCE, AUTH_FAILURE_THROTTLE_SEC), (device_uid, FAILURE_THROTTLE_SEC)]
        if for_client is not None:
            keys.append((_failure_key(device_uid, for_client), FAILURE_THROTTLE_SEC))
        for key, window in keys:
            entry = state.failures.get(key)
            if entry is None:
                continue
            remaining = window - (_monotonic() - entry[2])
            if remaining > 0:
                return RecentFailure(entry[0], entry[1], max(1, int(remaining + 0.999)))
            state.failures.pop(key, None)
    return None


def take_vendor_read(instance_id: int, cred_ref: str) -> int:
    """Spend one vendor read from this instance's budget. 0 = go ahead;
    otherwise the whole seconds to wait (nothing was spent)."""
    now = _monotonic()
    with _lock:
        reads = _for(instance_id, cred_ref).reads
        while reads and now - reads[0] >= _WINDOW_SEC:
            reads.popleft()
        if len(reads) >= VENDOR_READS_PER_MINUTE:
            return max(1, int(_WINDOW_SEC - (now - reads[0]) + 0.999))
        reads.append(now)
        return 0


def cached_count(instance_id: int) -> int:
    with _lock:
        state = _state.get(instance_id)
        return len(state.devices) if state else 0


def reset(instance_id: Optional[int] = None) -> None:
    """Forget one instance (disable, create rollback, link settings changed)
    or everything (tests)."""
    with _lock:
        if instance_id is None:
            _state.clear()
        else:
            _state.pop(instance_id, None)
