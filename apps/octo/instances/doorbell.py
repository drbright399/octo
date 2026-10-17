"""Webhook DOORBELL bookkeeping — one vendor fetch per rung bell, bounded.

A push webhook from a vendor that does not JSON-escape what it substitutes
into the operator's body template (Datto RMM: [alert_message]) cannot be
trusted to parse, and even when it does, the templated body is a different
shape from the object the poller stores. So the webhook is treated as a
DOORBELL: it says WHICH alert (an id), and Athena fetches the full object
from the vendor's API through the running instance's own client and stores
THAT — complete, and identical to the polled copy.

A doorbell is rung by the open internet (after the token verifies) and each
ring could cost a vendor read, so the reads are bounded here, per instance:

  * one fetch per alert id per ``PER_ID_WINDOW_SEC`` — a vendor retry burst
    or raised-then-resolved pair for one alert reuses the object (or the
    failure) the first ring fetched;
  * ``FETCHES_PER_MINUTE`` fetches per instance, all ids together — past
    that a ring falls back to its own body (or is answered 'unresolvable');
  * a fetch never holds the vendor's request longer than ``FETCH_DEADLINE_SEC``.

In memory, process-local, bounded (oldest out), keyed by the instance id and
the vendor's own alert id — never by anything else a body carries. Reset per
instance on disable; nothing here is ever persisted.

Vendor-neutral: the id is opaque here. What an id looks like, and what a
fetched object means, is the adapter's business (`adapters.datto.doorbell`).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Optional

# One fetch per alert id per window; a burst of rings for one alert = one
# read. Long enough to cover the vendor's retries and a raised-then-resolved
# pair, short enough that a genuinely re-raised alert is fetched afresh.
PER_ID_WINDOW_SEC = 60.0
# Instance-wide budget, all ids together: a flood of distinct ids must not
# turn into a flood of vendor reads (the vendor rate-limits, and then blocks).
FETCHES_PER_MINUTE = 60
_WINDOW_SEC = 60.0
# The vendor is waiting for its 2xx: the fetch runs synchronously inside the
# request, but never longer than this. The client's own per-read timeout is
# set a second shorter so the vendor's "slow" surfaces as a clean transport
# failure before the deadline does.
FETCH_TIMEOUT_SEC = 8.0
FETCH_DEADLINE_SEC = 9.0
MAX_REMEMBERED_PER_INSTANCE = 1024

FETCH_FAILURE_KINDS = (
    "not_running", "invalid", "auth", "forbidden", "not_found", "transport",
    "timeout",
)


class AlertFetchError(Exception):
    """`kind` ∈ FETCH_FAILURE_KINDS; `message` is operator-safe (static text
    and status codes only — never vendor body text, never a URL)."""

    def __init__(self, kind: str, message: str) -> None:
        self.kind = kind if kind in FETCH_FAILURE_KINDS else "transport"
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class Remembered:
    """What the last fetch for an id yielded within its window: the vendor's
    object, or the kind of failure (one of FETCH_FAILURE_KINDS)."""

    alert: Optional[dict[str, Any]]
    failure: Optional[str]


@dataclass
class _InstanceState:
    recent: "OrderedDict[str, tuple[Remembered, float]]"
    fetches: "deque[float]"


_lock = threading.Lock()
_state: dict[int, _InstanceState] = {}


def _monotonic() -> float:
    return time.monotonic()


def _for(instance_id: int) -> _InstanceState:
    """Caller holds `_lock`."""
    state = _state.get(instance_id)
    if state is None:
        state = _state[instance_id] = _InstanceState(OrderedDict(), deque())
    return state


def recent(instance_id: Optional[int], alert_id: str) -> Optional[Remembered]:
    """The outcome of a fetch for this id within PER_ID_WINDOW_SEC, else None."""
    if instance_id is None:
        return None
    with _lock:
        state = _state.get(instance_id)
        if state is None:
            return None
        hit = state.recent.get(alert_id)
        if hit is None:
            return None
        if _monotonic() - hit[1] > PER_ID_WINDOW_SEC:
            state.recent.pop(alert_id, None)
            return None
        return hit[0]


def remember(
    instance_id: Optional[int], alert_id: str, *,
    alert: Optional[dict[str, Any]] = None, failure: Optional[str] = None,
) -> None:
    """Record what the fetch for `alert_id` yielded (exactly one of the two)."""
    if instance_id is None:
        return
    with _lock:
        state = _for(instance_id)
        state.recent[alert_id] = (Remembered(alert, failure), _monotonic())
        state.recent.move_to_end(alert_id)
        while len(state.recent) > MAX_REMEMBERED_PER_INSTANCE:
            state.recent.popitem(last=False)


def take_fetch(instance_id: Optional[int]) -> int:
    """Spend one vendor fetch from this instance's budget. 0 = go ahead;
    otherwise the whole seconds until one frees up (nothing was spent)."""
    if instance_id is None:
        return 0
    now = _monotonic()
    with _lock:
        fetches = _for(instance_id).fetches
        while fetches and now - fetches[0] >= _WINDOW_SEC:
            fetches.popleft()
        if len(fetches) >= FETCHES_PER_MINUTE:
            return max(1, int(_WINDOW_SEC - (now - fetches[0]) + 0.999))
        fetches.append(now)
        return 0


def fetches_in_window(instance_id: Optional[int]) -> int:
    with _lock:
        state = _state.get(instance_id) if instance_id is not None else None
        return len(state.fetches) if state else 0


def reset(instance_id: Optional[int] = None) -> None:
    """Forget one instance (disable, create rollback) or everything (tests)."""
    with _lock:
        if instance_id is None:
            _state.clear()
        else:
            _state.pop(instance_id, None)
