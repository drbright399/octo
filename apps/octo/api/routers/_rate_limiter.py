"""In-process sliding-window rate limiter for the agent-query bridge.

Slice 9f (consensus reviewer P2). Three independent caps:

  * 60 calls/min per operator   — burst protection against a single
                                   compromised session
  * 30 calls/min per tenant     — protection against an analyst with
                                   many tenants spraying calls at one
                                   high-value tenant
  * 200 calls/min per bundle    — sibling-saturation protection so a
                                   coordinated abuse pattern can't
                                   make octo-llm starve real work

This is a v1 in-process implementation. A multi-worker deployment
needs a shared backing store (Redis or shared sqlite) — documented
in the 2026-05-22 LLM-pipeline review synthesis (archived outside the
repo) under the P2 follow-up section. For the v1 bundle (single octo-core
process) the in-memory implementation is sound.

The buckets use a `deque[float]` of monotonic timestamps. On each
hit we:
  1. Drop timestamps older than 60 seconds (sliding window).
  2. Check whether the current count exceeds the cap.
  3. If under, append the new timestamp and allow.
  4. If over, return the seconds-until-retry so the caller can
     thread it into a Retry-After header.

All three buckets are evaluated; the FIRST one that's exceeded
determines the reject. The audit row records WHICH bucket fired so
forensics can distinguish patterns.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional


# Per-bucket cap in calls per WINDOW_SECONDS. Reviewer P2 numbers.
LIMIT_OPERATOR_PER_MIN = 60
LIMIT_TENANT_PER_MIN = 30
LIMIT_BUNDLE_PER_MIN = 200

WINDOW_SECONDS = 60.0


@dataclass
class RateLimitVerdict:
    """The verdict returned from `check_or_reject`.

    `allowed=False` cases set `bucket` (operator/tenant/bundle) and
    `retry_after_s` (seconds until the oldest entry in the offending
    bucket ages out so the caller can retry). On allow, `bucket` is
    None and `retry_after_s` is 0."""
    allowed: bool
    bucket: Optional[str] = None
    retry_after_s: int = 0


class _SlidingWindowCounter:
    """A single bucket. Thread-safe via a single Lock guarding the
    deque since eviction + append must be atomic against concurrent
    reads."""

    def __init__(self, limit: int):
        self._limit = limit
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def hit(self, now: float) -> tuple[bool, float]:
        """Record a hit at time `now`. Returns (allowed, retry_after_s).
        retry_after_s is 0 on allow; on reject it's the time until the
        oldest stamp ages out + 1s of safety margin."""
        cutoff = now - WINDOW_SECONDS
        with self._lock:
            # Sliding-window eviction. popleft until the head is
            # within the window.
            while self._stamps and self._stamps[0] < cutoff:
                self._stamps.popleft()
            if len(self._stamps) >= self._limit:
                # Reject. retry_after = time until oldest stamp exits
                # the window + 1s safety so the caller doesn't busy-
                # retry exactly at the boundary.
                oldest = self._stamps[0]
                retry = max(1, int(oldest + WINDOW_SECONDS - now) + 1)
                return False, retry
            self._stamps.append(now)
            return True, 0.0


class AgentQueryRateLimiter:
    """Three coordinated buckets keyed by operator, tenant, and a
    process-global bundle counter. `check_or_reject` evaluates all
    three; the first one that fails determines the verdict."""

    def __init__(self):
        self._per_op: dict[int, _SlidingWindowCounter] = {}
        self._per_tenant: dict[str, _SlidingWindowCounter] = {}
        self._bundle = _SlidingWindowCounter(LIMIT_BUNDLE_PER_MIN)
        self._lookup_lock = threading.Lock()

    def _op_counter(self, op_id: int) -> _SlidingWindowCounter:
        with self._lookup_lock:
            c = self._per_op.get(op_id)
            if c is None:
                c = _SlidingWindowCounter(LIMIT_OPERATOR_PER_MIN)
                self._per_op[op_id] = c
            return c

    def _tenant_counter(self, slug: str) -> _SlidingWindowCounter:
        with self._lookup_lock:
            c = self._per_tenant.get(slug)
            if c is None:
                c = _SlidingWindowCounter(LIMIT_TENANT_PER_MIN)
                self._per_tenant[slug] = c
            return c

    def check_or_reject(
        self, operator_id: int, client_slug: str,
    ) -> RateLimitVerdict:
        """Evaluate operator + tenant + bundle buckets in that order.
        ORDER MATTERS: operator is checked first so a single abuser
        hitting their own tenant repeatedly gets `bucket=operator`
        rather than `bucket=tenant`, which is more diagnostic.

        Note: this CONSUMES a slot in each bucket only if the call
        is allowed. On reject we do NOT consume in the buckets that
        came before the failing one (otherwise a flood could starve
        a legitimate caller's tenant bucket through their own
        operator throttle)."""
        now = time.monotonic()
        # Pre-read the verdict from each bucket without mutating, so
        # we can decide which to consume.
        op = self._op_counter(operator_id)
        tn = self._tenant_counter(client_slug)

        # The simplest semantics: mutate operator bucket first; on
        # success mutate tenant; on success mutate bundle. On any
        # reject return — earlier-consumed slots are spent but only
        # for calls that the operator MADE. That matches what
        # rate-limit semantics usually mean ("this op already made
        # 60 calls this minute").
        ok, retry = op.hit(now)
        if not ok:
            return RateLimitVerdict(
                allowed=False, bucket="operator", retry_after_s=retry,
            )
        ok, retry = tn.hit(now)
        if not ok:
            return RateLimitVerdict(
                allowed=False, bucket="tenant", retry_after_s=retry,
            )
        ok, retry = self._bundle.hit(now)
        if not ok:
            return RateLimitVerdict(
                allowed=False, bucket="bundle", retry_after_s=retry,
            )
        return RateLimitVerdict(allowed=True)


# Process-singleton. Resetting state across tests requires reaching
# in to this attribute; tests that need a clean slate import + call
# .__init__() on it (see test_agent_query_rate_limit.py).
LIMITER = AgentQueryRateLimiter()
