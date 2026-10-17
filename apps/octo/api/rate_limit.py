"""Rate limiting: per-route throughput limits and the failed-auth limiter.

Motivation: 2026-04-23 CF Access temp-banned Athena Console for aggressive
polling on the OCTO tab. The lesson wasn't "poll less" — it was "the server
should reject excess traffic before upstream infrastructure does it less
politely." This middleware puts the limit in OUR control so tightening is
config-only.

Throughput limits (per caller per minute, sliding 60 s; defaults generous):
  - admin_read:     600
  - admin_write:    120
  - ingestion:     6000       (forwarders can be chatty; 100/s sustained is fine)
  - audit_read:     120
  - pattern_read:   600
  - search_*:       see DEFAULT_LIMITS_PER_MINUTE

The class is chosen from the URL path + method (`_resolve_class`): this
middleware runs before routing.

The "caller":
  - a request with `Authorization: Bearer <token>`: a keyed SHA-256 of the
    WHOLE token (`token_fingerprint`). Never the token, never a prefix: two
    tokens that share their first characters are two callers. A guesser who
    sends a fresh token per request gets a fresh bucket each time, which is
    what the failed-auth limiter below is for.
  - anything else: the client address (`limiter_address`, built on
    `apps.octo.api.client_ip`; an IPv6 client is bucketed by its /64).
  - a credential check (below) or a webhook: the client address ALWAYS.
    Those routes never authenticate with a bearer token, so a bearer header
    there is decoration: honouring it would let a sender pick a fresh bucket
    per request (past search_elevate's 5/min, say) or, in the failed-auth
    limiter, make every failed sign-in look like one retried token.

Failed-auth limiter (`AuthFailureLimiter`): counts authentication FAILURES
per client address in a sliding window: a 401 answered to a request that
presented a bearer token, or to a request that checks a credential (sign-in,
TOTP, magic link, passkey, password reset / change, backup codes, the
password re-check on an email change, search step-up: `_is_credential_check`).
A bearer token retried with the same value counts once per window (a buoy
left running with a revoked token is one failure, not one per heartbeat);
every failed credential check counts. At OCTO_AUTH_FAILURE_LIMIT failures
(default 30) within OCTO_AUTH_FAILURE_WINDOW_SEC (default 600) the address
cools down for OCTO_AUTH_FAILURE_COOLDOWN_SEC (default 900): its credential
attempts get 429 + Retry-After BEFORE they reach auth. Attempts still in
flight count toward the limit too, so a burst of parallel guesses cannot all
reach auth before the first 401 is counted. Successes never count and never
reset the count. Never throttled by it: requests that present no credential
(session-cookie traffic, webhooks, health checks), and a bearer token that
has authenticated on a bearer route in the last 24 h (a buoy keeps working
while a neighbour behind the same address is locked out). Webhooks are left
out on purpose: their secrets are checked in constant time without a key
derivation, the per-route limit and the receipt counters already cover a
flood, and a cool-down there would drop vendors' real deliveries. The
per-account lockout on sign-in (auth router: 5 failures, 15 min) is separate
and unchanged; this one is per address. OCTO_AUTH_FAILURE_LIMIT=0 turns it
off.

It acts only on an address that is ONE client's: it is off while
OCTO_TRUSTED_PROXIES is empty, and it skips a request whose client address
is itself a trusted proxy (the chain named no client). Behind a proxy that
is not declared, the "address" is the proxy's, shared by every user behind
it, and a per-address cool-down there is a switch anyone can flip: 30 wrong
passwords through the console would hold back every operator's sign-in and
step-up for 15 minutes, again and again. (The X-Forwarded-For hint the
throughput limiter uses while the setting is empty is not a substitute: any
direct caller writes it.)
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import itertools
import logging
import math
import os
import re
import secrets
import threading
import time
import uuid
from collections import OrderedDict, deque
from typing import Callable, Optional

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from apps.octo.api import client_ip as client_ip_mod

logger = logging.getLogger(__name__)

DEFAULT_LIMITS_PER_MINUTE: dict[str, int] = {
    "admin_read":    600,
    "admin_write":   120,
    "ingestion":    6000,
    "audit_read":    120,
    "pattern_read":  600,
    "auth":           60,   # G.1 — login attempts; per-IP since pre-auth has no token
    # Search surface — split into three tiers per the design doc
    # (the 2026-05-12 client-search design, §"Rate limiting"):
    "search_elevate":   5,   # very tight: brute-force protection on re-auth
    "search_query":    60,   # interactive search; 1/sec sustained is plenty
    "search_payload": 120,   # drawer-clicking is rapid in triage
    "meta":            0,   # 0 = no limit (healthz etc.)
}

# --- failed-auth limiter settings ------------------------------------------

ENV_AUTH_FAILURE_LIMIT = "OCTO_AUTH_FAILURE_LIMIT"
ENV_AUTH_FAILURE_WINDOW_SEC = "OCTO_AUTH_FAILURE_WINDOW_SEC"
ENV_AUTH_FAILURE_COOLDOWN_SEC = "OCTO_AUTH_FAILURE_COOLDOWN_SEC"

# 30 failed credentials in 10 minutes from one address. Normal use stays far
# below it even when a whole office shares one address: each account locks
# itself after 5 wrong passwords, so 30 needs six people locking themselves
# out within ten minutes, and a stale token counts once however often it is
# retried. A guesser gets at most 30 tries per address, then none for the
# 15-minute cool-down (the count starts again from zero after it).
AUTH_FAILURE_LIMIT_DEFAULT = 30
AUTH_FAILURE_WINDOW_SEC_DEFAULT = 600
# 15 minutes: the same as the per-account sign-in lockout.
AUTH_FAILURE_COOLDOWN_SEC_DEFAULT = 900
_AUTH_FAILURE_LIMIT_MIN = 5          # (0 = off) a lower value would lock out a typo
_AUTH_FAILURE_LIMIT_MAX = 100_000
_SECONDS_MIN, _SECONDS_MAX = 60, 86_400

# POST routes whose 401 means "the credential in this request did not
# verify". Their 401s count; while an address cools down they get 429.
CREDENTIAL_CHECK_PATHS: frozenset[str] = frozenset({
    "/api/v1/auth/password/begin",
    "/api/v1/auth/password/totp",
    "/api/v1/auth/magic-link/verify",
    "/api/v1/auth/passkey/complete",
    "/api/v1/auth/password/reset",
    "/api/v1/auth/password/change",
    "/api/v1/auth/backup-codes/regenerate",
    "/api/v1/search/elevate",
})
# The same for other methods: an email change re-checks the current password
# (401 AUTH_PASSWORD_INVALID), with no per-account lockout of its own.
CREDENTIAL_CHECK_OTHER: frozenset[tuple[str, str]] = frozenset({
    ("PATCH", "/api/v1/auth/me/profile"),
})
# Webhook routes authenticate with their own header or signature, never a
# bearer token (apps.octo.instances.webhook_auth).
_WEBHOOK_PREFIX = "/api/v1/webhooks/"

# Routes that answer 2xx only after resolving the presented bearer token, so
# a 2xx there proves the token. Only these mark a token as known good: a 2xx
# from a route that ignores the header (/healthz) proves nothing, and letting
# it count would let a guesser pre-register guesses past the cool-down. A
# bearer route missing from this list only means its tokens are not exempted
# from a cool-down by it (the safe direction).
_COMMAND_RESULT_PATH = re.compile(r"/api/v1/buoy/command/[0-9]+/result")


def _proves_bearer(method: str, path: str) -> bool:
    if method == "GET":
        return path == "/api/v1/whoami"
    if method == "POST":
        return (
            path == "/api/v1/buoy/heartbeat"
            or path.startswith("/api/v1/ingest/")
            or _COMMAND_RESULT_PATH.fullmatch(path) is not None
        )
    return False


def _is_credential_check(request: Request) -> bool:
    path = request.url.path.rstrip("/")
    if request.method == "POST":
        return path in CREDENTIAL_CHECK_PATHS
    return (request.method, path) in CREDENTIAL_CHECK_OTHER


def _ignores_bearer(request: Request) -> bool:
    """Routes that never authenticate with a bearer token: a bearer header
    there must not choose the throughput bucket or the failure key."""
    return _is_credential_check(request) or request.url.path.startswith(_WEBHOOK_PREFIX)


# --- caller keys -----------------------------------------------------------

# Per-process key for token fingerprints: memory keys and logs hold a keyed
# hash of the whole token, never the token, and a dump of them cannot be
# checked against candidate tokens offline.
_FINGERPRINT_KEY = secrets.token_bytes(32)


def token_fingerprint(token: str) -> str:
    """Keyed SHA-256 (hex) of the WHOLE bearer token."""
    return hmac.new(
        _FINGERPRINT_KEY, token.encode("utf-8", "surrogatepass"), hashlib.sha256,
    ).hexdigest()


def bearer_token(request: Request) -> Optional[str]:
    """The bearer credential, or None (no header, another scheme, or a bare
    "Bearer " — which must not 500 the middleware; the route answers 401)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[len("bearer "):].strip()
    return token or None


def _bucket_label(address: str) -> str:
    """An IPv6 client is bucketed by its /64 (one site; a host can rotate
    through the rest of it freely). Everything else as is."""
    ip = client_ip_mod.parse_ip(address)
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
    return address


def _addresses(request: Request) -> tuple[str, Optional[str]]:
    """(throughput address, failed-auth address or None): see
    `limiter_address` and `failure_address`."""
    trusted = client_ip_mod.trusted_proxies()
    client = client_ip_mod.client_ip(request)
    address = _bucket_label(client)
    if trusted:
        if client_ip_mod.is_trusted(client_ip_mod.parse_ip(client), trusted):
            return address, None
        return address, address
    forwarded = request.headers.getlist("x-forwarded-for")
    hint = client_ip_mod.unverified_forwarded_hint(forwarded) if forwarded else None
    if hint is not None:
        return f"{address}|{_bucket_label(hint)}", None
    return address, None


def limiter_address(request: Request) -> str:
    """The address the THROUGHPUT limiter buckets a request under.

    `client_ip()` (the socket peer unless it is a trusted proxy), IPv6 by /64.
    While OCTO_TRUSTED_PROXIES is EMPTY, a peer that sends X-Forwarded-For has
    its buckets split by the header's right-most address
    (`<peer>|<address>`): that keeps the ingest path bucketed per real client
    as it was before the setting existed, instead of every sender sharing the
    proxy's bucket, and the peer prefix means no header can reach another
    peer's bucket. With the setting non-empty the header from an untrusted
    peer is ignored outright."""
    return _addresses(request)[0]


def failure_address(request: Request) -> Optional[str]:
    """The address the FAILED-AUTH limiter counts a request under, or None
    when it must not act on the request.

    None while OCTO_TRUSTED_PROXIES is empty (the address may be a proxy's,
    shared by everyone behind it, and the only per-client hint is a header
    any direct caller writes), and None when the client address is itself a
    trusted proxy (the chain named no client). Otherwise `client_ip()`,
    IPv6 by /64."""
    return _addresses(request)[1]


# --- throughput limiter ----------------------------------------------------

class RateLimiter:
    """Sliding 60 s window per (caller, class) key.

    Memory is bounded twice over: keys with no hit in the window are dropped
    every minute, and at most `max_keys` keys are held at all (a flood of
    fresh bearer tokens or IPv6 /64s within one minute must not grow memory
    without limit). Keys are kept in order of their last counted hit, so
    both the sweep and the cap drop the oldest idle keys first, from the
    front, in O(1) per key: every request stays O(1) amortised however full
    the map is. A key evicted by the cap while still inside its window just
    starts counting again (only under a flood of more than `max_keys`
    distinct callers a minute)."""

    _SWEEP_INTERVAL_SEC = 60.0
    MAX_KEYS_DEFAULT = 50_000

    def __init__(self, limits: dict[str, int] | None = None, *,
                 max_keys: int = MAX_KEYS_DEFAULT):
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self.limits = dict(DEFAULT_LIMITS_PER_MINUTE)
        if limits:
            self.limits.update(limits)
        self.max_keys = int(max_keys)
        self._lock = threading.Lock()
        # (caller, class) -> hit times, oldest first; the map is ordered by
        # each key's LAST counted hit, least recent first.
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._last_sweep = time.monotonic()

    def check_and_record(self, caller: str, klass: str) -> tuple[bool, int, int]:
        """Return (allowed, remaining, limit). Allowed=False → 429."""
        limit = self.limits.get(klass, 600)
        if limit == 0:
            return True, 0, 0
        key = (caller, klass)
        with self._lock:
            now = time.monotonic()          # under the lock: hits stay in order
            cutoff = now - 60.0
            if now - self._last_sweep >= self._SWEEP_INTERVAL_SEC:
                self._sweep(cutoff)
                self._last_sweep = now
            q = self._hits.get(key)
            if q is None:
                q = self._hits[key] = deque()
                while len(self._hits) > self.max_keys:
                    self._hits.popitem(last=False)     # never `key`: it is last
            else:
                while q and q[0] < cutoff:
                    q.popleft()
                if len(q) >= limit:
                    return False, 0, limit
                self._hits.move_to_end(key)
            q.append(now)
            remaining = max(0, limit - len(q))
            return True, remaining, limit

    def _sweep(self, cutoff: float) -> None:
        """Drop keys with no hit in the window (a caller per guessed token or
        per address must not grow memory for ever), from the front of the
        map, stopping at the first key still in use: O(dropped keys).
        Caller holds the lock."""
        hits = self._hits
        while hits:
            q = next(iter(hits.values()))
            if q and q[-1] >= cutoff:
                return
            hits.popitem(last=False)


# --- failed-auth limiter ---------------------------------------------------

class _AddressState:
    __slots__ = ("failures", "blocked_until", "in_flight")

    def __init__(self) -> None:
        # credential (or a unique id per credential check) -> last failure
        # time, oldest first.
        self.failures: OrderedDict[str, float] = OrderedDict()
        self.blocked_until = 0.0
        # key -> attempts admitted and not yet answered.
        self.in_flight: dict[str, int] = {}

    def idle(self, now: float) -> bool:
        return not self.failures and not self.in_flight and self.blocked_until <= now


def _env_int(name: str, default: int, lo: int, hi: int, *, zero_ok: bool = False) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s=%r is not a whole number; using %d", name, raw[:32], default)
        return default
    if zero_ok and value == 0:
        return 0
    clamped = max(lo, min(hi, value))
    if clamped != value:
        logger.warning("%s=%d is outside %d..%d; using %d", name, value, lo, hi, clamped)
    return clamped


class AuthFailureLimiter:
    """Failed authentications per address in a sliding window, a cool-down
    above the limit, and the set of bearer tokens recently proven good.
    Thread-safe; memory is bounded (addresses and tokens are LRU-capped)."""

    def __init__(
        self,
        limit: int = AUTH_FAILURE_LIMIT_DEFAULT,
        window_sec: float = AUTH_FAILURE_WINDOW_SEC_DEFAULT,
        cooldown_sec: float = AUTH_FAILURE_COOLDOWN_SEC_DEFAULT,
        *,
        known_token_ttl_sec: float = 86_400.0,
        max_addresses: int = 50_000,
        max_known_tokens: int = 20_000,
        clock: Callable[[], float] = time.monotonic,
    ):
        if limit < 1:
            raise ValueError("limit must be >= 1 (use None for no limiter)")
        self.limit = int(limit)
        self.window_sec = float(window_sec)
        self.cooldown_sec = float(cooldown_sec)
        self.known_token_ttl_sec = float(known_token_ttl_sec)
        self._max_addresses = max_addresses
        self._max_known = max_known_tokens
        self._clock = clock
        self._lock = threading.Lock()
        self._addresses: OrderedDict[str, _AddressState] = OrderedDict()
        self._known: OrderedDict[str, float] = OrderedDict()  # fingerprint -> expiry
        self._seq = itertools.count()

    @classmethod
    def from_env(cls) -> Optional["AuthFailureLimiter"]:
        """The limiter the settings describe, or None when turned off."""
        limit = _env_int(
            ENV_AUTH_FAILURE_LIMIT, AUTH_FAILURE_LIMIT_DEFAULT,
            _AUTH_FAILURE_LIMIT_MIN, _AUTH_FAILURE_LIMIT_MAX, zero_ok=True,
        )
        if limit == 0:
            logger.warning("failed-auth limiter OFF (%s=0)", ENV_AUTH_FAILURE_LIMIT)
            return None
        return cls(
            limit=limit,
            window_sec=_env_int(ENV_AUTH_FAILURE_WINDOW_SEC, AUTH_FAILURE_WINDOW_SEC_DEFAULT,
                                _SECONDS_MIN, _SECONDS_MAX),
            cooldown_sec=_env_int(ENV_AUTH_FAILURE_COOLDOWN_SEC,
                                  AUTH_FAILURE_COOLDOWN_SEC_DEFAULT,
                                  _SECONDS_MIN, _SECONDS_MAX),
        )

    # -- per address --

    def retry_after(self, address: str) -> int:
        """Whole seconds left in `address`'s cool-down; 0 = not cooling down."""
        now = self._clock()
        with self._lock:
            state = self._addresses.get(address)
            if state is None or state.blocked_until <= now:
                return 0
            return max(1, math.ceil(state.blocked_until - now))

    def new_attempt_key(self) -> str:
        """A failure key of its own (a credential check: every one counts)."""
        return f"#{next(self._seq)}"

    def admit(self, address: str, key: str) -> int:
        """Before a credential attempt from `address` (`key`: the token
        fingerprint, or `new_attempt_key()`): 0 = go ahead, the attempt is
        now in flight until `settle`; else the Retry-After seconds.

        Refused during a cool-down, and when the failures in the window plus
        the attempts still in flight already reach the limit: a guesser's
        parallel burst is held to the limit like a sequential one. A key
        already counted or in flight adds nothing (a token retried)."""
        now = self._clock()
        with self._lock:
            state = self._state(address, now)
            if state.blocked_until > now:
                return max(1, math.ceil(state.blocked_until - now))
            self._prune(state, now)
            if key not in state.failures and key not in state.in_flight:
                pending = sum(1 for k in state.in_flight if k not in state.failures)
                if len(state.failures) + pending >= self.limit:
                    return 1
            state.in_flight[key] = state.in_flight.get(key, 0) + 1
            return 0

    def settle(self, address: str, key: str, *, failed: bool, reserved: bool = True) -> bool:
        """After the attempt: release its in-flight slot (`reserved`: it was
        admitted) and, when it `failed`, count it. True when this starts a
        cool-down."""
        now = self._clock()
        with self._lock:
            state = self._addresses.get(address)
            if reserved and state is not None:
                left = state.in_flight.get(key, 0) - 1
                if left > 0:
                    state.in_flight[key] = left
                else:
                    state.in_flight.pop(key, None)
            started = self._record(address, key, now) if failed else False
            state = self._addresses.get(address)
            if state is not None and state.idle(now):
                del self._addresses[address]
            return started

    def record_failure(self, address: str, credential: Optional[str] = None) -> bool:
        """Count one failed authentication from `address`. `credential` is the
        token fingerprint (the same token again within the window counts
        once) or None (every call counts). True when this starts a cool-down."""
        now = self._clock()
        with self._lock:
            key = credential if credential is not None else self.new_attempt_key()
            return self._record(address, key, now)

    def _state(self, address: str, now: float) -> _AddressState:
        """`address`'s state, created (and the map trimmed) if new, marked
        most recently used. Caller holds the lock."""
        state = self._addresses.get(address)
        if state is None:
            state = _AddressState()
            self._addresses[address] = state
            self._trim_addresses(now, keep=address)
        else:
            self._addresses.move_to_end(address)
        return state

    def _prune(self, state: _AddressState, now: float) -> None:
        failures = state.failures
        cutoff = now - self.window_sec
        while failures and next(iter(failures.values())) < cutoff:
            failures.popitem(last=False)

    def _record(self, address: str, key: str, now: float) -> bool:
        """Caller holds the lock."""
        state = self._state(address, now)
        if state.blocked_until > now:
            return False
        self._prune(state, now)
        failures = state.failures
        failures.pop(key, None)
        failures[key] = now
        if len(failures) < self.limit:
            return False
        state.blocked_until = now + self.cooldown_sec
        failures.clear()
        return True

    def _trim_addresses(self, now: float, keep: str) -> None:
        """Over the cap, evict a tenth at once (one pass per many inserts),
        least recently used first, keeping addresses that are cooling down
        or have attempts in flight, and `keep` (the address being recorded).
        Caller holds the lock."""
        if len(self._addresses) <= self._max_addresses:
            return
        target = self._max_addresses - max(1, self._max_addresses // 10)
        for address in [a for a, st in self._addresses.items()
                        if st.blocked_until <= now and not st.in_flight and a != keep]:
            if len(self._addresses) <= target:
                return
            del self._addresses[address]
        while len(self._addresses) > target:
            oldest = next(iter(self._addresses))
            if oldest == keep:
                return
            del self._addresses[oldest]

    # -- tokens proven good --

    def note_success(self, credential: str) -> None:
        now = self._clock()
        with self._lock:
            self._known[credential] = now + self.known_token_ttl_sec
            self._known.move_to_end(credential)
            while len(self._known) > self._max_known:
                self._known.popitem(last=False)

    def is_known(self, credential: str) -> bool:
        now = self._clock()
        with self._lock:
            expiry = self._known.get(credential)
            if expiry is None:
                return False
            if expiry <= now:
                del self._known[credential]
                return False
            return True

    def forget(self, credential: str) -> None:
        with self._lock:
            self._known.pop(credential, None)


# --- middleware ------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        limiter: RateLimiter,
        failures: Optional[AuthFailureLimiter] = None,
    ):
        super().__init__(app)
        self.limiter = limiter
        self.failures = failures

    async def dispatch(self, request: Request, call_next: Callable):
        klass = self._resolve_class(request)
        address, fail_address = _addresses(request)
        sign_in = _is_credential_check(request)
        token = None if _ignores_bearer(request) else bearer_token(request)
        credential = token_fingerprint(token) if token else None
        failures = getattr(self, "failures", None)
        tracked = (failures is not None and fail_address is not None
                   and (sign_in or credential is not None))

        key: Optional[str] = None
        reserved = False
        if tracked:
            if credential is not None and failures.is_known(credential):
                key = credential            # proven: never held back
            else:
                key = credential if credential is not None else failures.new_attempt_key()
                wait = failures.admit(fail_address, key)
                if wait:
                    return self._throttled(
                        request,
                        "too many failed authentication attempts from this address; "
                        "try again after Retry-After seconds",
                        retry_after=wait, klass="auth_failure", no_store=True,
                    )
                reserved = True

        caller = self._caller(address, credential)
        allowed, remaining, limit = self.limiter.check_and_record(caller, klass)
        if not allowed:
            if reserved:
                failures.settle(fail_address, key, failed=False)
            return self._throttled(
                request, f"exceeded {limit}/min for class {klass!r}",
                retry_after=60, klass=klass, limit=limit,
            )
        try:
            response = await call_next(request)
        except BaseException:
            if reserved:
                failures.settle(fail_address, key, failed=False)
            raise
        if tracked:
            self._observe(failures, request, fail_address, key, credential,
                          reserved, response.status_code)
        if limit > 0:
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Class"] = klass
        return response

    @staticmethod
    def _throttled(request: Request, message: str, *, retry_after: int, klass: str,
                   limit: Optional[int] = None, no_store: bool = False) -> JSONResponse:
        # A throttled vendor webhook still REACHED us: the Integrations
        # card must be able to say so (memory-only; never raises).
        from apps.octo.instances import webhook_receipt
        if request.method == "POST":
            webhook_receipt.record_rate_limited(request.url.path)
        headers = {"Retry-After": str(retry_after), "X-RateLimit-Class": klass}
        if limit is not None:
            headers["X-RateLimit-Limit"] = str(limit)
        if no_store:
            headers["Cache-Control"] = "no-store"
        return JSONResponse(
            status_code=429,
            content={
                "code": "RATE_LIMITED",
                "message": message,
                "request_id": str(uuid.uuid4()),
            },
            headers=headers,
        )

    @staticmethod
    def _observe(failures: AuthFailureLimiter, request: Request, address: str,
                 key: str, credential: Optional[str], reserved: bool,
                 status: int) -> None:
        failed = status == 401
        if failed and credential is not None:
            failures.forget(credential)
        if failures.settle(address, key, failed=failed, reserved=reserved):
            logger.warning(
                "failed-auth limit: %d failed credentials from %s within %ds; "
                "its credential attempts get 429 for %ds",
                failures.limit, address, int(failures.window_sec),
                int(failures.cooldown_sec),
            )
        if (not failed and credential is not None and 200 <= status < 300
                and _proves_bearer(request.method, request.url.path)):
            failures.note_success(credential)

    def _resolve_class(self, request: Request) -> str:
        # BaseHTTPMiddleware dispatch runs BEFORE routing populates
        # request.scope["route"], so we classify by URL path + method directly.
        # Order matters: more-specific prefixes first.
        path = request.url.path
        method = request.method
        if path in ("/healthz", "/readyz") or path.startswith("/docs") or path.startswith("/redoc") or path == "/openapi.json":
            return "meta"
        if "/ingest/" in path:
            return "ingestion"
        # Search surface — three tiers for elevate/query/payload-fetch.
        # Order matters: /elevate matches first since it's a sibling of /events.
        if path.startswith("/api/v1/search/elevate"):
            return "search_elevate"
        if path.startswith("/api/v1/search/event/"):
            return "search_payload"
        if (path.startswith("/api/v1/search/events")
                or path.startswith("/api/v1/search/indicators")
                or path.startswith("/api/v1/search/")):
            return "search_query"
        if path.endswith("/audit") or path.endswith("/audit/verify") or "/audit?" in path or "/audit/" in path:
            return "audit_read"
        if path.startswith("/api/v1/patterns") or path.startswith("/api/v1/patterns/"):
            return "pattern_read"
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "admin_write"
        return "admin_read"

    @staticmethod
    def _caller(address: str, credential: Optional[str]) -> str:
        return f"tok:{credential}" if credential is not None else f"ip:{address}"

    def _caller_key(self, request: Request) -> str:
        """The throughput bucket of `request`: `tok:<fingerprint of the whole
        token>` or `ip:<limiter address>` (always the address on a route that
        never takes a bearer token)."""
        token = None if _ignores_bearer(request) else bearer_token(request)
        return self._caller(
            limiter_address(request), token_fingerprint(token) if token else None,
        )


_SHARED_LIMITER: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    global _SHARED_LIMITER
    if _SHARED_LIMITER is None:
        _SHARED_LIMITER = RateLimiter()
    return _SHARED_LIMITER


def reset_limiter() -> None:
    """Test hook: wipe the rate-limit state. (The failed-auth limiter is per
    app: every create_app() starts with a fresh one.)"""
    global _SHARED_LIMITER
    _SHARED_LIMITER = RateLimiter()


def _startup_line(trusted: tuple, failures: Optional[AuthFailureLimiter]) -> str:
    """The one line that states the client-address trust setting at start.
    Names the trusted networks (addresses, never anything else) so an
    operator can check from `docker logs` what the running process uses."""
    env = client_ip_mod.TRUSTED_PROXIES_ENV
    if not trusted:
        return (
            f"client addresses: {env} is empty: X-Forwarded-For is believed from "
            "nobody, the socket peer is the client address, and the failed-auth "
            "limiter is off. Behind a reverse proxy set it "
            "(docs/operations/bundle.md, \"Client addresses behind the proxy\")"
        )
    networks = ", ".join(str(n) for n in trusted)
    if failures is None:
        limiter = f"failed-auth limiter off ({ENV_AUTH_FAILURE_LIMIT}=0)"
    else:
        limiter = (
            f"failed-auth limiter on: {failures.limit} failures in "
            f"{int(failures.window_sec)} s from one address -> "
            f"{int(failures.cooldown_sec)} s cool-down"
        )
    return (
        f"client addresses: X-Forwarded-For believed only from {env} = "
        f"{networks} ({len(trusted)} network{'s' if len(trusted) != 1 else ''}); "
        f"{limiter}"
    )


def install_rate_limit_middleware(app: FastAPI) -> None:
    """Both limiters in front of `app`. Refuses (TrustedProxiesError, so
    octo-core does not start) when OCTO_TRUSTED_PROXIES has an unusable
    entry, and states the trust setting in one WARNING line: uvicorn's
    default logging shows WARNING and above from the application's loggers
    (Python's last-resort handler, stderr), never INFO, and the deploy
    guide's check reads that line from `docker logs`."""
    trusted = client_ip_mod.check_trusted_proxies()
    failures = AuthFailureLimiter.from_env()
    logger.warning("%s", _startup_line(trusted, failures))
    app.state.auth_failure_limiter = failures
    app.add_middleware(RateLimitMiddleware, limiter=get_limiter(), failures=failures)
