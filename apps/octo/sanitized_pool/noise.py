"""§11.1 — Differential privacy via frozen Laplace noise.

Provides aggregate-count responses to unprivileged callers with
provable privacy guarantees against repeated-sampling deanonymization.

Privileged callers (LLM tool surface, super_admin reads, audit-trail
inspectors) receive EXACT counts. Unprivileged callers (public reads
through the proxy, analyst-tier scope queries) receive NOISY counts
sampled from Laplace(0, 1/ε) with ε=1.0. The audit row per query
records which version the caller received.

Why frozen (deterministic) noise:

  A naive "add fresh Laplace noise on every query" approach is
  defeated by repeated sampling — an attacker queries the same IOC
  N times, averages the responses, and recovers the true count (the
  noise averages to zero as N grows). The fix is to make the noise
  DETERMINISTIC for a given (IOC, time-bucket): the same query
  within the bucket returns the same noisy answer, and the noise
  doesn't average out across repeats.

  The time bucket is 1 hour. Within an hour, every query for the
  same IOC gets the same noisy count. The bucket boundary refreshes
  the noise — this is intentional, so the true count can change
  meaningfully over time and the noise tracks it, but not so often
  that repeated-sampling within a short window leaks.

  The seed for the deterministic noise is HMAC(per-bundle-secret,
  ioc_canonical + hour_bucket). The attacker cannot reproduce the
  noise offline (no secret), so they can't compute "true count =
  noisy count - known noise" either.

Privacy budget:

  ε=1.0 per (IOC, hour). A determined attacker who probes K
  different IOCs once each within an hour gets K independent
  noisy counts with the standard Laplace tail (95% within ±3
  count). Probability of any one count being off by ±10 is < 0.1%.
  For aggregate-count use-cases ("how many tenants saw this IOC"),
  this is plenty accurate while preserving k-anonymity-adjacent
  privacy floors.

References:
  Dwork & Roth (2014). The Algorithmic Foundations of Differential
  Privacy. The Laplace mechanism is the textbook ε-DP method for
  numeric queries.

Banked 2026-05-21 — first piece of Section B (read-side hardening).
"""
from __future__ import annotations

import hashlib
import hmac
import math
import random
from datetime import datetime, timezone
from typing import Optional


# DP privacy parameter. ε=1.0 is a reasonable default for
# aggregate-count queries on a multi-tenant security pool — tight
# enough to provide meaningful privacy, loose enough that the
# noisy counts stay useful. Per-bundle override is a future feature
# (would live in bundle_config alongside the k-anonymity threshold).
EPSILON = 1.0


# Hour bucket — 3600 seconds in UTC. The bucket boundary is the same
# across all readers; "same query within the same hour returns the
# same noisy answer" is the property we need.
_BUCKET_SECONDS = 3600


def _hour_bucket(now: datetime) -> str:
    """Return an ISO-8601 timestamp truncated to the hour boundary.
    Used as one input to the deterministic-noise seed."""
    if now.tzinfo is None:
        # Treat naive datetimes as UTC. Don't crash; just normalize.
        now = now.replace(tzinfo=timezone.utc)
    truncated = now.replace(minute=0, second=0, microsecond=0)
    return truncated.isoformat()


def _seed(secret: bytes, ioc_canonical: str, when: datetime) -> int:
    """Compute the deterministic 64-bit seed for the Laplace sampler.

    `secret` is the per-bundle HMAC secret (same one used for tenant
    identity). `ioc_canonical` is the post-M8-canonicalized IOC value.
    `when` is the query timestamp; we truncate to the hour to get the
    bucket.

    Mixing the bundle secret in defeats offline reproduction of the
    noise by an attacker who knows the (IOC, hour) but not the secret.
    """
    bucket = _hour_bucket(when)
    msg = f"{ioc_canonical}|{bucket}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    # Take the first 8 bytes as a 64-bit seed.
    return int.from_bytes(digest[:8], "big")


def _laplace(rng: random.Random, scale: float) -> float:
    """Sample one value from Laplace(0, scale). Uses the inverse-CDF
    method against the supplied RNG."""
    # Uniform in (-0.5, 0.5); skip exact 0 to keep ln() finite.
    u = rng.random() - 0.5
    while u == 0.0:
        u = rng.random() - 0.5
    # Inverse CDF: noise = -scale * sign(u) * ln(1 - 2|u|).
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def noisy_count(
    true_count: int,
    ioc_canonical: str,
    *,
    when: Optional[datetime] = None,
    secret: Optional[bytes] = None,
    epsilon: float = EPSILON,
) -> int:
    """Return a Laplace-noised count for the given IOC at the given
    time-bucket. Same inputs → same output (frozen noise).

    Parameters:
      true_count    — the exact count to mask
      ioc_canonical — the canonicalized IOC value (per M8)
      when          — query timestamp; defaults to now-UTC
      secret        — per-bundle HMAC secret; defaults to the cached
                      sanitized-pool secret loaded by identity.py
      epsilon       — DP privacy parameter; lower = more noise.
                      Default 1.0.

    Returns a non-negative integer.

    Invariants:
      - Same (true_count, ioc_canonical, when, secret, epsilon) →
        always the same integer.
      - Two true_counts differing by ≤1 produce outputs whose
        log-ratio is bounded by ε (the ε-DP guarantee).
      - Output is non-negative (a count of -3 makes no sense; clamp
        at 0).
    """
    if when is None:
        when = datetime.now(timezone.utc)
    if secret is None:
        from apps.octo.sanitized_pool.identity import _get_cached_secret
        _, secret = _get_cached_secret()
    if epsilon <= 0.0:
        raise ValueError(f"epsilon must be positive (got {epsilon})")

    rng = random.Random()
    rng.seed(_seed(secret, ioc_canonical, when))
    scale = 1.0 / epsilon
    noise = _laplace(rng, scale)
    noisy = round(true_count + noise)
    return max(0, noisy)


def exact_count(true_count: int) -> int:
    """Pass-through identity function. Documented as a parallel API
    surface to `noisy_count` so caller sites read symmetrically:

        count = (noisy_count(...) if not privileged
                 else exact_count(true_count))

    Trivially defined, but keeps the privileged/unprivileged split
    visible in the caller code rather than buried in a ternary.
    """
    return max(0, true_count)
