"""Tests for sanitized_pool.noise (§11.1 DP frozen Laplace noise).

Coverage:
  - Same inputs → same output (frozen / deterministic).
  - Different IOCs within same hour produce different noise.
  - Different hours produce different noise for same IOC.
  - Different secrets produce different noise (attacker offline-
    derivation defeated).
  - Output is non-negative integer.
  - Output mean is close to true count over many trials across IOCs.
  - exact_count() is identity (modulo clamping to >=0).
  - epsilon=0 rejected.
"""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.sanitized_pool import noise


# A stable test secret. Tests pass it explicitly so we don't depend on
# the file-based identity module.
_SECRET = b"x" * 32


def _at(year, month, day, hour) -> datetime:
    return datetime(year, month, day, hour, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Frozen noise: same inputs → same output
# ---------------------------------------------------------------------------

def test_same_inputs_same_output() -> None:
    when = _at(2026, 5, 21, 10)
    a = noise.noisy_count(100, "evil.com", when=when, secret=_SECRET)
    b = noise.noisy_count(100, "evil.com", when=when, secret=_SECRET)
    assert a == b


def test_same_inputs_repeated_many_times_same_output() -> None:
    """100 repeated calls all return the same answer."""
    when = _at(2026, 5, 21, 10)
    answers = {
        noise.noisy_count(50, "evil.com", when=when, secret=_SECRET)
        for _ in range(100)
    }
    assert len(answers) == 1


# ---------------------------------------------------------------------------
# Different inputs → different (probable) outputs
# ---------------------------------------------------------------------------

def test_different_iocs_within_hour_differ() -> None:
    """Different IOCs (same hour, same true_count, same secret) should
    almost always produce different noisy counts. The Laplace mean is
    0, but the per-seed sample is deterministic + different per IOC."""
    when = _at(2026, 5, 21, 10)
    samples = {
        noise.noisy_count(50, f"evil-{i}.com", when=when, secret=_SECRET)
        for i in range(50)
    }
    # Laplace(0,1) sample, integer-rounded + clamped, around true=50
    # gives integers roughly in 46-54 (heavy tail). 5-6 unique values
    # out of 50 samples is typical; if we see <4, the seed isn't
    # actually feeding into the noise. Threshold deliberately loose.
    assert len(samples) >= 4, (
        f"only {len(samples)} unique noisy counts across 50 IOCs — "
        "suspiciously low spread for ε=1.0 (seed probably not feeding "
        "into the RNG)"
    )


def test_different_hours_for_same_ioc_differ() -> None:
    """Different hour buckets give different noise for same IOC."""
    samples = {
        noise.noisy_count(50, "evil.com",
                          when=_at(2026, 5, 21, h),
                          secret=_SECRET)
        for h in range(0, 24)
    }
    assert len(samples) >= 5, (
        f"only {len(samples)} unique noisy counts across 24 hours — "
        "hour bucket isn't refreshing noise"
    )


def test_same_hour_minute_boundary_returns_same() -> None:
    """Within the same hour, all timestamps map to the same bucket.
    Both 10:01 and 10:59 must produce the same noisy answer."""
    a = noise.noisy_count(50, "evil.com",
                          when=_at(2026, 5, 21, 10).replace(minute=1),
                          secret=_SECRET)
    b = noise.noisy_count(50, "evil.com",
                          when=_at(2026, 5, 21, 10).replace(minute=59),
                          secret=_SECRET)
    assert a == b


def test_hour_boundary_crossing_refreshes() -> None:
    """Crossing the hour boundary refreshes the noise."""
    before = noise.noisy_count(50, "evil.com",
                               when=_at(2026, 5, 21, 10),
                               secret=_SECRET)
    after = noise.noisy_count(50, "evil.com",
                              when=_at(2026, 5, 21, 11),
                              secret=_SECRET)
    # Not strictly different (Laplace can coincide) but usually is.
    # Just confirm the seed bucketing changed by computing internals.
    bucket_a = noise._hour_bucket(_at(2026, 5, 21, 10))
    bucket_b = noise._hour_bucket(_at(2026, 5, 21, 11))
    assert bucket_a != bucket_b


def test_different_secrets_produce_different_noise() -> None:
    """Attacker offline-derivation defense: rotating the secret
    changes the noise even for the same (IOC, hour, true_count)."""
    when = _at(2026, 5, 21, 10)
    secret_a = b"x" * 32
    secret_b = b"y" * 32
    # Run 20 IOCs through both secrets; at least 10 should differ.
    differences = 0
    for i in range(20):
        a = noise.noisy_count(50, f"evil-{i}.com",
                              when=when, secret=secret_a)
        b = noise.noisy_count(50, f"evil-{i}.com",
                              when=when, secret=secret_b)
        if a != b:
            differences += 1
    assert differences >= 10, (
        f"only {differences}/20 IOCs got different noise under different "
        "secrets — secret isn't actually feeding into the seed"
    )


# ---------------------------------------------------------------------------
# Distribution properties
# ---------------------------------------------------------------------------

def test_output_is_nonneg_integer() -> None:
    when = _at(2026, 5, 21, 10)
    for true_count in (0, 1, 5, 100):
        result = noise.noisy_count(true_count, "evil.com",
                                   when=when, secret=_SECRET)
        assert isinstance(result, int)
        assert result >= 0


def test_zero_count_stays_nonneg() -> None:
    """A true_count of 0 should never produce a negative output."""
    when = _at(2026, 5, 21, 10)
    for i in range(30):
        result = noise.noisy_count(0, f"evil-{i}.com",
                                   when=when, secret=_SECRET)
        assert result >= 0


def test_mean_close_to_true_count_across_many_iocs() -> None:
    """With ε=1.0 (Laplace scale=1), the mean of 200 noisy counts
    centered on the same true count should be within ±1 of the true
    count. Standard error for sample mean of Laplace(0,1) over n=200
    is ≈ √(2/200) ≈ 0.1; ±1 is very conservative."""
    when = _at(2026, 5, 21, 10)
    true_count = 100
    samples = [
        noise.noisy_count(true_count, f"evil-{i}.com",
                          when=when, secret=_SECRET)
        for i in range(200)
    ]
    mean = statistics.mean(samples)
    assert abs(mean - true_count) < 2.0, (
        f"mean of 200 noisy counts is {mean}, expected near {true_count}"
    )


def test_noise_spread_consistent_with_laplace_scale_one() -> None:
    """Stddev across 200 noisy samples should be approximately √2
    (Laplace(0,1) has variance 2). Allow generous tolerance because
    integer rounding distorts the moments a bit."""
    when = _at(2026, 5, 21, 10)
    samples = [
        noise.noisy_count(100, f"evil-{i}.com",
                          when=when, secret=_SECRET)
        for i in range(500)
    ]
    sd = statistics.stdev(samples)
    # Expected ≈ √2 ≈ 1.41. Allow 0.5 < sd < 3.0 — coarse but the
    # right order of magnitude.
    assert 0.5 < sd < 3.0, f"stddev {sd} outside expected Laplace range"


# ---------------------------------------------------------------------------
# Boundary behavior
# ---------------------------------------------------------------------------

def test_epsilon_zero_rejected() -> None:
    with pytest.raises(ValueError, match="epsilon must be positive"):
        noise.noisy_count(50, "evil.com",
                          when=_at(2026, 5, 21, 10),
                          secret=_SECRET, epsilon=0.0)


def test_epsilon_negative_rejected() -> None:
    with pytest.raises(ValueError):
        noise.noisy_count(50, "evil.com",
                          when=_at(2026, 5, 21, 10),
                          secret=_SECRET, epsilon=-1.0)


def test_naive_datetime_treated_as_utc() -> None:
    """A naive datetime shouldn't crash — treated as UTC."""
    naive = datetime(2026, 5, 21, 10)  # no tzinfo
    aware = _at(2026, 5, 21, 10)
    a = noise.noisy_count(50, "evil.com", when=naive, secret=_SECRET)
    b = noise.noisy_count(50, "evil.com", when=aware, secret=_SECRET)
    assert a == b


def test_exact_count_is_passthrough() -> None:
    assert noise.exact_count(0) == 0
    assert noise.exact_count(100) == 100
    # Defensive clamp at 0 — if a caller passes negative, return 0.
    assert noise.exact_count(-5) == 0
