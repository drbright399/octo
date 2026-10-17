"""normalize_timestamp — the one canonical received_at form for every adapter."""
from __future__ import annotations

import re

import pytest

from apps.octo.ingest.timestamps import normalize_timestamp, utcnow_iso

_CANONICAL = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


@pytest.mark.parametrize("raw,expected", [
    ("2026-09-19T12:00:00.000Z", "2026-09-19T12:00:00.000Z"),
    ("2026-09-19T12:00:00Z", "2026-09-19T12:00:00.000Z"),            # no ms
    ("2026-09-19T07:00:00-05:00", "2026-09-19T12:00:00.000Z"),       # CONVERTED
    ("2026-09-19T17:30:00.250+05:30", "2026-09-19T12:00:00.250Z"),
    ("2026-09-19T12:00:00.000+0000", "2026-09-19T12:00:00.000Z"),    # colon-less
    ("  2026-09-19T12:00:00Z  ", "2026-09-19T12:00:00.000Z"),
])
def test_iso_strings_become_canonical_utc_ms(raw, expected):
    assert normalize_timestamp(raw) == expected


@pytest.mark.parametrize("raw", [
    None, "", "   ", "x", "not-a-timestamp", "Sat Sep 19 12:00:00 2026",
    True, False, {"weird": "shape"}, [1], b"2026-09-19T12:00:00Z",
    -5, -5.0, float("nan"), float("inf"), 10**18, 1e30, "-5",
])
def test_unusable_values_are_empty_and_never_raise(raw):
    assert normalize_timestamp(raw, allow_epoch=True, naive_is_utc=True) == ""


def test_epochs_only_when_allowed():
    assert normalize_timestamp(1700000000) == ""
    assert normalize_timestamp("1700000000") == ""
    assert normalize_timestamp(1700000000, allow_epoch=True) == "2023-11-14T22:13:20.000Z"
    assert normalize_timestamp("1700000000", allow_epoch=True) == "2023-11-14T22:13:20.000Z"
    # >= 1e12 is epoch MILLISECONDS
    assert normalize_timestamp(1700000000123, allow_epoch=True) == "2023-11-14T22:13:20.123Z"


def test_zone_less_iso_is_ambiguous_unless_caller_asserts_utc():
    assert normalize_timestamp("2026-09-19T12:00:00") == ""
    assert (
        normalize_timestamp("2026-09-19T12:00:00", naive_is_utc=True)
        == "2026-09-19T12:00:00.000Z"
    )


def test_equal_instants_compare_equal_as_strings():
    """The poller cursor compares these lexically: 'Z' vs '.500Z' must not
    invert, and an offset form must not sort hours off."""
    a = normalize_timestamp("2026-09-19T12:00:00Z")
    b = normalize_timestamp("2026-09-19T12:00:00.500Z")
    c = normalize_timestamp("2026-09-19T07:00:00-05:00")
    assert a < b and a == c


def test_utcnow_iso_is_canonical():
    assert _CANONICAL.fullmatch(utcnow_iso())
