"""Canonical `received_at` normalization — ONE helper for every adapter.

`events.received_at` is the ordering key, the dashboard bucketing key
(SQLite date functions only accept the canonical shape) and one third of the
ingest idempotency identity `(source, payload_sha256, received_at)`. Every
writer must therefore store the same form:

    YYYY-MM-DDTHH:MM:SS.mmmZ      (UTC, millisecond precision)

Lives under `apps.octo.ingest` (not `apps/octo/adapters/`, which adapter
discovery walks as vendor subpackages) so adapters share it without a
cross-adapter import.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Optional

_EPOCH_STRING_RE = re.compile(r"\d+(?:\.\d+)?")
_ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")


def format_utc_ms(dt: datetime) -> str:
    """Single source of truth for OCTO's ISO8601-UTC-millisecond wire format.

    Deriving the ms from dt.microsecond (not from `seconds % 1`) keeps the
    sub-second and seconds fields from the same rounded instant."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def utcnow_iso() -> str:
    return format_utc_ms(datetime.now(timezone.utc))


def _from_epoch(seconds: float) -> Optional[datetime]:
    if not math.isfinite(seconds) or seconds < 0:
        return None
    if seconds >= 1e12:  # epoch MILLISECONDS -> seconds (guards year-overflow)
        seconds /= 1000.0
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _from_string(text: str) -> Optional[datetime]:
    # strptime %z first: it accepts the colon-less '+0000' offset some vendors
    # emit, which fromisoformat rejects on older Pythons.
    for fmt in _ISO_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_timestamp(
    value: Any,
    *,
    allow_epoch: bool = False,
    naive_is_utc: bool = False,
) -> str:
    """Normalize a vendor timestamp to canonical UTC ms, or "" if unusable.

    Accepts ISO8601 strings with `Z` or any numeric offset (converted to UTC,
    not re-labelled). With ``allow_epoch``, also int/float/all-digit-string
    epochs (seconds, or milliseconds when >= 1e12). An ISO string with NO zone
    is ambiguous: "" unless the caller asserts ``naive_is_utc``.

    Returns "" for everything else — None, bool (an int subclass that would
    otherwise read as 1970), negative or non-finite epochs, containers, free
    text — so the caller chooses the fallback. NEVER raises: a normalizer
    exception would wedge a poller or turn a real alert into a 4xx.
    """
    try:
        if isinstance(value, bool):
            return ""
        parsed: Optional[datetime] = None
        if isinstance(value, (int, float)):
            if allow_epoch:
                parsed = _from_epoch(float(value))
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return ""
            if _EPOCH_STRING_RE.fullmatch(text):
                if allow_epoch:
                    parsed = _from_epoch(float(text))
            else:
                parsed = _from_string(text)
        if parsed is None:
            return ""
        if parsed.tzinfo is None:
            if not naive_is_utc:
                return ""
            parsed = parsed.replace(tzinfo=timezone.utc)
        return format_utc_ms(parsed)
    except Exception:  # noqa: BLE001 — never-raise is the contract
        return ""
