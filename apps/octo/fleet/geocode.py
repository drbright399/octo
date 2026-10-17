"""Address → coordinates for the Fleet's site location editor — ON DEMAND
only (an operator types an address and presses Find; owner decision
2026-10-02: "Census geocoder").

  US Census Bureau geocoder (public, free, no key):
    GET https://geocoding.geo.census.gov/geocoder/locations/onelineaddress
        ?address=<the typed text>&benchmark=Public_AR_Current&format=json
    → result.addressMatches[]: {matchedAddress, coordinates{x: lng, y: lat}}

WHAT LEAVES THE BOX: the typed address string — nothing else (no tenant, no
client name, no site, no operator). Nothing is cached or stored here: the
operator picks a match and SAVES it as the site's location (the coordinate
pair plus the matched address as its label), which is then locked — never
looked up again. The address is never logged (a failure logs its class
only).

SWITCH: `OCTO_GEOCODER` = `census` (default) | `off`. Any other value is
treated as off (an outbound call is opt-out, never guessed). Off: the API
says "address lookup is turned off on this server" and the console hides the
Find button; pasting coordinates or a map link still works (client-side, no
outside call).

RATE LIMIT: per operator, `RATE_MAX` lookups per `RATE_WINDOW_SEC`.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Optional

from apps.octo.fleet.locations import clean_label, valid_pair

logger = logging.getLogger(__name__)

GEOCODER_ENV = "OCTO_GEOCODER"
CENSUS_URL = "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress"
CENSUS_BENCHMARK = "Public_AR_Current"
TIMEOUT_SEC = 10.0
MAX_MATCHES = 3
MAX_RESPONSE_BYTES = 256 * 1024
ADDRESS_MIN, ADDRESS_MAX = 5, 200
RATE_MAX = 10
RATE_WINDOW_SEC = 60.0


class GeocodeError(Exception):
    """Operator-safe text (never the address, never the provider's body)."""

    def __init__(self, message: str, *, kind: str = "unavailable") -> None:
        super().__init__(message)
        self.kind = kind            # 'invalid' | 'off' | 'rate' | 'unavailable'


@dataclass(frozen=True)
class Match:
    lat: float
    lng: float
    label: str

    def as_dict(self) -> dict[str, Any]:
        return {"lat": self.lat, "lng": self.lng, "label": self.label}


def provider() -> Optional[str]:
    """'census', or None when address lookup is off."""
    raw = (os.environ.get(GEOCODER_ENV) or "census").strip().lower()
    return "census" if raw == "census" else None


def clean_address(value: Any) -> str:
    """One line, printable, collapsed whitespace — or GeocodeError."""
    if not isinstance(value, str):
        raise GeocodeError("enter an address", kind="invalid")
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    if not ADDRESS_MIN <= len(text) <= ADDRESS_MAX:
        raise GeocodeError(f"an address is {ADDRESS_MIN}–{ADDRESS_MAX} characters "
                           "(street, city, state)", kind="invalid")
    return text


class RateLimiter:
    """Per-operator sliding window."""

    def __init__(self, limit: int = RATE_MAX, window_sec: float = RATE_WINDOW_SEC,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._limit, self._window, self._clock = limit, window_sec, clock
        self._hits: dict[int, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, operator_id: int) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(int(operator_id), deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True


LIMITER = RateLimiter()


def _parse(body: Any) -> list[Match]:
    matches = (((body or {}).get("result") or {}).get("addressMatches")
               if isinstance(body, dict) else None)
    out: list[Match] = []
    for m in matches if isinstance(matches, list) else []:
        if not isinstance(m, dict):
            continue
        coords = m.get("coordinates") if isinstance(m.get("coordinates"), dict) else {}
        pair = valid_pair(coords.get("y"), coords.get("x"))
        if pair is None:
            continue
        label = clean_label(m.get("matchedAddress"))
        if not label:
            continue
        out.append(Match(round(pair[0], 6), round(pair[1], 6), label))
        if len(out) >= MAX_MATCHES:
            break
    return out


def lookup(address: str, *,
           opener: Callable[..., Any] = urllib.request.urlopen) -> list[Match]:
    """Up to MAX_MATCHES matches for `address` (already `clean_address`ed);
    [] when the provider knows none. GeocodeError when off or unreachable."""
    if provider() is None:
        raise GeocodeError("address lookup is turned off on this server — paste the "
                           "coordinates or a map link instead", kind="off")
    query = urllib.parse.urlencode({"address": address, "benchmark": CENSUS_BENCHMARK,
                                    "format": "json"})
    req = urllib.request.Request(f"{CENSUS_URL}?{query}", headers={
        "Accept": "application/json", "User-Agent": "athena-octo-fleet-geocoder/1"})
    try:
        with opener(req, timeout=TIMEOUT_SEC) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("[fleet-geocode] the address lookup failed (%s)", type(exc).__name__)
        raise GeocodeError("the address lookup service could not be reached — try again, "
                           "or paste the coordinates or a map link") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        logger.warning("[fleet-geocode] the address lookup answer was too large")
        raise GeocodeError("the address lookup service answered unexpectedly")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        logger.warning("[fleet-geocode] the address lookup answer was not JSON")
        raise GeocodeError("the address lookup service answered unexpectedly") from None
    return _parse(body)
