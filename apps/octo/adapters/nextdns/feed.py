"""The NextDNS FEED — what the poller hands to entity resolution, per MAPPED
profile, with that profile's tenant slug (the UniFi feed's pattern).

Two reads exist ONLY for the feed, both per PROFILE (never per device), both
through the key's one limiter at health priority, and only for a tenant
whose consumer `wants` them (entity resolution switched on for it):

  DEVICES  each closed clock hour: GET analytics/devices (from = the hour,
           to = its end) — every device NextDNS identified (the NextDNS app's
           device id / name / model / LAN address) with its query count. If
           the endpoint is refused (HTTP 400 / 404) three times in a row ON
           ONE PROFILE, that profile samples ONE page of the hour's log
           (limit 1000, newest first) instead, and analytics/devices is asked
           again every 6 hours; the hour counts as read WHOLE only when that
           page held the whole hour (no cursor) — otherwise a device absent
           from the page is UNKNOWN for that hour, never silent.
  SEED     once per profile and UTC day, the 14 days before today: GET
           analytics/devices for the day — so a device whose app was already
           dead when the client was switched on is known and watched.
  IPS      once per UTC day (yesterday): GET analytics/ips — queries per
           client IP. The consumer keeps only this tenant's own egress
           addresses (the L-EGRESS statistic); any other public address is
           counted, never stored. A refused day (400 / 403 / 404) is not
           asked again.

Device reads of EVERY profile come before the seed and the per-IP reads; the
start profile rotates each cycle; a 403 on one of these reads holds that
profile's read only (never the key, never the cycle); the whole feed runs
AFTER the cycle's lapse decisions and bucket closes.

Calls (all optional for a consumer; the default does nothing and wants
nothing):

  wants(slug) -> bool
  hours_needed(slug, profile_id, hours[ISO]) -> hours[ISO]   (not read yet)
  on_device_hour(slug, profile_id, {hour, complete, method, total,
                 devices[{id, name, model, local_ip, client, queries}], read_at})
  seed_days_needed(slug, profile_id, days[YYYY-MM-DD]) -> days   (not read yet)
  on_device_day(slug, profile_id, {day, devices[{id, name, model, local_ip,
                 queries}], read_at})
  day_needed(slug, profile_id, day) -> bool
  on_ip_day(slug, profile_id, {day, total, ips[[ip, queries]], read_at})
  pending_signals(slug) -> [{key, kind ('device_silent' | 'device_restored'),
                 …facts}]   the device-silence check's outbox: the POLLER
                 builds each payload (its OCSF mapping) and stores the alert
  signal_stored(slug, key, event_id)

A consumer that raises never stops the poller (logged; the next cycle asks
again).
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)


class NullConsumer:
    def wants(self, slug: str) -> bool:
        return False


_lock = threading.Lock()
_registered: Optional[Any] = None


def register(consumer: Optional[Any]) -> None:
    global _registered
    with _lock:
        _registered = consumer


def current() -> Any:
    with _lock:
        return _registered if _registered is not None else NullConsumer()


def call(consumer: Any, method: str, *args: Any, default: Any = None) -> Any:
    fn = getattr(consumer, method, None)
    if not callable(fn):
        return default
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 — a consumer never stops the poller
        logger.warning("[nextdns-feed] %s failed (%s)", method, type(exc).__name__)
        return default
