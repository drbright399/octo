"""The Datto FEED — the inventory poller's per-site device lists, handed to
entity resolution with the site's tenant slug (the UniFi feed's pattern).

  wants(slug) -> bool                       (kept for older consumers; the
                                            poller reads EVERY mapped site —
                                            v0.17.2, D)
  on_inventory(slug, site_uid, snapshot)    every 30 min per MAPPED site:
      {instance_id, site_uid, polled_at, complete, devices[{uid, hostname,
       device_type, online, last_seen, int_ip, ext_ip, os, domain, ocsf}]}
      — a WHOLE list (every page) or `complete: False` (nothing is marked
      missing from a partial list)
  audit_due(slug, instance_id, site_uids, before, limit, skip_types)
      -> [(device uid, site uid, audit_at)]  (v0.17.3) the devices of the
      tenant's list (those sites, not missing, not of a `skip_types` device
      type) whose audit was never read or was read before `before` — never
      audited first, then the oldest
  on_audit(slug, snapshot) -> bool          one device's audit, ONLY:
      {instance_id, site_uid, device_uid, audited_at, serial, manufacturer,
       model, ocsf} — True when the device's row took it

Only mapped sites of ACTIVE tenants are read; there is no default tenant
and no auto-create on this path. A consumer that raises never stops the
poller.
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
        logger.warning("[datto-feed] %s failed (%s)", method, type(exc).__name__)
        return default
