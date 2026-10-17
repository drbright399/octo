"""FR2 — detection blindness, measured by INTAKE HEALTH, never by event
arrival (event-driven sources are naturally sparse: a quiet Datto account is
not a blind one).

What counts (each for > 60 minutes):
  * a detection source's integration failing every poll (`vendor_contact`:
    the first failure of the current run, `failing_since`) — Datto RMM,
    UniFi, NextDNS, RocketCyber, Wazuh;
  * the Datto open-alert list at its cap every poll (`DattoPoller.
    intake_health`: alerts beyond the cap are not being read);
  * the tier worker's heartbeat stale (no threat correlation at all).

Display (design 4.3 FR2):
  * an internal banner, "Athena is blind to <source> since HH:MM" (operators);
  * a per-tenant coverage reason on the threat layer: YELLOW when the
    blindness is the tenant's own (an integration that serves only that
    tenant), NOTICE plus the banner when fleet-wide (it serves several);
  * an integration mapped to NO tenant — or whose mapping cannot be read —
    is the banner only (`internal`): it covers no client, so it is painted on
    none (never on every one).
FR2 never opens, changes or masks an incident: it is a condition (Yellow at
most) — an open Red / Black stays exactly what it is.

Not measured in slice 1 (stated, not guessed): the Datto webhook doorbell's
error rate, a single UniFi site's system-log read, a single NextDNS
profile's security round — those layers already read Unknown when stale.
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo.threat import registry
from apps.octo.threat.store import parse

logger = logging.getLogger(__name__)

BLIND_AFTER = timedelta(minutes=60)
DETECTION_VENDORS: dict[str, str] = {
    "datto": "Datto RMM", "unifi": "UniFi", "nextdns": "NextDNS",
    "rocketcyber": "RocketCyber", "wazuh": "Wazuh",
}
WORKER_INTERVAL_SEC = 30.0
WORKER_STALE = timedelta(seconds=WORKER_INTERVAL_SEC * 2 + 60)
HEARTBEAT_KEY = "heartbeat"


@dataclass(frozen=True)
class Blind:
    source: str
    label: str
    since: str
    tenants: tuple[str, ...]          # () = every tenant (unless internal)
    fleet_wide: bool
    why: str
    internal: bool = False
    """The banner only: it covers no client (an integration mapped to no
    tenant, or whose mapping could not be read)."""

    def covers(self, slug: str) -> bool:
        if self.internal:
            return False
        return not self.tenants or slug in self.tenants

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "label": self.label, "since": self.since,
                "fleet_wide": self.fleet_wide, "why": self.why,
                "tenants": list(self.tenants), "internal": self.internal}


def worker_heartbeat() -> Optional[datetime]:
    hb = registry.state_get(HEARTBEAT_KEY)
    return parse(hb.get("at")) if isinstance(hb, dict) else None


def worker_fresh(now: datetime) -> bool:
    at = worker_heartbeat()
    return at is not None and now - at <= WORKER_STALE


def _instances() -> list[Any]:
    from apps.octo.instances.manager import list_instances

    try:
        return [r for r in list_instances() if r.vendor_slug in DETECTION_VENDORS
                and r.disabled_at is None]
    except sqlite3.Error:
        return []


def _tenants(record: Any) -> Optional[tuple[str, ...]]:
    """The tenants the instance serves; None when that cannot be read."""
    from apps.octo.instances import tenant_map

    try:
        return tuple(sorted(tenant_map.instance_tenant_slugs(record) - {"_unmapped", ""}))
    except sqlite3.Error:
        return None


def _blind(source: str, label: str, since: str, tenants: Optional[tuple[str, ...]],
           why: str) -> Blind:
    if not tenants:
        # Mapped to no client (or the mapping is unreadable): the banner only.
        return Blind(source, label, since, (), fleet_wide=False, internal=True,
                     why=why + (" (its client mapping could not be read)" if tenants is None
                                else " (it is mapped to no client)"))
    return Blind(source, label, since, tenants, fleet_wide=len(tenants) != 1, why=why)


def freshness(slug: Optional[str], now: Optional[datetime] = None) -> list[dict[str, Any]]:
    """The per-source freshness MATRIX an incident freezes at open (G8): every
    detection integration serving `slug` (or mapped to none of it — the
    banner's) with its last good contact and whether it is failing, plus the
    tier worker's heartbeat. Never raises (a page never fails for it)."""
    from apps.octo.instances import vendor_contact

    now = now or datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    try:
        for rec in _instances():
            tenants = _tenants(rec)
            if slug is not None and tenants and slug not in tenants:
                continue
            snap = vendor_contact.snapshot(rec.id)
            since = parse(snap.get("failing_since"))
            out.append({"source": rec.vendor_slug, "label": DETECTION_VENDORS[rec.vendor_slug],
                        "last_ok_at": snap.get("last_ok_at"),
                        "failing_since": snap.get("failing_since"),
                        "blind": bool(snap.get("consecutive_failures") and since is not None
                                      and now - since > BLIND_AFTER)})
        hb = worker_heartbeat()
        out.append({"source": "tier_worker", "label": "threat correlation",
                    "last_ok_at": hb.strftime("%Y-%m-%dT%H:%M:%S.000Z") if hb else None,
                    "failing_since": None,
                    "blind": hb is None or now - hb > WORKER_STALE})
    except Exception as exc:  # noqa: BLE001
        logger.warning("[intake] freshness not read (%s)", type(exc).__name__)
    return out


def blind_sources(manager: Any, now: Optional[datetime] = None, *,
                  check_worker: bool = True) -> list[Blind]:
    from apps.octo.instances import vendor_contact

    now = now or datetime.now(timezone.utc)
    out: list[Blind] = []
    for rec in _instances():
        label = DETECTION_VENDORS[rec.vendor_slug]
        snap = vendor_contact.snapshot(rec.id)
        since = parse(snap.get("failing_since"))
        if snap.get("consecutive_failures") and since is not None and now - since > BLIND_AFTER:
            out.append(_blind(rec.vendor_slug, label, snap["failing_since"], _tenants(rec),
                              f"every {label} poll has failed since then"))
        if rec.vendor_slug == "datto" and manager is not None:
            health = _datto_health(manager, rec.id)
            capped = parse(health.get("capped_since")) if health else None
            if capped is not None and now - capped > BLIND_AFTER:
                out.append(_blind("datto_cap", "Datto RMM (open-alert cap)",
                                  health["capped_since"], _tenants(rec),
                                  "the open-alert list has been at its cap on every poll — "
                                  "alerts beyond it are not being read"))
    if check_worker:
        at = worker_heartbeat()
        if at is None or now - at > WORKER_STALE:
            out.append(Blind("tier_worker", "threat correlation",
                             at.strftime("%Y-%m-%dT%H:%M:%S.000Z") if at else "",
                             (), fleet_wide=True, why="the tier worker is not running"))
    return out


def _datto_health(manager: Any, instance_id: int) -> Optional[dict[str, Any]]:
    try:
        adapter = manager.running_adapter(instance_id)
    except Exception:  # noqa: BLE001
        return None
    poller = getattr(adapter, "poller", None) or getattr(adapter, "_poller", None)
    fn = getattr(poller, "intake_health", None)
    if not callable(fn):
        return None
    try:
        out = fn()
    except Exception:  # noqa: BLE001
        return None
    return out if isinstance(out, dict) else None
