"""Buoy service health — ONE rollup for the heartbeat publisher, the fleet
view and source health.

A buoy heartbeats the units it watches with their `systemctl is-active`
state and — from v0.11 — their `systemctl is-enabled` state (`enabled`).

RETIRED (grey, never a fault) needs BOTH:
  * the OPERATOR retired the unit, server-side: it is on the bundle's list
    of retired units (`OCTO_BUOY_RETIRED_UNITS`, comma-separated; default
    `octo-forwarder`, retired 2026-09-29 with the legacy host) — the buoy's
    own word is never enough; and
  * the buoy says it is disabled / masked and not running.
Why the list: "disabled" alone is exactly what an attacker on a buoy — or a
technician's troubleshooting step — leaves behind with `systemctl disable
--now wazuh-agent suricata` (MITRE T1562.001, impair defenses). Inferring
"retired" from that turned a blinded sensor green. A watched unit that is
disabled but NOT on the list keeps the old rule — not active = degraded —
and is named as "disabled" (`disabled_units`), so the change is visible.

A unit whose enablement is unknown (a heartbeat daemon older than v0.11,
systemctl could not say, the unit file is gone) keeps the old rule too.

Rollup: no services → unknown; tailscaled not active → red (the tunnel);
every non-retired unit active → green; otherwise yellow.
"""
from __future__ import annotations

import os
from typing import Any, Mapping, Optional

# `systemctl is-enabled` answers meaning "switched off".
RETIRED_ENABLEMENT = frozenset({"disabled", "masked", "masked-runtime"})
TAILNET_UNIT = "tailscaled"
RETIRED_UNITS_ENV = "OCTO_BUOY_RETIRED_UNITS"
DEFAULT_RETIRED_UNITS = frozenset({"octo-forwarder"})


def retired_allowlist(env: Optional[Mapping[str, str]] = None) -> frozenset[str]:
    """The units an operator retired on purpose (bundle-wide). Unset → the
    default; set (even empty) → exactly that list. The tailnet unit is never
    retired: without it the buoy is unreachable."""
    raw = (os.environ if env is None else env).get(RETIRED_UNITS_ENV)
    units = DEFAULT_RETIRED_UNITS if raw is None else frozenset(
        u.strip() for u in str(raw).split(",") if u.strip())
    return units - {TAILNET_UNIT}


def service_state(entry: Any) -> str:
    """The `state` of a service entry (legacy flat string or dict)."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, Mapping):
        s = entry.get("state")
        return s if isinstance(s, str) else "unknown"
    return "unknown"


def service_enabled(entry: Any) -> str | None:
    if isinstance(entry, Mapping):
        e = entry.get("enabled")
        return e if isinstance(e, str) and e else None
    return None


def _switched_off(entry: Any) -> bool:
    return (service_enabled(entry) in RETIRED_ENABLEMENT
            and service_state(entry) != "active")


def unit_retired(unit: str, entry: Any,
                 allowlist: Optional[frozenset[str]] = None) -> bool:
    """On the operator's retired list AND disabled / masked and not running."""
    allowed = retired_allowlist() if allowlist is None else allowlist
    return unit in allowed and _switched_off(entry)


def retired_units(services: Mapping[str, Any],
                  allowlist: Optional[frozenset[str]] = None) -> list[str]:
    allowed = retired_allowlist() if allowlist is None else allowlist
    return sorted(u for u, e in services.items() if unit_retired(u, e, allowed))


def disabled_units(services: Mapping[str, Any],
                   allowlist: Optional[frozenset[str]] = None) -> list[str]:
    """Disabled / masked and not running, but NOT retired by the operator:
    a fault (degraded), named so a security tool switched off shows as such."""
    allowed = retired_allowlist() if allowlist is None else allowlist
    return sorted(u for u, e in services.items()
                  if _switched_off(e) and not unit_retired(u, e, allowed))


def rollup(services: Mapping[str, Any],
           allowlist: Optional[frozenset[str]] = None) -> str:
    """'unknown' | 'red' | 'green' | 'yellow' — see the module docstring."""
    if not services:
        return "unknown"
    if service_state(services.get(TAILNET_UNIT, {})) != "active":
        return "red"
    allowed = retired_allowlist() if allowlist is None else allowlist
    bad = [u for u, e in services.items()
           if service_state(e) != "active" and not unit_retired(u, e, allowed)]
    return "yellow" if bad else "green"
