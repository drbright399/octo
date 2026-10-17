"""A made-up fleet for the Fleet v2 tests: sites in a FICTIONAL county
("Example County"), coordinates on a regular synthetic grid, TEST-NET
addresses, documentation ASNs (64496-64511), example.test names. No real
place, client, address or network.

`FakeManager` stands in for the running InstanceManager: `running_adapter(id)`
answers an object with `.poller` — the UniFi poller's read side
(`fleet_health`, `site_states`, `isp_outages`) or the NextDNS one
(`profile_states`, `snapshot`) — the exact methods the Fleet reads. The
instances, tenants and mappings themselves are REAL registry rows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from apps.octo.ingest.timestamps import format_utc_ms

SITE_ID = "f1x7517e0000000000000001"
COUNTY = "Example County"


def host(n: int) -> str:
    return f"F1X7{n:04d}000000000000000000000000000000000000000000000000:10000{n:04d}"


def scope(n: int) -> str:
    return f"{host(n)}/{SITE_ID}"


def grid(n: int) -> tuple[float, float]:
    """A synthetic grid — NOT a real site's coordinates."""
    return round(41.0 + (n % 8) * 0.06, 6), round(-101.0 + (n // 8) * 0.08, 6)


def fleet_site(n: int, *, name: Optional[str] = None, located: bool = True,
               connected: bool = True, gateways_offline: int = 0, devices_offline: int = 0,
               port_up: bool = True, internet_issues: int = 0, asn: int = 64500,
               isp: str = "Example ISP") -> dict[str, Any]:
    lat, lng = grid(n)
    return {
        "scope": scope(n), "host_id": host(n), "site_id": SITE_ID, "internal_ref": "default",
        "name": name or f"Example Site {n}", "console_name": f"console-{n}",
        "timezone": "America/Chicago",
        "location": ({"lat": lat, "long": lng, "radius": 100,
                      "text": f"{n} Example Road, {COUNTY}"} if located else {}),
        "wans": [{"wan": "WAN", "external_ip": f"203.0.113.{n % 250 + 1}", "asn": asn,
                  "isp": isp, "port_up": port_up, "nat_kind": "direct"}],
        "gateway_online": gateways_offline == 0, "host_connected": connected,
        "report_fresh": connected,
        "stats": {"devices_total": 6, "devices_offline": devices_offline + gateways_offline,
                  "gateways_offline": gateways_offline, "pending_updates": 1,
                  "critical_notifications": 0, "isp_name": isp, "isp_asn": asn,
                  "internet_issues": internet_issues,
                  "internet_issue_keys": [f"i{k}" for k in range(internet_issues)],
                  "wan_issue_keys": {}},
        "counts": {"totalDevice": 6},
    }


@dataclass
class FakeUnifiPoller:
    at: Optional[datetime]
    sites: dict[str, dict[str, Any]] = field(default_factory=dict)
    syslog_at: Optional[datetime] = None
    outages: list[dict[str, Any]] = field(default_factory=list)
    interval_sec: float = 300.0

    def fleet_health(self) -> dict[str, Any]:
        return {"at": format_utc_ms(self.at) if self.at else None,
                "interval_sec": self.interval_sec, "syslog_interval_sec": 300.0,
                "sites": {k: dict(v) for k, v in self.sites.items()}}

    def site_states(self) -> dict[str, dict[str, Any]]:
        at = format_utc_ms(self.syslog_at or self.at) if (self.syslog_at or self.at) else None
        return {s: {"scope": s, "last_syslog_at": at, "problem": None} for s in self.sites}

    def isp_outages(self) -> list[dict[str, Any]]:
        return list(self.outages)


@dataclass
class FakeNextDnsPoller:
    states: dict[str, dict[str, Any]] = field(default_factory=dict)
    interval_sec: float = 300.0
    pending_check_sec: float = 6 * 3600.0
    security_round_sec: Optional[float] = None

    def profile_states(self) -> dict[str, dict[str, Any]]:
        return {k: dict(v) for k, v in self.states.items()}

    def snapshot(self) -> dict[str, Any]:
        return {"interval_sec": self.interval_sec, "pending_check_sec": self.pending_check_sec,
                "security_round_sec": self.security_round_sec or self.interval_sec}


def dns_state(pid: str, slug: str, state: str, at: datetime, *, name: Optional[str] = None,
              missing: bool = False, checked_at: Optional[datetime] = None) -> dict[str, Any]:
    """Shaped like the real poller's `profile_states()` row: an ACTIVE /
    LAPSED profile carries its security check (`last_check_at` = `at`); a
    PENDING / NEW profile never had one (None) — only its status read
    (`health_at`); a MISSING one keeps its last check (`checked_at`, may be
    old) and its re-probe time (`health_at` = `at`)."""
    watched = state in ("active", "lapsed") and not missing
    last_check = at if watched else checked_at
    return {"profile_id": pid, "name": name or f"Profile {pid}", "tenant_slug": slug,
            "state": state, "missing": missing,
            "last_check_at": format_utc_ms(last_check) if last_check else None,
            "health_at": format_utc_ms(at)}


@dataclass
class _Adapter:
    poller: Any


class FakeManager:
    def __init__(self) -> None:
        self.pollers: dict[int, Any] = {}

    def running_adapter(self, instance_id: int) -> Any:
        poller = self.pollers.get(instance_id)
        return _Adapter(poller) if poller is not None else None


def ago(now: datetime, minutes: float) -> datetime:
    return now - timedelta(minutes=minutes)


def stamp_tier_worker(at: Optional[datetime] = None) -> None:
    """A fresh tier-worker heartbeat (Tier Black slice 1): without one every
    site's threat layer reads "threat correlator not running" (unknown) —
    the truth when no worker runs, which a test of something else must not
    trip over."""
    from datetime import timezone

    from apps.octo.threat import intake, registry

    now = at or datetime.now(timezone.utc)
    registry.state_put(intake.HEARTBEAT_KEY, {"at": format_utc_ms(now), "passes": 1}, now)
