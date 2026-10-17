"""Dev-only synthetic event generator (Task #119f).

Emits varied-severity synthetic events into the active dev tenants via the
real IngestSink, so an operator can toggle "incoming traffic" on/off from
the topbar and watch the autonomous triage worker annotate it live —
without running a terminal script.

HARD-GATED to dev:
  * `synthetic_allowed()` requires OCTO_DEV_SYNTHETIC=1 (set only by
    start-dev-backend.sh) AND a dev data root: the strict check of
    `apps.octo.dev.dev_root` (resolved under ~/.octo-dev or strictly under
    /tmp or /var/tmp, never inside /var/lib/octo or ~/octo; a path that
    merely contains 'octo-dev' is not enough).
  * The emit path refuses outright if the data root isn't a dev root.
Neither holds in production, so this never runs there. The topbar toggle
is independently hidden outside Vite's dev MODE.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import random
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from shared_adapter_contract.types import CanonicalEvent

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.dev.dev_root import is_dev_data_root
from apps.octo.ingest.sink import SqliteIngestSink

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 10
# Per-tick volume — small, so the triage feed reads as a live trickle, not
# a flood. Severity weights skew realistic (mostly info/low) but include
# enough medium/high/critical that the disposition variety shows.
EVENTS_PER_TICK = 4
_SEVERITY_WEIGHTS = [
    ("info", 50), ("low", 25), ("medium", 15), ("high", 8), ("critical", 2),
]
_SOURCES = ["datto", "wazuh", "unifi", "rocketcyber"]
_HOSTS = ["web-01", "db-02", "fw-edge", "ws-1147", "vpn-gw", "mail-01"]

# Fraction of emitted events drawn from the curated scenario pool below
# (the rest are random baseline noise). Tuned so the feed regularly shows
# escalations + uncertain→LLM cases, not just noise.
SCENARIO_PROB = 0.4

# Curated "test alert" scenarios — realistic SOC alert shapes with FAKE,
# RFC-safe indicators (RFC 2606/6761 domains: .example/.test/.invalid;
# RFC 5737 IP TEST-NETs; obviously-fake hashes). NONE are real. They map to
# heuristic dispositions like so (with the LLM on, mediums get re-reasoned):
#   high/critical → escalate · medium → uncertain (→ LLM) · low → uncertain/noise
_SCENARIOS = [
    {"source": "wazuh", "severity": "high", "summary": "Outbound connection to suspected C2 domain",
     "indicator": "c2-beacon-panel.example", "indicator_type": "domain"},
    {"source": "datto", "severity": "critical", "summary": "Malware signature match on endpoint",
     "indicator": "deadbeef" * 8, "indicator_type": "sha256"},
    {"source": "datto", "severity": "high", "summary": "Credential phishing page visited",
     "indicator": "login-verify-account.example", "indicator_type": "domain"},
    {"source": "rocketcyber", "severity": "medium", "summary": "DNS query to newly-registered domain",
     "indicator": "secure-update-cdn.example", "indicator_type": "domain"},
    {"source": "wazuh", "severity": "medium", "summary": "Encoded PowerShell command executed",
     "indicator": None, "indicator_type": None},
    {"source": "unifi", "severity": "medium", "summary": "Connection to Tor exit node",
     "indicator": "198.51.100.7", "indicator_type": "ip"},  # RFC 5737 TEST-NET-2
    {"source": "rocketcyber", "severity": "medium", "summary": "Repeated failed admin authentications",
     "indicator": None, "indicator_type": None},
    {"source": "datto", "severity": "critical", "summary": "Ransomware-like mass file rename",
     "indicator": None, "indicator_type": None},
    {"source": "wazuh", "severity": "low", "summary": "Port scan from internal host",
     "indicator": "203.0.113.55", "indicator_type": "ip"},  # RFC 5737 TEST-NET-3
    {"source": "unifi", "severity": "medium", "summary": "Beaconing to dynamic DNS provider",
     "indicator": "home-server-update.example", "indicator_type": "domain"},
]

# Maps an indicator_type to the payload key the feature-extractor recognizes
# (apps/octo/agent/features.py::_INDICATOR_KEYS).
_INDICATOR_PAYLOAD_KEY = {"ip": "ip", "domain": "domain", "url": "url", "sha256": "sha256"}


def synthetic_allowed() -> bool:
    """True only in a dev environment that has explicitly opted in."""
    opted_in = os.environ.get("OCTO_DEV_SYNTHETIC", "0").lower() in ("1", "true")
    if not opted_in:
        return False
    return is_dev_data_root(paths.data_root())


def _weighted_severity(rng: random.Random) -> str:
    total = sum(w for _, w in _SEVERITY_WEIGHTS)
    pick = rng.uniform(0, total)
    acc = 0.0
    for sev, w in _SEVERITY_WEIGHTS:
        acc += w
        if pick <= acc:
            return sev
    return "info"


def _make_event(rng: random.Random, seq: int) -> tuple[str, CanonicalEvent]:
    """Build one synthetic (source, event). With probability SCENARIO_PROB
    it's a curated 'test alert' (sketchy domain / threat) so the agent has
    interesting things to triage; otherwise it's random baseline noise."""
    host = rng.choice(_HOSTS)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    vid = f"synthetic-{seq}-{rng.randint(1000, 9999)}"
    payload: dict = {"synthetic": True, "host": host}
    indicator = None
    indicator_type = None

    if rng.random() < SCENARIO_PROB:
        sc = rng.choice(_SCENARIOS)
        sev = sc["severity"]
        source = sc["source"]
        indicator = sc["indicator"]
        indicator_type = sc["indicator_type"]
        summary = f"[synthetic] {sc['summary']}"
        payload["scenario"] = sc["summary"]
        if indicator:
            payload[_INDICATOR_PAYLOAD_KEY.get(indicator_type, "ioc")] = indicator
    else:
        sev = _weighted_severity(rng)
        source = rng.choice(_SOURCES)
        summary = f"[synthetic] {sev} event on {host}"
        # ~30% of baseline events carry an IP so the IOC path exercises.
        if rng.random() < 0.3:
            indicator = f"203.0.113.{rng.randint(1, 254)}"  # TEST-NET-3
            indicator_type = "ip"
            payload["ip"] = indicator

    payload["severity"] = sev
    payload_sha256 = hashlib.sha256(f"{vid}{now}{sev}{host}".encode()).hexdigest()
    event = CanonicalEvent(
        vendor_event_id=vid,
        received_at=now,
        severity=sev,  # type: ignore[arg-type]
        indicator=indicator,
        indicator_type=indicator_type,  # type: ignore[arg-type]
        source_host=host,
        summary=summary,
        payload=payload,
        payload_sha256=payload_sha256,
    )
    return source, event


def _active_dev_tenants() -> list[str]:
    reg_path = paths.registry_db_path()
    if not reg_path.exists():
        return []
    reg = connect(reg_path, read_only=True)
    try:
        rows = reg.execute(
            "SELECT slug FROM clients WHERE status = 'active' ORDER BY slug"
        ).fetchall()
        return [r["slug"] for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        reg.close()


def emit_batch(rng: random.Random, *, n: int = EVENTS_PER_TICK) -> int:
    """Emit `n` synthetic events spread across active dev tenants. Returns
    the count actually ingested. Refuses outright on a non-dev data root."""
    if not is_dev_data_root(paths.data_root()):
        raise RuntimeError("refusing to emit synthetic traffic on a non-dev data root")
    tenants = _active_dev_tenants()
    if not tenants:
        return 0
    sink = SqliteIngestSink()
    emitted = 0
    for i in range(n):
        slug = rng.choice(tenants)
        source, event = _make_event(rng, seq=i)
        try:
            sink.ingest(slug, source, event)
            emitted += 1
        except FileNotFoundError:
            # tenant has no events.db provisioned — skip
            continue
    return emitted


class SyntheticTrafficGenerator:
    """Background emitter, toggled on/off at runtime from the topbar.

    The task is wired at startup only in dev; it idles until `enabled` is
    flipped true, then emits a small batch each tick. Mirrors the
    triage-worker start/stop shape.
    """

    def __init__(self, *, interval_seconds: Optional[int] = None) -> None:
        self._interval = interval_seconds or int(
            os.environ.get("OCTO_DEV_SYNTHETIC_INTERVAL", DEFAULT_INTERVAL_SECONDS)
        )
        self._enabled = False
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._rng = random.Random()
        self._emitted_total = 0
        self._last_emit_at: Optional[str] = None

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        logger.info("synthetic traffic %s", "ENABLED" if enabled else "disabled")

    def status(self) -> dict:
        return {
            "allowed": synthetic_allowed(),
            "enabled": self._enabled,
            "emitted_total": self._emitted_total,
            "last_emit_at": self._last_emit_at,
            "interval_seconds": self._interval,
        }

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        logger.info("synthetic traffic generator armed (idle until enabled)")
        while not self._stop.is_set():
            if self._enabled:
                try:
                    n = await asyncio.to_thread(emit_batch, self._rng)
                    if n:
                        self._emitted_total += n
                        self._last_emit_at = datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        )
                except Exception:  # noqa: BLE001 — never let the loop die
                    logger.exception("synthetic emit failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass
