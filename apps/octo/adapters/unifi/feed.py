"""The UniFi FEED — what the poller hands to entity resolution, per MAPPED site.

Entity resolution (the "who had what, when" lookups: egress intervals, LAN
leases, subnets) is built on these feeds; this adapter only reads, sanitises
and routes them. The contract keeps tenant isolation absolute:

  * every call carries ONE tenant slug and ONE site scope ("<hostId>/
    <siteId>"); a site that is not mapped to an ACTIVE tenant (unmapped,
    ignored, its tenant offboarded) produces NO call at all — nothing about it
    is written anywhere (invariant I10);
  * two consoles whose sites share an id and internal reference ('default')
    are two scopes, never one (I11);
  * the only fleet-wide fact a site's report carries is one bit per WAN,
    `shared_external`: the same public address is another console's WAN in
    the same fleet snapshot. No pointer to the other site, tenant or console.

Calls (all optional for a consumer — the default does nothing):

  on_site_report(slug, scope, report)          every fleet poll (5 min):
      {scope, host_id, site_id, internal_ref, name, console_name, timezone,
       location{lat, long, radius, text}, wans[{wan, external_ip, asn, isp,
       port_up, shared_external}], gateway_online, host_connected,
       report_fresh, polled_at} — a dual-stack single-site console adds
       {wan: "<WAN>/v6", external_ip (its IPv6 WAN address), prefix_len 128}
       and, when /v1/hosts gives one, {wan: "<WAN>/pd", external_ip (the
       delegated prefix), prefix_len 32-64}; nat_kind 'direct', family 6
  on_client_snapshot(slug, scope, snapshot)    every client poll (5 min):
      {scope, polled_at, complete: True, gateway_online, clients[{id, name,
       mac, ip, connected_at, type, uplink_device_id, access}]} — read whole
       (all pages) or not at all
  on_client_snapshot_failed(slug, scope, failure)
      {scope, polled_at, reason} — the snapshot could not be read whole:
      nothing closes, nothing extends
  on_log_events(slug, scope, events)           every system-log read:
      [{id, ts_ms, time, event, client{mac, ip, name, hostname, network,
        wlan} | wan}] — the lease / egress boundaries, oldest first
  on_log_progress(slug, scope, progress)       after every system-log window
      applied: {scanned_to (ISO)} — the log is read whole up to there (entity
      resolution waits for it before naming a LAN device)
  on_networks(slug, scope, networks)           daily: [{_id, name, purpose,
      ip_subnet, vlan, … dhcpd_dns_1..4}] — an allowlist, never a secret
  on_signal_stored(slug, scope, stored)        a DERIVED signal the consumer
      asked for was stored: {anomaly_id, event_id}

DERIVED SIGNALS: on_client_snapshot / on_log_events may RETURN
{"signals": [{"kind": "mac_anomaly", "anomaly_id", "mac", "anomaly", "from",
"to", "detail"}]} — the MAC-anomaly rule's findings (entity resolution's
safeguard for MAC-based identity). The POLLER stores each one as a UniFi
signal (its own payload and OCSF mapping, coalesced per site + MAC + hour),
then calls on_signal_stored — the mapping stays at the adapter boundary.

A consumer is registered process-wide (`register`) or passed to the poller;
a consumer that raises never stops the poller (logged, the next cycle goes
on).
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


class FeedConsumer(Protocol):
    def on_site_report(self, slug: str, scope: str, report: dict[str, Any]) -> None: ...
    def on_client_snapshot(self, slug: str, scope: str, snapshot: dict[str, Any]) -> None: ...
    def on_client_snapshot_failed(self, slug: str, scope: str, failure: dict[str, Any]) -> None: ...
    def on_log_events(self, slug: str, scope: str, events: list[dict[str, Any]]) -> None: ...
    def on_log_progress(self, slug: str, scope: str, progress: dict[str, Any]) -> None: ...
    def on_networks(self, slug: str, scope: str, networks: list[dict[str, Any]]) -> None: ...
    def on_signal_stored(self, slug: str, scope: str, stored: dict[str, Any]) -> None: ...


class NullConsumer:
    """The default: nothing consumes the feeds yet."""

    def on_site_report(self, slug: str, scope: str, report: dict[str, Any]) -> None:
        return None

    def on_client_snapshot(self, slug: str, scope: str, snapshot: dict[str, Any]) -> None:
        return None

    def on_client_snapshot_failed(self, slug: str, scope: str, failure: dict[str, Any]) -> None:
        return None

    def on_log_events(self, slug: str, scope: str, events: list[dict[str, Any]]) -> None:
        return None

    def on_log_progress(self, slug: str, scope: str, progress: dict[str, Any]) -> None:
        return None

    def on_networks(self, slug: str, scope: str, networks: list[dict[str, Any]]) -> None:
        return None

    def on_signal_stored(self, slug: str, scope: str, stored: dict[str, Any]) -> None:
        return None


class RecordingConsumer(NullConsumer):
    """Tests: every call, in order — (method, slug, scope, data)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, Any]] = []

    def on_site_report(self, slug, scope, report):  # noqa: ANN001
        self.calls.append(("site_report", slug, scope, report))

    def on_client_snapshot(self, slug, scope, snapshot):  # noqa: ANN001
        self.calls.append(("client_snapshot", slug, scope, snapshot))

    def on_client_snapshot_failed(self, slug, scope, failure):  # noqa: ANN001
        self.calls.append(("client_snapshot_failed", slug, scope, failure))

    def on_log_events(self, slug, scope, events):  # noqa: ANN001
        self.calls.append(("log_events", slug, scope, events))

    def on_log_progress(self, slug, scope, progress):  # noqa: ANN001
        self.calls.append(("log_progress", slug, scope, progress))

    def on_networks(self, slug, scope, networks):  # noqa: ANN001
        self.calls.append(("networks", slug, scope, networks))

    def on_signal_stored(self, slug, scope, stored):  # noqa: ANN001
        self.calls.append(("signal_stored", slug, scope, stored))

    def of(self, method: str) -> list[tuple[str, str, Any]]:
        return [(slug, scope, data) for m, slug, scope, data in self.calls if m == method]


_lock = threading.Lock()
_registered: Optional[Any] = None


def register(consumer: Optional[Any]) -> None:
    """Install the process-wide consumer (None = back to the null one)."""
    global _registered
    with _lock:
        _registered = consumer


def current() -> Any:
    with _lock:
        return _registered if _registered is not None else NullConsumer()


def deliver(consumer: Any, method: str, slug: str, scope: str, data: Any) -> bool:
    """Call one consumer method; never raises. True when it ran."""
    return call(consumer, method, slug, scope, data)[0]


def call(consumer: Any, method: str, slug: str, scope: str, data: Any) -> tuple[bool, Any]:
    """Call one consumer method; never raises. (ran, what it returned)."""
    fn = getattr(consumer, method, None)
    if not callable(fn):
        return False, None
    try:
        return True, fn(slug, scope, data)
    except Exception as exc:  # noqa: BLE001 — a consumer never stops the poller
        logger.warning("[unifi-feed] %s for %s failed (%s)", method, scope, type(exc).__name__)
        return False, None


def derived_signals(result: Any) -> list[dict[str, Any]]:
    """The derived signals a consumer handed back (bounded, shape-checked)."""
    if not isinstance(result, dict) or not isinstance(result.get("signals"), list):
        return []
    out = []
    for item in result["signals"][:50]:
        if isinstance(item, dict) and item.get("kind") == "mac_anomaly" \
                and isinstance(item.get("anomaly_id"), int) and isinstance(item.get("mac"), str):
            out.append(item)
    return out
