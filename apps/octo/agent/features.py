"""Derive TriageFeatures for an event from per-tenant DB context (#119b).

The heuristic engine is pure; this module is the impure half that reads a
tenant's events.db / indicators.db to compute the recurrence + indicator
context the engine needs. Kept separate so the engine stays unit-testable
and this stays the only place that knows the storage shape.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Optional

from apps.octo.agent.heuristic_l1 import (
    DnsFilterEvent,
    NetworkEvent,
    TriageFeatures,
    VendorClosure,
)

# Payload keys an adapter might use to carry an IOC value. Best-effort
# (the events table doesn't persist the indicator — it lives in
# indicators.db), so we sniff the payload for a candidate and then confirm
# against indicators.db for the hit count. A future migration could persist
# the indicator on the event row for exactness; this is the v1 approximation.
_INDICATOR_KEYS = (
    "indicator", "ioc", "indicator_value",
    "ip", "src_ip", "source_ip", "remote_ip", "dest_ip",
    "domain", "hostname_ioc", "url", "sha256", "hash", "md5",
)


def _extract_indicator(payload: dict[str, Any]) -> Optional[str]:
    """Best-effort: pull a single IOC value out of an event payload."""
    for key in _INDICATOR_KEYS:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def ensure_recurrence_index(conn: sqlite3.Connection) -> None:
    """Index backing the recurrence COUNT. Without it, each event triggers
    a full events-table scan — fine for tests, far too slow at real volume
    (~189k events/tenant on the dev fleet). Idempotent + near-free when
    present; created once on the worker's writable handle."""
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_recurrence "
        "ON events(source, event_type, source_host, id)"
    )
    conn.commit()


def _recurrence_count(
    events_conn: sqlite3.Connection,
    *,
    source: str,
    source_host: Optional[str],
    event_type: str,
    before_id: int,
) -> int:
    """Count prior events sharing this event's recurrence signature
    (same source + host + event_type), strictly before this event's id.

    The NULL branch is split out rather than folded into one query: a
    `(col IS NULL AND ? IS NULL) OR col = ?` predicate is NOT sargable, so
    SQLite ignores idx_events_recurrence and full-scans per event. Branching
    keeps each query a plain equality range scan that uses the index.
    """
    if source_host is None:
        row = events_conn.execute(
            "SELECT COUNT(*) AS c FROM events "
            "WHERE source = ? AND event_type = ? AND source_host IS NULL "
            "  AND id < ?",
            (source, event_type, before_id),
        ).fetchone()
    else:
        row = events_conn.execute(
            "SELECT COUNT(*) AS c FROM events "
            "WHERE source = ? AND event_type = ? AND source_host = ? "
            "  AND id < ?",
            (source, event_type, source_host, before_id),
        ).fetchone()
    return int(row["c"]) if row else 0


# Vendors whose incidents CHANGE after they are raised and that report the
# change as a new stored version (the adapter stores each version as its own
# event): event_type → (display name, the statuses that CLOSE an incident).
# The payload is the vendor's incident as listed: `id` + `status`.
_CLOSURE_REPORTING: dict[str, tuple[str, frozenset[str]]] = {
    "rocketcyber.incident": ("RocketCyber", frozenset({"resolved", "suppressed"})),
}


def _vendor_closure(
    event_row: sqlite3.Row, payload: dict[str, Any], events_conn: sqlite3.Connection,
) -> Optional[VendorClosure]:
    """A vendor-reported closure of an incident, with this tenant's earlier
    OPEN row of it (newest before this one) when stored. None otherwise."""
    known = _CLOSURE_REPORTING.get(event_row["event_type"])
    if known is None:
        return None
    vendor, closing = known
    status = payload.get("status")
    status = status.strip().lower() if isinstance(status, str) else ""
    if status not in closing:
        return None
    raw_id = payload.get("id")
    incident_id = (
        str(raw_id) if isinstance(raw_id, (int, str)) and not isinstance(raw_id, bool)
        and str(raw_id).strip() else None
    )
    open_event_id: Optional[int] = None
    if incident_id is not None:
        # The recurrence index narrows it to this source/type (newest first);
        # an incident's versions are few.
        host = event_row["source_host"]
        try:
            row = events_conn.execute(
                "SELECT id FROM events WHERE source = ? AND event_type = ? "
                + ("AND source_host IS NULL " if host is None else "AND source_host = ? ")
                + "AND id < ? AND json_valid(payload) "
                "AND CAST(CASE WHEN json_valid(payload) THEN json_extract(payload, '$.id') "
                "         END AS TEXT) = ? "
                "AND lower(CASE WHEN json_valid(payload) THEN json_extract(payload, '$.status') "
                "          END) = 'open' "
                "ORDER BY id DESC LIMIT 1",
                (event_row["source"], event_row["event_type"],
                 *(() if host is None else (host,)), int(event_row["id"]), incident_id),
            ).fetchone()
        except sqlite3.Error:
            row = None
        if row is not None:
            open_event_id = int(row["id"])
    return VendorClosure(vendor=vendor, status=status, incident_id=incident_id,
                         open_event_id=open_event_id)


_DNS_FILTER_KINDS = {
    "nextdns.security_block": "block",
    "nextdns.protection_lapsed": "lapsed",
    "nextdns.protection_restored": "restored",
    "nextdns.fleet_dns_outage": "fleet_outage",
}


def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _clean(value: Any, limit: int = 96) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[:limit]


def _dns_filter(event_row: sqlite3.Row, payload: dict[str, Any]) -> Optional[DnsFilterEvent]:
    """A NextDNS record's triage context, from its stored payload alone."""
    kind = _DNS_FILTER_KINDS.get(event_row["event_type"])
    if kind is None:
        return None
    name = _clean(payload.get("profile_name"))
    pid = _clean(payload.get("profile_id"), 32)
    profile = f"{name} ({pid})" if name and pid else (name or pid)
    if kind == "block":
        log = payload.get("log") if isinstance(payload.get("log"), dict) else {}
        device = log.get("device") if isinstance(log.get("device"), dict) else {}
        signal = payload.get("signal") if isinstance(payload.get("signal"), dict) else {}
        return DnsFilterEvent(
            kind="block",
            level=_clean(signal.get("level"), 16) or "medium",
            reason_id=_clean(signal.get("reason_id"), 64),
            reason_label=_clean(signal.get("reason_label")),
            device=_clean(device.get("name"), 64) or _clean(log.get("clientIp"), 64),
            profile=profile,
        )
    if kind == "fleet_outage":
        return DnsFilterEvent(
            kind="fleet_outage",
            fleet_sites=_count(payload.get("sites")),
            fleet_watched=_count(payload.get("watched")),
            lapsed_since=_clean(payload.get("since"), 32) or None,
        )
    lapse = payload.get("lapse_event_id")
    fleet = payload.get("fleet") if isinstance(payload.get("fleet"), dict) else {}
    return DnsFilterEvent(
        kind=kind,  # type: ignore[arg-type]
        profile=profile,
        cause=_clean(payload.get("cause"), 32),
        lapse_event_id=lapse if isinstance(lapse, int) and not isinstance(lapse, bool) else None,
        lapsed_since=_clean(payload.get("lapsed_since") or payload.get("since"), 32) or None,
        restored_hour=_clean(payload.get("restored_hour"), 32) or None,
        fleet_sites=_count(fleet.get("sites")),
        fleet_watched=_count(fleet.get("watched")),
    )


_NETWORK_KINDS = {
    "unifi.ips_threat": "ips_threat",
    "unifi.rogue_ap": "rogue_ap",
    "unifi.admin_activity": "admin_activity",
    "unifi.config_change": "config_change",
    "unifi.wan_down": "wan_down",
    "unifi.wan_failover": "wan_failover",
    "unifi.wan_restored": "wan_restored",
    "unifi.vpn_down": "vpn_down",
    "unifi.system_event": "system_event",
    "fleet.isp_outage": "isp_outage",
}


def _network(event_row: sqlite3.Row, payload: dict[str, Any]) -> Optional[NetworkEvent]:
    """A UniFi gateway record's triage context, from its stored payload alone."""
    kind = _NETWORK_KINDS.get(event_row["event_type"])
    if kind is None:
        return None
    if kind == "isp_outage":
        isp = payload.get("isp") if isinstance(payload.get("isp"), dict) else {}
        sites = payload.get("sites")
        return NetworkEvent(
            kind=kind, site="", isp=_clean(isp.get("name"), 80),
            asn=isp.get("asn") if isinstance(isp.get("asn"), int) else 0,
            sites=sites if isinstance(sites, int) and not isinstance(sites, bool) else 0,
        )
    site = _clean(payload.get("site_name"))
    console = _clean(payload.get("console_name"))
    if site and console and site.lower() != console.lower():
        site = f"{site} ({console})"
    ips = payload.get("ips") if isinstance(payload.get("ips"), dict) else {}
    client = ips.get("client") if isinstance(ips.get("client"), dict) else {}
    device = (_clean(client.get("name"), 64) or _clean(client.get("hostname"), 64)
              or _clean(ips.get("local_ip"), 64))
    return NetworkEvent(
        kind=kind, site=site or console, device=device,
        action=_clean(ips.get("action"), 16), signature=_clean(ips.get("signature"), 96),
        remote=_clean(ips.get("remote_ip"), 64),
    )


def _indicator_hits(
    indicators_conn: Optional[sqlite3.Connection], value: str,
) -> int:
    """Prior hit count for an IOC value in this tenant's indicators.db.

    The ingest sink increments `hits` on repeat sightings, so a value with
    hits > 1 has been seen before. Returns 0 if indicators.db is absent or
    the value is unknown.
    """
    if indicators_conn is None:
        return 0
    try:
        row = indicators_conn.execute(
            "SELECT hits FROM indicators WHERE value = ? AND deleted_at IS NULL",
            (value,),
        ).fetchone()
    except sqlite3.OperationalError:
        return 0
    if not row:
        return 0
    # `hits` counts total sightings incl. this one; prior hits = hits - 1.
    return max(0, int(row["hits"]) - 1)


def build_features(
    event_row: sqlite3.Row,
    *,
    events_conn: sqlite3.Connection,
    indicators_conn: Optional[sqlite3.Connection],
) -> TriageFeatures:
    """Assemble the feature set the pure engine consumes for one event."""
    try:
        payload = json.loads(event_row["payload"]) if event_row["payload"] else {}
        if not isinstance(payload, dict):
            payload = {}
    except (json.JSONDecodeError, TypeError):
        payload = {}

    indicator_value = _extract_indicator(payload)
    has_indicator = indicator_value is not None
    indicator_hits = (
        _indicator_hits(indicators_conn, indicator_value)
        if indicator_value else 0
    )

    recurrence = _recurrence_count(
        events_conn,
        source=event_row["source"],
        source_host=event_row["source_host"],
        event_type=event_row["event_type"],
        before_id=int(event_row["id"]),
    )

    return TriageFeatures(
        severity=event_row["severity"],
        has_indicator=has_indicator,
        indicator_hits=indicator_hits,
        recurrence_count=recurrence,
        known_false_positive=False,  # seam: per-tenant FP ruleset (future)
        vendor_closure=_vendor_closure(event_row, payload, events_conn),
        dns_filter=_dns_filter(event_row, payload),
        network=_network(event_row, payload),
    )
