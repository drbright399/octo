"""Alerts as OCCURRENCES the verdict evaluator reads — from the coalescing
ledgers the Fleet counts Yellow from (UniFi IPS / NextDNS buckets in the
tenant's telemetry.db) and from stored event rows (events.db). Read-only,
fail-soft: a store that cannot be read gives nothing to hide (louder,
never quieter).

`linked_events` names the events an incident cites (`incident_events`):
those are never "expected" (an expected condition never touches anything a
Red / Black rests on). When it cannot be read, EVERY asked id counts as
linked — no expected label is applied (acknowledgements still are).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.verdicts import keys
from apps.octo.verdicts.state import Occurrence


def _ro(path) -> Optional[sqlite3.Connection]:
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    return conn


def linked_events(slug: str, event_ids: Iterable[int]) -> set[int]:
    ids = sorted({int(i) for i in event_ids if i})
    if not ids:
        return set()
    conn = _ro(paths.client_dir(slug) / "events.db")
    if conn is None:
        return set()
    out: set[int] = set()
    try:
        has = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND "
                           "name = 'incident_events'").fetchone()
        if has is None:
            return set()
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            out |= {int(r[0]) for r in conn.execute(
                f"SELECT DISTINCT event_id FROM incident_events WHERE event_id IN "
                f"({','.join('?' * len(chunk))})", chunk).fetchall()}
    except sqlite3.Error:
        return set(ids)
    finally:
        conn.close()
    return out


def event_rows(slug: str, event_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
    """{id: {id, received_at, source, source_host, event_type, severity,
    payload}} — the events asked for that exist."""
    ids = sorted({int(i) for i in event_ids if i})
    if not ids:
        return {}
    conn = _ro(paths.client_dir(slug) / "events.db")
    if conn is None:
        return {}
    out: dict[int, dict[str, Any]] = {}
    try:
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            for r in conn.execute(
                    f"SELECT id, received_at, source, source_host, event_type, severity, payload "
                    f"FROM events WHERE id IN ({','.join('?' * len(chunk))})", chunk).fetchall():
                out[int(r["id"])] = dict(r)
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return out


def row_occurrence(row: dict[str, Any], *, linked: bool = False,
                   payload: Optional[dict[str, Any]] = None) -> Occurrence:
    """One stored event as an occurrence (not coalesced)."""
    p = payload if payload is not None else keys.payload_of(row)
    at = str(row.get("received_at") or "")
    return Occurrence(int(row["id"]), keys.alert_key(row, p), at, at, None, None,
                      eligible=keys.expected_refusal(row, p, linked_incident=linked) is None)


def nextdns_buckets(slug: str, profile_ids: list[str], hour: str, day_cut: str, *,
                    since_iso: Optional[str] = None) -> list[dict[str, Any]]:
    """The NextDNS ledger buckets of the window (hour buckets from `hour`,
    DAY buckets from `day_cut` — and, with `since_iso`, a day bucket that
    began earlier but whose FIRST hit is at or after it: wholly inside the
    window), one dict per bucket. [] when unreadable."""
    from apps.octo.ingest import telemetry

    if not profile_ids:
        return []
    conn = _ro(telemetry.db_path_for(slug))
    if conn is None:
        return []
    marks = ",".join("?" * len(profile_ids))
    early = " OR (span = 'day' AND hour < ? AND first_seen >= ?)" if since_iso else ""
    try:
        rows = conn.execute(
            f"SELECT bucket_key, hour, span, profile_id, reason_id, root, device, event_id, hits, "
            f"first_seen, last_seen FROM nextdns_signal_buckets WHERE profile_id IN ({marks}) "
            f"AND ((span = 'day' AND hour >= ?) OR (span <> 'day' AND hour >= ?){early})",
            (*profile_ids, day_cut, hour, *((day_cut, since_iso) if since_iso else ())),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [dict(r) for r in rows]


def nextdns_occurrence(b: dict[str, Any], *, linked: bool = False) -> Occurrence:
    key = keys.nextdns_key(str(b["profile_id"]), str(b["device"] or ""), str(b["root"] or ""),
                           str(b["reason_id"] or ""))
    return Occurrence(int(b["event_id"]) if b.get("event_id") else None, key,
                      str(b["first_seen"]), str(b["last_seen"]), int(b["hits"] or 1), None,
                      eligible=not linked and keys.expected_eligible_bucket(key))


def unifi_occurrence(b: Any, *, linked: bool = False) -> Occurrence:
    """A UniFi ledger bucket (`adapters.unifi.store.BucketInfo`)."""
    key = keys.unifi_key(b.scope, b.kind, b.subject)
    return Occurrence(b.event_id or None, key, b.first_seen, b.last_seen, b.hits, b.remotes,
                      eligible=not linked and keys.device_refusal(key) is None)


def payload_json(text: Any) -> dict[str, Any]:
    try:
        value = json.loads(text) if isinstance(text, str) and text else {}
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def nextdns_by_event(slug: str, event_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
    """{event id: its NextDNS ledger bucket} for alerts a bucket created."""
    from apps.octo.ingest import telemetry

    ids = sorted({int(i) for i in event_ids if i})
    if not ids:
        return {}
    conn = _ro(telemetry.db_path_for(slug))
    if conn is None:
        return {}
    out: dict[int, dict[str, Any]] = {}
    try:
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            for r in conn.execute(
                    f"SELECT bucket_key, hour, span, profile_id, reason_id, root, device, "
                    f"event_id, hits, first_seen, last_seen FROM nextdns_signal_buckets "
                    f"WHERE event_id IN ({','.join('?' * len(chunk))})", chunk).fetchall():
                out[int(r["event_id"])] = dict(r)
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return out
