"""Shared helpers for the data-tiering / retention tests: a real data root
(bootstrap + provisioned tenants), and rows written the way the product
writes them. Fixture values only (acme-corp / globex, RFC 5737 / 2606)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

NOW = datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ago(**kw) -> str:
    return iso(NOW - timedelta(**kw))


def make_root(tmp_path: Path, monkeypatch, tenants=("acme-corp", "globex")) -> Path:
    """Bootstrapped data root (registry at head, global audit) with tenants
    provisioned by client_provisioning — the production path."""
    from apps.octo import client_provisioning
    from apps.octo.auth import bootstrap
    from apps.octo.ingest import telemetry
    from apps.octo.retention import archive_crypto

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    monkeypatch.delenv("OCTO_ARCHIVE_ROOT", raising=False)
    # Archive encryption: off unless a test configures it (never the host's
    # own recipients file).
    monkeypatch.delenv(archive_crypto.POLICY_ENV, raising=False)
    monkeypatch.delenv(archive_crypto.RECIPIENTS_ENV, raising=False)
    monkeypatch.setattr(archive_crypto, "DEFAULT_RECIPIENTS_PATH",
                        tmp_path / "no-archive-recipients.txt")
    telemetry.reset_schema_cache()
    bootstrap.init_data_root()
    for slug in tenants:
        client_provisioning.create_client(slug, slug.replace("-", " ").title(), kind="client")
    return root


def db(root: Path, slug: str, name: str) -> Path:
    return root / "clients" / slug / f"{name}.db"


def rows(path: Path, sql: str, params: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return [tuple(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()


def pihole_payload(status: int, domain: str = "example.test",
                   client: str = "192.0.2.10", n: int = 0) -> dict:
    return {"event_type": "pihole.query", "severity": "info",
            "raw_query": {"id": n, "status": status, "domain": domain, "client": client},
            "_adapter": "pihole", "_buoy": "buoy-acme-1"}


def suricata_payload(kind: str, domain: str = "example.test",
                     src: str = "192.0.2.10", **extra) -> dict:
    eve: dict = {"event_type": kind, "src_ip": src, "dest_ip": "198.51.100.53", **extra}
    if kind == "dns":
        eve.setdefault("dns", {"type": "query", "rrname": domain, "rrtype": "A"})
    return {"event_type": f"suricata.{kind}", "severity": "info", "raw_eve": eve,
            "_adapter": "suricata"}


def insert_event(root: Path, slug: str, *, event_type: str, payload: dict,
                 received_at: str, severity: str = "info",
                 source: str = "buoy:acme", source_host: str = "buoy-acme-1",
                 stamped: bool = True, ingested_at: Optional[str] = None) -> int:
    """An events.db row (payload text = the sink's serialisation, sha = the
    router's canonical sha). `stamped` (default): with an arrival time, as the
    sink writes from 036 on — `ingested_at`, else its received_at (a live
    feed). `stamped=False`: as the pre-036 sink stored it (no arrival time —
    the tenant's arrival backfill is then pending)."""
    text = json.dumps(payload, separators=(",", ":"))
    sha = hashlib.sha256(json.dumps(payload, separators=(",", ":"), sort_keys=True)
                         .encode()).hexdigest()
    arrived = (ingested_at or received_at) if stamped else None
    conn = sqlite3.connect(db(root, slug, "events"))
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?)",
            (received_at, source, source_host, event_type, severity, text, sha, arrived),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def live_signal(root: Path, slug: str, at: Optional[datetime] = None) -> int:
    """One signal that ARRIVED at `at` (default NOW): a bundle whose ingest is
    live. A scheduled retention run with no run on record compares its clock
    with the newest arrival (the clock check) — fixtures made only of old
    rows look exactly like a clock that jumped."""
    when = iso(at or NOW)
    return insert_event(root, slug, event_type="wazuh.alert", payload={"live": when},
                        received_at=when, severity="high", source="wazuh",
                        source_host="web-01")


def write_telemetry(root: Path, slug: str, *, received_at: str, domain: str = "example.test",
                    device: str = "192.0.2.10", event_type: str = "pihole.query",
                    n: int = 0, payload: Optional[str] = None,
                    ingested_at: Optional[str] = None) -> int:
    """A raw telemetry row; it ARRIVED at `ingested_at` (default: its
    received_at — a live feed)."""
    from apps.octo.ingest import telemetry

    arrived = ingested_at or received_at
    [w] = telemetry.TelemetryStore(root, clock=lambda: arrived).write(
        slug, [telemetry.TelemetryRow(
            received_at=received_at, source="buoy:acme", event_type=event_type,
            severity="info", source_host="buoy-acme-1", domain=domain, device=device,
            payload=payload if payload is not None else json.dumps({"n": n, "d": domain}),
            payload_truncated=False,
            payload_sha256=hashlib.sha256(f"{received_at}|{domain}|{n}".encode()).hexdigest(),
        )])
    return w.telemetry_id


def write_telemetry_many(root: Path, slug: str, specs: list[dict]) -> list[int]:
    """Many rows in ONE store transaction (each spec: received_at, domain, n,
    payload)."""
    from apps.octo.ingest import telemetry

    batch = [telemetry.TelemetryRow(
        received_at=sp["received_at"], source="buoy:acme", event_type="pihole.query",
        severity="info", source_host="buoy-acme-1", domain=sp.get("domain", "example.test"),
        device="192.0.2.10", payload=sp["payload"], payload_truncated=False,
        payload_sha256=hashlib.sha256(f"{sp['received_at']}|{sp.get('n')}".encode()).hexdigest(),
        ingested_at=sp.get("ingested_at") or sp["received_at"],
    ) for sp in specs]
    return [w.telemetry_id for w in telemetry.TelemetryStore(root).write(slug, batch)]


def insert_events_many(root: Path, slug: str, items: list[tuple[str, dict]]) -> None:
    """(received_at, payload) wazuh.alert rows in one transaction (arrived
    at their received_at)."""
    conn = sqlite3.connect(db(root, slug, "events"))
    try:
        conn.executemany(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            " payload, payload_sha256, summary, ingested_at) VALUES (?, 'wazuh', 'web-01', "
            " 'wazuh.alert', 'high', ?, ?, '', ?)",
            [(ts, json.dumps(p), hashlib.sha256(json.dumps(p).encode()).hexdigest(), ts)
             for ts, p in items],
        )
        conn.commit()
    finally:
        conn.close()


def open_ticket(root: Path, slug: str, source_event_id: int, title: str = "t") -> int:
    """A ticket citing an event, in the tenant's tickets.db (created at the
    current tickets schema by the tickets router's own ensure step)."""
    from apps.octo.api.routers.tickets import _ensure_schema

    conn = sqlite3.connect(_ensure_schema(slug))
    try:
        cur = conn.execute("INSERT INTO tickets (title, source_event_id) VALUES (?, ?)",
                           (title, source_event_id))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def event_note(root: Path, slug: str, event_id: int, created_at: Optional[str] = None) -> int:
    """An agent note about an event (the event becomes evidence)."""
    conn = sqlite3.connect(db(root, slug, "events"))
    try:
        cur = conn.execute(
            "INSERT INTO agent_notes (ref_kind, ref_id, agent_id, note_text, confidence, "
            " created_at, audit_request_id) VALUES ('event', ?, 'octo', 'looked at this', "
            " 0.5, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')), 'r-1')",
            (event_id, created_at))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def file_digests(root: Path) -> dict[str, str]:
    """sha256 of every file under the data root (a dry run must change none).
    SQLite's shared-memory index and an EMPTY write-ahead log are not data —
    a read-only open of a WAL database creates them — so they are left out."""
    out = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name.endswith(("-shm", ".lock")):
            continue
        if p.name.endswith("-wal") and p.stat().st_size == 0:
            continue
        out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def audit_rows(root: Path, action: str) -> list[dict]:
    conn = sqlite3.connect(root / "global" / "audit.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,))]
    finally:
        conn.close()
