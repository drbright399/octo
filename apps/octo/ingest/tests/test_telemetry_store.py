"""The per-tenant telemetry store and the sink's routing into it.

Real SqliteIngestSink / TelemetryStore on real SQLite files (a tenant
provisioned by `client_provisioning.provision_client_dbs`). Pins:
  * telemetry goes to telemetry.db — raw row + hourly roll-up + first-seen,
    one transaction; signals keep going to events.db; SSE/indicators are
    signal-only;
  * roll-up counts are exact under two concurrent writer threads on the
    same hour/domain/device; first-seen keeps the EARLIEST sighting whatever
    the arrival order;
  * the sink's idempotency identity applies (source, sha, received_at; sha
    alone without a vendor timestamp); payloads are bounded with the sha of
    the full text;
  * a telemetry-store failure falls back to events.db (never fails the
    write) and is counted; an unprovisioned tenant still raises.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.ingest import sink as sink_module
from apps.octo.ingest import telemetry
from apps.octo.ingest.sink import SqliteIngestSink
from apps.octo.ingest.tiering import SIGNAL, TELEMETRY

SLUG = "acme-corp"


@pytest.fixture
def root(tmp_path, monkeypatch):
    data = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(data))
    telemetry.reset_schema_cache()
    sink_module.reset_telemetry_fallbacks()
    from apps.octo import client_provisioning

    client_provisioning.provision_client_dbs(SLUG)
    yield data
    telemetry.reset_schema_cache()


def _event(payload: dict, *, received_at: str = "2026-09-29T10:15:00.000Z",
           severity: str = "info") -> CanonicalEvent:
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return CanonicalEvent(
        vendor_event_id="v", received_at=received_at, severity=severity,
        indicator=None, indicator_type=None, source_host="buoy-acme-1",
        summary=payload.get("event_type", ""), payload=payload,
        payload_sha256=hashlib.sha256(text.encode()).hexdigest(),
    )


def _pihole(status: int, domain: str = "example.test", client: str = "192.0.2.10",
            n: int = 0) -> dict:
    return {"event_type": "pihole.query", "severity": "info",
            "raw_query": {"id": n, "status": status, "domain": domain, "client": client}}


def _rows(root: Path, db: str, sql: str) -> list[tuple]:
    conn = sqlite3.connect(root / "clients" / SLUG / db)
    try:
        return [tuple(r) for r in conn.execute(sql)]
    finally:
        conn.close()


def test_provisioning_creates_an_incremental_telemetry_db(root):
    conn = sqlite3.connect(root / "clients" / SLUG / "telemetry.db")
    try:
        assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
        # 036 (the store) + 037 (NextDNS) + 039 (UniFi roll-up tables) + 046
        # (the IPS buckets' remotes).
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 46
    finally:
        conn.close()
    # New events.db / indicators.db are born incremental too.
    for name in ("events.db", "indicators.db"):
        c = sqlite3.connect(root / "clients" / SLUG / name)
        try:
            assert c.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
        finally:
            c.close()


def test_answered_dns_goes_to_telemetry_and_blocked_stays_a_signal(root):
    # Arrived 30 s after the sensor saw it (the sink's injected clock).
    arrived = "2026-09-29T10:15:30.000Z"
    sink = SqliteIngestSink(publish_to_stream=False, clock=lambda: arrived)
    answered = sink.ingest(SLUG, "buoy:acme", _event(_pihole(2)),
                           event_type="pihole.query", dedup=False)
    blocked = sink.ingest(SLUG, "buoy:acme", _event(_pihole(1, "ads.example.test")),
                          event_type="pihole.query", dedup=False)
    assert answered.tier == TELEMETRY and not answered.fallback
    assert blocked.tier == SIGNAL
    assert _rows(root, "events.db", "SELECT id, event_type, received_at, ingested_at "
                 "FROM events") == [
        (blocked.event_id, "pihole.query", "2026-09-29T10:15:00.000Z", arrived)]
    raw = _rows(root, "telemetry.db",
                "SELECT id, source, event_type, domain, device, received_at, payload_sha256, "
                "ingested_at FROM telemetry_raw")
    assert raw == [(answered.event_id, "buoy:acme", "pihole.query", "example.test",
                    "192.0.2.10", "2026-09-29T10:15:00.000Z",
                    _event(_pihole(2)).payload_sha256, arrived)]
    assert _rows(root, "telemetry.db", "SELECT * FROM telemetry_hourly") == [
        ("2026-09-29T10:00:00Z", "pihole.query", "example.test", "192.0.2.10", "", 1,
         "2026-09-29T10:15:00.000Z", "2026-09-29T10:15:00.000Z", arrived)]
    assert _rows(root, "telemetry.db", "SELECT domain, first_device FROM first_seen_domains") == [
        ("example.test", "192.0.2.10")]


def test_the_stored_payload_is_what_events_db_would_have_held(root):
    payload = _pihole(3, n=9)
    ev = _event(payload)
    SqliteIngestSink(publish_to_stream=False).ingest(
        SLUG, "buoy:acme", ev, event_type="pihole.query", dedup=False)
    [(text, truncated)] = _rows(root, "telemetry.db",
                                "SELECT payload, payload_truncated FROM telemetry_raw")
    assert text == json.dumps(payload, separators=(",", ":"))
    assert truncated == 0


def test_oversize_payload_is_bounded_with_the_full_sha(root):
    payload = _pihole(2)
    payload["padding"] = "x" * (telemetry.MAX_PAYLOAD_BYTES + 100)
    ev = _event(payload)
    SqliteIngestSink(publish_to_stream=False).ingest(
        SLUG, "buoy:acme", ev, event_type="pihole.query", dedup=False)
    [(text, truncated, sha)] = _rows(
        root, "telemetry.db", "SELECT payload, payload_truncated, payload_sha256 FROM telemetry_raw")
    assert truncated == 1
    assert len(text.encode()) <= telemetry.MAX_PAYLOAD_BYTES
    assert sha == ev.payload_sha256


def test_dedup_identity_matches_the_events_sink(root):
    sink = SqliteIngestSink(publish_to_stream=False)
    ev = _event(_pihole(2))
    first = sink.ingest(SLUG, "buoy:acme", ev, event_type="pihole.query")
    again = sink.ingest(SLUG, "buoy:acme", ev, event_type="pihole.query")
    assert again.duplicate and again.event_id == first.event_id and again.tier == TELEMETRY
    # Another source, or another vendor timestamp, is a different event.
    other_source = sink.ingest(SLUG, "buoy:other", ev, event_type="pihole.query")
    later = sink.ingest(SLUG, "buoy:acme",
                        _event(_pihole(2), received_at="2026-09-29T10:16:00.000Z"),
                        event_type="pihole.query")
    assert not other_source.duplicate and not later.duplicate
    # A replay is not counted twice.
    assert _rows(root, "telemetry.db", "SELECT SUM(count) FROM telemetry_hourly") == [(3,)]
    # No vendor timestamp: the payload alone is the identity.
    no_ts = _event(_pihole(3, "b.example.test"), received_at="")
    a = sink.ingest(SLUG, "buoy:acme", no_ts, event_type="pihole.query")
    b = sink.ingest(SLUG, "buoy:acme", no_ts, event_type="pihole.query")
    assert b.duplicate and b.event_id == a.event_id
    # dedup=False (the /events contract): identical telemetry repeats.
    c = sink.ingest(SLUG, "buoy:acme", ev, event_type="pihole.query", dedup=False)
    assert not c.duplicate


def test_concurrent_writers_count_exactly(root):
    """Two threads, same hour / domain / device, 200 writes each."""
    store = telemetry.TelemetryStore(root)
    errors: list[BaseException] = []

    def writer(tag: str) -> None:
        try:
            for i in range(200):
                store.write(SLUG, [telemetry.TelemetryRow(
                    received_at=f"2026-09-29T10:{i % 60:02d}:{i % 60:02d}.000Z",
                    source=f"buoy:{tag}", event_type="suricata.dns", severity="info",
                    source_host="buoy-acme-1", domain="example.test", device="192.0.2.10",
                    payload="{}", payload_truncated=False, payload_sha256=f"{tag}{i:060d}",
                )])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(t,)) for t in ("aaaa", "bbbb")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert _rows(root, "telemetry.db", "SELECT hour, count, first_seen, last_seen "
                                       "FROM telemetry_hourly") == [
        ("2026-09-29T10:00:00Z", 400, "2026-09-29T10:00:00.000Z", "2026-09-29T10:59:59.000Z")]
    assert _rows(root, "telemetry.db", "SELECT COUNT(*) FROM telemetry_raw") == [(400,)]
    assert _rows(root, "telemetry.db", "SELECT domain, first_seen, last_seen "
                                       "FROM first_seen_domains") == [
        ("example.test", "2026-09-29T10:00:00.000Z", "2026-09-29T10:59:59.000Z")]


def test_first_seen_keeps_the_earliest_sighting_in_any_order(root):
    store = telemetry.TelemetryStore(root)

    def row(ts: str, device: str, et: str) -> telemetry.TelemetryRow:
        return telemetry.TelemetryRow(
            received_at=ts, source="buoy:acme", event_type=et, severity="info",
            source_host=None, domain="new.example.test", device=device, payload="{}",
            payload_truncated=False, payload_sha256=hashlib.sha256(ts.encode()).hexdigest(),
        )

    store.write(SLUG, [row("2026-09-29T12:00:00.000Z", "bob-pc", "pihole.query")])
    store.write(SLUG, [row("2026-09-29T08:00:00.000Z", "alice-pc", "suricata.tls")])
    store.write(SLUG, [row("2026-09-29T10:00:00.000Z", "carol-pc", "suricata.dns")])
    assert _rows(root, "telemetry.db", "SELECT * FROM first_seen_domains") == [
        ("new.example.test", "2026-09-29T08:00:00.000Z", "alice-pc", "suricata.tls",
         "2026-09-29T12:00:00.000Z")]
    assert _rows(root, "telemetry.db",
                 "SELECT hour, event_type, count FROM telemetry_hourly ORDER BY hour") == [
        ("2026-09-29T08:00:00Z", "suricata.tls", 1),
        ("2026-09-29T10:00:00Z", "suricata.dns", 1),
        ("2026-09-29T12:00:00Z", "pihole.query", 1),
    ]


def test_a_telemetry_store_failure_falls_back_to_events_db(root):
    """A real failure: the telemetry.db file is read-only. The write still
    succeeds — into events.db, flagged — and is counted per tenant."""
    tdb = root / "clients" / SLUG / "telemetry.db"
    os.chmod(tdb, 0o444)
    try:
        out = SqliteIngestSink(publish_to_stream=False).ingest(
            SLUG, "buoy:acme", _event(_pihole(2)), event_type="pihole.query", dedup=False)
    finally:
        os.chmod(tdb, 0o644)
    assert out.tier == SIGNAL and out.fallback
    assert _rows(root, "events.db", "SELECT event_type FROM events") == [("pihole.query",)]
    stats = sink_module.telemetry_fallbacks()[SLUG]
    assert stats["count"] == 1 and stats["last_error"] == "OperationalError"


def test_the_fault_count_is_recent_faults_only(root):
    """The console warns about RECENT store faults (the last 24 h), not a
    count since the process started: a fault that cleared yesterday stops
    showing. Real failures (a read-only telemetry.db) at injected times."""
    tdb = root / "clients" / SLUG / "telemetry.db"
    clock = {"now": "2026-09-28T09:10:00.000Z"}
    sink = SqliteIngestSink(publish_to_stream=False, clock=lambda: clock["now"])
    os.chmod(tdb, 0o444)
    try:
        for n, at in enumerate(("2026-09-28T09:10:00.000Z", "2026-09-28T09:40:00.000Z",
                                "2026-09-29T08:05:00.000Z")):
            clock["now"] = at
            assert sink.ingest(SLUG, "buoy:acme", _event(_pihole(2, n=n)),
                               event_type="pihole.query", dedup=False).fallback
    finally:
        os.chmod(tdb, 0o644)
    # An hour after the last fault: all three are within the day.
    now = sink_module.telemetry_fallbacks(now="2026-09-29T09:05:00.000Z")[SLUG]
    assert (now["count"], now["last_at"], now["window_hours"]) == (
        3, "2026-09-29T08:05:00.000Z", 24)
    # 25 h after the first two, 1 h after the last: only the last counts.
    assert sink_module.telemetry_fallbacks(
        now="2026-09-29T10:30:00.000Z")[SLUG]["count"] == 1
    # A day after the last: nothing to warn about, the tenant is not listed.
    assert sink_module.telemetry_fallbacks(now="2026-09-30T09:30:00.000Z") == {}


def test_an_unprovisioned_tenant_still_raises(root):
    with pytest.raises(FileNotFoundError):
        SqliteIngestSink(publish_to_stream=False).ingest(
            "globex", "buoy:x", _event(_pihole(2)), event_type="pihole.query")


def test_a_pre_036_tenant_gets_its_store_lazily(root):
    """A tenant provisioned before 036 has no telemetry.db: the first
    telemetry write creates it at current schema."""
    (root / "clients" / SLUG / "telemetry.db").unlink()
    for side in ("-wal", "-shm"):
        p = root / "clients" / SLUG / f"telemetry.db{side}"
        if p.exists():
            p.unlink()
    out = SqliteIngestSink(publish_to_stream=False).ingest(
        SLUG, "buoy:acme", _event(_pihole(2)), event_type="pihole.query", dedup=False)
    assert out.tier == TELEMETRY
    assert _rows(root, "telemetry.db", "PRAGMA user_version") == [(46,)]


def _suricata_dns(kind: str, domain: str, n: int) -> dict:
    src, dst = ("192.0.2.10", "192.0.2.53") if kind == "query" else ("192.0.2.53", "192.0.2.10")
    return {"event_type": "suricata.dns", "severity": "info", "n": n,
            "raw_eve": {"event_type": "dns", "src_ip": src, "dest_ip": dst,
                        "dns": {"type": kind, "rrname": domain, "rrtype": "A"}}}


def test_a_suricata_answer_is_rolled_up_apart_from_its_query(root):
    """Suricata logs one lookup as a query record AND an answer record: the
    roll-up counts the query under suricata.dns and the answer under
    suricata.dns.answer — one lookup, same device; both raw rows kept as
    received."""
    sink = SqliteIngestSink(root, publish_to_stream=False)
    sink.ingest(SLUG, "buoy:acme", _event(_suricata_dns("query", "example.test", 1)),
                event_type="suricata.dns")
    sink.ingest(SLUG, "buoy:acme", _event(_suricata_dns("answer", "example.test", 2)),
                event_type="suricata.dns")
    assert _rows(root, "telemetry.db", "SELECT event_type FROM telemetry_raw ORDER BY id") == [
        ("suricata.dns",), ("suricata.dns",)]
    assert _rows(root, "telemetry.db", "SELECT event_type, device, count FROM telemetry_hourly "
                                       "ORDER BY event_type") == [
        ("suricata.dns", "192.0.2.10", 1), ("suricata.dns.answer", "192.0.2.10", 1)]


def test_reverse_lookups_and_probes_are_counted_but_never_first_seen(root):
    sink = SqliteIngestSink(root, publish_to_stream=False)
    for n, name in enumerate(["224.2.0.192.in-addr.arpa", "qwhzkcdmrb", "printer.local",
                              "new.example.test"]):
        sink.ingest(SLUG, "buoy:acme", _event(_pihole(2, name, n=n)), event_type="pihole.query")
    assert _rows(root, "telemetry.db", "SELECT domain FROM first_seen_domains") == [
        ("new.example.test",)]
    assert _rows(root, "telemetry.db", "SELECT SUM(count) FROM telemetry_hourly") == [(4,)]
