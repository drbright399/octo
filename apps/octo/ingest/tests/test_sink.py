"""SqliteIngestSink — persistence + indicator upsert + SSE publish.

Smoke + behavior tests against a temp data root. Each test provisions
a per-client SQLite via the migration runner so schema matches prod.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from shared_adapter_contract.types import CanonicalEvent

from apps.octo.ingest import SqliteIngestSink


def _apply_client_migrations(client_dir: Path) -> None:
    """Apply migration 002 (events.db + indicators.db schemas) to a
    fresh per-client directory. Mirrors what lifecycle.provision() does."""
    client_dir.mkdir(parents=True, exist_ok=True)
    # __file__ is apps/octo/ingest/tests/test_sink.py
    #   parents[0] = tests, [1] = ingest, [2] = octo
    migrations_dir = Path(__file__).resolve().parents[2] / "migrations"
    sql_002 = (migrations_dir / "002-initialize-client-dbs.sql").read_text()
    # Migration 002 has @target sections — extract the events + indicators
    # sections + apply each to its own DB.
    sections: dict[str, list[str]] = {}
    current = None
    for line in sql_002.splitlines():
        if line.startswith("-- @target:"):
            current = line.split(":", 1)[1].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    for target, lines in sections.items():
        db_name = {
            "events": "events.db",
            "indicators": "indicators.db",
            "audit":  "audit.db",
            "allow_list": "allow_list.db",
        }.get(target)
        if db_name is None:
            continue
        conn = sqlite3.connect(client_dir / db_name)
        try:
            conn.executescript("\n".join(lines))
            conn.commit()
        finally:
            conn.close()


@pytest.fixture
def data_root(tmp_path):
    """A fresh OCTO data_root with one provisioned client `acme`."""
    root = tmp_path / "octo-data"
    (root / "clients" / "acme").mkdir(parents=True)
    _apply_client_migrations(root / "clients" / "acme")
    return root


@pytest.fixture
def sample_event():
    return CanonicalEvent(
        vendor_event_id="evt-001",
        received_at="2026-05-11T08:00:00.000Z",
        severity="high",
        indicator="8.8.8.8",
        indicator_type="ip",
        source_host="buoy-acme-1",
        summary="[authentication_failed] SSH brute force",
        payload={"rule": {"id": "5503", "level": 10}, "agent": {"name": "buoy-acme-1"}},
        payload_sha256="a" * 64,
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_ingest_writes_event_row(data_root, sample_event):
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", sample_event)

    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    rows = conn.execute(
        "SELECT source, source_host, severity, payload, payload_sha256 "
        "FROM events"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    source, host, severity, payload_json, sha = rows[0]
    assert source == "wazuh"
    assert host == "buoy-acme-1"
    assert severity == "high"
    payload = json.loads(payload_json)
    assert payload["rule"]["id"] == "5503"
    assert sha == "a" * 64


def test_ingest_preserves_relay_pending_default(data_root, sample_event):
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", sample_event)
    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    r = conn.execute("SELECT relay_status, relay_attempts FROM events").fetchone()
    conn.close()
    assert r[0] == "pending"
    assert r[1] == 0


def test_ingest_writes_indicator_on_first_seen(data_root, sample_event):
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", sample_event)
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    r = conn.execute(
        "SELECT value, type, source, severity, hits FROM indicators"
    ).fetchone()
    conn.close()
    assert r[0] == "8.8.8.8"
    assert r[1] == "ip"
    assert r[2] == "wazuh"
    assert r[3] == "high"
    assert r[4] == 1


def test_ingest_increments_hit_count_on_repeat(data_root, sample_event):
    """Same IOC seen again in DISTINCT events → hits++, NOT a new row."""
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    for second in ("00", "01", "02"):
        sink.ingest("acme", "wazuh", replace(
            sample_event, received_at=f"2026-05-11T08:00:{second}.000Z",
        ))
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    rows = conn.execute("SELECT id, hits FROM indicators").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][1] == 3


# ---------------------------------------------------------------------------
# Idempotency guard — (source, payload_sha256, received_at)
# ---------------------------------------------------------------------------

def _event_count(data_root) -> int:
    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def test_replay_is_a_duplicate_not_a_second_row(data_root, sample_event):
    """A byte-identical replay returns the EXISTING row id and neither
    re-counts the indicator nor writes again."""
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    first = sink.ingest("acme", "wazuh", sample_event)
    again = sink.ingest("acme", "wazuh", sample_event)

    assert (first.duplicate, again.duplicate) == (False, True)
    assert again.event_id == first.event_id
    assert _event_count(data_root) == 1
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    hits = conn.execute("SELECT hits FROM indicators").fetchone()[0]
    conn.close()
    assert hits == 1


def test_same_payload_at_a_different_time_or_source_still_stores(
    data_root, sample_event,
):
    """A lookup guard, not a UNIQUE index: only the full identity collapses."""
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", sample_event)
    later = sink.ingest("acme", "wazuh", replace(
        sample_event, received_at="2026-05-11T09:00:00.000Z",
    ))
    other_source = sink.ingest("acme", "datto", sample_event)

    assert not later.duplicate and not other_source.duplicate
    assert _event_count(data_root) == 3


def test_event_without_a_vendor_timestamp_is_deduped_on_payload_identity(
    data_root, sample_event,
):
    """received_at "" = the vendor gave no usable timestamp. The sink stamps
    receive-time, which therefore must NOT be part of the identity — or a
    poller re-reading the same open alert every 30 s stores ~2,880 rows/day."""
    import re
    sink = SqliteIngestSink(data_root=data_root)
    ev = replace(sample_event, received_at="")

    outcomes = [sink.ingest("acme", "datto", ev) for _ in range(3)]   # three drains

    assert [o.duplicate for o in outcomes] == [False, True, True]
    assert len({o.event_id for o in outcomes}) == 1
    assert _event_count(data_root) == 1
    stored = sqlite3.connect(data_root / "clients" / "acme" / "events.db").execute(
        "SELECT received_at FROM events").fetchone()[0]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", stored)   # never ""

    # a DIFFERENT timestamp-less alert still stores
    other = replace(ev, payload={**ev.payload, "alertUid": "another"},
                    payload_sha256="f" * 64)
    assert sink.ingest("acme", "datto", other).duplicate is False
    assert _event_count(data_root) == 2


def test_dedup_false_keeps_repeating_telemetry(data_root, sample_event):
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "buoy:fwd", sample_event, dedup=False)
    repeat = sink.ingest("acme", "buoy:fwd", sample_event, dedup=False)
    assert not repeat.duplicate
    assert _event_count(data_root) == 2


def test_lookup_index_is_created_on_a_db_provisioned_before_it_existed(
    data_root, sample_event,
):
    """Existing client DBs predate the migration-002 index line; the sink
    ensures it on first write, and it must not be UNIQUE."""
    db = data_root / "clients" / "acme" / "events.db"
    conn = sqlite3.connect(db)
    conn.execute("DROP INDEX IF EXISTS idx_events_payload_sha256")
    conn.commit()
    conn.close()

    SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "wazuh", sample_event,
    )

    conn = sqlite3.connect(db)
    row = conn.execute(
        "SELECT \"unique\" FROM pragma_index_list('events') "
        "WHERE name = 'idx_events_payload_sha256'"
    ).fetchone()
    conn.close()
    assert row is not None and row[0] == 0


def test_ingest_info_severity_maps_to_low_for_indicator(data_root):
    """Indicators table has no 'info' severity (CHECK constraint).
    Event-level 'info' → indicator-level 'low'."""
    info_event = CanonicalEvent(
        vendor_event_id="evt-info",
        received_at="2026-05-11T08:00:00.000Z",
        severity="info",
        indicator="1.1.1.1",
        indicator_type="ip",
        source_host="host-1",
        summary="info event",
        payload={"x": 1},
        payload_sha256="b" * 64,
    )
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", info_event)
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    sev = conn.execute("SELECT severity FROM indicators").fetchone()[0]
    conn.close()
    assert sev == "low"


def test_ingest_no_indicator_skips_indicator_write(data_root):
    """Event without an IOC → events.db row but NO indicators.db row."""
    bare_event = CanonicalEvent(
        vendor_event_id="evt-no-ioc",
        received_at="2026-05-11T08:00:00.000Z",
        severity="medium",
        indicator=None,
        indicator_type=None,
        source_host="host-1",
        summary="event with no IOC",
        payload={"x": 1},
        payload_sha256="c" * 64,
    )
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", bare_event)
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    n = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    conn.close()
    assert n == 0


def test_ingest_missing_tenant_db_raises(data_root, sample_event):
    """Ingest into a tenant that hasn't been provisioned → clear error,
    NOT a silent failure."""
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    with pytest.raises(FileNotFoundError, match="not-provisioned-tenant"):
        sink.ingest("not-provisioned-tenant", "wazuh", sample_event)


def test_ingest_unknown_indicator_type_falls_back_to_other(data_root):
    """An unmapped indicator_type doesn't trip the indicators CHECK
    constraint — sink coerces to 'other'."""
    weird_event = CanonicalEvent(
        vendor_event_id="evt-weird",
        received_at="2026-05-11T08:00:00.000Z",
        severity="medium",
        indicator="some-value",
        indicator_type="asn",  # not in the CHECK list
        source_host=None,
        summary="weird indicator type",
        payload={"x": 1},
        payload_sha256="d" * 64,
    )
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "wazuh", weird_event)
    conn = sqlite3.connect(data_root / "clients" / "acme" / "indicators.db")
    t = conn.execute("SELECT type FROM indicators").fetchone()[0]
    conn.close()
    assert t == "other"


# ---------------------------------------------------------------------------
# summary + event_type — what makes a stored row readable
# ---------------------------------------------------------------------------

def _add_summary_column(data_root: Path) -> None:
    """What migration 004 does to every provisioned client DB (the `data_root`
    fixture stops at 002)."""
    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    conn.execute("ALTER TABLE events ADD COLUMN summary TEXT NOT NULL DEFAULT ''")
    conn.commit()
    conn.close()


def _one_row(data_root: Path, columns: str) -> tuple:
    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    try:
        return conn.execute(f"SELECT {columns} FROM events").fetchone()
    finally:
        conn.close()


def test_the_adapters_summary_is_persisted(data_root, sample_event):
    """It was computed and then dropped: every adapter-written row had
    summary '' — a blank dashboard row, nothing for search to match."""
    _add_summary_column(data_root)
    SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "wazuh", sample_event,
    )
    assert _one_row(data_root, "summary, event_type") == (
        "[authentication_failed] SSH brute force", "alert",
    )


def test_a_db_without_the_summary_column_still_ingests(data_root, sample_event):
    outcome = SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "wazuh", sample_event,
    )
    assert outcome.event_id == 1 and not outcome.duplicate


def test_stored_summary_is_bounded(data_root, sample_event):
    _add_summary_column(data_root)
    SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "wazuh", replace(sample_event, summary="x" * 50_000),
    )
    assert len(_one_row(data_root, "summary")[0]) == 500


def test_stored_summary_is_cleaned_like_presented_text(data_root, sample_event):
    """Every adapter's summary is vendor-derived text and, once stored, goes
    to the feed, the drawer, exports and the triage model as-is. Control,
    bidi-override and zero-width characters are removed at the write; line
    breaks are kept (the drawer renders them); blank lines are dropped."""
    _add_summary_column(data_root)
    nasty = "sshd\x00 brute‮ force​ from\x1b[31m alice\x07\r\nsecond\x08 line\n\n\n"
    SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "buoy:x", replace(sample_event, summary=nasty), event_type="ids.brute_force",
    )
    (stored,) = _one_row(data_root, "summary")
    assert stored == "sshd brute force from[31m alice\nsecond line"


def test_event_type_comes_from_the_event_unless_the_caller_declares_one(
    data_root, sample_event,
):
    from apps.octo.ingest.presentation import TypedCanonicalEvent

    _add_summary_column(data_root)
    typed = TypedCanonicalEvent(
        **{**sample_event.__dict__, "event_type": "datto.eventlog"},
    )
    sink = SqliteIngestSink(data_root=data_root, publish_to_stream=False)
    sink.ingest("acme", "datto", typed)
    assert _one_row(data_root, "event_type") == ("datto.eventlog",)

    # A caller-declared type (the ingest router's) still wins.
    sink.ingest("acme", "datto", replace(typed, payload_sha256="e" * 64),
                event_type="suricata.dns")
    conn = sqlite3.connect(data_root / "clients" / "acme" / "events.db")
    types = [r[0] for r in conn.execute("SELECT event_type FROM events ORDER BY id")]
    conn.close()
    assert types == ["datto.eventlog", "suricata.dns"]


def test_a_summary_that_only_repeats_the_event_type_is_not_stored(
    data_root, sample_event,
):
    _add_summary_column(data_root)
    SqliteIngestSink(data_root=data_root, publish_to_stream=False).ingest(
        "acme", "buoy:x", replace(sample_event, summary="suricata.dns"),
        event_type="suricata.dns", dedup=False,
    )
    assert _one_row(data_root, "summary, event_type") == ("", "suricata.dns")
