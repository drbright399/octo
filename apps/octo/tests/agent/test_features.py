"""Unit tests for feature derivation (Task #119b).

Uses in-memory SQLite so recurrence + indicator-hit logic is verified
without the full data-root machinery.
"""
from __future__ import annotations

import sqlite3

from apps.octo.agent.features import build_features


def _events_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "received_at TEXT, source TEXT, source_host TEXT, event_type TEXT, "
        "severity TEXT, payload TEXT, summary TEXT)"
    )
    return conn


def _indicators_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE indicators (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "value TEXT, hits INTEGER, deleted_at TEXT)"
    )
    return conn


def _add_event(conn, *, severity="medium", source="s", host="h",
               etype="t", payload="{}"):
    cur = conn.execute(
        "INSERT INTO events (received_at, source, source_host, event_type, "
        "severity, payload, summary) VALUES ('t', ?, ?, ?, ?, ?, '')",
        (source, host, etype, severity, payload),
    )
    conn.commit()
    return conn.execute("SELECT * FROM events WHERE id = ?", (cur.lastrowid,)).fetchone()


def test_recurrence_counts_prior_same_signature():
    ev = _events_conn()
    _add_event(ev, host="h", etype="t")
    _add_event(ev, host="h", etype="t")
    row = _add_event(ev, host="h", etype="t")  # 3rd, 2 priors
    f = build_features(row, events_conn=ev, indicators_conn=None)
    assert f.recurrence_count == 2


def test_recurrence_excludes_other_host_and_type():
    ev = _events_conn()
    _add_event(ev, host="other", etype="t")
    _add_event(ev, host="h", etype="other")
    row = _add_event(ev, host="h", etype="t")  # no matching priors
    f = build_features(row, events_conn=ev, indicators_conn=None)
    assert f.recurrence_count == 0


def test_indicator_extracted_and_hits_counted():
    ev = _events_conn()
    ind = _indicators_conn()
    ind.execute(
        "INSERT INTO indicators (value, hits, deleted_at) VALUES ('203.0.113.4', 3, NULL)"
    )
    ind.commit()
    row = _add_event(ev, payload='{"src_ip": "203.0.113.4"}')
    f = build_features(row, events_conn=ev, indicators_conn=ind)
    assert f.has_indicator is True
    assert f.indicator_hits == 2  # hits(3) - 1 = prior sightings


def test_no_indicator_in_payload():
    ev = _events_conn()
    row = _add_event(ev, payload='{"message": "nothing ioc-ish here"}')
    f = build_features(row, events_conn=ev, indicators_conn=None)
    assert f.has_indicator is False
    assert f.indicator_hits == 0


def test_indicator_unknown_to_db_zero_hits():
    ev = _events_conn()
    ind = _indicators_conn()
    row = _add_event(ev, payload='{"domain": "evil.example"}')
    f = build_features(row, events_conn=ev, indicators_conn=ind)
    assert f.has_indicator is True
    assert f.indicator_hits == 0


def test_malformed_payload_is_safe():
    ev = _events_conn()
    row = _add_event(ev, payload="not-json{")
    f = build_features(row, events_conn=ev, indicators_conn=None)
    assert f.has_indicator is False
