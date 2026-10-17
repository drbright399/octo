"""v0.17.2 review fixes — the Fleet's counts against real stores:

  * a RocketCyber incident acknowledged days ago stays out of the Yellow
    while it is open (the ack is read by incident, whatever its age);
  * the DNS MEDIUM count is never only a difference: the ledger's own
    count is its floor (the roll-up lags) — and, merged with v0.17.1, an
    acknowledgement never takes a block out of a count (the counts are
    facts; the Yellow is the device view);
  * an acknowledged MEDIUM day bucket that began before the window's first
    whole day but whose first hit is inside the window counts as hidden
    (the drawer hides it); one with hits from before the window does not
    (its share is unknown: louder);
  * the IPS counts shown keep every hit (`raw`) — only the Yellow is the
    humans' to change.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from apps.octo.fleet import sources
from apps.octo.ingest import telemetry
from apps.octo.verdicts.state import TenantVerdicts
from apps.octo.verdicts.tests.helpers import SCOPE_B, store_ips_hit
from apps.octo.verdicts.tests.test_fleet_counts import A, _ack, _event, _iso, _now, _rc, _tv


def _medium_bucket(slug: str, *, device: str, hits: int, hour: str, first: datetime,
                   last: datetime, reason: str = "nrd") -> int:
    eid = _event(slug, source="nextdns", event_type="nextdns.security_block", at=first, payload={
        "kind": "security_block", "profile_id": "p1",
        "log": {"domain": "x.fresh-example.test", "root": "fresh-example.test",
                "device": {"id": device}, "reasons": [{"id": reason}]},
        "signal": {"reason_id": reason, "level": "medium", "bucket_hour": hour,
                   "bucket_span": "day", "cross_domain": True}})
    path = telemetry.db_path_for(slug)
    telemetry.ensure_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO nextdns_signal_buckets (bucket_key, hour, span, profile_id, reason_id, "
            "root, device, event_id, hits, first_seen, last_seen) "
            "VALUES (?, ?, 'day', 'p1', ?, '*', ?, ?, ?, ?, ?)",
            (f"k-{eid}", hour, reason, device, eid, hits, _iso(first), _iso(last)))
        conn.commit()
    finally:
        conn.close()
    return eid


def _rollup(slug: str, at: datetime, medium: int) -> None:
    path = telemetry.db_path_for(slug)
    telemetry.ensure_db(path)
    hour = at.strftime("%Y-%m-%dT%H:00:00Z")
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO nextdns_hourly (hour, profile_id, signal_medium, fetched_at) "
            "VALUES (?, 'p1', ?, 'x') ON CONFLICT (hour, profile_id) DO UPDATE SET "
            "signal_medium = signal_medium + excluded.signal_medium", (hour, medium))
        conn.commit()
    finally:
        conn.close()


def test_a_rocketcyber_ack_holds_while_the_incident_stays_open_for_days(troot):
    first = _rc(A, 101, "open", "Suspicious PowerShell", 30)
    _ack(A, first)
    later = _now() + timedelta(hours=72)                 # no new version since
    assert sources.rocketcyber_open(A, later) == 1
    hidden: dict[str, int] = {}
    tv = TenantVerdicts.load(A, later)
    assert sources.rocketcyber_open(A, later, verdicts=tv, hidden=hidden) == 0
    assert hidden == {"rocketcyber": 1}


def test_the_medium_count_is_never_only_a_difference(troot):
    now = _now()
    since = now - timedelta(hours=24)
    today = now.strftime("%Y-%m-%dT00:00:00Z")
    acked = _medium_bucket(A, device="D1", hits=10, hour=today,
                           first=now - timedelta(minutes=50), last=now - timedelta(minutes=1))
    _medium_bucket(A, device="D2", hits=5, hour=today, first=now - timedelta(minutes=40),
                   last=now - timedelta(minutes=2))
    _rollup(A, now, 12)                  # the roll-up lags: 7 of the 10, all 5 of the other
    _ack(A, acked)
    hidden: dict[str, int] = {}
    counts = sources.dns_threats(A, ["p1"], since, verdicts=_tv(), hidden=hidden)["p1"]
    assert counts.medium == 15           # the ledger's 10 + 5, not the lagging 12
    assert counts.total == 15 and hidden == {"p1": 10}


def test_an_early_day_bucket_wholly_inside_the_window_is_hidden_when_acknowledged(troot):
    now = _now()
    since = now - timedelta(hours=24)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = (today - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
    # Began yesterday (before the first whole day of the window) — but its
    # first hit is inside the window: all its hits are.
    inside = _medium_bucket(A, device="D1", hits=4, hour=yesterday,
                            first=since + timedelta(minutes=30),
                            last=since + timedelta(minutes=40))
    _rollup(A, since + timedelta(minutes=30), 4)
    # Began before the window: part of its hits are older — its in-window
    # share is unknown, it is never taken out (louder).
    straddles = _medium_bucket(A, device="D3", hits=6, hour=yesterday,
                               first=since - timedelta(hours=2),
                               last=since + timedelta(minutes=50))
    _rollup(A, since + timedelta(minutes=50), 2)
    assert sources.dns_threats(A, ["p1"], since)["p1"].medium == 6
    _ack(A, inside)
    _ack(A, straddles)
    hidden: dict[str, int] = {}
    counts = sources.dns_threats(A, ["p1"], since, verdicts=_tv(), hidden=hidden)["p1"]
    assert counts.medium == 6 and counts.total == 6
    assert hidden == {"p1": 4}


def test_the_ips_counts_shown_keep_every_hit(troot):
    t0 = (_now() - timedelta(minutes=5)).replace(minute=1, second=0, microsecond=0)
    since = _now() - timedelta(hours=24)
    eid = store_ips_hit(A, SCOPE_B, t0, remote="203.0.113.66")
    store_ips_hit(A, SCOPE_B, t0 + timedelta(seconds=1), remote="203.0.113.66")
    _ack(A, eid)
    raw: dict[str, tuple[int, int, int]] = {}
    assert sources.ips_counts(A, since, verdicts=_tv(), raw=raw) == {}
    assert raw == {SCOPE_B: (0, 2, 0)}
    raw = {}
    assert sources.ips_counts(A, since, raw=raw) == raw == {SCOPE_B: (0, 2, 0)}
