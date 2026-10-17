"""The Fleet's Yellow counts honour the human verdicts (v0.17.2) — and only
the health layers' counts: an acknowledged / expected NextDNS block, UniFi
IPS bucket, RocketCyber incident or decoy PORT TOUCH stops counting; a decoy
CREDENTIAL attempt never does; a CSAM block is never "expected"; a NEW
occurrence counts again. Plus the UniFi ledger's per-remote split (046)."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from apps.octo import paths
from apps.octo.adapters.unifi import store as ustore
from apps.octo.db import connect, transaction
from apps.octo.fleet import sources
from apps.octo.ingest import telemetry
from apps.octo.threat import store as incident_store
from apps.octo.verdicts import annotate, keys, occurrences
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import TenantVerdicts
from apps.octo.verdicts.tests.helpers import SCOPE_B, store_ips_hit

A = "acme-corp"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _event(slug: str, *, source: str, event_type: str, payload: dict,
           summary: str = "", at: datetime | None = None) -> int:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256, summary) VALUES (?, ?, NULL, ?, 'high', ?, ?, ?)",
            (_iso(at or _now() - timedelta(minutes=3)), source, event_type, json.dumps(payload),
             f"sha-{os.urandom(6).hex()}", summary))
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def _ack(slug: str, event_id: int, *, repeat: bool = False) -> None:
    row = occurrences.event_rows(slug, [event_id])[event_id]
    a = annotate.one(slug, row)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            # As the API records it: a single event's own time as last-seen.
            vstore.record(reg, slug=slug, event_id=event_id, key=a.key, verdict=vstore.ACK,
                          actor=1, hits_at=a.hits,
                          last_seen_at=a.last_seen or a.occurrence.last_at,
                          repeat_until=_now() + timedelta(hours=24) if repeat else None)
    finally:
        reg.close()


def _tv(slug: str = A) -> TenantVerdicts:
    return TenantVerdicts.load(slug, _now())


# ---------------------------------------------------------------------------
# NextDNS
# ---------------------------------------------------------------------------

def _dns_block(slug: str, *, reason: str, hits: int, device: str = "D1",
               root: str = "bad.example.test") -> int:
    now = _now()
    hour = now.strftime("%Y-%m-%dT%H:00:00Z")
    eid = _event(slug, source="nextdns", event_type="nextdns.security_block", payload={
        "kind": "security_block", "profile_id": "p1",
        "log": {"domain": f"x.{root}", "root": root, "device": {"id": device},
                "reasons": [{"id": reason}]},
        "signal": {"reason_id": reason, "level": "high", "bucket_hour": hour}})
    path = telemetry.db_path_for(slug)
    telemetry.ensure_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO nextdns_signal_buckets (bucket_key, hour, span, profile_id, reason_id, "
            "root, device, event_id, hits, first_seen, last_seen) "
            "VALUES (?, ?, 'hour', 'p1', ?, ?, ?, ?, ?, ?, ?)",
            (f"k-{eid}", hour, reason, root, device, eid, hits, _iso(now - timedelta(minutes=5)),
             _iso(now - timedelta(minutes=4))))
        conn.execute(
            "INSERT INTO nextdns_hourly (hour, profile_id, signal_high, fetched_at) "
            "VALUES (?, 'p1', ?, 'x') ON CONFLICT (hour, profile_id) DO UPDATE SET "
            "signal_high = signal_high + excluded.signal_high", (hour, hits))
        conn.commit()
    finally:
        conn.close()
    return eid


def test_an_acknowledged_dns_block_leaves_the_device_view_and_csam_is_never_expected(troot):
    """Merged with v0.17.1: DNS blocks are a count (a fact, every block — a
    notice); the Yellow is the DEVICE view (beaconing hours, device-
    originated reasons). An acknowledged bucket leaves the device view (its
    hits to `hidden`); the count stays."""
    since = _now() - timedelta(hours=24)
    dga = _dns_block(A, reason="dga", hits=3)
    before = sources.dns_threats(A, ["p1"], since)["p1"]
    assert [d.key for d in before.devices] == ["D1"]
    assert dict(before.devices[0].originated) == {"dga": 3}
    _ack(A, dga)
    hidden: dict[str, int] = {}
    after = sources.dns_threats(A, ["p1"], since, verdicts=_tv(), hidden=hidden)["p1"]
    assert after.devices == () and hidden == {"p1": 3}
    assert (after.high, after.total) == (before.high, before.total)
    # An expected condition can never cover a CSAM bucket (even one built
    # past the API, the schema and the poller).
    _dns_block(A, reason="csam", hits=2, device="D2", root="csam.example.test")
    csam_key = keys.nextdns_key("p1", "D2", "csam.example.test", "csam")
    rule = vstore.ExpectedRule(9, A, "nextdns", csam_key.device_key, csam_key.signature_key,
                               None, "x", "a bad caller's rule", 1, 1,
                               _iso(_now() - timedelta(days=1)), _iso(_now() + timedelta(days=9)))
    tv = TenantVerdicts(A, [], [rule], now=_now())
    hidden = {}
    sources.dns_threats(A, ["p1"], since, verdicts=tv, hidden=hidden)
    assert hidden == {}


# ---------------------------------------------------------------------------
# RocketCyber
# ---------------------------------------------------------------------------

def _rc(slug: str, iid: int, status: str, title: str, minutes: int) -> int:
    return _event(slug, source="rocketcyber", event_type="rocketcyber.incident",
                  payload={"id": iid, "status": status, "title": title},
                  summary=f"RocketCyber: {title}", at=_now() - timedelta(minutes=minutes))


def test_an_acknowledged_rocketcyber_incident_stops_counting_until_a_new_version(troot):
    first = _rc(A, 101, "open", "Suspicious PowerShell", 30)
    _rc(A, 102, "open", "Example tool installed", 20)
    assert sources.rocketcyber_open(A, _now()) == 2
    _ack(A, first)
    hidden: dict[str, int] = {}
    assert sources.rocketcyber_open(A, _now(), verdicts=_tv(), hidden=hidden) == 1
    assert hidden == {"rocketcyber": 1}
    _rc(A, 101, "open", "Suspicious PowerShell", 1)                   # a newer version
    assert sources.rocketcyber_open(A, _now(), verdicts=_tv()) == 2


# ---------------------------------------------------------------------------
# Decoys
# ---------------------------------------------------------------------------

def test_an_acknowledged_port_touch_stops_counting_a_credential_never_does(troot):
    incident_store.ensure_schema(A)
    touch = _event(A, source="buoy", event_type="opencanary.http",
                   payload={"src_host": "192.0.2.9", "logtype": 3000})
    cred = _event(A, source="buoy", event_type="opencanary.ssh",
                  payload={"src_host": "192.0.2.9", "logtype": 4002})
    observed = _iso(_now() - timedelta(minutes=2))
    incident_store.add_fact(A, fact_key=f"evt:{touch}:R6", kind="canary_touch", stage="live",
                            observed_at=observed, source="buoy", source_event_id=touch)
    incident_store.add_fact(A, fact_key=f"evt:{cred}:R6", kind="canary_credential",
                            stage="shadow", observed_at=observed, source="buoy",
                            source_event_id=cred)
    assert sources.canary_touches(A, _now()) == 2
    _ack(A, touch)
    _ack(A, cred)
    hidden: dict[str, int] = {}
    assert sources.canary_touches(A, _now(), verdicts=_tv(), hidden=hidden) == 1
    assert hidden == {"canary": 1}


# ---------------------------------------------------------------------------
# UniFi IPS + the per-remote split
# ---------------------------------------------------------------------------

def test_ips_counts_skip_an_acknowledged_bucket_and_the_remotes_are_split(troot):
    t0 = (_now() - timedelta(minutes=5)).replace(minute=1, second=0, microsecond=0)
    since = _now() - timedelta(hours=24)
    eid = store_ips_hit(A, SCOPE_B, t0, remote="203.0.113.66")
    store_ips_hit(A, SCOPE_B, t0 + timedelta(seconds=1), remote="203.0.113.66")
    store_ips_hit(A, SCOPE_B, t0 + timedelta(seconds=2), remote="203.0.113.77")
    (info,) = ustore.bucket_info(A, [eid]).values()
    assert info.hits == 3 and info.remotes == {"203.0.113.66": 2, "203.0.113.77": 1}
    assert sources.ips_counts(A, since) == {SCOPE_B: (0, 3, 0)}
    _ack(A, eid)
    hidden: dict[str, int] = {}
    assert sources.ips_counts(A, since, verdicts=_tv(), hidden=hidden) == {}
    assert hidden == {SCOPE_B: 3}
    store_ips_hit(A, SCOPE_B, t0 + timedelta(seconds=3), remote="203.0.113.77")
    assert sources.ips_counts(A, since, verdicts=_tv()) == {SCOPE_B: (0, 4, 0)}  # re-surfaced


def test_the_remote_split_is_bounded_and_only_for_ips():
    claim = ustore.Claim("k", "h", "ips_threat", "s", "t", {}, remote=None)
    held = None
    for n in range(20):
        held = ustore.merge_remotes(held, ustore.Claim("k", "h", "ips_threat", "s", "t", {},
                                                       remote=f"198.51.100.{n}"))
    held = ustore.merge_remotes(held, claim)
    split = json.loads(held)
    assert len([k for k in split if k not in ("~", "?")]) == ustore.REMOTES_MAX
    assert split["~"] == 4 and split["?"] == 1 and sum(split.values()) == 21
    other = ustore.Claim("k", "h", "wan_down", "s", "t", {}, remote="198.51.100.1")
    assert ustore.merge_remotes(None, other) is None
