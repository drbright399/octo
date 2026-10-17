"""The buoy forwarder's Pi-hole adapter against a real FTL-v6-shaped SQLite DB.

Regression: a query row whose domain is not valid UTF-8 (mDNS / DNS-SD names
can carry raw bytes) raised OperationalError("Could not decode to UTF-8
column 'domain' ...") on fetch. The poll loop treated every OperationalError
as "DB busy" and returned without advancing last_id — so the adapter retried
the same row forever and forwarded nothing more (seen on a production buoy:
~3.2 million queries behind)."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

FORWARDER = Path(__file__).resolve().parents[2] / "buoy" / "forwarder"
sys.path.insert(0, str(FORWARDER))
from adapters.pihole import PiholeAdapter  # noqa: E402


def _ftl_v6(path: Path, domains: list[bytes]) -> None:
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE query_storage (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER,
            status INTEGER, domain INTEGER, client INTEGER, forward INTEGER,
            additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER);
        CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);
        CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);
        CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);
        INSERT INTO client_by_id VALUES (1, '192.0.2.10', 'alice-laptop');
        INSERT INTO forward_by_id VALUES (1, '198.51.100.53#53');
    """)
    for i, raw in enumerate(domains, start=1):
        # Store the raw bytes AS TEXT exactly as FTL would, bypassing Python's encoder.
        c.execute("INSERT INTO domain_by_id VALUES (?, CAST(? AS TEXT))", (i, raw))
        c.execute("INSERT INTO query_storage VALUES (?, 1700000000, 1, 2, ?, 1, 1, NULL, 3, 0.01, 0)", (i, i))
    c.commit()
    c.close()


def _drain(adapter: PiholeAdapter) -> list:
    return list(adapter.iter_events())


def test_undecodable_domain_does_not_stall_the_adapter(tmp_path):
    db = tmp_path / "pihole-FTL.db"
    _ftl_v6(db, [b"good.example.test", b"b._dns-sd._udp.\xff\xfe\x00local", b"after.example.test"])
    adapter = PiholeAdapter(db_path=db, state_dir=tmp_path / "state", hostname="buoy-test")
    # First run starts at the tail (existing rows are history) — rewind to replay them.
    adapter._last_id = 0
    events = _drain(adapter)
    assert adapter._last_id == 3, "last_id must advance past the undecodable row"
    domains = [e["data"]["raw_query"].get("domain") for e in events]
    assert len(events) == 3
    assert any(d and "�" in d for d in domains), "the bad bytes are replaced, not dropped"
    assert _drain(adapter) == [], "nothing replays on the next cycle"


def test_old_behaviour_reproduced_without_the_fix(tmp_path):
    """Pins the failure mode the fix addresses: default decoding raises."""
    db = tmp_path / "pihole-FTL.db"
    _ftl_v6(db, [b"b._dns-sd._udp.\xff\xfe"])
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError, match="decode"):
        c.execute("SELECT domain FROM domain_by_id").fetchall()
    c.close()


# ---------------------------------------------------------------------------
# The status table against Pi-hole FTL's documented query status codes (T6)
# ---------------------------------------------------------------------------

# docs.pi-hole.net → Database → Query database → "Query status" (FTL v5 and
# v6; v6 adds 18): code → (label, severity) the forwarder must emit.
DOCUMENTED = {
    0: ("unknown", "info"),                    # Unknown status (not answered)
    1: ("blocked-gravity", "low"),             # Blocked by gravity
    2: ("forwarded", "info"),                  # Forwarded
    3: ("cached", "info"),                     # Replied from cache
    4: ("blocked-regex", "low"),               # Blocked by regex blacklist
    5: ("blocked-denylist", "low"),            # Blocked by exact blacklist
    6: ("blocked-upstream-ip", "low"),         # Blocked by upstream (blocking page IP)
    7: ("blocked-upstream-null", "low"),       # Blocked by upstream (0.0.0.0 / ::)
    8: ("blocked-upstream-nxdomain", "low"),   # Blocked by upstream (NXDOMAIN, RA unset)
    9: ("blocked-gravity-cname", "low"),       # Blocked by gravity (deep CNAME)
    10: ("blocked-regex-cname", "low"),        # Blocked by regex (deep CNAME)
    11: ("blocked-denylist-cname", "low"),     # Blocked by exact blacklist (deep CNAME)
    12: ("retried", "info"),                   # Retried query
    13: ("retried-dnssec", "info"),            # Retried but ignored (DNSSEC)
    14: ("in-progress", "info"),               # Already forwarded, not forwarding again
    15: ("blocked-dbbusy", "low"),             # Blocked (database is busy)
    16: ("blocked-special-domain", "low"),     # Blocked (special domain)
    17: ("cached-stale", "info"),              # Replied from stale cache
    18: ("blocked-upstream-ede15", "low"),     # Blocked by upstream (EDE 15)
}


def _ftl_v6_status(path: Path, statuses: list[int]) -> None:
    _ftl_v6(path, [f"s{s}.example.test".encode() for s in statuses])
    c = sqlite3.connect(path)
    for i, status in enumerate(statuses, start=1):
        c.execute("UPDATE query_storage SET status = ? WHERE id = ?", (status, i))
    c.commit()
    c.close()


@pytest.mark.parametrize("code", sorted(DOCUMENTED))
def test_each_documented_status_code_gets_its_label_and_severity(tmp_path, code):
    """One row per documented code through the real adapter on an FTL v6
    DB: the label names what FTL documents, a block is "low", an answered
    query "info"."""
    db = tmp_path / "pihole-FTL.db"
    _ftl_v6_status(db, [code])
    adapter = PiholeAdapter(db_path=db, state_dir=tmp_path / "state", hostname="buoy-test")
    adapter._last_id = 0
    [event] = _drain(adapter)
    raw = event["data"]["raw_query"]
    assert raw["status"] == code
    assert (raw["status_label"], event["severity"]) == DOCUMENTED[code]


def test_the_table_is_exactly_the_documented_codes_and_agrees_with_the_server():
    """The forwarder's table and the server's classifier
    (`apps.octo.ingest.tiering.PIHOLE_STATUS`) read the same codes the same
    way: blocked ⇔ severity "low"; every documented code is mapped; an
    undocumented one is ("unknown", "info")."""
    from adapters.pihole import _STATUS_TABLE

    from apps.octo.ingest.tiering import PIHOLE_STATUS

    assert _STATUS_TABLE == DOCUMENTED
    assert set(_STATUS_TABLE) == set(PIHOLE_STATUS)
    for code, (_name, blocked) in PIHOLE_STATUS.items():
        assert (_STATUS_TABLE[code][1] == "low") is bool(blocked), code
        assert _STATUS_TABLE[code][0].startswith("blocked-") is bool(blocked), code


def test_an_undocumented_status_is_unknown_info(tmp_path):
    db = tmp_path / "pihole-FTL.db"
    _ftl_v6_status(db, [99])
    adapter = PiholeAdapter(db_path=db, state_dir=tmp_path / "state", hostname="buoy-test")
    adapter._last_id = 0
    [event] = _drain(adapter)
    assert (event["data"]["raw_query"]["status_label"], event["severity"]) == ("unknown", "info")
