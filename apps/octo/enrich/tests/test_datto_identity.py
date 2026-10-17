"""WHICH device a Datto alert is (v0.17.2): two PCs named "Shared-PC" at
two sites of one client are two machines — the alert carries its Datto
device uid, site, LAN and WAN address, a warning that the name is shared,
and "N repeats" counts THIS device only (keyed by the device uid, never
the host name). Fictional tenant and devices; documentation addresses only
(192.0.2.x stands in for a LAN: the device list's addresses are only read
back here, never classified)."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from apps.octo import paths
from apps.octo.enrich import alerts
from apps.octo.entity import normalize as nz
from apps.octo.entity.db import TenantDB

A = "acme-corp"


def _device(conn: sqlite3.Connection, uid: str, host: str, *, site: str, lan: str, wan: str,
            missing: bool = False) -> None:
    conn.execute(
        "INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
        "hostname_key, device_type, online, int_ip, ext_ip, first_seen_at, updated_at, "
        "missing_since) VALUES (1, ?, ?, ?, ?, 'Desktop', 1, ?, ?, "
        "'2026-10-01T00:00:00.000Z', '2026-10-06T00:00:00.000Z', ?)",
        (uid, site, host, nz.name_key(nz.hostname(host)), lan, wan,
         "2026-10-05T00:00:00.000Z" if missing else None))


def _alert(now: datetime, uid: str, device: str, host: str, site: str, minutes: int) -> dict:
    payload = {"alertUid": uid, "priority": "High",
               "alertSourceInfo": {"deviceUid": device, "deviceName": host, "siteName": site},
               "alertContext": {"@class": "eventlog_ctx", "logName": "System", "code": "1000",
                                "source": "example-source", "description": "Example event."}}
    at = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, severity, "
            "payload, payload_sha256) VALUES (?, 'datto', ?, 'datto.eventlog', 'high', ?, ?)",
            (at, host, json.dumps(payload), f"sha-{os.urandom(6).hex()}"))
        conn.commit()
        rid = int(cur.lastrowid)
    finally:
        conn.close()
    return {"id": rid, "source": "datto", "source_host": host, "received_at": at,
            "payload": json.dumps(payload)}


def test_two_machines_one_name_are_told_apart(troot):
    tdb = TenantDB.for_tenant(A)
    tdb.ensure()
    with tdb.write() as conn:
        _device(conn, "dev-a", "Shared-PC", site="site-a", lan="192.0.2.20",
                wan="203.0.113.10")
        _device(conn, "dev-b", "SHARED-PC.example.local", site="site-b",
                lan="192.0.2.120", wan="198.51.100.7")
        _device(conn, "dev-old", "Shared-PC", site="site-a", lan="192.0.2.21",
                wan="203.0.113.10", missing=True)               # Datto no longer lists it
        _device(conn, "dev-srv", "SRV-01", site="site-a", lan="192.0.2.2",
                wan="203.0.113.10")
    now = datetime.now(timezone.utc)
    # Three alerts from the site-B PC; one from the site-A PC.
    site_b = [_alert(now, f"0000cccc-0000-0000-0000-00000000000{i}", "dev-b", "Shared-PC",
                     "Example Site B", 60 * i) for i in range(1, 4)]
    site_a = _alert(now, "0000cccc-0000-0000-0000-000000000009", "dev-a", "Shared-PC",
                    "Example Site A", 30)
    srv = _alert(now, "0000cccc-0000-0000-0000-00000000000a", "dev-srv", "SRV-01",
                 "Example Site A", 30)
    out = alerts.datto(A, [site_b[0], site_a, srv], now=now)

    p, o, s = out[site_b[0]["id"]], out[site_a["id"]], out[srv["id"]]
    assert (p["device_uid"], p["site"], p["lan_ip"], p["wan_ip"]) == \
        ("dev-b", "Example Site B", "192.0.2.120", "198.51.100.7")
    assert (o["device_uid"], o["site"], o["lan_ip"], o["wan_ip"]) == \
        ("dev-a", "Example Site A", "192.0.2.20", "203.0.113.10")
    # Two devices (the one Datto dropped does not count) at two sites.
    assert (p["shared_hostname"], p["shared_sites"]) == (2, 2)
    assert (o["shared_hostname"], o["shared_sites"]) == (2, 2)
    assert (s["shared_hostname"], s["shared_sites"]) == (0, 0)
    # Repeats are THIS device's: never merged across the two by name.
    assert p["repeats"] == 2 and o["repeats"] == 0


def test_a_device_not_in_the_list_still_gets_its_uid_and_site(troot):
    now = datetime.now(timezone.utc)
    row = _alert(now, "0000dddd-0000-0000-0000-000000000001", "dev-new", "NEW-PC",
                 "Example Site A", 5)
    e = alerts.datto(A, [row], now=now)[row["id"]]
    assert (e["device_uid"], e["site"], e["lan_ip"], e["wan_ip"]) == \
        ("dev-new", "Example Site A", None, None)
    assert e["shared_hostname"] == 0


# ---------------------------------------------------------------------------
# v0.17.3 — the device's serial number, manufacturer and model (its audit)
# ---------------------------------------------------------------------------

def _serial(conn: sqlite3.Connection, uid: str, serial, manufacturer=None, model=None) -> None:
    conn.execute("UPDATE inv_device SET serial = ?, manufacturer = ?, model = ?, audit_at = "
                 "'2026-10-07T00:00:00.000Z' WHERE device_uid = ?",
                 (serial, manufacturer, model, uid))


def test_the_device_line_carries_its_serial_and_the_other_devices_serials(troot):
    tdb = TenantDB.for_tenant(A)
    tdb.ensure()
    with tdb.write() as conn:
        _device(conn, "dev-a", "Shared-PC", site="site-a", lan="192.0.2.20",
                wan="203.0.113.10")
        _device(conn, "dev-b", "SHARED-PC", site="site-b", lan="192.0.2.120",
                wan="198.51.100.7")
        _device(conn, "dev-c", "shared-pc", site="site-b", lan="192.0.2.121",
                wan="198.51.100.7")
        _device(conn, "dev-old", "Shared-PC", site="site-a", lan="192.0.2.21",
                wan="203.0.113.10", missing=True)
        _serial(conn, "dev-a", "EXAMPLE-SN-A", "Example Computers Inc.", "Model 7")
        _serial(conn, "dev-b", "EXAMPLE-SN-B")
        _serial(conn, "dev-c", None)                          # audited: no serial
        _serial(conn, "dev-old", "EXAMPLE-SN-GONE")           # Datto dropped it
    now = datetime.now(timezone.utc)
    site_a = _alert(now, "0000eeee-0000-0000-0000-000000000001", "dev-a", "Shared-PC",
                    "Example Site A", 10)
    site_b = _alert(now, "0000eeee-0000-0000-0000-000000000002", "dev-b", "Shared-PC",
                    "Example Site B", 10)
    out = alerts.datto(A, [site_a, site_b], now=now)
    o, p = out[site_a["id"]], out[site_b["id"]]
    assert (o["serial"], o["manufacturer"], o["model"]) == \
        ("EXAMPLE-SN-A", "Example Computers Inc.", "Model 7")
    assert (p["serial"], p["manufacturer"], p["model"]) == ("EXAMPLE-SN-B", None, None)
    # Three devices carry the name (the dropped one does not count); the
    # warning names the OTHER devices' serials where known — never its own.
    assert (o["shared_hostname"], o["shared_sites"]) == (3, 2)
    assert o["shared_serials"] == ["EXAMPLE-SN-B"]
    assert p["shared_serials"] == ["EXAMPLE-SN-A"]


def test_a_device_without_an_audit_and_an_unknown_device_have_no_serial(troot):
    tdb = TenantDB.for_tenant(A)
    tdb.ensure()
    with tdb.write() as conn:
        _device(conn, "dev-1", "WS-1", site="site-a", lan="192.0.2.30",
                wan="203.0.113.10")
    now = datetime.now(timezone.utc)
    known = _alert(now, "0000ffff-0000-0000-0000-000000000001", "dev-1", "WS-1", "Office", 5)
    unknown = _alert(now, "0000ffff-0000-0000-0000-000000000002", "dev-x", "WS-X", "Office", 5)
    out = alerts.datto(A, [known, unknown], now=now)
    for e in out.values():
        assert (e["serial"], e["manufacturer"], e["model"], e["shared_serials"]) == \
            (None, None, None, [])
    assert out[known["id"]]["lan_ip"] == "192.0.2.30"


def test_a_tenant_file_not_yet_at_047_reads_as_no_serial_never_an_error(troot):
    """The lazy-migration rule: a read path never migrates and never fails on
    a column a file does not have yet — the drawer keeps the device's LAN /
    WAN address (046) and simply has no serial; a file at 040 (no ext_ip)
    still names the LAN address."""
    from apps.octo.migration import apply_migration, list_migrations

    path = TenantDB.for_tenant(A).path
    by_number = {m.number: m for m in list_migrations(kind="forward")}
    now = datetime.now(timezone.utc)
    for upto, wan in ((46, "203.0.113.10"), (40, None)):
        for f in path.parent.glob("entities.db*"):
            f.unlink()
        conn = sqlite3.connect(path)
        try:
            for num in (40, 46):
                if num <= upto:
                    apply_migration(conn, by_number[num], target="entities")
            cols = "int_ip, ext_ip" if upto >= 46 else "int_ip"
            vals = "'192.0.2.40', '203.0.113.10'" if upto >= 46 else "'192.0.2.40'"
            for uid in ("dev-1", "dev-2"):
                conn.execute(
                    f"INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, "
                    f"hostname, hostname_key, {cols}, first_seen_at, updated_at) VALUES "
                    f"(1, ?, 'site-a', 'WS-1', ?, {vals}, 'a', 'b')",
                    (uid, nz.name_key(nz.hostname("WS-1"))))
            conn.commit()
        finally:
            conn.close()
        row = _alert(now, f"0000abab-0000-0000-0000-0000000000{upto}", "dev-1", "WS-1",
                     "Office", 5)
        e = alerts.datto(A, [row], now=now)[row["id"]]
        assert (e["lan_ip"], e["wan_ip"]) == ("192.0.2.40", wan), upto
        assert (e["serial"], e["manufacturer"], e["model"]) == (None, None, None), upto
        assert (e["shared_hostname"], e["shared_serials"]) == (2, []), upto
        conn = sqlite3.connect(path)
        try:                                       # a read never migrated the file
            assert conn.execute("PRAGMA user_version").fetchone()[0] == upto
        finally:
            conn.close()
