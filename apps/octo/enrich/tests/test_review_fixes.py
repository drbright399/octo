"""v0.17.2 review fixes — enrichment:

  * the local device's Datto name only when exactly ONE device (not missing,
    not at a Datto site linked to another of the tenant's UniFi sites) holds
    the address — two offices on the same LAN subnet are ambiguous: no Datto
    name, never a guess;
  * an RDAP owner label needs a WHOLE word ("modat" is not in
    "Accommodation");
  * a Datto raise whose resolution row was stored since reads resolved.
Fictional tenants and devices; documentation addresses only (192.0.2.x
stands in for a LAN: the Datto name lookup matches the address, never
classifies it).
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from apps.octo import paths
from apps.octo.enrich import alerts, labels
from apps.octo.entity.db import TenantDB

A = "acme-corp"


def _device(conn: sqlite3.Connection, uid: str, host: str, ip: str, *, site: str = "site-1",
            missing: bool = False, inst: int = 1) -> None:
    conn.execute(
        "INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, hostname, "
        "hostname_key, device_type, online, int_ip, first_seen_at, updated_at, missing_since) "
        "VALUES (?, ?, ?, ?, ?, 'Desktop', 1, ?, '2026-10-01T00:00:00.000Z', "
        "'2026-10-06T00:00:00.000Z', ?)",
        (inst, uid, site, host, host.lower(), ip,
         "2026-10-05T00:00:00.000Z" if missing else None))


def test_a_datto_name_only_for_an_address_one_device_holds(troot):
    tdb = TenantDB.for_tenant(A)
    tdb.ensure()
    with tdb.write() as conn:
        _device(conn, "dev-a", "OFFICE-A-PC", "192.0.2.20", site="site-a")
        _device(conn, "dev-b", "OFFICE-B-SIRIS", "192.0.2.20", site="site-b")   # same LAN
        _device(conn, "dev-c", "OFFICE-A-SRV", "192.0.2.2", site="site-a")
        _device(conn, "dev-d", "OLD-PC", "192.0.2.3", site="site-a", missing=True)
        _device(conn, "dev-e", "NEW-PC", "192.0.2.3", site="site-a")
    names = alerts.datto_names_by_ip(A, ["192.0.2.20", "192.0.2.2", "192.0.2.3"])
    # Two offices on one subnet: ambiguous — no Datto name at all.
    assert names == {"192.0.2.2": "OFFICE-A-SRV", "192.0.2.3": "NEW-PC"}
    # A Datto site linked to ANOTHER UniFi site is not this site's.
    names = alerts.datto_names_by_ip(A, ["192.0.2.20"], exclude_sites=frozenset({"site-b"}))
    assert names == {"192.0.2.20": "OFFICE-A-PC"}


def test_the_link_exclusion_is_used_only_with_the_entity_switch_on(troot, monkeypatch):
    from apps.octo.fleet import sources

    class T:
        def __init__(self, mode: str) -> None:
            self.entity_mode = mode

    links = {"scope-a": {"datto": {"site-a"}}, "scope-b": {"datto": {"site-b"}}}
    monkeypatch.setattr(sources, "entity_links", lambda slug: links)
    monkeypatch.setattr(sources, "tenants", lambda: {A: T("on")})
    on = alerts._OtherSites(A)
    assert on.of("scope-a") == {"site-b"} and on.of("scope-b") == {"site-a"}
    assert on.of("scope-unlinked") == {"site-a", "site-b"}
    monkeypatch.setattr(sources, "tenants", lambda: {A: T("shadow")})
    assert alerts._OtherSites(A).of("scope-a") == frozenset()


def test_rdap_owner_labels_need_a_whole_word():
    def rdap(org: str, net: str = "") -> list[str]:
        return [x["name"] for x in labels.labels("198.51.100.9", {"org": org, "net_name": net})]

    assert rdap("Example Hospitality & Accommodation LLC") == []          # not "Modat"
    assert rdap("Accommodations Example Group", "ACCOMMODAT-NET") == []
    assert rdap("Modat B.V.") == ["Modat"]
    assert rdap("Example Hosting", "CENSYS-ARIN-01") == ["Censys"]
    assert rdap("Internet Measurement Ltd") == ["internet-measurement.com (Driftnet)"]
    assert rdap("Internet-Measurement Example") == ["internet-measurement.com (Driftnet)"]
    assert rdap("Shodanski Example Farms") == []
    assert rdap("Shadowserver Foundation") == ["Shadowserver"]


def test_a_datto_raise_reads_resolved_once_its_resolution_is_stored(troot):
    now = datetime.now(timezone.utc)

    def insert(uid: str, minutes: int, resolved: bool) -> dict:
        payload = {"alertUid": uid, "priority": "High", "resolved": resolved,
                   "alertSourceInfo": {"deviceUid": "dev-1", "deviceName": "EXAMPLE-SRV"},
                   "alertContext": {"@class": "srvc_status_ctx", "serviceName": "Spooler",
                                    "status": "Stopped"}}
        at = (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        conn = sqlite3.connect(paths.client_dir(A) / "events.db")
        try:
            cur = conn.execute(
                "INSERT INTO events (received_at, source, source_host, event_type, severity, "
                "payload, payload_sha256) VALUES (?, 'datto', 'EXAMPLE-SRV', 'datto.srvc', "
                "'high', ?, ?)", (at, json.dumps(payload), f"sha-{os.urandom(6).hex()}"))
            conn.commit()
            rid = int(cur.lastrowid)
        finally:
            conn.close()
        return {"id": rid, "source": "datto", "received_at": at, "payload": json.dumps(payload)}

    raised = insert("0000bbbb-0000-0000-0000-000000000001", 30, False)
    still_open = insert("0000bbbb-0000-0000-0000-000000000002", 20, False)
    insert("0000bbbb-0000-0000-0000-000000000001", 5, True)
    out = alerts.datto(A, [raised, still_open], now=now)
    assert out[raised["id"]]["resolved"] is True
    assert out[still_open["id"]]["resolved"] is False
