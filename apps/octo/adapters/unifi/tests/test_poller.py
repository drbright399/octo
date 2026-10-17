"""The UniFi poller end to end on the real pieces (registry, tenant map,
sink, telemetry store, limiter, client) — only the socket is fake, on ONE fake
clock. Pins:

  * the fleet is TWO calls; nothing else is read until a site is mapped, and
    an unmapped / ignored site writes nothing anywhere (I10);
  * sites are keyed (hostId, siteId): two consoles with the same site id and
    internal reference 'default', mapped to two tenants, never mix (I11,
    AT-R7);
  * the system log: IPS → HIGH signals coalesced per site + client +
    signature per hour (detected-not-blocked ranks first); rogue AP MEDIUM;
    admin / config audit; WAN / VPN availability; firewall blocks and client
    connect / roam roll-ups ONLY; a 24-hour back-fill; a restart-safe
    high-water mark — exactly once across restarts and overlapping windows;
    a crash between claim and alert never loses or doubles an alert;
  * client snapshots (whole or nothing) and lease boundaries to the feed;
  * ONE limiter: never two calls within 1 s, security first;
  * one console down holds only its site; 429 = throttled, 401 = auth.
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from apps.octo.adapters.unifi import sanitize, store
from apps.octo.adapters.unifi.poller import counts_by_kind
from apps.octo.adapters.unifi.tests.fake_unifi import (
    HOST_A,
    HOST_B,
    HOST_C,
    INTEGRATION_DEFAULT,
    SCOPE_A,
    SCOPE_B,
    SCOPE_C,
    SITE_DEFAULT,
    client_event,
    ips_event,
    lan,
    log_event,
    mac,
)
from apps.octo.instances import vendor_contact, vendor_tenants

A, B = "acme-corp", "example-bakery"


def _seed_log(world, host: str, *items) -> None:
    world.transport.site(host).log.extend(items)


# ---------------------------------------------------------------------------
# Nothing mapped: two fleet calls, nothing written
# ---------------------------------------------------------------------------

def test_nothing_is_read_or_written_until_a_site_is_mapped(world):
    _seed_log(world, HOST_A, ips_event(world.clock.now() - timedelta(minutes=10)))
    p = world.poller()
    world.run_for(p, 15 * 60)
    paths = world.transport.paths()
    assert set(paths) == {"/v1/hosts", "/v1/sites"}            # the fleet only
    assert len(paths) == 2 * 3                                  # every 5 minutes
    assert world.events(A) == [] and world.events(B) == []
    assert world.telemetry_rows(A, "unifi_syslog_cursor") == []
    assert world.consumer.calls == []                           # nothing fed for unmapped sites
    snap = p.snapshot()
    assert snap["known"] == 3 and snap["mapped"] == 0 and snap["consoles"] == 3
    # The fleet IS the discovery listing (the mapping panel never calls UniFi).
    listing = vendor_tenants.latest(world.record.id, world.record.cred_ref)
    assert {t.id for t in listing.tenants} == {SCOPE_A, SCOPE_B, SCOPE_C}
    labels = {t.id: t.label for t in listing.tenants}
    assert labels[SCOPE_A] == "Acme Corp — acme-udm (100 Example St, Springfield)"
    assert world.instance_row()["status"] in ("running", "starting")


# ---------------------------------------------------------------------------
# The system log
# ---------------------------------------------------------------------------

def test_signals_rollups_and_boundaries_from_one_site(world):
    now = world.clock.now()
    t = now - timedelta(minutes=50)                       # inside one clock hour (11:10)
    _seed_log(
        world, HOST_A,
        ips_event(t, blocked=True, eid="ips-1"),
        ips_event(t + timedelta(minutes=5), blocked=True, eid="ips-2"),     # same bucket
        ips_event(t + timedelta(minutes=6), blocked=True, client_n=38, lan_ip=lan(38),
                  client_name="OFFICE-2", eid="ips-3"),                    # another client
        ips_event(t + timedelta(minutes=7), blocked=False, eid="ips-4"),    # detected: its own
        log_event(t + timedelta(minutes=8), "BLOCKED_BY_FIREWALL",
                  subcategory="SECURITY_FIREWALL", severity="MEDIUM", eid="fw-1"),
        log_event(t + timedelta(minutes=9), "BLOCKED_BY_FIREWALL",
                  subcategory="SECURITY_FIREWALL", severity="MEDIUM", eid="fw-2"),
        client_event(t + timedelta(minutes=10)),
        client_event(t + timedelta(minutes=11), "CLIENT_ROAMED"),
        log_event(t + timedelta(minutes=12), "ROGUE_AP_DETECTED", category="UNIFI_DEVICES",
                  subcategory="SYSTEM_WIFI", severity="MEDIUM",
                  params={"ROGUE_AP": {"id": mac(90), "name": "FreeWiFi"}}, eid="rogue-1"),
        log_event(t + timedelta(minutes=13), "ADMIN_ACCESS", category="AUDIT",
                  subcategory="SYSTEM_ADMIN", severity="MEDIUM",
                  params={"ADMIN": {"id": "admin-1", "name": "alice"},
                          "IP": {"id": "198.51.100.7"}}, eid="adm-1"),
        log_event(t + timedelta(minutes=14), "NETWORK_WAN_FAILED", category="INTERNET_AND_WAN",
                  subcategory="INTERNET_OUTAGE_AND_FAILOVER", severity="VERY_HIGH",
                  params={"WAN": {"id": "wan1", "name": "WAN"}}, eid="wan-1"),
        log_event(t + timedelta(minutes=15), "NETWORK_WAN_RESTORED", category="INTERNET_AND_WAN",
                  subcategory="INTERNET_OUTAGE_AND_FAILOVER", severity="MEDIUM",
                  params={"WAN": {"id": "wan1", "name": "WAN"}}, eid="wan-2"),
        log_event(t + timedelta(minutes=16), "VPN_SITE_TO_SITE_DISCONNECTED", category="VPN",
                  subcategory="SYSTEM_VPN", severity="MEDIUM", eid="vpn-1"),
    )
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    report = p.run_cycle()
    assert report.signals == 8 and report.rollups == 4

    types = [r["event_type"] for r in world.events(A)]
    assert sorted(types) == sorted([
        "unifi.ips_threat", "unifi.ips_threat", "unifi.ips_threat",   # 2 clients + detected
        "unifi.rogue_ap", "unifi.admin_activity", "unifi.wan_down", "unifi.wan_restored",
        "unifi.vpn_down",
    ])
    ips = world.payloads(A, "unifi.ips_threat")
    by_id = {p["event"]["id"]: p for p in ips}
    assert set(by_id) == {"ips-1", "ips-3", "ips-4"}           # ips-2 only COUNTED
    rows = {r["event_type"]: r for r in world.events(A)}
    sev = {r["event_type"]: r["severity"] for r in world.events(A)}
    assert sev["unifi.ips_threat"] == "high" and sev["unifi.rogue_ap"] == "medium"
    assert sev["unifi.admin_activity"] == "low" and sev["unifi.wan_down"] == "medium"
    detected = by_id["ips-4"]
    assert detected["ips"]["action"] == "detected"
    assert [r["summary"] for r in world.events(A) if json.loads(r["payload"])["event"]["id"] == "ips-4"] \
        == [f"UniFi IPS detected (NOT blocked) ET MALWARE Example Beacon — {lan(37)}"]
    # OCSF at the boundary: Detection Finding, disposition Detected / Blocked.
    assert detected["ocsf"]["class_uid"] == 2004 and detected["ocsf"]["disposition_id"] == 15
    assert by_id["ips-1"]["ocsf"]["disposition_id"] == 2
    assert by_id["ips-1"]["ocsf"]["evidences"][0]["src_endpoint"]["ip"] == lan(37)
    assert by_id["ips-1"]["ocsf"]["evidences"][0]["dst_endpoint"]["ip"] == "203.0.113.66"
    assert by_id["ips-1"]["ocsf"]["device"]["org"]["ou_uid"] == f"unifi:{SCOPE_A}"
    # The IOC is the public remote address; the event time is the console's.
    assert rows["unifi.ips_threat"]["received_at"].startswith("2026-10-01T11:")

    # Coalescing ledger: ips-1's bucket counted ips-2 (the live IPS event has
    # no client parameter: the LAN address is the subject's device).
    buckets = {b["subject"].split("|")[0]: b for b in store.buckets(A)
               if b["kind"] == "ips_threat" and b["subject"].endswith("|blocked")}
    assert buckets[lan(37)]["hits"] == 2 and buckets[lan(38)]["hits"] == 1
    assert all(b["pending_payload"] is None and b["event_id"] for b in store.buckets(A))

    # Roll-ups only: firewall blocks and client connect / roam.
    counts = counts_by_kind(store.hourly(A, SCOPE_A))
    assert counts == {"firewall_block": 2, "client_connect": 1, "client_roam": 1}
    classes = {r["kind"]: r["ocsf_class_uid"] for r in store.hourly(A, SCOPE_A)}
    assert classes == {"firewall_block": 4001, "client_connect": 4001, "client_roam": 4001}
    assert not [r for r in world.events(A) if "FIREWALL" in r["payload"]]

    # Lease / WAN boundaries to the feed — this tenant, this site only.
    ((slug, scope, bounds),) = world.consumer.of("log_events")
    assert (slug, scope) == (A, SCOPE_A)
    assert [b["event"] for b in bounds] == [
        "CLIENT_CONNECTED_WIRED", "CLIENT_ROAMED", "NETWORK_WAN_FAILED", "NETWORK_WAN_RESTORED"]
    assert bounds[0]["client"] == {"mac": mac(37), "ip": lan(37), "name": "FRONT-DESK-PC",
                                   "hostname": "front-desk-pc", "network": "Office"}


def test_a_restart_continues_from_the_cursor_exactly_once(world):
    now = world.clock.now()
    _seed_log(world, HOST_A,
              ips_event(now - timedelta(minutes=30), eid="ips-1"),
              log_event(now - timedelta(minutes=20), "BLOCKED_BY_FIREWALL",
                        subcategory="SECURITY_FIREWALL", severity="MEDIUM", eid="fw-1"))
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    # New events, some INSIDE the 5-minute overlap the next read re-reads.
    world.clock.advance(4 * 60)
    now = world.clock.now()
    _seed_log(world, HOST_A,
              log_event(now - timedelta(minutes=2), "BLOCKED_BY_FIREWALL",
                        subcategory="SECURITY_FIREWALL", severity="MEDIUM", eid="fw-2"),
              ips_event(now - timedelta(minutes=1), eid="ips-2", client_n=40,
                        lan_ip=lan(40), client_name="LAPTOP-40"))
    # A brand-new poller (a restart): nothing in memory.
    p2 = world.poller()
    p2.run_cycle()
    world.clock.advance(6 * 60)
    p2.run_cycle()
    world.poller().run_cycle()                       # and another restart
    ids = sorted(p["event"]["id"] for p in world.payloads(A))
    assert ids == ["ips-1", "ips-2"]                 # each alert once
    assert counts_by_kind(store.hourly(A, SCOPE_A)) == {"firewall_block": 2}   # counted once
    cur = store.cursor(A, SCOPE_A)
    assert cur is not None and cur.hwm_ms >= 0 and cur.scanned_to_ms > cur.hwm_ms - 1


def test_a_crash_between_claim_and_alert_is_finished_once(world, monkeypatch):
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=10), eid="ips-1"))
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    calls = {"n": 0}
    real = p._store_alert

    def crash(st, key, payload):
        calls["n"] += 1
        raise RuntimeError("fixture: process died after the claim")

    monkeypatch.setattr(p, "_store_alert", crash)
    p.cycle_with_reporting()                      # the claim commits, the alert never lands
    assert calls["n"] == 1 and world.events(A) == []
    (b,) = list(store.buckets(A))
    assert b["event_id"] is None and b["pending_payload"]          # the outbox row
    monkeypatch.setattr(p, "_store_alert", real)
    world.clock.advance(60)
    world.poller().run_cycle()                                     # a restart finishes it
    world.poller().run_cycle()
    assert [p["event"]["id"] for p in world.payloads(A)] == ["ips-1"]
    (b,) = list(store.buckets(A))
    assert b["event_id"] and b["pending_payload"] is None and b["hits"] == 1


def test_a_new_site_back_fills_24_hours_in_bounded_windows(world):
    now = world.clock.now()
    _seed_log(world, HOST_A,
              ips_event(now - timedelta(hours=30), eid="too-old"),
              ips_event(now - timedelta(hours=20), eid="ips-20h", client_n=41,
                        lan_ip=lan(41)),
              ips_event(now - timedelta(hours=2), eid="ips-2h", client_n=42,
                        lan_ip=lan(42)))
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    assert sorted(p["event"]["id"] for p in world.payloads(A)) == ["ips-20h", "ips-2h"]
    windows = [c.body for c in world.transport.calls_to("system-log")]
    assert len(windows) >= 4                                    # 6-hour windows
    # Each window: at most 6 hours of NEW time plus the 5-minute re-read.
    assert all(w["timestampTo"] - w["timestampFrom"] <= (6 * 3600 + 300) * 1000 for w in windows)
    # The first window starts 24 h before the read (the fleet calls took 2 s).
    assert abs(windows[0]["timestampFrom"] - int((now - timedelta(hours=24)).timestamp() * 1000)) \
        <= 5_000


def test_a_busy_window_is_halved_until_its_pages_fit(world, monkeypatch):
    from apps.octo.adapters.unifi import poller as poller_mod

    monkeypatch.setattr(poller_mod, "MAX_LOG_PAGES_PER_WINDOW", 2)
    monkeypatch.setattr(poller_mod, "LOG_PAGE_SIZE", 500, raising=False)
    now = world.clock.now()
    for i in range(1500):                                        # 3 pages of 500 in 10 min
        world.transport.site(HOST_A).log.append(
            log_event(now - timedelta(minutes=10) + timedelta(milliseconds=400 * i),
                      "BLOCKED_BY_FIREWALL", subcategory="SECURITY_FIREWALL",
                      severity="MEDIUM", eid=f"fw-{i:05d}"))
    world.map_sites({SCOPE_A: A})
    cur_from = now - timedelta(minutes=20)
    store.apply_page(A, SCOPE_A, rollups={}, claims=[], new_cursor=store.Cursor(
        SCOPE_A, hwm_ms=int(cur_from.timestamp() * 1000),
        scanned_to_ms=int(cur_from.timestamp() * 1000) + 300_000, recent_ids=[]))
    world.poller().run_cycle()
    assert counts_by_kind(store.hourly(A, SCOPE_A)) == {"firewall_block": 1500}


# ---------------------------------------------------------------------------
# Isolation: (hostId, siteId), never a default tenant
# ---------------------------------------------------------------------------

def test_two_consoles_with_the_same_site_id_never_mix(world):
    """AT-R7 / I11: every single-site console has the SAME site id and the
    internal reference 'default'. Mapped to two tenants, no row crosses; the
    unmapped third console writes nothing anywhere."""
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=9), eid="a-1"),
              client_event(now - timedelta(minutes=8), n=10, ip=lan(10), name="A-PC"))
    _seed_log(world, HOST_B, ips_event(now - timedelta(minutes=9), eid="b-1", client_n=60,
                                       lan_ip=lan(60), client_name="B-PC"),
              client_event(now - timedelta(minutes=8), n=60, ip=lan(60), name="B-PC"))
    _seed_log(world, HOST_C, ips_event(now - timedelta(minutes=9), eid="c-1"))
    world.transport.site(HOST_A).clients = [{"id": "c-a", "name": "A-PC", "macAddress": mac(10),
                                             "ipAddress": lan(10), "type": "WIRED",
                                             "connectedAt": "2026-10-01T08:00:00Z"}]
    world.transport.site(HOST_B).clients = [{"id": "c-b", "name": "B-PC", "macAddress": mac(60),
                                             "ipAddress": lan(60), "type": "WIRED",
                                             "connectedAt": "2026-10-01T08:00:00Z"}]
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    world.poller().run_cycle()

    assert [p["event"]["id"] for p in world.payloads(A)] == ["a-1"]
    assert [p["event"]["id"] for p in world.payloads(B)] == ["b-1"]
    assert {p["scope"] for p in world.payloads(A)} == {SCOPE_A}
    assert {p["scope"] for p in world.payloads(B)} == {SCOPE_B}
    assert {r["scope"] for r in world.telemetry_rows(A, "unifi_syslog_cursor")} == {SCOPE_A}
    assert {r["scope"] for r in world.telemetry_rows(B, "unifi_syslog_cursor")} == {SCOPE_B}
    # The system-log and client paths name the console every time.
    for c in world.transport.calls_to("/proxy/network/"):
        assert HOST_A in c.path or HOST_B in c.path
    assert not world.transport.calls_to(HOST_C)                 # never touched
    # The feed: each tenant gets its own site only.
    for method in ("site_report", "client_snapshot", "log_events"):
        assert {(slug, scope) for slug, scope, _ in world.consumer.of(method)} == {
            (A, SCOPE_A), (B, SCOPE_B)}, method
    snaps = {slug: d for slug, _s, d in world.consumer.of("client_snapshot")}
    assert [c["mac"] for c in snaps[A]["clients"]] == [mac(10)]
    assert [c["mac"] for c in snaps[B]["clients"]] == [mac(60)]
    # Both clients endpoints used the SAME integration id — on their own console.
    clients_calls = world.transport.calls_to(f"/sites/{INTEGRATION_DEFAULT}/clients")
    assert {c.path.split("/")[4] for c in clients_calls} == {HOST_A, HOST_B}


def test_an_ignored_site_and_a_tenant_that_left_are_never_polled(world):
    from apps.octo.db import connect
    from apps.octo import paths

    now = world.clock.now()
    _seed_log(world, HOST_B, ips_event(now - timedelta(minutes=5), eid="b-1"))
    _seed_log(world, HOST_C, ips_event(now - timedelta(minutes=5), eid="c-1"))
    world.map_sites({SCOPE_B: B}, ignore=(SCOPE_C,))
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = ?", (B,))
    reg.close()
    world.poller().run_cycle()
    assert not world.transport.calls_to("/proxy/network/")
    assert world.events(B) == [] and world.consumer.calls == []


def test_a_legacy_local_controller_mapping_is_never_polled(world):
    """A bare site id (the retired adapter's key) collides across consoles:
    it is never polled, whoever it points at."""
    world.map_sites({SITE_DEFAULT: A})
    world.poller().run_cycle()
    assert not world.transport.calls_to("/proxy/network/")


def test_a_site_re_mapped_to_another_tenant_starts_fresh_there(world):
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=5), eid="a-1"))
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    p.run_cycle()
    world.map_sites({SCOPE_A: B})
    world.clock.advance(6 * 60)
    p.run_cycle()
    # B back-fills ITS OWN copy; nothing of A's state moved into B's file.
    assert [x["event"]["id"] for x in world.payloads(A)] == ["a-1"]
    assert [x["event"]["id"] for x in world.payloads(B)] == ["a-1"]
    assert len(world.telemetry_rows(A, "unifi_syslog_cursor")) == 1
    assert len(world.telemetry_rows(B, "unifi_syslog_cursor")) == 1


# ---------------------------------------------------------------------------
# Feeds: fleet report, client snapshots, networks
# ---------------------------------------------------------------------------

def test_fleet_reports_carry_egress_location_and_one_shared_bit(world):
    # Console B's WAN shows the SAME public address as A's (a shared building).
    world.transport.site(HOST_B).wans["WAN"]["externalIp"] = "203.0.113.129"
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    world.poller().run_cycle()
    reports = {slug: r for slug, _s, r in world.consumer.of("site_report")}
    a = reports[A]
    assert (a["host_id"], a["site_id"], a["internal_ref"]) == (HOST_A, SITE_DEFAULT, "default")
    # nat_kind: the console's WAN interface (192.0.2.10) is neither the
    # public address, CGNAT nor RFC 1918 → unknown.
    assert a["wans"] == [{"wan": "WAN", "external_ip": "203.0.113.129", "nat_kind": "unknown",
                          "asn": 64500, "isp": "Example ISP", "port_up": True,
                          "plugged": True, "ipv4_present": True, "configured": True,
                          "role": "primary", "shared_external": True}]
    assert a["location"]["text"] == "100 Example St, Springfield" and a["timezone"] == "America/Chicago"
    assert a["gateway_online"] is True and a["host_connected"] is True
    # One bit — nothing about the other site, console or tenant.
    assert HOST_B not in json.dumps(a) and B not in json.dumps(a)


def test_client_snapshots_are_whole_or_nothing(world):
    world.transport.site(HOST_A).clients = [
        {"id": f"c{i}", "name": f"PC-{i}", "macAddress": mac(i).upper(),
         "ipAddress": lan(i), "type": "WIRED", "connectedAt": "2026-10-01T09:00:00Z",
         "uplinkDeviceId": "sw-1", "access": {"type": "DEFAULT"}}
        for i in range(1, 451)]                                  # 3 pages of 200
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    p.run_cycle()
    ((slug, scope, snap),) = world.consumer.of("client_snapshot")
    assert (slug, scope, snap["complete"], snap["total"]) == (A, SCOPE_A, True, 450)
    assert len(snap["clients"]) == 450 and snap["clients"][0]["mac"] == mac(1)
    assert snap["gateway_online"] is True
    # A page fails half-way → no snapshot at all, a failure instead.
    world.transport.clients_fail_after_page[HOST_A] = 1
    world.clock.advance(6 * 60)
    p.run_cycle()
    assert len(world.consumer.of("client_snapshot")) == 1
    ((_s, _sc, failure),) = world.consumer.of("client_snapshot_failed")
    assert failure["scope"] == SCOPE_A and "502" in failure["reason"]
    assert "could not be read whole" in p.site_states()[SCOPE_A]["problem"]
    # …and the site's security read is NOT held for it.
    syslog_reads = len(world.transport.calls_to("system-log"))
    world.clock.advance(5 * 60)
    p.run_cycle()
    assert len(world.transport.calls_to("system-log")) == syslog_reads + 1
    # Back to normal: the problem clears with the next whole snapshot.
    del world.transport.clients_fail_after_page[HOST_A]
    world.clock.advance(5 * 60)
    p.run_cycle()
    assert p.site_states()[SCOPE_A]["problem"] is None
    assert len(world.consumer.of("client_snapshot")) == 2


def test_a_client_list_that_shifts_while_it_is_read_is_read_again_or_failed(world):
    """Clients leave between page reads: a changed totalCount restarts the
    read (a shifted list would otherwise report a client that left and miss
    one that is there); a list that never holds still fails — never a
    partial snapshot."""
    site = world.transport.site(HOST_A)
    site.clients = [{"id": f"c{i}", "macAddress": mac(i), "ipAddress": lan(i)}
                    for i in range(1, 251)]
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    shifted = {"n": 0}

    def leave_once(call):
        if "/clients" in call.path and call.query.get("offset") == "200" and not shifted["n"]:
            shifted["n"] = 1
            del site.clients[:2]                     # two leave after the first page

    world.transport.before_request = leave_once
    p.run_cycle()
    ((_s, _sc, snap),) = world.consumer.of("client_snapshot")
    assert snap["total"] == 248 and len(snap["clients"]) == 248
    assert mac(1) not in {c["mac"] for c in snap["clients"]}
    assert {mac(201), mac(202)} <= {c["mac"] for c in snap["clients"]}

    def leave_always(call):
        if "/clients" in call.path and call.query.get("offset") == "200":
            site.clients.pop(0)

    world.transport.before_request = leave_always
    world.clock.advance(5 * 60)
    p.run_cycle()
    assert len(world.consumer.of("client_snapshot")) == 1          # no partial one
    ((_s, _sc, failure),) = world.consumer.of("client_snapshot_failed")
    assert "kept changing" in failure["reason"]


def test_networks_are_read_daily_and_never_carry_a_secret(world):
    world.map_sites({SCOPE_A: A})
    p = world.poller()
    world.run_for(p, 30 * 60)
    ((slug, scope, nets),) = world.consumer.of("networks")
    assert [n["name"] for n in nets] == ["Office", "Guest", "Site VPN"]
    assert nets[1]["purpose"] == "guest" and nets[1]["dhcpd_dns_1"] == "198.51.100.53"
    assert sanitize.find_secret_keys(nets) == []
    text = json.dumps(nets)
    for needle in ("passphrase", "psk", "wireguard", "ipsec", "radius", "OPENVPN", "fixture-"):
        assert needle not in text, needle
    assert len(world.transport.calls_to("networkconf")) == 1        # daily, not per cycle
    world.poller().run_cycle()                                       # a restart: still daily
    assert len(world.transport.calls_to("networkconf")) == 1


def test_no_secret_key_reaches_any_store(world):
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=3), eid="ips-1"))
    item = world.transport.site(HOST_A).log[-1]
    item["parameters"]["x_auth_secret"] = "fixture-secret-material"
    item["parameters"]["SRC_IP"]["utm_token"] = "fixture-utm-material"
    world.map_sites({SCOPE_A: A})
    world.poller().run_cycle()
    for r in world.events(A):
        assert sanitize.find_secret_keys(json.loads(r["payload"])) == []
        assert "fixture-secret-material" not in r["payload"]
        assert "fixture-utm-material" not in r["payload"]
    for b in store.buckets(A):
        assert "fixture-" not in (b["pending_payload"] or "")
    for _m, _slug, _scope, data in world.consumer.calls:
        assert sanitize.find_secret_keys(data) == []


# ---------------------------------------------------------------------------
# Rate: ONE limiter, security first
# ---------------------------------------------------------------------------

def test_every_call_is_spaced_through_one_limiter_within_the_budget(world):
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=3)))
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    p = world.poller()
    world.run_for(p, 3600)
    assert world.transport.min_gap_seen >= 1.0
    grants = world.limiter.grants()
    assert len(grants) == len(world.transport.calls)
    # Planned: 2 fleet calls per 5 min + (system log + clients) per site per 5 min.
    assert p.planned_calls_per_hour() == pytest.approx(24 + 2 * 24)
    # The hour: 24 fleet + per site 12 system-log reads (+3 more windows for
    # the first 24-hour back-fill) and 12 client reads, + one console site
    # lookup and one network read per site.
    assert len(world.transport.calls) == 24 + 2 * (12 + 3 + 12 + 1 + 1)


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------

def test_one_console_down_holds_only_its_site(world):
    now = world.clock.now()
    _seed_log(world, HOST_A, ips_event(now - timedelta(minutes=3), eid="a-1"))
    _seed_log(world, HOST_B, ips_event(now - timedelta(minutes=3), eid="b-1"))
    world.transport.console_status[HOST_A] = 502
    world.map_sites({SCOPE_A: A, SCOPE_B: B})
    p = world.poller()
    p.cycle_with_reporting()
    assert world.events(A) == [] and len(world.events(B)) == 1
    states = p.site_states()
    assert "did not answer" in states[SCOPE_A]["problem"] and states[SCOPE_B]["problem"] is None
    assert world.instance_row()["status"] == "running"          # the integration works
    assert p.snapshot()["problems"] == 1
    # Back: the held site catches up from where it stopped.
    del world.transport.console_status[HOST_A]
    world.clock.advance(5 * 60)
    world.run_for(p, 10 * 60)
    assert [x["event"]["id"] for x in world.payloads(A)] == ["a-1"]
    assert p.site_states()[SCOPE_A]["problem"] is None


def test_a_429_is_a_throttle_not_a_failure(world):
    world.map_sites({SCOPE_A: A})
    world.transport.throttle_next = 1
    p = world.poller()
    wait = p.cycle_with_reporting()
    assert wait >= 15.0
    row = world.instance_row()
    assert row["status"] == "running" and "rate limiting" in row["status_detail"]
    assert p.snapshot()["throttled"] is True
    assert vendor_contact.snapshot(world.record.id)["last_throttled_at"]
    world.clock.advance(wait)
    p.cycle_with_reporting()
    assert world.instance_row()["status"] == "running"
    assert p.snapshot()["throttled"] is False


def test_a_rejected_key_is_an_auth_failure_and_never_echoes_the_key(world):
    from apps.octo.adapters.unifi.tests.fake_unifi import API_KEY

    world.transport.key = "fixture-another-key-" + "9" * 24
    p = world.poller()
    delay = p.cycle_with_reporting()
    row = world.instance_row()
    assert row["status"] == "error" and "HTTP 401" in row["status_detail"]
    assert API_KEY not in row["status_detail"] and delay >= 60


def test_an_unreachable_cloud_is_a_transport_failure(world):
    world.transport.unreachable = True
    p = world.poller()
    p.cycle_with_reporting()
    row = world.instance_row()
    assert row["status"] == "error" and "Could not read from UniFi" in row["status_detail"]


def test_an_unreadable_tenant_map_polls_nothing(world, monkeypatch):
    import sqlite3

    from apps.octo.instances import tenant_map

    world.map_sites({SCOPE_A: A})

    def boom(_iid):
        raise sqlite3.OperationalError("fixture: locked")

    monkeypatch.setattr(tenant_map, "get_mappings", boom)
    report = world.poller().run_cycle()
    assert report.held and world.transport.calls == []
