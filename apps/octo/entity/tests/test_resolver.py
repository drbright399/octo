"""The resolver against the design's slice-1 acceptance tests (AT1-AT13) and
the adversarial ones that apply to slice 1 (AT-R2, R4, R5, R7, R10, R12, R13).
The motivating case of 2026-10-01 is "Site A" here (the design's example);
every public address is a documentation value, the LAN is the fixture's
`lan()` (private on purpose: see there)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from apps.octo.adapters.nextdns import store as nd_store
from apps.octo.entity import resolver as rv
from apps.octo.entity import sites as st
from apps.octo.entity.tests.conftest import (
    A,
    B,
    EGRESS_A,
    PROFILE_A,
    SCOPE_A,
    SCOPE_B,
    T0,
    client,
    iso,
    join_event,
    lan,
    mac,
    nextdns_block,
    store_event,
)

T_BLOCK = T0.replace(minute=17, second=5, microsecond=412000)      # 14:17:05.412
EARLY = T0.replace(hour=8)                                          # connected this morning


def _resolver(world, at: datetime, slug: str = A) -> rv.Resolver:
    return rv.Resolver.for_tenant(slug, now=lambda: at)


def _confirm_profile(world, slug: str = A, profile: str = PROFILE_A) -> str:
    with world.db(slug).write() as conn:
        site_id = conn.execute("SELECT site_id FROM site ORDER BY created_at LIMIT 1"
                               ).fetchone()["site_id"]
        st.operator_link(conn, site_id=site_id, vendor="nextdns", instance_id=world.nextdns_id,
                         scope_id=profile, operator_id=7, now=iso(T0), rule_id="L-EGRESS",
                         reason="profile P belongs to Site A")
    return site_id


def site_a_clients(at_last_hit: bool = False) -> list[dict]:
    """14 leases: 9 on the office VLAN, 5 on the guest VLAN (DHCP hands the
    guests the ISP's DNS — they cannot have produced a NextDNS line)."""
    office = [client(n, lan(10 + n), connected=EARLY + timedelta(minutes=n))
              for n in range(1, 10)]
    guests = [client(20 + n, lan(10 + n, 30), kind="WIRELESS",
                     connected=EARLY + timedelta(minutes=n)) for n in range(1, 6)]
    if at_last_hit:
        return office[:4]               # only 4 of the office devices are still there
    return office + guests


def site_a(world) -> str:
    world.networks()
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), site_a_clients())
    return _confirm_profile(world)


def reports(world, *, until: int = 20, **kw) -> None:
    """A fleet report every 5 minutes from 14:00 to 14:<until>."""
    for minute in range(0, until + 1, 5):
        world.site_report(T0.replace(minute=minute), **kw)


def _block_event(world, at: datetime = T_BLOCK, slug: str = A, **kw) -> int:
    payload = nextdns_block(at, **kw)
    return store_event(slug, "nextdns", "nextdns.security_block", payload, iso(at))


def _answer(world, event_id: int, at: datetime, slug: str = A) -> dict:
    return _resolver(world, at, slug).resolve_event(event_id)


def _stable(row: dict) -> dict:
    return {k: row[k] for k in ("site_id", "site_basis", "site_score", "site_tier", "device_ref",
                                "tier", "score", "n_candidates", "chain", "candidates", "flags",
                                "status")}


# ---------------------------------------------------------------------------
# AT1 — the motivating case
# ---------------------------------------------------------------------------

def test_at1_site_a_gateway_block_resolves_to_the_site_and_nine_candidates(world):
    site_id = site_a(world)
    eid = _block_event(world)
    row = _answer(world, eid, T0.replace(minute=20, second=30))
    assert (row["site_id"], row["site_basis"], row["site_score"], row["site_tier"]) == \
        (site_id, "both", 99, "strong")
    assert (row["tier"], row["n_candidates"], row["status"]) == ("candidate", 9, "final")
    cands = json.loads(row["candidates"])
    assert [c["score"] for c in cands] == [11] * 9                  # min(50, 100 // 9)
    assert all(c["is_guest"] == 0 for c in cands)                   # the guest VLAN is filtered
    chain = json.loads(row["chain"])
    assert [h["rule"] for h in chain] == ["S1", "S2", "S-AGREE", "D4", "D7"]
    d7 = chain[-1]
    assert d7["out"] == {"candidates": 9, "excluded": {"dns_bypasses_nextdns": 5}}
    # No name, raw address or MAC is ever copied into the answer (G11, AT14:
    # what an LLM would be handed is tokens only).
    from apps.octo.entity.ocsf import enrichment

    stored = json.dumps({k: row[k] for k in ("chain", "candidates", "flags", "subject_tok")})
    stored += json.dumps(enrichment(row))
    for raw in ("PC-", EGRESS_A, lan(0).rpartition(".")[0] + ".", "00:00:5e"):
        assert raw not in stored, raw


def test_at1_byte_identical_over_runs_and_every_insertion_order(world):
    """Same lookups → same chain and candidates, whatever order the leases
    were written in (AT1: byte-identical over 3 runs and every input order)."""
    site_a(world)
    eid = _block_event(world)
    at = T0.replace(minute=20, second=30)
    first = _stable(_answer(world, eid, at))
    for _ in range(2):
        assert _stable(_answer(world, eid, at)) == first
    clients = site_a_clients()
    n = len(clients)
    orders = [list(reversed(range(n))), [(i * 5) % n for i in range(n)],
              list(range(1, n, 2)) + list(range(0, n, 2))]
    for order in orders:
        # A fresh tenant per order: the same facts, written in another order.
        slug = B
        world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: B})
        world.map(world.nextdns_id, {PROFILE_A: A, "def456": B})
        world.set_mode(B, "on")
        with world.db(B).connect() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE maint SET allow_operator_delete = 1")
            for t in ("lk_ip_lease", "lk_watermark", "lk_site_egress", "lk_site_subnet",
                      "site_vendor_ref", "site", "resolution", "resolution_dep"):
                conn.execute(f"DELETE FROM {t}")
            conn.execute("UPDATE maint SET allow_operator_delete = 0")
            conn.execute("COMMIT")
        world.networks(slug=slug, scope=SCOPE_B)
        shuffled = [clients[i] for i in order]
        for minute in (10, 15, 20):
            world.poll(T0.replace(minute=minute), shuffled, slug=slug, scope=SCOPE_B)
        _confirm_profile(world, slug=slug, profile="def456")
        eid_b = store_event(slug, "nextdns", "nextdns.security_block",
                            nextdns_block(T_BLOCK, profile="def456"), iso(T_BLOCK))
        other = _stable(_answer(world, eid_b, at, slug=slug))
        assert (other["tier"], other["n_candidates"], other["site_score"]) == ("candidate", 9, 99)
        assert [c["score"] for c in json.loads(other["candidates"])] == \
            [c["score"] for c in json.loads(first["candidates"])]
        assert [c["mac_tok"] is not None for c in json.loads(other["candidates"])] == [True] * 9


def test_site_a_nextdns_app_devices_are_excluded_from_a_gateway_block(world):
    """Rick 2026-10-01: a gateway-sourced (dnscrypt) block excludes every
    device that reports through the NextDNS app (its lookups never pass the
    gateway)."""
    world.networks()
    clients = site_a_clients() + [client(40, lan(40), name="DESKTOP-APP01",
                                          connected=EARLY)]
    for minute in (10, 15, 20):
        world.poll(T0.replace(minute=minute), clients)
    _confirm_profile(world)
    world.nextdns.on_device_hour(A, PROFILE_A, {
        "hour": "2026-10-01T14:00:00Z", "complete": True, "method": "analytics",
        "devices": [{"id": "D9F2A1", "name": "DESKTOP-APP01", "model": "Windows",
                     "client": "nextdns-windows", "queries": 223}],
        "read_at": iso(T0.replace(hour=15, minute=5))})
    eid = _block_event(world)
    row = _answer(world, eid, T0.replace(minute=20, second=30))
    assert row["n_candidates"] == 9
    d7 = json.loads(row["chain"])[-1]
    assert d7["out"]["excluded"] == {"dns_bypasses_nextdns": 5, "nextdns_app_device": 1}
    assert "gateway_sourced" in json.loads(row["flags"])
    # The app's OWN line names its device (D5, client-asserted: medium at most).
    eid2 = _block_event(world, device={"id": "D9F2A1", "name": "DESKTOP-APP01"},
                        client_kind="nextdns-windows", vid="app-line")
    row2 = _answer(world, eid2, T0.replace(minute=20, second=30))
    assert (row2["tier"], row2["score"]) == ("medium", 80)
    assert row2["device_ref"].startswith("nextdns_device:nd_")


# ---------------------------------------------------------------------------
# AT2 — bucket close re-rank
# ---------------------------------------------------------------------------

def test_at2_bucket_close_supersedes_and_ranks_the_clients_present_at_both_hits(world):
    site_a(world)
    for minute in (30, 35, 40, 45, 50, 55):
        world.poll(T0.replace(minute=minute), site_a_clients(at_last_hit=True))
    eid = _block_event(world)
    bucket = nd_store.Bucket(key="b" * 32, hour="2026-10-01T14:00:00Z", profile_id=PROFILE_A,
                             reason_id="threat-intelligence-feeds", root="bad.example",
                             device=EGRESS_A)
    nd_store.count_hits(A, [(bucket, iso(T_BLOCK), "l1", "bad.example")], arrived=iso(T_BLOCK))
    nd_store.set_event(A, bucket.key, eid)
    from apps.octo.entity.worker import EntityWorker

    # The one-minute sweep resolves the alert when it lands (14:20:30) …
    assert EntityWorker(now=lambda: T0.replace(minute=20, second=30)).run_tenant(A)["scanned"] == 1
    first = world.one("SELECT * FROM resolution WHERE event_id = ?", (eid,))
    assert first["n_candidates"] == 9 and "bucket_later_hits" not in json.loads(first["flags"])
    # … two more hits land in the bucket; the last at 14:51:40 …
    last = T0.replace(minute=51, second=40)
    nd_store.count_hits(A, [(bucket, iso(last - timedelta(minutes=9)), "l2", "bad.example")],
                        arrived=iso(last))
    nd_store.count_hits(A, [(bucket, iso(last), "l3", "bad.example")], arrived=iso(last))
    # … nothing is redone while the hour is still filling …
    w = EntityWorker(now=lambda: T0.replace(minute=58))
    assert w.run_tenant(A)["bucket_close"] == 0
    # … and after it closed, the alert is re-ranked with its last hit.
    counts = EntityWorker(now=lambda: T0.replace(hour=15, minute=11)).run_tenant(A)
    assert counts["bucket_close"] == 1
    rows = world.rows("SELECT * FROM resolution WHERE event_id = ? ORDER BY created_at, res_id",
                      (eid,))
    current = [r for r in rows if r["status"] != "superseded"]
    assert len(current) == 1 and current[0]["mode"] == "bucket_close"
    assert all(r["superseded_by"] == current[0]["res_id"] for r in rows if r is not current[0]
               and r["status"] == "superseded")
    cands = json.loads(current[0]["candidates"])
    assert [c["score"] for c in cands[:4]] == [21] * 4 and all("F2" in c["features"]
                                                               for c in cands[:4])
    assert [c["score"] for c in cands[4:]] == [11] * 5
    assert "bucket_later_hits" in json.loads(current[0]["flags"])


# ---------------------------------------------------------------------------
# AT3 — a LAN witness (a buoy's Pi-hole) names the device
# ---------------------------------------------------------------------------

def test_at3_a_pihole_witness_names_the_device_medium_85(world):
    site_a(world)
    sensor = T_BLOCK - timedelta(milliseconds=214)
    store_event(A, "buoy", "pihole.query", {
        "event_type": "pihole.query", "severity": "high",
        "raw_query": {"id": 9, "timestamp": sensor.timestamp(), "status": 7,
                      "domain": "x.bad.example", "client": lan(13)}}, iso(T_BLOCK))
    eid = _block_event(world)
    row = _answer(world, eid, T0.replace(minute=20, second=30))
    assert (row["tier"], row["score"]) == ("medium", 85)
    chain = json.loads(row["chain"])
    assert [h["rule"] for h in chain][-2:] == ["D4", "D3"] and chain[-2]["score"] == 88
    assert row["device_ref"] == "unifi_client:" + json.loads(row["candidates"])[0]["mac_tok"]


# ---------------------------------------------------------------------------
# AT4 / AT5 — provisional, finalised stale, data gap
# ---------------------------------------------------------------------------

def test_at4_provisional_then_final_then_stale(world):
    world.networks()
    for minute in (5, 10, 15):
        world.poll(T0.replace(minute=minute), site_a_clients())
    _confirm_profile(world)
    eid = _block_event(world)                                   # 14:17:05 — after the 14:15 poll
    row = _answer(world, eid, T0.replace(minute=18))
    assert row["status"] == "provisional"
    world.poll(T0.replace(minute=20), site_a_clients())
    row = _answer(world, eid, T0.replace(minute=20, second=30))
    assert row["status"] == "final" and "lookup_stale" not in json.loads(row["flags"])
    # Another block with no snapshot after it for 30 minutes.
    late = T0.replace(minute=40)
    eid2 = _block_event(world, at=late, vid="late")
    row2 = _answer(world, eid2, late + timedelta(minutes=31))
    assert row2["status"] == "final" and "lookup_stale" in json.loads(row2["flags"])


def test_at5_t_inside_an_outage_gives_no_pick_and_data_gap(world):
    world.networks()
    world.poll(T0.replace(minute=0), site_a_clients())
    _confirm_profile(world)
    world.poll(T0.replace(minute=40), site_a_clients())          # 40 min outage
    eid = _block_event(world, at=T0.replace(minute=17))
    row = _answer(world, eid, T0.replace(minute=50))
    # Leases closed at the last good poll (gap): nobody is "connected" at T.
    assert row["n_candidates"] == 0 and row["tier"] == "none"


def test_at_r9_a_stale_answer_is_redone_when_the_backfill_covers_it(world):
    world.networks()
    for minute in (5, 10, 15):
        world.poll(T0.replace(minute=minute), site_a_clients())
    _confirm_profile(world)
    eid = _block_event(world)
    from apps.octo.entity.worker import EntityWorker

    # The sweep sees the alert while the console is away (nothing after 14:15)
    # and, 30 minutes on, finalises it as stale.
    EntityWorker(now=lambda: T0.replace(minute=50)).run_tenant(A)
    stale = world.one("SELECT * FROM resolution WHERE event_id = ?", (eid,))
    assert stale["status"] == "final" and "lookup_stale" in json.loads(stale["flags"])
    world.poll(T0.replace(minute=55), site_a_clients())          # the console comes back
    counts = EntityWorker(now=lambda: T0.replace(minute=56)).run_tenant(A)
    assert counts["backfill"] == 1
    cur = world.one("SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'",
                    (eid,))
    assert cur["mode"] == "backfill" and "lookup_stale" not in json.loads(cur["flags"])


# ---------------------------------------------------------------------------
# AT6 / AT-R12 / AT-R13 — DHCP reuse, sampled closes, reconnects, ghosts
# ---------------------------------------------------------------------------

def _ips_world(world):
    world.networks()
    world.poll(T0.replace(minute=10), [client(1, lan(37), connected=EARLY)])


def _ips_event(world, at: datetime, lan_ip: str = lan(37), n: int = 1) -> int:
    payload = {"vendor_event_id": f"{SCOPE_A}:ips-{int(at.timestamp())}", "kind": "ips_threat",
               "scope": SCOPE_A, "site_name": "Site A",
               "event": {"id": f"ips-{int(at.timestamp())}", "timestamp": iso(at),
                         "event": "THREAT_BLOCKED"},
               "ips": {"action": "blocked", "local_ip": lan_ip, "remote_ip": "203.0.113.66",
                       "client": {"mac": mac(n), "ip": lan_ip}},
               "signal": {"level": "high"}}
    return store_event(A, "unifi", "unifi.ips_threat", payload, iso(at))


def test_at13_an_ips_alert_names_the_client_holding_the_lan_ip(world):
    _ips_world(world)
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    eid = _ips_event(world, T0.replace(minute=12))
    row = _answer(world, eid, T0.replace(minute=16))
    assert (row["tier"], row["score"], row["status"]) == ("medium", 85, "final")
    assert row["device_ref"].startswith("unifi_client:mc_")


def test_at6_and_r12_ip_reuse_inside_the_margin_gives_both_never_the_new_holder(world):
    _ips_world(world)
    world.poll(T0.replace(minute=15), [client(2, lan(37))])     # MAC2 took .37
    world.poll(T0.replace(minute=20), [client(2, lan(37))])
    t = T0.replace(minute=12, second=40)                              # just after the midpoint
    row = _answer(world, _ips_event(world, t), T0.replace(minute=21))
    assert row["tier"] == "candidate" and row["n_candidates"] == 2
    assert "lease_overlap" in json.loads(row["flags"])


def test_at_r13_reconnect_hole_and_ghost_join_give_no_pick(world):
    _ips_world(world)
    back = T0.replace(minute=14)
    world.poll(T0.replace(minute=15), [client(1, lan(37), connected=back)])
    row = _answer(world, _ips_event(world, T0.replace(minute=12)), T0.replace(minute=16))
    assert row["tier"] == "candidate" and "reconnect_hole" in json.loads(row["flags"])
    # A ghost: a device that joined WITH THAT ADDRESS and left between polls,
    # just before T.
    world.log([join_event(T0.replace(minute=16, second=10), 9, lan(37))])
    world.poll(T0.replace(minute=20), [client(1, lan(37), connected=back)])
    row = _answer(world, _ips_event(world, T0.replace(minute=17)), T0.replace(minute=21))
    assert row["tier"] == "candidate" and "ghost_join" in json.loads(row["flags"])


def test_at_r2_mac_anomaly_two_ips_marks_conflict_and_raises_a_signal(world):
    """One global MAC, two IPs within one poll window, the client record
    continuous: candidates only, and a derived signal handed back."""
    _ips_world(world)
    world.log([join_event(T0.replace(minute=12), 1, lan(88))])   # MAC1 joins as .88
    out = world.poll(T0.replace(minute=15), [client(1, lan(37), connected=EARLY)])
    assert out and out["signals"][0]["kind"] == "mac_anomaly"
    assert out["signals"][0]["anomaly"] == "two_ips" and out["signals"][0]["mac"] == mac(1)
    # The finding is time-bounded (lk_mac_anomaly), never a whole-row flag.
    (anomaly,) = world.rows("SELECT * FROM lk_mac_anomaly")
    assert anomaly["from_ts"] == iso(T0.replace(minute=12))
    assert all(r["conflict"] == 0 for r in world.rows("SELECT * FROM lk_ip_lease"))
    row = _answer(world, _ips_event(world, T0.replace(minute=13)), T0.replace(minute=16))
    assert row["tier"] == "candidate" and "mac_anomaly" in json.loads(row["flags"])
    world.unifi.on_signal_stored(A, SCOPE_A, {"anomaly_id": out["signals"][0]["anomaly_id"]})
    assert world.poll(T0.replace(minute=20), [client(1, lan(37), connected=EARLY)]) is None


# ---------------------------------------------------------------------------
# AT7 — isolation
# ---------------------------------------------------------------------------

def test_at7_two_tenants_same_egress_macs_and_ips_never_cross(world, tmp_path):
    world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: B})
    world.map(world.nextdns_id, {PROFILE_A: A, "def456": B})
    world.set_mode(B, "on")
    for slug, scope in ((A, SCOPE_A), (B, SCOPE_B)):
        world.networks(slug=slug, scope=scope)
        for minute in (10, 15, 20):
            world.poll(T0.replace(minute=minute), site_a_clients(), slug=slug, scope=scope)
    site_a = _confirm_profile(world, A, PROFILE_A)
    site_b = _confirm_profile(world, B, "def456")
    assert site_a != site_b
    row_a = _answer(world, _block_event(world), T0.replace(minute=21))
    eid_b = store_event(B, "nextdns", "nextdns.security_block",
                        nextdns_block(T_BLOCK, profile="def456"), iso(T_BLOCK))
    row_b = _answer(world, eid_b, T0.replace(minute=21), slug=B)
    assert row_a["site_id"] == site_a and row_b["site_id"] == site_b
    toks_a = {c["mac_tok"] for c in json.loads(row_a["candidates"])}
    toks_b = {c["mac_tok"] for c in json.loads(row_b["candidates"])}
    assert toks_a and toks_b and not toks_a & toks_b       # the same MACs, different tokens
    # Nothing of B in A's file, and the resolver refuses B's path.
    blob = (world.root / "clients" / A / "entities.db").read_bytes()
    assert site_b.encode() not in blob and B.encode() not in blob
    r = rv.Resolver.for_tenant(A)
    with pytest.raises(ValueError):
        r.guard(world.root / "clients" / B / "entities.db")
    evil = world.root / "clients" / A / "evil"
    evil.symlink_to(world.root / "clients" / B)
    with pytest.raises(ValueError):
        r.guard(evil / "entities.db")


def test_at7_no_entity_function_takes_two_tenant_slugs():
    """Static check over the package: no function signature has two slug
    parameters (I3)."""
    import ast
    import pathlib

    import apps.octo.entity as pkg

    root = pathlib.Path(pkg.__file__).parent
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names = [a.arg for a in node.args.args + node.args.kwonlyargs]
                if sum(1 for n in names if "slug" in n) > 1:
                    offenders.append(f"{path.name}:{node.name}")
    assert offenders == []


# ---------------------------------------------------------------------------
# AT8 / AT9 / AT10 / AT-R10 — names, operator wins, shared profiles
# ---------------------------------------------------------------------------

def test_at8_a_name_match_only_suggests_and_s1_ignores_it(world):
    from apps.octo.entity import linkrules

    world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: A})
    world.site_report(T0, name="Site A office")
    world.site_report(T0, scope=SCOPE_B, name="Warehouse",
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.20", "nat_kind": "direct"}])
    world.map(world.nextdns_id, {PROFILE_A: A})
    with world.db().write() as conn:
        conn.execute("UPDATE site SET label = 'label abc123' WHERE label = 'Site A office'")
        linkrules.run_all(conn, A, iso(T0))
    refs = world.rows("SELECT * FROM site_vendor_ref WHERE vendor = 'nextdns'")
    assert [(r["rule_id"], r["state"], r["score"]) for r in refs] == [("N-SITE", "suggested", 45)]
    eid = _block_event(world)
    row = _answer(world, eid, T0.replace(minute=21))
    assert "S1" not in [h["rule"] for h in json.loads(row["chain"])]


def test_at9_and_r10_operator_wins_on_update_insert_and_delete(world):
    import sqlite3

    world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: A})
    world.site_report(T0)
    world.site_report(T0, scope=SCOPE_B, name="Warehouse",
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.20", "nat_kind": "direct"}])
    site_a = _confirm_profile(world)
    site_b = world.one("SELECT site_id FROM site WHERE label = 'Warehouse'")["site_id"]
    with world.db().write() as conn:
        # A rule's INSERT for a confirmed scope aborts → a Conflicts card.
        p = st.propose(conn, site_id=site_b, vendor="nextdns", instance_id=world.nextdns_id,
                       scope_id=PROFILE_A, state="auto", score=90, rule_id="L-EGRESS",
                       rule_version=1, evidence={}, now=iso(T0))
        assert p.outcome == "conflict"
    conflicts = world.rows("SELECT * FROM link_conflict")
    assert [(c["kind"], c["subject"]) for c in conflicts] == \
        [("operator_decision", f"nextdns:{world.nextdns_id}:{PROFILE_A}")]
    with world.db().connect() as conn:
        ref_id = conn.execute("SELECT id FROM site_vendor_ref WHERE vendor = 'nextdns' "
                              "AND state = 'confirmed'").fetchone()["id"]
        with pytest.raises(sqlite3.IntegrityError, match="operator"):
            conn.execute("UPDATE site_vendor_ref SET state = 'auto', decided_by = 'rule:x' "
                         "WHERE id = ?", (ref_id,))
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            conn.execute("DELETE FROM site_vendor_ref WHERE id = ?", (ref_id,))
    # S1 still returns ONE site.
    row = _answer(world, _block_event(world), T0.replace(minute=21))
    assert row["site_id"] == site_a
    # Reject → suppressed; an expired rejection comes back only as suggested.
    with world.db().write() as conn:
        p = st.propose(conn, site_id=site_b, vendor="nextdns", instance_id=world.nextdns_id,
                       scope_id="zzz999", state="suggested", score=85, rule_id="L-EGRESS",
                       rule_version=1, evidence={}, now=iso(T0))
        st.operator_reject(conn, p.ref_id, operator_id=7, now=iso(T0), reason="not this site",
                           expires_at=iso(T0 + timedelta(days=1)))
        again = st.propose(conn, site_id=site_b, vendor="nextdns", instance_id=world.nextdns_id,
                           scope_id="zzz999", state="auto", score=90, rule_id="L-EGRESS",
                           rule_version=1, evidence={}, now=iso(T0 + timedelta(hours=1)))
        assert again.outcome in ("suppressed", "unchanged")
        conn.execute("UPDATE site_vendor_ref SET valid_to = ?, state = 'retired', "
                     "decided_by = 'operator:7' WHERE id = ?", (iso(T0), p.ref_id))
        later = st.propose(conn, site_id=site_b, vendor="nextdns", instance_id=world.nextdns_id,
                           scope_id="zzz999", state="auto", score=90, rule_id="L-EGRESS",
                           rule_version=1, evidence={}, now=iso(T0 + timedelta(days=2)))
        assert later.outcome == "inserted"
        state = conn.execute("SELECT state FROM site_vendor_ref WHERE id = ?",
                             (later.ref_id,)).fetchone()["state"]
        assert state == "suggested"


def test_at10_a_shared_profile_is_narrowed_by_the_egress(world):
    world.map(world.unifi_id, {SCOPE_A: A, SCOPE_B: A})
    world.site_report(T0)
    world.site_report(T0, scope=SCOPE_B, name="Warehouse",
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.20", "nat_kind": "direct"}])
    sites_ = [r["site_id"] for r in world.rows("SELECT site_id FROM site ORDER BY created_at")]
    with world.db().write() as conn:
        for s in sites_:
            st.propose(conn, site_id=s, vendor="nextdns", instance_id=world.nextdns_id,
                       scope_id=PROFILE_A, state="auto", score=90, rule_id="L-EGRESS",
                       rule_version=1, evidence={}, now=iso(T0))
    reports(world)
    reports(world, scope=SCOPE_B, name="Warehouse",
            wans=[{"wan": "WAN", "external_ip": "198.51.100.20", "nat_kind": "direct"}])
    eid = _block_event(world, client_ip="198.51.100.20")
    row = _answer(world, eid, T0.replace(minute=21))
    assert row["site_id"] == sites_[1] and row["site_basis"] == "both"
    assert "S-NARROW" in [h["rule"] for h in json.loads(row["chain"])]


# ---------------------------------------------------------------------------
# AT11 / AT-R4 / AT-R5 / AT12 — unstable egress, not located
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("nat,expect_basis,expect_score", [
    ("cgnat", "policy", 95), ("unknown", "policy", 95), ("direct", "both", 99)])
def test_at11_r5_cgnat_and_unknown_never_corroborate(world, nat, expect_basis, expect_score):
    reports(world, wans=[{"wan": "WAN", "external_ip": EGRESS_A, "nat_kind": nat}])
    _confirm_profile(world)
    row = _answer(world, _block_event(world), T0.replace(minute=21))
    assert (row["site_basis"], row["site_score"]) == (expect_basis, expect_score)
    if nat != "direct":
        assert "location_unverified" in json.loads(row["flags"])
        s2 = next(h for h in json.loads(row["chain"]) if h["rule"] == "S2")
        assert s2["score"] == 60


def test_at_r4_a_shared_external_address_never_corroborates(world):
    reports(world, wans=[{"wan": "WAN", "external_ip": EGRESS_A, "nat_kind": "direct",
                          "shared_external": True}])
    _confirm_profile(world)
    row = _answer(world, _block_event(world), T0.replace(minute=21))
    assert row["site_basis"] == "policy" and "location_unverified" in json.loads(row["flags"])


def test_at12_an_address_that_is_no_egress_is_not_located_and_not_stored(world):
    reports(world)
    _confirm_profile(world)
    eid = _block_event(world, client_ip="198.51.100.250")          # an employee's home
    row = _answer(world, eid, T0.replace(minute=21))
    assert (row["site_basis"], row["n_candidates"]) == ("not_located", 0)
    assert "ip_not_an_egress" in json.loads(row["flags"])
    blob = (world.root / "clients" / A / "entities.db").read_bytes()
    assert b"198.51.100.250" not in blob                           # only its token is kept


def test_at15_off_resolves_nothing_shadow_stores(world):
    site_a(world)
    world.set_mode(A, "off")
    _block_event(world, vid="while-off")
    from apps.octo.entity.worker import EntityWorker

    assert EntityWorker(now=lambda: T0.replace(minute=21)).run_once() == {}
    assert world.rows("SELECT * FROM resolution") == []
    # Off → shadow: the sweep starts at the switch (the alert stored while it
    # was off has no lookups behind it); the next alert is stored, not shown.
    world.set_mode(A, "shadow")
    eid = _block_event(world)
    out = EntityWorker(now=lambda: T0.replace(minute=21)).run_once()
    assert out[A]["scanned"] == 1
    assert world.one("SELECT * FROM resolution WHERE event_id = ?", (eid,)) is not None


def test_at16_resolver_version_is_a_hash_of_the_rules():
    import hashlib

    assert rv.RESOLVER_VERSION == "rv_" + hashlib.sha256(
        json.dumps(sorted(rv.RULES.items())).encode()).hexdigest()[:12]


def test_at18_resolve_p99_under_20ms_with_100k_leases(world):
    import time

    site_a(world)
    site = world.one("SELECT site_id FROM site")["site_id"]
    with world.db().write() as conn:
        rows = []
        base = T0 - timedelta(days=60)
        for i in range(100_000):
            start = base + timedelta(minutes=i)
            rows.append((site, SCOPE_A, f"10.20.{(i // 250) % 250}.{i % 250}", mac(i % 250),
                         "global", iso(start), iso(start + timedelta(minutes=30)), "unifi.clients",
                         "fixture"))
        conn.executemany(
            "INSERT INTO lk_ip_lease (site_id, vendor_scope_id, ip, mac, mac_kind, valid_from, "
            " valid_to, source, source_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    eid = _block_event(world)
    r = _resolver(world, T0.replace(minute=21))
    times = []
    from apps.octo.entity.resolver import subject_of

    payload = nextdns_block(T_BLOCK)
    for _ in range(50):
        s = subject_of(eid, "nextdns", "nextdns.security_block", payload)
        t = time.perf_counter()
        with world.db().connect() as conn:
            r.compute(conn, s)
        times.append(time.perf_counter() - t)
    times.sort()
    assert times[int(len(times) * 0.99) - 1] < 0.02, times[-5:]
