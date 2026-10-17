"""Lookup intervals from the UniFi feeds (design 2.6 with G7 / G10): egress
per site, leases per snapshot with honest slack, the gap rule, day-chunking,
reconnect splits, the system-log watermark, subnets / DNS path, and I10 (an
unmapped site writes nothing)."""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo.entity.tests.conftest import (
    A,
    B,
    EGRESS_A,
    SCOPE_A,
    SCOPE_B,
    T0,
    client,
    iso,
    join_event,
    lan,
    mac,
)


def _leases(world, ip=None):
    sql = "SELECT * FROM lk_ip_lease"
    args: tuple = ()
    if ip:
        sql += " WHERE ip = ?"
        args = (ip,)
    return world.rows(sql + " ORDER BY id", args)


def test_mapping_a_unifi_site_creates_the_site_and_a_confirmed_ref(world):
    world.site_report(T0)
    site = world.one("SELECT * FROM site")
    assert site["anchor"] == "unifi" and site["label"] == "Site A"
    assert site["geo_text"] == "100 Example St" and site["tz"] == "America/Chicago"
    ref = world.one("SELECT * FROM site_vendor_ref")
    assert (ref["vendor"], ref["vendor_scope_id"], ref["state"], ref["rule_id"], ref["score"]) == \
        ("unifi", SCOPE_A, "confirmed", "L-UNIFI", 95)
    assert ref["decided_by"] == "operator:mapping"
    eg = world.one("SELECT * FROM lk_site_egress")
    assert (eg["addr"], eg["nat_kind"], eg["source"], eg["valid_to"]) == (EGRESS_A, "direct",
                                                                         "unifi.sites", None)
    wm = world.one("SELECT * FROM lk_watermark WHERE source = 'unifi.sites'")
    assert wm["scope"] == SCOPE_A and wm["last_ok_at"] == iso(T0)


def test_an_offline_console_moves_no_watermark_and_closes_nothing(world):
    """G7 / AT-R8: /v1/sites can return the last WAN IP of an offline console."""
    world.site_report(T0)
    world.site_report(T0 + timedelta(minutes=5), host_connected=False,
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.77", "nat_kind": "direct"}])
    world.site_report(T0 + timedelta(minutes=10), gateway_online=False)
    rows = world.rows("SELECT * FROM lk_site_egress")
    assert len(rows) == 1 and rows[0]["addr"] == EGRESS_A and rows[0]["valid_to"] is None
    wm = world.one("SELECT * FROM lk_watermark WHERE source = 'unifi.sites'")
    assert wm["last_ok_at"] == iso(T0)
    assert wm["last_attempt_at"] == iso(T0 + timedelta(minutes=10))
    assert "gateway" in wm["last_error"]


def test_an_egress_change_closes_with_slack_and_a_gap_closes_at_the_last_good_poll(world):
    world.site_report(T0)
    world.site_report(T0 + timedelta(minutes=5),
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.9", "nat_kind": "direct"}])
    old, new = world.rows("SELECT * FROM lk_site_egress ORDER BY id")
    mid = iso(T0 + timedelta(minutes=2, seconds=30))
    assert (old["valid_to"], old["to_slack_s"], old["close_reason"]) == (mid, 155, "changed")
    assert (new["valid_from"], new["from_slack_s"]) == (mid, 155)
    # 20 minutes without a good report: the gap is never bridged.
    world.site_report(T0 + timedelta(minutes=25),
                      wans=[{"wan": "WAN", "external_ip": "198.51.100.9", "nat_kind": "direct"}])
    rows = world.rows("SELECT * FROM lk_site_egress ORDER BY id")
    assert rows[1]["valid_to"] == iso(T0 + timedelta(minutes=5)) and rows[1]["close_reason"] == "gap"
    assert rows[2]["valid_from"] == iso(T0 + timedelta(minutes=25))


def test_unmapped_or_switched_off_sites_write_nothing(world):
    """I10: a site not mapped to the tenant named writes nothing; nor does a
    tenant whose switch is off."""
    world.site_report(T0, slug=B, scope=SCOPE_B)                  # B: not mapped, switch off
    world.site_report(T0, slug=A, scope=SCOPE_B)                  # A: that scope is not A's
    assert not (world.root / "clients" / B / "entities.db").exists() or \
        world.rows("SELECT * FROM site", slug=B) == []
    assert world.rows("SELECT * FROM site") == []
    world.set_mode(A, "off")
    world.site_report(T0)
    assert world.rows("SELECT * FROM site") == []


def test_leases_open_exact_from_connected_at_and_an_unchanged_snapshot_writes_nothing(world):
    world.networks()
    c1 = client(1, lan(11), connected=T0 - timedelta(hours=2))
    world.poll(T0, [c1])
    (row,) = _leases(world)
    assert (row["ip"], row["mac"], row["from_exact"], row["valid_from"]) == \
        (lan(11), mac(1), 1, iso(T0 - timedelta(hours=2)))
    assert row["mac_kind"] == "global" and row["mac_tok"].startswith("mc_")
    assert row["name_obs"] == "PC-1"            # device names are not masked (Rick 2026-10-01)
    before = world.rows("SELECT * FROM lk_ip_lease")
    world.poll(T0 + timedelta(minutes=5), [c1])
    after = world.rows("SELECT * FROM lk_ip_lease")
    assert [dict(r) for r in before] == [dict(r) for r in after]


def test_ip_reuse_closes_the_old_holder_with_slack_never_a_bare_edge(world):
    """G10 / AT-R12: MAC1 leaves, MAC2 gets the IP between polls."""
    world.networks()
    world.poll(T0, [client(1, lan(37), connected=T0 - timedelta(hours=1))])
    world.poll(T0 + timedelta(minutes=5), [client(2, lan(37))])
    old, new = _leases(world, lan(37))
    mid = iso(T0 + timedelta(minutes=2, seconds=30))
    assert (old["mac"], old["valid_to"], old["to_exact"], old["to_slack_s"]) == \
        (mac(1), mid, 0, 155)
    assert old["close_reason"] in ("absent", "mac_changed")
    assert (new["mac"], new["valid_from"], new["from_exact"], new["from_slack_s"]) == \
        (mac(2), mid, 0, 155)


def test_a_reconnect_between_polls_splits_the_row(world):
    """G10: same IP at both polls, but connectedAt > prev — the hole
    [prev, connectedAt] is not vouched for."""
    world.networks()
    world.poll(T0, [client(1, lan(37), connected=T0 - timedelta(hours=1))])
    back = T0 + timedelta(minutes=4)
    world.poll(T0 + timedelta(minutes=5), [client(1, lan(37), connected=back)])
    first, second = _leases(world)
    assert (first["valid_to"], first["close_reason"], first["to_slack_s"]) == \
        (iso(T0), "reconnect", 240)
    assert (second["valid_from"], second["from_exact"]) == (iso(back), 1)


def test_a_failed_snapshot_closes_nothing_and_a_long_gap_closes_at_the_last_good_poll(world):
    """AT5."""
    world.networks()
    c1 = client(1, lan(11))
    world.poll(T0, [c1])
    world.unifi.on_client_snapshot_failed(A, SCOPE_A, {"polled_at": iso(T0 + timedelta(minutes=5)),
                                                       "reason": "fixture: 502"})
    world.snapshot(T0 + timedelta(minutes=10), [c1], gateway_online=False)
    (row,) = _leases(world)
    assert row["valid_to"] is None
    wm = world.one("SELECT * FROM lk_watermark WHERE source = 'unifi.clients'")
    assert wm["last_ok_at"] == iso(T0) and wm["last_error"] == "gateway offline"
    world.poll(T0 + timedelta(minutes=30), [c1])
    first, second = _leases(world)
    assert (first["valid_to"], first["close_reason"]) == (iso(T0), "gap")
    assert second["valid_from"] == iso(T0 + timedelta(minutes=30))


def test_a_continuing_lease_is_split_at_midnight(world):
    world.networks()
    late = T0.replace(hour=23, minute=58)
    c1 = client(1, lan(11), connected=late - timedelta(hours=3))
    world.poll(late, [c1])
    world.poll(late + timedelta(minutes=5), [c1])
    first, second = _leases(world)
    midnight = iso((late + timedelta(minutes=5)).replace(hour=0, minute=0))
    assert (first["valid_to"], first["to_exact"], first["close_reason"]) == (midnight, 1, "rollover")
    assert (second["valid_from"], second["from_exact"], second["valid_to"]) == (midnight, 1, None)


def test_joins_give_exact_edges_and_disconnects_close_exactly(world):
    world.networks()
    world.poll(T0, [])
    joined = T0 + timedelta(minutes=2, seconds=11)
    world.log([join_event(joined, 5, lan(55))])
    world.poll(T0 + timedelta(minutes=5), [client(5, lan(55))])
    (row,) = _leases(world)
    assert (row["valid_from"], row["from_exact"]) == (iso(joined), 1)
    left = T0 + timedelta(minutes=7)
    world.log([join_event(left, 5, lan(55), event="CLIENT_DISCONNECTED_WIRED")])
    (row,) = _leases(world)
    assert (row["valid_to"], row["to_exact"], row["close_reason"]) == \
        (iso(left), 1, "disconnect_event")
    assert len(world.rows("SELECT * FROM lk_join")) == 2


def test_networks_give_subnets_with_their_dns_path(world):
    world.site_report(T0)
    world.networks()
    rows = {r["name"]: r for r in world.rows("SELECT * FROM lk_site_subnet")}
    assert (rows["Office"]["cidr"], rows["Office"]["purpose"], rows["Office"]["dns_path"]) == \
        (f"{lan(0)}/24", "corporate", "gateway")
    assert (rows["Guest"]["purpose"], rows["Guest"]["dns_path"], rows["Guest"]["vlan"]) == \
        ("guest", "other", 30)


def test_guest_leases_are_marked_and_the_log_watermark_moves(world):
    world.networks()
    world.poll(T0, [client(1, lan(5, 30))])
    (row,) = _leases(world)
    assert row["is_guest"] == 1 and row["net_id"] == "net-2"
    wm = world.one("SELECT * FROM lk_watermark WHERE source = 'unifi.syslog'")
    assert wm["last_ok_at"] == iso(T0)


def test_no_x_field_or_secret_ever_reaches_entities_db(world):
    """AT14: every UniFi `x_*` / `utm_token` key is stripped before it gets
    here; scan every text column of every table."""
    world.networks([{"_id": "n", "name": "Office", "purpose": "corporate",
                     "ip_subnet": f"{lan(1)}/24", "x_passphrase": "fixture-secret",
                     "utm_token": "fixture-utm"}])
    world.poll(T0, [client(1, lan(11))])
    with world.db().connect() as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        dump = [[dict(r) for r in conn.execute(f"SELECT * FROM {t}")] for t in tables]
    blob = json.dumps(dump)
    assert "fixture-secret" not in blob and "fixture-utm" not in blob

    def keys(value):
        if isinstance(value, dict):
            for k, v in value.items():
                yield k
                yield from keys(v)
        elif isinstance(value, list):
            for v in value:
                yield from keys(v)
        elif isinstance(value, str) and value[:1] in "[{":
            try:
                yield from keys(json.loads(value))
            except ValueError:
                return

    assert not [k for k in keys(dump) if str(k).startswith("x_") or k == "utm_token"]
