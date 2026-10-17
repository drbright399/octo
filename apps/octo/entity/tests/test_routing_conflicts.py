"""Review round 3, item 2: a conflict an operator resolved stays resolved.

The routing check ("this NextDNS profile's traffic comes from none of the
client's sites") re-opened a Resolve within a minute (`record_conflict` reset
`resolved_at`) and counted as a change on every pass. Now:
  * a Resolve sticks until the evidence MATERIALLY changes — a new egress of
    the client, or the condition going away and coming back after days;
  * "accept as expected" (a branch office without UniFi, roaming laptops)
    suppresses the check for that profile;
  * seeing the same condition again writes nothing and is never a change."""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo.entity import linkrules
from apps.octo.entity import sites as st
from apps.octo.entity.tests.conftest import A, PROFILE_A, T0, iso, world  # noqa: F401
from apps.octo.entity.worker import EntityWorker


def _silent_days(world, days, *, egress_queries: int = 0) -> None:  # noqa: F811
    """The profile's per-day volume: none of it from the client's egress."""
    with world.db().write() as conn:
        for day in days:
            conn.execute("INSERT INTO ndns_ip_day (profile_id, day, egress_queries, total_queries, "
                         "egress_ips, read_at) VALUES (?, ?, ?, 5000, '[]', ?) ON CONFLICT "
                         "(profile_id, day) DO UPDATE SET egress_queries = excluded.egress_queries",
                         (PROFILE_A, day, egress_queries, iso(T0)))


def _days(*offsets: int) -> list[str]:
    return [(T0 + timedelta(days=d)).strftime("%Y-%m-%d") for d in offsets]


def _conflict(world):  # noqa: F811
    rows = world.rows("SELECT * FROM link_conflict WHERE kind = 'routing'")
    assert len(rows) == 1
    return rows[0]


def _routing(world, at) -> int:  # noqa: F811
    with world.db().write() as conn:
        return linkrules.routing_sanity(conn, A, iso(at))


def _resolve(world, at) -> None:  # noqa: F811
    with world.db().write() as conn:
        assert st.close_conflict(conn, _conflict(world)["id"], resolution="resolved",
                                 by="operator:7", now=iso(at)) == 1


def test_a_resolved_routing_conflict_stays_resolved_and_is_never_a_change(world):  # noqa: F811
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    worker = EntityWorker(now=world.clock.now)
    first = worker.run_tenant(A)
    assert first["conflicts"] == 1                              # opened + one notice
    _resolve(world, world.clock.now())
    runs = len(world.rows("SELECT * FROM resolution_run"))
    for _ in range(10):
        world.clock.advance(60)
        out = worker.run_tenant(A)
        assert out["links"] == 0 and out["conflicts"] == 0
    c = _conflict(world)
    assert c["resolved_at"] is not None and c["resolution"] == "resolved"
    assert len(world.rows("SELECT * FROM resolution_run")) == runs     # no per-pass rows


def test_an_open_conflict_seen_again_is_written_at_most_hourly(world):  # noqa: F811
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0) == 1
    for minute in range(1, 30):
        assert _routing(world, T0 + timedelta(minutes=minute)) == 0
    assert _conflict(world)["hits"] == 1
    assert _routing(world, T0 + timedelta(minutes=61)) == 0
    assert _conflict(world)["hits"] == 2


def test_a_new_egress_reopens_a_resolved_routing_conflict(world):  # noqa: F811
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0) == 1
    _resolve(world, T0)
    assert _routing(world, T0 + timedelta(minutes=5)) == 0
    world.site_report(T0 + timedelta(minutes=5), wans=[
        {"wan": "WAN", "external_ip": "198.51.100.44", "nat_kind": "direct"}])
    assert _routing(world, T0 + timedelta(minutes=6)) == 1             # material: reopened
    c = _conflict(world)
    assert c["resolved_at"] is None and c["notified"] == 0              # a new notice
    assert "198.51.100.44" in json.loads(c["detail"])["egress"]


def test_the_condition_coming_back_after_days_away_reopens_it(world):  # noqa: F811
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0) == 1
    _resolve(world, T0)
    # Back within a day: the Resolve stands.
    _silent_days(world, _days(-4, -3, -2, -1), egress_queries=4000)
    assert _routing(world, T0 + timedelta(hours=1)) == 0
    assert _conflict(world)["cleared_at"] is not None
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0 + timedelta(hours=20)) == 0
    c = _conflict(world)
    assert c["resolved_at"] is not None and c["cleared_at"] is None
    # Away for days, then back: material — reopened.
    _silent_days(world, _days(-4, -3, -2, -1), egress_queries=4000)
    assert _routing(world, T0 + timedelta(days=1)) == 0
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0 + timedelta(days=1 + linkrules.ROUTING_REOPEN_DAYS)) == 1
    assert _conflict(world)["resolved_at"] is None


def test_accept_as_expected_suppresses_the_check_for_that_profile(world):  # noqa: F811
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    assert _routing(world, T0) == 1
    cid = _conflict(world)["id"]
    with world.db().write() as conn:
        assert st.close_conflict(conn, cid, resolution="accepted", by="operator:7",
                                 now=iso(T0)) == 1
        st.suppress(conn, "routing", linkrules.routing_subject(PROFILE_A),
                    *linkrules.ROUTING_EXPECTED, reason="the branch office has no UniFi",
                    decided_by="operator:7", now=iso(T0), rule_id="routing",
                    expires_at=iso(T0 + timedelta(days=30)))
    # Even a new egress does not bring it back while accepted.
    world.site_report(T0 + timedelta(minutes=5), wans=[
        {"wan": "WAN", "external_ip": "198.51.100.44", "nat_kind": "direct"}])
    for day in range(0, 29, 7):
        assert _routing(world, T0 + timedelta(days=day, minutes=6)) == 0
    assert _conflict(world)["resolution"] == "accepted"
    # The acceptance ran out and the condition still holds: open once more.
    _silent_days(world, _days(27, 28, 29, 30))
    assert _routing(world, T0 + timedelta(days=31)) == 1
    assert _conflict(world)["resolved_at"] is None


def test_a_resolved_operator_decision_conflict_reopens_only_on_new_evidence(world):  # noqa: F811
    world.site_report(T0)
    with world.db().write() as conn:
        site_a = conn.execute("SELECT site_id FROM site").fetchone()["site_id"]
        site_b = st.create_site(conn, label="Warehouse", anchor="operator", now=iso(T0),
                                created_by="operator:7")
        st.operator_link(conn, site_id=site_a, vendor="nextdns", instance_id=world.nextdns_id,
                         scope_id=PROFILE_A, operator_id=7, now=iso(T0))

        def rule_wants(site: str) -> str:
            return st.propose(conn, site_id=site, vendor="nextdns", instance_id=world.nextdns_id,
                              scope_id=PROFILE_A, state="suggested", score=85,
                              rule_id="L-EGRESS", rule_version=1, evidence={},
                              now=iso(T0)).outcome

        assert rule_wants(site_b) == "conflict"
        cid = conn.execute("SELECT id FROM link_conflict").fetchone()["id"]
        assert st.close_conflict(conn, cid, resolution="resolved", by="operator:7",
                                 now=iso(T0)) == 1
        for _ in range(3):
            assert rule_wants(site_b) == "conflict"
        row = conn.execute("SELECT * FROM link_conflict WHERE id = ?", (cid,)).fetchone()
        assert row["resolved_at"] is not None                      # the same evidence again
        third = st.create_site(conn, label="Annex", anchor="operator", now=iso(T0),
                               created_by="operator:7")
        st.operator_link(conn, site_id=third, vendor="nextdns", instance_id=world.nextdns_id,
                         scope_id=PROFILE_A, operator_id=7, now=iso(T0))
        assert rule_wants(site_a) == "conflict"                   # a different site: material
        row = conn.execute("SELECT * FROM link_conflict WHERE id = ?", (cid,)).fetchone()
        assert row["resolved_at"] is None


def _entity_review_notices() -> list:
    from apps.octo import paths
    from apps.octo.db import connect
    reg = connect(paths.registry_db_path())
    try:
        return reg.execute("SELECT request_id, recipient_id FROM operator_notices "
                           "WHERE kind = 'entity_review' ORDER BY id").fetchall()
    finally:
        reg.close()


def test_a_reopened_conflict_notifies_the_admins_again(world):  # noqa: F811
    """Verifier round 2: a reopened conflict kept its id, so the notice dedupe
    key (slug + conflict id) skipped every admin and nobody was told."""
    from apps.octo.auth.operators import create_operator

    create_operator(username="alice", email="alice@example.test", role="admin")
    world.site_report(T0)
    _silent_days(world, _days(-4, -3, -2, -1))
    worker = EntityWorker(now=world.clock.now)
    assert worker.run_tenant(A)["conflicts"] == 1
    first = _entity_review_notices()
    assert len(first) == 1                                          # opened: one notice
    _resolve(world, world.clock.now())
    world.clock.advance(300)
    assert worker.run_tenant(A)["conflicts"] == 0
    assert len(_entity_review_notices()) == 1                       # resolved: silent
    world.site_report(world.clock.now(), wans=[
        {"wan": "WAN", "external_ip": "198.51.100.44", "nat_kind": "direct"}])
    world.clock.advance(60)
    out = worker.run_tenant(A)
    assert out["conflicts"] == 1                                    # reopened ...
    after = _entity_review_notices()
    assert len(after) == 2 and after[0][0] != after[1][0]           # ... and notified again
    world.clock.advance(60)
    worker.run_tenant(A)
    assert len(_entity_review_notices()) == 2                       # never once per pass
