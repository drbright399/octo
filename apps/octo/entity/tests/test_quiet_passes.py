"""Review round 3, item 1: a pass that changes nothing writes nothing.

L-SOLE and N-SITE used to take turns rewriting the SAME (site, profile)
suggestion (85, then 45, then 85 …): every minute a `resolution_run` row and a
global audit row per client — +38.6 MB of global audit a day for 40 clients.
Now the link rules give ONE combined suggestion per (site, profile) — the
strongest rule, the others kept as provenance — written only when its
effective state changes, and the worker records a run / audit row only on a
real change, plus at most one heartbeat an hour."""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

from apps.octo import paths
from apps.octo.entity import linkrules
from apps.octo.entity.tests.conftest import A, EGRESS_A, PROFILE_A, T0, iso, world  # noqa: F401
from apps.octo.entity.worker import EntityWorker
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping


def _audit(action: str, slug: str = A) -> int:
    g = sqlite3.connect(paths.global_audit_db_path())
    try:
        return g.execute("SELECT COUNT(*) FROM audit_log WHERE action = ? AND client_slug = ?",
                         (action, slug)).fetchone()[0]
    finally:
        g.close()


def _same_name_profile(world) -> None:  # noqa: F811
    """The profile's mapping label equals the site's label, and it was made by
    a name match (not an operator) — L-SOLE stays `suggested` and N-SITE fires
    on the same (site, profile)."""
    world.site_report(T0, name="Acme Pharmacy, Inc.")
    tenant_map.set_mappings(world.nextdns_id, [TenantMapping(PROFILE_A, A, "Acme Pharmacy, Inc.",
                                                             "auto-name")])


def test_l_sole_and_n_site_give_one_combined_suggestion_written_once(world):  # noqa: F811
    _same_name_profile(world)
    worker = EntityWorker(now=world.clock.now)
    outs = []
    for _ in range(6):
        outs.append(worker.run_tenant(A))
        world.clock.advance(60)
    refs = world.rows("SELECT * FROM site_vendor_ref WHERE vendor = 'nextdns' "
                      "AND valid_to IS NULL")
    assert len(refs) == 1
    ref = refs[0]
    assert (ref["state"], ref["rule_id"], ref["score"]) == ("suggested", "L-SOLE", 85)
    evidence = json.loads(ref["evidence"])
    assert evidence["rules"] == ["L-SOLE", "N-SITE"]          # provenance: both agree
    assert evidence["also"]["N-SITE"] == {"same_name": True}
    assert [o["links"] for o in outs] == [1, 0, 0, 0, 0, 0]
    # One recorded run (the change) — never one per pass.
    assert len(world.rows("SELECT * FROM resolution_run WHERE mode <> 'heartbeat'")) == 1
    assert _audit("entity_resolution_run") == 1


def test_the_evidence_counts_refresh_silently_at_most_once_a_day(world):  # noqa: F811
    _same_name_profile(world)
    with world.db().write() as conn:
        assert linkrules.profile_sites(conn, A, iso(T0)) == 1
        day = (T0 - timedelta(days=1)).strftime("%Y-%m-%d")
        conn.execute("INSERT INTO ndns_ip_day (profile_id, day, egress_queries, total_queries, "
                     "egress_ips, read_at) VALUES (?, ?, 600, 1000, ?, ?)",
                     (PROFILE_A, day, json.dumps([[EGRESS_A, 600]]), iso(T0)))
        # The same day: the coverage changed, the effective state did not.
        assert linkrules.profile_sites(conn, A, iso(T0 + timedelta(minutes=5))) == 0
        before = json.loads(conn.execute("SELECT evidence FROM site_vendor_ref WHERE vendor = "
                                         "'nextdns'").fetchone()[0])
        assert before["coverage"]["queries"] == 0
        # The next day: refreshed (not a change), once.
        assert linkrules.profile_sites(conn, A, iso(T0 + timedelta(days=1))) == 0
        after = json.loads(conn.execute("SELECT evidence FROM site_vendor_ref WHERE vendor = "
                                        "'nextdns'").fetchone()[0])
        assert after["coverage"]["queries"] == 1000 and after["as_of"] > before["as_of"]


def test_a_stronger_opinion_is_a_change_and_a_weaker_one_is_kept_as_provenance(world):  # noqa: F811
    world.site_report(T0)
    tenant_map.set_mappings(world.nextdns_id, [TenantMapping(PROFILE_A, A, "Site A", "manual")])
    with world.db().write() as conn:
        assert linkrules.profile_sites(conn, A, iso(T0)) == 1          # L-SOLE suggested 85
        for d in range(4):                    # the site's egress row is open since T0
            day = (T0 + timedelta(days=d)).strftime("%Y-%m-%d")
            conn.execute("INSERT INTO ndns_ip_day (profile_id, day, egress_queries, "
                         "total_queries, egress_ips, read_at) VALUES (?, ?, 900, 1000, ?, ?)",
                         (PROFILE_A, day, json.dumps([[EGRESS_A, 900]]), iso(T0)))
        later = T0 + timedelta(days=4)
        assert linkrules.profile_sites(conn, A, iso(later)) == 1       # → auto 90 (a change)
        row = conn.execute("SELECT state, score, rule_id, evidence FROM site_vendor_ref "
                           "WHERE vendor = 'nextdns' AND valid_to IS NULL").fetchone()
        assert (row["state"], row["score"], row["rule_id"]) == ("auto", 90, "L-SOLE")
        assert json.loads(row["evidence"])["rules"] == ["L-SOLE", "N-SITE"]
        for minute in (1, 2, 3):
            assert linkrules.profile_sites(conn, A, iso(later + timedelta(minutes=minute))) == 0


def test_a_quiet_tenant_gets_one_heartbeat_an_hour_and_the_worker_one_audit_row(world):  # noqa: F811
    _same_name_profile(world)
    worker = EntityWorker(now=world.clock.now)
    for _ in range(150):                         # 2.5 hours, one pass a minute
        worker.run_once()
        world.clock.advance(60)
    runs = world.rows("SELECT mode, notes FROM resolution_run ORDER BY id")
    assert [r["mode"] for r in runs] == ["sweep", "heartbeat", "heartbeat"]
    assert json.loads(runs[1]["notes"])["passes"] == 60
    assert _audit("entity_resolution_run") == 1                  # the one real change
    assert _audit("entity_worker_heartbeat", "global") == 2      # hourly, all tenants
    # A restart never adds an early heartbeat: it counts from the last row.
    again = EntityWorker(now=world.clock.now)
    for _ in range(20):
        again.run_once()
        world.clock.advance(60)
    assert len(world.rows("SELECT * FROM resolution_run")) == 3
