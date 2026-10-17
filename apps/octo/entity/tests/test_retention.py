"""Entity retention (design 7.5 + G11) through the REAL nightly retention job:
closed leases go at 90 days (guest networks at 7), answers keep their chain
but their candidate list is cut to a count once the leases behind it are
gone (AT17 / AT-R15), ended links go 400 days after they ended — through the
`maint` flag, never by a rule — open intervals and active links never go,
and a dry run deletes nothing."""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo.entity import db as entity_db
from apps.octo.retention.job import RetentionJob
from apps.octo.tests._tiering_fixtures import NOW, ago, make_root

A = "acme-corp"


@pytest.fixture
def root(tmp_path, monkeypatch):
    entity_db.reset_schema_cache()
    return make_root(tmp_path, monkeypatch, tenants=(A,))


def _conn(root) -> sqlite3.Connection:
    path = root / "clients" / A / "entities.db"
    entity_db.ensure_db(path)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _seed(root) -> str:
    c = _conn(root)
    c.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, updated_at) "
              "VALUES ('st_A', 'Site A', 'unifi', ?, 'rule:L-UNIFI', ?)", (ago(days=500),) * 2)
    leases = [  # (ip, valid_from, valid_to, guest)
        ("192.0.2.11", ago(days=120), ago(days=119), 0),      # old: goes
        ("192.0.2.12", ago(days=30), ago(days=29), 0),        # recent: stays
        ("192.0.2.13", ago(days=10), ago(days=9), 1),         # guest, 9 days: goes
        ("192.0.2.14", ago(days=200), None, 0),               # open: never goes
    ]
    for n, (ip, start, end, guest) in enumerate(leases):
        c.execute("INSERT INTO lk_ip_lease (id, site_id, vendor_scope_id, ip, mac, mac_tok, "
                  "mac_kind, name_obs, is_guest, valid_from, valid_to, source, source_ref) "
                  "VALUES (?, 'st_A', 's', ?, ?, ?, 'global', ?, ?, ?, ?, 'unifi.clients', 'x')",
                  (n + 1, ip, f"00:00:5e:00:53:{n:02x}", f"mc_{n}", f"FRONT-DESK-{n}", guest,
                   start, end))
    cands = [{"lease_id": 1, "mac_tok": "mc_0", "score": 50, "features": []},
             {"lease_id": 2, "mac_tok": "mc_1", "score": 50, "features": []}]
    for res_id, created, cl in (("rs_old", ago(days=118), cands),
                                ("rs_recent", ago(days=29), [cands[1]]),
                                ("rs_ancient", ago(days=400), [])):
        c.execute("INSERT INTO resolution (res_id, event_id, event_source, subject_type, "
                  "subject_tok, tok_key_version, at, time_quality, site_id, site_basis, tier, "
                  "score, n_candidates, chain, candidates, resolver_version, lookup_watermark, "
                  "status, created_at, created_by) VALUES (?, 1, 'nextdns', 'public_ip', 'ip_x', "
                  "'v1', ?, 'vendor', 'st_A', 'both', 'candidate', 25, ?, '[{\"rule\":\"S1\"}]', "
                  "?, 'rv', 'complete', 'final', ?, 'rule:sweep')",
                  (res_id, created, len(cl), json.dumps(cl), created))
    # Links: a rejected one ended 500 days ago (goes), a confirmed one (never).
    for rid, state, decided in ((1, "rejected", ago(days=500)), (2, "confirmed", ago(days=500))):
        c.execute("INSERT INTO site_vendor_ref (id, site_id, vendor, vendor_scope_id, state, "
                  "score, rule_id, rule_version, inputs_sha256, valid_from, valid_to, decided_by, "
                  "decided_at, created_at) VALUES (?, 'st_A', 'nextdns', ?, ?, 95, 'op', 1, 'h', "
                  "?, NULL, 'operator:7', ?, ?)", (rid, f"p{rid}", state, decided, decided,
                                                   decided))
    c.close()
    return "st_A"


def _rows(root, sql):
    c = _conn(root)
    try:
        return [dict(r) for r in c.execute(sql)]
    finally:
        c.close()


def test_entity_classes_prune_what_they_should_and_cut_candidates_to_a_count(root):
    _seed(root)
    dry = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script", dry_run=True)
    [t] = [t for t in dry.tenants if t.slug == A]
    assert t.classes["entity_lookup_lease"].planned == 2
    assert t.classes["entity_resolution"].planned == 1
    assert t.classes["entity_links"].planned == 1
    assert len(_rows(root, "SELECT * FROM lk_ip_lease")) == 4          # dry: nothing went

    report = RetentionJob(data_root=root, now=lambda: NOW, archive_from_env=False).run(
        trigger="script")
    [t] = [t for t in report.tenants if t.slug == A]
    assert t.classes["entity_lookup_lease"].deleted == 2
    assert [r["ip"] for r in _rows(root, "SELECT ip FROM lk_ip_lease ORDER BY id")] == \
        ["192.0.2.12", "192.0.2.14"]
    res = {r["res_id"]: r for r in _rows(root, "SELECT * FROM resolution")}
    assert set(res) == {"rs_old", "rs_recent"}                         # 365 d: ancient went
    # G11: the old answer keeps its count and chain; its list is gone.
    assert json.loads(res["rs_old"]["candidates"]) == [] and res["rs_old"]["n_candidates"] == 2
    assert res["rs_old"]["chain"] == '[{"rule":"S1"}]'
    assert len(json.loads(res["rs_recent"]["candidates"])) == 1
    # The ended operator decision went through the retention job's flag; the
    # confirmed one stays, and the flag is back to 0.
    assert [r["state"] for r in _rows(root, "SELECT state FROM site_vendor_ref")] == ["confirmed"]
    assert _rows(root, "SELECT allow_operator_delete FROM maint")[0]["allow_operator_delete"] == 0
    # No name of a device is anywhere in a stored answer (AT-R15 scan).
    assert "FRONT-DESK" not in json.dumps(_rows(root, "SELECT * FROM resolution"))


def test_nobody_else_can_delete_an_operator_decision(root):
    _seed(root)
    c = _conn(root)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            c.execute("DELETE FROM site_vendor_ref WHERE id = 2")
    finally:
        c.close()
