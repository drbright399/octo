"""Evidence windows through the REAL nightly retention job (Tier Black, 044;
Rick, 2026-10-05: "Ingestion should not stop but if a threat is confirmed
everything from first detection up until the all clear should be treated as
event evidence").

Pins:
  * EVERY prune path keeps what lies inside a held window and prunes what
    lies outside it as usual: events (vendor time OR arrival inside),
    agent notes, indicators (auto / promoted: their first→last sighting
    overlapping), raw telemetry (and its cold archive never takes an
    in-window row), every roll-up table, the first-seen ledger, every
    entity class (intervals overlapping; hour / day buckets) and the G11
    trim of stored answers, the nightly sweep (an in-window row stays in
    events.db as it is) — the run is OK, not partial, and says per class
    and per window what it kept (written back to the window);
  * an OPEN window (the incident not closed yet) keeps everything from the
    first detection on;
  * a window opened between the plan and the delete holds at once (events:
    inside the DELETE; the other stores: re-read before every batch);
  * windows that cannot be read prune NOTHING of the tenant (fail closed);
  * released, the next run prunes what had expired inside it;
  * a dry run counts the same and writes nothing;
  * INGESTION never stops nor slows because of a window: it never reads one.
Fixture names only (acme-corp / globex, RFC 5737 / 2606).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from apps.octo.retention import evidence
from apps.octo.retention.archive import ColdArchive
from apps.octo.retention.job import RetentionJob
from apps.octo.tests._tiering_fixtures import (
    NOW, ago, db, file_digests, insert_event, iso, make_root, pihole_payload, rows,
    write_telemetry,
)

A, B = "acme-corp", "globex"
# The window under test: ~6.5 years back — older than EVERY class's retention
# (the longest, agent notes and promoted indicators, is 2190 days), so all
# that lies inside it has expired and only the window keeps it.
W_START, W_END = 2400, 2300          # days ago
IN, BEFORE, AFTER = 2350, 2500, 2250  # days ago: inside, before, after (still expired: > 2190)


@pytest.fixture
def root(tmp_path, monkeypatch):
    from apps.octo.entity import db as entity_db
    from apps.octo.threat import store

    entity_db.reset_schema_cache()
    store.reset_schema_cache()
    return make_root(tmp_path, monkeypatch, tenants=(A, B))


def _job(root, **kw) -> RetentionJob:
    kw.setdefault("archive_from_env", False)
    return RetentionJob(data_root=root, now=lambda: NOW, **kw)


def _ids(root, slug, name, table, key="id") -> set:
    return {r[0] for r in rows(db(root, slug, name), f"SELECT {key} FROM {table}")}


def _closed_window(slug: str = A, start_days: int = W_START, end_days: int = W_END) -> tuple:
    """A Black opened on evidence `start_days` ago, closed `end_days` ago:
    its window is [first detection, the all-clear] and still HELD."""
    from apps.octo.threat import store

    trigger = _event(slug, ago(days=start_days), {"trigger": 1})
    inc = store.open_incident(slug, tier="black", rule_id="B6", rule_version=1,
                              key=f"{slug}|ws-01|analyst|", summary="hands on keyboard",
                              scope="device", opened_by="7", reason="the client called",
                              device_ref="ws-01", event_ids=[trigger],
                              now=NOW - timedelta(days=start_days - 1)).incident
    store.close(slug, inc.id, by="7", code="remediated", text="reimaged",
                now=NOW - timedelta(days=end_days))
    (w,) = store.evidence_windows(slug, incident_id=inc.id)
    assert (w.start, w.end, w.held) == (ago(days=start_days), ago(days=end_days), True)
    return inc, w, trigger


def _event(slug: str, when: str, payload: dict, *, arrived: str | None = None,
           event_type: str = "wazuh.alert") -> int:
    from apps.octo import paths

    return insert_event(paths.data_root(), slug, event_type=event_type, payload=payload, received_at=when,
                        severity="high" if event_type == "wazuh.alert" else "info",
                        source="wazuh" if event_type == "wazuh.alert" else "buoy:acme",
                        ingested_at=arrived)


def _exec(root, slug: str, store_name: str, sql: str, params: tuple = ()) -> int:
    conn = sqlite3.connect(db(root, slug, store_name))
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def _note(root, slug: str, created: str) -> int:
    return _exec(root, slug, "events",
                 "INSERT INTO agent_notes (ref_kind, ref_id, agent_id, note_text, confidence, "
                 "created_at, audit_request_id) VALUES ('ticket', 1, 'octo', 'n', 0.5, ?, 'r')",
                 (created,))


def _indicator(root, slug: str, value: str, first: str, last: str, promoted=None) -> int:
    return _exec(root, slug, "indicators",
                 "INSERT INTO indicators (value, type, source, severity, confidence, first_seen, "
                 "last_seen, promoted_at) VALUES (?, 'ip', 'wazuh', 'high', 0.5, ?, ?, ?)",
                 (value, first, last, promoted))


def _hour(days: int) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:00:00Z")


def _day(days: int) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%d")


def _rollups(root, slug: str, days: int, tag: str) -> None:
    """One row in EVERY roll-up table of telemetry.db, of that hour/time."""
    h, t = _hour(days), ago(days=days)
    for sql, params in (
        ("INSERT INTO telemetry_hourly (hour, event_type, domain, device, count, first_seen, "
         "last_seen, last_arrival) VALUES (?, 'pihole.query', ?, '192.0.2.10', 3, ?, ?, ?)",
         (h, f"{tag}-rollup.example.test", t, t, t)),
        ("INSERT INTO nextdns_hourly (hour, profile_id, queries, fetched_at, last_arrival) "
         "VALUES (?, ?, 5, ?, ?)", (h, f"p-{tag}", t, t)),
        ("INSERT INTO nextdns_signal_buckets (bucket_key, hour, profile_id, reason_id, "
         "first_seen, last_seen, last_arrival) VALUES (?, ?, 'p', 'r', ?, ?, ?)",
         (f"nb-{tag}", h, t, t, t)),
        ("INSERT INTO unifi_hourly (hour, scope, kind, events, last_arrival) "
         "VALUES (?, ?, 'ips', 2, ?)", (h, f"s-{tag}", t)),
        ("INSERT INTO unifi_signal_buckets (bucket_key, hour, scope, kind, first_seen, "
         "last_seen, last_arrival) VALUES (?, ?, 's', 'ips', ?, ?, ?)",
         (f"ub-{tag}", h, t, t, t)),
        ("INSERT INTO unifi_syslog_cursor (scope, hwm_ms, scanned_to_ms, updated_at, "
         "last_arrival) VALUES (?, 0, 0, ?, ?)", (f"s-{tag}", t, t)),
    ):
        _exec(root, slug, "telemetry", sql, params)


ROLLUP_KEYS = {"telemetry_hourly": "domain", "nextdns_hourly": "profile_id",
               "nextdns_signal_buckets": "bucket_key", "unifi_hourly": "scope",
               "unifi_signal_buckets": "bucket_key", "unifi_syslog_cursor": "scope"}


def _entities(root, slug: str, days: int, tag: str) -> None:
    """One expired row in every table each entity class prunes."""
    from apps.octo.entity import db as entity_db

    path = db(root, slug, "entities")
    entity_db.ensure_db(path)
    t, t2 = ago(days=days), ago(days=days - 1)
    conn = sqlite3.connect(path)
    try:
        conn.execute("INSERT OR IGNORE INTO site (site_id, label, anchor, created_at, "
                     "created_by, updated_at) VALUES ('st_A', 'Site A', 'unifi', ?, 'r', ?)",
                     (ago(days=3000), ago(days=3000)))
        for sql, params in (
            ("INSERT INTO lk_ip_lease (site_id, vendor_scope_id, ip, mac, mac_kind, "
             "valid_from, valid_to, source, source_ref) VALUES ('st_A', 's', ?, ?, 'global', "
             "?, ?, 'unifi.clients', 'x')", (f"192.0.2.{len(tag)}", f"{tag}-mac", t, t2)),
            ("INSERT INTO lk_join (site_id, vendor_scope_id, event, at, vendor_event_id) "
             "VALUES ('st_A', 's', 'join', ?, ?)", (t, f"j-{tag}")),
            ("INSERT INTO lk_mac_anomaly (site_id, vendor_scope_id, mac, kind, from_ts, to_ts, "
             "created_at) VALUES ('st_A', 's', ?, 'two_ips', ?, ?, ?)", (f"{tag}-mac", t, t2, t)),
            ("INSERT INTO lk_ip_conflict (site_id, vendor_scope_id, ip, at, vendor_event_id) "
             "VALUES ('st_A', 's', '192.0.2.9', ?, ?)", (t, f"c-{tag}")),
            ("INSERT INTO lk_uplink (site_id, vendor_scope_id, mac, source, uplink, at) "
             "VALUES ('st_A', 's', ?, 'log', 'sw-1', ?)", (f"{tag}-mac", t)),
            ("INSERT INTO lk_site_egress (site_id, addr, prefix_len, source, valid_from, "
             "valid_to, source_ref) VALUES ('st_A', '198.51.100.7', 32, 'unifi.sites', ?, ?, "
             "?)", (t, t2, f"e-{tag}")),
            ("INSERT INTO lk_site_subnet (site_id, cidr, valid_from, valid_to, source) "
             "VALUES ('st_A', ?, ?, ?, 'unifi')", (f"10.{len(tag)}.0.0/24", t, t2)),
            ("INSERT INTO resolution (res_id, subject_type, subject_tok, tok_key_version, at, "
             "time_quality, tier, score, chain, resolver_version, lookup_watermark, status, "
             "created_at, created_by) VALUES (?, 'public_ip', 'ip_x', 'v1', ?, 'vendor', "
             "'none', 0, '[]', 'rv', 'w', 'final', ?, 'rule:sweep')", (f"rs-{tag}", t, t)),
            ("INSERT INTO device_link (a_type, a_value, b_type, b_value, state, score, rule_id, "
             "rule_version, valid_from, valid_to, decided_by, decided_at, created_at) VALUES "
             "('nextdns_device', ?, 'datto_device', 'd', 'retired', 50, 'L', 1, ?, ?, "
             "'rule:x', ?, ?)", (f"p:{tag}", t, t2, t2, t)),
            ("INSERT INTO link_suppression (a_type, a_value, b_type, b_value, reason, "
             "decided_by, decided_at, expires_at) VALUES ('x', ?, 'y', 'z', 'a reason', "
             "'operator:1', ?, ?)", (tag, t, t2)),
            ("INSERT INTO link_conflict (kind, subject, first_seen, last_seen, resolved_at) "
             "VALUES ('routing', ?, ?, ?, ?)", (tag, t, t, t2)),
            ("INSERT INTO resolution_run (mode, resolver_version, started_at, finished_at) "
             "VALUES ('sweep', 'rv', ?, ?)", (t, t2)),
            ("INSERT INTO inv_device (adapter_instance_id, device_uid, site_uid, first_seen_at, "
             "updated_at, missing_since) VALUES (1, ?, 's', ?, ?, ?)", (f"d-{tag}", t, t2, t2)),
            ("INSERT INTO ndns_device (profile_id, device_id, first_seen, last_seen) "
             "VALUES ('p', ?, ?, ?)", (f"nd-{tag}", t, t2)),
            ("INSERT INTO ndns_device_hour (profile_id, device_id, hour, queries) "
             "VALUES ('p', ?, ?, 1)", (f"nd-{tag}", _hour(days))),
            ("INSERT INTO ndns_presence_hour (profile_id, hour, complete, method, read_at) "
             "VALUES (?, ?, 1, 'logs', ?)", (f"p-{tag}", _hour(days), t)),
            ("INSERT INTO ndns_ip_day (profile_id, day, read_at) VALUES (?, ?, ?)",
             (f"p-{tag}", _day(days), t)),
            ("INSERT INTO ndns_device_day (profile_id, device_id, day, queries) "
             "VALUES ('p', ?, ?, 1)", (f"nd-{tag}", _day(days))),
            ("INSERT INTO ndns_seed_day (profile_id, day, read_at) VALUES (?, ?, ?)",
             (f"p-{tag}", _day(days), t)),
        ):
            conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


ENTITY_TABLES = ("lk_ip_lease", "lk_join", "lk_mac_anomaly", "lk_ip_conflict", "lk_uplink",
                 "lk_site_egress", "lk_site_subnet", "resolution", "device_link",
                 "link_suppression", "link_conflict", "resolution_run", "inv_device",
                 "ndns_device", "ndns_device_hour", "ndns_presence_hour", "ndns_ip_day",
                 "ndns_device_day", "ndns_seed_day")


def _entity_count(root, slug: str, table: str) -> int:
    return rows(db(root, slug, "entities"), f"SELECT COUNT(*) FROM {table}")[0][0]


def _seed(root, slug: str) -> dict:
    """In / before / after the window, in every class."""
    s: dict = {}
    for octet, (tag, days) in enumerate((("in", IN), ("before", BEFORE), ("after", AFTER)), 1):
        s[f"event_{tag}"] = _event(slug, ago(days=days), {"tag": tag})
        s[f"note_{tag}"] = _note(root, slug, ago(days=days))
        s[f"auto_{tag}"] = _indicator(root, slug, f"203.0.113.{octet}", ago(days=days),
                                      ago(days=days))
        s[f"prom_{tag}"] = _indicator(root, slug, f"198.51.100.{octet}",
                                      ago(days=days + 5), ago(days=days),
                                      promoted=ago(days=days))
        s[f"raw_{tag}"] = write_telemetry(root, slug, received_at=ago(days=days),
                                          domain=f"{tag}.example.test", n=days)
        _rollups(root, slug, days, tag)
        _exec(root, slug, "telemetry", "INSERT INTO first_seen_domains VALUES (?, ?, 'x', "
              "'pihole.query', ?)", (f"fs-{tag}.example.test", ago(days=days + 2),
                                     ago(days=days)))
        _entities(root, slug, days, tag)
    # The vendor's time is outside, its ARRIVAL inside: evidence too.
    s["event_late"] = _event(slug, ago(days=BEFORE), {"tag": "late"}, arrived=ago(days=IN))
    # An indicator first seen before the window, last seen after it (and
    # long expired): it spans the window — kept.
    s["auto_span"] = _indicator(root, slug, "203.0.113.200", ago(days=BEFORE), ago(days=AFTER))
    return s


# ---------------------------------------------------------------------------
# Every prune path
# ---------------------------------------------------------------------------

def test_every_prune_path_keeps_what_lies_inside_a_held_window(root):
    from apps.octo.threat import store

    inc, w, trigger = _closed_window(A)
    s, other = _seed(root, A), _seed(root, B)
    report = _job(root).run(trigger="script")
    assert report.status == "ok", report.as_dict()          # NOT partial for the tenant
    t = next(t for t in report.tenants if t.slug == A)
    c = t.classes

    # events: inside (by vendor time OR arrival) kept; outside pruned.
    left = _ids(root, A, "events", "events")
    assert {s["event_in"], s["event_late"], trigger} <= left
    assert not {s["event_before"], s["event_after"]} & left
    # agent notes, indicators
    assert _ids(root, A, "events", "agent_notes") == {s["note_in"]}
    assert _ids(root, A, "indicators", "indicators") == {s["auto_in"], s["auto_span"],
                                                          s["prom_in"]}
    # raw telemetry, every roll-up table, the first-seen ledger
    assert _ids(root, A, "telemetry", "telemetry_raw") == {s["raw_in"]}
    for table, key in ROLLUP_KEYS.items():
        kept = _ids(root, A, "telemetry", table, key)          # (the raw writes fold too)
        assert kept and all(k.startswith(("in", "nb-in", "ub-in", "s-in", "p-in"))
                            for k in kept), (table, kept)
    assert _ids(root, A, "telemetry", "first_seen_domains", "domain") == {
        "fs-in.example.test", "in.example.test"}
    # every entity table
    for table in ENTITY_TABLES:
        assert _entity_count(root, A, table) == 1, table
    # Counted per class as evidence, and per window on the window itself.
    for name in ("events", "agent_notes", "indicators_auto", "indicators_promoted",
                 "telemetry_raw", "telemetry_rollup", "first_seen_domains",
                 "entity_lookup_lease", "entity_lookup_egress", "entity_resolution",
                 "entity_links", "entity_inventory"):
        assert c[name].status == "ok" and c[name].evidence >= 1, (name, c[name])
        assert "evidence window (incident #" in c[name].note, name
    assert c["events"].evidence == 2 and c["events"].referenced >= 1    # the trigger: cited
    assert c["telemetry_rollup"].evidence == 7          # one per table, + the raw row's hour
    total = sum(cr.evidence for cr in c.values())
    assert t.evidence["kept"] == {str(w.id): total}
    (after,) = store.evidence_windows(A, incident_id=inc.id)
    assert after.kept_rows == total and after.kept_counted_at
    # On the chain: the plan row says what the windows kept.
    audit = sqlite3.connect(root / "global" / "audit.db")
    try:
        plan = json.loads(audit.execute(
            "SELECT after_state FROM audit_log WHERE action = 'retention_enforce' AND "
            "client_slug = ?", (A,)).fetchone()[0])
    finally:
        audit.close()
    assert plan["evidence_windows"][0]["id"] == w.id
    assert plan["classes"]["telemetry_raw"]["evidence"] == 1

    # The other tenant has no window: everything expired went.
    assert _ids(root, B, "events", "events") == set()
    assert _ids(root, B, "telemetry", "telemetry_raw") == set()
    assert _ids(root, B, "indicators", "indicators") == set()
    for table in ENTITY_TABLES:
        assert _entity_count(root, B, table) == 0, table
    assert other  # seeded alike

    # Released (after the all-clear): the next run prunes what had expired
    # inside it — the incident's own records stay (cited: never deleted).
    store.release_window(A, inc.id, w.id, by="1", reason="the claim is settled", now=NOW)
    again = next(t for t in _job(root).run().tenants if t.slug == A)
    assert again.classes["events"].deleted == 2 and again.classes["events"].evidence == 0
    assert _ids(root, A, "events", "agent_notes") == set()
    assert _ids(root, A, "telemetry", "telemetry_raw") == set()
    for table in ENTITY_TABLES:
        assert _entity_count(root, A, table) == 0, table
    assert trigger in _ids(root, A, "events", "events")


def test_an_open_window_keeps_everything_from_the_first_detection_on(root):
    from apps.octo.threat import store

    trigger = _event(A, ago(days=400), {"trigger": 1})
    store.open_incident(A, tier="red", rule_id="R8", rule_version=1, key=f"{A}|ws-01|analyst|",
                        summary="confirmed", scope="device", opened_by="7",
                        reason="a ransomware hash", device_ref="ws-01", event_ids=[trigger],
                        now=NOW - timedelta(days=1))
    before = _event(A, ago(days=500), {"n": 1})
    inside = _event(A, ago(days=390), {"n": 2})
    raw_before = write_telemetry(root, A, received_at=ago(days=420), domain="a.example.test")
    raw_inside = write_telemetry(root, A, received_at=ago(days=20), domain="b.example.test")
    report = _job(root).run()
    assert report.status == "ok"
    assert inside in _ids(root, A, "events", "events")
    assert before not in _ids(root, A, "events", "events")
    assert _ids(root, A, "telemetry", "telemetry_raw") == {raw_inside}
    assert raw_before not in _ids(root, A, "telemetry", "telemetry_raw")


def test_a_window_opened_between_the_plan_and_the_delete_holds_at_once(root, monkeypatch):
    """A window recorded while the job runs (after its plan, before its
    deletes) keeps its rows: events.db re-checks the live table inside every
    DELETE; the other stores re-read the windows before every batch."""
    from apps.octo.threat import store

    event = _event(A, ago(days=500), {"n": 1})
    raw = write_telemetry(root, A, received_at=ago(days=30), domain="c.example.test")
    note = _note(root, A, ago(days=3000))
    real_audit = RetentionJob._audit

    def audit_then_open(self, result, report):
        out = real_audit(self, result, report)
        if result.slug == A:
            inc = store.open_incident(A, tier="black", rule_id="B6", rule_version=1,
                                      key=f"{A}|tenant|analyst|", summary="declared",
                                      scope="tenant", opened_by="7", reason="client called",
                                      now=NOW)
            store.add_window(A, inc.incident.id, start=ago(days=3100), end=None, by="1",
                             reason="claim CL-0002", now=NOW)
        return out

    monkeypatch.setattr(RetentionJob, "_audit", audit_then_open)
    report = _job(root).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.classes["events"].planned == 1 and t.classes["events"].deleted == 0
    assert t.classes["telemetry_raw"].planned == 1 and t.classes["telemetry_raw"].deleted == 0
    assert t.classes["agent_notes"].deleted == 0
    assert event in _ids(root, A, "events", "events")
    assert raw in _ids(root, A, "telemetry", "telemetry_raw")
    assert note in _ids(root, A, "events", "agent_notes")


def test_windows_that_cannot_be_read_prune_nothing_of_the_tenant(root, monkeypatch):
    _seed(root, A)
    real = evidence.held

    def broken(client_dir, **kw):
        if client_dir.name == A:
            raise evidence.WindowsUnavailable("database disk image is malformed")
        return real(client_dir, **kw)

    monkeypatch.setattr(evidence, "held", broken)
    before = {name: rows(db(root, A, name), "SELECT COUNT(*) FROM sqlite_master")
              for name in ("events", "telemetry")}
    counts = (len(_ids(root, A, "events", "events")),
              len(_ids(root, A, "telemetry", "telemetry_raw")))
    report = _job(root).run()
    assert report.status == "partial"
    t = next(t for t in report.tenants if t.slug == A)
    assert t.sweep.get("skipped") is True
    for name, cr in t.classes.items():
        if name not in ("audit", "secure_notepad"):
            assert cr.status == "blocked" and cr.deleted == 0, name
            assert "evidence windows could not be read" in cr.note, name
    assert (len(_ids(root, A, "events", "events")),
            len(_ids(root, A, "telemetry", "telemetry_raw"))) == counts
    assert before  # schema untouched
    assert t.evidence["error"]


def test_a_dry_run_counts_the_evidence_and_writes_nothing(root):
    _closed_window(A)
    _seed(root, A)
    digests = file_digests(root)
    dry = next(t for t in _job(root).run(dry_run=True).tenants if t.slug == A)
    assert file_digests(root) == digests                     # kept_rows not written either
    real = next(t for t in _job(root).run().tenants if t.slug == A)
    assert {k: c.evidence for k, c in dry.classes.items()} == \
           {k: c.evidence for k, c in real.classes.items()}
    assert {k: c.planned for k, c in dry.classes.items()} == \
           {k: c.deleted for k, c in real.classes.items()}


def test_the_g11_trim_never_cuts_an_answer_inside_a_window(root):
    """G11: once its leases are pruned, a stored answer's candidate list is
    cut to a count — but an answer inside an evidence window is evidence:
    left whole."""
    from apps.octo.entity import db as entity_db

    _closed_window(A, start_days=200, end_days=150)
    path = db(root, A, "entities")
    entity_db.ensure_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute("INSERT INTO site (site_id, label, anchor, created_at, created_by, "
                     "updated_at) VALUES ('st_A', 'Site A', 'unifi', ?, 'r', ?)",
                     (ago(days=900), ago(days=900)))
        conn.execute("INSERT INTO lk_ip_lease (id, site_id, vendor_scope_id, ip, mac, mac_kind, "
                     "valid_from, valid_to, source, source_ref) VALUES (1, 'st_A', 's', "
                     "'192.0.2.5', '00:00:5e:00:53:01', 'global', ?, ?, 'unifi.clients', 'x')",
                     (ago(days=300), ago(days=299)))                    # outside: pruned
        cands = json.dumps([{"lease_id": 1, "mac_tok": "mc_1", "score": 50}])
        for res_id, created in (("rs_in", ago(days=160)), ("rs_out", ago(days=250))):
            conn.execute(
                "INSERT INTO resolution (res_id, subject_type, subject_tok, tok_key_version, at, "
                "time_quality, tier, score, n_candidates, chain, candidates, resolver_version, "
                "lookup_watermark, status, created_at, created_by) VALUES (?, 'public_ip', "
                "'ip_x', 'v1', ?, 'vendor', 'candidate', 25, 1, '[]', ?, 'rv', 'w', 'final', ?, "
                "'rule:sweep')", (res_id, created, cands, created))
        conn.commit()
    finally:
        conn.close()
    _job(root).run()
    out = {r[0]: json.loads(r[1]) for r in rows(path, "SELECT res_id, candidates FROM resolution")}
    assert rows(path, "SELECT COUNT(*) FROM lk_ip_lease")[0][0] == 0
    assert out == {"rs_in": json.loads(cands), "rs_out": []}


# ---------------------------------------------------------------------------
# The sweep and the archive
# ---------------------------------------------------------------------------

def test_the_sweep_leaves_in_window_rows_in_events_db_as_they_are(root):
    """Telemetry that fell back into events.db: the sweep moves it to
    telemetry.db — except what lies inside a held window (evidence keeps its
    id, like a cited event)."""
    from apps.octo.threat import store

    store.open_incident(A, tier="red", rule_id="R8", rule_version=1, key=f"{A}|ws-01|analyst|",
                        summary="confirmed", scope="device", opened_by="7", reason="x" * 20,
                        now=NOW - timedelta(days=2))
    inside = _event(A, ago(days=1), pihole_payload(2), event_type="pihole.query")
    outside = _event(A, ago(days=4), pihole_payload(2, n=3), event_type="pihole.query")
    report = _job(root).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.sweep["moved"] == 1 and t.sweep["kept_evidence"] == 1
    assert inside in _ids(root, A, "events", "events")
    assert outside not in _ids(root, A, "events", "events")
    assert rows(db(root, A, "telemetry"), "SELECT origin_event_id FROM telemetry_raw") == \
        [(outside,)]


def test_the_archive_never_takes_an_in_window_row(root, tmp_path):
    _closed_window(A, start_days=12, end_days=9)
    inside = write_telemetry(root, A, received_at=ago(days=10), domain="in.example.test")
    outside = write_telemetry(root, A, received_at=ago(days=20), domain="out.example.test")
    arch_root = tmp_path / "archive"
    arch_root.mkdir()
    arch = ColdArchive(arch_root)
    report = _job(root, archive=arch).run()
    t = next(t for t in report.tenants if t.slug == A)
    assert t.archive["days"] == [ago(days=20)[:10]]
    assert [r["id"] for r in arch.read_day(A, ago(days=20)[:10])] == [outside]
    assert _ids(root, A, "telemetry", "telemetry_raw") == {inside}
    assert t.classes["telemetry_raw"].evidence == 1


# ---------------------------------------------------------------------------
# Ingestion never stops nor slows for a window
# ---------------------------------------------------------------------------

def test_ingestion_never_reads_a_window_and_never_stops_for_one(root, monkeypatch):
    """An open window (a Black still open) changes nothing for ingest: the
    sink stores signals and telemetry exactly as before, and never even
    looks at a window — every window read below raises if it were called."""
    import hashlib

    from shared_adapter_contract.types import CanonicalEvent

    from apps.octo.ingest.sink import SqliteIngestSink
    from apps.octo.threat import store
    from apps.octo.threat import windows as threat_windows

    store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key=f"{A}|ws-01|analyst|",
                        summary="declared", scope="device", opened_by="7", reason="the client",
                        now=NOW - timedelta(hours=1))
    assert store.evidence_windows(A, state="held")[0].is_open

    def never(*_a, **_k):
        raise AssertionError("ingest read an evidence window")

    monkeypatch.setattr(evidence, "held", never)
    monkeypatch.setattr(evidence, "load_temp", never)
    for name in ("first_detection", "listing", "for_incident", "held_incident_ids", "get"):
        monkeypatch.setattr(threat_windows, name, never)

    def ev(payload: dict, at: str, severity: str = "high") -> CanonicalEvent:
        return CanonicalEvent(
            vendor_event_id=str(payload.get("n")), received_at=at, severity=severity,
            summary="s", source_host="ws-01", payload=payload, indicator=None,
            indicator_type=None,
            payload_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()
                                          ).hexdigest())

    sink = SqliteIngestSink(root, publish_to_stream=False, clock=lambda: iso(NOW))
    signals = [sink.ingest(A, "wazuh", ev({"n": i}, iso(NOW - timedelta(minutes=i))),
                           event_type="wazuh.alert") for i in range(50)]
    dns = [sink.ingest(A, "buoy:acme", ev(pihole_payload(2, n=i), iso(NOW), "info"),
                       event_type="pihole.query", dedup=False) for i in range(50)]
    assert all(not o.duplicate for o in signals) and len({o.event_id for o in signals}) == 50
    assert all(o.tier == "telemetry" for o in dns)
    assert {o.event_id for o in signals} <= _ids(root, A, "events", "events")
    assert {o.event_id for o in dns} <= _ids(root, A, "telemetry", "telemetry_raw")


# ---------------------------------------------------------------------------
# The write lock: a delete batch never re-examines what a window keeps
# ---------------------------------------------------------------------------

def _locked_work(monkeypatch) -> dict:
    """Every connection the job's deletes (and the entity prune) open counts
    the SQLite VM steps it runs INSIDE an explicit write transaction — what
    ingest waits on. Returns {"<tenant>/<file>": [steps per transaction]}."""
    from pathlib import Path

    from apps.octo.entity import retention as entity_retention
    from apps.octo.retention import job as job_mod

    work: dict = {}

    def wrap(module) -> None:
        real = module._connect

        def connect(path, *a, **kw):
            conn = real(path, *a, **kw)
            name = f"{Path(path).parent.name}/{Path(path).name}"
            state = {"in": False, "n": 0}

            def trace(sql: str) -> None:
                head = sql.lstrip().upper()
                if head.startswith("BEGIN"):
                    state.update({"in": True, "n": 0})
                elif head.startswith(("COMMIT", "ROLLBACK")) and state["in"]:
                    work.setdefault(name, []).append(state["n"])
                    state["in"] = False

            def progress() -> int:
                if state["in"]:
                    state["n"] += 1
                return 0

            conn.set_trace_callback(trace)
            conn.set_progress_handler(progress, 20)
            return conn

        monkeypatch.setattr(module, "_connect", connect)

    wrap(job_mod)
    wrap(entity_retention)
    return work


def _kept_then_deletable(root, slug: str, kept: int, deletable: int = 30) -> None:
    """On one long-expired day: `kept` rows inside a held (manual) window
    from 00:00 to 06:00 — OLDER than the `deletable` rows outside it (12:00
    on), so every scan meets them first — in events, raw telemetry (and so
    its hourly roll-up and the first-seen ledger) and an entity table."""
    from apps.octo.entity import db as entity_db
    from apps.octo.tests._tiering_fixtures import insert_events_many, write_telemetry_many
    from apps.octo.threat import store

    day = (NOW - timedelta(days=AFTER)).replace(hour=0, minute=0, second=0, microsecond=0)
    inc = store.open_incident(slug, tier="black", rule_id="B6", rule_version=1,
                              key=f"{slug}|tenant|analyst|", summary="declared", scope="tenant",
                              opened_by="7", reason="the client called", now=NOW).incident
    store.add_window(slug, inc.id, start=iso(day), end=iso(day + timedelta(hours=6)), by="1",
                     reason="claim CL-0009", now=NOW)
    at = ([iso(day + timedelta(hours=3, seconds=i)) for i in range(kept)]
          + [iso(day + timedelta(hours=12, seconds=i)) for i in range(deletable)])
    insert_events_many(root, slug, [(t, {"n": i}) for i, t in enumerate(at)])
    write_telemetry_many(root, slug, [
        {"received_at": t, "domain": f"d{i}.example.test", "n": i, "payload": f'{{"n":{i}}}'}
        for i, t in enumerate(at)])
    path = db(root, slug, "entities")
    entity_db.ensure_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.executemany("INSERT INTO lk_join (site_id, vendor_scope_id, event, at, "
                         "vendor_event_id) VALUES ('st_A', 's', 'join', ?, ?)",
                         [(t, f"j-{i}") for i, t in enumerate(at)])
        conn.commit()
    finally:
        conn.close()


def test_a_delete_batch_never_re_examines_what_a_window_keeps(root, monkeypatch):
    """Rows a window keeps lie BEFORE the deletable ones (they are older):
    a batch used to walk past every one of them again, under the write lock
    — kept rows × batches — so ingest waited longer the longer a window was
    held. Now the keys are picked OUTSIDE the lock (keyset: each kept row is
    passed over once a run) and a batch under the lock touches only what it
    deletes: the same work per batch with 20 kept rows as with 600."""
    small, big = 20, 600
    _kept_then_deletable(root, A, small)
    _kept_then_deletable(root, B, big)
    work = _locked_work(monkeypatch)
    report = _job(root, batch_size=5).run()
    assert report.status == "ok", report.as_dict()
    for slug, kept in ((A, small), (B, big)):
        t = next(t for t in report.tenants if t.slug == slug)
        assert t.classes["events"].deleted == 30 and t.classes["events"].evidence == kept
        assert t.classes["telemetry_raw"].deleted == 30
        assert t.classes["telemetry_raw"].evidence == kept
        assert t.classes["entity_lookup_lease"].deleted == 30
        assert rows(db(root, slug, "events"),
                    "SELECT COUNT(*) FROM events WHERE source = 'wazuh'")[0][0] == kept
        assert len(_ids(root, slug, "telemetry", "telemetry_raw")) == kept
        assert len(_ids(root, slug, "telemetry", "telemetry_hourly", "domain")) == kept
    for name in ("events.db", "telemetry.db", "entities.db"):
        few, many = max(work[f"{A}/{name}"]), max(work[f"{B}/{name}"])
        # 30× the kept rows; the work under the lock stays the same (the old
        # statement's grew with them, ~30×).
        assert many <= few * 1.5 + 10, (name, few, many)


# ---------------------------------------------------------------------------
# Windows a 044 rollback parked
# ---------------------------------------------------------------------------

def _roll_back_044(root, slug: str) -> None:
    from apps.octo.migration import apply_migration, list_migrations

    back = next(m for m in list_migrations(kind="rollback") if m.number == 44)
    conn = sqlite3.connect(db(root, slug, "events"), isolation_level=None)
    try:
        apply_migration(conn, back, target="events")
    finally:
        conn.close()


def test_windows_a_rollback_parked_still_hold_until_044_is_back(root):
    """A 044 rollback moves the windows aside (with their ids); a re-upgrade
    puts them back only when 044 reaches the tenant's events.db again —
    lazily, and the tier worker only reaches ACTIVE tenants. Meanwhile every
    prune path honours the parked windows exactly like live ones; at startup
    every tenant holding parked windows gets 044 again, whatever its status,
    so the console lists them and an admin can release them."""
    from apps.octo.threat import store

    _inc, w, trigger = _closed_window(A)
    s = _seed(root, A)
    _roll_back_044(root, A)
    conn = sqlite3.connect(db(root, A, "events"))
    try:
        assert not evidence.live(conn)                       # the live table is gone
    finally:
        conn.close()
    assert [x.id for x in evidence.held(root / "clients" / A)] == [w.id]
    store.reset_schema_cache()
    assert store.evidence_windows(A) == []                   # not shown before 044 is back

    report = _job(root).run()
    assert report.status == "ok", report.as_dict()
    left = _ids(root, A, "events", "events")
    assert {s["event_in"], s["event_late"], trigger} <= left
    assert not {s["event_before"], s["event_after"]} & left
    assert _ids(root, A, "telemetry", "telemetry_raw") == {s["raw_in"]}
    assert _ids(root, A, "events", "agent_notes") == {s["note_in"]}
    for table in ENTITY_TABLES:
        assert _entity_count(root, A, table) == 1, table

    # Startup: 044 again for the tenant — the window is back where it was.
    assert store.restore_parked_windows() == [A]
    (back,) = store.evidence_windows(A, state="held")
    assert (back.id, back.start, back.end) == (w.id, w.start, w.end)
    assert store.restore_parked_windows() == []               # nothing parked any more


def test_the_sweep_honours_parked_windows_too(root):
    from apps.octo.threat import store

    store.open_incident(A, tier="red", rule_id="R8", rule_version=1, key=f"{A}|ws-01|analyst|",
                        summary="confirmed", scope="device", opened_by="7", reason="x" * 20,
                        now=NOW - timedelta(days=2))
    inside = _event(A, ago(days=1), pihole_payload(2), event_type="pihole.query")
    outside = _event(A, ago(days=4), pihole_payload(2, n=3), event_type="pihole.query")
    _roll_back_044(root, A)
    t = next(t for t in _job(root).run().tenants if t.slug == A)
    assert t.sweep["moved"] == 1 and t.sweep["kept_evidence"] == 1
    assert inside in _ids(root, A, "events", "events")
    assert outside not in _ids(root, A, "events", "events")


# ---------------------------------------------------------------------------
# An events.db stored before 036 (no arrival column yet)
# ---------------------------------------------------------------------------

def test_the_arrival_backfill_runs_on_a_pre_036_store_that_holds_a_window(root):
    """A pre-036 events.db (no `ingested_at` yet — its backfill pending) that
    got 044's tables (the tier worker's lazy migration): the move / backfill
    matches the windows on the vendor time alone and never fails on the
    missing column — the backfill that adds it finishes, in-window rows
    stay."""
    from apps.octo.retention.move import move_tenant
    from apps.octo.tests._tiering_fixtures import insert_event as raw_insert
    from apps.octo.threat import store

    trigger = _event(A, ago(days=2), {"trigger": 1})
    store.open_incident(A, tier="red", rule_id="R8", rule_version=1, key=f"{A}|ws-01|analyst|",
                        summary="confirmed", scope="device", opened_by="7", reason="x" * 20,
                        event_ids=[trigger], now=NOW - timedelta(days=1))
    inside = raw_insert(root, A, event_type="pihole.query", payload=pihole_payload(2),
                        received_at=ago(days=1), stamped=False)
    outside = raw_insert(root, A, event_type="pihole.query", payload=pihole_payload(2, n=3),
                         received_at=ago(days=4), stamped=False)
    conn = sqlite3.connect(db(root, A, "events"))
    try:
        conn.execute("DROP INDEX idx_events_ingested_at")
        conn.execute("ALTER TABLE events DROP COLUMN ingested_at")
        conn.commit()
    finally:
        conn.close()
    dry = move_tenant(A, data_root=root, dry_run=True, now=iso(NOW))
    assert dry.error is None and dry.kept_evidence == 1, dry.as_dict()
    report = move_tenant(A, data_root=root, dry_run=False, now=iso(NOW))
    assert report.error is None and report.arrival_error is None, report.as_dict()
    assert report.moved == 1 and report.kept_evidence == 1
    left = _ids(root, A, "events", "events")
    assert inside in left and outside not in left
    conn = sqlite3.connect(db(root, A, "events"))
    try:                                                     # the backfill finished
        assert conn.execute("SELECT COUNT(*) FROM events WHERE ingested_at IS NULL"
                            ).fetchone()[0] == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The sweep comes back for what a window kept, once it is released
# ---------------------------------------------------------------------------

def test_a_row_the_sweep_kept_for_a_window_moves_once_the_window_is_released(root):
    """The sweep resumes from where it stopped — but never past a row a
    window kept: released, the row is moved after all (and ages as raw
    telemetry) instead of staying in events.db for the events' 365 days."""
    from apps.octo.threat import store

    inc = store.open_incident(A, tier="red", rule_id="R8", rule_version=1,
                              key=f"{A}|ws-01|analyst|", summary="confirmed", scope="device",
                              opened_by="7", reason="x" * 20,
                              now=NOW - timedelta(days=2)).incident
    inside = _event(A, ago(days=1), pihole_payload(2), event_type="pihole.query")
    first = next(t for t in _job(root).run().tenants if t.slug == A)
    assert first.sweep["kept_evidence"] == 1 and first.sweep["evidence_min_id"] == inside
    assert inside in _ids(root, A, "events", "events")
    # Still held: the next run keeps it again (its resume point did not pass it).
    again = next(t for t in _job(root).run().tenants if t.slug == A)
    assert again.sweep["kept_evidence"] == 1
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW - timedelta(hours=2))
    (w,) = store.evidence_windows(A, incident_id=inc.id)
    store.release_window(A, inc.id, w.id, by="1", reason="nothing to keep", now=NOW)
    after = next(t for t in _job(root).run().tenants if t.slug == A)
    assert after.sweep["moved"] == 1 and after.sweep["kept_evidence"] == 0
    assert inside not in _ids(root, A, "events", "events")
    assert rows(db(root, A, "telemetry"), "SELECT origin_event_id FROM telemetry_raw") == \
        [(inside,)]


# ---------------------------------------------------------------------------
# Held windows never fill the disk unseen
# ---------------------------------------------------------------------------

def test_the_admins_are_told_when_held_windows_keep_data_on_a_filling_disk(root, monkeypatch):
    """A window never expires — so the nightly run tells the tenant's admins
    (it never releases anything): daily while the data volume runs low and a
    window keeps rows past their retention; weekly about windows held long
    after their all-clear."""
    from collections import namedtuple

    from apps.octo.retention import job as job_mod
    from apps.octo.threat import notify, store

    _inc, w, _trigger = _closed_window(A)                     # ended 2300 days ago
    _seed(root, A)
    sent: list = []
    monkeypatch.setattr(notify, "notify_admins", lambda **kw: sent.append(kw))
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(job_mod.shutil, "disk_usage", lambda _p: usage(100, 92, 8))
    report = _job(root).run()
    by = {n["kind"]: n for n in report.evidence_notices}
    assert set(by) == {"disk", "held"} and by["disk"]["windows"] == [w.id]
    assert by["disk"]["request_id"] == f"evw-disk:{A}:{iso(NOW)[:10]}"   # once a day
    assert by["held"]["request_id"].startswith(f"evw-held:{A}:")          # once a week
    (disk,) = [kw for kw in sent if kw["request_id"].startswith("evw-disk")]
    assert disk["slug"] == A and "8% free" in disk["title"]
    assert f"window #{w.id}" in disk["body"] and "Nothing is released" in disk["body"]
    assert {n["tenant"] for n in report.evidence_notices} == {A}          # B holds none
    # Plenty of room: only the weekly reminder — and the window is still held.
    monkeypatch.setattr(job_mod.shutil, "disk_usage", lambda _p: usage(100, 40, 60))
    report = _job(root).run()
    assert [n["kind"] for n in report.evidence_notices] == ["held"]
    assert store.evidence_windows(A, state="held")[0].id == w.id
