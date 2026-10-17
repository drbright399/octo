"""The incident record's guarantees (migration 044's triggers and the store
on top): never deleted, what it was opened on is frozen, a Black is never
lowered in place, one OPEN incident per dedupe key, the same key within 14
days of a close reopens it — unless an analyst verdict blocks the key — and
an events.db made before 044 gets the schema on first use."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.threat import registry, store
from apps.octo.threat.tests.conftest import A

NOW = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)


def _open(key: str = "acme-corp|ws-01|analyst|", tier: str = "red", at: datetime = NOW,
          **kw) -> store.Opened:
    return store.open_incident(A, tier=tier, rule_id="R8" if tier == "red" else "B6",
                               rule_version=1, key=key, summary="confirmed threat",
                               scope="device", opened_by="7", reason="seen by alice",
                               device_ref="ws-01", now=at, **kw)


def _raw() -> sqlite3.Connection:
    store.ensure_schema(A)
    return sqlite3.connect(paths.client_dir(A) / "events.db", isolation_level=None)


def test_an_incident_is_never_deleted(troot):
    inc = _open(event_ids=[1]).incident
    conn = _raw()
    try:
        with pytest.raises(sqlite3.DatabaseError, match="never deleted"):
            conn.execute("DELETE FROM incidents WHERE id = ?", (inc.id,))
        with pytest.raises(sqlite3.DatabaseError, match="never deleted"):
            conn.execute("DELETE FROM incident_events")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM incident_notes")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("UPDATE incident_notes SET text = 'rewritten'")
    finally:
        conn.close()


@pytest.mark.parametrize("column,value", [
    ("detected_at", "2020-01-01T00:00:00.000Z"),
    ("rule_id", "R6"),
    ("snapshot_sha256", "0" * 64),
    ("evidence_refs", "{}"),
])
def test_what_it_was_opened_on_is_frozen(troot, column, value):
    inc = _open().incident
    assert inc.snapshot_sha256 and inc.evidence["rule"] == "R8@1"
    conn = _raw()
    try:
        with pytest.raises(sqlite3.DatabaseError, match="frozen"):
            conn.execute(f"UPDATE incidents SET {column} = ? WHERE id = ?", (value, inc.id))
        # Everything else of the lifecycle may change.
        conn.execute("UPDATE incidents SET status = 'acknowledged' WHERE id = ?", (inc.id,))
    finally:
        conn.close()


def test_a_black_is_never_lowered_in_place(troot):
    inc = _open(tier="black").incident
    conn = _raw()
    try:
        with pytest.raises(sqlite3.DatabaseError, match="never lowered"):
            conn.execute("UPDATE incidents SET tier = 'red' WHERE id = ?", (inc.id,))
        with pytest.raises(sqlite3.DatabaseError, match="never lowered"):
            conn.execute("UPDATE incidents SET tier = NULL WHERE id = ?", (inc.id,))
        # Red → Black is a raise: allowed.
        red = _open(key="acme-corp|ws-02|analyst|").incident
        conn.execute("UPDATE incidents SET tier = 'black' WHERE id = ?", (red.id,))
    finally:
        conn.close()


def test_one_open_incident_per_dedupe_key(troot):
    first = _open()
    assert first.outcome == "opened"
    conn = _raw()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, "
                "evidence_refs, tier, rule_id, dedupe_key) VALUES ('high', '[]', '[]', 'x', "
                "'{}', 'red', 'R8', ?)", (first.incident.dedupe_key,))
    finally:
        conn.close()
    # The store appends instead; a Black on the same key RAISES the same
    # incident, its acknowledgement cleared and the ladder restarted.
    store.ack(A, first.incident.id, by="7", now=NOW + timedelta(minutes=1))
    again = _open(at=NOW + timedelta(minutes=2))
    assert again.outcome == "appended" and again.incident.id == first.incident.id
    raised = _open(tier="black", at=NOW + timedelta(minutes=3))
    assert raised.outcome == "raised" and raised.incident.id == first.incident.id
    assert raised.incident.tier == "black" and not raised.incident.acked
    assert raised.incident.ladder_started_at == "2026-10-03T15:03:00.000Z"
    assert raised.incident.escalation_step == 0


def test_the_same_key_within_14_days_of_a_close_reopens(troot):
    inc = _open().incident
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW)
    back = _open(at=NOW + timedelta(days=13))
    assert back.outcome == "reopened" and back.incident.id == inc.id
    assert back.incident.is_open and back.incident.reopened_count == 1
    assert back.incident.closed_at is None and not back.incident.acked
    store.close(A, inc.id, by="7", code="remediated", text="cleaned again",
                now=NOW + timedelta(days=13, hours=1))
    # Past 14 days: a NEW incident (the old one is history).
    fresh = _open(at=NOW + timedelta(days=28))
    assert fresh.outcome == "opened" and fresh.incident.id != inc.id


def _automated(key: str, at: datetime) -> store.Opened:
    return store.open_incident(A, tier="red", rule_id="R6", rule_version=1, key=key,
                               summary="credential tried on a decoy", scope="device",
                               opened_by=store.SYSTEM_ACTOR, device_ref="ip:192.0.2.9",
                               now=at)


def _verdict(key: str, rule_id: str, incident_id: int) -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            registry.add_verdict(reg, slug=A, device_ref="ws-01", key=key, rule_id=rule_id,
                                 incident_id=incident_id, reason="a printer", by=7, now=NOW)
    finally:
        reg.close()


def test_an_analyst_verdict_blocks_an_automated_rule_reopening_and_refiring(troot):
    key = "acme-corp|ip:192.0.2.9|deception|"
    inc = _automated(key, NOW).incident
    store.close(A, inc.id, by="7", code="false_positive", text="a printer's scan", now=NOW)
    _verdict(key, "R6", inc.id)
    blocked = _automated(key, NOW + timedelta(days=1))
    assert blocked.outcome == "blocked" and blocked.incident is None
    assert store.get(A, inc.id).status == "false_positive"
    # Another key is not blocked.
    assert _automated("acme-corp|ip:192.0.2.10|deception|",
                      NOW + timedelta(days=1)).outcome == "opened"


def test_a_verdict_never_blocks_a_persons_declaration(troot):
    """G10 blocks a RULE re-firing on its exact key. A person is always
    heard: the client calls ("someone is controlling my screen") weeks after
    a false-positive close on that device, and B6 opens — a verdict on the
    key (even one written on a human rule's record) changes nothing."""
    inc = _open(tier="black").incident
    store.close(A, inc.id, by="7", code="false_positive", text="the vendor's session",
                now=NOW)
    _verdict(inc.dedupe_key, "B6", inc.id)
    back = _open(tier="black", at=NOW + timedelta(days=3))
    assert back.incident is not None and back.outcome == "reopened"
    assert back.incident.tier == "black" and back.incident.is_open
    store.close(A, inc.id, by="7", code="false_positive", text="again the vendor",
                now=NOW + timedelta(days=3))
    fresh = _open(tier="black", at=NOW + timedelta(days=21))
    assert fresh.outcome == "opened" and fresh.incident.id != inc.id


def test_raising_a_contained_red_clears_its_containment(troot):
    """The attacker is back: the raised Black pulses again and tells the
    client nothing is contained."""
    red = _open().incident
    store.ack(A, red.id, by="7", now=NOW)
    store.contain(A, red.id, by="7", receipt="EDR isolation receipt 42", now=NOW)
    raised = _open(tier="black", at=NOW + timedelta(hours=2)).incident
    assert raised.tier == "black" and not raised.contained and raised.contained_by is None
    assert not raised.acked
    again = store.raise_to_black(A, _open(key="acme-corp|ws-07|analyst|").incident.id,
                                 by="7", reason="the client called back")
    assert not again.contained


def test_a_close_rechecks_the_tier_inside_its_write(troot):
    """The role checks were made for a Red; a raise to Black lands before
    the close's write: the close is refused, never applied by a Red's rules
    (an analyst, no step-up, no checklist)."""
    red = _open().incident
    store.raise_to_black(A, red.id, by="8", reason="the client called", now=NOW)
    with pytest.raises(store.Refused, match="BLACK"):
        store.close(A, red.id, by="7", code="remediated", text="cleaned",
                    expected_tier="red", now=NOW)
    assert store.get(A, red.id).is_open
    closed = store.close(A, red.id, by="7", code="remediated", text="cleaned",
                         expected_tier="black", now=NOW)
    assert closed.status == "closed"


def test_predict_names_what_an_open_will_do(troot):
    key = "acme-corp|ws-03|analyst|"
    assert store.predict(A, key, "red", NOW) == "open"
    inc = _open(key=key).incident
    assert store.predict(A, key, "red", NOW) == "append"
    assert store.predict(A, key, "black", NOW) == "raise"
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW)
    assert store.predict(A, key, "red", NOW + timedelta(days=2)) == "reopen"
    assert store.predict(A, key, "red", NOW + timedelta(days=20)) == "open"


def test_every_lifecycle_change_appends_its_ocsf_event(troot):
    """Design 6.3: the `incidents` row is the mutable projection; one
    `athena.incident` event per change (OCSF 2005, in the same transaction)
    is the immutable timeline — listed in `incident_signals`, so the
    retention job keeps every one."""
    import json as _json

    from apps.octo.retention import references

    inc = _open(event_ids=[5]).incident
    store.ack(A, inc.id, by="7", now=NOW)
    store.raise_to_black(A, inc.id, by="7", reason="the client called", now=NOW)
    store.close(A, inc.id, by="7", code="false_positive", text="the vendor's session",
                now=NOW)
    conn = _raw()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM events WHERE source = 'athena' ORDER BY id").fetchall()
        signals = conn.execute("SELECT * FROM incident_signals ORDER BY event_id").fetchall()
    finally:
        conn.close()
    assert [r["event_type"] for r in rows] == ["athena.incident"] * 4
    payloads = [_json.loads(r["payload"]) for r in rows]
    assert [p["athena"]["change"] for p in payloads] == ["open", "ack", "raise", "close"]
    assert [p["activity_id"] for p in payloads] == [1, 2, 2, 3]
    assert [p["severity_id"] for p in payloads] == [4, 4, 5, 5]
    assert [r["severity"] for r in rows] == ["high", "high", "critical", "critical"]
    assert payloads[0]["class_uid"] == 2005 and payloads[0]["is_suspected_breach"] is False
    assert payloads[2]["is_suspected_breach"] is True
    assert payloads[3]["verdict_id"] == 1 and payloads[3]["verdict"] == "False Positive"
    assert payloads[0]["finding_info"]["uid"] == "R8"
    assert payloads[0]["finding_info"]["related_events"] == [{"uid": "5"}]
    assert all(r["source_host"] == "ws-01" for r in rows)
    assert rows[2]["summary"].startswith("[black] raise:")
    assert [s["event_id"] for s in signals] == [r["id"] for r in rows]
    # Kept by retention (an incident is never deleted, nor its timeline).
    assert {r["id"] for r in rows} <= references.events_db_references(paths.client_dir(A))
    # The engine's own bookkeeping is audited, not an event.
    store.set_ladder(A, inc.id, step=3, at=NOW, note="paged: step 3")
    conn = _raw()
    try:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE source = 'athena'"
                            ).fetchone()[0] == 4
    finally:
        conn.close()


def test_a_manual_evidence_window_is_recorded_and_an_authorized_close_proposes_a_fact(troot):
    """The former legal hold: an admin's manual evidence window (explicit
    start, no end = held until released) lands on the timeline."""
    inc = _open().incident
    w = store.add_window(A, inc.id, start="2026-09-01T00:00:00Z", end=None, by="7",
                         reason="claim CL-0001", now=NOW)
    assert (w.kind, w.start, w.end, w.held) == ("manual", "2026-09-01T00:00:00.000Z", None, True)
    with pytest.raises(ValueError, match="future"):
        store.add_window(A, inc.id, start="2027-01-01T00:00:00Z", end=None, by="7",
                         reason="a claim from the future", now=NOW)
    assert any(n["kind"] == "evidence_window" and "claim CL-0001" in n["text"]
               for n in store.notes(A, inc.id))
    store.close(A, inc.id, by="7", code="authorized_activity",
                text="the vendor's scheduled maintenance", now=NOW)
    conn = _raw()
    conn.row_factory = sqlite3.Row
    try:
        (fact,) = conn.execute("SELECT * FROM threat_fact WHERE kind = "
                               "'authorized_activity_proposal'").fetchall()
    finally:
        conn.close()
    assert fact["incident_id"] == inc.id and fact["device_ref"] == "ws-01"
    assert "the vendor's scheduled maintenance" in fact["attrs"]


def test_only_a_person_closes_and_a_closed_incident_takes_no_lifecycle_step(troot):
    inc = _open().incident
    with pytest.raises(store.Refused, match="person"):
        store.close(A, inc.id, by=store.SYSTEM_ACTOR, code="remediated", text="auto")
    store.close(A, inc.id, by="7", code="duplicate", text="see #1", now=NOW)
    for step in (lambda: store.ack(A, inc.id, by="7"),
                 lambda: store.contain(A, inc.id, by="7", receipt="x"),
                 lambda: store.raise_to_black(A, inc.id, by="7", reason="x")):
        with pytest.raises(store.Refused):
            step()


def test_reclassify_closes_the_black_and_opens_a_linked_red(troot):
    black = _open(tier="black").incident
    closed, red = store.reclassify(A, black.id, by="7", reason="the screen share was ours",
                                   now=NOW)
    assert closed.tier == "black" and closed.status == "closed"
    assert closed.close_reason_code == "reclassified_red"
    assert red.tier == "red" and red.is_open and red.reclassified_from == black.id
    assert red.dedupe_key == black.dedupe_key


def test_an_events_db_made_before_044_gets_the_schema_on_first_use(troot):
    path = paths.client_dir(A) / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        # Roll the tenant's events.db back to before 044 (its section only).
        from apps.octo.migration import apply_migration, list_migrations

        rb = next(m for m in list_migrations(kind="rollback") if m.number == 44)
        if store.has_schema(conn):
            apply_migration(conn, rb, target="events")
        assert not store.has_schema(conn)
        conn.execute("INSERT INTO incidents (severity, indicator_ids, event_ids, summary, "
                     "evidence_refs) VALUES ('high', '[]', '[7]', 'legacy', '{}')")
    finally:
        conn.close()
    store.reset_schema_cache()
    with store.read(A) as ro:
        assert ro is None                         # a read never creates the schema
    assert store.ensure_schema(A) is True
    inc = _open().incident
    assert inc.id > 1
    # The legacy row is kept, untiered; the incidents' lists never show it.
    assert [i.id for i in store.list_incidents(A)] == [inc.id]
    assert store.ensure_schema("example-nobody") is False      # never provisioned


def test_the_retention_job_keeps_an_incidents_evidence(troot):
    from apps.octo.retention import references

    inc = _open(event_ids=[41]).incident
    conn = _raw()
    try:
        store.link_events(conn, inc.id, [42], "context", "2026-10-03T15:00:00.000Z")
    finally:
        conn.close()
    held = references.events_db_references(paths.client_dir(A))
    assert {41, 42} <= held


# ---------------------------------------------------------------------------
# Athena's own records in events.db stay Athena's
# ---------------------------------------------------------------------------

def test_the_triage_worker_never_triages_an_incidents_own_record(troot):
    from apps.octo.agent import worker
    from apps.octo.threat.tests.conftest import insert_event

    seen: list[int] = []

    def spy(features, row, slug):
        seen.append(int(row["id"]))
        return worker.heuristic_decide(features, row, slug)

    _open(tier="black")                                    # its athena.incident event
    vendor = insert_event(A, source="wazuh", event_type="wazuh.alert",
                          payload={"rule": {"level": 12}}, source_host="ws-01")
    worker.process_tenant_once(A, decide=spy, backfill=True)
    assert seen == [vendor]


def test_an_incidents_record_never_makes_a_dead_feed_read_fresh(troot):
    from apps.octo.instances import freshness

    _open()
    assert freshness.newest_stored_event(A) is None


def test_a_merge_leaves_an_incidents_record_with_its_incident(troot):
    from apps.octo.api.routers import admin_tenants
    from apps.octo.threat.tests.conftest import B, insert_event

    _open()
    vendor = insert_event(A, source="wazuh", event_type="wazuh.alert", payload={"n": 1})
    record = admin_tenants._CopiedEvents(B)
    copied, skipped = admin_tenants._copy_events(A, B, record)
    assert copied == 1 and skipped == 1                    # the vendor event; the record
    conn = sqlite3.connect(paths.client_dir(B) / "events.db")
    try:
        sources_ = [r[0] for r in conn.execute("SELECT source FROM events")]
    finally:
        conn.close()
    assert sources_ == ["wazuh"] and vendor
