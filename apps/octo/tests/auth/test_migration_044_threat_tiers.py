"""Migration 044 (Tier Black slice 1 — incident records, the threat
registries, the threat notices) — forward, rollback, forward again — and
scripts/rollback_v017.py, its one-command rollback.

Pins:
  - registry: asset_tag (cleared, never deleted; one live tag per asset),
    the registries and settings with no-delete triggers, rule_brake ≤ 24 h,
    threat_exception ≤ 90 d, attribution windows ≤ 8 h, operator_notices
    with the threat_* kinds; user_version 44;
  - events: incidents + the threat columns, the no-delete / frozen /
    no-lower triggers and the open-dedupe index; incident_events /
    incident_notes / incident_decisions / incident_signals / threat_fact /
    threat_would_fire; the `athena.incident` lifecycle events moved aside
    by a rollback (with their ids) and put back by a re-upgrade;
  - the rollback keeps the threat notices (operator_notices_rolled_back_044)
    and every incident's threat columns (incidents_threat_rolled_back_044),
    rebuilds operator_notices with 040's kinds, drops the incidents'
    columns, triggers and indexes, LEAVES the new tables, version 43;
  - re-applying restores both and spends what was kept;
  - rollback_v017: dry run by default, every events.db with the 044 columns
    then the registry, a root newer than 44 refused, nothing to do on a 43
    root; rollback_v016 refuses a 44 root until this ran.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.migration import apply_migration, list_migrations

SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
NEW_REGISTRY_TABLES = {"asset_tag", "remote_access_registry", "ra_baseline", "msp_roster",
                       "egress_set", "attribution_ledger", "threat_exception",
                       "analyst_verdict", "domain_intel", "canary_scanner_allowlist",
                       "tier_settings", "rule_brake", "threat_worker_state"}
NEW_EVENTS_TABLES = {"incident_events", "incident_notes", "incident_decisions", "threat_fact",
                     "threat_would_fire", "incident_signals"}
# Moved aside by a rollback (the incidents' 044 columns its triggers name go).
WINDOWS = "evidence_windows"


def _migration(number: int, kind: str = "forward"):
    return next(m for m in list_migrations(kind=kind) if m.number == number)


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _cols(conn, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "root"))
    bootstrap.init_data_root()
    create_client("acme-corp", "Acme Corp", kind="client")
    return tmp_path / "root"


def _notice(reg, kind: str) -> None:
    oid = reg.execute("INSERT INTO operators (username, email, token_hash, token_prefix) "
                      "VALUES ('alice', 'alice@example.test', 'h', 'p')").lastrowid
    reg.execute("INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, "
                "title, body, request_id) VALUES (?, ?, 0, 'acme-corp', 't', 'b', 'r1')",
                (oid, kind))


def test_044_targets_the_registry_and_events():
    for kind in ("forward", "rollback"):
        sql = _migration(44, kind).sql
        assert "-- @target: registry" in sql and "-- @target: events" in sql
        assert "-- @target: telemetry" not in sql and "-- @target: entities" not in sql


def test_registry_constraints(root):
    reg = connect(root / "registry.db")
    try:
        assert reg.execute("PRAGMA user_version").fetchone()[0] == 48   # v0.17.5 on top
        assert NEW_REGISTRY_TABLES <= _tables(reg)
        reg.execute("INSERT INTO asset_tag (tenant_slug, device_ref, tag, set_by, reason) "
                    "VALUES ('acme-corp', 'dispatch-01', 'life_safety', 7, '911 console')")
        with pytest.raises(sqlite3.IntegrityError):              # one live tag per asset
            reg.execute("INSERT INTO asset_tag (tenant_slug, device_ref, tag, set_by, reason) "
                        "VALUES ('acme-corp', 'dispatch-01', 'life_safety', 7, 'again')")
        with pytest.raises(sqlite3.IntegrityError):
            reg.execute("INSERT INTO asset_tag (tenant_slug, device_ref, tag, set_by, reason) "
                        "VALUES ('acme-corp', 'x', 'invented', 7, 'abc')")
        with pytest.raises(sqlite3.DatabaseError, match="cleared, never deleted"):
            reg.execute("DELETE FROM asset_tag")
        with pytest.raises(sqlite3.DatabaseError, match="only ever cleared"):
            reg.execute("UPDATE asset_tag SET tag = 'lab'")
        reg.execute("UPDATE asset_tag SET cleared_by = 8, cleared_at = 'x', "
                    "clear_reason = 'decommissioned'")
        with pytest.raises(sqlite3.IntegrityError):              # > 90 days
            reg.execute("INSERT INTO threat_exception (tenant_slug, binding_kind, binding, "
                        "rule_id, reason, created_by, created_at, expires_at) VALUES "
                        "('acme-corp', 'path_prefix', 'C:\\\\ExampleLOB\\\\', 'R2', 'lob', 1, "
                        "'2026-10-01T00:00:00Z', '2027-01-15T00:00:00Z')")
        with pytest.raises(sqlite3.IntegrityError):              # a window > 8 h
            reg.execute("INSERT INTO attribution_ledger (kind, tenant_slug, actor, reason, "
                        "created_by, window_start, window_end) VALUES ('window', 'acme-corp', "
                        "'alice', 'maintenance', 'alice', '2026-10-03T00:00:00Z', "
                        "'2026-10-03T09:00:00Z')")
        for table in ("tier_settings", "rule_brake", "analyst_verdict", "msp_roster"):
            assert reg.execute("SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND "
                               "tbl_name = ? AND name LIKE '%no_delete'",
                               (table,)).fetchone(), table
        _notice(reg, "threat_black")
    finally:
        reg.close()


def test_registry_forward_rollback_forward(root):
    reg = connect(root / "registry.db")
    try:
        _notice(reg, "threat_black")
        reg.execute("INSERT INTO tier_settings (scope, key, value_json, updated_by) "
                    "VALUES ('msp', 'watch_days', '14', 1)")
        fwd, back = _migration(44), _migration(44, "rollback")
        apply_migration(reg, back, target="registry")
        assert reg.execute("PRAGMA user_version").fetchone()[0] == 43
        assert NEW_REGISTRY_TABLES <= _tables(reg)               # left as they are
        assert reg.execute("SELECT COUNT(*) FROM operator_notices").fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError):              # 040's kinds again
            reg.execute("INSERT INTO operator_notices (recipient_id, kind, actor_id, "
                        "subject_slug, title, body, request_id) VALUES (1, 'threat_red', 0, "
                        "'x', 't', 'b', 'r')")
        apply_migration(reg, fwd, target="registry")
        assert reg.execute("PRAGMA user_version").fetchone()[0] == 44
        assert [r[0] for r in reg.execute("SELECT kind FROM operator_notices")] == \
            ["threat_black"]
        assert reg.execute("SELECT COUNT(*) FROM operator_notices_rolled_back_044"
                           ).fetchone()[0] == 0                   # spent
        assert reg.execute("SELECT value_json FROM tier_settings").fetchone()[0] == "14"
    finally:
        reg.close()


def test_events_forward_rollback_forward(root):
    path = root / "clients" / "acme-corp" / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        assert "tier" in _cols(conn, "incidents") and NEW_EVENTS_TABLES <= _tables(conn)
        assert "legal_hold" not in _cols(conn, "incidents")       # evidence windows instead
        conn.execute("INSERT INTO incidents (severity, indicator_ids, event_ids, summary, "
                     "evidence_refs, tier, rule_id, rule_version, dedupe_key, "
                     "snapshot_sha256, stages, reopened_count) VALUES ('critical', '[]', '[5]', "
                     "'x', '{}', 'black', 'B6', 1, 'acme-corp|ws-01|analyst|', 'abc', "
                     "'[{\"kind\":\"open\"}]', 1)")
        fwd, back = _migration(44), _migration(44, "rollback")
        apply_migration(conn, back, target="events")
        assert "tier" not in _cols(conn, "incidents")
        assert NEW_EVENTS_TABLES <= _tables(conn)                # left as they are
        conn.execute("DELETE FROM incidents")                     # 002's table: no trigger
        conn.execute("INSERT INTO incidents (id, severity, indicator_ids, event_ids, summary, "
                     "evidence_refs) VALUES (1, 'critical', '[]', '[5]', 'x', '{}')")
        apply_migration(conn, fwd, target="events")
        row = conn.execute("SELECT tier, rule_id, dedupe_key, snapshot_sha256, stages, "
                           "reopened_count FROM incidents").fetchone()
        assert row == ("black", "B6", "acme-corp|ws-01|analyst|", "abc",
                       '[{"kind":"open"}]', 1)
        assert conn.execute("SELECT COUNT(*) FROM incidents_threat_rolled_back_044"
                            ).fetchone()[0] == 0
        with pytest.raises(sqlite3.DatabaseError, match="never deleted"):
            conn.execute("DELETE FROM incidents")
    finally:
        conn.close()


def test_the_lifecycle_events_go_aside_and_come_back_with_their_ids(root):
    """The `athena.incident` events (design 6.3): a release before 044 does
    not know them as Athena's own (its search would hand them to a client
    user) — a rollback moves them aside WITH THEIR IDS (what
    `incident_signals` cites) and a re-upgrade puts them back."""
    path = root / "clients" / "acme-corp" / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.execute("INSERT INTO events (received_at, source, source_host, event_type, "
                     "severity, payload, payload_sha256) VALUES ('2026-10-03T12:00:00.000Z', "
                     "'wazuh', 'ws-01', 'wazuh.alert', 'high', '{}', 'v1')")
        own = conn.execute("INSERT INTO events (received_at, source, source_host, event_type, "
                           "severity, payload, payload_sha256, relay_status) VALUES "
                           "('2026-10-03T12:01:00.000Z', 'athena', 'ws-01', "
                           "'athena.incident', 'critical', '{\"class_uid\":2005}', 'a1', "
                           "'skipped')").lastrowid
        conn.execute("INSERT INTO incident_signals (incident_id, event_id, change) "
                     "VALUES (1, ?, 'open')", (own,))
        fwd, back = _migration(44), _migration(44, "rollback")
        apply_migration(conn, back, target="events")
        assert [r[0] for r in conn.execute("SELECT source FROM events")] == ["wazuh"]
        assert conn.execute("SELECT id FROM events_athena_rolled_back_044").fetchall() == \
            [(own,)]
        apply_migration(conn, fwd, target="events")
        assert conn.execute("SELECT id, source, event_type, payload FROM events "
                            "WHERE source = 'athena'").fetchall() == \
            [(own, "athena", "athena.incident", '{"class_uid":2005}')]
        assert conn.execute("SELECT COUNT(*) FROM events_athena_rolled_back_044"
                            ).fetchone()[0] == 0                   # spent
        assert conn.execute("SELECT event_id FROM incident_signals").fetchall() == [(own,)]
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute("DELETE FROM incident_signals")
    finally:
        conn.close()


def _incident(conn, *, status: str = "open", closed_at=None, reclassified_from=None) -> int:
    n = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    return conn.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs, "
        "tier, rule_id, rule_version, dedupe_key, status, closed_at, reclassified_from) "
        "VALUES ('critical', '[]', '[]', 'x', '{}', 'black', 'B6', 1, ?, ?, ?, ?)",
        (f"acme-corp|ws-{n}|analyst|", status, closed_at, reclassified_from)).lastrowid


def _window(conn, incident_id: int, *, kind: str = "incident", start="2026-10-01T00:00:00.000Z",
            end=None) -> int:
    return conn.execute(
        "INSERT INTO evidence_windows (incident_id, origin_incident_id, kind, start_at, end_at, "
        "opened_by, opened_at, reason) VALUES (?, ?, ?, ?, ?, '7', '2026-10-02T00:00:00.000Z', "
        "'a confirmed threat')", (incident_id, incident_id, kind, start, end)).lastrowid


def test_evidence_windows_never_shrink_and_are_released_never_deleted(root):
    """Rick, 2026-10-05: first detection → the all-clear is evidence, kept
    until an admin releases it. Under the code, the triggers: never deleted;
    a start only earlier, an end only later; an open window ends only at its
    incident's all-clear (and then at that close's time); released only
    after the all-clear; a released window is frozen; it moves only to the
    Red its Black was reclassified to."""
    path = root / "clients" / "acme-corp" / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        assert WINDOWS in _tables(conn)
        iid = _incident(conn)
        wid = _window(conn, iid)
        with pytest.raises(sqlite3.IntegrityError):              # the end before the start
            _window(conn, iid, kind="manual", end="2026-09-01T00:00:00.000Z")
        with pytest.raises(sqlite3.IntegrityError):              # one automatic per incident
            _window(conn, iid)
        with pytest.raises(sqlite3.DatabaseError, match="released, never deleted"):
            conn.execute("DELETE FROM evidence_windows")
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks"):
            conn.execute("UPDATE evidence_windows SET start_at = '2026-10-01T00:00:01.000Z'")
        conn.execute("UPDATE evidence_windows SET start_at = '2026-09-20T00:00:00.000Z'")
        with pytest.raises(sqlite3.DatabaseError, match="all-clear"):     # still open
            conn.execute("UPDATE evidence_windows SET end_at = '2026-10-03T00:00:00.000Z'")
        with pytest.raises(sqlite3.DatabaseError, match="all-clear"):     # still open
            conn.execute("UPDATE evidence_windows SET released_at = 'x', released_by = '1', "
                         "release_reason = 'the claim is settled'")
        with pytest.raises(sqlite3.DatabaseError, match="frozen"):
            conn.execute("UPDATE evidence_windows SET reason = 'something else'")
        conn.execute("UPDATE incidents SET status = 'closed', "
                     "closed_at = '2026-10-04T00:00:00.000Z' WHERE id = ?", (iid,))
        with pytest.raises(sqlite3.DatabaseError, match="all-clear"):     # not ITS close time
            conn.execute("UPDATE evidence_windows SET end_at = '2026-10-03T00:00:00.000Z'")
        conn.execute("UPDATE evidence_windows SET end_at = '2026-10-04T00:00:00.000Z'")
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks"):
            conn.execute("UPDATE evidence_windows SET end_at = '2026-10-03T00:00:00.000Z'")
        conn.execute("UPDATE evidence_windows SET end_at = '2026-10-06T00:00:00.000Z'")
        # A manual window without an end is held open until released: no end
        # is ever written to it.
        mid = _window(conn, iid, kind="manual", start="2026-08-01T00:00:00.000Z")
        with pytest.raises(sqlite3.DatabaseError, match="all-clear"):
            conn.execute("UPDATE evidence_windows SET end_at = '2026-10-04T00:00:00.000Z' "
                         "WHERE id = ?", (mid,))
        # Moves only to its reclassified Red.
        other = _incident(conn, status="open")
        with pytest.raises(sqlite3.DatabaseError, match="reclassified Red"):
            conn.execute("UPDATE evidence_windows SET incident_id = ? WHERE id = ?",
                         (other, wid))
        red = _incident(conn, status="open", reclassified_from=iid)
        conn.execute("UPDATE evidence_windows SET incident_id = ? WHERE id = ?", (red, mid))
        with pytest.raises(sqlite3.IntegrityError):              # a release needs who + why
            conn.execute("UPDATE evidence_windows SET released_at = 'x' WHERE id = ?", (wid,))
        conn.execute("UPDATE evidence_windows SET released_at = '2026-10-07T00:00:00.000Z', "
                     "released_by = '1', release_reason = 'the claim is settled' WHERE id = ?",
                     (wid,))
        with pytest.raises(sqlite3.DatabaseError, match="frozen"):
            conn.execute("UPDATE evidence_windows SET start_at = '2026-01-01T00:00:00.000Z' "
                         "WHERE id = ?", (wid,))
        with pytest.raises(sqlite3.DatabaseError, match="all-clear"):     # its Red is open
            conn.execute("UPDATE evidence_windows SET released_at = 'x', released_by = '1', "
                         "release_reason = 'not yet' WHERE id = ?", (mid,))
    finally:
        conn.close()


def test_a_rollback_keeps_the_evidence_windows_aside_and_a_re_upgrade_puts_them_back(root):
    path = root / "clients" / "acme-corp" / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        iid = _incident(conn)
        wid = _window(conn, iid)
        conn.execute("UPDATE evidence_windows SET kept_rows = 12 WHERE id = ?", (wid,))
        held = conn.execute("SELECT * FROM evidence_windows").fetchall()
        fwd, back = _migration(44), _migration(44, "rollback")
        apply_migration(conn, back, target="events")
        assert WINDOWS not in _tables(conn)                       # aside, not read by v0.16
        assert conn.execute("SELECT * FROM evidence_windows_rolled_back_044").fetchall() == held
        conn.execute("DELETE FROM incidents")                     # 002's table again
        conn.execute("INSERT INTO incidents (id, severity, indicator_ids, event_ids, summary, "
                     "evidence_refs) VALUES (?, 'critical', '[]', '[]', 'x', '{}')", (iid,))
        apply_migration(conn, fwd, target="events")
        assert conn.execute("SELECT * FROM evidence_windows").fetchall() == held
        assert conn.execute("SELECT COUNT(*) FROM evidence_windows_rolled_back_044"
                            ).fetchone()[0] == 0                   # spent
        with pytest.raises(sqlite3.DatabaseError, match="never deleted"):
            conn.execute("DELETE FROM evidence_windows")          # the triggers are back
        # The next window's id never reuses a kept one.
        assert _window(conn, iid, kind="manual") > wid
        # A second rollback keeps them again (both).
        apply_migration(conn, back, target="events")
        assert conn.execute("SELECT COUNT(*) FROM evidence_windows_rolled_back_044"
                            ).fetchone()[0] == 2
    finally:
        conn.close()


def test_a_reopened_window_keeps_its_end_as_a_floor(root):
    """The end a window had (its close, an admin's extension past it) is its
    floor (`min_end_at`) once a reopen opens it again: the next all-clear
    never ends it earlier, and the floor itself never comes down."""
    path = root / "clients" / "acme-corp" / "events.db"
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        iid = _incident(conn)
        wid = _window(conn, iid)
        conn.execute("UPDATE incidents SET status = 'closed', "
                     "closed_at = '2026-10-04T00:00:00.000Z' WHERE id = ?", (iid,))
        conn.execute("UPDATE evidence_windows SET end_at = '2026-10-04T00:00:00.000Z'")
        conn.execute("UPDATE evidence_windows SET end_at = '2026-11-01T00:00:00.000Z'")  # admin
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks"):  # no floor kept
            conn.execute("UPDATE evidence_windows SET end_at = NULL")
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks"):  # a lower floor
            conn.execute("UPDATE evidence_windows SET end_at = NULL, "
                         "min_end_at = '2026-10-04T00:00:00.000Z'")
        conn.execute("UPDATE evidence_windows SET end_at = NULL, "
                     "min_end_at = '2026-11-01T00:00:00.000Z'")                  # the reopen
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks"):
            conn.execute("UPDATE evidence_windows SET min_end_at = '2026-10-05T00:00:00.000Z'")
        conn.execute("UPDATE incidents SET closed_at = '2026-10-07T00:00:00.000Z' "
                     "WHERE id = ?", (iid,))                                       # closed again
        with pytest.raises(sqlite3.DatabaseError, match="never shrinks|all-clear"):
            conn.execute("UPDATE evidence_windows SET end_at = '2026-10-07T00:00:00.000Z'")
        conn.execute("UPDATE evidence_windows SET end_at = '2026-11-01T00:00:00.000Z'")
        assert conn.execute("SELECT end_at, min_end_at FROM evidence_windows WHERE id = ?",
                            (wid,)).fetchone() == ("2026-11-01T00:00:00.000Z",
                                                   "2026-11-01T00:00:00.000Z")
    finally:
        conn.close()


def test_rollback_v017_refuses_while_evidence_windows_are_held(root, capsys, monkeypatch):
    """v0.16 prunes by the clock alone: --apply with a window held is
    refused unless retention is OFF in this environment AND a person says
    why (`--accept-unprotected-evidence`) — nothing is written until then."""
    events = root / "clients" / "acme-corp" / "events.db"
    ev = sqlite3.connect(events, isolation_level=None)
    try:
        held = _window(ev, _incident(ev), start="2026-09-30T08:00:00.000Z")
    finally:
        ev.close()
    # v0.17.5 (048), v0.17.3 (047) and v0.17.2 (046) sit on top: rolled back
    # first.
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0173").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0172").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    mod = _script("rollback_v017")
    monkeypatch.delenv("OCTO_RETENTION_SCHEDULE", raising=False)
    assert mod.main(["--data-root", str(root), "--apply"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is False and "--accept-unprotected-evidence" in out["refused"]
    assert [w["window"] for w in out["held_windows"]] == [held]
    monkeypatch.setenv("OCTO_RETENTION_SCHEDULE", "1")
    assert mod.main(["--data-root", str(root), "--apply", "--accept-unprotected-evidence",
                     "Rick: the window is copied off-box"]) == 1
    assert "OCTO_RETENTION_SCHEDULE" in json.loads(capsys.readouterr().out)["refused"]
    monkeypatch.delenv("OCTO_RETENTION_SCHEDULE")
    assert mod.main(["--data-root", str(root), "--apply", "--accept-unprotected-evidence",
                     "short"]) == 1                                      # a real reason
    capsys.readouterr()
    ev = sqlite3.connect(events)
    try:                                                     # nothing written so far
        assert "tier" in _cols(ev, "incidents") and WINDOWS in _tables(ev)
    finally:
        ev.close()
    assert mod.main(["--data-root", str(root), "--apply", "--accept-unprotected-evidence",
                     "Rick: the window is copied off-box"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["applied"] is True and out["failed"] == []
    assert out["accepted_unprotected_evidence"] == "Rick: the window is copied off-box"
    # Rolled back, the parked window is still listed (still unprotected on v0.16).
    assert mod.main(["--data-root", str(root)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [w["window"] for w in out["held_windows"]] == [held] and out["steps"] == []


def test_rollback_v017_script(root, capsys, monkeypatch):
    monkeypatch.delenv("OCTO_RETENTION_SCHEDULE", raising=False)
    events = root / "clients" / "acme-corp" / "events.db"
    reg = sqlite3.connect(root / "registry.db")
    try:
        _notice(reg, "threat_red")
        reg.commit()
    finally:
        reg.close()
    ev = sqlite3.connect(events, isolation_level=None)
    try:
        held = _window(ev, _incident(ev), start="2026-09-30T08:00:00.000Z")
    finally:
        ev.close()
    mod = _script("rollback_v017")
    assert mod.main(["--data-root", str(root)]) == 1                   # v0.17.5 root: refused
    assert "48" in json.loads(capsys.readouterr().out)["error"]
    assert _script("rollback_v0175").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0173").main(["--data-root", str(root), "--apply"]) == 0
    assert _script("rollback_v0172").main(["--data-root", str(root), "--apply"]) == 0
    capsys.readouterr()
    assert _script("rollback_v016").main(["--data-root", str(root)]) == 1   # 44: not its own
    assert "44" in json.loads(capsys.readouterr().out)["error"]

    assert mod.main(["--data-root", str(root)]) == 0                       # dry run
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert out["applied"] is False
    assert [(Path(s["file"]).name, s["target"]) for s in out["steps"]] == [
        ("events.db", "events"), ("registry.db", "registry")]
    # v0.16 does not honour evidence windows: every held one is named, loudly.
    assert out["held_windows"] == [{"tenant": "acme-corp", "window": held, "incident": 1,
                                    "start": "2026-09-30T08:00:00.000Z", "end": None}]
    assert "does not honour" in out["warning"] and "WARNING" in captured.err

    assert mod.main(["--data-root", str(root), "--apply",
                     "--accept-unprotected-evidence", "test: a fixture window"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["failed"] == [] and all(d["integrity"] == "ok" for d in out["done"])
    ev = sqlite3.connect(events)
    try:                                                                    # kept aside
        assert ev.execute("SELECT id FROM evidence_windows_rolled_back_044").fetchall() == \
            [(held,)]
    finally:
        ev.close()
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 43
        assert conn.execute("SELECT kind FROM operator_notices_rolled_back_044").fetchall() == \
            [("threat_red",)]
    finally:
        conn.close()
    ev = sqlite3.connect(events)
    try:
        assert "tier" not in _cols(ev, "incidents")
    finally:
        ev.close()

    assert mod.main(["--data-root", str(root), "--apply"]) == 0            # nothing left
    assert json.loads(capsys.readouterr().out)["steps"] == []

    bootstrap.init_data_root()                                              # re-upgrade
    conn = sqlite3.connect(root / "registry.db")
    try:
        assert conn.execute("SELECT kind FROM operator_notices").fetchall() == \
            [("threat_red",)]
        conn.execute("PRAGMA user_version = 45")
        conn.commit()
    finally:
        conn.close()
    assert mod.main(["--data-root", str(root)]) == 1                       # newer: refused
    assert "45" in json.loads(capsys.readouterr().out)["error"]
    assert mod.main(["--data-root", str(root.parent / "missing")]) == 2
