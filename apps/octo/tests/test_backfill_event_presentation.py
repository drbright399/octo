"""scripts/backfill_event_presentation.py — stored rows get their summary and
event_type re-derived from their own payload, and NOTHING else changes.

Real provisioning (every migration's events section), the real adapter's
present_event, the real script entry point.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.datto.tests.test_presentation import (
    COMP_SCRIPT,
    EVENTLOG,
    api_alert,
)

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "backfill_event_presentation.py"


@pytest.fixture
def backfill(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path))
    from apps.octo.auth import bootstrap
    bootstrap.init_data_root()
    client_provisioning.create_client("acme", "Acme")
    client_provisioning.create_client("globex", "Globex")
    spec = importlib.util.spec_from_file_location("backfill_event_presentation", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def _insert(slug, payload, *, source="datto", event_type="alert", summary="") -> int:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        cur = conn.execute(
            "INSERT INTO events (received_at, source, source_host, event_type, "
            "severity, summary, payload, payload_sha256) VALUES (?,?,?,?,?,?,?,?)",
            ("2026-09-21T14:13:20.000Z", source, "WS-EXAMPLE-01", event_type, "high",
             summary, json.dumps(payload, separators=(",", ":")), "a" * 64),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _dump(slug) -> list[tuple]:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        return conn.execute(
            "SELECT id, received_at, source, source_host, event_type, severity, "
            "summary, payload, payload_sha256, relay_status FROM events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def test_dry_run_reports_and_writes_nothing(backfill, capsys):
    _insert("acme", api_alert(EVENTLOG))
    before = _dump("acme")
    assert backfill.main(["--dry-run", "--show", "1"]) == 0
    out = capsys.readouterr().out
    assert "acme: scanned 1 datto rows, would change 1" in out
    assert "datto.eventlog: Event log · Security 4625" in out
    assert "dry run — nothing was written" in out
    assert _dump("acme") == before


def test_backfill_rewrites_only_summary_and_event_type_and_is_idempotent(backfill, capsys):
    eid = _insert("acme", api_alert(EVENTLOG))
    cid = _insert("acme", api_alert(COMP_SCRIPT))
    wazuh = _insert("acme", {"rule": "x"}, source="wazuh", event_type="auth.failure",
                    summary="kept")
    declared = _insert("acme", api_alert(EVENTLOG), event_type="custom.type", summary="kept")
    not_an_object = _insert("acme", [1, 2])
    other_tenant = _insert("globex", api_alert(EVENTLOG))
    before = {r[0]: r for r in _dump("acme")}

    assert backfill.main(["--slug", "acme"]) == 0
    assert "acme: scanned 4 datto rows, changed 2, unparseable 1, other-typed (left alone) 1" \
        in capsys.readouterr().out
    after = {r[0]: r for r in _dump("acme")}

    assert after[eid][4] == "datto.eventlog"
    assert after[eid][6] == "Event log · Security 4625 — An account failed to log on"
    assert after[cid][4] == "datto.comp_script"
    assert after[cid][6].startswith("Component monitor — Backup job")
    # Everything else on those rows — the ingest idempotency keys above all —
    # is byte-identical: id, received_at, source, host, severity, payload, sha.
    for rid in (eid, cid):
        for col in (0, 1, 2, 3, 5, 7, 8, 9):
            assert after[rid][col] == before[rid][col]
    # Rows that are not ours to touch.
    for rid in (wazuh, declared, not_an_object):
        assert after[rid] == before[rid]
    # --slug acme means acme only.
    assert _dump("globex")[0][4] == "alert" and _dump("globex")[0][0] == other_tenant

    # Second run: nothing left to do.
    assert backfill.main(["--slug", "acme"]) == 0
    assert "changed 0" in capsys.readouterr().out
    assert {r[0]: r for r in _dump("acme")} == after


def test_a_row_the_presenter_recognises_nothing_in_keeps_its_summary(backfill, capsys):
    """Dev synthetic traffic files rows under source 'datto' with a payload
    that is not a Datto alert and a summary that means something. The
    presenter's last-resort label must not overwrite it; a synthetic row
    WITHOUT a summary still gets the label (better than blank)."""
    synthetic = {"synthetic": True, "host": "ws-syn-01",
                 "scenario": "Malware signature match on endpoint", "severity": "critical"}
    kept = _insert("acme", synthetic, summary="[synthetic] Malware signature match on endpoint")
    blank = _insert("acme", {"synthetic": True, "host": "ws-syn-02", "severity": "low"})
    real = _insert("acme", api_alert(EVENTLOG))
    before = {r[0]: r for r in _dump("acme")}

    assert backfill.main(["--slug", "acme"]) == 0
    out = capsys.readouterr().out
    assert "acme: scanned 3 datto rows, changed 2" in out
    assert "unrecognised (summary kept) 1" in out
    after = {r[0]: r for r in _dump("acme")}
    assert after[kept] == before[kept]
    assert after[blank][4] == "datto.alert" and after[blank][6] == "Datto alert"
    assert after[real][4] == "datto.eventlog"

    assert backfill.main(["--slug", "acme"]) == 0          # idempotent
    assert "changed 0" in capsys.readouterr().out
    assert {r[0]: r for r in _dump("acme")} == after


def test_a_re_poll_after_the_backfill_still_dedups(backfill):
    """The sink's identity is (source, payload_sha256, received_at): the
    backfill leaves all three alone, so the same alert is not stored twice."""
    from apps.octo.adapters.datto import DattoSourceAdapter
    from apps.octo.ingest import SqliteIngestSink

    raw = api_alert(EVENTLOG)
    sink = SqliteIngestSink(publish_to_stream=False)
    first = sink.ingest("acme", "datto", DattoSourceAdapter().extract_event(raw))
    conn = sqlite3.connect(paths.client_dir("acme") / "events.db")
    conn.execute("UPDATE events SET summary = '', event_type = 'alert'")  # as the old sink left it
    conn.commit()
    conn.close()

    assert backfill.main([]) == 0
    again = sink.ingest("acme", "datto", DattoSourceAdapter().extract_event(raw))
    assert again.duplicate and again.event_id == first.event_id
    assert len(_dump("acme")) == 1


def test_no_tenants_is_exit_2(backfill, tmp_path, capsys):
    assert backfill.main(["--data-root", str(tmp_path / "nowhere")]) == 2
    assert backfill.main(["--source", "nope"]) == 2
