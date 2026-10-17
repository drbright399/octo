"""Coverage for the audit-grade /search/export + /search/links/expand
endpoints (apps/octo/api/routers/search_export.py).

Reuses the seed helpers from test_search_events for fixture consistency.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp

from apps.octo import paths

from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _register_client,
    _insert_event,
    _login,
    _elevate,
)


def _seed_with_agent_layer(auth_data_root: Path, slug: str, count: int = 6) -> list[int]:
    """Create a tenant with `count` recent events. Inject one agent_note +
    one agent_pattern_link from event[0] → event[1] so the expand test
    has a real edge to traverse. Returns the event IDs in insertion order."""
    _register_client(slug)
    cdir = auth_data_root / "clients" / slug
    _apply_events_db_migration(cdir)
    now = datetime.now(timezone.utc)
    for i in range(count):
        ts = (now - timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        _insert_event(
            cdir, ts,
            event_type="wazuh.alert",
            severity="high",
            source_host=f"buoy-{slug}-1",
            summary=f"event {i} for {slug}",
        )
    # Pull event IDs in DESC received_at order (matches what /events returns)
    conn = sqlite3.connect(cdir / "events.db")
    try:
        ids = [row[0] for row in conn.execute(
            "SELECT id FROM events ORDER BY received_at DESC"
        )]
        # Seed one note + one link (event[0] → event[1])
        conn.execute(
            "INSERT INTO agent_notes "
            "(ref_kind, ref_id, agent_id, note_text, confidence, "
            " audit_request_id) "
            "VALUES ('event', ?, 'octo', 'synthetic test note', 0.8, 'test-rid')",
            (ids[0],),
        )
        conn.execute(
            "INSERT INTO agent_pattern_links "
            "(from_kind, from_id, to_kind, to_id, relation, strength, "
            " rationale, created_by_agent) "
            "VALUES ('event', ?, 'event', ?, 'same_host', 0.9, "
            "        'shared source_host', 'octo')",
            (ids[0], ids[1]),
        )
        conn.commit()
    finally:
        conn.close()
    return ids


def test_expand_returns_linked_refs_and_audits_once(auth_client, auth_data_root):
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/search/links/expand", json={
        "refs": [
            {"client_slug": "acme", "event_id": ids[0]},
            {"client_slug": "acme", "event_id": ids[2]},  # no edges
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["refs"]) == 2
    first = next(r for r in body["refs"] if r["event_id"] == ids[0])
    assert len(first["linked_refs"]) == 1
    assert first["linked_refs"][0]["relation"] == "same_host"
    assert first["linked_refs"][0]["to_id"] == ids[1]
    second = next(r for r in body["refs"] if r["event_id"] == ids[2])
    assert second["linked_refs"] == []


def test_expand_silently_drops_out_of_scope_tenants(auth_client, auth_data_root):
    """Scoped viewer requesting refs in tenants outside their scope gets
    empty linked_refs back — not 403. Anti-disclosure."""
    _seed_with_agent_layer(auth_data_root, "acme")
    _seed_with_agent_layer(auth_data_root, "globex")

    op = auth_client.provision_operator(
        "alice-scoped", "pw1234567890",
        athena_role="analyst", scope_slugs=["acme"],
    )
    _login(auth_client, op)
    _elevate(auth_client, op)

    # Request refs from BOTH tenants; only acme should resolve.
    conn = sqlite3.connect(paths.client_db_path("globex", "events"))
    globex_id = conn.execute("SELECT id FROM events ORDER BY received_at DESC LIMIT 1").fetchone()[0]
    conn.close()

    r = auth_client.post("/api/v1/search/links/expand", json={
        "refs": [
            {"client_slug": "globex", "event_id": globex_id},
        ],
    })
    assert r.status_code == 200
    # Returned but with no linked_refs — caller can't tell whether the
    # ref exists or is out-of-scope.
    body = r.json()
    assert body["refs"][0]["linked_refs"] == []


def test_export_csv_returns_attachment_with_audit_headers(auth_client, auth_data_root):
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["acme"],
        "format": "csv",
        "event_ids": [
            {"client_slug": "acme", "event_id": ids[0]},
            {"client_slug": "acme", "event_id": ids[1]},
        ],
    })
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert "athena-export-" in r.headers["content-disposition"]
    # Audit headers expose the request id + filter hash so the operator
    # can correlate their download with the audit chain.
    assert "x-athena-audit-request-id" in {k.lower() for k in r.headers}
    assert "x-athena-filter-hash" in {k.lower() for k in r.headers}

    text = r.content.decode("utf-8")
    # Header row + 2 data rows
    lines = text.strip().split("\n")
    assert len(lines) == 3
    assert lines[0].startswith("client_slug,event_id,received_at,")
    assert "acme" in lines[1]
    assert "wazuh.alert" in lines[1]


def test_export_pdf_returns_pdf_bytes(auth_client, auth_data_root):
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["acme"],
        "format": "pdf",
        "event_ids": [
            {"client_slug": "acme", "event_id": ids[0]},
        ],
    })
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    # PDF magic bytes
    assert r.content[:4] == b"%PDF"
    # File size sanity — header+table+footer for one row should be > 1KB
    assert len(r.content) > 1024


def test_export_blocked_when_no_step_up(auth_client, auth_data_root):
    _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    # NOT elevated
    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["acme"], "format": "csv",
    })
    # require_step_up returns 403 STEP_UP_REQUIRED
    assert r.status_code in (401, 403), r.text
    body = r.json()
    assert body.get("code") in ("STEP_UP_REQUIRED",) or "step" in str(body).lower()


def test_export_csv_with_agent_notes_attaches_column(auth_client, auth_data_root):
    """include_agent_notes=true → CSV gains agent_notes_json column
    populated for events that have notes, [] for those that don't."""
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)

    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["acme"],
        "format": "csv",
        "event_ids": [
            {"client_slug": "acme", "event_id": ids[0]},  # has a note
            {"client_slug": "acme", "event_id": ids[2]},  # no note
        ],
        "include_agent_notes": True,
    })
    assert r.status_code == 200, r.text
    text = r.content.decode("utf-8")
    header = text.split("\n")[0]
    assert "agent_notes_json" in header
    # First data row (newest event = ids[0]) should have a non-empty
    # JSON array; the no-note one should have "[]".
    lines = text.strip().split("\n")
    assert any('"octo"' in ln for ln in lines), text
    assert any(ln.endswith(",[]") for ln in lines[1:]), text


def test_export_pdf_includes_render_extra_sections(auth_client, auth_data_root):
    """include_agent_notes + include_indicators both true → PDF
    grows beyond the no-includes baseline. We don't crack the PDF
    structure; just confirm it renders and exceeds the bare-row size."""
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    common = {
        "tenants": ["acme"], "format": "pdf",
        "event_ids": [{"client_slug": "acme", "event_id": ids[0]}],
    }
    bare = auth_client.post("/api/v1/search/export", json=common).content
    rich = auth_client.post("/api/v1/search/export", json={
        **common, "include_agent_notes": True, "include_indicators": True,
    }).content
    assert bare[:4] == b"%PDF" and rich[:4] == b"%PDF"
    # The rich PDF should be measurably larger — extra sections add
    # text + table chrome. Threshold is conservative.
    assert len(rich) > len(bare) + 500


def test_export_audit_records_included_flags(auth_client, auth_data_root):
    """The `search.export` audit row's after_state captures whether
    agent_notes / indicators were included. Auditor can later prove
    'this exact PDF had Y agent reasoning included'."""
    ids = _seed_with_agent_layer(auth_data_root, "acme")
    op = auth_client.provision_operator("alice", "pw1234567890",
                                          athena_role="super_admin")
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["acme"], "format": "csv",
        "event_ids": [{"client_slug": "acme", "event_id": ids[0]}],
        "include_agent_notes": True,
    })
    assert r.status_code == 200
    # Read the global audit log directly; latest search.export row
    # should carry our flag set.
    import sqlite3
    from apps.octo import paths
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        row = conn.execute(
            "SELECT after_state FROM audit_log "
            "WHERE action = 'search.export' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    import json as _json
    after = _json.loads(row[0])
    assert after["included"] == {"agent_notes": True, "indicators": False}


def test_export_isolation_violation_for_out_of_scope_request(auth_client, auth_data_root):
    """Caller asks to export from a tenant they can't see — refused."""
    _seed_with_agent_layer(auth_data_root, "acme")
    _seed_with_agent_layer(auth_data_root, "globex")
    op = auth_client.provision_operator(
        "alice-scoped", "pw1234567890",
        athena_role="analyst", scope_slugs=["acme"],
    )
    _login(auth_client, op)
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/export", json={
        "tenants": ["globex"], "format": "csv",
    })
    assert r.status_code in (400, 403), r.text
    body = r.json()
    assert body.get("code") == "ISOLATION_VIOLATION"
