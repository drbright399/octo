"""Test the dev triage-reset tool's trigger handling (Task #119d-2).

The non-obvious part: agent_pattern_links has migration-011 append-only
triggers that block DELETE, so the reset must drop → delete → recreate
them and leave the append-only guarantee intact afterward.
"""
from __future__ import annotations

import sqlite3

import pytest

from scripts.dev_reset_triage import _reset_tenant


def _make_events_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE agent_notes (id INTEGER PRIMARY KEY, note_text TEXT);
        CREATE TABLE agent_pattern_links (id INTEGER PRIMARY KEY, rel TEXT);
        CREATE TABLE agent_triage_state (id INTEGER PRIMARY KEY CHECK (id=1),
                                         last_triaged_event_id INTEGER);
        CREATE TRIGGER agent_pattern_links_no_update
            BEFORE UPDATE ON agent_pattern_links
            BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;
        CREATE TRIGGER agent_pattern_links_no_delete
            BEFORE DELETE ON agent_pattern_links
            BEGIN SELECT RAISE(FAIL, 'agent_pattern_links is append-only'); END;
        INSERT INTO agent_notes (note_text) VALUES ('a'), ('b');
        INSERT INTO agent_pattern_links (rel) VALUES ('same_host'), ('temporal');
        INSERT INTO agent_triage_state (id, last_triaged_event_id) VALUES (1, 999);
        """
    )
    conn.commit()
    conn.close()


def test_reset_clears_all_three_tables(tmp_path):
    edb = tmp_path / "events.db"
    _make_events_db(edb)

    counts = _reset_tenant(edb)
    assert counts == {"agent_notes": 2, "agent_pattern_links": 2,
                      "agent_triage_state": 1}

    conn = sqlite3.connect(edb)
    try:
        for t in ("agent_notes", "agent_pattern_links", "agent_triage_state"):
            assert conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0
        # Triggers recreated → append-only guarantee restored.
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert "agent_pattern_links_no_delete" in names
        assert "agent_pattern_links_no_update" in names
        conn.execute("INSERT INTO agent_pattern_links (rel) VALUES ('x')")
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM agent_pattern_links")
    finally:
        conn.close()


def test_reset_is_idempotent(tmp_path):
    edb = tmp_path / "events.db"
    _make_events_db(edb)
    _reset_tenant(edb)
    second = _reset_tenant(edb)  # already empty
    assert second == {"agent_notes": 0, "agent_pattern_links": 0,
                      "agent_triage_state": 0}
