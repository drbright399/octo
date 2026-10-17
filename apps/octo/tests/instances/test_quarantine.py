"""Quarantine store — hold / idempotency / retention / resolve, on the real
platform DB (global/quarantine.db built from the migrations' @target sections)."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import quarantine


@pytest.fixture
def qroot(monkeypatch, tmp_path):
    root = tmp_path / "octo-data"
    (root / "global").mkdir(parents=True)
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    quarantine.reset_schema_cache()
    yield root
    quarantine.reset_schema_cache()


def _hold(instance_id=1, *, reason="no-tenant-id", payload=None, tid=None, label=None, **kw):
    return quarantine.hold(
        instance_id=instance_id, vendor_slug="datto", source="poll", reason=reason,
        payload=payload if payload is not None else {"alertUid": "a-1"},
        vendor_tenant_id=tid, vendor_tenant_label=label, **kw,
    )


def test_db_is_created_lazily_from_the_migration_target(qroot):
    assert not quarantine.exists()
    assert quarantine.list_rows() == ([], 0)          # no file, no rows, no crash
    applied = quarantine.ensure_db()
    assert applied == [33] and quarantine.exists()
    assert quarantine.ensure_db() == []                # idempotent
    conn = sqlite3.connect(paths.global_dir() / "quarantine.db")
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 33
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()


def test_hold_is_idempotent_per_instance_and_payload(qroot):
    first = _hold(payload={"alertUid": "a-1", "x": 1})
    again = _hold(payload={"x": 1, "alertUid": "a-1"})   # same canonical JSON
    other_instance = _hold(instance_id=2, payload={"alertUid": "a-1", "x": 1})
    assert first.created and not again.created and first.id == again.id
    assert other_instance.created and other_instance.id != first.id
    rows, total = quarantine.list_rows()
    assert total == 2 and {r.adapter_instance_id for r in rows} == {1, 2}


def test_hold_stores_bounded_cleaned_metadata_and_opaque_payload(qroot):
    held = _hold(
        reason="ambiguous-name", tid="  site-\x00uid  ", label="Acme\nCorp" + "!" * 500,
        event_summary="Disk — full\x07", payload={"alertContext": {"message": "<b>hi</b>\n"}},
    )
    row = quarantine.get(held.id)
    assert row.reason == "ambiguous-name" and row.state == "held"
    assert row.vendor_tenant_id == "site-uid"          # control char gone, trimmed
    assert len(row.vendor_tenant_label) <= quarantine.MAX_LABEL_CHARS
    assert "\n" not in row.vendor_tenant_label
    assert row.event_summary == "Disk — full"
    assert not row.payload_truncated
    # The payload is what the adapter saw, as text — nothing rendered.
    assert quarantine.payload_text(held.id) == '{"alertContext":{"message":"<b>hi</b>\\n"}}'
    assert quarantine.payload_json(held.id) == {"alertContext": {"message": "<b>hi</b>\n"}}


def test_unknown_reason_is_a_programming_error(qroot):
    with pytest.raises(ValueError):
        _hold(reason="whatever")


def test_oversize_payload_is_truncated_and_cannot_be_replayed(qroot, monkeypatch):
    monkeypatch.setattr(quarantine, "MAX_PAYLOAD_BYTES", 64)
    held = _hold(payload={"alertUid": "a-1", "blob": "z" * 200})
    row = quarantine.get(held.id)
    assert row.payload_truncated
    assert len(quarantine.payload_text(held.id).encode()) <= 64
    assert quarantine.payload_json(held.id) is None     # never half an envelope
    # Identity is the FULL payload's sha: the same oversize alert holds once.
    assert not _hold(payload={"alertUid": "a-1", "blob": "z" * 200}).created


def test_retention_caps_rows_per_instance_oldest_out_and_counts(qroot, monkeypatch):
    monkeypatch.setattr(quarantine, "MAX_ROWS_PER_INSTANCE", 5)
    ids = [_hold(payload={"n": n}).id for n in range(8)]
    rows, total = quarantine.list_rows(instance_id=1)
    assert total == 5 and [r.id for r in rows] == sorted(ids[-5:], reverse=True)
    assert quarantine.counts(1) == {"held": 5, "evicted_since_restart": 3}
    # Another instance's rows are not touched by instance 1's cap.
    _hold(instance_id=2, payload={"n": "other"})
    assert quarantine.counts(2)["held"] == 1


def test_retention_ages_out_resolved_rows_but_never_a_held_one(qroot):
    """The clock removes only what a human already decided on (routed /
    discarded); a HELD row waits for that decision however old it gets."""
    old_held = _hold(payload={"n": "old-held"})
    old_routed = _hold(payload={"n": "old-routed"})
    old_discarded = _hold(payload={"n": "old-discarded"})
    quarantine.mark_routed(old_routed.id, slug="acme-corp", by="7")
    quarantine.mark_discarded(old_discarded.id, by="7", reason="noise")
    conn = sqlite3.connect(paths.global_dir() / "quarantine.db")
    stale = format_utc_ms(datetime.now(timezone.utc) - timedelta(days=quarantine.MAX_AGE_DAYS + 1))
    conn.execute("UPDATE quarantine SET received_at = ? WHERE id IN (?, ?, ?)",
                 (stale, old_held.id, old_routed.id, old_discarded.id))
    conn.commit(); conn.close()
    _hold(payload={"n": "new"})                            # retention runs on a new hold
    assert quarantine.get(old_routed.id) is None and quarantine.get(old_discarded.id) is None
    assert quarantine.get(old_held.id) is not None and quarantine.get(old_held.id).state == "held"
    # Housekeeping is not news: nothing HELD was evicted, so nothing is counted.
    assert quarantine.counts(1)["evicted_since_restart"] == 0
    assert quarantine.card_warnings(1, "Datto RMM")[0].startswith("2 event(s) from Datto RMM are held")
    assert len(quarantine.card_warnings(1, "Datto RMM")) == 1


def test_row_cap_evicts_resolved_rows_before_held_ones_and_warns(qroot, monkeypatch):
    """Under a flood the cap holds, but routed/discarded rows go first —
    oldest first within each — and a HELD eviction is counted and shown."""
    monkeypatch.setattr(quarantine, "MAX_ROWS_PER_INSTANCE", 4)
    first_held = _hold(payload={"n": "held-1"})
    routed = _hold(payload={"n": "routed"})
    discarded = _hold(payload={"n": "discarded"})
    quarantine.mark_routed(routed.id, slug="acme-corp", by="7")
    quarantine.mark_discarded(discarded.id, by="7", reason="noise")
    _hold(payload={"n": "held-2"})                         # 4 rows: at the cap
    fifth = _hold(payload={"n": "held-3"})                 # 5 → one must go: the resolved one first
    assert quarantine.get(routed.id) is None               # oldest resolved row went
    assert quarantine.get(discarded.id) is not None and quarantine.get(first_held.id) is not None
    assert quarantine.counts(1) == {"held": 3, "evicted_since_restart": 0}
    _hold(payload={"n": "held-4"})                         # the other resolved row goes
    assert quarantine.get(discarded.id) is None and quarantine.get(first_held.id) is not None
    assert quarantine.counts(1)["evicted_since_restart"] == 0
    _hold(payload={"n": "held-5"})                         # only held rows left: oldest held goes
    assert quarantine.get(first_held.id) is None and quarantine.get(fifth.id) is not None
    assert quarantine.counts(1) == {"held": 4, "evicted_since_restart": 1}
    held_line, evicted_line = quarantine.card_warnings(1, "Datto RMM")
    assert "keeps the newest 4 events per integration" in held_line
    assert evicted_line.startswith("1 held event(s) from Datto RMM were evicted from quarantine UNREVIEWED")
    # A silent restart forgets the counter but not the rule: still 4 rows.
    quarantine.reset_schema_cache()
    assert quarantine.counts(1) == {"held": 4, "evicted_since_restart": 0}


def test_list_filters_and_pages(qroot):
    for n in range(3):
        _hold(payload={"n": n}, reason="no-tenant-id", tid=None)
    for n in range(2):
        _hold(payload={"m": n}, reason="ambiguous-name", tid="site-9")
    _hold(instance_id=2, payload={"k": 1}, reason="ambiguous-name", tid="site-9")
    assert quarantine.list_rows(reason="ambiguous-name")[1] == 3
    assert quarantine.list_rows(instance_id=1, reason="ambiguous-name")[1] == 2
    assert quarantine.list_rows(vendor_tenant_id="site-9")[1] == 3
    rows, total = quarantine.list_rows(limit=2, offset=2)
    assert total == 6 and len(rows) == 2
    assert quarantine.held_ids_for_vendor_tenant(1, "site-9") == sorted(
        quarantine.held_ids_for_vendor_tenant(1, "site-9"))
    assert len(quarantine.held_ids_for_vendor_tenant(1, "site-9")) == 2
    assert quarantine.held_count() == 6


def test_route_and_discard_are_terminal_and_exclusive(qroot):
    a = _hold(payload={"n": 1}).id
    b = _hold(payload={"n": 2}).id
    assert quarantine.mark_routed(a, slug="acme-corp", by="7")
    assert not quarantine.mark_routed(a, slug="other", by="7")          # already routed
    assert not quarantine.mark_discarded(a, by="7", reason="late")      # …and not discardable
    assert quarantine.mark_discarded(b, by="7", reason="test noise")
    assert quarantine.get(a).state == "routed" and quarantine.get(a).routed_to_slug == "acme-corp"
    assert quarantine.get(b).state == "discarded" and quarantine.get(b).discard_reason == "test noise"
    assert quarantine.list_rows(state="held")[1] == 0
    assert quarantine.list_rows(state="routed")[1] == 1
    assert quarantine.list_rows(state="all")[1] == 2
    assert quarantine.counts(1)["held"] == 0
    # A re-listed alert that was already routed/discarded is NOT held again.
    assert not _hold(payload={"n": 1}).created


def test_card_warning_only_when_something_is_held(qroot):
    assert quarantine.card_warnings(1, "Datto RMM") == []
    _hold(payload={"n": 1})
    (line,) = quarantine.card_warnings(1, "Datto RMM")
    assert "1 event(s) from Datto RMM are held in quarantine" in line
    assert quarantine.card_warnings(None, "Datto RMM") == []
