"""Evidence windows — the record (Rick, 2026-10-05: "Ingestion should not stop
but if a threat is confirmed everything from first detection up until the all
clear should be treated as event evidence").

Pins: a Red or a Black opens a window for its tenant, from its FIRST
DETECTION (the earliest time of the evidence linked to it — vendor time or
arrival — else its open; a dead clock's 1970 is never one), OPEN until the
all-clear; earlier evidence linked later widens it back; a raise keeps it;
the close ends it at the close's time and it stays HELD (no expiry) until an
admin releases it — never before the all-clear; a reopen opens the held
window again, or (released) a new one from the first detection; a reclassify
carries it to the linked Red, still open; a person widens (earlier only),
adds (manual — the former legal hold) or extends (never a shrink); every
change lands on the incident's timeline. Fixture names only (Acme / Example).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.threat import store
from apps.octo.threat.tests.conftest import A, B, insert_event

NOW = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _event(slug: str = A, *, at: datetime, arrived: datetime | None = None) -> int:
    eid = insert_event(slug, source="wazuh", event_type="wazuh.alert", payload={"at": iso(at)},
                       received_at=iso(at), source_host="ws-01")
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        conn.execute("UPDATE events SET ingested_at = ? WHERE id = ?",
                     (iso(arrived or at), eid))
        conn.commit()
    finally:
        conn.close()
    return eid


def _open(tier: str = "red", *, key: str = f"{A}|ws-01|analyst|", at: datetime = NOW,
          event_ids=None, by: str = "7") -> store.Opened:
    return store.open_incident(A, tier=tier, rule_id="R8" if tier == "red" else "B6",
                               rule_version=1, key=key, summary="confirmed threat",
                               scope="device", opened_by=by, reason="seen by alice",
                               device_ref="ws-01", event_ids=event_ids or [], now=at)


def _windows(incident_id: int | None = None, state: str = "all"):
    return store.evidence_windows(A, incident_id=incident_id, state=state)


def _timeline(incident_id: int) -> list[str]:
    return [n["text"] for n in store.notes(A, incident_id) if n["kind"] == "evidence_window"]


# ---------------------------------------------------------------------------
# Opening: a Red or a Black, from the first detection
# ---------------------------------------------------------------------------

def test_a_red_opens_a_window_from_its_first_detection(troot):
    first = _event(at=NOW - timedelta(days=3, hours=2))
    later = _event(at=NOW - timedelta(days=1))
    inc = _open("red", event_ids=[later, first]).incident
    (w,) = _windows(inc.id)
    assert (w.kind, w.incident_id, w.origin_incident_id) == ("incident", inc.id, inc.id)
    assert w.start == iso(NOW - timedelta(days=3, hours=2))            # the earliest evidence
    assert w.end is None and w.is_open and w.held                       # until the all-clear
    assert w.opened_by == "7"
    assert any("first detection" in t for t in _timeline(inc.id))
    # Its own lifecycle events are not doubled by the window's note.
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE source = 'athena'"
                            ).fetchone()[0] == 1                       # 'open' only
    finally:
        conn.close()


def test_a_black_with_no_evidence_starts_at_its_open_and_the_other_tenant_has_none(troot):
    inc = _open("black").incident
    (w,) = _windows(inc.id)
    assert w.start == iso(NOW) and w.is_open
    assert store.evidence_windows(B) == []


def test_the_arrival_counts_when_it_is_earlier_and_a_dead_clock_never_does(troot):
    # The vendor's clock ahead of ours: the arrival is the first detection.
    ahead = _event(at=NOW + timedelta(hours=5), arrived=NOW - timedelta(hours=6))
    # A dead clock (1970) is not a detection: it would hold everything.
    dead = _event(at=datetime(1970, 1, 1, tzinfo=timezone.utc), arrived=NOW - timedelta(hours=1))
    inc = _open("red", event_ids=[ahead, dead]).incident
    (w,) = _windows(inc.id)
    assert w.start == iso(NOW - timedelta(hours=6))


def test_earlier_evidence_widens_it_back_never_forward(troot):
    inc = _open("red", event_ids=[_event(at=NOW - timedelta(hours=2))]).incident
    (w,) = _windows(inc.id)
    assert w.start == iso(NOW - timedelta(hours=2))
    # Later evidence: unchanged.
    _open("red", event_ids=[_event(at=NOW - timedelta(minutes=5))], at=NOW + timedelta(minutes=1))
    assert _windows(inc.id)[0].start == iso(NOW - timedelta(hours=2))
    # Earlier evidence (the same key): widened, and said on the timeline.
    out = _open("red", event_ids=[_event(at=NOW - timedelta(days=9))],
                at=NOW + timedelta(minutes=2))
    assert out.outcome == "appended"
    assert _windows(inc.id)[0].start == iso(NOW - timedelta(days=9))
    assert any("widened" in t and "earlier evidence" in t for t in _timeline(inc.id))


def test_a_raise_keeps_the_same_window(troot):
    red = _open("red", event_ids=[_event(at=NOW - timedelta(hours=3))]).incident
    black = store.raise_to_black(A, red.id, by="7", reason="hands on keyboard",
                                 now=NOW + timedelta(minutes=5))
    assert black.id == red.id and black.tier == "black"
    (w,) = _windows(red.id)
    assert w.start == iso(NOW - timedelta(hours=3)) and w.is_open


# ---------------------------------------------------------------------------
# The all-clear, the release
# ---------------------------------------------------------------------------

def test_the_all_clear_ends_it_and_it_stays_held_until_an_admin_releases_it(troot):
    inc = _open("black", event_ids=[_event(at=NOW - timedelta(days=2))]).incident
    (w,) = _windows(inc.id)
    with pytest.raises(store.Refused, match="all-clear"):               # not before it
        store.release_window(A, inc.id, w.id, by="1", reason="too early", now=NOW)
    closed_at = NOW + timedelta(days=1)
    store.close(A, inc.id, by="7", code="remediated", text="reimaged", now=closed_at)
    (w,) = _windows(inc.id)
    assert w.end == iso(closed_at) and not w.is_open and w.held          # kept: no expiry
    assert any("all-clear" in t for t in _timeline(inc.id))
    released = store.release_window(A, inc.id, w.id, by="1", reason="the claim is settled",
                                    now=closed_at + timedelta(days=40))
    assert not released.held and released.released_by == "1"
    assert released.release_reason == "the claim is settled"
    assert any("RELEASED" in t and "the claim is settled" in t for t in _timeline(inc.id))
    assert _windows(state="held") == [] and len(_windows(state="released")) == 1
    with pytest.raises(store.Refused, match="already released"):
        store.release_window(A, inc.id, w.id, by="1", reason="again", now=closed_at)
    with pytest.raises(store.Refused, match="released"):                # history now
        store.widen_window(A, inc.id, w.id, start=iso(NOW - timedelta(days=30)), by="7",
                           reason="dwell time", now=closed_at)


def test_a_close_never_fails_because_of_its_window(troot, monkeypatch):
    """A close stamped before the window's start (a host clock stepped back)
    ends the window at its start; and should the window bookkeeping fail
    outright, the incident change still happens — the timeline says so (a
    person is always heard, the paging goes on)."""
    from apps.octo.threat import windows as threat_windows

    inc = _open("red", event_ids=[_event(at=NOW - timedelta(hours=1))]).incident
    closed = store.close(A, inc.id, by="7", code="remediated", text="done",
                         now=NOW - timedelta(days=9))
    assert closed.status == "closed"
    (w,) = _windows(inc.id)
    assert w.end == w.start == iso(NOW - timedelta(hours=1))

    def broken(*_a, **_k):
        raise sqlite3.IntegrityError("a constraint the window broke")

    monkeypatch.setattr(threat_windows, "open_auto", broken)
    black = _open("black", key=f"{A}|ws-09|analyst|").incident
    assert black is not None and black.tier == "black" and black.is_open
    assert _windows(black.id) == []
    assert any("NOT recorded" in t for t in _timeline(black.id))


def test_a_false_positive_close_is_an_all_clear_too(troot):
    inc = _open("red", event_ids=[_event(at=NOW - timedelta(hours=1))]).incident
    store.close(A, inc.id, by="7", code="false_positive", text="a test file", now=NOW)
    (w,) = _windows(inc.id)
    assert w.end == iso(NOW) and w.held


# ---------------------------------------------------------------------------
# Reopen and reclassify
# ---------------------------------------------------------------------------

def test_a_reopen_opens_the_held_window_again(troot):
    inc = _open("red", event_ids=[_event(at=NOW - timedelta(days=1))]).incident
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW)
    again = _open("red", event_ids=[_event(at=NOW + timedelta(days=2))],
                  at=NOW + timedelta(days=3))
    assert again.outcome == "reopened" and again.incident.id == inc.id
    (w,) = _windows(inc.id)                                             # the same window
    assert w.start == iso(NOW - timedelta(days=1)) and w.is_open and w.held
    assert any("open again" in t for t in _timeline(inc.id))


def test_a_reopen_after_a_release_opens_a_new_window_from_the_first_detection(troot):
    inc = _open("red", event_ids=[_event(at=NOW - timedelta(days=1))]).incident
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW)
    (old,) = _windows(inc.id)
    store.release_window(A, inc.id, old.id, by="1", reason="nothing to keep",
                         now=NOW + timedelta(hours=1))
    _open("red", event_ids=[_event(at=NOW + timedelta(days=2))], at=NOW + timedelta(days=2))
    held = _windows(inc.id, state="held")
    assert len(held) == 1 and held[0].id != old.id
    assert held[0].start == iso(NOW - timedelta(days=1)) and held[0].is_open
    assert not [w for w in _windows(inc.id) if w.id == old.id][0].held   # stays released


def test_a_reclassify_keeps_the_window_open_with_the_linked_red(troot):
    black = _open("black", event_ids=[_event(at=NOW - timedelta(hours=4))]).incident
    (w,) = _windows(black.id)
    closed, red = store.reclassify(A, black.id, by="1", reason="a vendor's session",
                                   now=NOW + timedelta(hours=1))
    assert closed.status == "closed" and red.reclassified_from == black.id
    (carried,) = _windows(red.id)
    assert carried.id == w.id and carried.incident_id == red.id
    assert carried.origin_incident_id == black.id and carried.is_open   # NOT ended
    assert _windows(black.id) == [carried]                              # shown on both
    assert any("carried to Red" in t for t in _timeline(black.id))
    assert any("carried to Red" in t for t in _timeline(red.id))
    with pytest.raises(store.Refused, match="all-clear"):               # the Red is open
        store.release_window(A, black.id, w.id, by="1", reason="early", now=NOW)
    store.close(A, red.id, by="7", code="remediated", text="done", now=NOW + timedelta(days=1))
    assert _windows(red.id)[0].end == iso(NOW + timedelta(days=1))


# ---------------------------------------------------------------------------
# A person's changes
# ---------------------------------------------------------------------------

def test_widen_only_ever_moves_the_start_earlier(troot):
    inc = _open("black", event_ids=[_event(at=NOW - timedelta(hours=2))]).incident
    (w,) = _windows(inc.id)
    with pytest.raises(store.Refused, match="only widens"):
        store.widen_window(A, inc.id, w.id, start=iso(NOW - timedelta(hours=1)), by="7",
                           reason="later", now=NOW)
    with pytest.raises(ValueError, match="not a date"):
        store.widen_window(A, inc.id, w.id, start="last tuesday", by="7", reason="x", now=NOW)
    out = store.widen_window(A, inc.id, w.id, start="2026-09-20T08:00:00Z", by="7",
                             reason="dwell time: the first beacon was on the 20th", now=NOW)
    assert out.start == "2026-09-20T08:00:00.000Z"
    assert any("dwell time" in t for t in _timeline(inc.id))
    with pytest.raises(store.NotFound):                                 # another incident's
        other = _open("red", key=f"{A}|ws-02|analyst|").incident
        store.widen_window(A, other.id, w.id, start="2026-09-01T00:00:00Z", by="7",
                           reason="x", now=NOW)


def test_add_and_extend_never_shrink(troot):
    inc = _open("black").incident
    (auto,) = _windows(inc.id)
    with pytest.raises(store.Refused, match="open"):                    # no end to extend
        store.extend_window(A, inc.id, auto.id, start=auto.start, end=iso(NOW), by="1",
                            reason="x", now=NOW)
    manual = store.add_window(A, inc.id, start="2026-09-01T00:00:00Z",
                              end="2026-09-10T00:00:00Z", by="1", reason="claim CL-0001",
                              now=NOW)
    assert (manual.kind, manual.end) == ("manual", "2026-09-10T00:00:00.000Z")
    for start, end, why in (("2026-09-02T00:00:00Z", None, "never shrinks"),
                            ("2026-09-01T00:00:00Z", "2026-09-09T00:00:00Z", "never shrinks"),
                            ("2026-09-01T00:00:00Z", None, "nothing to extend")):
        with pytest.raises(store.Refused, match=why):
            store.extend_window(A, inc.id, manual.id, start=start, end=end, by="1",
                                reason="x", now=NOW)
    out = store.extend_window(A, inc.id, manual.id, start="2026-08-25T00:00:00Z",
                              end="2026-09-15T00:00:00Z", by="1", reason="more of the claim",
                              now=NOW)
    assert (out.start, out.end) == ("2026-08-25T00:00:00.000Z", "2026-09-15T00:00:00.000Z")
    with pytest.raises(store.Refused, match="end is before"):
        store.add_window(A, inc.id, start="2026-09-10T00:00:00Z", end="2026-09-01T00:00:00Z",
                         by="1", reason="x", now=NOW)
    # The close ends the automatic window only — a manual one keeps its own.
    store.close(A, inc.id, by="1", code="remediated", text="done", now=NOW)
    ends = {w.id: w.end for w in _windows(inc.id)}
    assert ends == {auto.id: iso(NOW), manual.id: "2026-09-15T00:00:00.000Z"}
    # A human change is an incident lifecycle event (the automatic ones are
    # not: the incident change that caused them is).
    conn = sqlite3.connect(paths.client_dir(A) / "events.db")
    try:
        changes = [r[0] for r in conn.execute(
            "SELECT change FROM incident_signals WHERE incident_id = ? ORDER BY event_id",
            (inc.id,))]
    finally:
        conn.close()
    assert changes == ["open", "evidence_window", "evidence_window", "close"]


def test_a_reopen_and_the_next_close_never_take_back_an_extended_end(troot):
    """An admin extends a closed window's end (a claim period); the incident
    reopens and closes again before that end: the window still ends there —
    the end it had is its floor (`min_end`). Nobody shrinks a window except
    by releasing it."""
    inc = _open("red", event_ids=[_event(at=NOW - timedelta(days=1))]).incident
    store.close(A, inc.id, by="7", code="remediated", text="cleaned", now=NOW)
    (w,) = _windows(inc.id)
    claim_end = iso(NOW + timedelta(days=30))
    store.extend_window(A, inc.id, w.id, start=w.start, end=claim_end, by="1",
                        reason="the claim period", now=NOW + timedelta(hours=1))
    again = _open("red", event_ids=[_event(at=NOW + timedelta(days=4))],
                  at=NOW + timedelta(days=5))
    assert again.outcome == "reopened"
    (w,) = _windows(inc.id)
    assert w.is_open and w.min_end == claim_end
    store.close(A, inc.id, by="7", code="remediated", text="cleaned again",
                now=NOW + timedelta(days=7))
    (w,) = _windows(inc.id)
    assert w.end == claim_end and w.held                       # not the second close's time
    # Reopened again and closed AFTER the floor: the close's time, as ever.
    _open("red", event_ids=[_event(at=NOW + timedelta(days=8))], at=NOW + timedelta(days=9))
    store.close(A, inc.id, by="7", code="remediated", text="done",
                now=NOW + timedelta(days=40))
    (w,) = _windows(inc.id)
    assert w.end == iso(NOW + timedelta(days=40))


def test_a_window_never_starts_before_2000(troot):
    """A slip of the year (1970 from an empty field, 0001) would hold the
    tenant's whole history until a release: refused for widen, add and
    extend alike."""
    inc = _open("black").incident
    (w,) = _windows(inc.id)
    manual = store.add_window(A, inc.id, start="2026-09-01T00:00:00Z", end=None, by="1",
                              reason="claim CL-0001", now=NOW)
    for call in (
            lambda s: store.widen_window(A, inc.id, w.id, start=s, by="7", reason="typo",
                                         now=NOW),
            lambda s: store.add_window(A, inc.id, start=s, end=None, by="1", reason="typo",
                                       now=NOW),
            lambda s: store.extend_window(A, inc.id, manual.id, start=s, end=None, by="1",
                                          reason="typo", now=NOW)):
        for start in ("1970-01-01T00:00:00Z", "1999-12-31T23:59:59Z"):
            with pytest.raises(ValueError, match="before 2000"):
                call(start)
    out = store.widen_window(A, inc.id, w.id, start="2000-01-01T00:00:00Z", by="7",
                             reason="dwell time since the old server went in", now=NOW)
    assert out.start == "2000-01-01T00:00:00.000Z"
