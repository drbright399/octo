"""v0.17.5 — a RECALLED acknowledgement covers nothing (Rick, 2026-10-08:
"A recall button/feature would be useful for exactly this situation
honestly."), and the follow-up rows behind it (migration 048).

The evaluator in isolation:
  * a single event, a coalesced row and the alerts a "repeats for 24 h" ack
    covered are OPEN again once their ack is recalled (not acknowledged, not
    "re-surfaced") — and the state carries the recalled ack (history);
  * the ack that DECIDES an alert is chosen as before: when it is recalled
    no ack made BEFORE the recall takes over (an older ack of the row,
    another row's ack of the vendor alert, another repeat-ack that also
    covered it); an ack made AFTER it (acknowledged again — this row or
    another row of the vendor alert) decides;
  * a recalled ack of a vendor alert's row covers none of its other rows;
  * an expected rule is untouched (it has its own revoke).

The store (a real registry at the current schema):
  * every verdict read carries its recall; `followups` reads notes and the
    recall oldest first; the writer refuses a short reason, a second recall,
    a follow-up on a label that is not an ack or of another tenant;
  * the table is append-only (the schema refuses UPDATE / DELETE);
  * a registry whose follow-ups cannot be read hides NOTHING (louder).
"""
from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.verdicts import keys
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import (
    ACKED,
    EXPECTED,
    OPEN,
    RESURFACED,
    AlertState,
    Occurrence,
    TenantVerdicts,
)

NOW = datetime(2026, 10, 8, 15, 0, tzinfo=timezone.utc)
SCOPE = "F1X7HOST/f1x7site"
RECALLED = vstore.iso(NOW - timedelta(minutes=1))


def iso(dt: datetime) -> str:
    return vstore.iso(dt)


def ips_key(client: str = "192.0.2.37") -> keys.AlertKey:
    return keys.unifi_key(SCOPE, "ips_threat", f"{client}|ET POLICY Example|outbound|blocked",
                          remote="203.0.113.66")


def ack(event_id: int, key: keys.AlertKey, *, at: datetime, hits: int | None = None,
        last: datetime | None = None, repeat: bool = False, vid: int = 1,
        recalled: bool = False) -> vstore.Verdict:
    return vstore.Verdict(vid, "acme-corp", event_id, key.source, key.device_key,
                          key.signature_key, vstore.ACK, 7, iso(at), "seen", hits,
                          iso(last) if last else None,
                          iso(at + timedelta(hours=24)) if repeat else None,
                          alert_ref=key.ref, recalled_at=RECALLED if recalled else None)


def occ(key: keys.AlertKey, *, event_id: int = 41, first: datetime = NOW - timedelta(hours=1),
        last: datetime | None = None, hits: int | None = None) -> Occurrence:
    return Occurrence(event_id, key, iso(first), iso(last or first), hits)


# ---------------------------------------------------------------------------
# The evaluator
# ---------------------------------------------------------------------------

def test_a_recalled_ack_of_a_single_event_leaves_it_open():
    k = keys.alert_key({"source": "rocketcyber", "event_type": "rocketcyber.incident"},
                       {"id": 101, "title": "Suspicious PowerShell Detected"})
    at = NOW - timedelta(hours=1)
    plain = TenantVerdicts("acme-corp", [ack(41, k, at=at, last=at)], [], now=NOW)
    assert plain.state(occ(k, first=at)).status == ACKED
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=at, last=at, recalled=True)], [], now=NOW)
    st = tv.state(occ(k, first=at))
    assert st.status == OPEN and not st.hidden
    assert st.recalled and st.ack is not None and st.ack.recalled_at == RECALLED
    assert not plain.state(occ(k, first=at)).recalled


def test_a_recalled_ack_of_a_coalesced_row_leaves_it_open_not_resurfaced():
    k = ips_key()
    seen = NOW - timedelta(minutes=40)
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=NOW - timedelta(minutes=30), hits=3,
                                          last=seen, recalled=True)], [], now=NOW)
    for shown in (occ(k, hits=3, last=seen), occ(k, hits=5, last=NOW)):
        st = tv.state(shown)
        assert st.status == OPEN and not st.hidden and st.new_hits == 0 and st.recalled


def test_a_recalled_repeat_ack_covers_no_repeat_and_not_its_own_growth():
    k = ips_key()
    at = NOW - timedelta(hours=2)
    a = ack(41, k, at=at, hits=1, last=at, repeat=True)
    live = TenantVerdicts("acme-corp", [a], [], now=NOW)
    later = occ(k, event_id=43, first=at + timedelta(hours=1), hits=2)
    assert live.state(later).status == ACKED and live.state(later).by_repeat
    assert live.state(occ(k, hits=4, last=NOW)).status == ACKED          # its own growth
    tv = TenantVerdicts("acme-corp", [replace(a, recalled_at=RECALLED)], [], now=NOW)
    st = tv.state(later)
    # Open — and it says which recall brought it back (history).
    assert st.status == OPEN and not st.hidden and st.recalled and st.by_repeat
    assert st.ack is not None and st.ack.id == a.id
    assert tv.state(occ(k, hits=4, last=NOW)).status == OPEN
    assert tv.state(occ(k, hits=1, last=at)).recalled                    # its own row


def test_no_older_ack_takes_over_and_a_newer_one_decides():
    k = ips_key()
    seen = NOW - timedelta(minutes=50)
    older = ack(41, k, at=NOW - timedelta(minutes=45), hits=3, last=seen, vid=1)
    newer = ack(41, k, at=NOW - timedelta(minutes=30), hits=3, last=seen, vid=2,
                recalled=True)
    tv = TenantVerdicts("acme-corp", [older, newer], [], now=NOW)
    st = tv.state(occ(k, hits=3, last=seen))
    assert st.status == OPEN and st.ack is not None and st.ack.id == 2
    # Acknowledged again (a NEW ack): it decides.
    again = ack(41, k, at=NOW - timedelta(minutes=10), hits=3, last=seen, vid=3)
    tv.add_acks([again])
    st = tv.state(occ(k, hits=3, last=seen))
    assert st.status == ACKED and st.ack is not None and st.ack.id == 3
    # The same acks in any order: the newest decides.
    tv = TenantVerdicts("acme-corp", [again, newer, older], [], now=NOW)
    assert tv.state(occ(k, hits=3, last=seen)).status == ACKED
    # An older recall never undoes a newer ack's growth rule.
    grown = tv.state(occ(k, hits=6, last=NOW))
    assert grown.status == RESURFACED and grown.ack is not None and grown.ack.id == 3


def _datto(uid: str, *, resolved: bool = False) -> dict:
    return {"alertUid": uid, "resolved": resolved,
            "alertSourceInfo": {"deviceUid": "dev-1", "deviceName": "EXAMPLE-SRV"},
            "alertContext": {"@class": "srvc_status_ctx", "serviceName": "Spooler",
                             "status": "Stopped"}}


def test_a_recalled_ack_of_one_row_covers_no_other_row_of_the_vendor_alert():
    raise_key = keys.alert_key({"source": "datto"}, _datto("uid-1"))
    resolved_key = keys.alert_key({"source": "datto"}, _datto("uid-1", resolved=True))
    at = NOW - timedelta(minutes=40)
    tv = TenantVerdicts("acme-corp", [ack(10, raise_key, at=NOW - timedelta(minutes=30),
                                          last=at, recalled=True)], [], now=NOW)
    for st in (tv.state(occ(raise_key, event_id=10, first=at)),
               tv.state(occ(resolved_key, event_id=11, first=NOW - timedelta(minutes=5)))):
        assert st.status == OPEN and st.recalled
    # A RocketCyber incident's earlier version: open too.
    rc = keys.alert_key({"source": "rocketcyber", "event_type": "rocketcyber.incident"},
                        {"id": 101, "title": "Suspicious PowerShell Detected"})
    v1, v2 = NOW - timedelta(hours=3), NOW - timedelta(hours=2)
    tv = TenantVerdicts("acme-corp", [ack(20, rc, at=NOW - timedelta(hours=1), last=v2,
                                          recalled=True)], [], now=NOW)
    assert tv.state(occ(rc, event_id=19, first=v1)).status == OPEN


def _ack_id(st: AlertState) -> int | None:
    return st.ack.id if st.ack is not None else None


def test_a_recalled_repeat_ack_hands_nothing_to_another_repeat_ack_made_before_the_recall():
    """Review fix (v0.17.5): two "repeats for 24 h" acks of one device +
    signature both cover a later row — the OLDER decides (the drawer offers
    to recall it); once it is recalled the row is OPEN, not acknowledged by
    the other one (the dialog promised "needs attention"). The other keeps
    its own row; a repeat-ack made AFTER the recall covers what began after
    it."""
    k = ips_key()
    a0 = ack(30, k, at=NOW - timedelta(hours=6), hits=1, last=NOW - timedelta(hours=7),
             repeat=True, vid=1)
    a1 = ack(31, k, at=NOW - timedelta(hours=5), hits=1, last=NOW - timedelta(hours=6),
             repeat=True, vid=2)
    z = occ(k, event_id=41, first=NOW - timedelta(hours=1), hits=2)
    live = TenantVerdicts("acme-corp", [a0, a1], [], now=NOW)
    st = live.state(z)
    assert st.status == ACKED and st.by_repeat and st.ack is not None and st.ack.id == 1
    # The same in any read order (`ensure` adds older acks later).
    late = TenantVerdicts("acme-corp", [a1], [], now=NOW)
    late.add_acks([a0])
    assert _ack_id(late.state(z)) == 1

    recalled_at = NOW - timedelta(minutes=10)
    tv = TenantVerdicts("acme-corp", [replace(a0, recalled_at=iso(recalled_at)), a1], [],
                        now=NOW)
    st = tv.state(z)
    assert st.status == OPEN and not st.hidden and st.recalled
    assert st.ack is not None and st.ack.id == 1                         # the recalled one
    own = tv.state(occ(k, event_id=31, first=NOW - timedelta(hours=6), hits=1,
                       last=NOW - timedelta(hours=6)))
    assert own.status == ACKED and own.ack is not None and own.ack.id == 2
    # A repeat-ack made after the recall covers occurrences that began after it.
    a2 = ack(32, k, at=NOW - timedelta(minutes=5), hits=1, last=NOW - timedelta(minutes=6),
             repeat=True, vid=3)
    tv.add_acks([a2])
    assert tv.state(z).status == OPEN                                    # began before a2
    newer = tv.state(occ(k, event_id=42, first=NOW - timedelta(minutes=2), hits=1))
    assert newer.status == ACKED and newer.ack is not None and newer.ack.id == 3


def _datto_rows(at: datetime):
    raise_key = keys.alert_key({"source": "datto"}, _datto("uid-1"))
    resolved_key = keys.alert_key({"source": "datto"}, _datto("uid-1", resolved=True))
    return (occ(raise_key, event_id=10, first=at),
            occ(resolved_key, event_id=11, first=at + timedelta(minutes=20)),
            raise_key, resolved_key)


def test_re_acknowledging_another_row_after_a_recall_covers_the_recalled_row():
    """Review fix (v0.17.5): the raise's ack is recalled, then the analyst
    acknowledges the RESOLUTION (a new ack, after the recall): it covers the
    raise again — the recalled ack never keeps its own row open against a
    newer ack of the same vendor alert."""
    t = NOW - timedelta(minutes=40)
    raised, resolved, raise_key, resolved_key = _datto_rows(t)
    a = ack(10, raise_key, at=NOW - timedelta(minutes=30), last=t, vid=1)
    a = replace(a, recalled_at=iso(NOW - timedelta(minutes=10)))
    tv = TenantVerdicts("acme-corp", [a], [], now=NOW)
    assert tv.state(raised).status == OPEN and tv.state(resolved).status == OPEN
    b = ack(11, resolved_key, at=NOW - timedelta(minutes=5),
            last=NOW - timedelta(minutes=20), vid=2)
    tv.add_acks([b])
    for row in (raised, resolved):
        st = tv.state(row)
        assert st.status == ACKED and st.ack is not None and st.ack.id == 2, row
    # Without the recall the same acks decide as before (no regression).
    plain = TenantVerdicts("acme-corp", [replace(a, recalled_at=None), b], [], now=NOW)
    assert _ack_id(plain.state(raised)) == 1 and _ack_id(plain.state(resolved)) == 2


def test_a_recalled_ack_that_covered_the_most_hands_over_to_an_ack_made_after_it():
    """The reverse order: the RESOLUTION's ack (the newest row acked: it
    covers the most) is recalled, then the raise is acknowledged again — the
    resolution and any other row of the alert are covered by the new ack."""
    t = NOW - timedelta(minutes=40)
    raised, resolved, raise_key, resolved_key = _datto_rows(t)
    a = ack(11, resolved_key, at=NOW - timedelta(minutes=15),
            last=NOW - timedelta(minutes=20), vid=1)
    a = replace(a, recalled_at=iso(NOW - timedelta(minutes=10)))
    third = occ(resolved_key, event_id=12, first=NOW - timedelta(minutes=8))
    tv = TenantVerdicts("acme-corp", [a], [], now=NOW)
    assert all(tv.state(r).status == OPEN for r in (raised, resolved, third))
    tv.add_acks([ack(10, raise_key, at=NOW - timedelta(minutes=5), last=t, vid=2)])
    for row in (raised, resolved, third):
        st = tv.state(row)
        assert st.status == ACKED and st.ack is not None and st.ack.id == 2, row


def test_an_ack_made_before_the_recall_does_not_take_over_the_recalled_row():
    """The recall is the latest word on the row: another row's ack of the
    same vendor alert made BEFORE the recall keeps ITS row, not the
    recalled one (the dialog said the alert returns to "needs attention")."""
    t = NOW - timedelta(minutes=40)
    raised, resolved, raise_key, resolved_key = _datto_rows(t)
    a = replace(ack(10, raise_key, at=NOW - timedelta(minutes=30), last=t, vid=1),
                recalled_at=iso(NOW - timedelta(minutes=5)))
    b = ack(11, resolved_key, at=NOW - timedelta(minutes=15),
            last=NOW - timedelta(minutes=20), vid=2)                    # before the recall
    tv = TenantVerdicts("acme-corp", [a, b], [], now=NOW)
    st = tv.state(raised)
    assert st.status == OPEN and st.recalled and st.ack is not None and st.ack.id == 1
    assert tv.state(resolved).status == ACKED                            # its own ack


def test_a_rocketcyber_version_recalled_then_a_later_version_acknowledged():
    """Recall the ack of version 1, acknowledge version 2 (after the recall):
    version 1 (an EARLIER version) is covered again; a version after v2
    re-surfaces as before."""
    rc = keys.alert_key({"source": "rocketcyber", "event_type": "rocketcyber.incident"},
                        {"id": 101, "title": "Suspicious PowerShell Detected"})
    v1, v2 = NOW - timedelta(hours=3), NOW - timedelta(hours=2)
    a = replace(ack(19, rc, at=NOW - timedelta(hours=1), last=v1, vid=1),
                recalled_at=iso(NOW - timedelta(minutes=30)))
    tv = TenantVerdicts("acme-corp", [a], [], now=NOW)
    assert tv.state(occ(rc, event_id=19, first=v1)).status == OPEN
    tv.add_acks([ack(20, rc, at=NOW - timedelta(minutes=10), last=v2, vid=2)])
    st = tv.state(occ(rc, event_id=19, first=v1))
    assert st.status == ACKED and st.ack is not None and st.ack.id == 2
    assert tv.state(occ(rc, event_id=21, first=NOW - timedelta(minutes=5))).status == RESURFACED


def test_a_second_recall_after_a_re_acknowledgement_shows_the_latest_recall():
    """Recalled, acknowledged again, recalled again: open, and the drawer
    shows the LATEST recall (the newest word)."""
    k = ips_key()
    seen = NOW - timedelta(minutes=50)
    first = replace(ack(41, k, at=NOW - timedelta(minutes=45), hits=3, last=seen, vid=1),
                    recalled_at=iso(NOW - timedelta(minutes=40)))
    second = replace(ack(41, k, at=NOW - timedelta(minutes=30), hits=3, last=seen, vid=2),
                     recalled_at=iso(NOW - timedelta(minutes=20)))
    tv = TenantVerdicts("acme-corp", [first, second], [], now=NOW)
    st = tv.state(occ(k, hits=3, last=seen))
    assert st.status == OPEN and st.recalled and st.ack is not None and st.ack.id == 2


def test_a_recall_dated_before_its_own_ack_never_loops():
    """A hand-made row whose recall predates its ack (clock skew) still ends:
    open, carrying that recall."""
    k = ips_key()
    seen = NOW - timedelta(minutes=50)
    odd = replace(ack(41, k, at=NOW - timedelta(minutes=10), hits=3, last=seen, vid=1),
                  recalled_at=iso(NOW - timedelta(minutes=30)))
    st = TenantVerdicts("acme-corp", [odd], [], now=NOW).state(occ(k, hits=3, last=seen))
    assert st.status == OPEN and st.recalled


def test_an_expected_rule_is_not_touched_by_a_recall():
    k = ips_key()
    rule = vstore.ExpectedRule(5, "acme-corp", k.source, k.device_key, k.signature_key, None,
                               "label", "known backup traffic", 41, 7,
                               iso(NOW - timedelta(days=1)), iso(NOW + timedelta(days=30)))
    tv = TenantVerdicts("acme-corp", [ack(41, k, at=NOW - timedelta(minutes=30), hits=1,
                                          last=NOW - timedelta(minutes=40), recalled=True)],
                        [rule], now=NOW)
    assert tv.state(occ(k, hits=1, last=NOW - timedelta(minutes=40))).status == EXPECTED


# ---------------------------------------------------------------------------
# The store (a real registry)
# ---------------------------------------------------------------------------

A = "acme-corp"
B = "example-bakery"


def _record(reg, *, slug: str = A, verdict: str = vstore.ACK, event_id: int = 41,
            repeat: bool = False, at: datetime | None = None) -> int:
    k = ips_key()
    when = at or datetime.now(timezone.utc) - timedelta(minutes=5)
    with transaction(reg):
        return vstore.record(reg, slug=slug, event_id=event_id, key=k, verdict=verdict,
                             actor=7, at=when, hits_at=1, last_seen_at=vstore.iso(when),
                             repeat_until=when + timedelta(hours=24) if repeat else None)


def _follow(reg, vid: int, kind: str, text: str, *, slug: str = A,
            at: datetime | None = None) -> int:
    with transaction(reg):
        return vstore.add_followup(reg, verdict_id=vid, slug=slug, kind=kind, actor=8,
                                   text=text, at=at)


def test_the_store_reads_recalls_and_notes_and_the_evaluator_follows(troot):
    reg = connect(paths.registry_db_path())
    try:
        vid = _record(reg)
        other = _record(reg, event_id=42)
        t0 = datetime.now(timezone.utc) - timedelta(minutes=3)
        _follow(reg, vid, vstore.NOTE, "  a partner   removed the agents ", at=t0)
        _follow(reg, vid, vstore.RECALL, "recalled: the partner did it", at=t0 +
                timedelta(minutes=1))
        _follow(reg, vid, vstore.NOTE, "confirmed by phone", at=t0 + timedelta(minutes=2))
    finally:
        reg.close()
    got = {v.id: v for v in vstore.verdicts(A, kinds=(vstore.ACK,))}
    assert got[vid].recalled and not got[other].recalled
    one = vstore.get_verdict(vid)
    assert one is not None and one.recalled_at == vstore.iso(t0 + timedelta(minutes=1))
    assert vstore.get_verdict(other + 999) is None
    fups = vstore.followups(A, [vid, other])
    assert list(fups) == [vid]
    assert [(f.kind, f.text) for f in fups[vid]] == [
        ("note", "a partner removed the agents"), ("recall", "recalled: the partner did it"),
        ("note", "confirmed by phone")]
    assert vstore.followups(B, [vid]) == {}                       # another tenant: nothing
    tv = TenantVerdicts.load(A)
    k = ips_key()
    when = vstore.parse(got[vid].last_seen_at)
    assert when is not None
    assert tv.state(Occurrence(41, k, iso(when), iso(when), 1)).status == OPEN
    assert tv.state(Occurrence(42, k, iso(when), iso(when), 1)).status == ACKED


def test_the_writer_refuses_what_the_api_refuses(troot):
    reg = connect(paths.registry_db_path())
    try:
        vid = _record(reg)
        expected = _record(reg, verdict=vstore.CONFIRMED, event_id=43)
        for kind, text, err in ((vstore.RECALL, "too short", "at least 10"),
                                (vstore.NOTE, "   ", "required"),
                                (vstore.NOTE, "x" * 501, "at most 500"),
                                ("dismiss", "a reason long enough", "one of")):
            with pytest.raises(ValueError, match=err):
                _follow(reg, vid, kind, text)
        with pytest.raises(vstore.FollowUpConflict, match="only an acknowledgement"):
            _follow(reg, expected, vstore.NOTE, "context")
        with pytest.raises(ValueError, match="no such acknowledgement"):
            _follow(reg, vid, vstore.NOTE, "context", slug=B)
        _follow(reg, vid, vstore.RECALL, "the partner removed the agents")
        with pytest.raises(vstore.FollowUpConflict, match="already recalled"):
            _follow(reg, vid, vstore.RECALL, "and once more, to be sure")
        _follow(reg, vid, vstore.NOTE, "a note after the recall is fine")
        assert reg.execute("SELECT COUNT(*) FROM alert_verdict_followup").fetchone()[0] == 2
    finally:
        reg.close()


def test_the_follow_ups_are_append_only_and_the_ack_row_untouched(troot):
    reg = connect(paths.registry_db_path())
    try:
        vid = _record(reg)
        before = tuple(reg.execute("SELECT * FROM alert_verdict WHERE id = ?", (vid,)).fetchone())
        fid = _follow(reg, vid, vstore.RECALL, "the partner removed the agents")
        with pytest.raises(sqlite3.IntegrityError, match="never changed"):
            reg.execute("UPDATE alert_verdict_followup SET text = 'rewritten history' "
                        "WHERE id = ?", (fid,))
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            reg.execute("DELETE FROM alert_verdict_followup")
        after = tuple(reg.execute("SELECT * FROM alert_verdict WHERE id = ?", (vid,)).fetchone())
        assert before == after
    finally:
        reg.close()


def test_unreadable_follow_ups_hide_nothing(troot):
    """A registry whose follow-up table cannot be read answers "no verdict"
    — louder — never a recalled ack that covers again."""
    reg = connect(paths.registry_db_path())
    try:
        _record(reg)
        reg.execute("ALTER TABLE alert_verdict_followup RENAME TO followup_moved_aside")
    finally:
        reg.close()
    assert vstore.verdicts(A) == []
    assert vstore.followups(A, [1]) == {}
    assert vstore.get_verdict(1) is None
    assert TenantVerdicts.load(A).empty
