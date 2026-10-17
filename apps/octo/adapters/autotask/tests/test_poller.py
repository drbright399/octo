"""AutotaskPoller pure-unit tests (P4-c1).

Tests for the picklist translation helpers. Integration tests that
need the DB + auth fixtures live in
`apps/octo/tests/auth/test_autotask_poller.py`."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.adapters.autotask.client import AutotaskPageCapError
from apps.octo.adapters.autotask.poller import (
    autotask_priority_to_severity,
    autotask_status_to_athena,
    format_activity_ts,
    parse_activity_ts,
)
from apps.octo.adapters.autotask.tests.fake_autotask_query import FakeAutotaskQuery


# ---------------------------------------------------------------------------
# AW03 static maps (TODO(zack): verify — slice 1 replaces them with the mirror)
# ---------------------------------------------------------------------------

def test_inbound_priority_aw03():
    """AW03: 1 High, 2 Medium, 3 Low, 4 Critical, 5 Informational. The factory
    map read priority 4 (Critical here) as "low"."""
    assert autotask_priority_to_severity(4) == "critical"
    assert autotask_priority_to_severity(1) == "high"
    assert autotask_priority_to_severity(2) == "medium"
    assert autotask_priority_to_severity(3) == "low"
    assert autotask_priority_to_severity(5) == "info"


def test_priority_unknown_keeps_previous_else_medium():
    assert autotask_priority_to_severity(999) == "medium"
    assert autotask_priority_to_severity(None) == "medium"
    assert autotask_priority_to_severity(999, previous="critical") == "critical"
    assert autotask_priority_to_severity(None, previous="low") == "low"


def test_priority_to_severity_cache_overrides_defaults():
    """When the autotask_picklist_cache is populated, per-instance
    integer-id translations win over the static defaults."""
    cache = {1: "critical", 42: "critical"}
    assert autotask_priority_to_severity(42, cache=cache) == "critical"
    assert autotask_priority_to_severity(1, cache=cache) == "critical"


def test_inbound_status_aw03():
    """11 (Escalated) is never resolved; 7 is waiting on the customer; an
    unknown id keeps the previous Athena status instead of falling to new."""
    assert autotask_status_to_athena(1) == "new"
    for v in (8, 10, 11, 21, 22, 26, 28, 29):
        assert autotask_status_to_athena(v) == "in_progress", v
    for v in (7, 19, 23, 24, 25):
        assert autotask_status_to_athena(v) == "waiting_customer", v
    for v in (9, 17):
        assert autotask_status_to_athena(v) == "waiting_vendor", v
    for v in (5, 20, 27):
        assert autotask_status_to_athena(v) == "resolved", v
    assert autotask_status_to_athena(11) != "resolved"
    assert autotask_status_to_athena(11, previous="resolved") == "in_progress"
    # Unknown (12 / 13 were the factory "closed" / "reopened"): keep previous.
    for unknown in (12, 13, 999, None):
        assert autotask_status_to_athena(unknown, previous="waiting_vendor") == "waiting_vendor"
        assert autotask_status_to_athena(unknown, previous="resolved") == "resolved"
    # No previous (a brand-new mirror row): new.
    assert autotask_status_to_athena(999) == "new"
    assert autotask_status_to_athena(None) == "new"


def test_status_to_athena_cache_overrides_defaults():
    cache = {99: "in_progress", 1: "closed"}
    assert autotask_status_to_athena(99, cache=cache) == "in_progress"
    assert autotask_status_to_athena(1, cache=cache) == "closed"


# ---------------------------------------------------------------------------
# Cursor timestamps
# ---------------------------------------------------------------------------

def test_activity_timestamps_parse_any_precision_as_utc_instants():
    a = parse_activity_ts("2026-10-05T14:22:31.1234567Z")      # .NET: 7 digits
    b = parse_activity_ts("2026-10-05T14:22:31.123Z")
    c = parse_activity_ts("2026-10-05T09:22:31.9-05:00")
    d = parse_activity_ts("2026-10-05T14:22:31")                # no zone: UTC
    assert a is not None and b is not None and c is not None and d is not None
    assert a > b and c > a and d < b
    assert c.utcoffset() == timedelta(0)
    for bad in (None, "", "yesterday", 42, "2026-13-40T99:00:00Z"):
        assert parse_activity_ts(bad) is None
    assert format_activity_ts(datetime(2026, 10, 5, 14, 22, 31, 123999, tzinfo=timezone.utc)) \
        == "2026-10-05T14:22:31.123Z"


# ---------------------------------------------------------------------------
# Catch-up: query_all windows, split in half over the page cap
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _ts(minutes_ago: float) -> str:
    return format_activity_ts(_NOW - timedelta(minutes=minutes_ago))


def _catchup_poller(client, **kw):
    from apps.octo.adapters.autotask.poller import AutotaskPoller

    kw.setdefault("initial_ticket_cursor", _ts(24 * 60))
    kw.setdefault("initial_note_cursor", _ts(24 * 60))
    return AutotaskPoller(client=client, adapter_instance_id=7, max_batch=2, max_pages=2,
                          proposals_every_sec=0, persist_cursors=False,
                          now=lambda: _NOW, **kw)


def test_catchup_bisects_over_cap_window(monkeypatch):
    """Ten changed tickets, a cap of 4 rows (2 pages x 2): the open window is
    over the cap, so the poller halves it (by time) until a half fits, reads
    that half WHOLE, moves the cursor to its end, and goes on — every row is
    seen exactly once and the cursor never jumps past an unread row."""
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})   # all unmapped
    tickets = [{"id": i, "companyID": 1, "status": 1, "priority": 2,
                "lastActivityDate": _ts(600 - 60 * i)} for i in range(10)]
    client = FakeAutotaskQuery(tickets=tickets)
    p = _catchup_poller(client)
    p.tick_once()

    assert p.last_cycle_tickets_caught_up is True
    assert p.last_cycle_tickets_skipped == 10                 # each row exactly once
    assert p.ticket_cursor == tickets[-1]["lastActivityDate"]
    windows = client.windows("Tickets")
    # First the open window — over the cap, refused whole.
    assert windows[0] == (_ts(24 * 60), None)
    assert client.answered[0] is False
    read = client.read_windows("Tickets")
    closed = [w for w in read if w[1] is not None]
    assert closed, "an over-cap window must be split, not skipped"
    # The windows actually read tile the time line with no gap: each starts
    # exactly where the previous one ended, from the old cursor to the open
    # window that finished the catch-up.
    assert read[0][0] == _ts(24 * 60)
    for (lo_a, hi_a), (lo_b, _hi_b) in zip(read, read[1:]):
        assert hi_a is not None and lo_b == hi_a
        assert parse_activity_ts(lo_a) < parse_activity_ts(hi_a) <= _NOW
    assert read[-1][1] is None
    # The notes ran too (tickets caught up first).
    assert client.windows("TicketNotes")


def test_catchup_resumes_next_tick_when_the_read_budget_runs_out(monkeypatch):
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    tickets = [{"id": i, "companyID": 1, "lastActivityDate": _ts(600 - 60 * i)}
               for i in range(10)]
    client = FakeAutotaskQuery(tickets=tickets)
    p = _catchup_poller(client, max_windows_per_tick=3)
    p.tick_once()
    assert p.last_cycle_tickets_caught_up is False
    assert p.last_cycle_windows == 3                          # the per-tick bound
    # The notes wait while the tickets are behind (a note's parent may not
    # have landed yet).
    assert client.windows("TicketNotes") == []
    cursors = [p.ticket_cursor]
    assert parse_activity_ts(cursors[0]) > parse_activity_ts(_ts(24 * 60))
    seen = p.last_cycle_tickets_skipped
    for _ in range(20):
        if p.last_cycle_tickets_caught_up:
            break
        p.tick_once()
        seen += p.last_cycle_tickets_skipped
        cursors.append(p.ticket_cursor)
    assert p.last_cycle_tickets_caught_up is True
    assert seen == 10                                         # every row once, none twice
    assert p.ticket_cursor == tickets[-1]["lastActivityDate"]
    stamps = [parse_activity_ts(c) for c in cursors]
    assert stamps == sorted(stamps)                           # never moves back
    assert client.windows("TicketNotes")                      # once caught up


def test_catchup_floor_window_reads_a_bulk_edit_whole(monkeypatch):
    """Rows touched within one second beyond the cap: the window cannot be
    split further, so it is read with the floor's larger page allowance."""
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    at = _NOW - timedelta(minutes=5)
    tickets = [{"id": i, "companyID": 1,
                "lastActivityDate": format_activity_ts(at + timedelta(milliseconds=i))}
               for i in range(9)]
    client = FakeAutotaskQuery(tickets=tickets)
    p = _catchup_poller(client, max_windows_per_tick=200, initial_ticket_cursor=_ts(10))
    p.tick_once()
    assert p.last_cycle_tickets_caught_up is True
    assert p.last_cycle_tickets_skipped == 9
    assert any(mp == mod.FLOOR_MAX_PAGES for e, _, _, mp in client.calls if e == "Tickets")


def test_catchup_floor_still_over_cap_is_loud(monkeypatch):
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    monkeypatch.setattr(mod, "FLOOR_MAX_PAGES", 2)
    at = _NOW - timedelta(minutes=5)
    tickets = [{"id": i, "companyID": 1, "lastActivityDate": format_activity_ts(at)}
               for i in range(9)]
    p = _catchup_poller(FakeAutotaskQuery(tickets=tickets), max_windows_per_tick=200,
                        initial_ticket_cursor=_ts(10))
    with pytest.raises(AutotaskPageCapError):
        p.tick_once()
    # It may move up to the bulk edit (everything before it was read whole),
    # never past a row it has not read.
    assert parse_activity_ts(p.ticket_cursor) < at


def test_first_run_starts_at_the_lookback(monkeypatch):
    from apps.octo.adapters.autotask import poller as mod
    from apps.octo.adapters.autotask.poller import AutotaskPoller

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    client = FakeAutotaskQuery()
    p = AutotaskPoller(client=client, adapter_instance_id=7, persist_cursors=False,
                       proposals_every_sec=0, initial_lookback_days=30, now=lambda: _NOW)
    p.tick_once()
    assert client.windows("Tickets")[0] == (format_activity_ts(_NOW - timedelta(days=30)), None)


def _secs(seconds_ago: float) -> str:
    return format_activity_ts(_NOW - timedelta(seconds=seconds_ago))


def test_catchup_near_now_never_puts_the_cursor_at_a_local_clock_window_end(monkeypatch):
    """A bulk edit in the last minutes, over the cap: the windows the split
    produces end within SETTLE_LAG of the LOCAL clock. The cursor must follow
    the rows actually read (Autotask's clock), not those windows' ends — or a
    row stamped before such an end but visible only after the read (a clock
    ahead of Autotask's, a bulk edit still being written) is skipped for good."""
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    tickets = [{"id": i, "companyID": 1, "lastActivityDate": _secs(90 - i)}
               for i in range(5)]                                 # 90..86 s ago
    client = FakeAutotaskQuery(tickets=tickets)
    p = _catchup_poller(client, initial_ticket_cursor=_secs(100))
    p.tick_once()
    assert p.last_cycle_tickets_caught_up is True
    assert p.last_cycle_tickets_skipped == 5
    read = client.read_windows("Tickets")
    assert any(hi is not None for _lo, hi in read)                # it did split
    assert all(parse_activity_ts(hi) > _NOW - mod.SETTLE_LAG
               for _lo, hi in read if hi is not None)             # all near "now"
    assert p.ticket_cursor == _secs(86)                           # the newest row read
    # Read ahead, now visible: stamped before the windows' ends, after the
    # cursor. The next tick finds it.
    client.rows["Tickets"].append({"id": 99, "companyID": 1, "lastActivityDate": _secs(60)})
    p.tick_once()
    assert p.last_cycle_tickets_skipped == 1
    assert p.ticket_cursor == _secs(60)


def test_catchup_settled_window_moves_the_cursor_to_its_end(monkeypatch):
    """Long before "now" a window that was read whole is final: the cursor
    moves to its end even when it was empty (an empty history is crossed in
    a few reads, not re-read every tick)."""
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    tickets = [{"id": i, "companyID": 1, "lastActivityDate": _ts(600 - 60 * i)}
               for i in range(10)]
    client = FakeAutotaskQuery(tickets=tickets)
    p = _catchup_poller(client, max_windows_per_tick=2)
    p.tick_once()
    (_lo, hi), = [w for w in client.read_windows("Tickets")]
    assert hi == _ts(12 * 60)                     # (24 h ago, 12 h ago]: no rows
    assert p.ticket_cursor == hi


# ---------------------------------------------------------------------------
# The daily site-location proposals (scheduling only — the refresh itself is
# apps/octo/proposals/tests)
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _poller(clock, *, due, runs, every=24 * 3600.0, instance_id=3):
    from apps.octo.adapters.autotask.poller import AutotaskPoller

    def run(client, iid):
        runs.append(iid)
        return {"created": 1}

    return AutotaskPoller(client=FakeAutotaskQuery(), adapter_instance_id=instance_id,
                          proposals_every_sec=every, proposals_first_check_sec=600.0,
                          proposals_due=due, proposals_refresh=run, clock=clock,
                          persist_cursors=False)


def test_location_proposals_run_daily_after_a_first_delay(monkeypatch):
    from apps.octo.adapters.autotask import poller as mod

    monkeypatch.setattr(mod, "load_tenant_routing", lambda _iid: {})
    clock, runs, asked = _Clock(), [], []

    def due(iid, every):
        asked.append(every)
        return len(runs) == 0                         # due once, then fresh

    p = _poller(clock, due=due, runs=runs)
    p.tick_once()
    assert runs == [] and asked == []                 # the first check waits 10 min
    clock.now += 601
    p.tick_once()
    assert runs == [3] and asked == [24 * 3600.0]
    assert p.last_proposals_summary == {"created": 1}
    clock.now += 60
    p.tick_once()
    assert asked == [24 * 3600.0]                     # re-checked hourly, not per tick
    clock.now += 3600
    p.tick_once()
    assert len(asked) == 2 and runs == [3]            # checked: not due


def test_location_proposals_never_break_the_ticket_poll():
    clock, runs = _Clock(), []

    def broken(_iid, _every):
        raise RuntimeError("registry hiccup")

    p = _poller(clock, due=broken, runs=runs)
    clock.now += 601
    assert p.maybe_refresh_location_proposals() is False
    assert runs == []
    # Off: 0, or a poller with no persisted instance.
    assert _poller(clock, due=lambda *_: True, runs=runs, every=0)\
        .maybe_refresh_location_proposals() is False
    clock.now += 601
    assert _poller(clock, due=lambda *_: True, runs=runs, instance_id=0)\
        .maybe_refresh_location_proposals() is False
    assert runs == []
