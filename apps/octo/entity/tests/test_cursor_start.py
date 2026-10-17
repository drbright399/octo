"""Review round 3, item 4: switching a client on does not resolve its whole
history. The sweep's cursor started at 0, so the first pass after switch-on
wrote a 'final / none' answer for every alert ever stored (300 alerts up to
60 days old in the probe) — answers with nothing behind them, since lookups
only exist from switch-on. Now a tenant's cursor starts at the newest event
(OCTO_ENTITY_SWEEP_HISTORY_DAYS = 0, the default), or N days back; and a
switch turned off → on starts it there again."""
from __future__ import annotations

from datetime import timedelta

from apps.octo.entity import switch
from apps.octo.entity import worker as worker_mod
from apps.octo.entity.tests.conftest import A, T0, iso, nextdns_block, store_event, world  # noqa: F401
from apps.octo.entity.worker import EntityWorker


def _history(days: int = 60, per_day: int = 5) -> list[int]:
    ids = []
    for d in range(days, 0, -1):
        for k in range(per_day):
            at = T0 - timedelta(days=d) + timedelta(minutes=k * 7)
            ids.append(store_event(A, "nextdns", "nextdns.security_block",
                                   nextdns_block(at, domain=f"h{d}-{k}.bad.example"), iso(at)))
    return ids


def test_switching_a_client_on_starts_at_its_newest_event(world, monkeypatch):  # noqa: F811
    monkeypatch.delenv(worker_mod.HISTORY_ENV, raising=False)
    world.set_mode(A, "off")
    ids = _history()
    world.set_mode(A, "on")                                  # as PUT /mode does
    w = EntityWorker(now=world.clock.now)
    assert w.run_once()[A]["scanned"] == 0
    assert world.rows("SELECT * FROM resolution") == []
    assert world.one("SELECT last_event_id FROM resolver_cursor")["last_event_id"] == max(ids)
    fresh = store_event(A, "nextdns", "nextdns.security_block",
                        nextdns_block(T0, domain="new.bad.example"), iso(T0))
    world.clock.advance(60)
    assert w.run_once()[A]["scanned"] == 1
    assert [r["event_id"] for r in world.rows("SELECT event_id FROM resolution")] == [fresh]


def test_the_history_window_is_configurable(world, monkeypatch):  # noqa: F811
    monkeypatch.setenv(worker_mod.HISTORY_ENV, "7")
    world.set_mode(A, "off")
    _history(days=20, per_day=2)
    world.set_mode(A, "on")
    out = EntityWorker(now=world.clock.now).run_once()
    assert out[A]["scanned"] == 7 * 2                       # the last 7 days only


def test_a_switch_turned_off_and_on_again_starts_at_the_newest_event(world, monkeypatch):  # noqa: F811
    monkeypatch.delenv(worker_mod.HISTORY_ENV, raising=False)
    store_event(A, "nextdns", "nextdns.security_block",
                nextdns_block(T0, domain="first.bad.example"), iso(T0))
    w = EntityWorker(now=world.clock.now)
    w.run_once()                                             # the cursor exists (on)
    switch.set_mode(A, "off")
    ids = _history(days=3)
    switch.set_mode(A, "on")
    worker_mod.switched(A, "off", "on")                      # what PUT /mode calls
    world.clock.advance(60)
    assert w.run_once()[A]["scanned"] == 0
    assert world.one("SELECT last_event_id FROM resolver_cursor")["last_event_id"] == max(ids)


def test_a_tenant_without_a_cursor_starts_at_its_newest_event_too(world, monkeypatch):  # noqa: F811
    """Switched on outside PUT /mode (no cursor written): the first pass
    takes the same start point — never 0."""
    monkeypatch.delenv(worker_mod.HISTORY_ENV, raising=False)
    switch.set_mode(A, "off")
    ids = _history(days=5)
    switch.set_mode(A, "on")
    with world.db().write() as conn:
        conn.execute("DELETE FROM resolver_cursor")
    assert EntityWorker(now=world.clock.now).run_once()[A]["scanned"] == 0
    assert world.one("SELECT last_event_id FROM resolver_cursor")["last_event_id"] == max(ids)


def test_bad_history_settings_fall_back_to_the_newest_event(monkeypatch):
    for raw in ("", "x", "-3", "400"):
        monkeypatch.setenv(worker_mod.HISTORY_ENV, raw)
        assert worker_mod.history_days() in (0, worker_mod.MAX_HISTORY_DAYS)
    monkeypatch.setenv(worker_mod.HISTORY_ENV, "400")
    assert worker_mod.history_days() == worker_mod.MAX_HISTORY_DAYS
