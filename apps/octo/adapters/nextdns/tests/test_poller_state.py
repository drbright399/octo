"""What the NextDNS poller writes to the registry to survive a restart — and
how often. A measurement found ~540 MB/day of state JSON at about 50 active
profiles (the whole state rewritten after nearly every task). Pinned:

  * only CHANGED per-profile rows are written, batched at the end of a cycle
    and never more than once per 30 s — a steady fleet of 50 active
    profiles stays under 5 MB/day, night-dark offices included (their 48 h
    of per-hour evidence is packed as one bitmask per list);
  * crash / restart safety is kept: a protection signal is only written
    after the state that records it is durable (an outbox), so a crash at
    any point neither duplicates it nor loses it; security marks never
    leave a gap (test_poller.py).
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from apps.octo.adapters.nextdns import poller as poller_module
from apps.octo.adapters.nextdns.presentation import EVENT_LAPSED
from apps.octo.adapters.nextdns.tests.fake_nextdns import T0, hour_of
from apps.octo.instances import poller_state, tenant_map
from apps.octo.instances.tenant_map import TenantMapping

ACME = "acme-corp"


class _Writes:
    """Every registry write of poller state: (fake-clock time, keys, bytes)."""

    def __init__(self, world, monkeypatch) -> None:
        self.rows: list[tuple[float, list[str], int]] = []
        for name in ("save", "save_many"):
            real = getattr(poller_state, name, None)
            if real is None:
                continue

            def wrapped(instance_id, *args, _real=real, _name=name, **kwargs):
                if _name == "save":
                    keys, size = [args[0]], len(json.dumps(args[1], separators=(",", ":")))
                else:
                    values = args[0]
                    keys = sorted(values)
                    size = sum(len(json.dumps(v, separators=(",", ":"))) for v in values.values())
                self.rows.append((world.clock.monotonic(), keys, size))
                return _real(instance_id, *args, **kwargs)
            monkeypatch.setattr(poller_state, name, wrapped)

    @property
    def bytes(self) -> int:
        return sum(size for _t, _k, size in self.rows)

    def gaps(self) -> list[float]:
        at = [t for t, _k, _s in self.rows]
        return [b - a for a, b in zip(at, at[1:])]


def _sites(world, n: int, *, pending: int = 0) -> list[str]:
    ids = [f"s{i:05d}" for i in range(n + pending)]
    world.transport.profiles = [{"id": pid, "name": f"Site {pid}", "role": "owner"}
                                for pid in ids]
    for pid in ids[:n]:
        world.transport.set_rate(pid)
    tenant_map.set_mappings(world.record.id, [TenantMapping(pid, ACME, None, "manual")
                                              for pid in ids])
    return ids


def test_state_is_written_as_changed_rows_at_most_every_30_seconds(world, monkeypatch):
    _sites(world, 10)
    writes = _Writes(world, monkeypatch)
    poller = world.poller()
    world.run_for(poller, 3600)                                  # warm-up
    start, start_bytes = world.clock.monotonic(), writes.bytes
    world.run_for(poller, 3 * 3600)
    span = world.clock.monotonic() - start
    assert min(writes.gaps()) >= 30.0
    per_profile_day = (writes.bytes - start_bytes) / span * 86400 / 10
    projected_mb = per_profile_day * 50 / 1e6
    print(f"\nstate writes: {len(writes.rows)} in {span / 3600:.1f} h, "
          f"projected {projected_mb:.2f} MB/day at 50 active profiles")
    assert projected_mb < 5.0


def test_an_unchanged_profile_row_is_not_rewritten(world, monkeypatch):
    ids = _sites(world, 1, pending=1)                            # one active, one pending
    writes = _Writes(world, monkeypatch)
    poller = world.poller()
    world.run_for(poller, 2 * 3600)
    active_key = poller_module.profile_state_key(ids[0])
    pending_key = poller_module.profile_state_key(ids[1])
    written = [keys for _t, keys, _s in writes.rows]
    assert sum(active_key in keys for keys in written) >= 10    # its marks move
    # The pending profile changed once (classified) — within 6 h nothing more.
    assert sum(pending_key in keys for keys in written) == 1
    assert poller_state.load(world.record.id, pending_key)["state"] == "pending"


def _dark_before_watch(world) -> None:
    t = world.transport
    t.set_rate("abc123")
    h = hour_of(T0 - timedelta(hours=72))
    while h < T0 + timedelta(hours=24):
        t.silence("abc123", h)
        h += timedelta(hours=1)
    world.map(abc123=ACME)


def test_a_crash_before_the_state_is_saved_raises_the_lapse_exactly_once(world, monkeypatch):
    _dark_before_watch(world)

    def died(*_a, **_k):
        raise RuntimeError("fixture: the process died before its state was saved")
    with monkeypatch.context() as m:
        for name in ("save", "save_many"):
            if hasattr(poller_state, name):
                m.setattr(poller_state, name, died)
        crashing = world.poller()
        with pytest.raises(RuntimeError):
            crashing.run_cycle()
    world.clock.advance(3600)                                    # restarted an hour later
    world.run_for(world.poller(), 3600)
    [lapse] = world.events(ACME, EVENT_LAPSED)
    assert json.loads(lapse["payload"])["cause"] == "before_watch"


def test_a_crash_after_the_state_is_saved_delivers_the_lapse_once(world, monkeypatch):
    _dark_before_watch(world)
    crashing = world.poller()

    def died(*_a, **_k):
        raise RuntimeError("fixture: the process died while writing the alert")
    monkeypatch.setattr(crashing, "_ingest", died)
    with pytest.raises(RuntimeError):
        crashing.run_cycle()
    assert world.events(ACME, EVENT_LAPSED) == []
    # The state (LAPSED, the alert still to write) is durable already.
    state = poller_state.load(world.record.id, poller_module.profile_state_key("abc123"))
    assert state["state"] == "lapsed" and state["outbox"]
    world.clock.advance(600)
    fresh = world.poller()
    fresh.run_cycle()                                            # delivers it
    [lapse] = world.events(ACME, EVENT_LAPSED)
    # A crash right after that write (before the cleared outbox is saved):
    # the next start delivers it again — and finds the same alert.
    state = poller_state.load(world.record.id, poller_module.profile_state_key("abc123"))
    assert state["outbox"]
    world.run_for(world.poller(), 3600)
    assert [r["id"] for r in world.events(ACME, EVENT_LAPSED)] == [lapse["id"]]
    state = poller_state.load(world.record.id, poller_module.profile_state_key("abc123"))
    assert not state.get("outbox") and state["lapse"]["event_id"] == lapse["id"]


def test_night_dark_sites_at_steady_state_stay_under_5_mb_a_day(world, monkeypatch):
    """Offices dark 18:00-06:00 UTC with 3 weeks of baseline: every row
    carries up to 48 h of per-hour evidence (zero / failed-read hours)
    and is rewritten about every 10 minutes (its security mark moves). The
    evidence is stored compactly, so steady state stays under 5 MB/day."""
    ids = _sites(world, 10)
    for pid in ids:
        for h in list(range(18, 24)) + list(range(0, 6)):
            world.transport.of(pid).rate_by_hour_of_day[h] = {
                "default": 0, "blocked": 0, "allowed": 0}
        world.seed_baseline(pid, ACME)
    writes = _Writes(world, monkeypatch)
    poller = world.poller()
    world.run_for(poller, 48 * 3600)                             # warm-up: lists full
    rows = poller_state.load_prefix(world.record.id, poller_module.PROFILE_KEY_PREFIX)
    biggest = max(len(json.dumps(v, separators=(",", ":"))) for v in rows.values())
    start, start_bytes = world.clock.monotonic(), writes.bytes
    world.run_for(poller, 24 * 3600)
    span = world.clock.monotonic() - start
    projected_mb = (writes.bytes - start_bytes) / span * 86400 / 10 * 50 / 1e6
    print(f"\nnight-dark: row up to {biggest} bytes, projected {projected_mb:.2f} MB/day "
          "at 50 active profiles")
    assert world.events(ACME, EVENT_LAPSED) == []
    assert biggest < 700
    assert projected_mb < 5.0
