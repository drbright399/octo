"""Review round 3, item 5: a gateway-sourced alert in a profile with NextDNS
app devices waits for T's presence hour — readable only about 65 minutes
after the hour starts — so finalising it after a flat 30 minutes stamped
`lookup_stale` on it while every feed was healthy (a stale pill for 20-35
minutes, app PCs still listed). Now the finalise deadline knows when the
presence hour is due: the answer stays `provisional` (no stale pill) until
the hour is due + slack, and is final WITHOUT `lookup_stale` once it is read."""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo.entity import resolver as rv
from apps.octo.entity.tests.conftest import A, T0, world  # noqa: F401
from apps.octo.entity.tests.test_hardening import APP, _app_site, _device_hour, _worker
from apps.octo.entity.tests.test_resolver import _block_event


def _current(world, eid):  # noqa: F811
    return world.one("SELECT * FROM resolution WHERE event_id = ? AND status <> 'superseded'",
                     (eid,))


def test_the_presence_hour_is_waited_for_until_it_is_due_never_stale_before(world):  # noqa: F811
    _app_site(world)
    _device_hour(world, "2026-10-01T13:00:00Z", [{**APP, "queries": 180}], T0.replace(minute=5))
    eid = _block_event(world)                                      # 14:17:05
    _worker(T0.replace(minute=20, second=30)).run_tenant(A)
    for at in (T0.replace(minute=48), T0.replace(minute=59), T0.replace(hour=15, minute=4)):
        _worker(at).run_tenant(A)
        cur = _current(world, eid)
        assert cur["status"] == "provisional", at
        flags = json.loads(cur["flags"])
        assert "lookup_stale" not in flags and "app_presence_pending" in flags
    # 15:05 — the hour is read (the app reported in it): final, never stale.
    _device_hour(world, "2026-10-01T14:00:00Z", [{**APP, "queries": 120}],
                 T0.replace(hour=15, minute=5))
    _worker(T0.replace(hour=15, minute=6)).run_tenant(A)
    cur = _current(world, eid)
    assert cur["status"] == "final" and "lookup_stale" not in json.loads(cur["flags"])
    assert json.loads(cur["chain"])[-1]["out"]["excluded"] == \
        {"dns_bypasses_nextdns": 5, "nextdns_app_device": 1}
    history = world.rows("SELECT status, flags FROM resolution WHERE event_id = ? ORDER BY "
                         "created_at", (eid,))
    assert not any("lookup_stale" in r["flags"] for r in history)


def test_a_presence_hour_that_never_comes_is_finalised_stale_after_due_plus_slack(world):  # noqa: F811
    _app_site(world)
    _device_hour(world, "2026-10-01T13:00:00Z", [{**APP, "queries": 180}], T0.replace(minute=5))
    eid = _block_event(world)
    _worker(T0.replace(minute=20, second=30)).run_tenant(A)
    due = rv.finalise_deadline(T0.replace(minute=17, second=5), rv.parse_waits(
        _current(world, eid)["lookup_watermark"]))
    assert due == T0 + rv.PRESENCE_READ_AFTER + rv.PRESENCE_SLACK     # 14:00 + 65 + 20 min
    _worker(due - timedelta(minutes=1)).run_tenant(A)
    assert _current(world, eid)["status"] == "provisional"
    _worker(due + timedelta(minutes=1)).run_tenant(A)
    cur = _current(world, eid)
    assert cur["status"] == "final" and "lookup_stale" in json.loads(cur["flags"])


def test_an_answer_waiting_only_for_unifi_still_finalises_after_30_minutes(world):  # noqa: F811
    waits = [("unifi.clients", "h/s", None, "2026-10-01T14:17:30.000Z")]
    at = T0.replace(minute=17, second=5)
    assert rv.finalise_deadline(at, waits) == at + rv.FINALISE_AFTER


def test_the_presence_lag_matches_the_nextdns_pollers_hourly_delay():
    from apps.octo.adapters.nextdns import poller as nd_poller

    assert rv.PRESENCE_READ_AFTER == timedelta(hours=1, seconds=nd_poller.HOURLY_DELAY_SEC)
