"""The TierWorker skeleton: a pass pages the open incidents, stamps an
incident visible to the client's users after 60 unacknowledged minutes,
writes its heartbeat, and NEVER closes or lowers anything (there is no code
path for it); a poked tenant runs at once; a tenant that fails never stops
the others."""
from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

from apps.octo.threat import engine, intake, store
from apps.octo.threat.tests.conftest import A, B, add_operator, notices

T0 = datetime(2026, 10, 3, 15, 0, tzinfo=timezone.utc)


def _open(slug: str, tier: str, key: str) -> store.Incident:
    return store.open_incident(slug, tier=tier, rule_id="B6" if tier == "black" else "R8",
                               rule_version=1, key=key, summary="x", scope="tenant",
                               opened_by="1", now=T0).incident


def test_a_pass_pages_stamps_visibility_and_beats(troot):
    add_operator("alice", "analyst", [A])
    black = _open(A, "black", "k1")
    clock = {"now": T0}
    worker = engine.TierWorker(now=lambda: clock["now"])
    out = worker.run_once()
    assert out[A]["paged"] == 1 and notices("threat_black")
    assert intake.worker_fresh(T0)
    assert store.get(A, black.id).client_visible_at is None
    clock["now"] = T0 + timedelta(minutes=61)
    out = worker.run_once()
    assert out[A]["visible"] == 1
    assert store.get(A, black.id).client_visible_at == "2026-10-03T16:01:00.000Z"
    assert not intake.worker_fresh(T0 + timedelta(minutes=61 + 3))


def test_the_engine_never_closes_or_lowers(troot):
    black, red = _open(A, "black", "k1"), _open(B, "red", "k2")
    worker = engine.TierWorker(now=lambda: T0 + timedelta(days=40))
    for _ in range(3):
        worker.run_once()
    for slug, inc in ((A, black), (B, red)):
        after = store.get(slug, inc.id)
        assert after.is_open and after.tier == inc.tier          # 40 days: no decay
    src = inspect.getsource(engine)
    for forbidden in ("store.close(", "store.reclassify(", "tier = 'red'", "status = 'closed'"):
        assert forbidden not in src, forbidden


def test_a_poke_runs_one_tenant_and_a_failing_tenant_never_stops_the_others(troot,
                                                                           monkeypatch):
    worker = engine.TierWorker(now=lambda: T0)
    engine.set_current(worker)
    try:
        engine.poke(A)
        assert worker._poked == {A}
    finally:
        engine.set_current(None)
    real = worker.run_tenant

    def flaky(slug, now, *, tenant_name):
        if slug == A:
            raise RuntimeError("one tenant's store is broken")
        return real(slug, now, tenant_name=tenant_name)

    monkeypatch.setattr(worker, "run_tenant", flaky)
    out = worker.run_once()
    assert out[A] == {"error": 1} and "error" not in out[B]
    only = worker.run_once({B})
    assert set(only) == {B}
