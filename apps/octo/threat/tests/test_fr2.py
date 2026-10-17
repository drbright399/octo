"""FR2 — detection blindness, measured by INTAKE HEALTH (a poll failing for
> 60 min, the Datto open-alert cap, a stale tier worker), never by event
arrival; fleet-wide → the internal banner + Notice on its tenants;
tenant-specific → Yellow; an open incident is untouched."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from apps.octo.fleet import build
from apps.octo.fleet import state as fs
from apps.octo.fleet.tests.fixtures import FakeManager, stamp_tier_worker
from apps.octo.instances import create_instance, tenant_map, vendor_contact
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.instances.vendor_contact import ContactReporter
from apps.octo.threat import engine, intake, store
from apps.octo.threat.tests.conftest import A, B, notices


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _instance(vendor: str, tenants: list[str]) -> int:
    from apps.octo.adapters.datto.tests.fake_datto import CREDS as DT
    from apps.octo.adapters.nextdns.tests.fake_nextdns import CREDS as ND

    rec = create_instance(vendor_slug=vendor, display_name=vendor.title(),
                          credentials_dict=dict(DT if vendor == "datto" else ND),
                          instance_config={})
    tenant_map.set_mappings(rec.id, [TenantMapping(f"{vendor}-{t}", t, t, "manual")
                                     for t in tenants])
    return rec.id


def test_blindness_is_intake_health_not_event_arrival(troot):
    vendor_contact.reset()
    quiet = _instance("datto", [A, B])
    ContactReporter(quiet, what="test").ok()          # polls succeed; no events at all
    assert [b.source for b in intake.blind_sources(None, _now(), check_worker=False)] == []
    ContactReporter(quiet, what="test").failed("transport", "down")
    assert intake.blind_sources(None, _now() + timedelta(minutes=59), check_worker=False) == []
    (blind,) = intake.blind_sources(None, _now() + timedelta(minutes=61), check_worker=False)
    assert blind.source == "datto" and blind.fleet_wide and set(blind.tenants) == {A, B}
    ContactReporter(quiet, what="test").ok()          # recovered: no longer blind
    assert intake.blind_sources(None, _now() + timedelta(minutes=61), check_worker=False) == []
    vendor_contact.reset()


def test_the_datto_open_list_cap_and_a_stale_worker_are_blindness(troot):
    @dataclass
    class P:
        since: str

        def intake_health(self):
            return {"capped_since": self.since}

    @dataclass
    class Ad:
        poller: P

    vendor_contact.reset()
    dt = _instance("datto", [A])
    mgr = FakeManager()
    mgr.pollers[dt] = P((_now() - timedelta(minutes=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    found = intake.blind_sources(mgr, _now())
    assert {b.source for b in found} == {"datto_cap", "tier_worker"}   # never stamped
    stamp_tier_worker()
    assert {b.source for b in intake.blind_sources(mgr, _now())} == {"datto_cap"}
    vendor_contact.reset()


def test_fleet_wide_is_a_banner_and_a_notice_tenant_specific_is_yellow(troot):
    vendor_contact.reset()
    stamp_tier_worker()
    fleet_dt = _instance("datto", [A, B])
    own_nd = _instance("nextdns", [B])
    for iid in (fleet_dt, own_nd):
        ContactReporter(iid, what="test").failed("transport", "down")
    later = _now() + timedelta(minutes=61)
    stamp_tier_worker(later)
    model = build.build(None, now=later)
    assert {b.source for b in model.blind} == {"datto", "nextdns"}
    by_tenant = {e.tenant_slug: e for e in model.sites}
    a_threat = by_tenant[A].layers["threat"]
    assert a_threat.state == fs.NOTICE
    assert "Athena is blind to Datto RMM since" in a_threat.reasons[0].text
    b_threat = by_tenant[B].layers["threat"]
    assert b_threat.state == fs.WARN                                   # NextDNS is B's own
    assert any("blind to NextDNS here" in r.text for r in b_threat.reasons)
    vendor_contact.reset()


def test_an_integration_mapped_to_no_client_is_the_banner_only(troot):
    """It covers no client: never "security monitoring interrupted" on every
    one of them (an empty tenant list once read as "every tenant")."""
    vendor_contact.reset()
    stamp_tier_worker()
    stray = _instance("nextdns", [])
    _instance("datto", [A])
    ContactReporter(stray, what="test").failed("transport", "down")
    later = _now() + timedelta(minutes=61)
    stamp_tier_worker(later)
    (blind,) = intake.blind_sources(None, later, check_worker=False)
    assert blind.internal and not blind.covers(A) and not blind.covers(B)
    assert "mapped to no client" in blind.why
    model = build.build(None, now=later)
    assert [b.source for b in model.blind] == ["nextdns"]               # the banner
    (entry,) = [e for e in model.sites if e.tenant_slug == A]
    assert entry.layers["threat"].state == fs.OK                        # not painted
    vendor_contact.reset()


def test_fr2_never_touches_an_open_incident(troot):
    vendor_contact.reset()
    dt = _instance("datto", [A])
    ContactReporter(dt, what="test").failed("transport", "down")
    later = _now() + timedelta(minutes=61)
    stamp_tier_worker(later)
    inc = store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key="k",
                              summary="the client called", scope="tenant", opened_by="1",
                              now=later).incident
    model = build.build(None, now=later)
    (entry,) = [e for e in model.sites if e.tenant_slug == A]
    assert entry.verdict.state == fs.BLACK
    assert store.get(A, inc.id).tier == "black" and store.get(A, inc.id).is_open
    vendor_contact.reset()


def test_one_coverage_notice_per_outage(troot):
    from apps.octo.threat.tests.conftest import add_operator

    vendor_contact.reset()
    add_operator("carol", "admin")
    dt = _instance("datto", [A, B])
    ContactReporter(dt, what="test").failed("transport", "down")
    later = _now() + timedelta(minutes=61)
    worker = engine.TierWorker(now=lambda: later)
    worker.run_once()
    worker.run_once()
    (n,) = notices("threat_coverage")
    assert "blind to Datto RMM" in n["title"]
    vendor_contact.reset()
