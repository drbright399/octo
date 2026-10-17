"""LIFE-SAFETY FIRST (Rick, 2026-10-02 23:21): "911 and life saving systems
should NEVER be blocked." A lockdown request — the client's or an
analyst's — can never include a life_safety-tagged asset or path: they are
listed as EXCLUDED, by name, with "911 / life-safety systems are never
blocked"; a request that cannot read the tag list is not built at all; and
nothing executes in slice 1."""
from __future__ import annotations

import pytest

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.threat import lockdown, registry
from apps.octo.threat.tests.conftest import A, B


def _tag(slug: str, ref: str, tag: str = "life_safety", kind: str = "device") -> None:
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            registry.add_tag(reg, slug=slug, ref_kind=kind, device_ref=ref, tag=tag, set_by=7,
                             reason="911 dispatch console")
    finally:
        reg.close()


def test_a_lockdown_request_never_includes_a_life_safety_asset(troot):
    _tag(A, "dispatch-01")
    _tag(A, "192.0.2.0/24", kind="path")                           # the dispatch network
    _tag(A, "ws-02", tag="dev")                                    # not a life-safety tag
    # The incident is ON the 911 console, and an analyst asks for more.
    req = lockdown.build(A, device_ref="DISPATCH-01", site_key=None, extra_targets=[
        {"kind": "device", "ref": "dispatch-01"}, {"kind": "path", "ref": "192.0.2.0/24"},
        {"kind": "device", "ref": "ws-02"}])
    refs = {t["ref"].lower() for t in req.scope}
    assert "dispatch-01" not in refs and "192.0.2.0/24" not in refs
    # ws-02 is a NAME at a tenant whose 911 path is tagged by ADDRESS:
    # nothing here can tell whether it sits on that path — kept out of scope
    # and marked for an analyst's check (fail closed).
    assert refs == set()
    assert {(e["kind"], e["ref"]) for e in req.excluded if not e.get("unverified")} == {
        ("device", "dispatch-01"), ("path", "192.0.2.0/24")}
    assert all(e["why"] == "911 / life-safety systems are never blocked"
               for e in req.excluded if not e.get("unverified"))
    (check,) = [e for e in req.excluded if e.get("unverified")]
    assert check["ref"] == "ws-02" and "analyst" in check["why"] and req.needs_review
    assert req.notice == "911 / life-safety systems are never blocked"
    assert req.executes is False
    assert lockdown.never_includes_life_safety(req, A)


def test_a_name_only_tenant_keeps_other_devices_in_scope(troot):
    _tag(A, "dispatch-01")
    req = lockdown.build(A, device_ref="ws-02", site_key=None)
    assert req.scope == [{"kind": "device", "ref": "ws-02"}] and not req.needs_review
    assert lockdown.never_includes_life_safety(req, A)


@pytest.mark.parametrize("device", [
    "dispatch-01.example.local",                 # the FQDN of a tagged short name
    "DISPATCH-01.EXAMPLE.LOCAL.",
    "CORP\\dispatch-01",                         # DOMAIN\host
])
def test_any_spelling_of_a_tagged_host_is_carved_out(troot, device):
    _tag(A, "DISPATCH-01")
    req = lockdown.build(A, device_ref=device, site_key=None)
    assert req.scope == []
    assert any(e.get("matched") and e["ref"] == device for e in req.excluded)
    # The invariant uses the same comparison: forcing it into scope is caught.
    forced = lockdown.LockdownRequest(scope=[{"kind": "device", "ref": device}])
    assert not lockdown.never_includes_life_safety(forced, A)


@pytest.mark.parametrize("target", [
    {"kind": "device", "ref": "192.0.2.167"},    # an address ON the tagged network
    {"kind": "path", "ref": "192.0.0.0/16"},     # a network that overlaps it
    {"kind": "device", "ref": "ip:192.0.2.9"},   # R6's device reference
])
def test_an_address_or_network_touching_a_tagged_path_is_carved_out(troot, target):
    _tag(A, "192.0.2.0/24", kind="path")
    req = lockdown.build(A, device_ref=None, site_key="u-0123456789abcdef0123",
                         extra_targets=[target])
    assert target not in req.scope
    assert req.scope == [{"kind": "site_perimeter", "ref": "u-0123456789abcdef0123"}]
    forced = lockdown.LockdownRequest(scope=[target])
    assert not lockdown.never_includes_life_safety(forced, A)


def test_a_target_with_no_comparable_identity_is_never_assumed_clear(troot):
    _tag(A, "dispatch-01")
    uid = "0b5e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"            # a vendor device id
    req = lockdown.build(A, device_ref=uid, site_key=None)
    assert req.scope == [] and req.needs_review
    forced = lockdown.LockdownRequest(scope=[{"kind": "device", "ref": uid}])
    assert not lockdown.never_includes_life_safety(forced, A)


def test_a_life_safety_tag_must_name_a_host_or_an_address(troot):
    with pytest.raises(ValueError, match="address or a network"):
        registry.validate_tag(ref_kind="path", device_ref="example-vlan 20", tag="life_safety")
    with pytest.raises(ValueError, match="host name or an address"):
        registry.validate_tag(ref_kind="device", device_ref="0b5e2f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
                              tag="life_safety")
    registry.validate_tag(ref_kind="path", device_ref="192.0.2.0/24", tag="life_safety")
    registry.validate_tag(ref_kind="device", device_ref="DISPATCH-02", tag="life_safety")
    # Other tags keep free text (a NIC description, say).
    registry.validate_tag(ref_kind="device", device_ref="ws-09 NIC2", tag="hands_off")


@pytest.mark.parametrize("device", ["dispatch-01", "Dispatch-01 ", "DISPATCH-01"])
def test_the_carve_out_is_exact_and_case_blind(troot, device):
    _tag(A, "dispatch-01")
    req = lockdown.build(A, device_ref=device, site_key=None)
    assert req.scope == [] and req.excluded[0]["ref"] == "dispatch-01"


def test_every_tagged_asset_of_the_tenant_is_named_even_off_target(troot):
    _tag(A, "dispatch-01")
    _tag(B, "ems-radio-01")                                        # another tenant's
    req = lockdown.build(A, device_ref=None, site_key="u-0123456789abcdef0123")
    assert req.scope == [{"kind": "site_perimeter", "ref": "u-0123456789abcdef0123"}]
    assert [e["ref"] for e in req.excluded] == ["dispatch-01"]      # never B's


def test_a_cleared_tag_no_longer_protects_and_an_unreadable_list_refuses(troot,
                                                                         monkeypatch):
    _tag(A, "dispatch-01")
    reg = connect(paths.registry_db_path())
    try:
        tid = reg.execute("SELECT id FROM asset_tag").fetchone()[0]
        with transaction(reg):
            registry.clear_tag(reg, tid, by=7, reason="decommissioned console")
    finally:
        reg.close()
    assert lockdown.build(A, device_ref="dispatch-01", site_key=None).excluded == []

    def broken(*_a, **_kw):
        raise registry.RegistryUnavailable("OperationalError")

    monkeypatch.setattr(registry, "asset_tags", broken)
    with pytest.raises(lockdown.LockdownRefused, match="never blocked"):
        lockdown.build(A, device_ref="ws-01", site_key=None)


def test_the_record_can_never_be_executed(troot):
    from apps.octo.threat import store

    inc = store.open_incident(A, tier="black", rule_id="B6", rule_version=1, key="k1",
                              summary="x", scope="tenant", opened_by="7").incident
    d = store.record_decision(A, inc.id, kind="lockdown", requested_by="7",
                              requested_role="analyst", status="recorded", scope=[],
                              excluded=[{"kind": "device", "ref": "dispatch-01"}],
                              notice=lockdown.LIFE_SAFETY_NOTICE)
    assert d["executed"] == 0 and d["excluded"][0]["ref"] == "dispatch-01"
    import sqlite3

    conn = sqlite3.connect(paths.client_dir(A) / "events.db", isolation_level=None)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE incident_decisions SET executed = 1")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE incident_decisions SET excluded_json = '[]'")
    finally:
        conn.close()
