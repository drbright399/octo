"""The attested single-person tenant merge / offboard (v0.10 item 7) — on the
real app, real registry, real audit chain, real step-up, real Resend client
(only its HTTP transport faked).

Pins the owner's decisions (2026-09-28):
  - two-person approval is the DEFAULT for merge and offboard, for every
    role; an admin only ever files a request;
  - a super_admin may apply one ALONE only as an explicit attested
    exception: a typed attestation (≥ 40 characters, stored verbatim), the
    subject slug confirmed SERVER-side, an active step-up window — each
    missing piece refused with its own error, and nothing written;
  - the single-person merge is refused (409, offering the two-person request)
    when the target's EFFECTIVE AI policy is more permissive than the
    subject's, or the subject carries a compliance regime the target lacks;
    the two-person fallback then works as ever (and unions the flags);
  - the change record says single_attested and keeps the attestation and the
    typed slug; the audit chain is loudly flagged (approval_mode on the
    change row + a distinct *_single_attested marker — the hash, not the
    text);
  - every OTHER active admin+ is told in-app (never the actor), by e-mail
    when a Resend integration is configured; a notification failure never
    blocks or rolls back the change, and is recorded;
  - the optional post-hoc review is by a second person only;
  - the merge caveats the console shows are what the code does.
"""
from __future__ import annotations

import hashlib
import inspect
import json

import pyotp
import pytest
import requests

from apps.octo import paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.agent import worker
from apps.octo.api.routers import admin_notices, admin_tenants
from apps.octo.auth import operator_notices
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import ai_policy, create_instance
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)
from apps.octo.tests.auth.test_admin_tenants import (  # noqa: F401
    PW,
    TENANTS,
    _api_alert,
    _audit_actions,
    _chain_ok,
    _client_row,
    _events,
    _mint_token,
    _set_scope,
    app,
)

NOTICES = "/api/v1/admin/notices"
ATTESTATION = (
    "Auto-created duplicate of the same customer from a second vendor site; "
    "I compared both tenants' tags and AI policy today."
)
MERGE = f"{TENANTS}/acme-dup/merge-into/acme-corp"
OFFBOARD = f"{TENANTS}/acme-dup/offboard"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _op(app, name: str, role: str, *, elevate: bool = False) -> dict:
    """An operator's cookies (optionally stepped up through the real
    /search/elevate) + its id."""
    op = app.provision_operator(name, PW, athena_role=role)
    cookies = app.login(op)
    if elevate:
        r = app.post("/api/v1/search/elevate", json={
            "current_password": PW, "totp_code": pyotp.TOTP(op["totp_secret_b32"]).now(),
        }, cookies=cookies)
        assert r.status_code == 200, r.text
    return {"cookies": cookies, "id": op["id"]}


def _alone(slug: str = "acme-dup", reason: str = "same customer", **over) -> dict:
    return {"reason": reason, "approval_mode": "single_attested",
            "attestation": ATTESTATION, "confirm_subject": slug, **over}


def _event(slug: str, n: int) -> None:
    SqliteIngestSink(publish_to_stream=False).ingest(
        slug, "datto", DattoSourceAdapter().extract_event(_api_alert(n, site_uid=f"site-{n}")))


def _pair(*, s_policy: str = "none", t_policy: str = "none", s_flags: str = "[]",
          t_flags: str = "[]") -> None:
    """acme-dup (an auto-created duplicate holding one event) and acme-corp."""
    create_client("acme-corp", "Acme Corp", kind="client", ai_policy=t_policy,
                  compliance_flags_json=t_flags)
    create_client("acme-dup", "Acme Corp (dup)", origin="auto", ai_policy=s_policy,
                  compliance_flags_json=s_flags)
    _event("acme-dup", 1)


def _rows(sql: str, args: tuple = ()) -> list[dict]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return [dict(r) for r in reg.execute(sql, args).fetchall()]
    finally:
        reg.close()


def _requests() -> list[dict]:
    return _rows("SELECT * FROM tenant_change_requests ORDER BY id")


def _notices() -> list[dict]:
    return _rows("SELECT * FROM operator_notices ORDER BY id")


def _audit(action: str) -> list[dict]:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return [
            {**dict(r), "before": json.loads(r["before_state"]) if r["before_state"] else None,
             "after": json.loads(r["after_state"]) if r["after_state"] else None}
            for r in g.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,))
        ]
    finally:
        g.close()


def _all_audit_text() -> str:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return "\n".join(
            f"{r['before_state']} {r['after_state']} {r['reason']}"
            for r in g.execute("SELECT before_state, after_state, reason FROM audit_log")
        )
    finally:
        g.close()


def _audit_count() -> int:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return int(g.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
    finally:
        g.close()


def _state(subject: str = "acme-dup", target: str = "acme-corp") -> dict:
    """Everything a refused request must leave exactly as it was."""
    return {
        "requests": _requests(), "notices": _notices(), "audit_rows": _audit_count(),
        "subject": _client_row(subject)["status"],
        "target_flags": _client_row(target)["compliance_flags"],
        "target_events": len(_events(target)),
    }


def _sign(app, root: dict, slug: str, flags: list[str]) -> int:
    """A cloud-AI compliance sign-off through the real route (workstream A)."""
    r = app.post(f"{TENANTS}/{slug}/compliance-signoff", json={
        "agreement_references": {k: f"AGR-{k}-2026-001" for k in ai_policy.agreement_keys(flags)},
        "attestation_text": "I checked this tenant's tags today; the agreements on file cover cloud.",
        "attestation_version": ai_policy.ATTESTATION_VERSION, "acknowledge_flags": flags,
    }, cookies=root["cookies"])
    assert r.status_code == 201, r.text
    return r.json()["signoff"]["id"]


# ---------------------------------------------------------------------------
# Who may do what
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role, expect", [
    ("viewer", 403),
    ("analyst", 403),
    (None, 401),                          # unauthenticated
])
def test_below_admin_and_unauthenticated_reach_none_of_it(app, role, expect):
    _pair()
    create_client("gone-co", "Gone Co", kind="client")
    root = _op(app, "root1", "super_admin", elevate=True)
    rid = app.post(MERGE, json=_alone(), cookies=root["cookies"]).json()["change_request_id"]
    nid = _notices()[0]["id"] if _notices() else 1
    if role is None:
        app.cookies.clear()
        cookies = None
    else:
        # Stepped up, so a refusal is the ROLE rule, never the step-up one.
        cookies = _op(app, f"{role}1", role, elevate=True)["cookies"]
        app.cookies.clear()
    before = _state("gone-co")
    calls = [
        ("post", f"{TENANTS}/gone-co/offboard", _alone("gone-co")),
        ("post", f"{TENANTS}/gone-co/offboard", {"reason": "contract ended"}),
        ("post", f"{TENANTS}/gone-co/merge-into/acme-corp", _alone("gone-co")),
        ("post", f"{TENANTS}/gone-co/merge-into/acme-corp", {"reason": "same customer"}),
        ("get", f"{TENANTS}/gone-co/merge-into/acme-corp/preview", None),
        ("get", f"{TENANTS}/requests?state=all&approval_mode=single_attested", None),
        ("post", f"{TENANTS}/requests/{rid}/post-review", {"verdict": "ok", "note": "looked fine"}),
        ("get", NOTICES, None),
        ("post", f"{NOTICES}/{nid}/acknowledge", None),
    ]
    for method, url, body in calls:
        r = (app.post(url, json=body, cookies=cookies) if method == "post"
             else app.get(url, cookies=cookies))
        want = expect
        if role == "analyst" and url.startswith(NOTICES):
            # Tier Black: an analyst reads their OWN inbox (threat paging);
            # another admin's notice is not theirs — the same 404.
            want = 200 if method == "get" else 404
        assert r.status_code == want, (url, r.text)
    assert _state("gone-co") == before


def test_an_admin_only_ever_files_a_request(app):
    _pair()
    admin = _op(app, "admin1", "admin", elevate=True)       # even stepped up
    before = _state()
    for url in (MERGE, OFFBOARD):
        r = app.post(url, json=_alone(), cookies=admin["cookies"])
        assert r.status_code == 403 and r.json()["code"] == "ISOLATION_VIOLATION", r.text
        assert "two-person request" in r.json()["message"]
    assert _state() == before
    r = app.post(MERGE, json={"reason": "same customer"}, cookies=admin["cookies"])
    assert r.status_code == 202, r.text
    req = r.json()["request"]
    assert (req["approval_mode"], req["attestation"], req["post_review_state"]) == (
        "two_person", None, "not_requested")


def test_two_person_is_the_default_for_a_super_admin_too(app):
    """No approval_mode = a request — a super_admin included — which a
    DIFFERENT super_admin approves; the apply row says so."""
    _pair()
    create_client("gone-co", "Gone Co", kind="client")
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(MERGE, json={"reason": "same customer"}, cookies=root["cookies"])
    assert r.status_code == 202 and r.json()["applied"] is False, r.text
    rid = r.json()["request"]["id"]
    r = app.post(f"{TENANTS}/gone-co/offboard", json={"reason": "contract ended"},
                 cookies=root["cookies"])
    assert r.status_code == 202 and r.json()["request"]["approval_mode"] == "two_person"
    assert _client_row("acme-dup")["status"] == "active"
    assert _client_row("gone-co")["status"] == "active"
    assert [a["after"]["approval_mode"] for a in _audit("tenant_change_request_create")] == [
        "two_person", "two_person"]
    assert _notices() == []                       # nothing applied, nobody to tell yet
    # Not their own approval …
    assert app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root["cookies"]).status_code == 409
    # … a second super_admin's.
    root2 = _op(app, "root2", "super_admin")
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root2["cookies"])
    assert r.status_code == 200 and r.json()["state"] == "applied", r.text
    (row,) = _audit("tenant_merge")
    assert (row["after"]["approval_mode"], row["after"]["change_request_id"],
            row["after"]["requested_by"]) == ("two_person", rid, root["id"])
    assert row["actor"] == str(root2["id"]) and _chain_ok()


@pytest.mark.parametrize("url", [MERGE, OFFBOARD], ids=["merge", "offboard"])
def test_each_missing_piece_is_refused_with_its_own_error_and_nothing_is_written(app, url):
    _pair()
    stepped = _op(app, "root1", "super_admin", elevate=True)
    fresh = _op(app, "root2", "super_admin")                 # never stepped up
    before = _state()
    padded = " " * 10 + "x" * 39 + " " * 10                  # 59 raw, 39 typed
    cases = [
        (stepped, _alone(attestation=None), 422, "ATTESTATION_REQUIRED"),
        (stepped, _alone(attestation=""), 422, "ATTESTATION_REQUIRED"),
        (stepped, _alone(attestation=padded), 422, "ATTESTATION_REQUIRED"),
        (stepped, _alone(confirm_subject=None), 422, "SUBJECT_CONFIRMATION_MISMATCH"),
        (stepped, _alone(confirm_subject="ACME-DUP"), 422, "SUBJECT_CONFIRMATION_MISMATCH"),
        (stepped, _alone(confirm_subject="acme-dup "), 422, "SUBJECT_CONFIRMATION_MISMATCH"),
        (stepped, _alone(confirm_subject="acme-corp"), 422, "SUBJECT_CONFIRMATION_MISMATCH"),
        (fresh, _alone(), 401, "STEP_UP_REQUIRED"),
        (stepped, _alone(approval_mode="solo"), 422, "VALIDATION_FAILED"),
    ]
    for who, body, status, code in cases:
        r = app.post(url, json=body, cookies=who["cookies"])
        assert (r.status_code, r.json()["code"]) == (status, code), (body, r.text)
    r = app.post(url, json=_alone(attestation=padded), cookies=stepped["cookies"])
    assert "at least 40 characters (39 given)" in r.json()["message"]
    r = app.post(url, json=_alone(confirm_subject="acme-corp"), cookies=stepped["cookies"])
    assert "exactly 'acme-dup'" in r.json()["message"]
    assert _state() == before
    # Every piece present: it applies.
    r = app.post(url, json=_alone(), cookies=stepped["cookies"])
    assert r.status_code == 200 and r.json()["applied"] is True, r.text


# ---------------------------------------------------------------------------
# What a single-person change leaves on record
# ---------------------------------------------------------------------------

def test_the_change_record_and_the_audit_chain_say_single_attested_loudly(app):
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    typed = "  The integration created this duplicate; I compared both tenants today.\n"
    r = app.post(MERGE, json=_alone(attestation=typed), cookies=root["cookies"])
    assert r.status_code == 200, r.text
    body = r.json()
    (rec,) = _requests()
    assert {k: rec[k] for k in (
        "kind", "subject_slug", "target_slug", "requested_by", "decided_by", "state",
        "approval_mode", "attestation", "subject_confirmation", "post_review_state",
        "post_reviewed_by", "reason")} == {
        "kind": "merge", "subject_slug": "acme-dup", "target_slug": "acme-corp",
        "requested_by": root["id"], "decided_by": root["id"], "state": "applied",
        "approval_mode": "single_attested", "attestation": typed,        # verbatim
        "subject_confirmation": "acme-dup", "post_review_state": "pending",
        "post_reviewed_by": None, "reason": "same customer",
    }
    assert (body["change_request_id"], body["post_review_state"], body["approval_mode"]) == (
        rec["id"], "pending", "single_attested")
    assert _client_row("acme-dup")["status"] == "archived" and len(_events("acme-corp")) == 1

    (merge_row,) = _audit("tenant_merge")
    assert (merge_row["after"]["approval_mode"], merge_row["after"]["change_request_id"]) == (
        "single_attested", rec["id"])
    (marker,) = _audit("tenant_merge_single_attested")
    assert (marker["actor"], marker["target_kind"], marker["target_id"], marker["client_slug"]) == (
        str(root["id"]), "tenant_change_request", str(rec["id"]), "acme-dup")
    after = marker["after"]
    assert after["attestation_sha256"] == hashlib.sha256(typed.encode()).hexdigest()
    assert (after["attestation_chars"], after["subject_confirmation"], after["step_up"]) == (
        len(typed), "acme-dup", True)
    assert after["eligibility"] == {
        "subject_effective_ai_policy": "none", "target_effective_ai_policy": "none",
        "subject_flags_not_on_target": []}
    assert after["events_copied"] == 1 and after["notified"] == {
        "recipients": [], "notices": [], "error": None}
    assert marker["reason"] == (
        "SINGLE-PERSON MERGE — attested exception, no second approver: same customer")
    assert _audit_actions() == ["tenant_merge", "tenant_merge_single_attested"]
    # The typed text lives on the change record — never in the chain.
    assert typed.strip() not in _all_audit_text() and _chain_ok()
    # Nothing sits in the two-person queue, and an applied record cannot be
    # approved, rejected or cancelled after the fact.
    assert app.get(f"{TENANTS}/requests", cookies=root["cookies"]).json()["requests"] == []
    for decision in ("approve", "reject", "cancel"):
        r = app.post(f"{TENANTS}/requests/{rec['id']}/{decision}", cookies=root["cookies"])
        assert r.status_code == 409, r.text
    # The requests panel's list of single-person changes carries it.
    (listed,) = app.get(f"{TENANTS}/requests?state=all&approval_mode=single_attested",
                        cookies=root["cookies"]).json()["requests"]
    assert (listed["id"], listed["attestation"], listed["post_review_state"]) == (
        rec["id"], typed, "pending")
    assert app.get(f"{TENANTS}/requests?approval_mode=solo",
                   cookies=root["cookies"]).status_code == 422


def test_exactly_forty_typed_characters_is_enough(app):
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(MERGE, json=_alone(attestation="y" * 40), cookies=root["cookies"])
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Eligibility guards (owner-accepted) and the two-person fallback
# ---------------------------------------------------------------------------

def test_refused_when_the_target_runs_ai_more_permissively_then_two_people_can(app):
    """The STORED policies are equal ('cloud'); what RUNS is not: the
    subject was never tagged, so its cloud waits for a sign-off and runs as
    local, while the target is tagged 'none' and runs as cloud. The guard
    reads the effective policies — and answers before any re-auth prompt."""
    _pair(s_policy="cloud", s_flags="[]", t_policy="cloud", t_flags='["none"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    fresh = _op(app, "root2", "super_admin")                 # not stepped up
    before = _state()
    for who in (root, fresh):
        r = app.post(MERGE, json=_alone(), cookies=who["cookies"])
        assert (r.status_code, r.json()["code"]) == (409, "SINGLE_PERSON_INELIGIBLE"), r.text
    msg = r.json()["message"]
    # Honest about WHY: the subject asks for cloud too, it is just unsigned —
    # and it says what would let one person merge.
    assert "acme-corp runs AI as 'cloud'; acme-dup asks for 'cloud' but runs as 'local'" in msg
    assert "To merge alone: sign acme-dup off for [] first" in msg
    assert "or merge acme-corp into acme-dup instead (keeps acme-dup)" in msg
    assert "Or file a two-person request" in msg and "super admin other than you" in msg
    assert _state() == before
    # The preview says so before anyone clicks.
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()
    assert p["single_person"]["eligible"] is False and p["caller_may_apply_alone"] is True
    assert [x["code"] for x in p["single_person"]["reasons"]] == ["target_ai_more_permissive"]
    assert (p["single_person"]["subject_effective_ai_policy"],
            p["single_person"]["target_effective_ai_policy"]) == ("local", "cloud")
    assert p["single_person"]["reasons"][0]["remedy"].startswith("sign acme-dup off for [] first")
    assert p["single_person"]["other_super_admins"] == 1
    # The fallback the refusal offered: a two-person request, approved by
    # the other super_admin, applies.
    r = app.post(MERGE, json={"reason": "same customer"}, cookies=root["cookies"])
    assert r.status_code == 202 and r.json()["request"]["approval_mode"] == "two_person"
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve",
                 cookies=fresh["cookies"])
    assert r.status_code == 200, r.text
    assert _client_row("acme-dup")["status"] == "archived"
    assert _audit("tenant_merge")[0]["after"]["approval_mode"] == "two_person"
    assert _audit("tenant_merge_single_attested") == []


def test_the_guards_read_effective_policy_not_the_stored_one(app):
    """Stored target 'cloud' vs stored subject 'local' looks more permissive,
    but the unsigned target runs as local: one person may merge. And a
    signed subject may merge alone into a signed target — until its own
    sign-off is revoked and it runs as local."""
    create_client("acme-corp", "Acme Corp", kind="client", ai_policy="cloud",
                  compliance_flags_json='["hipaa"]')
    create_client("acme-dup", "Acme Dup", origin="auto", ai_policy="local",
                  compliance_flags_json='["hipaa"]')
    create_client("acme-west", "Acme West", kind="client", ai_policy="cloud",
                  compliance_flags_json='["hipaa"]')
    for slug, n in (("acme-dup", 1), ("acme-west", 2)):
        _event(slug, n)
    root = _op(app, "root1", "super_admin", elevate=True)
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()["single_person"]
    assert (p["eligible"], p["subject_effective_ai_policy"], p["target_effective_ai_policy"]) == (
        True, "local", "local")
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 200, r.text

    # Both signed → both run as cloud → one person may merge them …
    _sign(app, root, "acme-corp", ["hipaa"])
    west_signoff = _sign(app, root, "acme-west", ["hipaa"])
    west = f"{TENANTS}/acme-west/merge-into/acme-corp"
    assert app.get(f"{west}/preview", cookies=root["cookies"]).json()["single_person"][
        "eligible"] is True
    # … until the subject's sign-off goes: it runs as local, the target as cloud.
    r = app.post(f"{TENANTS}/acme-west/compliance-signoff/{west_signoff}/revoke",
                 json={"reason": "BAA lapsed"}, cookies=root["cookies"])
    assert r.status_code == 200, r.text
    r = app.post(west, json=_alone("acme-west"), cookies=root["cookies"])
    assert r.status_code == 409, r.text
    assert (f"acme-west asks for 'cloud' but runs as 'local' (sign-off #{west_signoff} was "
            "revoked — sign off again)") in r.json()["message"]


def test_refused_when_the_subject_carries_a_regime_the_target_lacks_then_two_people_union_it(app):
    _pair(s_flags='["pci"]', t_flags='["hipaa"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    before = _state()
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert (r.status_code, r.json()["code"]) == (409, "SINGLE_PERSON_INELIGIBLE"), r.text
    assert "acme-dup is tagged [pci] and acme-corp is not" in r.json()["message"]
    assert _state() == before
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()
    assert p["target_flags_added"] == ["pci"]
    assert [x["code"] for x in p["single_person"]["reasons"]] == ["subject_flags_not_on_target"]
    # Two people: the regime is unioned onto the target (workstream A).
    r = app.post(MERGE, json={"reason": "same customer"}, cookies=root["cookies"])
    assert r.status_code == 202, r.text
    root2 = _op(app, "root2", "super_admin")
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve", cookies=root2["cookies"])
    assert r.status_code == 200, r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa", "pci"]
    (row,) = _audit("tenant_merge")
    assert (row["after"]["target_flags_added"], row["after"]["approval_mode"]) == (
        ["pci"], "two_person")


def test_both_guards_are_named_when_both_apply(app):
    _pair(s_flags='["cjis"]', t_policy="local", t_flags='["hipaa"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()["single_person"]
    assert [x["code"] for x in p["reasons"]] == [
        "target_ai_more_permissive", "subject_flags_not_on_target"]
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 409 and r.json()["message"].count(" — ") >= 2


def test_the_guards_run_again_under_the_write_lock(app, monkeypatch):
    """The pair is checked read-only BEFORE the re-authentication prompt, and
    again inside the write transaction: whatever changed while the operator
    stepped up (here another admin tags the subject [pci], which the target
    lacks) is caught there — 409, nothing written."""
    _pair(t_flags='["hipaa"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    real = admin_tenants.require_step_up

    def step_up_then_someone_retags(request, caller):  # noqa: ANN001
        info = real(request, caller)
        reg = connect(paths.registry_db_path())
        reg.execute("UPDATE clients SET compliance_flags = '[\"pci\"]' WHERE slug = 'acme-dup'")
        reg.commit()
        reg.close()
        return info

    monkeypatch.setattr(admin_tenants, "require_step_up", step_up_then_someone_retags)
    before = _state()
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert (r.status_code, r.json()["code"]) == (409, "SINGLE_PERSON_INELIGIBLE"), r.text
    assert "acme-dup is tagged [pci] and acme-corp is not" in r.json()["message"]
    assert _state() == before                       # no record, no audit, no events moved
    assert _client_row("acme-dup")["status"] == "active"


def test_an_offboarded_subject_is_never_merged_alone(app):
    """Its frozen site mappings would be re-pointed into the target — a
    departed client's traffic flowing again — so two people decide."""
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(OFFBOARD, json=_alone(reason="contract ended"), cookies=root["cookies"])
    assert r.status_code == 200, r.text
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()["single_person"]
    assert p["eligible"] is False
    assert [x["code"] for x in p["reasons"]] == ["subject_not_active"]
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert (r.status_code, r.json()["code"]) == (409, "SINGLE_PERSON_INELIGIBLE"), r.text
    assert "acme-dup is offboarded — its frozen site mappings would be re-pointed" in (
        r.json()["message"])


def test_a_lone_super_admin_is_told_the_two_person_request_cannot_be_approved(app):
    """With no other super admin, offering the two-person request as the
    way out is a dead end: the refusal says so, and names what would make
    the single-person path apply instead."""
    _pair(s_flags='["glba"]', t_flags='[]')
    root = _op(app, "root1", "super_admin", elevate=True)
    p = app.get(f"{MERGE}/preview", cookies=root["cookies"]).json()["single_person"]
    assert p["other_super_admins"] == 0
    (reason,) = p["reasons"]
    assert reason["remedy"].startswith("tag acme-corp with [glba] first")
    msg = app.post(MERGE, json=_alone(), cookies=root["cookies"]).json()["message"]
    assert "To merge alone: tag acme-corp with [glba] first" in msg
    assert "this deployment has none" in msg and "Or file a two-person request" not in msg


def test_a_subject_tagged_none_or_untagged_adds_nothing_and_may_merge_alone(app):
    create_client("acme-corp", "Acme Corp", kind="client", compliance_flags_json='["hipaa"]')
    create_client("acme-dup", "Acme Dup", origin="auto", compliance_flags_json='["none"]')
    _event("acme-dup", 1)
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 200 and r.json()["target_flags_added"] == [], r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa"]


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def _set_operator(op_id: int, column: str) -> None:
    reg = connect(paths.registry_db_path())
    reg.execute(f"UPDATE operators SET {column} = '2026-09-28T00:00:00.000Z' WHERE id = ?", (op_id,))
    reg.commit()
    reg.close()


def test_every_other_admin_is_told_in_app_and_mail_not_configured_is_recorded(app):
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    root2 = _op(app, "root2", "super_admin")
    admin1 = _op(app, "admin1", "admin")
    _set_operator(_op(app, "admin2", "admin")["id"], "disabled_at")
    _set_operator(_op(app, "admin3", "admin")["id"], "removed_at")
    analyst = _op(app, "analyst1", "analyst")
    _op(app, "viewer1", "viewer")

    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 200, r.text
    assert r.json()["notifications"] == {"recipients": 2, "in_app_error": None, "email": "queued"}
    rid = r.json()["change_request_id"]
    notices = _notices()
    # The OTHER active admin+ — never the actor, an analyst, a viewer, a
    # disabled or a removed account.
    assert sorted(n["recipient_id"] for n in notices) == sorted([root2["id"], admin1["id"]])
    for n in notices:
        assert (n["kind"], n["actor_id"], n["subject_slug"], n["target_slug"],
                n["change_request_id"]) == ("single_attested_merge", root["id"], "acme-dup",
                                            "acme-corp", rid)
        assert n["title"] == "Single-person merge: acme-dup → acme-corp"
        assert f"root1 (operator #{root['id']}) merged acme-dup into acme-corp" in n["body"]
        assert "Reason: same customer" in n["body"] and ATTESTATION not in n["body"]
        # No Resend integration: recorded, nothing attempted.
        assert (n["email_state"], n["email_attempted_at"]) == ("not_configured", None)
    (mail,) = _audit("operator_notice_email")
    assert mail["actor"] == "system" and mail["target_id"] == str(rid)
    assert sorted(mail["after"]["not_configured"]) == sorted([root2["id"], admin1["id"]])
    assert mail["after"]["sent"] == [] and "not configured" in mail["reason"]
    (marker,) = _audit("tenant_merge_single_attested")
    assert sorted(marker["after"]["notified"]["recipients"]) == sorted([root2["id"], admin1["id"]])

    # The recipient sees it on next load; the actor does not.
    mine = app.get(NOTICES, cookies=admin1["cookies"]).json()
    assert mine["open"] == 1 and mine["notices"][0]["title"].startswith("Single-person merge")
    assert app.get(NOTICES, cookies=root["cookies"]).json() == {"notices": [], "open": 0}
    # An analyst's inbox (Tier Black paging) never holds a tenant change.
    assert app.get(NOTICES, cookies=analyst["cookies"]).json() == {"notices": [], "open": 0}
    nid = mine["notices"][0]["id"]
    # Another admin's notice is not theirs to acknowledge.
    assert app.post(f"{NOTICES}/{nid}/acknowledge", cookies=root2["cookies"]).status_code == 404
    r = app.post(f"{NOTICES}/{nid}/acknowledge", cookies=admin1["cookies"])
    assert r.status_code == 200 and r.json()["acknowledged_at"], r.text
    again = app.post(f"{NOTICES}/{nid}/acknowledge", cookies=admin1["cookies"])
    assert again.json()["acknowledged_at"] == r.json()["acknowledged_at"]
    (ack,) = _audit("operator_notice_acknowledge")                 # once
    assert (ack["actor"], ack["target_id"], ack["after"]["change_request_id"]) == (
        str(admin1["id"]), str(nid), rid)
    assert app.get(NOTICES, cookies=admin1["cookies"]).json()["open"] == 0
    assert len(app.get(f"{NOTICES}?include_acknowledged=1",
                       cookies=admin1["cookies"]).json()["notices"]) == 1
    assert app.get(NOTICES, cookies=root2["cookies"]).json()["open"] == 1
    assert _chain_ok()


def test_mail_goes_through_a_configured_resend_integration_and_a_failed_send_is_recorded(
    app, monkeypatch,
):
    create_instance(vendor_slug="resend", display_name="Resend", credentials_dict={
        "RESEND_API_KEY": "re_fixture_only", "RESEND_DOMAIN": "example.test",
        "RESEND_FROM": "Athena <athena@example.test>",
    })
    sent: list[tuple[str, dict]] = []

    def fake_socket(self, request, **kwargs):  # noqa: ANN001 — HTTPAdapter.send's shape
        body = json.loads(request.body)
        sent.append((request.url, body))
        if body["to"] == ["admin1@example.test"]:
            raise requests.ConnectionError("fixture: connection refused")
        resp = requests.Response()
        resp.status_code = 200
        resp._content = json.dumps({"id": f"msg-{len(sent)}"}).encode()
        resp.headers["Content-Type"] = "application/json"
        resp.url, resp.request = request.url, request
        return resp

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_socket)
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    root2 = _op(app, "root2", "super_admin")
    admin1 = _op(app, "admin1", "admin")
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    # A failed e-mail never fails (or rolls back) the merge.
    assert r.status_code == 200 and _client_row("acme-dup")["status"] == "archived", r.text
    rid = r.json()["change_request_id"]
    assert [u for u, _ in sent] == ["https://api.resend.com/emails"] * 2
    assert sorted(b["to"][0] for _, b in sent) == ["admin1@example.test", "root2@example.test"]
    for _, b in sent:
        assert b["from"] == "Athena <athena@example.test>"
        assert b["subject"] == f"Athena: single-person tenant merge applied (change #{rid})"
        assert f"Applied by: operator #{root['id']}" in b["text"]
        # Mail transits a third-party provider: no tenant names, no attestation.
        for secret in ("acme-dup", "acme-corp", "Acme", ATTESTATION):
            assert secret not in b["text"] and secret not in b["subject"]
    states = {n["recipient_id"]: n for n in _notices()}
    assert states[root2["id"]]["email_state"] == "sent" and states[root2["id"]]["email_attempted_at"]
    assert states[admin1["id"]]["email_state"] == "failed"
    (mail,) = _audit("operator_notice_email")
    assert (mail["after"]["sent"], mail["after"]["failed"]) == ([root2["id"]], [admin1["id"]])
    assert mail["reason"] == "e-mail copy: 1 sent, 1 failed, 0 without an address"
    # The key went into an Authorization header, never into the chain.
    assert "re_fixture_only" not in _all_audit_text() and _chain_ok()


def test_a_notice_failure_never_blocks_the_change_and_is_recorded(app):
    _pair()
    root = _op(app, "root1", "super_admin", elevate=True)
    admin1 = _op(app, "admin1", "admin")
    reg = connect(paths.registry_db_path())
    reg.execute(
        "CREATE TRIGGER notices_unavailable BEFORE INSERT ON operator_notices "
        "BEGIN SELECT RAISE(ABORT, 'fixture: notices unavailable'); END",
    )
    reg.commit()
    reg.close()
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 200, r.text
    assert r.json()["notifications"] == {
        "recipients": 0, "in_app_error": "IntegrityError", "email": "none"}
    assert _client_row("acme-dup")["status"] == "archived" and _notices() == []
    (rec,) = _requests()
    assert rec["approval_mode"] == "single_attested" and rec["state"] == "applied"
    # Who was NOT told stays on record.
    (marker,) = _audit("tenant_merge_single_attested")
    assert marker["after"]["notified"] == {
        "recipients": [admin1["id"]], "notices": [], "error": "IntegrityError"}
    assert _audit("operator_notice_email") == [] and _chain_ok()


# ---------------------------------------------------------------------------
# Post-hoc review
# ---------------------------------------------------------------------------

def test_post_review_is_by_a_second_person_only_and_once(app):
    _pair()
    create_client("gone-co", "Gone Co", kind="client")
    root = _op(app, "root1", "super_admin", elevate=True)
    admin1 = _op(app, "admin1", "admin")
    root2 = _op(app, "root2", "super_admin")
    analyst = _op(app, "analyst1", "analyst")
    rid = app.post(MERGE, json=_alone(), cookies=root["cookies"]).json()["change_request_id"]
    url = f"{TENANTS}/requests/{rid}/post-review"
    before = _state()
    # The one who applied it may not review it.
    r = app.post(url, json={"verdict": "ok", "note": "fine by me"}, cookies=root["cookies"])
    assert r.status_code == 409 and "second-person rule" in r.json()["message"], r.text
    assert app.post(url, json={"verdict": "ok", "note": "fine"},
                    cookies=analyst["cookies"]).status_code == 403
    assert app.post(url, json={"verdict": "ok", "note": "x"},
                    cookies=admin1["cookies"]).status_code == 422
    assert app.post(url, json={"verdict": "maybe", "note": "not sure"},
                    cookies=admin1["cookies"]).status_code == 422
    assert _state() == before

    r = app.post(url, json={"verdict": "concern", "note": "no ticket references this merge"},
                 cookies=admin1["cookies"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert (out["post_review_state"], out["post_reviewed_by"], out["post_review_note"]) == (
        "reviewed_concern", admin1["id"], "no ticket references this merge")
    # Reviewing it is having seen it: the reviewer's notice is acknowledged;
    # the other recipient's is still open.
    by = {n["recipient_id"]: n for n in _notices()}
    assert by[admin1["id"]]["acknowledged_at"] and by[root2["id"]]["acknowledged_at"] is None
    (row,) = _audit("tenant_change_request_post_review")
    assert (row["actor"], row["before"]["post_review_state"], row["after"]["post_review_state"]) == (
        str(admin1["id"]), "pending", "reviewed_concern")
    assert row["after"]["notices_acknowledged"] == [by[admin1["id"]]["id"]]
    assert row["reason"] == "no ticket references this merge" and _chain_ok()
    # Once.
    r = app.post(url, json={"verdict": "ok", "note": "looks fine"}, cookies=root2["cookies"])
    assert r.status_code == 409 and "already post-reviewed" in r.json()["message"]
    # A two-person request was reviewed before it applied: nothing to post-review.
    req = app.post(f"{TENANTS}/gone-co/offboard", json={"reason": "contract ended"},
                   cookies=admin1["cookies"]).json()["request"]
    r = app.post(f"{TENANTS}/requests/{req['id']}/post-review",
                 json={"verdict": "ok", "note": "fine"}, cookies=root2["cookies"])
    assert r.status_code == 409 and "two-person" in r.json()["message"]
    assert app.post(f"{TENANTS}/requests/999/post-review", json={"verdict": "ok", "note": "fine"},
                    cookies=root2["cookies"]).status_code == 404
    # The requests panel's single-person list shows the verdict.
    (listed,) = app.get(f"{TENANTS}/requests?state=all&approval_mode=single_attested",
                        cookies=root2["cookies"]).json()["requests"]
    assert listed["post_review_state"] == "reviewed_concern"


# ---------------------------------------------------------------------------
# Offboard takes the same hardening
# ---------------------------------------------------------------------------

def test_single_person_offboard_is_hardened_the_same_way(app):
    """No eligibility guards (no data moves between tenants) — a flagged
    cloud tenant can be cut off by one super_admin NOW — but the same
    attestation, typed slug, step-up, record, marker and notices."""
    create_client("gone-co", "Gone Co", kind="client", ai_policy="cloud",
                  compliance_flags_json='["hipaa"]')
    _mint_token("gone-co")
    root = _op(app, "root1", "super_admin", elevate=True)
    admin1 = _op(app, "admin1", "admin")
    r = app.post(f"{TENANTS}/gone-co/offboard", json=_alone("gone-co", "contract ended"),
                 cookies=root["cookies"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["approval_mode"], body["post_review_state"]) == (
        "offboarded", "single_attested", "pending")
    assert body["access"]["tokens_revoked"] == 1
    assert body["notifications"] == {"recipients": 1, "in_app_error": None, "email": "queued"}
    (rec,) = _requests()
    assert (rec["kind"], rec["target_slug"], rec["approval_mode"], rec["attestation"],
            rec["subject_confirmation"], rec["state"]) == (
        "offboard", None, "single_attested", ATTESTATION, "gone-co", "applied")
    assert _audit_actions() == ["tenant_offboard", "tenant_offboard_single_attested"]
    (off,) = _audit("tenant_offboard")
    assert (off["after"]["approval_mode"], off["after"]["change_request_id"]) == (
        "single_attested", rec["id"])
    (marker,) = _audit("tenant_offboard_single_attested")
    assert marker["reason"].startswith("SINGLE-PERSON OFFBOARD — attested exception")
    assert "eligibility" not in marker["after"]
    (notice,) = _notices()
    assert (notice["recipient_id"], notice["kind"], notice["title"]) == (
        admin1["id"], "single_attested_offboard", "Single-person offboard: gone-co")
    assert ATTESTATION not in _all_audit_text() and _chain_ok()


# ---------------------------------------------------------------------------
# The merge caveats the console shows are what the code does
# ---------------------------------------------------------------------------

def test_merge_preview_states_the_caveats_and_what_stays_behind(app):
    _pair()
    ev = connect(paths.client_db_path("acme-dup", "events"))
    ev.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs) "
        "VALUES ('high', '[]', '[1]', 'fixture incident', '[]')",
    )
    ev.commit()
    ev.close()
    _mint_token("acme-dup")
    viewer = app.provision_operator("client-user", PW, athena_role="viewer")
    _set_scope(viewer["id"], ["acme-dup"])
    admin = _op(app, "admin1", "admin")
    rows_before = _audit_count()
    p = app.get(f"{MERGE}/preview", cookies=admin["cookies"])
    assert p.status_code == 200 and p.headers["cache-control"] == "no-store", p.text
    p = p.json()
    assert [c["code"] for c in p["caveats"]] == [
        "irreversible", "events_only", "retriage", "write_lock", "scoped_users"]
    assert p["left_behind"] == {"incidents": 1, "agent_notes": 0, "indicators": 0, "tickets": 0}
    assert (p["events_to_copy"], p["tokens_to_revoke"], p["scoped_operators"]) == (1, 1, 1)
    assert p["single_person"]["eligible"] is True
    assert p["caller_may_apply_alone"] is False                     # an admin
    assert p["attestation_min_chars"] == 40
    assert _audit_count() == rows_before                            # a preview is not a decision
    assert app.get(f"{TENANTS}/acme-dup/merge-into/acme-dup/preview",
                   cookies=admin["cookies"]).status_code == 422
    assert app.get(f"{TENANTS}/acme-dup/merge-into/nope/preview",
                   cookies=admin["cookies"]).status_code == 404


def test_merge_caveats_hold_in_code(app):
    """Each caveat, against the code: only events move (the incident stays
    in the archived subject's store); copied events are new rows the triage
    worker annotates under the TARGET; the subject's client user is signed
    out and not re-scoped; and nothing brings the archived subject back."""
    _pair()
    ev = connect(paths.client_db_path("acme-dup", "events"))
    ev.execute(
        "INSERT INTO incidents (severity, indicator_ids, event_ids, summary, evidence_refs) "
        "VALUES ('high', '[]', '[1]', 'fixture incident', '[]')",
    )
    ev.commit()
    ev.close()
    viewer = app.provision_operator("client-user", PW, athena_role="viewer")
    _set_scope(viewer["id"], ["acme-dup"])
    v_cookies = app.login(viewer)
    assert app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=v_cookies).status_code == 200
    # A running worker has seen the target before (its watermark exists).
    worker.process_tenant_once("acme-corp")
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(MERGE, json=_alone(), cookies=root["cookies"])
    assert r.status_code == 200, r.text

    def _count(slug: str, table: str) -> int:
        c = connect(paths.client_db_path(slug, "events"), read_only=True)
        try:
            return int(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            c.close()

    # events_only: the incident did not move.
    assert (_count("acme-dup", "incidents"), _count("acme-corp", "incidents")) == (1, 0)
    assert len(_events("acme-corp")) == 1
    # retriage: the copied event is a new row the worker picks up — for the
    # target's slug, i.e. under the target's AI policy.
    seen: list[str] = []

    def spy(features, row, slug):  # noqa: ANN001 — the worker's DecideFn
        seen.append(slug)
        return worker.heuristic_decide(features, row, slug)

    result = worker.process_tenant_once("acme-corp", decide=spy)
    assert result.processed == 1 and seen == ["acme-corp"]
    assert _count("acme-corp", "agent_notes") == 1
    # scoped_users: signed out, and not re-scoped to the target.
    assert app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=v_cookies).status_code == 401
    r = app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=app.login(viewer))
    assert r.status_code == 200 and r.json()["scope_slugs"] == []
    # irreversible: no route brings it back.
    for url, body in ((OFFBOARD, _alone()), (MERGE, _alone()),
                      (f"{TENANTS}/acme-dup", {"status": "active"})):
        method = app.patch if url == f"{TENANTS}/acme-dup" else app.post
        method(url, json=body, cookies=root["cookies"])
    assert _client_row("acme-dup")["status"] == "archived"


# ---------------------------------------------------------------------------
# No bypass
# ---------------------------------------------------------------------------

def test_no_environment_variable_or_setting_can_bypass_the_rules():
    """The owner's ruling: nothing configurable turns two-person approval,
    the attestation, the typed slug, step-up or the guards off. The modules
    that enforce them read no environment at all."""
    for module in (admin_tenants, admin_notices, operator_notices):
        src = inspect.getsource(module)
        assert "os.environ" not in src and "getenv" not in src, module.__name__
