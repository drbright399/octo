"""Compliance sign-off before cloud AI (v0.10) — on the real app, real
registry, real audit chain, real step-up.

Pins: 'cloud' may be STORED without a sign-off (super_admin only, as
before) but runs as 'local' until a super_admin — stepped up — signs for
EXACTLY the tenant's current flags, naming one agreement per regime; the
tenant list, PATCH answers and the bulk preview say which policy actually
runs and why; a stale acknowledgement or attestation version is refused; a
flag change (PATCH, bulk, merge) revokes the sign-off on record and says
so in the audit chain; a merge unions the subject's regimes onto the
target (an untagged subject takes a 'none' target back to []), and one
that fails after copying events removes them again; viewers, analysts and
admins can never sign or revoke, and a super_admin cannot without step-up
— nor make a tenant run as cloud any OTHER way (tagging it 'none') without
the same bar; an offboarded or merged-away tenant's sign-offs are revoked
and it runs as 'none'; the dashboard counts sign-offs about to lapse.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from apps.octo import paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.api.routers import admin_tenants
from apps.octo.auth import audit as audit_log
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect, transaction
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import ai_policy
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
    _tenant,
    app,
)

BULK = f"{TENANTS}/bulk-update"
TEXT = (
    "I have checked Acme's compliance tags today; our BAA with them covers "
    "processing their alert data in a cloud model."
)


def _op(app, name: str, role: str, *, elevate: bool = False) -> dict:
    """An operator's cookies (optionally stepped up) + its id."""
    op = app.provision_operator(name, PW, athena_role=role)
    cookies = app.login(op)
    if elevate:
        r = app.post("/api/v1/search/elevate", json={
            "current_password": PW, "totp_code": pyotp.TOTP(op["totp_secret_b32"]).now(),
        }, cookies=cookies)
        assert r.status_code == 200, r.text
    return {"cookies": cookies, "id": op["id"]}


def _refs(flags: list[str]) -> dict[str, str]:
    """One agreement per regime (the untagged tenant's DPA for [])."""
    return {k: ("BAA-2026-014" if k == "hipaa" else f"AGR-{k}-014")
            for k in ai_policy.agreement_keys(flags)}


def _body(flags: list[str], **over) -> dict:
    return {
        "agreement_references": _refs(flags), "attestation_text": TEXT,
        "attestation_version": ai_policy.ATTESTATION_VERSION, "acknowledge_flags": flags, **over,
    }


def _flagged(slug: str = "acme-corp", flags: list[str] | None = None, policy: str = "cloud") -> None:
    create_client(slug, slug.replace("-", " ").title(), kind="client", ai_policy=policy,
                  compliance_flags_json=json.dumps(["hipaa"] if flags is None else flags))


def _signoffs(slug: str = "acme-corp") -> list[dict]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        cur = reg.execute(
            "SELECT * FROM tenant_compliance_signoffs WHERE slug = ? ORDER BY id", (slug,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        reg.close()


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


def _sign(app, root: dict, slug: str = "acme-corp", flags: list[str] | None = None) -> int:
    r = app.post(f"{TENANTS}/{slug}/compliance-signoff",
                 json=_body(["hipaa"] if flags is None else flags),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    return r.json()["signoff"]["id"]


# ---------------------------------------------------------------------------
# Role + step-up matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role, read, write", [
    ("viewer", 403, 403),
    ("analyst", 403, 403),
    ("admin", 200, 403),               # reads the history; never signs or revokes
    ("super_admin", 200, None),        # 201 / 200
    (None, 401, 401),                  # unauthenticated
])
def test_signoff_routes_role_and_step_up_matrix(app, role, read, write):
    _flagged()
    root = _op(app, "root0", "super_admin", elevate=True)
    sid = _sign(app, root)
    if role is None:
        app.cookies.clear()
        cookies = None
    else:
        # Stepped up, so a refusal is the ROLE rule, never the step-up one.
        cookies = _op(app, f"{role}1", role, elevate=True)["cookies"]
        app.cookies.clear()
    g = app.get(f"{TENANTS}/acme-corp/compliance-signoffs", cookies=cookies)
    assert g.status_code == read, g.text
    s = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["hipaa"]), cookies=cookies)
    if s.status_code == 201:
        sid = s.json()["signoff"]["id"]           # it superseded the fixture's
    v = app.post(f"{TENANTS}/acme-corp/compliance-signoff/{sid}/revoke",
                 json={"reason": "client withdrew consent"}, cookies=cookies)
    if write is None:
        assert (s.status_code, v.status_code) == (201, 200), (s.text, v.text)
        return
    assert (s.status_code, v.status_code) == (write, write), (s.text, v.text)
    if write == 403:
        assert s.json()["code"] == v.json()["code"] == "ISOLATION_VIOLATION"
    # Nothing but the fixture's own sign-off exists, still live.
    rows = _signoffs()
    assert [(r["id"], r["revoked_at"]) for r in rows] == [(sid, None)]
    assert len(_audit("tenant_compliance_signoff")) == 1
    assert _audit("tenant_compliance_signoff_revoke") == []


def test_super_admin_without_step_up_is_asked_to_re_authenticate(app):
    _flagged()
    root = _op(app, "root1", "super_admin")                 # NOT elevated
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    assert _signoffs() == [] and _audit("tenant_compliance_signoff") == []
    # The read needs no step-up.
    assert app.get(f"{TENANTS}/acme-corp/compliance-signoffs",
                   cookies=root["cookies"]).status_code == 200


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def test_cloud_runs_as_local_until_signed_then_as_cloud_and_is_audited(app):
    _flagged()
    root = _op(app, "root1", "super_admin", elevate=True)
    t = _tenant(app, root["cookies"], "acme-corp")
    assert (t["ai_policy"], t["effective_ai_policy"]) == ("cloud", "local")
    assert t["ai_policy_reason"] == "cloud requested — degraded to local: sign-off required for [hipaa]"
    assert t["signoff"]["state"] == "required"

    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    body = r.json()
    so = body["signoff"]
    assert (so["flags_covered"], so["agreement_references"], so["attestation_text"],
            so["state"]) == (["hipaa"], {"hipaa": "BAA-2026-014"}, TEXT, "live")
    assert so["attestation_sha256"] == hashlib.sha256(TEXT.encode()).hexdigest()
    assert so["attestation_version"] == ai_policy.ATTESTATION_VERSION
    assert so["signed_by"] == root["id"] and so["expires_at"][:4] == str(int(so["signed_at"][:4]) + 1)
    assert (body["ai_policy"]["requested"], body["ai_policy"]["effective"]) == ("cloud", "cloud")
    assert body["ai_policy"]["degraded"] is False

    t = _tenant(app, root["cookies"], "acme-corp")
    assert t["effective_ai_policy"] == "cloud" and t["signoff"]["state"] == "live"
    assert (t["signoff"]["signoff_id"], t["signoff"]["signed_by"]) == (so["id"], root["id"])
    assert t["ai_policy_reason"].startswith(
        f"cloud permitted — sign-off #{so['id']} covers [hipaa] until ")
    assert ai_policy.ai_allowed("acme-corp", "cloud") is True

    (row,) = _audit("tenant_compliance_signoff")
    assert row["actor"] == str(root["id"]) and row["client_slug"] == "acme-corp"
    assert row["target_id"] == str(so["id"])
    assert row["before"]["effective"] == "local" and row["after"]["effective"] == "cloud"
    assert row["after"]["attestation_sha256"] == so["attestation_sha256"]
    assert row["after"]["flags_covered"] == ["hipaa"] and row["after"]["superseded"] == []
    assert TEXT not in (row["after_state"] + (row["reason"] or ""))   # the hash, not the text
    assert _chain_ok()

    hist = app.get(f"{TENANTS}/acme-corp/compliance-signoffs", cookies=root["cookies"]).json()
    assert [h["state"] for h in hist["signoffs"]] == ["live"]
    assert hist["attestation"]["version"] == ai_policy.ATTESTATION_VERSION
    assert hist["attestation"]["text"] == ai_policy.ATTESTATION_TEMPLATES[ai_policy.ATTESTATION_VERSION]
    assert hist["term_months_default"] == 12


def test_signing_again_supersedes_and_history_keeps_both(app):
    _flagged()
    root = _op(app, "root1", "super_admin", elevate=True)
    first = _sign(app, root)
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff",
                 json=_body(["hipaa"], term_months=6,
                            agreement_references={"hipaa": "BAA-2026-015"}),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    assert r.json()["superseded"] == [first]
    hist = app.get(f"{TENANTS}/acme-corp/compliance-signoffs", cookies=root["cookies"]).json()
    assert [(h["id"], h["state"]) for h in hist["signoffs"]] == [
        (r.json()["signoff"]["id"], "live"), (first, "superseded")]


def test_acknowledged_flags_must_equal_the_current_flags(app):
    _flagged(flags=["hipaa", "pci"])
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 409, r.text
    assert "tagged [hipaa, pci], not [hipaa]" in r.json()["message"]
    assert _signoffs() == [] and _audit("tenant_compliance_signoff") == []
    # Order and duplicates do not matter; the SET does.
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["pci", "hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    assert r.json()["signoff"]["flags_covered"] == ["hipaa", "pci"]


def test_never_tagged_needs_a_signoff_and_tagged_none_needs_none(app):
    _flagged("untagged-co", flags=[])
    _flagged("plain-co", flags=["none"])
    root = _op(app, "root1", "super_admin", elevate=True)
    untagged = _tenant(app, root["cookies"], "untagged-co")
    plain = _tenant(app, root["cookies"], "plain-co")
    assert (untagged["effective_ai_policy"], untagged["signoff"]["state"]) == ("local", "required")
    assert (plain["effective_ai_policy"], plain["signoff"]["state"]) == ("cloud", "not_required")
    r = app.post(f"{TENANTS}/plain-co/compliance-signoff", json=_body(["none"]),
                 cookies=root["cookies"])
    assert r.status_code == 409 and "needs no sign-off" in r.json()["message"]
    r = app.post(f"{TENANTS}/untagged-co/compliance-signoff", json=_body([]),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    assert r.json()["signoff"]["flags_covered"] == []
    assert _tenant(app, root["cookies"], "untagged-co")["effective_ai_policy"] == "cloud"


@pytest.mark.parametrize("over, code", [
    ({"attestation_text": "too short"}, 422),
    ({"attestation_text": " " * 30 + "x" * 20}, 422),          # padding is not an attestation
    ({"attestation_text": TEXT + "\x07"}, 422),
    ({"agreement_references": {"hipaa": "   "}}, 422),
    ({"agreement_references": {}}, 422),
    ({"agreement_references": {"hipaa": "BAA-1", "cjis": "CSA-1"}}, 422),   # not a regime it has
    ({"agreement_references": {"reference": "BAA-1"}}, 422),
    ({"agreement_references": {"hipaa": "x" * 121}}, 422),
    ({"attestation_version": "1999-01-01.v0"}, 422),
    ({"acknowledge_flags": ["sox"]}, 422),
    ({"term_months": 13}, 422),
    ({"term_months": 0}, 422),
])
def test_signoff_validation(app, over, code):
    _flagged()
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["hipaa"], **over),
                 cookies=root["cookies"])
    assert r.status_code == code, r.text
    assert _signoffs() == [] and _audit("tenant_compliance_signoff") == []


def test_stale_attestation_version_unknown_offboarded_and_missing_tenants(app, monkeypatch):
    _flagged()
    _flagged("gone-co")
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'gone-co'")
    reg.commit(); reg.close()
    root = _op(app, "root1", "super_admin", elevate=True)
    # The wording moved on while the dialog was open.
    with monkeypatch.context() as m:
        m.setitem(ai_policy.ATTESTATION_TEMPLATES, "2026-10-01.v2", "new wording")
        m.setattr(ai_policy, "ATTESTATION_VERSION", "2026-10-01.v2")
        r = app.post(f"{TENANTS}/acme-corp/compliance-signoff",
                     json=_body(["hipaa"], attestation_version="2026-09-28.v1"),
                     cookies=root["cookies"])
    assert r.status_code == 409 and "wording changed" in r.json()["message"]
    r = app.post(f"{TENANTS}/gone-co/compliance-signoff", json=_body(["hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 409
    r = app.post(f"{TENANTS}/nope-co/compliance-signoff", json=_body(["hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 404
    assert _signoffs() == [] and _signoffs("gone-co") == []


def test_every_regime_names_its_own_agreement(app):
    """A BAA is HIPAA's instrument, not CJIS's: a tenant tagged [cjis, hipaa]
    is signed only with a reference for EACH — the history says which
    instrument each one is, and the audit row keeps the references."""
    _flagged(flags=["cjis", "hipaa"])
    root = _op(app, "root1", "super_admin", elevate=True)
    hist = app.get(f"{TENANTS}/acme-corp/compliance-signoffs", cookies=root["cookies"]).json()
    assert hist["agreements_required"] == [
        {"key": "cjis", "instrument": "CJIS Security Addendum"},
        {"key": "hipaa", "instrument": "HIPAA business associate agreement (BAA)"},
    ]
    assert hist["agreement_reference_max_chars"] == ai_policy.AGREEMENT_REFERENCE_MAX_CHARS
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff",
                 json=_body(["cjis", "hipaa"], agreement_references={"hipaa": "BAA-2026-014"}),
                 cookies=root["cookies"])
    assert r.status_code == 422, r.text
    assert "cjis (CJIS Security Addendum)" in r.json()["message"]
    assert _signoffs() == []
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff", json=_body(["cjis", "hipaa"]),
                 cookies=root["cookies"])
    assert r.status_code == 201, r.text
    assert r.json()["signoff"]["agreement_references"] == {
        "cjis": "AGR-cjis-014", "hipaa": "BAA-2026-014"}
    (row,) = _audit("tenant_compliance_signoff")
    assert row["after"]["agreement_references"] == {"cjis": "AGR-cjis-014", "hipaa": "BAA-2026-014"}
    # A never-tagged tenant names its data-processing agreement.
    _flagged("untagged-co", flags=[])
    hist = app.get(f"{TENANTS}/untagged-co/compliance-signoffs", cookies=root["cookies"]).json()
    assert hist["agreements_required"] == [
        {"key": "untagged", "instrument": "data-processing agreement"}]


def test_flags_that_are_not_known_tags_cannot_be_signed_for(app):
    """Stored flags this code did not write read as [] in canonical form;
    signing "[]" for them would bless whatever they really say. Re-tag
    first."""
    _flagged("odd-co", flags=[])
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET compliance_flags = '[\"HIPAA\"]' WHERE slug = 'odd-co'")
    reg.commit(); reg.close()
    root = _op(app, "root1", "super_admin", elevate=True)
    r = app.post(f"{TENANTS}/odd-co/compliance-signoff", json=_body([]), cookies=root["cookies"])
    assert r.status_code == 409 and "re-tag it" in r.json()["message"], r.text
    assert _signoffs("odd-co") == []
    t = _tenant(app, root["cookies"], "odd-co")
    assert (t["effective_ai_policy"], t["signoff"]["state"]) == ("local", "required")


# ---------------------------------------------------------------------------
# Revoking
# ---------------------------------------------------------------------------

def test_revoke_drops_cloud_to_local_once_and_is_audited(app):
    _flagged()
    _flagged("other-co")
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root)
    other = _sign(app, root, "other-co")
    # A sign-off id belongs to its tenant.
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff/{other}/revoke",
                 json={"reason": "wrong tenant"}, cookies=root["cookies"])
    assert r.status_code == 404
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff/{sid}/revoke",
                 json={"reason": "  BAA not renewed  "}, cookies=root["cookies"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["signoff"]["state"] == "revoked" and body["signoff"]["revoke_reason"] == "BAA not renewed"
    assert body["signoff"]["revoked_kind"] == "operator" and body["signoff"]["revoked_by"] == root["id"]
    assert (body["ai_policy"]["effective"], body["ai_policy"]["signoff"]["state"]) == ("local", "revoked")
    assert body["ai_policy"]["reason"] == (
        f"cloud requested — degraded to local: sign-off #{sid} was revoked — sign off again")
    r = app.post(f"{TENANTS}/acme-corp/compliance-signoff/{sid}/revoke",
                 json={"reason": "again"}, cookies=root["cookies"])
    assert r.status_code == 409
    (row,) = _audit("tenant_compliance_signoff_revoke")
    assert row["reason"] == "BAA not renewed" and row["target_id"] == str(sid)
    assert (row["before"]["effective"], row["after"]["effective"]) == ("cloud", "local")
    assert ai_policy.effective_ai_policy("other-co") == "cloud" and _chain_ok()


# ---------------------------------------------------------------------------
# Flag changes invalidate
# ---------------------------------------------------------------------------

def test_a_flag_change_revokes_the_signoff_and_the_audit_says_so(app):
    _flagged()
    root = _op(app, "root1", "super_admin", elevate=True)
    admin = _op(app, "admin1", "admin")
    sid = _sign(app, root)
    # A rename does not touch the sign-off.
    r = app.patch(f"{TENANTS}/acme-corp", json={"display_name": "Acme Corporation"},
                  cookies=admin["cookies"])
    assert r.status_code == 200 and r.json()["effective_ai_policy"] == "cloud"
    # A flag change does — an admin's edit is enough to take cloud away.
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["hipaa", "pci"]},
                  cookies=admin["cookies"])
    assert r.status_code == 200, r.text
    t = r.json()
    assert (t["ai_policy"], t["effective_ai_policy"], t["signoff"]["state"]) == (
        "cloud", "local", "flags_changed")
    assert t["ai_policy_reason"] == (
        f"cloud requested — degraded to local: compliance flags changed since sign-off #{sid} "
        "(signed for [hipaa], now [hipaa, pci]) — sign off again")
    (so,) = _signoffs()
    assert (so["revoked_kind"], so["revoked_by"]) == ("flags_changed", admin["id"])
    assert so["revoke_reason"] == "compliance flags changed: [hipaa] → [hipaa, pci]"
    row = _audit("tenant_update")[-1]
    assert row["after"]["compliance_signoffs_invalidated"] == [sid]
    assert (row["before"]["effective_ai_policy"], row["after"]["effective_ai_policy"]) == (
        "cloud", "local")
    assert f"compliance sign-off(s) #{sid} revoked: flags changed" in row["reason"]
    # Changing the flags BACK does not resurrect it: a human signs again.
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["hipaa"]},
                  cookies=admin["cookies"])
    assert r.json()["effective_ai_policy"] == "local"
    assert r.json()["signoff"]["state"] == "flags_changed" and _chain_ok()


def test_bulk_preview_says_local_until_signed_and_which_signoffs_a_flag_change_revokes(app):
    _flagged("acme-corp", ["hipaa"], policy="none")
    _flagged("plain-co", ["none"], policy="none")
    _flagged("untagged-co", [], policy="none")
    _flagged("signed-co", ["pci"], policy="cloud")
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root, "signed-co", flags=["pci"])

    items = [{"slug": s, "patch": {"ai_policy": "cloud"}}
             for s in ("acme-corp", "plain-co", "untagged-co")]
    items.append({"slug": "signed-co", "patch": {"compliance_flags": ["pci", "hipaa"]}})
    r = app.post(BULK, json={"items": items, "dry_run": True}, cookies=root["cookies"])
    assert r.status_code == 200, r.text
    rows = {row["slug"]: row for row in r.json()["rows"]}
    assert rows["acme-corp"]["effective_ai_policy"] == "local"
    assert rows["acme-corp"]["ai_policy_note"] == (
        "will run as local until signed — sign-off required for [hipaa]")
    assert rows["acme-corp"]["signoff"]["state"] == "required"
    assert rows["plain-co"]["effective_ai_policy"] == "cloud"
    # Cleared for cloud on the 'none' tag: the sign-off's bar applies.
    assert rows["plain-co"]["ai_policy_note"] == (
        "will be cleared for cloud AI — tagged 'none', no sign-off needed; applying needs a "
        "super admin with step-up re-authentication")
    assert rows["plain-co"]["step_up_required"] is True
    assert [s for s, row in rows.items() if row["step_up_required"]] == ["plain-co"]
    assert r.json()["step_up_required"] is True
    assert "never been tagged" in rows["untagged-co"]["ai_policy_note"]
    assert rows["signed-co"]["signoffs_invalidated"] == [sid]
    assert rows["signed-co"]["effective_ai_policy"] == "local"
    assert rows["signed-co"]["ai_policy_note"].startswith(
        f"sign-off #{sid} will be revoked: compliance flags change; will run as local until signed")
    # A preview writes nothing.
    assert _signoffs("signed-co")[0]["revoked_at"] is None
    assert ai_policy.effective_ai_policy("signed-co") == "cloud"

    r = app.post(BULK, json={"items": items}, cookies=root["cookies"])
    assert r.status_code == 200, r.text
    rows = {row["slug"]: row for row in r.json()["rows"]}
    assert rows["acme-corp"]["ai_policy_note"] == (
        "runs as local until signed — sign-off required for [hipaa]")
    assert rows["plain-co"]["ai_policy_note"] == (
        "is now cleared for cloud AI — tagged 'none', no sign-off needed")
    assert rows["signed-co"]["signoffs_invalidated"] == [sid]
    assert _signoffs("signed-co")[0]["revoked_kind"] == "flags_changed"
    assert _client_row("acme-corp")["ai_policy"] == "cloud"          # the intent is stored
    assert ai_policy.effective_ai_policy("acme-corp") == "local"     # … and not honoured
    assert ai_policy.effective_ai_policy("plain-co") == "cloud"
    updates = {row["client_slug"]: row for row in _audit("tenant_update")}
    assert updates["signed-co"]["after"]["compliance_signoffs_invalidated"] == [sid]
    assert "compliance_signoffs_invalidated" not in updates["acme-corp"]["after"]
    assert updates["plain-co"]["after"]["cloud_clearance"] == {
        "step_up": True, "basis": "not_required"}
    assert "cloud_clearance" not in updates["acme-corp"]["after"]


# ---------------------------------------------------------------------------
# Merges reconcile flags
# ---------------------------------------------------------------------------

def test_merge_unions_the_subjects_regimes_and_revokes_the_targets_signoff(app):
    """A subject carrying a regime the target lacks can only be merged by
    TWO people (v0.10 item 7's eligibility guard); applying it unions the
    regime onto the target and revokes the target's sign-off."""
    _flagged("acme-corp", ["hipaa"])
    create_client("acme-billing", "Acme Billing", kind="client",
                  compliance_flags_json='["pci"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root)
    r = app.post(f"{TENANTS}/acme-billing/merge-into/acme-corp",
                 json={"reason": "same customer"}, cookies=root["cookies"])
    assert r.status_code == 202, r.text
    other_root = _op(app, "root2", "super_admin")
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve",
                 cookies=other_root["cookies"])
    assert r.status_code == 200, r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa", "pci"]
    (so,) = _signoffs()
    assert (so["revoked_kind"], so["revoke_reason"]) == (
        "merge_added_flags", "merge of acme-billing added [pci]")
    t = _tenant(app, root["cookies"], "acme-corp")
    assert (t["effective_ai_policy"], t["signoff"]["state"]) == ("local", "flags_changed")
    (row,) = _audit("tenant_merge")
    assert row["after"]["compliance_signoffs_invalidated"] == [sid]
    assert row["after"]["approval_mode"] == "two_person"
    assert row["after"]["target_flags_added"] == ["pci"]
    assert row["after"]["compliance_signoffs_invalidated"] == [sid]
    assert row["after"]["target_effective_ai_policy"] == "local"
    assert row["before"]["target"]["effective_ai_policy"] == "cloud"
    assert "merge added [pci] to acme-corp" in row["reason"] and _chain_ok()


def test_a_merge_that_adds_no_regime_leaves_the_signoff_live_on_both_paths(app):
    """An untagged duplicate (the usual auto-created one) and a subject whose
    regimes the target already carries change nothing — through the
    two-person path as much as the attested single-person one."""
    _flagged("acme-corp", ["hipaa", "pci"])
    # Signed for cloud itself, so the target is not MORE permissive than it
    # and one super_admin may merge it (v0.10 item 7's guards).
    _flagged("acme-north", ["pci"])
    create_client("acme-dup", "Acme Dup", origin="auto")                     # [] — never tagged
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root, flags=["hipaa", "pci"])
    _sign(app, root, "acme-north", flags=["pci"])
    r = app.post(f"{TENANTS}/acme-north/merge-into/acme-corp", json={
        "reason": "same customer", "approval_mode": "single_attested",
        "attestation": "Same customer, second vendor site; both tagged and signed for pci.",
        "confirm_subject": "acme-north",
    }, cookies=root["cookies"])
    assert r.status_code == 200, r.text
    assert r.json()["target_flags_added"] == [] and r.json()["approval_mode"] == "single_attested"
    admin = _op(app, "admin1", "admin")
    r = app.post(f"{TENANTS}/acme-dup/merge-into/acme-corp",
                 json={"reason": "auto-created duplicate"}, cookies=admin["cookies"])
    assert r.status_code == 202, r.text
    other_root = _op(app, "root2", "super_admin")
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve",
                 cookies=other_root["cookies"])
    assert r.status_code == 200, r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa", "pci"]
    assert _signoffs()[0]["id"] == sid and _signoffs()[0]["revoked_at"] is None
    assert ai_policy.effective_ai_policy("acme-corp") == "cloud"
    assert "tenant_merge" in _audit_actions()


def test_merge_request_approved_later_reconciles_flags_then(app):
    _flagged("acme-corp", ["hipaa"])
    create_client("acme-west", "Acme West", kind="client", compliance_flags_json='["cjis"]')
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root)
    admin = _op(app, "admin1", "admin")
    r = app.post(f"{TENANTS}/acme-west/merge-into/acme-corp",
                 json={"reason": "same customer"}, cookies=admin["cookies"])
    assert r.status_code == 202
    # Asking changes nothing.
    assert ai_policy.effective_ai_policy("acme-corp") == "cloud"
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve", cookies=root["cookies"])
    assert r.status_code == 200, r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["cjis", "hipaa"]
    assert _signoffs()[0]["revoked_kind"] == "merge_added_flags"
    assert _signoffs()[0]["revoked_by"] == root["id"] and _signoffs()[0]["id"] == sid
    assert ai_policy.effective_ai_policy("acme-corp") == "local"


# ---------------------------------------------------------------------------
# Cloud by any other route takes the sign-off's bar
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role, elevate, status, code", [
    ("viewer", True, 403, "ISOLATION_VIOLATION"),
    ("analyst", True, 403, "ISOLATION_VIOLATION"),
    ("admin", True, 403, "ISOLATION_VIOLATION"),        # stepped up: still the ROLE rule
    ("super_admin", False, 401, "STEP_UP_REQUIRED"),
    ("super_admin", True, 200, None),
    (None, False, 401, None),                            # unauthenticated
])
def test_tagging_a_waiting_cloud_tenant_none_takes_the_signoff_bar(app, role, elevate, status, code):
    """A 'cloud' tenant tagged [hipaa] and unsigned runs as local. Re-tagging
    it ["none"] makes it run as cloud with no sign-off — the sign-off's
    decision, so the sign-off's bar: super_admin + step-up. (An admin used
    to get 200 and a tenant cleared for cloud.)"""
    _flagged()
    if role is None:
        app.cookies.clear()
        cookies = None
    else:
        cookies = _op(app, f"{role}1", role, elevate=elevate)["cookies"]
        app.cookies.clear()
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["none"]}, cookies=cookies)
    assert r.status_code == status, r.text
    if code:
        assert r.json()["code"] == code
    if status == 200:
        body = r.json()
        assert (body["effective_ai_policy"], body["signoff"]["state"]) == ("cloud", "not_required")
        (row,) = _audit("tenant_update")
        assert (row["before"]["effective_ai_policy"], row["after"]["effective_ai_policy"]) == (
            "local", "cloud")
        assert row["after"]["cloud_clearance"] == {"step_up": True, "basis": "not_required"}
        assert "cleared for cloud AI by a super_admin under step-up" in row["reason"]
        assert _chain_ok()
        return
    if role == "admin":
        assert "only a super admin may clear a tenant for cloud AI" in r.json()["message"]
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa"]
    assert ai_policy.ai_allowed("acme-corp", "cloud") is False
    assert _audit("tenant_update") == []


def test_moving_a_signed_tenant_onto_the_none_tag_takes_the_bar_too(app):
    """Signed for [hipaa] and running as cloud: re-tagging it 'none' revokes
    the sign-off but would KEEP it cloud — on an admin's say-so instead of
    the sign-off. Same bar. Other flag edits by an admin (which only ever
    lower what runs) stay the admin's."""
    _flagged()
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root)
    admin = _op(app, "admin1", "admin", elevate=True)
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["none"]},
                  cookies=admin["cookies"])
    assert (r.status_code, r.json()["code"]) == (403, "ISOLATION_VIOLATION"), r.text
    assert "on the tag 'none' alone" in r.json()["message"]
    assert _signoffs()[0]["revoked_at"] is None
    # Tagging it with MORE is an admin's call: it only degrades to local.
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["hipaa", "pci"]},
                  cookies=admin["cookies"])
    assert r.status_code == 200 and r.json()["effective_ai_policy"] == "local", r.text
    assert _signoffs()[0]["revoked_kind"] == "flags_changed"
    # A stepped-up super_admin may: the audit row says the basis moved.
    _sign(app, root, flags=["hipaa", "pci"])
    r = app.patch(f"{TENANTS}/acme-corp", json={"compliance_flags": ["none"]},
                  cookies=root["cookies"])
    assert r.status_code == 200 and r.json()["effective_ai_policy"] == "cloud", r.text
    row = _audit("tenant_update")[-1]
    assert row["after"]["cloud_clearance"] == {"step_up": True, "basis": "not_required"}
    assert sid in [so["id"] for so in _signoffs()]


@pytest.mark.parametrize("role, elevate, status", [
    ("admin", True, 403),
    ("super_admin", False, 401),
    ("super_admin", True, 200),
])
def test_bulk_tagging_none_takes_the_same_bar_all_or_nothing(app, role, elevate, status):
    _flagged()
    _flagged("other-co", ["pci"], policy="none")
    op = _op(app, f"{role}1", role, elevate=elevate)
    items = [{"slug": "acme-corp", "patch": {"compliance_flags": ["none"]}},
             {"slug": "other-co", "patch": {"kind": "internal"}}]
    dry = app.post(BULK, json={"items": items, "dry_run": True}, cookies=op["cookies"])
    assert dry.status_code == 200, dry.text
    rows = {row["slug"]: row for row in dry.json()["rows"]}
    if role == "admin":
        assert rows["acme-corp"]["error"]["code"] == "ISOLATION_VIOLATION"
        assert dry.json()["refusal"]["code"] == "ISOLATION_VIOLATION"
        assert "would make a tenant run as cloud" in dry.json()["refusal"]["message"]
    else:
        assert rows["acme-corp"]["step_up_required"] is True
        assert rows["other-co"]["step_up_required"] is False
        assert dry.json()["step_up_required"] is True and dry.json()["refusal"] is None
    r = app.post(BULK, json={"items": items}, cookies=op["cookies"])
    assert r.status_code == status, r.text
    if status == 200:
        assert ai_policy.effective_ai_policy("acme-corp") == "cloud"
        updates = {row["client_slug"]: row for row in _audit("tenant_update")}
        assert updates["acme-corp"]["after"]["cloud_clearance"]["step_up"] is True
        assert "cloud_clearance" not in updates["other-co"]["after"]
        return
    if status == 401:
        assert r.json()["code"] == "STEP_UP_REQUIRED"
    # All or nothing: neither row was written.
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa"]
    assert _client_row("other-co")["kind"] == "client"
    assert _audit("tenant_update") == []


def test_setting_cloud_on_a_none_tagged_tenant_or_creating_one_needs_step_up(app):
    _flagged("plain-co", ["none"], policy="local")
    root = _op(app, "root1", "super_admin")                  # not stepped up
    r = app.patch(f"{TENANTS}/plain-co", json={"ai_policy": "cloud"}, cookies=root["cookies"])
    assert (r.status_code, r.json()["code"]) == (401, "STEP_UP_REQUIRED"), r.text
    assert _client_row("plain-co")["ai_policy"] == "local"
    new = {"slug": "new-co", "display_name": "New Co", "kind": "client",
           "compliance_flags": ["none"], "ai_policy": "cloud"}
    r = app.post(TENANTS, json=new, cookies=root["cookies"])
    assert (r.status_code, r.json()["code"]) == (401, "STEP_UP_REQUIRED"), r.text
    assert ai_policy.policy_status("new-co") is None
    # Cloud asked for on a TAGGED tenant runs as local: no step-up needed.
    r = app.post(TENANTS, json={**new, "slug": "hip-co", "compliance_flags": ["hipaa"]},
                 cookies=root["cookies"])
    assert r.status_code == 201 and r.json()["effective_ai_policy"] == "local", r.text
    elevated = _op(app, "root2", "super_admin", elevate=True)
    r = app.patch(f"{TENANTS}/plain-co", json={"ai_policy": "cloud"}, cookies=elevated["cookies"])
    assert r.status_code == 200 and r.json()["effective_ai_policy"] == "cloud", r.text
    r = app.post(TENANTS, json=new, cookies=elevated["cookies"])
    assert r.status_code == 201 and r.json()["effective_ai_policy"] == "cloud", r.text


# ---------------------------------------------------------------------------
# Merges: untagged data, failed copies, retired tenants
# ---------------------------------------------------------------------------

def _ingest(slug: str, n: int) -> None:
    for i in range(1, n + 1):
        SqliteIngestSink(publish_to_stream=False).ingest(
            slug, "datto", DattoSourceAdapter().extract_event(_api_alert(i, site_uid=f"s-{i}")))


def test_untagged_data_merged_into_a_none_target_takes_it_back_to_untagged(app):
    """regimes_not_covered([], ["none"]) is empty — but "no regime applies"
    was said about the target's data, not the never-tagged subject's. The
    merged target goes back to [] (needs a sign-off), and the preview says
    so before anyone approves."""
    _flagged("acme-corp", ["none"])                          # cloud, no sign-off needed
    create_client("site-1a2b", "Datto site 1a2b", origin="auto")   # [] — never tagged
    _ingest("site-1a2b", 1)
    root = _op(app, "root1", "super_admin", elevate=True)
    merge = f"{TENANTS}/site-1a2b/merge-into/acme-corp"
    p = app.get(f"{merge}/preview", cookies=root["cookies"]).json()
    assert (p["target_flags_added"], p["target_flags_after"]) == ([], [])
    r = app.post(merge, json={"reason": "auto-created duplicate"}, cookies=root["cookies"])
    assert r.status_code == 202, r.text
    other = _op(app, "root2", "super_admin")
    r = app.post(f"{TENANTS}/requests/{r.json()['request']['id']}/approve", cookies=other["cookies"])
    assert r.status_code == 200, r.text
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == []
    t = _tenant(app, root["cookies"], "acme-corp")
    assert (t["effective_ai_policy"], t["signoff"]["state"]) == ("local", "required")
    assert ai_policy.ai_allowed("acme-corp", "cloud") is False
    (row,) = _audit("tenant_merge")
    assert row["after"]["target_compliance_flags"] == []
    assert "took acme-corp from ['none'] back to []" in row["reason"]


def test_a_merge_that_fails_after_copying_removes_the_copied_events(app, monkeypatch):
    """The target's events.db fails on the SECOND batch: the first batch was
    committed to a store the registry transaction cannot roll back. The
    subject's regulated events must not stay in a target still tagged
    ['none'] and running as cloud — the copied rows are deleted again, the
    attempt audited, and a retry after repair applies once."""
    _flagged("acme-corp", ["none"])
    create_client("acme-dup", "Acme Dup", kind="client", ai_policy="cloud",
                  compliance_flags_json='["hipaa"]')
    _ingest("acme-dup", 3)
    monkeypatch.setattr(admin_tenants, "_MERGE_BATCH", 1)
    target_db = paths.client_db_path("acme-corp", "events")
    conn = sqlite3.connect(target_db)
    conn.execute("CREATE TRIGGER fail_second BEFORE INSERT ON events "
                 "WHEN (SELECT COUNT(*) FROM events) >= 1 "
                 "BEGIN SELECT RAISE(ABORT, 'fixture: disk full'); END")
    conn.commit(); conn.close()
    admin = _op(app, "admin1", "admin")
    rid = app.post(f"{TENANTS}/acme-dup/merge-into/acme-corp", json={"reason": "same customer"},
                   cookies=admin["cookies"]).json()["request"]["id"]
    root = _op(app, "root1", "super_admin")
    with pytest.raises(sqlite3.DatabaseError):          # a 500; the TestClient re-raises it
        app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root["cookies"])
    assert _events("acme-corp") == []                   # the one copied row is gone again
    assert _client_row("acme-dup")["status"] == "active"
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["none"]
    (undo,) = _audit("tenant_merge_copy_undone")
    assert undo["after"] == {"target": "acme-corp", "events_copied": 1, "events_removed": 1,
                             "events_left_in_target": 0, "error": None}
    assert _audit_actions()[-3:] == [
        "tenant_merge_failed", "tenant_change_request_apply_failed", "tenant_merge_copy_undone"]
    assert _chain_ok()
    # Repaired → the retry applies once, with the regime unioned on.
    conn = sqlite3.connect(target_db)
    conn.execute("DROP TRIGGER fail_second")
    conn.commit(); conn.close()
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root["cookies"])
    assert r.status_code == 200, r.text
    assert len(_events("acme-corp")) == 3
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa"]
    assert ai_policy.effective_ai_policy("acme-corp") == "local"


def test_copied_events_that_cannot_be_removed_leave_the_target_fail_closed(app, monkeypatch):
    """Double fault: the copy fails part-way AND the target store refuses
    the delete. What stays is regulated data under tags that never covered
    it — so the target takes the subject's regimes and loses its sign-off
    anyway, in its own audited transaction."""
    _flagged("acme-corp", ["pci"])
    create_client("acme-dup", "Acme Dup", kind="client", compliance_flags_json='["hipaa"]')
    _ingest("acme-dup", 2)
    root = _op(app, "root1", "super_admin", elevate=True)
    sid = _sign(app, root, flags=["pci"])
    assert ai_policy.effective_ai_policy("acme-corp") == "cloud"
    monkeypatch.setattr(admin_tenants, "_MERGE_BATCH", 1)
    conn = sqlite3.connect(paths.client_db_path("acme-corp", "events"))
    conn.execute("CREATE TRIGGER fail_second BEFORE INSERT ON events "
                 "WHEN (SELECT COUNT(*) FROM events) >= 1 "
                 "BEGIN SELECT RAISE(ABORT, 'fixture: disk full'); END")
    conn.execute("CREATE TRIGGER no_delete BEFORE DELETE ON events "
                 "BEGIN SELECT RAISE(ABORT, 'fixture: read-only'); END")
    conn.commit(); conn.close()
    rid = app.post(f"{TENANTS}/acme-dup/merge-into/acme-corp", json={"reason": "same customer"},
                   cookies=root["cookies"]).json()["request"]["id"]
    other = _op(app, "root2", "super_admin")
    with pytest.raises(sqlite3.DatabaseError):
        app.post(f"{TENANTS}/requests/{rid}/approve", cookies=other["cookies"])
    assert len(_events("acme-corp")) == 1
    assert _client_row("acme-dup")["status"] == "active"
    assert json.loads(_client_row("acme-corp")["compliance_flags"]) == ["hipaa", "pci"]
    so = next(x for x in _signoffs() if x["id"] == sid)
    assert so["revoked_kind"] == "merge_added_flags"
    assert ai_policy.effective_ai_policy("acme-corp") == "local"
    (undo,) = _audit("tenant_merge_copy_undone")
    assert (undo["after"]["events_left_in_target"], undo["after"]["error"]) == (1, "IntegrityError")
    assert (undo["after"]["target_compliance_flags"], undo["after"]["target_signoffs_revoked"]) == (
        ["hipaa", "pci"], [sid])
    assert "fail closed" in undo["reason"] and "fixture" not in undo["reason"]
    assert _chain_ok()


def test_a_single_person_merge_whose_marker_fails_removes_the_copied_events(app, monkeypatch):
    """Failure AFTER the copy on the attested path (the loud audit marker
    cannot be appended): the registry rolls back and the copied events are
    removed from the target again."""
    create_client("acme-corp", "Acme Corp", kind="client")
    create_client("acme-dup", "Acme Dup", origin="auto")
    _ingest("acme-dup", 2)
    root = _op(app, "root1", "super_admin", elevate=True)
    real_append = audit_log.append

    def append(conn, entry):  # noqa: ANN001 — the audit DB refuses one row
        if entry.action == "tenant_merge_single_attested":
            raise sqlite3.OperationalError("fixture: database is locked")
        return real_append(conn, entry)

    monkeypatch.setattr(audit_log, "append", append)
    with pytest.raises(sqlite3.OperationalError):
        app.post(f"{TENANTS}/acme-dup/merge-into/acme-corp", json={
            "reason": "same customer", "approval_mode": "single_attested",
            "attestation": "Auto-created duplicate of the same customer; checked both today.",
            "confirm_subject": "acme-dup"}, cookies=root["cookies"])
    assert _events("acme-corp") == [] and _client_row("acme-dup")["status"] == "active"
    (undo,) = _audit("tenant_merge_copy_undone")
    assert (undo["after"]["events_copied"], undo["after"]["events_removed"]) == (2, 2)


def test_a_departed_tenant_loses_its_signoffs_and_runs_as_none(app):
    """Offboarded (the client left) or merged away (archived): its sign-offs
    are revoked in the same transaction, recorded in the audit row, and it
    runs as 'none' — no model, local or cloud, reasons over it."""
    _flagged("acme-corp", ["hipaa"])
    _flagged("acme-west", ["hipaa"])
    _flagged("acme-east", ["hipaa"])
    root = _op(app, "root1", "super_admin", elevate=True)
    corp, west, east = (_sign(app, root, slug) for slug in ("acme-corp", "acme-west", "acme-east"))
    alone = {"approval_mode": "single_attested",
             "attestation": "The client has left; cutting off its access today, checked."}
    r = app.post(f"{TENANTS}/acme-west/offboard",
                 json={**alone, "reason": "contract ended", "confirm_subject": "acme-west"},
                 cookies=root["cookies"])
    assert r.status_code == 200 and r.json()["signoffs_revoked"] == [west], r.text
    (off,) = _audit("tenant_offboard")
    assert (off["after"]["compliance_signoffs_revoked"], off["after"]["effective_ai_policy"]) == (
        [west], "none")
    r = app.post(f"{TENANTS}/acme-east/merge-into/acme-corp",
                 json={**alone, "reason": "same customer", "confirm_subject": "acme-east"},
                 cookies=root["cookies"])
    assert r.status_code == 200 and r.json()["subject_signoffs_revoked"] == [east], r.text
    (merged,) = _audit("tenant_merge")
    assert merged["after"]["subject_signoffs_revoked"] == [east]
    for slug, sid in (("acme-west", west), ("acme-east", east)):
        so = next(x for x in _signoffs(slug) if x["id"] == sid)
        assert so["revoked_kind"] == "operator", slug
        t = _tenant(app, root["cookies"], slug)
        assert t["effective_ai_policy"] == "none", slug
        assert t["ai_policy_reason"].endswith("no model reasons over a departed tenant's data")
        assert ai_policy.ai_allowed(slug, "local") is False
    # The surviving target keeps its own sign-off.
    assert ai_policy.effective_ai_policy("acme-corp") == "cloud"
    assert next(x for x in _signoffs() if x["id"] == corp)["revoked_at"] is None


def test_the_dashboard_counts_signoffs_about_to_lapse_and_lapsed(app):
    """Sign-offs made together lapse together: the needs-review counts say
    how many expire within 30 days, and how many 'cloud' tenants already run
    as local because theirs expired."""
    for slug in ("soon-co", "later-co", "lapsed-co", "gone-co"):
        _flagged(slug, ["hipaa"])
    now = datetime.now(timezone.utc)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            for slug, days_ago in (("soon-co", 355), ("later-co", 10), ("lapsed-co", 400),
                                   ("gone-co", 355)):
                ai_policy.record_signoff(
                    reg, slug, flags=["hipaa"], agreement_references={"hipaa": "BAA-2026-014"},
                    attestation_text=TEXT, attestation_version=ai_policy.ATTESTATION_VERSION,
                    operator_id=1, request_id=f"r-{slug}", now=now - timedelta(days=days_ago),
                )
        reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'gone-co'")
        reg.commit()
    finally:
        reg.close()
    admin = _op(app, "admin1", "admin")
    r = app.get(f"{TENANTS}/review-summary", cookies=admin["cookies"])
    assert r.status_code == 200, r.text
    assert (r.json()["signoffs_expiring"], r.json()["signoffs_expired"]) == (1, 1)

