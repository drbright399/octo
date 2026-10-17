"""Tenant manager v0.9 — the review rules and the review at scale, on the real
app, real registry and real audit chain.

Pins: a confirmed tenant keeps a real kind (PATCH and bulk refuse
'unclassified'; since migration 034 the registry refuses a confirmed +
unclassified row outright);
a disabled / offboarded tenant can be confirmed but never counts as "needs
review"; POST /admin/tenants/bulk-update applies PATCH's own rules to many
tenants ALL-OR-NOTHING (a dry run answers the per-row diff; any invalid row
means nothing is written or audited; 'cloud' from an admin refuses the whole
batch), writes one 'tenant_update' audit row per changed tenant and rolls the
registry back — saying so in the chain — if the audit log fails part-way;
the tenant list carries duplicate hints; every new route is admin+.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from apps.octo import paths
from apps.octo.auth import audit
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)
from apps.octo.tests.auth.test_admin_tenants import (  # noqa: F401
    PW,
    TENANTS,
    _admin,
    _audit_actions,
    _chain_ok,
    _client_row,
    _super,
    _tenant,
    app,
)

BULK = f"{TENANTS}/bulk-update"


def _raw_insert(slug: str, display_name: str, **cols: str) -> None:
    """A row the way dev seeds / old fixtures write it: bare SQL, taking the
    column defaults for whatever it does not name."""
    names = ["slug", "display_name", *cols]
    reg = connect(paths.registry_db_path())
    reg.execute(
        f"INSERT INTO clients ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
        [slug, display_name, *cols.values()],
    )
    reg.commit()
    reg.close()


def _set_status(slug: str, status: str) -> None:
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = ? WHERE slug = ?", (status, slug))
    reg.commit()
    reg.close()


def _audit_rows(action: str) -> list[sqlite3.Row]:
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return g.execute(
            "SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,),
        ).fetchall()
    finally:
        g.close()


def _registry_snapshot() -> dict[str, tuple]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {
            r["slug"]: (r["display_name"], r["kind"], r["review_state"],
                        r["compliance_flags"], r["ai_policy"], r["status"])
            for r in reg.execute("SELECT * FROM clients")
        }
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# PATCH — a confirmed tenant keeps a real kind
# ---------------------------------------------------------------------------

def test_patch_on_an_already_confirmed_tenant_with_a_real_kind_succeeds(app):
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp", kind="client", compliance_flags_json='["hipaa"]')
    assert _client_row("acme-corp")["review_state"] == "confirmed"
    r = app.patch(f"{TENANTS}/acme-corp", json={
        "kind": "internal", "compliance_flags": ["hipaa", "pci"], "ai_policy": "local",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    t = r.json()
    assert (t["kind"], t["review_state"], t["ai_policy"]) == ("internal", "confirmed", "local")
    assert t["compliance_flags"] == ["hipaa", "pci"]
    # Re-confirming a confirmed tenant is harmless, too.
    r = app.patch(f"{TENANTS}/acme-corp", json={"review_state": "confirmed"}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert _audit_actions() == ["tenant_update", "tenant_update"] and _chain_ok()


def test_patch_refuses_unclassified_on_a_confirmed_tenant(app):
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp", kind="client")
    for body in ({"kind": "unclassified"},
                 {"kind": "unclassified", "display_name": "Acme Corporation"},
                 {"kind": "unclassified", "review_state": "confirmed"}):
        r = app.patch(f"{TENANTS}/acme-corp", json=body, cookies=cookies)
        assert r.status_code == 422, (body, r.text)
        assert r.json()["code"] == "VALIDATION_FAILED"
    assert "cannot go back to 'unclassified'" in app.patch(
        f"{TENANTS}/acme-corp", json={"kind": "unclassified"}, cookies=cookies,
    ).json()["message"]
    row = _client_row("acme-corp")
    assert (row["kind"], row["display_name"]) == ("client", "Acme Corp")
    assert _audit_actions() == []
    # A PENDING tenant may still be (re)set to unclassified — nothing was confirmed.
    create_client("lab-box", "Lab Box", kind="dev", review_state="pending")
    r = app.patch(f"{TENANTS}/lab-box", json={"kind": "unclassified"}, cookies=cookies)
    assert r.status_code == 200 and r.json()["review_state"] == "pending"


def test_registry_refuses_confirmed_unclassified_rows_since_034(app):
    """Migration 033's column defaults are confirmed + unclassified, so a
    bare-SQL row (dev seed, old fixture) used to land "reviewed" with no kind
    and the admin API had to tolerate it. Since 034 the registry refuses the
    combination on INSERT and UPDATE (triggers) — the seed must name a kind
    or say pending — and the API's own 422 still answers first."""
    cookies = _admin(app)
    with pytest.raises(sqlite3.IntegrityError, match="needs a kind"):
        _raw_insert("legacy-co", "Legacy Co")
    _raw_insert("legacy-co", "Legacy Co", review_state="pending")
    row = _client_row("legacy-co")
    assert (row["kind"], row["review_state"]) == ("unclassified", "pending")
    r = app.patch(f"{TENANTS}/legacy-co", json={"display_name": "Legacy Company"}, cookies=cookies)
    assert r.status_code == 200, r.text
    r = app.patch(f"{TENANTS}/legacy-co", json={"kind": "client", "review_state": "confirmed"},
                  cookies=cookies)
    assert r.status_code == 200 and r.json()["kind"] == "client"
    assert app.patch(f"{TENANTS}/legacy-co", json={"kind": "unclassified"},
                     cookies=cookies).status_code == 422
    # Below the API, the registry itself holds the line.
    reg = connect(paths.registry_db_path())
    try:
        with pytest.raises(sqlite3.IntegrityError, match="needs a kind"):
            reg.execute("UPDATE clients SET kind = 'unclassified' WHERE slug = 'legacy-co'")
    finally:
        reg.close()
    assert _client_row("legacy-co")["kind"] == "client"


def test_non_active_tenants_can_be_confirmed_but_never_count_as_needing_review(app):
    """Migration 033 set every pre-existing row pending, departed ones too.
    They can be confirmed (a kind still required) so none stays pending for
    ever — and the dashboard notice never counted them: a disabled or
    offboarded tenant receives no traffic and blocks nothing."""
    cookies = _admin(app)
    create_client("live-co", "Live Co")                     # pending, active
    create_client("gone-co", "Gone Co")
    create_client("paused-co", "Paused Co")
    _set_status("gone-co", "offboarded")
    _set_status("paused-co", "disabled")
    summary = app.get(f"{TENANTS}/review-summary", cookies=cookies).json()
    assert summary["pending_review"] == 1
    assert app.get(TENANTS, cookies=cookies).json()["pending_review"] == 1

    r = app.patch(f"{TENANTS}/gone-co", json={"review_state": "confirmed"}, cookies=cookies)
    assert r.status_code == 422                                   # still needs a kind
    for slug in ("gone-co", "paused-co"):
        r = app.patch(f"{TENANTS}/{slug}", json={"kind": "client", "review_state": "confirmed"},
                      cookies=cookies)
        assert r.status_code == 200, r.text
        assert r.json()["review_state"] == "confirmed"
        assert r.json()["status"] != "active"                     # confirming never re-activates
    assert app.get(f"{TENANTS}/review-summary", cookies=cookies).json()["pending_review"] == 1


# ---------------------------------------------------------------------------
# Duplicate hints on the list
# ---------------------------------------------------------------------------

def test_list_carries_duplicate_hints_for_live_tenants_only(app):
    cookies = _admin(app)
    create_client("acme-holdings-llc", "Acme Holdings LLC", kind="client")
    create_client("acme-holdings-tax", "Acme Holdings Tax")
    create_client("acme-dental", "Acme Dental")
    create_client("globex-corp", "Globex Corp")
    create_client("globex-inc", "Globex, Inc.")
    create_client("globex-old", "Globex Corporation")
    _set_status("globex-old", "archived")                         # history: never hinted
    create_client("widget-co", "Widget Co")
    _set_status("widget-co", "offboarded")
    create_client("widget-company", "Widget Company")

    by_slug = {t["slug"]: t for t in app.get(TENANTS, cookies=cookies).json()["tenants"]}
    assert by_slug["acme-holdings-tax"]["duplicate_hints"] == [{
        "slug": "acme-holdings-llc", "display_name": "Acme Holdings LLC",
        "status": "active", "rule": "name-prefix"}]
    assert [h["slug"] for h in by_slug["acme-holdings-llc"]["duplicate_hints"]] == ["acme-holdings-tax"]
    assert by_slug["acme-dental"]["duplicate_hints"] == []
    assert [(h["slug"], h["rule"]) for h in by_slug["globex-corp"]["duplicate_hints"]] == [
        ("globex-inc", "same-name")]
    assert by_slug["globex-old"]["duplicate_hints"] == []
    # An offboarded look-alike is still worth a hint (merge it INTO the live one).
    assert by_slug["widget-company"]["duplicate_hints"] == [{
        "slug": "widget-co", "display_name": "Widget Co", "status": "offboarded",
        "rule": "same-name"}]
    # A hint is only a hint: nothing was merged, nothing audited.
    assert _registry_snapshot()["widget-company"][-1] == "active" and _audit_actions() == []


# ---------------------------------------------------------------------------
# Bulk update
# ---------------------------------------------------------------------------

def _seed_review_batch() -> None:
    create_client("acme-corp", "Acme Corp", origin="auto")                 # pending
    create_client("widget-co", "Widget Co", origin="auto")                 # pending
    create_client("lab-box", "Lab Box", kind="dev")                        # confirmed
    create_client("globex-corp", "Globex Corp", kind="client",
                  compliance_flags_json='["hipaa"]')                       # confirmed


def _batch(**patch) -> list[dict]:
    return [{"slug": s, "patch": dict(patch)}
            for s in ("acme-corp", "widget-co", "lab-box", "globex-corp")]


def test_bulk_dry_run_answers_the_per_row_diff_and_writes_nothing(app):
    cookies = _admin(app)
    _seed_review_batch()
    before = _registry_snapshot()
    r = app.post(BULK, json={
        "items": _batch(kind="client", compliance_flags=["hipaa"], review_state="confirmed"),
        "dry_run": True,
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["dry_run"], body["applied"], body["request_id"]) == (True, False, None)
    assert (body["changed"], body["unchanged"], body["errors"], body["refusal"]) == (3, 1, 0, None)
    rows = {row["slug"]: row for row in body["rows"]}
    assert rows["acme-corp"]["display_name"] == "Acme Corp" and rows["acme-corp"]["error"] is None
    assert rows["acme-corp"]["changes"] == [
        {"field": "kind", "before": "unclassified", "after": "client"},
        {"field": "compliance_flags", "before": [], "after": ["hipaa"]},
        {"field": "review_state", "before": "pending", "after": "confirmed"},
    ]
    assert rows["lab-box"]["changes"] == [
        {"field": "kind", "before": "dev", "after": "client"},
        {"field": "compliance_flags", "before": [], "after": ["hipaa"]},
    ]
    assert rows["globex-corp"]["changes"] == []                  # already says all that
    # A preview is not a decision.
    assert _registry_snapshot() == before and _audit_actions() == []


def test_bulk_apply_writes_one_audit_row_per_changed_tenant(app):
    cookies = _admin(app)
    _seed_review_batch()
    r = app.post(BULK, json={
        "items": _batch(kind="client", compliance_flags=["hipaa"], review_state="confirmed"),
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["applied"], body["changed"], body["unchanged"], body["errors"]) == (True, 3, 1, 0)
    snap = _registry_snapshot()
    for slug in ("acme-corp", "widget-co", "lab-box", "globex-corp"):
        assert snap[slug][1:4] == ("client", "confirmed", '["hipaa"]'), slug
    rows = _audit_rows("tenant_update")
    assert [r_["client_slug"] for r_ in rows] == ["acme-corp", "widget-co", "lab-box"]
    assert {r_["request_id"] for r_ in rows} == {body["request_id"]}   # one batch
    first_before, first_after = json.loads(rows[0]["before_state"]), json.loads(rows[0]["after_state"])
    assert (first_before["kind"], first_before["review_state"]) == ("unclassified", "pending")
    assert (first_after["kind"], first_after["review_state"]) == ("client", "confirmed")
    assert "bulk review" in rows[0]["reason"] and _chain_ok()
    # Confirmed by the batch → no longer "needs review".
    assert app.get(f"{TENANTS}/review-summary", cookies=cookies).json()["pending_review"] == 0


@pytest.mark.parametrize("bad_item, code", [
    ({"slug": "nope-co", "patch": {"kind": "client"}}, "CLIENT_NOT_FOUND"),
    ({"slug": "vague-co", "patch": {"review_state": "confirmed"}}, "VALIDATION_FAILED"),
    ({"slug": "lab-box", "patch": {"kind": "unclassified"}}, "VALIDATION_FAILED"),
    ({"slug": "old-co", "patch": {"kind": "client"}}, "CONFLICT"),
    ({"slug": "vague-co", "patch": {"compliance_flags": ["none", "pci"]}}, "VALIDATION_FAILED"),
    ({"slug": "vague-co", "patch": {}}, "VALIDATION_FAILED"),
    ({"slug": "acme-corp", "patch": {"kind": "dev"}}, "VALIDATION_FAILED"),    # listed twice
])
def test_bulk_is_all_or_nothing_with_per_row_errors(app, bad_item, code):
    cookies = _admin(app)
    _seed_review_batch()
    create_client("vague-co", "Vague Co")
    create_client("old-co", "Old Co", kind="client")
    _set_status("old-co", "archived")
    before = _registry_snapshot()
    items = [
        {"slug": "acme-corp", "patch": {"kind": "client", "review_state": "confirmed"}},
        {"slug": "widget-co", "patch": {"kind": "vendor", "review_state": "confirmed"}},
        bad_item,
    ]
    r = app.post(BULK, json={"items": items}, cookies=cookies)
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["code"] == "VALIDATION_FAILED" and body["request_id"]
    assert "Nothing was changed" in body["message"]
    assert body["applied"] is False and body["errors"] == 1
    assert [row["error"] for row in body["rows"][:2]] == [None, None]
    assert body["rows"][0]["changes"]                            # the valid rows' diff is still shown
    assert body["rows"][2]["error"]["code"] == code
    assert _registry_snapshot() == before and _audit_actions() == []
    # The dry run says the same thing, with a 200.
    r = app.post(BULK, json={"items": items, "dry_run": True}, cookies=cookies)
    assert r.status_code == 200 and r.json()["refusal"]["code"] == "VALIDATION_FAILED"


def test_bulk_cloud_from_an_admin_refuses_the_whole_batch(app):
    admin = _admin(app)
    _seed_review_batch()
    before = _registry_snapshot()
    items = [
        {"slug": "acme-corp", "patch": {"kind": "client", "review_state": "confirmed"}},
        {"slug": "lab-box", "patch": {"ai_policy": "local"}},
        {"slug": "globex-corp", "patch": {"ai_policy": "cloud"}},
    ]
    r = app.post(BULK, json={"items": items}, cookies=admin)
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["code"] == "ISOLATION_VIOLATION"
    assert "requires super_admin" in body["message"] and "globex-corp" in body["message"]
    assert [row["error"]["code"] if row["error"] else None for row in body["rows"]] == [
        None, None, "ISOLATION_VIOLATION"]
    assert _registry_snapshot() == before and _audit_actions() == []
    # The role refusal wins over an ordinary validation error in the same batch.
    r = app.post(BULK, json={"items": [*items, {"slug": "nope-co", "patch": {"kind": "client"}}]},
                 cookies=admin)
    assert r.status_code == 403 and r.json()["errors"] == 2
    dry = app.post(BULK, json={"items": items, "dry_run": True}, cookies=admin)
    assert dry.status_code == 200 and dry.json()["refusal"]["code"] == "ISOLATION_VIOLATION"
    # A super_admin applies the same batch.
    root = _super(app)
    r = app.post(BULK, json={"items": items}, cookies=root)
    assert r.status_code == 200, r.text
    assert _tenant(app, root, "globex-corp")["ai_policy"] == "cloud"
    assert len(_audit_rows("tenant_update")) == 3 and _chain_ok()


def test_bulk_rolls_back_and_says_so_when_the_audit_log_fails_part_way(app, monkeypatch):
    """The audit log is its own DB: the registry transaction cannot undo an
    appended row. When the second tenant's audit append fails, every
    registry change is rolled back and a 'tenant_bulk_update_failed' row
    names the tenant whose 'tenant_update' row was already written."""
    cookies = _admin(app)
    _seed_review_batch()
    before = _registry_snapshot()
    real_append = audit.append
    seen = {"n": 0}

    def flaky_append(db, entry):
        if entry.action == "tenant_update":
            seen["n"] += 1
            if seen["n"] == 2:
                raise sqlite3.OperationalError("disk I/O error")
        return real_append(db, entry)

    monkeypatch.setattr(audit, "append", flaky_append)
    with pytest.raises(sqlite3.OperationalError):
        app.post(BULK, json={
            "items": _batch(kind="client", review_state="confirmed"),
        }, cookies=cookies)
    monkeypatch.setattr(audit, "append", real_append)
    assert _registry_snapshot() == before
    assert _audit_actions() == ["tenant_update", "tenant_bulk_update_failed"]
    failed = _audit_rows("tenant_bulk_update_failed")[0]
    after = json.loads(failed["after_state"])
    assert after == {"rolled_back": ["acme-corp"], "error": "OperationalError"}
    assert failed["request_id"] == _audit_rows("tenant_update")[0]["request_id"]
    assert "disk" not in (failed["reason"] or "") and _chain_ok()


def test_bulk_bounds_the_batch(app):
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    too_many = [{"slug": f"t-{n}", "patch": {"kind": "client"}} for n in range(201)]
    assert app.post(BULK, json={"items": too_many}, cookies=cookies).status_code == 422
    assert app.post(BULK, json={"items": []}, cookies=cookies).status_code == 422
    assert _audit_actions() == []


# ---------------------------------------------------------------------------
# Roles — every role, and nobody signed in
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role, status", [
    ("viewer", 403), ("analyst", 403), ("admin", 200), ("super_admin", 200),
])
def test_bulk_update_role_gate(app, role, status):
    create_client("acme-corp", "Acme Corp")
    cookies = app.login(app.provision_operator(f"{role}1", PW, athena_role=role))
    body = {"items": [{"slug": "acme-corp", "patch": {"kind": "client", "review_state": "confirmed"}}]}
    dry = app.post(BULK, json={**body, "dry_run": True}, cookies=cookies)
    assert dry.status_code == status, dry.text
    r = app.post(BULK, json=body, cookies=cookies)
    assert r.status_code == status, r.text
    if status == 403:
        assert r.json()["code"] == "ISOLATION_VIOLATION"
        assert "acme-corp" not in r.text                      # nothing about any tenant leaks
        assert _client_row("acme-corp")["review_state"] == "pending"
        assert _audit_actions() == []
    else:
        assert _client_row("acme-corp")["review_state"] == "confirmed"


def test_bulk_update_and_list_refuse_the_unauthenticated(app):
    create_client("acme-corp", "Acme Corp")
    app.cookies.clear()
    body = {"items": [{"slug": "acme-corp", "patch": {"kind": "client"}}]}
    assert app.post(BULK, json=body).status_code == 401
    assert app.post(BULK, json={**body, "dry_run": True}).status_code == 401
    assert app.get(TENANTS).status_code == 401
    assert _client_row("acme-corp")["kind"] == "unclassified" and _audit_actions() == []
