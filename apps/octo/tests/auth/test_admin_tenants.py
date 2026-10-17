"""Tenant manager + quarantine admin API — on the real app, real registry,
real audit chain, real quarantine store, real Datto adapter for replays.

Pins the product rulings: tags are a curated enum; 'cloud' AI needs a
super_admin; offboard AND merge are a two-person request by default,
approved by a DIFFERENT super_admin — a super_admin may apply one alone only
as the attested exception (v0.10; pinned in test_attested_single_person.py);
an offboarded tenant
is never resurrected by traffic (its mappings are frozen, its default
cleared, its client users cut off); every change is audited and the chain
never says a change happened when it did not; routing from quarantine
ingests through the adapter's own extract path and maps the vendor site,
and never creates a tenant for a payload it cannot replay; viewers and
analysts get 403 on every route here and a scoped viewer never sees another
tenant's data.
"""
from __future__ import annotations

import json
import sqlite3

import pyotp
import pytest

from apps.octo import paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.auth import audit, core as core_auth
from apps.octo.client_provisioning import create_client
from apps.octo.db import connect
from apps.octo.ingest import SqliteIngestSink
from apps.octo.instances import create_instance, quarantine, tenant_autocreate, tenant_map
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)

TENANTS = "/api/v1/admin/tenants"
QUARANTINE = "/api/v1/admin/quarantine"
PW = "password1234567"


@pytest.fixture
def app(instance_endpoint_client):  # noqa: F811
    """The instance-endpoint app plus the real Datto adapter (quarantine
    replays go through it) and a clean quarantine store."""
    quarantine.reset_schema_cache()
    client = instance_endpoint_client
    client.app.state.adapter_registry.register_adapter_class(DattoSourceAdapter)
    yield client
    quarantine.reset_schema_cache()


def _super(app, name="root1"):
    return app.login(app.provision_operator(name, PW, athena_role="super_admin"))


def _admin(app, name="admin1"):
    return app.login(app.provision_operator(name, PW, athena_role="admin"))


def _super_stepped_up(app, name="root1"):
    """A super_admin's cookies with an active step-up window (password +
    TOTP through the real /search/elevate) — what the attested single-person
    offboard / merge needs."""
    op = app.provision_operator(name, PW, athena_role="super_admin")
    cookies = app.login(op)
    r = app.post("/api/v1/search/elevate", json={
        "current_password": PW, "totp_code": pyotp.TOTP(op["totp_secret_b32"]).now(),
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    return cookies


ATTESTATION = (
    "Duplicate created by the integration from a second vendor site; "
    "I checked both tenants and there is no second super admin this week."
)


def _alone(slug: str, reason: str) -> dict:
    """The body of the attested single-person exception (v0.10)."""
    return {"reason": reason, "approval_mode": "single_attested",
            "attestation": ATTESTATION, "confirm_subject": slug}


def _instance() -> int:
    rec = create_instance(
        vendor_slug="datto", display_name="Datto RMM",
        credentials_dict={"DATTO_API_URL": "https://datto-api.example.test",
                          "DATTO_API_KEY": "k", "DATTO_API_SECRET_KEY": "s"},
    )
    return rec.id


def _api_alert(n: int, *, site_uid: str, site_name: str | None = None):
    asi = {"siteUid": site_uid, "deviceName": f"WS-{n:02d}"}
    if site_name:
        asi["siteName"] = site_name
    return {
        "alertUid": f"alert-{n}", "priority": "High", "timestamp": 1700000000 + n,
        "alertSourceInfo": asi,
        "alertContext": {"@class": "eventlog_ctx", "message": f"event {n}"},
    }


def _hold(
    instance_id: int, env: dict, *, door="poll", default: str | None = None,
) -> tenant_autocreate.Delivery:
    adapter = DattoSourceAdapter()
    return tenant_autocreate.deliver(
        instance_id=instance_id, vendor_slug="datto", adapter=adapter, envelope=env,
        event=adapter.extract_event(env), sink=SqliteIngestSink(publish_to_stream=False),
        default_tenant_slug=default, door=door,
    )


def _events(slug: str) -> list[sqlite3.Row]:
    db = paths.client_dir(slug) / "events.db"
    if not db.exists():
        return []
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    finally:
        conn.close()


def _client_row(slug: str) -> dict:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return dict(reg.execute("SELECT * FROM clients WHERE slug = ?", (slug,)).fetchone())
    finally:
        reg.close()


_LIFECYCLE_PREFIXES = ("tenant_", "quarantine_", "adapter_tenant_map_")


def _audit_actions() -> list[str]:
    """Lifecycle audit actions, in order (login / operator rows filtered out)."""
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        return [
            r[0] for r in g.execute("SELECT action FROM audit_log ORDER BY id")
            if r[0].startswith(_LIFECYCLE_PREFIXES)
        ]
    finally:
        g.close()


def _chain_ok() -> bool:
    g = connect(paths.global_audit_db_path())
    try:
        return audit.verify(g)[0]
    finally:
        g.close()


def _tenant(app, cookies, slug) -> dict:
    r = app.get(TENANTS, cookies=cookies)
    assert r.status_code == 200, r.text
    return next(t for t in r.json()["tenants"] if t["slug"] == slug)


# ---------------------------------------------------------------------------
# List / create / patch
# ---------------------------------------------------------------------------

def test_list_shows_lifecycle_fields_mappings_events_and_vocabularies(app):
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp", kind="client", review_state="confirmed",
                  compliance_flags_json='["hipaa"]')
    _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="Widget Co"))   # auto-creates
    _hold(iid, _api_alert(2, site_uid="site-uid-0002"))                          # name-unknown → held

    r = app.get(TENANTS, cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pending_review"] == 1 and body["quarantined"] == 1
    assert body["kinds"][0] == "unclassified" and "hipaa" in body["compliance_tags"]
    assert body["ai_policies"] == ["none", "local", "cloud"]
    by_slug = {t["slug"]: t for t in body["tenants"]}
    acme = by_slug["acme-corp"]
    assert (acme["origin"], acme["kind"], acme["review_state"]) == ("manual", "client", "confirmed")
    assert acme["compliance_flags"] == ["hipaa"] and acme["ai_policy"] == "none"
    assert acme["event_count"] == 0 and acme["mapped_sources"] == []
    widget = by_slug["widget-co"]
    assert (widget["origin"], widget["review_state"]) == ("auto", "pending")
    assert widget["created_by_instance"] == {"instance_id": iid, "vendor": "datto", "label": "Datto RMM"}
    assert widget["event_count"] == 1 and widget["last_event_at"]
    assert widget["mapped_sources"] == [{
        "vendor": "datto", "instance_id": iid, "vendor_tenant_id": "site-uid-0001",
        "label": "Widget Co", "match_source": "auto"}]
    # pending first
    assert body["tenants"][0]["slug"] == "widget-co"
    assert r.headers["cache-control"] == "no-store"


def test_review_summary_counts_pending_tenants_held_events_and_requests(app):
    """The dashboard's 'needs review' notice: three counts, no audit row,
    no per-tenant store read — and 403 below admin."""
    iid = _instance()
    admin = _admin(app)
    create_client("acme-corp", "Acme Corp", kind="client", review_state="confirmed")
    create_client("old-co", "Old Co", review_state="pending")                   # untagged
    _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="Widget Co"))  # auto → pending
    _hold(iid, _api_alert(2, site_uid="site-uid-0002"))                         # name-unknown → held
    _hold(iid, _api_alert(3, site_uid="site-uid-0003"))                         # held
    assert app.post(f"{TENANTS}/acme-corp/offboard", json={"reason": "contract ended"},
                    cookies=admin).status_code == 202

    r = app.get(f"{TENANTS}/review-summary", cookies=admin)
    assert r.status_code == 200, r.text
    assert r.json() == {"pending_review": 2, "quarantined": 2, "pending_requests": 1,
                        "signoffs_expiring": 0, "signoffs_expired": 0}
    assert r.headers["cache-control"] == "no-store"
    # An offboarded pending tenant no longer counts (only ACTIVE ones need a tag).
    root = _super_stepped_up(app)
    assert app.post(f"{TENANTS}/old-co/offboard", json=_alone("old-co", "gone for good"),
                    cookies=root).status_code == 200
    before = _audit_actions()
    assert app.get(f"{TENANTS}/review-summary", cookies=root).json()["pending_review"] == 1
    # Reads are not decisions: the glance wrote nothing to the audit chain.
    assert _audit_actions() == before and _chain_ok()
    for role in ("viewer", "analyst"):
        cookies = app.login(app.provision_operator(f"{role}9", PW, athena_role=role))
        assert app.get(f"{TENANTS}/review-summary", cookies=cookies).status_code == 403


def test_create_tenant_with_kind_and_compliance_is_audited(app):
    cookies = _admin(app)
    r = app.post(TENANTS, json={
        "slug": "new-co", "display_name": "  New   Co ", "kind": "client",
        "compliance_flags": ["pci", "hipaa"],
    }, cookies=cookies)
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["display_name"] == "New Co" and t["review_state"] == "confirmed"
    assert t["compliance_flags"] == ["hipaa", "pci"] and t["origin"] == "manual"
    assert (paths.client_dir("new-co") / "events.db").exists()
    assert _audit_actions() == ["tenant_create"] and _chain_ok()
    # The legacy list still works and shows it.
    legacy = app.get("/api/v1/admin/clients", cookies=cookies).json()["clients"]
    assert [c["slug"] for c in legacy] == ["new-co"]
    # Unclassified on creation → still needs review.
    r = app.post(TENANTS, json={"slug": "vague", "display_name": "Vague"}, cookies=cookies)
    assert r.status_code == 201 and r.json()["review_state"] == "pending"


@pytest.mark.parametrize("body, code", [
    ({"slug": "Bad Slug", "display_name": "x"}, 422),
    ({"slug": "ok-co", "display_name": "x", "kind": "ignored"}, 422),
    ({"slug": "ok-co", "display_name": "x", "compliance_flags": ["gdpr"]}, 422),
    ({"slug": "ok-co", "display_name": "x", "compliance_flags": ["none", "pci"]}, 422),
    ({"slug": "ok-co", "display_name": "x", "ai_policy": "cloud"}, 403),
    ({"slug": "ok-co", "display_name": "x", "ai_policy": "maybe"}, 422),
])
def test_create_validates_enums_and_cloud_ai_needs_super_admin(app, body, code):
    cookies = _admin(app)
    r = app.post(TENANTS, json=body, cookies=cookies)
    assert r.status_code == code, r.text
    assert _audit_actions() == []                      # refused before anything happens


def test_create_conflict_on_existing_slug(app):
    cookies = _admin(app)
    create_client("acme-corp", "Acme")
    r = app.post(TENANTS, json={"slug": "acme-corp", "display_name": "Again"}, cookies=cookies)
    assert r.status_code == 409 and _audit_actions() == []


def test_patch_updates_fields_with_before_after_audit(app):
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp", origin="auto", review_state="pending")
    r = app.patch(f"{TENANTS}/acme-corp", json={
        "display_name": "Acme Corporation", "kind": "client",
        "compliance_flags": ["cjis"], "ai_policy": "local", "review_state": "confirmed",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    t = r.json()
    assert (t["display_name"], t["kind"], t["review_state"], t["ai_policy"]) == (
        "Acme Corporation", "client", "confirmed", "local")
    assert t["compliance_flags"] == ["cjis"]
    g = connect(paths.global_audit_db_path(), read_only=True)
    row = g.execute("SELECT * FROM audit_log WHERE action = 'tenant_update'").fetchone()
    g.close()
    before, after = json.loads(row["before_state"]), json.loads(row["after_state"])
    assert before["kind"] == "unclassified" and after["kind"] == "client"
    assert before["ai_policy"] == "none" and after["ai_policy"] == "local"
    assert row["client_slug"] == "acme-corp" and _chain_ok()
    # The LLM escalation gate reads the same column.
    from apps.octo.agent.llm_escalation import tenant_ai_consumption_allowed
    assert tenant_ai_consumption_allowed("acme-corp") is True


@pytest.mark.parametrize("body, code", [
    ({"kind": "ignored"}, 422),
    ({"compliance_flags": ["sox"]}, 422),
    ({"ai_policy": "cloud"}, 403),
    ({"review_state": "pending"}, 422),
    ({"review_state": "confirmed"}, 422),        # still unclassified
    ({}, 422),
    ({"display_name": "   "}, 422),
])
def test_patch_validation(app, body, code):
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    r = app.patch(f"{TENANTS}/acme-corp", json=body, cookies=cookies)
    assert r.status_code == code, r.text
    assert "tenant_update" not in _audit_actions()


def test_super_admin_may_set_cloud_ai(app):
    cookies = _super(app)
    create_client("acme-corp", "Acme Corp")
    r = app.patch(f"{TENANTS}/acme-corp", json={"ai_policy": "cloud"}, cookies=cookies)
    assert r.status_code == 200 and r.json()["ai_policy"] == "cloud"


def test_patch_unknown_tenant_is_404(app):
    cookies = _admin(app)
    assert app.patch(f"{TENANTS}/nope", json={"kind": "client"}, cookies=cookies).status_code == 404


# ---------------------------------------------------------------------------
# Offboard
# ---------------------------------------------------------------------------

def _mint_token(slug: str) -> None:
    plaintext = core_auth.generate_token()
    reg = connect(paths.registry_db_path())
    reg.execute(
        "INSERT INTO client_tokens (slug, token_hash, token_prefix, kind, label, created_by) "
        "VALUES (?, ?, ?, 'buoy', 'test', 'test')",
        (slug, core_auth.hash_token(plaintext), core_auth.token_prefix(plaintext)),
    )
    reg.commit(); reg.close()


def _set_scope(operator_id: int, slugs: list[str]) -> None:
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE operator_roles SET scope_slugs = ? WHERE operator_id = ?",
                (json.dumps(slugs), operator_id))
    reg.commit(); reg.close()


def _set_default_tenant(instance_id: int, slug: str | None) -> None:
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE adapter_instances SET default_tenant_slug = ? WHERE id = ?",
                (slug, instance_id))
    reg.commit(); reg.close()


def _client_rows() -> dict[str, str]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {r[0]: r[1] for r in reg.execute("SELECT slug, status FROM clients")}
    finally:
        reg.close()


def test_super_admin_offboards_alone_and_traffic_then_quarantines(app):
    """Ruling 5 in substance: a departed client's sites must never re-collect
    its data into a look-alike tenant. The site whose vendor name DIFFERS
    from the display name (a hand-mapped branch office) is the case that
    used to slip through when offboard deleted the mappings. (Applied here
    through the attested single-person exception — v0.10.)"""
    iid = _instance()
    cookies = _super_stepped_up(app)
    _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="Acme Corp"))   # auto-create + map
    # A second site, mapped by hand, whose vendor name is nothing like "Acme Corp".
    tenant_map.set_mappings(iid, [
        tenant_map.TenantMapping("site-uid-0001", "acme-corp"),
        tenant_map.TenantMapping("site-uid-0002", "acme-corp", vendor_tenant_label="Branch Office North"),
    ])
    _mint_token("acme-corp")
    _set_default_tenant(iid, "acme-corp")
    assert len(_events("acme-corp")) == 1

    r = app.post(f"{TENANTS}/acme-corp/offboard", json=_alone("acme-corp", "contract ended"),
                 cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {
        "slug": "acme-corp", "applied": True, "status": "offboarded", "request": None,
        "mappings_frozen": 2,
        "access": {"tokens_revoked": 1, "sessions_revoked": 0, "scoped_operators": 0,
                   "instance_defaults_cleared": 1},
        "signoffs_revoked": [],
        "approval_mode": "single_attested", "change_request_id": 1,
        "post_review_state": "pending",
        # Nobody else to tell on this bundle.
        "notifications": {"recipients": 0, "in_app_error": None, "email": "none"},
    }
    row = _client_row("acme-corp")
    assert row["status"] == "offboarded" and row["offboarded_at"]
    # Mappings are FROZEN, not deleted: the sites stay known as this tenant's.
    assert {m.vendor_tenant_id: m.octo_client_slug for m in tenant_map.get_mappings(iid)} == {
        "site-uid-0001": "acme-corp", "site-uid-0002": "acme-corp"}
    reg = connect(paths.registry_db_path(), read_only=True)
    assert reg.execute("SELECT revoked_at, revoked_by FROM client_tokens").fetchone()[0]
    assert reg.execute("SELECT default_tenant_slug FROM adapter_instances").fetchone()[0] is None
    reg.close()
    assert len(_events("acme-corp")) == 1                    # data retained
    assert _audit_actions()[-2:] == ["tenant_offboard", "tenant_offboard_single_attested"]
    assert _chain_ok()

    # Ruling 5: the sites' next events are held, never resurrect the tenant —
    # and never create a look-alike from the branch office's own name.
    d = _hold(iid, _api_alert(2, site_uid="site-uid-0001", site_name="Acme Corp"))
    assert d.status == "quarantined" and d.reason == "offboarded-tenant"
    d = _hold(iid, _api_alert(3, site_uid="site-uid-0002", site_name="Branch Office North"))
    assert d.status == "quarantined" and d.reason == "offboarded-tenant"
    assert _client_rows() == {"acme-corp": "offboarded"}     # no 'branch-office-north'
    assert len(_events("acme-corp")) == 1
    # An id-less event no longer lands in the departed default either.
    env = _api_alert(4, site_uid="")
    del env["alertSourceInfo"]["siteUid"]
    assert _hold(iid, env).reason == "no-tenant-id"
    # Twice is a conflict — and a refused offboard writes no audit row.
    before = _audit_actions()
    r = app.post(f"{TENANTS}/acme-corp/offboard", json=_alone("acme-corp", "again"), cookies=cookies)
    assert r.status_code == 409 and _audit_actions() == before
    # Held 'offboarded-tenant' traffic can still be routed by a HUMAN into a
    # new tenant (a re-signed customer under a new contract): the mapping is
    # re-pointed, nothing was done by itself.
    qid = quarantine.held_ids_for_vendor_tenant(iid, "site-uid-0002")[0]
    r = app.post(f"{QUARANTINE}/{qid}/route", json={
        "new": {"display_name": "Acme Corp (2027)", "kind": "client"},
    }, cookies=cookies)
    assert r.status_code == 200 and r.json()["mapping_written"] is True
    assert tenant_map.resolve(iid, "site-uid-0002") == "acme-corp-2027"
    assert tenant_map.resolve(iid, "site-uid-0001") == "acme-corp"     # still frozen


def test_offboard_cuts_off_the_tenants_own_users_and_the_dashboard_stops_at_once(app):
    """Viewers are CLIENT users. When their tenant leaves: live sessions are
    ended, and even a fresh sign-in sees nothing — the scoped reads drop a
    slug whose tenant is not active without waiting for anyone to edit the
    operator. The count of such accounts is reported so they get removed."""
    create_client("gone-co", "Gone Co")
    create_client("stays-co", "Stays Co")
    adapter = DattoSourceAdapter()
    sink = SqliteIngestSink(publish_to_stream=False)
    from datetime import datetime, timezone
    now = int(datetime.now(timezone.utc).timestamp()) - 60
    for n in range(3):
        sink.ingest("gone-co", "datto", adapter.extract_event(
            {**_api_alert(n, site_uid="s-a"), "timestamp": now - n}))
    viewer = app.provision_operator("viewer1", PW, athena_role="viewer")
    _set_scope(viewer["id"], ["gone-co"])
    both = app.provision_operator("viewer2", PW, athena_role="viewer")
    _set_scope(both["id"], ["gone-co", "stays-co"])
    v_cookies = app.login(viewer)
    b_cookies = app.login(both)
    r = app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=v_cookies)
    assert r.status_code == 200 and r.json()["scope_slugs"] == ["gone-co"]
    assert sum(p["v"] for p in r.json()["points"]) == 3

    root = _super_stepped_up(app)
    r = app.post(f"{TENANTS}/gone-co/offboard", json=_alone("gone-co", "contract ended"), cookies=root)
    assert r.status_code == 200, r.text
    assert r.json()["access"] == {"tokens_revoked": 0, "sessions_revoked": 2,
                                  "scoped_operators": 2, "instance_defaults_cleared": 0}
    # Their sessions are gone …
    assert app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=v_cookies).status_code == 401
    assert app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=b_cookies).status_code == 401
    # … and after signing in again the departed tenant is simply not theirs.
    r = app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=app.login(viewer))
    assert r.status_code == 200 and r.json()["scope_slugs"] == []
    assert sum(p["v"] for p in r.json()["points"]) == 0 and "gone-co" not in r.text
    r = app.get("/api/v1/dashboard/throughput?window_hours=24", cookies=app.login(both))
    assert r.status_code == 200 and r.json()["scope_slugs"] == ["stays-co"]
    # Search resolves scope by the same rule (its routes sit behind step-up).
    from apps.octo.api.routers.search import _resolve_caller_scope
    assert _resolve_caller_scope(viewer["id"]) == []
    assert _resolve_caller_scope(both["id"]) == ["stays-co"]
    # The super_admin's own ('*') session was never touched.
    assert app.get(TENANTS, cookies=root).status_code == 200
    g = connect(paths.global_audit_db_path(), read_only=True)
    after = json.loads(g.execute(
        "SELECT after_state FROM audit_log WHERE action = 'tenant_offboard'").fetchone()[0])
    g.close()
    assert sorted(after["scoped_operators"]) == sorted([viewer["id"], both["id"]])


def test_admin_offboard_is_a_request_applied_by_a_different_super_admin(app):
    create_client("acme-corp", "Acme Corp")
    admin = _admin(app)
    r = app.post(f"{TENANTS}/acme-corp/offboard", json={"reason": "contract ended"}, cookies=admin)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["applied"] is False and body["status"] == "active"
    req = body["request"]
    assert req["kind"] == "offboard" and req["state"] == "pending"
    assert _client_row("acme-corp")["status"] == "active"
    assert _tenant(app, admin, "acme-corp")["pending_request"]["id"] == req["id"]
    # A second request for the same tenant is refused while one is pending.
    r = app.post(f"{TENANTS}/acme-corp/offboard", json={"reason": "again"}, cookies=admin)
    assert r.status_code == 409
    # The queue lists it; admins may read the queue but not decide.
    assert [q["id"] for q in app.get(f"{TENANTS}/requests", cookies=admin).json()["requests"]] == [req["id"]]
    assert app.post(f"{TENANTS}/requests/{req['id']}/approve", cookies=admin).status_code == 403
    assert app.post(f"{TENANTS}/requests/{req['id']}/reject", cookies=admin).status_code == 403

    root = _super(app)
    r = app.post(f"{TENANTS}/requests/{req['id']}/approve", json={"note": "ok"}, cookies=root)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "applied" and r.json()["decision_note"] == "ok"
    assert _client_row("acme-corp")["status"] == "offboarded"
    assert _audit_actions() == [
        "tenant_change_request_create", "tenant_change_request_approve", "tenant_offboard",
    ] and _chain_ok()
    # Applied requests cannot be decided again.
    assert app.post(f"{TENANTS}/requests/{req['id']}/approve", cookies=root).status_code == 409
    assert app.get(f"{TENANTS}/requests?state=applied", cookies=root).json()["requests"][0]["id"] == req["id"]


def test_self_approval_is_refused_and_requester_may_cancel(app):
    create_client("acme-corp", "Acme Corp")
    create_client("acme-dup", "Acme Corp (old)")
    # An admin asks for a merge, then is promoted: still NOT their call.
    admin = app.provision_operator("later-root", PW, athena_role="admin")
    cookies = app.login(admin)
    r = app.post(f"{TENANTS}/acme-dup/merge-into/acme-corp", json={"reason": "dup"}, cookies=cookies)
    assert r.status_code == 202, r.text
    assert r.json()["applied"] is False
    rid = r.json()["request"]["id"]
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE operator_roles SET role_name = 'super_admin' WHERE operator_id = ?", (admin["id"],))
    reg.commit(); reg.close()
    before = _audit_actions()
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=cookies)
    assert r.status_code == 409 and "two-person" in r.json()["message"]
    assert _client_row("acme-dup")["status"] == "active"
    # Nor reject it — but may cancel it. A refusal leaves no audit trace.
    assert app.post(f"{TENANTS}/requests/{rid}/reject", cookies=cookies).status_code == 409
    assert _audit_actions() == before
    other = _super(app, "root2")
    assert app.post(f"{TENANTS}/requests/{rid}/cancel", cookies=other).status_code == 403
    r = app.post(f"{TENANTS}/requests/{rid}/cancel", json={"note": "changed my mind"}, cookies=cookies)
    assert r.status_code == 200 and r.json()["state"] == "cancelled"
    assert _audit_actions()[-1] == "tenant_change_request_cancel"


def test_reject_leaves_the_tenant_alone(app):
    create_client("acme-corp", "Acme Corp")
    admin = _admin(app)
    rid = app.post(f"{TENANTS}/acme-corp/offboard", json={"reason": "bye"}, cookies=admin).json()["request"]["id"]
    root = _super(app)
    r = app.post(f"{TENANTS}/requests/{rid}/reject", json={"note": "still a customer"}, cookies=root)
    assert r.status_code == 200 and r.json()["state"] == "rejected"
    assert _client_row("acme-corp")["status"] == "active"
    assert _tenant(app, admin, "acme-corp")["pending_request"] is None
    assert "tenant_change_request_reject" in _audit_actions() and "tenant_offboard" not in _audit_actions()


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def test_merge_request_then_approve_moves_events_idempotently_and_archives_subject(app):
    iid = _instance()
    create_client("acme-corp", "Acme Corp", kind="client", review_state="confirmed")
    # The subject: auto-created from a differently-named site, with 3 events.
    for n in (1, 2, 3):
        _hold(iid, _api_alert(n, site_uid="site-uid-0002", site_name="Acme Corp North"))
    assert len(_events("acme-corp-north")) == 3
    # One of them is ALREADY in the target (same source/payload/timestamp).
    shared = _api_alert(2, site_uid="site-uid-0002", site_name="Acme Corp North")
    adapter = DattoSourceAdapter()
    SqliteIngestSink(publish_to_stream=False).ingest("acme-corp", "datto", adapter.extract_event(shared))
    assert len(_events("acme-corp")) == 1

    _mint_token("acme-corp-north")
    _set_default_tenant(iid, "acme-corp-north")
    assert tenant_autocreate.autocreate_status(iid)["pending"] == 1

    admin = _admin(app)
    r = app.post(f"{TENANTS}/acme-corp-north/merge-into/acme-corp",
                 json={"reason": "same customer"}, cookies=admin)
    assert r.status_code == 202, r.text
    assert r.json()["applied"] is False and r.json()["status"] == "active"
    req = r.json()["request"]
    rid = req["id"]
    assert req["kind"] == "merge" and req["target_slug"] == "acme-corp"
    # Not applied by asking.
    assert _client_row("acme-corp-north")["status"] == "active"
    assert tenant_map.resolve(iid, "site-uid-0002") == "acme-corp-north"

    root = _super(app)
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root)
    assert r.status_code == 200, r.text
    subject = _client_row("acme-corp-north")
    assert subject["status"] == "archived" and subject["archived_at"]
    assert subject["notes"] == "merged into acme-corp"
    assert tenant_map.resolve(iid, "site-uid-0002") == "acme-corp"     # re-pointed
    target_events = _events("acme-corp")
    assert len(target_events) == 3                                      # 1 + 2 new, 1 skipped
    assert sorted(json.loads(e["payload"])["alertUid"] for e in target_events) == [
        "alert-1", "alert-2", "alert-3"]
    assert all(e["event_type"] == "datto.eventlog" for e in target_events)
    assert len(_events("acme-corp-north")) == 3                          # subject data untouched
    assert _audit_actions()[-2:] == ["tenant_change_request_approve", "tenant_merge"] and _chain_ok()
    # The subject's own side is cut off and the instance default follows the data.
    reg = connect(paths.registry_db_path(), read_only=True)
    assert reg.execute("SELECT revoked_at FROM client_tokens WHERE slug = 'acme-corp-north'").fetchone()[0]
    assert reg.execute("SELECT default_tenant_slug FROM adapter_instances").fetchone()[0] == "acme-corp"
    reg.close()
    # A merged pending tenant no longer holds an auto-create cap slot.
    assert tenant_autocreate.autocreate_status(iid)["pending"] == 0
    # Traffic from the merged site now lands in the target.
    d = _hold(iid, _api_alert(9, site_uid="site-uid-0002", site_name="Acme Corp North"))
    assert d.status == "stored" and d.slug == "acme-corp"
    # Re-approving is impossible; a second merge of an archived subject is refused.
    r = app.post(f"{TENANTS}/acme-corp-north/merge-into/acme-corp", json={"reason": "once more"}, cookies=admin)
    assert r.status_code == 409


def test_one_super_admin_can_still_clear_duplicates_alone_on_attestation(app):
    """A deployment with ONE super_admin (the bootstrap bundle mints one) must
    not be stuck with duplicate auto-created tenants: two-person approval is
    the default, and the attested single-person exception (v0.10) is how a
    lone super_admin merges the usual case — an untagged auto-created
    duplicate. Admin merges stay two-person."""
    iid = _instance()
    create_client("acme-corp", "Acme Corp", kind="client", review_state="confirmed")
    _hold(iid, _api_alert(1, site_uid="site-uid-0002", site_name="Acme Corp North"))
    root = _super_stepped_up(app)
    r = app.post(f"{TENANTS}/acme-corp-north/merge-into/acme-corp",
                 json=_alone("acme-corp-north", "same customer"), cookies=root)
    assert r.status_code == 200, r.text
    assert r.json() == {
        "slug": "acme-corp-north", "target": "acme-corp", "applied": True, "status": "archived",
        "request": None, "mappings_repointed": 1, "events_copied": 1, "events_skipped": 0,
        "access": {"tokens_revoked": 0, "sessions_revoked": 0, "scoped_operators": 0,
                   "instance_defaults_cleared": 0},
        # Neither tenant carries a compliance regime: nothing to reconcile.
        "target_flags_added": [], "target_flags_after": [], "signoffs_invalidated": [],
        "subject_signoffs_revoked": [],
        "approval_mode": "single_attested", "change_request_id": 1,
        "post_review_state": "pending",
        "notifications": {"recipients": 0, "in_app_error": None, "email": "none"},
    }
    assert _client_row("acme-corp-north")["status"] == "archived"
    assert len(_events("acme-corp")) == 1
    assert tenant_map.resolve(iid, "site-uid-0002") == "acme-corp"
    assert _audit_actions() == [
        "tenant_auto_create", "tenant_merge", "tenant_merge_single_attested",
    ] and _chain_ok()
    # Nothing waits in the two-person queue; the change is on record, applied.
    assert app.get(f"{TENANTS}/requests", cookies=root).json()["requests"] == []
    (rec,) = app.get(f"{TENANTS}/requests?state=all&approval_mode=single_attested",
                     cookies=root).json()["requests"]
    assert (rec["id"], rec["state"], rec["attestation"]) == (1, "applied", ATTESTATION)


def test_merge_refuses_self_unknown_inactive_and_oversize(app, monkeypatch):
    from apps.octo.api.routers import admin_tenants

    create_client("a-co", "A")
    create_client("b-co", "B")
    admin = _admin(app)
    why = {"reason": "same customer"}
    assert app.post(f"{TENANTS}/a-co/merge-into/a-co", json=why, cookies=admin).status_code == 422
    assert app.post(f"{TENANTS}/a-co/merge-into/nope", json=why, cookies=admin).status_code == 404
    assert app.post(f"{TENANTS}/a-co/merge-into/b-co", json={"reason": "x"}, cookies=admin).status_code == 422
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'disabled' WHERE slug = 'b-co'"); reg.commit(); reg.close()
    assert app.post(f"{TENANTS}/a-co/merge-into/b-co", json=why, cookies=admin).status_code == 409
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'active' WHERE slug = 'b-co'"); reg.commit(); reg.close()
    SqliteIngestSink(publish_to_stream=False).ingest(
        "a-co", "datto", DattoSourceAdapter().extract_event(_api_alert(1, site_uid="s")))
    monkeypatch.setattr(admin_tenants, "MERGE_MAX_EVENTS", 0)
    r = app.post(f"{TENANTS}/a-co/merge-into/b-co", json=why, cookies=admin)
    assert r.status_code == 409 and "more than the 0" in r.json()["message"]
    assert _audit_actions() == []


def test_merge_refused_while_either_tenants_flags_are_unreadable(app):
    """Unreadable stored flags (bare SQL, or a newer vocabulary after a
    downgrade) would read as 'untagged' in the union/eligibility rules and a
    regime could silently fall off the merged tenant — so any merge (request
    or single-person) is refused until the tags are fixed."""
    create_client("dup-co", "Dup Co")
    create_client("keep-co", "Keep Co")
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET compliance_flags = '[\"HIPAA\"]' WHERE slug = 'dup-co'")
    reg.commit(); reg.close()
    admin = _admin(app)
    r = app.post(f"{TENANTS}/dup-co/merge-into/keep-co", json={"reason": "same customer"}, cookies=admin)
    assert r.status_code == 409 and "cannot read" in r.json()["message"]
    # The other direction (unreadable TARGET) is refused too.
    r = app.post(f"{TENANTS}/keep-co/merge-into/dup-co", json={"reason": "same customer"}, cookies=admin)
    assert r.status_code == 409 and "cannot read" in r.json()["message"]
    assert _client_row("dup-co")["status"] == "active"
    assert _audit_actions() == []


def test_approve_audits_only_what_happened(app):
    """The audit DB is separate from the registry transaction, so the chain
    must be written in the right order: a refused approval (target no longer
    active) leaves NO approve row, and an apply that fails after the checks
    (a broken target store) is audited as failed, with the request still
    pending — never 'approved, merged' for a merge that rolled back."""
    create_client("subject-co", "Subject Co")
    create_client("target-co", "Target Co")
    SqliteIngestSink(publish_to_stream=False).ingest(
        "subject-co", "datto", DattoSourceAdapter().extract_event(_api_alert(1, site_uid="s")))
    admin = _admin(app)
    r = app.post(f"{TENANTS}/subject-co/merge-into/target-co", json={"reason": "dup"}, cookies=admin)
    rid = r.json()["request"]["id"]
    root = _super(app)

    # 1. Precondition fails → 409, nothing audited, request untouched.
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'disabled' WHERE slug = 'target-co'"); reg.commit(); reg.close()
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root)
    assert r.status_code == 409 and "not active" in r.json()["message"]
    assert _audit_actions() == ["tenant_change_request_create"]
    reg = connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'active' WHERE slug = 'target-co'"); reg.commit(); reg.close()

    # 2. The apply itself fails (the target's store is not a database). No
    #    'tenant_merge' row exists for a merge that rolled back: the merge
    #    audits itself only after the copy, and as failed otherwise.
    target_db = paths.client_db_path("target-co", "events")
    good = target_db.read_bytes()
    target_db.write_bytes(b"this is not a sqlite file" * 8)
    with pytest.raises(sqlite3.DatabaseError):          # the TestClient re-raises the 500
        app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root)
    assert _client_row("subject-co")["status"] == "active"
    assert app.get(f"{TENANTS}/requests", cookies=root).json()["requests"][0]["id"] == rid
    assert _audit_actions() == [
        "tenant_change_request_create", "tenant_change_request_approve",
        "tenant_merge_failed", "tenant_change_request_apply_failed",
    ] and _chain_ok()
    g = connect(paths.global_audit_db_path(), read_only=True)
    failed = g.execute(
        "SELECT after_state, reason FROM audit_log WHERE action = 'tenant_change_request_apply_failed'",
    ).fetchone()
    g.close()
    assert json.loads(failed["after_state"])["state"] == "pending"
    assert "stays pending" in failed["reason"]
    assert "sqlite" not in failed["reason"].lower()      # the type, never the message

    # 3. Store repaired → the retry applies once.
    target_db.write_bytes(good)
    r = app.post(f"{TENANTS}/requests/{rid}/approve", cookies=root)
    assert r.status_code == 200 and r.json()["state"] == "applied"
    assert _client_row("subject-co")["status"] == "archived" and len(_events("target-co")) == 1
    assert _audit_actions()[-2:] == ["tenant_change_request_approve", "tenant_merge"] and _chain_ok()


def test_direct_merge_audits_success_only_after_the_copy_succeeded(app):
    """The super_admin's direct merge used to append 'tenant_merge' (after
    state: archived) BEFORE copying the events; a corrupt target store then
    rolled the registry back while the chain claimed the merge happened. Now
    the success row is written only after copy + registry changes; a failure
    is a 'tenant_merge_failed' row naming the error CLASS (never a path)."""
    iid = _instance()
    create_client("subject-co", "Subject Co")
    create_client("target-co", "Target Co")
    SqliteIngestSink(publish_to_stream=False).ingest(
        "subject-co", "datto", DattoSourceAdapter().extract_event(_api_alert(1, site_uid="s")))
    tenant_map.set_mappings(iid, [tenant_map.TenantMapping("site-uid-0007", "subject-co")])
    _set_default_tenant(iid, "subject-co")
    root = _super_stepped_up(app)

    target_db = paths.client_db_path("target-co", "events")
    good = target_db.read_bytes()
    target_db.write_bytes(b"this is not a sqlite file" * 8)
    with pytest.raises(sqlite3.DatabaseError):          # a 500; the TestClient re-raises it
        app.post(f"{TENANTS}/subject-co/merge-into/target-co", json=_alone("subject-co", "dup"),
                 cookies=root)
    # Subject untouched: still active, its mapping and the default still its own.
    assert _client_row("subject-co")["status"] == "active"
    assert tenant_map.resolve(iid, "site-uid-0007") == "subject-co"
    reg = connect(paths.registry_db_path(), read_only=True)
    assert reg.execute("SELECT default_tenant_slug FROM adapter_instances").fetchone()[0] == "subject-co"
    reg.close()
    assert _audit_actions() == ["tenant_merge_failed"] and _chain_ok()
    # The single-person change record rolled back with everything else.
    assert app.get(f"{TENANTS}/requests?state=all", cookies=root).json()["requests"] == []
    g = connect(paths.global_audit_db_path(), read_only=True)
    failed = g.execute(
        "SELECT after_state, reason FROM audit_log WHERE action = 'tenant_merge_failed'",
    ).fetchone()
    g.close()
    after = json.loads(failed["after_state"])
    assert after["subject_status"] == "active" and after["merged_into"] is None
    assert after["error"] == "DatabaseError"
    assert "DatabaseError" in failed["reason"] and "nothing archived" in failed["reason"]
    assert "sqlite" not in failed["reason"].lower() and "/" not in failed["reason"]

    # Store repaired → the retry applies, and only then is 'tenant_merge' written.
    target_db.write_bytes(good)
    r = app.post(f"{TENANTS}/subject-co/merge-into/target-co", json=_alone("subject-co", "dup"),
                 cookies=root)
    assert r.status_code == 200 and r.json()["applied"] is True, r.text
    assert _client_row("subject-co")["status"] == "archived" and len(_events("target-co")) == 1
    assert tenant_map.resolve(iid, "site-uid-0007") == "target-co"
    assert _audit_actions() == [
        "tenant_merge_failed", "tenant_merge", "tenant_merge_single_attested",
    ] and _chain_ok()
    g = connect(paths.global_audit_db_path(), read_only=True)
    merged = json.loads(g.execute(
        "SELECT after_state FROM audit_log WHERE action = 'tenant_merge'").fetchone()[0])
    g.close()
    assert merged["events_copied"] == 1 and merged["mappings_repointed"] == 1


def test_offboarding_the_target_of_a_pending_merge_cancels_the_request(app):
    """A request whose TARGET left can never be applied: it is cancelled so
    it neither locks the subject nor sits in the queue for ever."""
    create_client("a-co", "A Co")
    create_client("b-co", "B Co")
    admin = _admin(app)
    rid = app.post(f"{TENANTS}/a-co/merge-into/b-co", json={"reason": "dup"},
                   cookies=admin).json()["request"]["id"]
    root = _super_stepped_up(app)
    assert app.post(f"{TENANTS}/b-co/offboard", json=_alone("b-co", "gone"),
                    cookies=root).status_code == 200
    assert app.get(f"{TENANTS}/requests", cookies=root).json()["requests"] == []
    gone = app.get(f"{TENANTS}/requests?state=cancelled", cookies=root).json()["requests"][0]
    assert gone["id"] == rid and gone["decision_note"] == "superseded: tenant offboarded"
    assert app.get(f"{TENANTS}/review-summary", cookies=root).json()["pending_requests"] == 0
    # a-co is free again.
    assert _tenant(app, root, "a-co")["pending_request"] is None
    r = app.post(f"{TENANTS}/a-co/offboard", json={"reason": "also gone"}, cookies=admin)
    assert r.status_code == 202


def test_legacy_admin_clients_post_creates_a_pending_audited_tenant(app):
    """The mapping panel's 'create client on the spot' goes through the same
    door as POST /admin/tenants: born unclassified → pending review, and
    audited (every tenant creation is)."""
    cookies = _admin(app)
    r = app.post("/api/v1/admin/clients", json={"slug": "spot-co", "display_name": " Spot  Co "},
                 cookies=cookies)
    assert r.status_code == 201, r.text
    # A hand-made tenant never carries an auto-create placeholder.
    assert r.json() == {"slug": "spot-co", "display_name": "Spot Co", "status": "active",
                        "placeholder_name": False, "placeholder_slug": False}
    row = _client_row("spot-co")
    assert (row["origin"], row["kind"], row["review_state"], row["ai_policy"]) == (
        "manual", "unclassified", "pending", "none")
    assert (paths.client_dir("spot-co") / "events.db").exists()
    assert _audit_actions() == ["tenant_create"] and _chain_ok()
    assert app.get(f"{TENANTS}/review-summary", cookies=cookies).json()["pending_review"] == 1
    assert _tenant(app, cookies, "spot-co")["review_state"] == "pending"
    # The legacy route refuses the same things the new one does.
    assert app.post("/api/v1/admin/clients", json={"slug": "spot-co", "display_name": "Again"},
                    cookies=cookies).status_code == 409
    assert app.post("/api/v1/admin/clients", json={"slug": "Bad Slug", "display_name": "x"},
                    cookies=cookies).status_code == 422
    assert _audit_actions() == ["tenant_create"]


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def test_quarantine_list_get_and_payload_as_text(app):
    iid = _instance()
    cookies = _admin(app)
    env = _api_alert(1, site_uid="site-uid-0001")
    env["alertContext"]["message"] = "<script>alert(1)</script>\nline two"
    d = _hold(iid, env)
    assert d.status == "quarantined"
    r = app.get(QUARANTINE, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1 and r.json()["reasons"] == list(quarantine.REASONS)
    (row,) = r.json()["rows"]
    assert row["reason"] == "name-unknown" and row["state"] == "held"
    assert row["vendor_tenant_id"] == "site-uid-0001" and row["instance_id"] == iid
    # The headline is one cleaned line of TEXT (control characters and line
    # breaks gone); it is the console's job to render it as text, never markup.
    assert row["event_summary"] == "Event log — <script>alert(1)</script>"
    assert "\n" not in row["event_summary"] and "line two" not in row["event_summary"]
    assert "payload" not in row
    detail = app.get(f"{QUARANTINE}/{row['id']}", cookies=cookies)
    assert detail.status_code == 200 and detail.headers["cache-control"] == "no-store"
    assert json.loads(detail.json()["payload"]) == env          # opaque text, round-trips
    assert app.get(f"{QUARANTINE}?reason=bogus", cookies=cookies).status_code == 422
    assert app.get(f"{QUARANTINE}?instance_id=999", cookies=cookies).json()["total"] == 0
    assert app.get(f"{QUARANTINE}/4242", cookies=cookies).status_code == 404


def test_idless_event_names_a_missing_default_distinctly_from_an_offboarded_one(app):
    """An instance default that points at NO client used to be held as
    'offboarded-tenant' (the status lookup returned None, and anything but
    'active' read as offboarded) — sending the operator to look for an
    offboarding that never happened. It is its own reason now;
    'offboarded-tenant' stays for a default whose tenant is offboarded,
    archived or disabled."""
    iid = _instance()
    cookies = _admin(app)
    create_client("gone-co", "Gone Co")
    idless = _api_alert(1, site_uid="")
    del idless["alertSourceInfo"]["siteUid"]

    def held_as(default: str | None, n: int) -> str:
        env = {**idless, "alertUid": f"alert-{n}"}
        d = _hold(iid, env, default=default)
        assert d.status == "quarantined", d
        return d.reason

    assert held_as("no-such-co", 1) == "default-tenant-missing"
    assert held_as(None, 2) == "no-tenant-id"
    for n, status in enumerate(("offboarded", "archived", "disabled"), start=3):
        reg = connect(paths.registry_db_path())
        reg.execute("UPDATE clients SET status = ? WHERE slug = 'gone-co'", (status,))
        reg.commit(); reg.close()
        assert held_as("gone-co", n) == "offboarded-tenant", status
    assert _client_rows() == {"gone-co": "disabled"}        # nothing was created
    # The console can name and filter the new reason like any other.
    assert "default-tenant-missing" in app.get(QUARANTINE, cookies=cookies).json()["reasons"]
    r = app.get(f"{QUARANTINE}?reason=default-tenant-missing", cookies=cookies)
    assert r.status_code == 200 and r.json()["total"] == 1
    assert r.json()["rows"][0]["vendor_tenant_id"] is None
    assert app.get(f"{QUARANTINE}?reason=offboarded-tenant", cookies=cookies).json()["total"] == 3


def test_route_from_quarantine_ingests_with_the_adapter_headline_and_maps_the_site(app):
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    env = _api_alert(5, site_uid="site-uid-0005")
    qid = _hold(iid, env).quarantine_id

    r = app.post(f"{QUARANTINE}/{qid}/route", json={"slug": "acme-corp"}, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"slug": "acme-corp", "created_tenant": False, "routed": 1,
                        "duplicates": 0, "skipped": 0, "mapping_written": True}
    (event,) = _events("acme-corp")
    assert event["event_type"] == "datto.eventlog" and event["summary"].startswith("Event log")
    assert event["source"] == "datto"
    assert quarantine.get(qid).state == "routed" and quarantine.get(qid).routed_to_slug == "acme-corp"
    (m,) = tenant_map.get_mappings(iid)
    assert (m.vendor_tenant_id, m.octo_client_slug, m.match_source) == ("site-uid-0005", "acme-corp", "manual")
    assert _audit_actions() == ["quarantine_route", "adapter_tenant_map_set"] and _chain_ok()
    # Future traffic from that site routes by the mapping, nothing held.
    d = _hold(iid, _api_alert(6, site_uid="site-uid-0005"))
    assert d.status == "stored" and d.outcome == "mapped" and d.slug == "acme-corp"
    # Routing a routed row is a conflict; routing the same payload again is a duplicate.
    assert app.post(f"{QUARANTINE}/{qid}/route", json={"slug": "acme-corp"}, cookies=cookies).status_code == 409


def test_route_into_a_new_tenant_and_validation(app):
    iid = _instance()
    cookies = _admin(app)
    qid = _hold(iid, _api_alert(1, site_uid="site-uid-0001")).quarantine_id
    bad = [
        ({}, 422), ({"slug": "acme-corp", "new": {"display_name": "x"}}, 422),
        ({"slug": "nope"}, 404), ({"new": {"display_name": "x", "kind": "ignored"}}, 422),
        ({"new": {"display_name": "x", "compliance_flags": ["sox"]}}, 422),
    ]
    for body, code in bad:
        assert app.post(f"{QUARANTINE}/{qid}/route", json=body, cookies=cookies).status_code == code, body
    r = app.post(f"{QUARANTINE}/{qid}/route", json={
        "new": {"display_name": "Brand New Co", "kind": "client", "compliance_flags": ["pci"]},
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["slug"] == "brand-new-co" and r.json()["created_tenant"] is True
    row = _client_row("brand-new-co")
    assert (row["origin"], row["kind"], row["review_state"]) == ("manual", "client", "confirmed")
    assert json.loads(row["compliance_flags"]) == ["pci"]
    assert len(_events("brand-new-co")) == 1
    assert _audit_actions() == ["tenant_create", "quarantine_route", "adapter_tenant_map_set"]


def test_route_into_a_non_active_tenant_is_refused_and_touches_nothing(app):
    """Ruling 5 through the back door: held traffic can never be routed into
    an offboarded (or archived / disabled) tenant — one row or a whole site."""
    iid = _instance()
    cookies = _admin(app)
    create_client("gone-co", "Gone Co")
    qid = _hold(iid, _api_alert(1, site_uid="site-uid-0001")).quarantine_id
    _hold(iid, _api_alert(2, site_uid="site-uid-0001"))
    for status in ("offboarded", "archived", "disabled"):
        reg = connect(paths.registry_db_path())
        reg.execute("UPDATE clients SET status = ? WHERE slug = 'gone-co'", (status,))
        reg.commit(); reg.close()
        r = app.post(f"{QUARANTINE}/{qid}/route", json={"slug": "gone-co"}, cookies=cookies)
        assert r.status_code == 409 and status in r.json()["message"], status
        r = app.post(f"{QUARANTINE}/bulk-route", json={
            "instance_id": iid, "vendor_tenant_id": "site-uid-0001", "slug": "gone-co",
        }, cookies=cookies)
        assert r.status_code == 409 and status in r.json()["message"], status
    assert _events("gone-co") == []
    assert quarantine.counts(iid)["held"] == 2 and quarantine.get(qid).state == "held"
    assert tenant_map.resolve(iid, "site-uid-0001") is None
    assert _audit_actions() == []


def _hold_truncated(iid: int, env: dict, monkeypatch) -> int:
    """Hold one event whose payload is truncated on arrival (too big for the
    store) — the row exists for review but can never be replayed."""
    with monkeypatch.context() as m:
        m.setattr(quarantine, "MAX_PAYLOAD_BYTES", 64)
        d = _hold(iid, env)
    assert d.status == "quarantined" and quarantine.get(d.quarantine_id).payload_truncated
    return d.quarantine_id


def test_route_new_never_creates_a_tenant_for_a_payload_it_cannot_replay(app, monkeypatch):
    """The replay check comes BEFORE the tenant is created: a 409 leaves no
    orphan tenant, no `tenant_create` audit row, and a retry creates no
    '-2' twin either."""
    iid = _instance()
    cookies = _admin(app)
    qid = _hold_truncated(iid, _api_alert(1, site_uid="site-uid-0001"), monkeypatch)
    body = {"new": {"display_name": "Brand New Co", "kind": "client"}}
    for _ in range(2):
        r = app.post(f"{QUARANTINE}/{qid}/route", json=body, cookies=cookies)
        assert r.status_code == 409 and "cannot be replayed" in r.json()["message"]
    assert _client_rows() == {}
    assert _audit_actions() == [] and quarantine.get(qid).state == "held"
    # An existing target is refused the same way, and nothing is mapped.
    create_client("acme-corp", "Acme Corp")
    r = app.post(f"{QUARANTINE}/{qid}/route", json={"slug": "acme-corp"}, cookies=cookies)
    assert r.status_code == 409 and tenant_map.resolve(iid, "site-uid-0001") is None
    # Discard is the way out for such a row.
    assert app.post(f"{QUARANTINE}/{qid}/discard", json={"reason": "payload truncated"},
                    cookies=cookies).status_code == 200


def test_bulk_route_skips_truncated_rows_and_still_maps_the_site(app, monkeypatch):
    """A truncated payload inside a group is skipped and counted, never a
    reason to stop half-way: the operator decided where the SITE belongs, so
    the rest is routed, the tenant created once, and the mapping written.
    When nothing in the group can be replayed, nothing is created at all."""
    iid = _instance()
    cookies = _admin(app)
    first = _hold(iid, _api_alert(1, site_uid="site-uid-0007")).quarantine_id
    bad = _hold_truncated(iid, _api_alert(2, site_uid="site-uid-0007"), monkeypatch)
    third = _hold(iid, _api_alert(3, site_uid="site-uid-0007")).quarantine_id
    body = {"instance_id": iid, "vendor_tenant_id": "site-uid-0007",
            "new": {"display_name": "Acme Corp", "kind": "client"}}
    r = app.post(f"{QUARANTINE}/bulk-route", json=body, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"slug": "acme-corp", "created_tenant": True, "routed": 2,
                        "duplicates": 0, "skipped": 1, "mapping_written": True}
    assert [quarantine.get(i).state for i in (first, bad, third)] == ["routed", "held", "routed"]
    assert len(_events("acme-corp")) == 2
    assert tenant_map.resolve(iid, "site-uid-0007") == "acme-corp"
    assert _audit_actions() == ["tenant_create", "quarantine_route", "quarantine_route",
                                "adapter_tenant_map_set"] and _chain_ok()
    # The retry finds only the truncated row: a clear 409, and NO 'acme-corp-2'.
    r = app.post(f"{QUARANTINE}/bulk-route", json=body, cookies=cookies)
    assert r.status_code == 409 and "discard them" in r.json()["message"]
    assert _client_rows() == {"acme-corp": "active"}
    assert _audit_actions().count("tenant_create") == 1
    # Future traffic from the site routes by the mapping written above.
    d = _hold(iid, _api_alert(4, site_uid="site-uid-0007"))
    assert d.status == "stored" and d.outcome == "mapped" and d.slug == "acme-corp"
    # Bulk discard clears the leftover without a mapping change.
    r = app.post(f"{QUARANTINE}/bulk-discard", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "reason": "truncated on arrival",
    }, cookies=cookies)
    assert r.status_code == 200 and r.json() == {"discarded": 1}


def test_bulk_route_moves_every_held_event_of_a_site_and_maps_once(app):
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    for n in range(1, 31):
        _hold(iid, _api_alert(n, site_uid="site-uid-0007"), door="webhook")
    _hold(iid, _api_alert(99, site_uid="site-uid-0008"))       # another site: untouched
    assert quarantine.counts(iid)["held"] == 31

    r = app.post(f"{QUARANTINE}/bulk-route", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "slug": "acme-corp",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"slug": "acme-corp", "created_tenant": False, "routed": 30,
                        "duplicates": 0, "skipped": 0, "mapping_written": True}
    assert len(_events("acme-corp")) == 30
    assert quarantine.counts(iid)["held"] == 1
    assert tenant_map.resolve(iid, "site-uid-0007") == "acme-corp"
    assert _audit_actions().count("quarantine_route") == 30
    assert _audit_actions().count("adapter_tenant_map_set") == 1 and _chain_ok()
    r = app.post(f"{QUARANTINE}/bulk-route", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "slug": "acme-corp",
    }, cookies=cookies)
    assert r.status_code == 404                                  # nothing left to route


def test_bulk_route_and_bulk_discard_honour_the_group_reason(app, monkeypatch):
    """The console groups held events by site AND reason; the bulk routes
    act on exactly that group when `quarantine_reason` is given, on the
    whole site when it is not. Discarding writes no mapping."""
    monkeypatch.setattr(tenant_autocreate, "AUTOCREATE_PER_HOUR", 1)
    iid = _instance()
    cookies = _admin(app)
    create_client("acme-corp", "Acme Corp")
    _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="One"))        # uses the hour's one
    for n in range(2, 5):
        _hold(iid, _api_alert(n, site_uid="site-uid-0007", site_name="Seven"))  # autocreate-limit ×3
    for n in range(5, 7):
        _hold(iid, _api_alert(n, site_uid="site-uid-0007"))                     # name-unknown ×2
    _hold(iid, _api_alert(9, site_uid="site-uid-0008"))                         # another site
    assert quarantine.counts(iid)["held"] == 6
    reasons = {quarantine.get(i).reason
               for i in quarantine.held_ids_for_vendor_tenant(iid, "site-uid-0007")}
    assert reasons == {"autocreate-limit", "name-unknown"}
    assert len(quarantine.held_ids_for_vendor_tenant(iid, "site-uid-0007", reason="name-unknown")) == 2

    bad = app.post(f"{QUARANTINE}/bulk-discard", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "reason": "vendor test noise",
        "quarantine_reason": "bogus",
    }, cookies=cookies)
    assert bad.status_code == 422
    r = app.post(f"{QUARANTINE}/bulk-discard", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "reason": "vendor test noise",
        "quarantine_reason": "name-unknown",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json() == {"discarded": 2}
    assert quarantine.counts(iid)["held"] == 4
    assert tenant_map.resolve(iid, "site-uid-0007") is None                     # nothing mapped
    assert _audit_actions().count("quarantine_discard") == 2 and _chain_ok()
    # The other group of the same site is still held and bulk-routes on its own.
    r = app.post(f"{QUARANTINE}/bulk-route", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "slug": "acme-corp",
        "quarantine_reason": "autocreate-limit",
    }, cookies=cookies)
    assert r.status_code == 200, r.text
    assert r.json()["routed"] == 3 and r.json()["mapping_written"] is True
    assert len(_events("acme-corp")) == 3
    assert quarantine.counts(iid)["held"] == 1                                  # site 0008 untouched
    # Nothing left in the group → 404 (same as bulk-route).
    assert app.post(f"{QUARANTINE}/bulk-discard", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0007", "reason": "vendor test noise",
    }, cookies=cookies).status_code == 404
    # Without a reason filter the whole site goes.
    r = app.post(f"{QUARANTINE}/bulk-discard", json={
        "instance_id": iid, "vendor_tenant_id": "site-uid-0008", "reason": "decommissioned site",
    }, cookies=cookies)
    assert r.status_code == 200 and r.json() == {"discarded": 1}
    assert quarantine.counts(iid)["held"] == 0


def test_discard_is_audited_and_terminal(app):
    iid = _instance()
    cookies = _admin(app)
    qid = _hold(iid, _api_alert(1, site_uid="site-uid-0001")).quarantine_id
    assert app.post(f"{QUARANTINE}/{qid}/discard", json={"reason": "x"}, cookies=cookies).status_code == 422
    r = app.post(f"{QUARANTINE}/{qid}/discard", json={"reason": "test alert from vendor"}, cookies=cookies)
    assert r.status_code == 200 and r.json() == {"id": qid, "discarded": True}
    assert quarantine.get(qid).state == "discarded"
    assert app.post(f"{QUARANTINE}/{qid}/route", json={"slug": "x-co"}, cookies=cookies).status_code in (404, 409)
    assert _audit_actions() == ["quarantine_discard"] and _chain_ok()
    # Quarantine never created anything by itself.
    reg = connect(paths.registry_db_path(), read_only=True)
    assert reg.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0
    reg.close()


def test_integration_card_carries_lifecycle_counters(app, monkeypatch):
    monkeypatch.setattr(tenant_autocreate, "AUTOCREATE_PER_HOUR", 1)
    iid = _instance()
    cookies = _admin(app)
    _hold(iid, _api_alert(1, site_uid="site-uid-0001", site_name="One"))
    _hold(iid, _api_alert(2, site_uid="site-uid-0002", site_name="Two"))       # limit → held
    _hold(iid, _api_alert(3, site_uid="site-uid-0003"))                        # name-unknown
    card = app.get("/api/v1/integrations", cookies=cookies).json()["instances"]["datto"]
    assert card["auto_created_pending"] == 1 and card["quarantined"] == 2
    assert card["autocreate_limited"] is True and card["unmapped_dropped"] == 0
    assert any("held in quarantine" in w for w in card["warnings"])
    assert any("PAUSED" in w for w in card["warnings"])
    listed = app.get("/api/v1/admin/adapters/instances", cookies=cookies).json()["instances"][0]
    assert (listed["auto_created_pending"], listed["quarantined"], listed["autocreate_limited"]) == (1, 2, True)


# ---------------------------------------------------------------------------
# Viewer / analyst safety
# ---------------------------------------------------------------------------

_EVERY_ROUTE = [
    ("get", TENANTS, None),
    ("post", TENANTS, {"slug": "x-co", "display_name": "X"}),
    ("patch", f"{TENANTS}/acme-corp", {"kind": "client"}),
    ("post", f"{TENANTS}/bulk-update", {"items": [{"slug": "acme-corp", "patch": {"kind": "client"}}]}),
    ("post", f"{TENANTS}/bulk-update",
     {"items": [{"slug": "acme-corp", "patch": {"kind": "client"}}], "dry_run": True}),
    ("post", f"{TENANTS}/acme-corp/offboard", {"reason": "bye bye"}),
    ("post", f"{TENANTS}/acme-corp/merge-into/other-co", {"reason": "dup dup"}),
    # v0.10: the attested single-person exception, its preview and review.
    ("post", f"{TENANTS}/acme-corp/offboard", _alone("acme-corp", "bye bye")),
    ("post", f"{TENANTS}/acme-corp/merge-into/other-co", _alone("acme-corp", "dup dup")),
    ("get", f"{TENANTS}/acme-corp/merge-into/other-co/preview", None),
    ("get", f"{TENANTS}/requests", None),
    ("get", f"{TENANTS}/requests?state=all&approval_mode=single_attested", None),
    ("post", f"{TENANTS}/requests/1/approve", None),
    ("post", f"{TENANTS}/requests/1/reject", None),
    ("post", f"{TENANTS}/requests/1/cancel", None),
    ("post", f"{TENANTS}/requests/1/post-review", {"verdict": "ok", "note": "looked fine"}),
    ("get", "/api/v1/admin/notices", None),
    ("post", "/api/v1/admin/notices/1/acknowledge", None),
    ("get", QUARANTINE, None),
    ("get", f"{QUARANTINE}/1", None),
    ("post", f"{QUARANTINE}/1/route", {"slug": "acme-corp"}),
    ("post", f"{QUARANTINE}/1/discard", {"reason": "noise noise"}),
    ("post", f"{QUARANTINE}/bulk-route", {"instance_id": 1, "vendor_tenant_id": "s", "slug": "acme-corp"}),
    ("post", f"{QUARANTINE}/bulk-discard", {"instance_id": 1, "vendor_tenant_id": "s", "reason": "noise noise"}),
    ("get", f"{TENANTS}/review-summary", None),
]


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_every_route_is_403_for_viewer_and_analyst(app, role):
    iid = _instance()
    create_client("acme-corp", "Acme Corp")
    create_client("other-co", "Other Co")
    qid = _hold(iid, _api_alert(1, site_uid="site-uid-0001")).quarantine_id
    cookies = app.login(app.provision_operator(f"{role}1", PW, athena_role=role))
    for method, path, body in _EVERY_ROUTE:
        path = path.replace(f"{QUARANTINE}/1", f"{QUARANTINE}/{qid}")
        r = getattr(app, method)(path, json=body, cookies=cookies) if body is not None \
            else getattr(app, method)(path, cookies=cookies)
        if role == "analyst" and path.startswith("/api/v1/admin/notices"):
            # Tier Black: an analyst is paged, so they read their OWN notice
            # inbox (never a tenant-change notice — empty here); another
            # operator's notice is not theirs to acknowledge.
            assert r.status_code == (200 if method == "get" else 404), (path, r.text)
            continue
        assert r.status_code == 403, (method, path, r.status_code, r.text)
        assert r.json()["code"] == "ISOLATION_VIOLATION"
    assert _audit_actions() == []
    assert quarantine.get(qid).state == "held"
    assert _client_row("acme-corp")["status"] == "active"


def test_scoped_viewer_sees_only_its_own_tenant(auth_client, auth_data_root):
    """A viewer scoped to one tenant: the dashboard counts only that tenant's
    events; other tenants, the quarantine store and the tenant manager stay
    invisible; analyst-tier feeds and admin routes are 403."""
    from datetime import datetime, timedelta, timezone

    from apps.octo.tests.auth.test_dashboard_throughput import _login

    quarantine.reset_schema_cache()
    create_client("acme-corp", "Acme Corp")
    create_client("other-co", "Other Co")
    adapter = DattoSourceAdapter()
    sink = SqliteIngestSink(publish_to_stream=False)
    now = int(datetime.now(timezone.utc).timestamp()) - 60
    for n in range(3):
        sink.ingest("acme-corp", "datto", adapter.extract_event(
            {**_api_alert(n, site_uid="s-a"), "timestamp": now - n}))
    for n in range(5):
        sink.ingest("other-co", "datto", adapter.extract_event(
            {**_api_alert(10 + n, site_uid="s-b"), "timestamp": now - n}))
    # Something held in quarantine for an instance, too.
    rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                          credentials_dict={"DATTO_API_KEY": "k"})
    _hold(rec.id, _api_alert(77, site_uid="site-uid-0077"))

    viewer = auth_client.provision_operator(
        "viewer", PW, role="viewer", athena_role="viewer", scope_slugs=["acme-corp"])
    _login(auth_client, viewer)
    r = auth_client.get("/api/v1/dashboard/throughput?window=24h")
    assert r.status_code == 200, r.text
    assert r.json()["scope_slugs"] == ["acme-corp"]
    assert sum(p["v"] for p in r.json()["points"]) == 3
    text = r.text
    assert "other-co" not in text and "site-uid-0077" not in text
    for path in (TENANTS, f"{TENANTS}/requests", QUARANTINE, "/api/v1/integrations",
                 "/api/v1/admin/clients", "/api/v1/dashboard/recent-events",
                 "/api/v1/dashboard/integrations"):
        r = auth_client.get(path)
        assert r.status_code == 403, (path, r.status_code)
        assert "other-co" not in r.text and "site-uid-0077" not in r.text
    quarantine.reset_schema_cache()
