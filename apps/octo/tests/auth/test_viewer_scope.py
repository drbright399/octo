"""Viewers are CLIENT users: scoped to named tenants, never to '*'.

The invite route used to default `scope_slugs` to ['*'] for every role (and
turned an empty list into ['*']), so a viewer invited without a scope saw
every tenant's data. Now a viewer role row — invite, role grant, the scope
editor's save — takes only an explicit list of ACTIVE tenants, none of which
still carries its auto-create placeholder name or slug (both name the vendor
that created the tenant: owner decision 2026-09-28 (b)). analyst+ keep the
['*'] default. The Tenants page and the scope pickers get the placeholder
flags to show why.

Real app, real registry, real routes, a real Datto instance row (never
started — no vendor is contacted) and the real auto-create path.
"""
from __future__ import annotations

import json

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.db import connect
from apps.octo.instances import create_instance, tenant_autocreate
from apps.octo.tests.auth.test_dashboard_throughput import _login

OPS = "/api/v1/admin/operators"
PW = "pw1234567890"
SITE_ID = "1a2b3c4d-0000-4000-8000-00000000abcd"
RENAMED_SITE_ID = "9f8e7d6c-0000-4000-8000-00000000abcd"


@pytest.fixture
def world(auth_client, auth_data_root, tmp_path, monkeypatch):
    """acme-corp + globex active, initech offboarded; two tenants auto-created
    by a Datto instance with no vendor name — one still named
    'datto site …', one renamed (its slug still 'datto-site-…')."""
    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "adapter-credentials-key.env"),
    )
    from apps.octo.credentials import ensure_key_file
    ensure_key_file()

    client_provisioning.create_client("acme-corp", "Acme Corp")
    client_provisioning.create_client("globex", "Globex")
    client_provisioning.create_client("initech", "Initech")
    datto = create_instance(
        vendor_slug="datto", display_name="Datto RMM", credentials_dict={"k": "v"},
    )
    slugs = {}
    for key, site in (("placeholder", SITE_ID), ("renamed", RENAMED_SITE_ID)):
        res = tenant_autocreate.resolve_tenant(
            instance_id=datto.id, vendor_slug="datto", vendor_tenant_id=site,
            vendor_tenant_label=None, default_tenant_slug=None, supports_discovery=False,
        )
        assert res.outcome == "auto-created", res
        slugs[key] = res.slug
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'initech'")
        reg.execute("UPDATE clients SET display_name = 'Acme Dental' WHERE slug = ?",
                    (slugs["renamed"],))
    finally:
        reg.close()
    return {"client": auth_client, "slugs": slugs}


def _as(world, role: str, scope: list[str] | None = None):
    client = world["client"]
    client.cookies.clear()
    op = client.provision_operator(
        f"caller-{role}", PW,
        role="admin" if role in ("admin", "super_admin") else role,
        athena_role=role, scope_slugs=scope or ["*"],
    )
    _login(client, op)
    return client


def _invite(client, username: str, role: str, scope: list[str] | None = ...):
    body = {"username": username, "email": f"{username}@example.test", "role": role}
    if scope is not ...:
        body["scope_slugs"] = scope
    return client.post(OPS, json=body)


def _scope_rows(operator_id: int) -> dict[str, list[str]]:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return {
            r["role_name"]: json.loads(r["scope_slugs"])
            for r in reg.execute(
                "SELECT role_name, scope_slugs FROM operator_roles WHERE operator_id = ?",
                (operator_id,),
            ).fetchall()
        }
    finally:
        reg.close()


def _operator_id(username: str) -> int | None:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute("SELECT id FROM operators WHERE username = ?", (username,)).fetchone()
    finally:
        reg.close()
    return int(row["id"]) if row else None


# ---------------------------------------------------------------------------
# Role matrix — the invite and grant routes stay admin+
# ---------------------------------------------------------------------------

def test_unauthenticated_cannot_invite_or_grant(world):
    client = world["client"]
    client.cookies.clear()
    assert _invite(client, "bob", "viewer", ["acme-corp"]).status_code == 401
    assert client.post(f"{OPS}/1/role/grant",
                       json={"role": "viewer", "scope_slugs": ["acme-corp"]}).status_code == 401


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_below_admin_cannot_invite_or_grant_viewers(world, role):
    client = _as(world, role, ["acme-corp"])
    r = _invite(client, "bob", "viewer", ["acme-corp"])
    assert r.status_code == 403 and r.json()["code"] == "ISOLATION_VIOLATION"
    assert _operator_id("bob") is None
    target = world["client"].provision_operator("carol", PW, role="viewer", athena_role="viewer",
                                                scope_slugs=["acme-corp"])
    r = client.post(f"{OPS}/{target['id']}/role/grant",
                    json={"role": "viewer", "scope_slugs": ["globex"]})
    assert r.status_code == 403
    assert _scope_rows(target["id"])["viewer"] == ["acme-corp"]


@pytest.mark.parametrize("role", ["admin", "super_admin"])
def test_admin_and_super_admin_invite_a_viewer_to_named_active_tenants(world, role):
    client = _as(world, role)
    r = _invite(client, "bob", "viewer", ["globex", "acme-corp", "acme-corp"])
    assert r.status_code == 200, r.text
    assert _scope_rows(r.json()["operator_id"]) == {"viewer": ["acme-corp", "globex"]}


# ---------------------------------------------------------------------------
# Invite
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["admin", "super_admin"])
@pytest.mark.parametrize("scope", [..., ["*"], [], ["acme-corp", "*"]])
def test_a_viewer_is_never_invited_to_every_tenant(world, role, scope):
    """Omitted (the old ['*'] default), '*', empty (which became '*') — no
    role can do it, super_admin included."""
    client = _as(world, role)
    r = _invite(client, "bob", "viewer", scope)
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "VALIDATION_FAILED"
    assert "client user" in r.json()["message"]
    assert _operator_id("bob") is None


@pytest.mark.parametrize("scope, needle", [
    (["no-such-co"], "no such tenant"),
    (["initech"], "ACTIVE"),
    (["Not A Slug"], "not a tenant slug"),
])
def test_a_viewer_is_scoped_to_existing_active_tenants_only(world, scope, needle):
    client = _as(world, "admin")
    r = _invite(client, "bob", "viewer", scope)
    assert r.status_code == 422 and needle in r.json()["message"]
    assert _operator_id("bob") is None


def test_a_viewer_is_never_invited_to_a_placeholder_named_tenant(world):
    client = _as(world, "admin")
    slug = world["slugs"]["placeholder"]
    r = _invite(client, "bob", "viewer", ["acme-corp", slug])
    assert r.status_code == 422
    msg = r.json()["message"]
    assert "placeholder name" in msg and "Rename" in msg and slug in msg
    assert _operator_id("bob") is None


def test_renaming_is_not_enough_while_the_slug_is_a_placeholder(world):
    """The slug was made from 'datto site …', can't be renamed, and a client
    user sees it (whoami, scope lists): the tenant must be merged into a
    properly named one first."""
    client = _as(world, "admin")
    slug = world["slugs"]["renamed"]
    assert slug.startswith("datto-site-")
    r = _invite(client, "bob", "viewer", [slug])
    assert r.status_code == 422
    msg = r.json()["message"]
    assert "placeholder slug" in msg and "merge" in msg
    assert _operator_id("bob") is None


@pytest.mark.parametrize("scope, stored", [(..., ["*"]), ([], ["*"]), (["acme-corp"], ["acme-corp"])])
def test_analysts_keep_the_all_tenants_default(world, scope, stored):
    client = _as(world, "admin")
    r = _invite(client, "bob", "analyst", scope)
    assert r.status_code == 200, r.text
    assert _scope_rows(r.json()["operator_id"]) == {"analyst": stored}
    # The audit row records what was stored, not the raw request.
    g = connect(paths.global_audit_db_path(), read_only=True)
    try:
        (after,) = g.execute(
            "SELECT after_state FROM audit_log WHERE action = 'admin_ops_create_operator' "
            "AND target_id = ?", (str(r.json()["operator_id"]),),
        ).fetchone()
    finally:
        g.close()
    assert json.loads(after)["scope_slugs"] == stored


# ---------------------------------------------------------------------------
# Role change: grant / scope edit / revoke
# ---------------------------------------------------------------------------

def _invited_viewer(client, username: str = "bob", scope=("acme-corp",)) -> int:
    r = _invite(client, username, "viewer", list(scope))
    assert r.status_code == 200, r.text
    return r.json()["operator_id"]


@pytest.mark.parametrize("scope", [["*"], [], ["globex", "*"]])
def test_an_existing_viewer_is_never_widened_to_every_tenant(world, scope):
    """The console's scope editor saves through role/grant with the viewer's
    own role: '*' (or an empty scope, which the editor used to send as '*')
    is refused and the stored scope is untouched."""
    client = _as(world, "admin")
    viewer = _invited_viewer(client)
    r = client.post(f"{OPS}/{viewer}/role/grant", json={"role": "viewer", "scope_slugs": scope})
    assert r.status_code == 422 and "client user" in r.json()["message"]
    assert _scope_rows(viewer) == {"viewer": ["acme-corp"]}


def test_the_grant_default_scope_is_refused_for_viewer(world):
    """role/grant's own default is ['*'] (the console's '+ role' menu sends
    no scope): for a viewer that is refused, whoever holds it."""
    client = _as(world, "super_admin")
    target = world["client"].provision_operator("carol", PW, role="analyst", athena_role="analyst")
    r = client.post(f"{OPS}/{target['id']}/role/grant", json={"role": "viewer"})
    assert r.status_code == 422
    assert "viewer" not in _scope_rows(target["id"])


def test_a_viewers_scope_can_be_changed_to_other_named_tenants(world):
    client = _as(world, "admin")
    viewer = _invited_viewer(client)
    r = client.post(f"{OPS}/{viewer}/role/grant",
                    json={"role": "viewer", "scope_slugs": ["globex"]})
    assert r.status_code == 200, r.text
    assert r.json()["scope_slugs"] == ["globex"]
    assert _scope_rows(viewer) == {"viewer": ["globex"]}
    # …but not to a placeholder or an inactive tenant.
    for bad in ([world["slugs"]["placeholder"]], [world["slugs"]["renamed"]], ["initech"]):
        r = client.post(f"{OPS}/{viewer}/role/grant", json={"role": "viewer", "scope_slugs": bad})
        assert r.status_code == 422, bad
    assert _scope_rows(viewer) == {"viewer": ["globex"]}


def test_promoting_a_viewer_keeps_the_analyst_default(world):
    client = _as(world, "admin")
    viewer = _invited_viewer(client)
    r = client.post(f"{OPS}/{viewer}/role/grant", json={"role": "analyst"})
    assert r.status_code == 200, r.text
    assert _scope_rows(viewer) == {"viewer": ["acme-corp"], "analyst": ["*"]}


def test_revoking_cannot_leave_a_viewer_scoped_to_every_tenant(world):
    """An analyst whose viewer row says '*' (written before viewers had to be
    scoped): revoking 'analyst' would leave a '*' viewer — refused, until the
    viewer row is scoped (grant 'viewer' with tenants replaces it)."""
    client = _as(world, "admin")
    target = world["client"].provision_operator("carol", PW, role="analyst", athena_role="viewer")
    assert _scope_rows(target["id"]) == {"analyst": ["*"], "viewer": ["*"]}
    r = client.post(f"{OPS}/{target['id']}/role/revoke", json={"role": "analyst"})
    assert r.status_code == 422 and "every tenant" in r.json()["message"]
    # The way out it names is one the console offers (its role picker hides
    # a role already held, so "grant viewer again" alone is not).
    assert ("revoke 'viewer' first, grant 'viewer' again with the specific tenant(s), "
            "then revoke 'analyst'") in r.json()["message"]
    assert set(_scope_rows(target["id"])) == {"analyst", "viewer"}

    r = client.post(f"{OPS}/{target['id']}/role/grant",
                    json={"role": "viewer", "scope_slugs": ["acme-corp"]})
    assert r.status_code == 200, r.text
    r = client.post(f"{OPS}/{target['id']}/role/revoke", json={"role": "analyst"})
    assert r.status_code == 200, r.text
    assert _scope_rows(target["id"]) == {"viewer": ["acme-corp"]}

    # The sequence the message gives, step by step.
    dave = world["client"].provision_operator("dave", PW, role="analyst", athena_role="viewer")
    for step, body in (("revoke", {"role": "viewer"}),
                       ("grant", {"role": "viewer", "scope_slugs": ["acme-corp"]}),
                       ("revoke", {"role": "analyst"})):
        r = client.post(f"{OPS}/{dave['id']}/role/{step}", json=body)
        assert r.status_code == 200, (step, r.text)
    assert _scope_rows(dave["id"]) == {"viewer": ["acme-corp"]}


# ---------------------------------------------------------------------------
# What the console reads: placeholder flags
# ---------------------------------------------------------------------------

def test_tenant_and_client_lists_flag_placeholders(world):
    client = _as(world, "admin")
    placeholder, renamed = world["slugs"]["placeholder"], world["slugs"]["renamed"]
    tenants = {t["slug"]: t for t in client.get("/api/v1/admin/tenants").json()["tenants"]}
    assert (tenants[placeholder]["placeholder_name"], tenants[placeholder]["placeholder_slug"]) == (True, True)
    assert (tenants[renamed]["placeholder_name"], tenants[renamed]["placeholder_slug"]) == (False, True)
    assert (tenants["acme-corp"]["placeholder_name"], tenants["acme-corp"]["placeholder_slug"]) == (False, False)
    # One tenant's own view (PATCH answers it) carries them too.
    r = client.patch(f"/api/v1/admin/tenants/{placeholder}", json={"display_name": "Globex West"})
    assert r.status_code == 200, r.text
    assert (r.json()["placeholder_name"], r.json()["placeholder_slug"]) == (False, True)

    clients = {c["slug"]: c for c in client.get("/api/v1/admin/clients").json()["clients"]}
    assert clients[renamed]["placeholder_slug"] is True and clients[renamed]["placeholder_name"] is False
    assert clients["acme-corp"]["placeholder_slug"] is False
    assert "initech" not in clients


def test_a_tenant_merely_named_like_its_vendor_is_not_a_placeholder(world):
    """A real vendor site name that happens to start with the vendor's name is
    not the placeholder: the slug check uses the site the tenant was created
    for, not the look of the slug."""
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        (iid,) = reg.execute("SELECT id FROM adapter_instances LIMIT 1").fetchone()
    finally:
        reg.close()
    res = tenant_autocreate.resolve_tenant(
        instance_id=iid, vendor_slug="datto", vendor_tenant_id="site-uid-77",
        vendor_tenant_label="Datto Site 2", default_tenant_slug=None, supports_discovery=True,
    )
    assert res.outcome == "auto-created" and res.slug == "datto-site-2"
    client = _as(world, "admin")
    tenants = {t["slug"]: t for t in client.get("/api/v1/admin/tenants").json()["tenants"]}
    assert tenants["datto-site-2"]["placeholder_slug"] is False
    assert tenants["datto-site-2"]["placeholder_name"] is False
    r = _invite(client, "bob", "viewer", ["datto-site-2"])
    assert r.status_code == 200, r.text
