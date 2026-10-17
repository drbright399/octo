"""Admin adapter catalog + smoke-test endpoints.

Catalog: GET /api/v1/admin/adapters/catalog
Smoke:   POST /api/v1/admin/adapters/<slug>/smoke-test

Both gated to admin+ tier. Audit log records every smoke-test call
without persisting credentials.
"""
from __future__ import annotations

import pyotp


def _login(client, op):
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text
    return dict(r2.cookies)


def _with_test_registry(client):
    """Wire a minimal AdapterRegistry onto the FastAPI app state so the
    catalog endpoint has something to walk. Real boot does this via
    discovery; tests substitute a registry seeded with the production
    adapter classes."""
    from apps.octo.framework import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.adapters.wazuh import WazuhSourceAdapter
    from apps.octo.adapters.datto import DattoSourceAdapter

    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(WazuhSourceAdapter)
    registry.register_adapter_class(DattoSourceAdapter)
    client.app.state.adapter_registry = registry
    return registry


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

def test_catalog_lists_registered_adapters(auth_client):
    """GET /catalog returns every adapter class the framework has
    registered, with vendor metadata + credential_shape ready for the
    wizard."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 200, r.text
    body = r.json()
    slugs = {a["vendor_slug"] for a in body["adapters"]}
    assert "wazuh" in slugs
    assert "datto" in slugs


def test_catalog_entry_has_credential_shape(auth_client):
    """Catalog includes the fields the wizard renders."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    adapters = {a["vendor_slug"]: a for a in r.json()["adapters"]}
    wazuh = adapters["wazuh"]
    cred_names = {f["name"] for f in wazuh["credential_shape"]}
    assert "WAZUH_MANAGER_URL" in cred_names
    assert "WAZUH_API_KEY" in cred_names


def test_catalog_entry_has_tenant_mapping_shape(auth_client):
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    adapters = {a["vendor_slug"]: a for a in r.json()["adapters"]}
    datto = adapters["datto"]
    assert datto["tenant_mapping_shape"] is not None
    assert "sites" in datto["tenant_mapping_shape"]["fetch_endpoint"]


def test_catalog_sorted_by_display_name(auth_client):
    """Stable ordering matters for the popout — operators expect the
    catalog in the same order every time they open it."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    names = [a["vendor_display_name"] for a in r.json()["adapters"]]
    assert names == sorted(names, key=str.lower)


def test_catalog_returns_empty_when_no_registry(auth_client):
    """If discovery hasn't run (e.g., partial boot), catalog returns
    empty rather than 500."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    # Simulate a partial boot where the adapter framework hasn't been wired:
    # create_app()'s best-effort _wire_adapter_runtime stashed a registry,
    # but we strip it for this assertion.
    if hasattr(auth_client.app.state, "adapter_registry"):
        del auth_client.app.state.adapter_registry

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 200
    assert r.json() == {"adapters": [], "categories": []}


# ---------------------------------------------------------------------------
# Category grouping
# ---------------------------------------------------------------------------

def test_catalog_entry_has_vendor_category(auth_client):
    """Every adapter declares a category for catalog grouping. The
    UI side-bar popout uses this to render one section per category."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    adapters = {a["vendor_slug"]: a for a in r.json()["adapters"]}
    assert adapters["wazuh"]["vendor_category"] == "siem"
    assert adapters["datto"]["vendor_category"] == "rmm"


def test_catalog_groups_by_category(auth_client):
    """The /catalog response includes a `categories` array — one entry
    per distinct vendor_category, each holding its own adapter list."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    body = r.json()
    assert "categories" in body
    cats = {g["category"]: g for g in body["categories"]}
    assert "siem" in cats
    assert "rmm" in cats
    siem_slugs = {a["vendor_slug"] for a in cats["siem"]["adapters"]}
    rmm_slugs = {a["vendor_slug"] for a in cats["rmm"]["adapters"]}
    assert "wazuh" in siem_slugs
    assert "datto" in rmm_slugs
    # No cross-leakage
    assert "datto" not in siem_slugs
    assert "wazuh" not in rmm_slugs


def test_catalog_category_groups_have_display_label(auth_client):
    """Each category group carries a human display_label the UI renders
    as the section header (no client-side title-casing needed)."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)

    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    cats = {g["category"]: g for g in r.json()["categories"]}
    assert cats["siem"]["display_label"] == "SIEM"
    assert cats["rmm"]["display_label"] == "RMM"


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------

def test_catalog_requires_admin_tier(auth_client):
    """Analyst tier cannot list the catalog — adapter management is
    admin+ only."""
    op = auth_client.provision_operator(
        "op-analyst", "pw1234567890",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)
    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 403


def test_catalog_requires_session(auth_client):
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/admin/adapters/catalog", follow_redirects=False)
    assert r.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def test_smoke_test_unknown_slug_returns_404(auth_client):
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)
    r = auth_client.post(
        "/api/v1/admin/adapters/no-such-vendor/smoke-test",
        json={"credentials": {}},
        cookies=cookies,
    )
    assert r.status_code == 404
    assert r.json()["code"] == "ADAPTER_NOT_FOUND"


def test_smoke_test_returns_adapter_response(auth_client):
    """The endpoint returns whatever the adapter's smoke_test() said."""
    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)
    # Empty credentials → adapter returns ok=False with a clear message
    r = auth_client.post(
        "/api/v1/admin/adapters/wazuh/smoke-test",
        json={"credentials": {}},
        cookies=cookies,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "MANAGER_URL" in body["message"]


def test_smoke_test_requires_admin_tier(auth_client):
    """Analyst tier cannot run smoke tests."""
    op = auth_client.provision_operator(
        "op-analyst", "pw1234567890",
        role="analyst", athena_role="analyst",
    )
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)
    r = auth_client.post(
        "/api/v1/admin/adapters/wazuh/smoke-test",
        json={"credentials": {"WAZUH_MANAGER_URL": "https://x", "WAZUH_API_KEY": "y"}},
        cookies=cookies,
    )
    assert r.status_code == 403


def test_smoke_test_audit_row_written(auth_client):
    """Every smoke-test attempt records an audit row with operator +
    adapter + outcome. Credentials are NEVER in the audit body."""
    import sqlite3
    from apps.octo import paths

    op = auth_client.provision_operator("admin-doc", "pw1234567890",
                                          athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client)
    auth_client.post(
        "/api/v1/admin/adapters/wazuh/smoke-test",
        json={"credentials": {"WAZUH_MANAGER_URL": "https://nope"}},
        cookies=cookies,
    )

    conn = sqlite3.connect(paths.global_audit_db_path())
    rows = conn.execute(
        "SELECT action, target_id, after_state FROM audit_log "
        "WHERE action = 'adapter_smoke_test' ORDER BY id DESC LIMIT 1"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    action, target_id, after_state = rows[0]
    assert action == "adapter_smoke_test"
    assert target_id == "wazuh"
    # Credentials must NOT be in the audit body
    assert "WAZUH_MANAGER_URL" not in (after_state or "")
    assert "https://nope" not in (after_state or "")
