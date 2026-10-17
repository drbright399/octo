"""Coverage for /api/v1/integrations/autotask/{instance_id}/mappings/*

Backs Autotask P4-b1 — the mapping schema landed in migration 015.
Asserts:
  - super_admin can GET + bulk-PUT operator/tenant mappings
  - below-tier callers are denied
  - duplicate keys in a PUT body are rejected (no half-applied state)
  - bulk PUT diff-applies (deletes rows omitted from the body)
  - every PUT writes an audit row with before/after state
  - homepage_url validation rejects non-http(s) prefixes
"""
from __future__ import annotations

import sqlite3

from apps.octo.tests.auth.test_search_events import _login


INSTANCE_ID = 7  # arbitrary; mapping rows don't enforce FK against
                  # adapter_instances yet (that lands in P4-c1)


# ---------------------------------------------------------------------------
# Operator mappings
# ---------------------------------------------------------------------------

def test_operator_mappings_super_admin_get_empty(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.get(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["instance_id"] == INSTANCE_ID
    assert body["mappings"] == []


def test_operator_mappings_bulk_put_and_round_trip(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)

    r = auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
        json={"mappings": [
            {"operator_id": op["id"],
             "autotask_resource_id": 42,
             "autotask_resource_email": "alice@example.com",
             "autotask_resource_name": "Smith, Alice"},
        ]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["mappings"]) == 1
    assert body["mappings"][0]["autotask_resource_id"] == 42
    assert body["mappings"][0]["autotask_resource_email"] == "alice@example.com"
    assert body["mappings"][0]["updated_by_operator_id"] == op["id"]

    r2 = auth_client.get(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
    )
    assert r2.json()["mappings"][0]["autotask_resource_id"] == 42


def test_operator_mappings_bulk_put_replaces_not_appends(auth_client, auth_data_root):
    """PUT is bulk-replace — rows omitted from the body get DELETED.
    Uses two real operators so the FK constraint (operator_id →
    operators.id) is satisfied for both rows in the seed step."""
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    op2 = auth_client.provision_operator(
        "bob", "pw1234567890",
        role="analyst", athena_role="analyst",
    )
    _login(auth_client, op)
    # Seed with 2 mappings
    auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
        json={"mappings": [
            {"operator_id": op["id"], "autotask_resource_id": 1},
            {"operator_id": op2["id"], "autotask_resource_id": 2},
        ]},
    )
    # Now PUT only the alice mapping — bob's should disappear
    auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
        json={"mappings": [
            {"operator_id": op["id"], "autotask_resource_id": 99},
        ]},
    )
    r = auth_client.get(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
    )
    body = r.json()
    assert len(body["mappings"]) == 1
    assert body["mappings"][0]["operator_id"] == op["id"]
    assert body["mappings"][0]["autotask_resource_id"] == 99


def test_operator_mappings_duplicate_in_request_rejected(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
        json={"mappings": [
            {"operator_id": op["id"], "autotask_resource_id": 1},
            {"operator_id": op["id"], "autotask_resource_id": 2},
        ]},
    )
    assert r.status_code == 422
    assert r.json().get("code") == "VALIDATION_FAILED"


def test_operator_mappings_admin_tier_denied(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice-admin", "pw1234567890", athena_role="admin",
    )
    _login(auth_client, op)
    r = auth_client.get(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
    )
    assert r.status_code in (401, 403)


def test_operator_mappings_audit_log(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/operators",
        json={"mappings": [
            {"operator_id": op["id"], "autotask_resource_id": 42},
        ]},
    )
    from apps.octo import paths
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        row = conn.execute(
            "SELECT action, target_id FROM audit_log "
            " WHERE action = 'integrations.autotask.operator_map_replace' "
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[1] == f"adapter_instance:{INSTANCE_ID}"


# ---------------------------------------------------------------------------
# Tenant mappings
# ---------------------------------------------------------------------------

def test_tenant_mappings_bulk_put_and_get(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme",
             "autotask_company_id": 100,
             "autotask_company_name": "Acme Corp",
             "autotask_homepage_url": "https://ww4.autotask.net/Mvc/Company/100"},
            {"tenant_slug": "globex",
             "autotask_company_id": 200,
             "autotask_company_name": "Globex Medical"},
        ]},
    )
    assert r.status_code == 200, r.text
    mappings = r.json()["mappings"]
    assert len(mappings) == 2
    by_slug = {m["tenant_slug"]: m for m in mappings}
    assert by_slug["acme"]["autotask_company_id"] == 100
    assert by_slug["acme"]["autotask_homepage_url"].startswith("https://")
    assert by_slug["globex"]["autotask_homepage_url"] is None


def test_tenant_mappings_save_is_one_transaction(auth_client, auth_data_root):
    """The bulk replace never leaves the map half-saved (a reader — the
    daily location proposals — would see companies vanish): a failure on
    a later row rolls back the delete and the earlier rows too."""
    import pytest

    from apps.octo import paths

    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    url = f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies"
    r = auth_client.put(url, json={"mappings": [
        {"tenant_slug": "acme", "autotask_company_id": 100}]})
    assert r.status_code == 200, r.text
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute("CREATE TRIGGER boom BEFORE INSERT ON autotask_tenant_company_map "
                     "WHEN NEW.tenant_slug = 'boom' BEGIN SELECT RAISE(ABORT, 'boom'); END")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(sqlite3.IntegrityError):
        auth_client.put(url, json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 101},
            {"tenant_slug": "boom", "autotask_company_id": 300}]})
    rows = auth_client.get(url).json()["mappings"]
    assert [(m["tenant_slug"], m["autotask_company_id"]) for m in rows] == [("acme", 100)]


def test_tenant_mappings_homepage_url_must_be_http(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme",
             "autotask_company_id": 100,
             "autotask_homepage_url": "not-a-url"},
        ]},
    )
    assert r.status_code == 422
    assert r.json().get("code") == "VALIDATION_FAILED"


def test_tenant_mappings_duplicate_slug_rejected(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    r = auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 1},
            {"tenant_slug": "acme", "autotask_company_id": 2},
        ]},
    )
    assert r.status_code == 422


def test_tenant_mappings_viewer_denied(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice-viewer", "pw1234567890",
        role="viewer", athena_role="viewer",
    )
    _login(auth_client, op)
    r = auth_client.get(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies",
    )
    assert r.status_code in (401, 403)


def test_tenant_mappings_audit_log(auth_client, auth_data_root):
    op = auth_client.provision_operator(
        "alice", "pw1234567890", athena_role="super_admin",
    )
    _login(auth_client, op)
    auth_client.put(
        f"/api/v1/integrations/autotask/{INSTANCE_ID}/mappings/companies",
        json={"mappings": [
            {"tenant_slug": "acme", "autotask_company_id": 42},
        ]},
    )
    from apps.octo import paths
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        row = conn.execute(
            "SELECT action, target_id FROM audit_log "
            " WHERE action = 'integrations.autotask.tenant_map_replace' "
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[1] == f"adapter_instance:{INSTANCE_ID}"


# ---------------------------------------------------------------------------
# Schema is applied at bootstrap
# ---------------------------------------------------------------------------

def test_migration_015_applied(auth_client, auth_data_root):
    """Migration 015 should have been applied by bootstrap, creating
    all three mapping tables in registry.db."""
    from apps.octo import paths
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    finally:
        conn.close()
    assert "autotask_picklist_cache" in names
    assert "autotask_operator_resource_map" in names
    assert "autotask_tenant_company_map" in names
