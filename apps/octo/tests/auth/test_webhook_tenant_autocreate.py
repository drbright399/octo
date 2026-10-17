"""Auto-create / quarantine on the WEBHOOK path — the real Datto webhook
route on the real app (instance created through the admin API, real token
check, real registry, real ingest, real quarantine store)."""
from __future__ import annotations

import sqlite3

import pytest

from apps.octo import paths
from apps.octo.instances import quarantine, tenant_map
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    instance_endpoint_client,
)
from apps.octo.tests.auth.test_webhook_reachability import (  # noqa: F401
    _HOOK,
    _card,
    _create_datto,
    hooks,
)


@pytest.fixture(autouse=True)
def _clean_quarantine():
    quarantine.reset_schema_cache()
    yield
    quarantine.reset_schema_cache()


def _webhook_alert(uid: str, *, site_uid: str, site_name: str | None) -> dict:
    body = {
        "event": "alert_raised", "alertUid": uid, "alertCategory": "Disk",
        "alertType": "Disk Usage", "alertContext": {"message": "disk full"},
        "device": {"hostname": "WS-1", "uid": "d-1"}, "siteUid": site_uid,
    }
    if site_name is not None:
        body["siteName"] = site_name
    return body


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


def test_webhook_from_a_new_named_site_creates_the_tenant_and_ingests(hooks):  # noqa: F811
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    good = {"X-Webhook-Token": token}

    r = client.post(_HOOK, json=_webhook_alert("a-1", site_uid="site-uid-0001",
                                               site_name="Acme Corp"), headers=good)
    assert r.status_code == 200, r.text
    # A hand-typed uid is never fetched: the templated body itself is routed.
    assert r.json() == {"status": "accepted", "ingested": True, "tenant": "acme-corp",
                        "event_id": "a-1", "idempotent": False, "routing": "auto-created",
                        "via": "template"}
    (event,) = _events("acme-corp")
    assert event["event_type"] == "datto.perf_disk_usage" and event["summary"] == "Disk — disk full"
    assert tenant_map.resolve(iid, "site-uid-0001") == "acme-corp"

    # Delivered again (vendor retry): mapped, idempotent, nothing new.
    r = client.post(_HOOK, json=_webhook_alert("a-1", site_uid="site-uid-0001",
                                               site_name="Acme Corp"), headers=good)
    assert r.json()["idempotent"] is True and r.json()["routing"] == "mapped"
    assert len(_events("acme-corp")) == 1

    card = _card(client, cookies)
    assert card["auto_created_pending"] == 1 and card["quarantined"] == 0
    assert card["webhook_receipt"]["accepted_since_start"] == 2
    tenants = client.get("/api/v1/admin/tenants", cookies=cookies).json()["tenants"]
    (t,) = tenants
    assert t["slug"] == "acme-corp" and t["origin"] == "auto" and t["review_state"] == "pending"
    assert t["created_by_instance"]["instance_id"] == iid


def test_webhook_without_site_name_is_held_and_visible_on_the_card(hooks):  # noqa: F811
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    good = {"X-Webhook-Token": token}

    r = client.post(_HOOK, json=_webhook_alert("a-2", site_uid="site-uid-0002",
                                               site_name=None), headers=good)
    assert r.status_code == 200 and r.json() == {
        "status": "accepted", "ingested": False, "reason": "quarantined",
        "quarantine_reason": "name-unknown", "via": "template",
    }
    # An unsubstituted template variable is "missing", not a name.
    r = client.post(_HOOK, json=_webhook_alert("a-3", site_uid="site-uid-0003",
                                               site_name="[site_name]"), headers=good)
    assert r.json()["quarantine_reason"] == "name-unknown"
    assert client.get("/api/v1/admin/tenants", cookies=cookies).json()["tenants"] == []

    card = _card(client, cookies)
    assert card["quarantined"] == 2 and card["auto_created_pending"] == 0
    assert any("2 event(s)" in w and "quarantine" in w for w in card["warnings"])
    held = client.get(f"/api/v1/admin/quarantine?instance_id={iid}", cookies=cookies).json()
    assert held["total"] == 2 and {r["source"] for r in held["rows"]} == {"webhook"}
    assert {r["vendor_tenant_id"] for r in held["rows"]} == {"site-uid-0002", "site-uid-0003"}
    assert all(r["event_summary"] == "Disk — disk full" for r in held["rows"])
    # Routing one from the console maps the site; the next webhook lands
    # directly. (The `hooks` fixture registers a stub under the datto slug
    # for instance creation; the replay needs the real adapter's extract.)
    from apps.octo.adapters.datto import DattoSourceAdapter
    client.app.state.adapter_registry._adapter_classes["datto"] = DattoSourceAdapter
    r = client.post(f"/api/v1/admin/quarantine/{held['rows'][0]['id']}/route",
                    json={"new": {"display_name": "Routed Co", "kind": "client"}}, cookies=cookies)
    assert r.status_code == 200 and r.json()["mapping_written"] is True
    site = held["rows"][0]["vendor_tenant_id"]
    r = client.post(_HOOK, json=_webhook_alert("a-9", site_uid=site, site_name=None), headers=good)
    assert r.json()["ingested"] is True and r.json()["tenant"] == "routed-co"
    assert r.json()["routing"] == "mapped"
