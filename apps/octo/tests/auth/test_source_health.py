"""GET /api/v1/dashboard/source-health + the scoping of /dashboard/integrations.

Owner decision 2026-09-28 (b): client-scoped users (viewers) must not learn
which vendor integrations the MSP runs. They get their own tenants' feed
freshness and nothing else; analyst+ get every source in their scope.

Real app, real registry, real ingest route, real heartbeat route, the real
Datto / Wazuh adapter classes (registered, never started — no vendor is
contacted), the real ContactReporter and freshness recorder.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.auth import core as core_auth
from apps.octo.db import connect
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import create_instance, freshness, vendor_contact
from apps.octo.instances.manager import set_contact_status
from apps.octo.instances.tenant_map import TenantMapping, set_mappings
from apps.octo.tests.auth.test_buoy_heartbeat import _heartbeat_body, _mint_client_token
from apps.octo.tests.auth.test_dashboard_throughput import _login

URL = "/api/v1/dashboard/source-health"
INTEGRATIONS = "/api/v1/dashboard/integrations"
# Everything that would tell a client user which vendors / instances the MSP
# runs. None of it may appear in a viewer's response.
VENDOR_STRINGS = (
    "datto", "wazuh", "rocketcyber", "unifi", "autotask", "resend", "nextdns",
    "shim-token", "buoy-acme-corp", "adapter", "globex",
)


@pytest.fixture(autouse=True)
def _clean_state():
    vendor_contact.reset()
    freshness.reset()
    for name in ("_pending_last_used", "_last_used_written", "_last_used_seen"):
        getattr(core_auth, name).clear()
    yield
    vendor_contact.reset()
    freshness.reset()
    for name in ("_pending_last_used", "_last_used_written", "_last_used_seen"):
        getattr(core_auth, name).clear()


def _ago(**delta) -> str:
    return format_utc_ms(datetime.now(timezone.utc) - timedelta(**delta))


@pytest.fixture
def world(auth_client, auth_data_root, tmp_path, monkeypatch):
    """Three active tenants and one offboarded; a Datto instance serving
    acme-corp, a Wazuh instance serving globex; a shim token per tenant for
    acme-corp and globex; a buoy for acme-corp."""
    monkeypatch.setenv(
        "OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "adapter-credentials-key.env"),
    )
    from apps.octo.credentials import ensure_key_file
    ensure_key_file()

    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(DattoSourceAdapter)
    registry.register_adapter_class(WazuhSourceAdapter)
    auth_client.app.state.adapter_registry = registry

    client_provisioning.create_client("acme-corp", "Acme Corp")
    client_provisioning.create_client("globex", "Globex")
    client_provisioning.create_client("umbrella", "Umbrella")
    client_provisioning.create_client("initech", "Initech")
    reg = connect(paths.registry_db_path())
    try:
        reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = 'initech'")
    finally:
        reg.close()

    datto = create_instance(
        vendor_slug="datto", display_name="Datto RMM", credentials_dict={"k": "v"},
        instance_config={"poll_interval_sec": 30},
    )
    set_mappings(datto.id, [TenantMapping("site-1", "acme-corp")])
    wazuh = create_instance(
        vendor_slug="wazuh", display_name="Wazuh", credentials_dict={"k": "v"},
        default_tenant_slug="globex",
    )
    tokens = {
        "acme-corp": _mint_client_token("acme-corp", kind="service", label="shim-token-acme"),
        "globex": _mint_client_token("globex", kind="service", label="shim-token-globex"),
    }
    buoy = _mint_client_token("acme-corp", kind="buoy", label="buoy")
    r = auth_client.post(
        "/api/v1/buoy/heartbeat", json=_heartbeat_body("acme-corp"),
        headers={"Authorization": f"Bearer {buoy}"},
    )
    assert r.status_code == 200, r.text
    return {"client": auth_client, "datto": datto, "wazuh": wazuh, "tokens": tokens,
            "buoy_token": buoy}


def _as(world, role: str, scope: list[str] | None = None, name: str | None = None):
    client = world["client"]
    client.cookies.clear()
    username = name or f"{role}-{'-'.join(scope or ['all'])}"
    op = client.provision_operator(
        username, "pw1234567890",
        role="admin" if role == "super_admin" else role,
        athena_role=role, scope_slugs=scope or ["*"],
    )
    _login(client, op)
    return client


def _ingest(world, slug: str) -> None:
    r = world["client"].post(
        f"/api/v1/ingest/{slug}/events",
        headers={"Authorization": f"Bearer {world['tokens'][slug]}"},
        json={"event_type": "probe", "severity": "info", "data": {"n": 1}},
    )
    assert r.status_code == 202, r.text


def _ids(body: dict) -> set[str]:
    return {s["id"] for s in body["sources"]}


# ---------------------------------------------------------------------------
# Role / scope matrix
# ---------------------------------------------------------------------------

def test_unauthenticated_is_refused(world):
    world["client"].cookies.clear()
    assert world["client"].get(URL).status_code == 401
    assert world["client"].get(INTEGRATIONS).status_code == 401


def test_viewer_sees_only_own_tenant_freshness_and_no_vendor_strings(world):
    _ingest(world, "acme-corp")
    _ingest(world, "globex")
    client = _as(world, "viewer", ["acme-corp"])
    r = client.get(URL)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["view"] == "tenant"
    assert body["sources"] == []
    (tenant,) = body["tenants"]
    assert tenant["slug"] == "acme-corp" and tenant["display_name"] == "Acme Corp"
    assert tenant["state"] == "ok" and tenant["last_event_age_sec"] is not None
    # No threshold either: its value said whether the tenant has a push
    # source (a shim or a buoy) — how the MSP feeds it.
    assert set(tenant) == {"slug", "display_name", "last_event_at", "last_event_age_sec", "state"}
    text = r.text.lower()
    for needle in VENDOR_STRINGS:
        assert needle not in text, needle


def test_viewer_gets_no_health_verdict_even_when_a_feed_fails(world):
    """MSP-wide health (a failing Datto poller serves many tenants) is not
    the client's to see: their row stays freshness only."""
    _insert_event("acme-corp", _ago(hours=30))
    vendor_contact.ContactReporter(world["datto"].id, what="test").failed("forbidden", "x")
    body = _as(world, "viewer", ["acme-corp"]).get(URL).json()
    (tenant,) = body["tenants"]
    assert tenant["state"] == "ok" and tenant["last_event_age_sec"] >= 30 * 3600
    # The same moment, an analyst sees the tenant flagged.
    analyst = {t["slug"]: t for t in _as(world, "analyst").get(URL).json()["tenants"]}
    assert analyst["acme-corp"]["state"] == "degraded"


def test_viewer_never_sees_an_auto_create_placeholder_name(world):
    """A tenant auto-created with no vendor name is named after the vendor
    ("datto site 1a2b3c4d") until someone renames it. A client user sees a
    neutral name instead; staff still see the real one."""
    from apps.octo.instances import tenant_autocreate

    res = tenant_autocreate.resolve_tenant(
        instance_id=world["datto"].id, vendor_slug="datto",
        vendor_tenant_id="1a2b3c4d-0000-4000-8000-00000000abcd",
        vendor_tenant_label=None, default_tenant_slug=None, supports_discovery=False,
    )
    assert res.slug, res
    placeholder = tenant_autocreate.placeholder_label(
        "datto", "1a2b3c4d-0000-4000-8000-00000000abcd",
    )
    r = _as(world, "viewer", [res.slug]).get(URL)
    (tenant,) = r.json()["tenants"]
    assert tenant["display_name"] == "Your organization"
    assert placeholder.lower() not in r.text.lower()

    analyst = {t["slug"]: t for t in _as(world, "analyst").get(URL).json()["tenants"]}
    assert analyst[res.slug]["display_name"] == placeholder

    # Renamed by an admin: the real name shows again.
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE clients SET display_name = 'Acme Dental' WHERE slug = ?", (res.slug,),
        )
    finally:
        reg.close()
    (tenant,) = _as(world, "viewer", [res.slug], name="viewer-renamed").get(URL).json()["tenants"]
    assert tenant["display_name"] == "Acme Dental"


def test_viewer_is_refused_the_integrations_list(world):
    client = _as(world, "viewer", ["acme-corp"])
    r = client.get(INTEGRATIONS)
    assert r.status_code == 403
    text = r.text.lower()
    for needle in ("datto", "wazuh"):
        assert needle not in text


def test_scoped_analyst_sees_only_sources_serving_their_tenants(world):
    client = _as(world, "analyst", ["acme-corp"])
    body = client.get(URL).json()
    assert body["view"] == "full"
    datto_id, wazuh_id = world["datto"].id, world["wazuh"].id
    ids = _ids(body)
    assert f"adapter:{datto_id}" in ids and f"adapter:{wazuh_id}" not in ids
    assert "buoy:acme-corp" in ids
    tokens = [s for s in body["sources"] if s["kind"] == "ingest_token"]
    assert [t["tenant_slug"] for t in tokens] == ["acme-corp"]
    assert [t["slug"] for t in body["tenants"]] == ["acme-corp"]

    items = client.get(INTEGRATIONS).json()["items"]
    assert [i["slug"] for i in items] == ["datto"]


@pytest.mark.parametrize("role", ["analyst", "admin", "super_admin"])
def test_all_scope_sees_every_source_of_active_tenants(world, role):
    client = _as(world, role)
    body = client.get(URL).json()
    assert body["view"] == "full"
    kinds = {}
    for s in body["sources"]:
        kinds.setdefault(s["kind"], set()).add(s["tenant_slug"])
    assert kinds["adapter"] == {None}
    assert len([s for s in body["sources"] if s["kind"] == "adapter"]) == 2
    assert kinds["ingest_token"] == {"acme-corp", "globex"}
    assert kinds["buoy"] == {"acme-corp"}
    # '*' = every ACTIVE tenant: the offboarded one is not listed.
    assert {t["slug"] for t in body["tenants"]} == {"acme-corp", "globex", "umbrella"}

    items = client.get(INTEGRATIONS).json()["items"]
    assert {i["slug"] for i in items} == {"datto", "wazuh"}


def test_scoped_admin_is_scoped_too(world):
    client = _as(world, "admin", ["globex"])
    body = client.get(URL).json()
    assert {s["id"] for s in body["sources"] if s["kind"] == "adapter"} == {
        f"adapter:{world['wazuh'].id}",
    }
    assert [t["slug"] for t in body["tenants"]] == ["globex"]
    assert [i["slug"] for i in client.get(INTEGRATIONS).json()["items"]] == ["wazuh"]


# ---------------------------------------------------------------------------
# Status + stale thresholds
# ---------------------------------------------------------------------------

def _source(body: dict, source_id: str) -> dict:
    (row,) = [s for s in body["sources"] if s["id"] == source_id]
    return row


def test_poller_awaits_first_poll_then_is_ok_then_stale(world, monkeypatch):
    client = _as(world, "analyst")
    sid = f"adapter:{world['datto'].id}"
    row = _source(client.get(URL).json(), sid)
    # Created, never started: no poll has happened.
    assert row["status"] == "pending" and row["freshness_basis"] == "contact"
    assert row["stale_after_sec"] == 2 * 30 + 60
    assert row["last_contact_at"] is None and row["stale"] is False

    set_contact_status(world["datto"].id, status="running", status_detail="started")
    row = _source(client.get(URL).json(), sid)
    assert row["status"] == "pending" and row["detail"] == "Awaiting the first poll."

    reporter = vendor_contact.ContactReporter(world["datto"].id, what="test")
    reporter.ok()
    freshness.record_event(instance_id=world["datto"].id, slug="acme-corp")
    row = _source(client.get(URL).json(), sid)
    assert row["status"] == "ok" and row["stale"] is False
    assert row["last_contact_age_sec"] <= 5 and row["last_event_age_sec"] <= 5

    # The last good poll is now 10 minutes old: the poller is stuck.
    monkeypatch.setattr(vendor_contact, "utcnow_iso", lambda: _ago(minutes=10))
    reporter.ok()
    row = _source(client.get(URL).json(), sid)
    assert row["status"] == "degraded" and row["stale"] is True
    assert row["last_contact_age_sec"] >= 600


def test_quiet_poller_is_not_stale(world):
    """No event for days is fine while polls succeed — a quiet vendor."""
    client = _as(world, "analyst")
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE adapter_instances SET last_event_at = ? WHERE id = ?",
            (_ago(days=3), world["datto"].id),
        )
    finally:
        reg.close()
    vendor_contact.ContactReporter(world["datto"].id, what="test").ok()
    row = _source(client.get(URL).json(), f"adapter:{world['datto'].id}")
    assert row["status"] == "ok" and row["stale"] is False
    assert row["last_event_age_sec"] >= 3 * 86400


def test_failing_poller_is_down_with_a_fixed_sentence(world):
    client = _as(world, "analyst")
    vendor_contact.ContactReporter(world["datto"].id, what="test").failed(
        "forbidden", "VENDOR-QUOTED-TEXT",
    )
    row = _source(client.get(URL).json(), f"adapter:{world['datto'].id}")
    assert row["status"] == "down"
    assert "VENDOR-QUOTED-TEXT" not in row["detail"]
    assert row["detail"] == vendor_contact.analyst_summary(world["datto"].id)


def _forget_process_memory() -> None:
    """A restart: every in-process clock is gone."""
    freshness.reset()
    for name in ("_pending_last_used", "_last_used_written", "_last_used_seen"):
        getattr(core_auth, name).clear()


def _set(sql: str, *params) -> None:
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(sql, params)
    finally:
        reg.close()


def _age_token_events(slug: str, label: str, received_at: str) -> None:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        conn.execute(
            "UPDATE events SET received_at = ? WHERE source = ?", (received_at, f"buoy:{label}"),
        )
        conn.commit()
    finally:
        conn.close()


def _token_row(client, slug: str) -> dict:
    (row,) = [
        s for s in client.get(URL).json()["sources"]
        if s["kind"] == "ingest_token" and s["tenant_slug"] == slug
    ]
    return row


def _post_as(world, slug: str, path: str, body: dict) -> int:
    return world["client"].post(
        f"/api/v1/ingest/{slug}{path}",
        headers={"Authorization": f"Bearer {world['tokens'][slug]}"},
        json=body,
    ).status_code


def _wazuh_alert(alert_id: str) -> dict:
    return {"payload": {
        "id": alert_id,
        "timestamp": _ago(minutes=1),
        "rule": {"level": 10, "id": "5720", "description": "Multiple authentication failures",
                 "groups": ["syslog", "authentication_failures"]},
        "agent": {"name": "web-01"},
        "data": {"srcip": "203.0.113.9"},
    }}


def test_ingest_token_fresh_then_stale(world):
    client = _as(world, "analyst")
    acme = _token_row(client, "acme-corp")
    assert acme["status"] == "pending" and acme["last_event_at"] is None
    assert acme["freshness_basis"] == "event" and acme["stale_after_sec"] == 24 * 3600

    _ingest(world, "acme-corp")
    acme = _token_row(client, "acme-corp")
    assert acme["status"] == "ok" and acme["last_event_age_sec"] <= 5
    assert acme["last_contact_age_sec"] <= 5

    # A restart, then an overnight lull: the shim has no heartbeat and posts
    # only when Wazuh raises an alert, so three quiet hours are not stale.
    # The last accepted post is read back from the stored events. (The token
    # is backdated too: the read-back takes nothing older than the token.)
    _forget_process_memory()
    _age_token_events("acme-corp", "shim-token-acme", _ago(hours=3))
    _set("UPDATE client_tokens SET created_at = ?, last_used_at = ? WHERE id = ?",
         _ago(days=7), _ago(hours=3), int(acme["id"].split(":")[1]))
    acme = _token_row(client, "acme-corp")
    assert acme["status"] == "ok" and acme["stale"] is False
    assert 3 * 3600 - 5 <= acme["last_event_age_sec"] <= 3 * 3600 + 5

    # A day and more: stale.
    _age_token_events("acme-corp", "shim-token-acme", _ago(hours=30))
    _set("UPDATE client_tokens SET last_used_at = ? WHERE id = ?",
         _ago(hours=30), int(acme["id"].split(":")[1]))
    acme = _token_row(client, "acme-corp")
    assert acme["status"] == "degraded" and acme["stale"] is True
    assert acme["last_event_age_sec"] >= 30 * 3600


def test_refused_posts_do_not_keep_a_token_green(world):
    """Every post refused (bad body, unknown source type, Wazuh schema
    drift): the token authenticated each time, so its last_used_at is
    fresh — but nothing was accepted, and the card must say so."""
    assert _post_as(world, "globex", "/events", {"data": "not-an-object"}) == 422
    assert _post_as(world, "globex", "/nosuch/alerts", {"payload": {}}) == 422
    assert _post_as(world, "globex", "/wazuh/alerts",
                    {"payload": {"rule": {"level": "high"}}}) == 422
    client = _as(world, "analyst")
    row = _token_row(client, "globex")
    assert row["status"] == "degraded"
    assert row["detail"] == "Posts are arriving but being refused."
    assert row["last_event_at"] is None and row["last_contact_age_sec"] <= 5
    tenants = {t["slug"]: t for t in client.get(URL).json()["tenants"]}
    assert tenants["globex"]["state"] == "degraded"

    # One accepted post and it is green again.
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202
    row = _token_row(client, "globex")
    assert row["status"] == "ok" and row["detail"] is None
    assert row["last_event_age_sec"] <= 5


def test_refusals_after_a_good_post_turn_the_token_degraded(world, monkeypatch):
    three_min_ago = _ago(minutes=3)
    with monkeypatch.context() as m:
        m.setattr(freshness, "utcnow_iso", lambda: three_min_ago)
        assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202
    client = _as(world, "analyst")
    assert _token_row(client, "globex")["status"] == "ok"

    # Schema drift: every post since is refused.
    assert _post_as(world, "globex", "/wazuh/alerts",
                    {"payload": {"rule": {"level": "high"}}}) == 422
    row = _token_row(client, "globex")
    assert row["status"] == "degraded"
    assert row["detail"] == "Posts are arriving but being refused."
    assert 175 <= row["last_event_age_sec"] <= 190


def test_a_replayed_alert_counts_as_an_accepted_post(world, monkeypatch):
    """A shim replay (cursor wiped) is answered `idempotent`: nothing new is
    stored, but the post was accepted — the shim works."""
    three_min_ago = _ago(minutes=3)
    alert = _wazuh_alert("g-replay")
    with monkeypatch.context() as m:
        m.setattr(freshness, "utcnow_iso", lambda: three_min_ago)
        assert _post_as(world, "globex", "/wazuh/alerts", alert) == 202
    r = world["client"].post(
        "/api/v1/ingest/globex/wazuh/alerts",
        headers={"Authorization": f"Bearer {world['tokens']['globex']}"}, json=alert,
    )
    assert r.status_code == 202 and r.json()["idempotent"] is True
    row = _token_row(_as(world, "analyst"), "globex")
    assert row["status"] == "ok" and row["last_event_age_sec"] <= 5


def _refuse(world, slug: str, bearer: str | None = None) -> None:
    r = world["client"].post(
        f"/api/v1/ingest/{slug}/events",
        headers={"Authorization": f"Bearer {bearer or world['tokens'][slug]}"},
        json={"data": "not-an-object"},
    )
    assert r.status_code == 422, r.text


def _at(monkeypatch, when: str, action) -> None:
    """Run `action` with the freshness clocks reading `when`."""
    with monkeypatch.context() as m:
        m.setattr(freshness, "utcnow_iso", lambda: when)
        action()


def test_a_refusal_holds_the_token_degraded_only_while_refusals_arrive(world, monkeypatch):
    """One refused post used to hold a token 'being refused' until the next
    accepted post — for a quiet feed, indefinitely. It holds while refused
    requests keep coming (REFUSED_RECENT_SEC after the latest); after that
    the token is judged by its last accepted post again, and the card notes
    the refusal until a post is accepted."""
    # globex: accepted 5 h ago, refused 20 min ago — still arriving.
    _at(monkeypatch, _ago(hours=5),
        lambda: _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")))
    _at(monkeypatch, _ago(minutes=20), lambda: _refuse(world, "globex"))
    # acme-corp: accepted 5 h ago, one refused post 2 h ago, nothing since.
    _at(monkeypatch, _ago(hours=5), lambda: _ingest(world, "acme-corp"))
    _at(monkeypatch, _ago(hours=2), lambda: _refuse(world, "acme-corp"))

    client = _as(world, "analyst")
    row = _token_row(client, "globex")
    assert row["status"] == "degraded"
    assert row["detail"] == "Posts are arriving but being refused."

    row = _token_row(client, "acme-corp")
    assert row["status"] == "ok" and row["stale"] is False
    assert row["detail"] == "Its latest post was refused; none accepted since."
    assert 5 * 3600 - 5 <= row["last_event_age_sec"] <= 5 * 3600 + 5
    tenants = {t["slug"]: t for t in client.get(URL).json()["tenants"]}
    assert tenants["acme-corp"]["state"] == "ok"

    # An accepted post clears the note.
    _ingest(world, "acme-corp")
    row = _token_row(client, "acme-corp")
    assert row["status"] == "ok" and row["detail"] is None


def test_a_quiet_feed_refused_every_time_stays_degraded(world, monkeypatch):
    """A feed that posts less than hourly (a Wazuh schema drift after an
    upgrade) and is refused EVERY time: each refusal is more than
    REFUSED_RECENT_SEC old before the next arrives, so the latest-refusal
    clock alone flipped the card between 'being refused' and 'ok' all day.
    Two or more refusals in a row keep it degraded until one is accepted."""
    _at(monkeypatch, _ago(hours=5), lambda: _ingest(world, "acme-corp"))
    for minutes in (210, 130, 70):
        _at(monkeypatch, _ago(minutes=minutes), lambda: _refuse(world, "acme-corp"))
    client = _as(world, "analyst")
    row = _token_row(client, "acme-corp")
    assert row["status"] == "degraded" and row["stale"] is False
    assert row["detail"] == "Its last 3 posts were refused; none accepted since."
    tenants = {t["slug"]: t for t in client.get(URL).json()["tenants"]}
    assert tenants["acme-corp"]["state"] == "degraded"

    # One accepted post ends the streak; a later single refusal decays again.
    _at(monkeypatch, _ago(minutes=65), lambda: _ingest(world, "acme-corp"))
    _at(monkeypatch, _ago(minutes=62), lambda: _refuse(world, "acme-corp"))
    row = _token_row(client, "acme-corp")
    assert row["status"] == "ok"
    assert row["detail"] == "Its latest post was refused; none accepted since."


def test_a_refusal_older_than_the_stale_window_is_no_longer_noted(world, monkeypatch):
    bearer = _mint_client_token("umbrella", kind="service", label="shim-token-umbrella")
    world["tokens"]["umbrella"] = bearer
    _at(monkeypatch, _ago(hours=31), lambda: _ingest(world, "umbrella"))
    _at(monkeypatch, _ago(hours=25), lambda: _refuse(world, "umbrella"))
    row = _token_row(_as(world, "analyst"), "umbrella")
    # Judged by the last accepted post (31 h: stale), no refusal note.
    assert row["status"] == "degraded" and row["stale"] is True
    assert row["detail"] == "No data received within the expected interval."


def _token_id(bearer: str) -> int:
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        return int(reg.execute(
            "SELECT id FROM client_tokens WHERE token_prefix = ?",
            (core_auth.token_prefix(bearer),),
        ).fetchone()[0])
    finally:
        reg.close()


def _token_rows_by_id(client, slug: str) -> dict[int, dict]:
    return {
        int(s["id"].split(":")[1]): s for s in client.get(URL).json()["sources"]
        if s["kind"] == "ingest_token" and s["tenant_slug"] == slug
    }


def test_rotation_overlap_an_idle_token_does_not_borrow_the_working_ones_freshness(world):
    """Rotation overlap: a second live token under the SAME label. Stored
    events carry the label, not the token — the idle one used to read the
    working one's events as its own and show ok."""
    working = _token_id(world["tokens"]["globex"])
    idle = _token_id(_mint_client_token("globex", kind="service", label="shim-token-globex"))
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202

    rows = _token_rows_by_id(_as(world, "analyst"), "globex")
    assert rows[working]["status"] == "ok" and rows[working]["detail"] is None
    assert rows[idle]["status"] == "pending"
    assert rows[idle]["last_event_at"] is None
    assert rows[idle]["detail"] == "No data received yet."


def test_rotation_overlap_after_a_restart_the_shared_label_is_flagged(world):
    """After a restart the process no longer knows which token posted the
    stored events. Each token's read-back says it may be the other's —
    until a token posts again, which makes its own freshness exact."""
    working = _token_id(world["tokens"]["globex"])
    idle = _token_id(_mint_client_token("globex", kind="service", label="shim-token-globex"))
    _set("UPDATE client_tokens SET created_at = ? WHERE slug = 'globex'", _ago(days=7))
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202
    _forget_process_memory()
    _age_token_events("globex", "shim-token-globex", _ago(hours=2))

    client = _as(world, "analyst")
    rows = _token_rows_by_id(client, "globex")
    assert rows[working]["status"] == "ok"
    assert rows[working]["detail"] == (
        f"Shares its label with token #{idle} — this freshness may be the other token's."
    )
    assert rows[idle]["detail"] == (
        f"Shares its label with token #{working} — this freshness may be the other token's."
    )

    # The working token posts again: its freshness is its own; the idle one
    # never takes that new post as its own, and stays flagged.
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-2")) == 202
    rows = _token_rows_by_id(client, "globex")
    assert rows[working]["detail"] is None and rows[working]["last_event_age_sec"] <= 5
    assert rows[idle]["last_event_age_sec"] >= 2 * 3600 - 5
    assert f"token #{working}" in rows[idle]["detail"]


def test_a_new_token_never_inherits_its_predecessors_events(world):
    """Rotation done: old token revoked, new token minted under the same
    label, and the shim never switched. After a restart the new token must
    not read the old one's events (they predate it) as its own."""
    old = _token_id(world["tokens"]["globex"])
    _set("UPDATE client_tokens SET created_at = ? WHERE id = ?", _ago(days=7), old)
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202
    _age_token_events("globex", "shim-token-globex", _ago(hours=5))
    new = _token_id(_mint_client_token("globex", kind="service", label="shim-token-globex"))
    _set("UPDATE client_tokens SET revoked_at = ? WHERE id = ?", _ago(hours=1), old)
    _forget_process_memory()

    rows = _token_rows_by_id(_as(world, "analyst"), "globex")
    assert set(rows) == {new}
    assert rows[new]["status"] == "pending" and rows[new]["last_event_at"] is None
    assert rows[new]["detail"] == "No data received yet."


def test_a_token_revoked_before_the_window_is_not_a_suspect(world):
    old = _token_id(world["tokens"]["globex"])
    bearer = _mint_client_token("globex", kind="service", label="shim-token-globex")
    new = _token_id(bearer)
    _set("UPDATE client_tokens SET created_at = ?, revoked_at = ? WHERE id = ?",
         _ago(days=30), _ago(days=3), old)
    _set("UPDATE client_tokens SET created_at = ? WHERE id = ?", _ago(days=7), new)
    world["tokens"]["globex"] = bearer
    assert _post_as(world, "globex", "/wazuh/alerts", _wazuh_alert("g-1")) == 202
    _forget_process_memory()
    _age_token_events("globex", "shim-token-globex", _ago(hours=2))

    row = _token_rows_by_id(_as(world, "analyst"), "globex")[new]
    assert row["status"] == "ok" and row["detail"] is None
    assert 2 * 3600 - 5 <= row["last_event_age_sec"] <= 2 * 3600 + 5


def test_buoy_heartbeat_basis_and_staleness(world):
    client = _as(world, "analyst")
    row = _source(client.get(URL).json(), "buoy:acme-corp")
    assert row["status"] == "ok" and row["freshness_basis"] == "heartbeat"
    assert row["stale_after_sec"] == 120 and row["name"] == "buoy-acme-corp"
    reg = connect(paths.registry_db_path())
    try:
        reg.execute(
            "UPDATE buoys SET last_heartbeat_at = ? WHERE slug = 'acme-corp'", (_ago(minutes=3),),
        )
    finally:
        reg.close()
    row = _source(client.get(URL).json(), "buoy:acme-corp")
    assert row["stale"] is True and row["status"] == "degraded"


def _insert_event(slug: str, received_at: str) -> None:
    conn = sqlite3.connect(paths.client_dir(slug) / "events.db")
    try:
        conn.execute(
            "INSERT INTO events (received_at, source, event_type, severity, payload, "
            "payload_sha256) VALUES (?, 'x', 'alert', 'low', '{}', ?)",
            (received_at, "c" * 64),
        )
        conn.commit()
    finally:
        conn.close()


def test_a_quiet_tenant_is_information_not_a_warning(world):
    """A day and more without an alert, every source feeding the tenant
    healthy: no alerts is good news, not a problem — for a shim-and-buoy
    tenant and a tenant with no source at all alike."""
    _insert_event("acme-corp", _ago(hours=30))
    _insert_event("umbrella", _ago(hours=30))
    client = _as(world, "analyst")
    tenants = {t["slug"]: t for t in client.get(URL).json()["tenants"]}
    assert tenants["acme-corp"]["state"] == "ok"
    assert tenants["acme-corp"]["last_event_age_sec"] >= 30 * 3600
    assert tenants["umbrella"]["state"] == "ok"
    assert tenants["globex"]["state"] == "none"
    assert "stale_after_sec" not in tenants["acme-corp"]


def test_a_tenant_is_degraded_when_a_source_feeding_it_fails(world):
    _insert_event("acme-corp", _ago(minutes=5))
    _insert_event("umbrella", _ago(minutes=5))
    client = _as(world, "analyst")
    # The Datto poller, which delivers into acme-corp only, starts failing.
    vendor_contact.ContactReporter(world["datto"].id, what="test").failed("forbidden", "x")
    body = client.get(URL).json()
    tenants = {t["slug"]: t for t in body["tenants"]}
    assert tenants["acme-corp"]["state"] == "degraded"
    assert tenants["umbrella"]["state"] == "ok"
    assert tenants["globex"]["state"] == "none"
    # Problems float to the top.
    assert body["tenants"][0]["slug"] == "acme-corp"

    # The poller recovers; then a buoy whose heartbeat is overdue flags its
    # tenant the same way.
    set_contact_status(world["datto"].id, status="running", status_detail="recovered")
    vendor_contact.ContactReporter(world["datto"].id, what="test").ok()
    assert {t["slug"]: t for t in client.get(URL).json()["tenants"]}["acme-corp"]["state"] == "ok"
    _set("UPDATE buoys SET last_heartbeat_at = ? WHERE slug = 'acme-corp'", _ago(minutes=3))
    assert {t["slug"]: t for t in client.get(URL).json()["tenants"]}["acme-corp"]["state"] == "degraded"


def test_no_secret_or_raw_payload_in_the_full_view(world):
    _ingest(world, "acme-corp")
    client = _as(world, "super_admin")
    text = client.get(URL).text
    for token in world["tokens"].values():
        assert token not in text
        assert core_auth.token_prefix(token) not in text
    assert "cred_ref" not in text and "v1:" not in json.dumps(client.get(URL).json()["sources"])


def test_a_buoy_unit_disabled_on_purpose_is_retired_not_degraded(world):
    """v0.11 B1: the heartbeat reports each watched unit's is-enabled state.
    A unit DISABLED on purpose (the retired octo-forwarder) is information —
    the buoy stays ok and the row names it; an ENABLED unit that is not
    active degrades it, as before."""
    client = world["client"]

    def beat(services: dict) -> None:
        r = client.post(
            "/api/v1/buoy/heartbeat", json=_heartbeat_body("acme-corp", services=services),
            headers={"Authorization": f"Bearer {world['buoy_token']}"},
        )
        assert r.status_code == 200, r.text

    active = {"state": "active", "enabled": "enabled"}
    beat({"tailscaled": active, "suricata": active,
          "octo-forwarder": {"state": "inactive", "enabled": "disabled"}})
    analyst = _as(world, "analyst")
    row = _source(analyst.get(URL).json(), "buoy:acme-corp")
    assert row["status"] == "ok"
    assert row["detail"] == "Retired (disabled on purpose): octo-forwarder."

    beat({"tailscaled": active, "suricata": {"state": "failed", "enabled": "enabled"},
          "octo-forwarder": {"state": "inactive", "enabled": "masked"}})
    row = _source(analyst.get(URL).json(), "buoy:acme-corp")
    assert row["status"] == "degraded"
    assert row["detail"] == (
        "A monitored service the buoy should be running is not active. "
        "Retired (disabled on purpose): octo-forwarder.")

    # A heartbeat daemon older than v0.11 (no enablement): not active is
    # degraded, as before — nothing shows the stop was deliberate.
    beat({"tailscaled": "active", "octo-forwarder": "inactive"})
    row = _source(analyst.get(URL).json(), "buoy:acme-corp")
    assert row["status"] == "degraded" and "Retired" not in (row["detail"] or "")


def test_a_security_tool_disabled_on_the_buoy_is_a_fault_not_retired(world, monkeypatch):
    """`systemctl disable --now wazuh-agent suricata` (T1562.001) on a buoy
    must never read as "retired": only a unit the OPERATOR retired
    server-side (OCTO_BUOY_RETIRED_UNITS, default octo-forwarder) is. Such a
    buoy is degraded and the row names the disabled units."""
    client = world["client"]

    def beat(services: dict) -> None:
        r = client.post(
            "/api/v1/buoy/heartbeat", json=_heartbeat_body("acme-corp", services=services),
            headers={"Authorization": f"Bearer {world['buoy_token']}"},
        )
        assert r.status_code == 200, r.text

    active = {"state": "active", "enabled": "enabled"}
    off = {"state": "inactive", "enabled": "disabled"}
    monkeypatch.delenv("OCTO_BUOY_RETIRED_UNITS", raising=False)
    beat({"tailscaled": active, "wazuh-agent": off,
          "suricata": {"state": "inactive", "enabled": "masked"}, "octo-forwarder": off})
    analyst = _as(world, "analyst")
    row = _source(analyst.get(URL).json(), "buoy:acme-corp")
    assert row["status"] == "degraded"
    assert "Retired (disabled on purpose): octo-forwarder." in row["detail"]
    assert ("Disabled on the buoy but not retired: suricata, wazuh-agent — if on purpose, "
            "add it to OCTO_BUOY_RETIRED_UNITS.") in row["detail"]
    # The operator retires opencanary for this bundle (the list replaces the
    # default): it is grey; octo-forwarder, no longer listed, is a fault.
    monkeypatch.setenv("OCTO_BUOY_RETIRED_UNITS", "opencanary")
    beat({"tailscaled": active, "suricata": active, "opencanary": off})
    row = _source(analyst.get(URL).json(), "buoy:acme-corp")
    assert (row["status"], row["detail"]) == (
        "ok", "Retired (disabled on purpose): opencanary.")
    beat({"tailscaled": active, "suricata": active, "octo-forwarder": off})
    assert _source(analyst.get(URL).json(), "buoy:acme-corp")["status"] == "degraded"
