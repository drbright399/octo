"""NextDNS through the real HTTP routes, real sign-in, the REAL adapter /
client / limiter — only the NextDNS socket is fake (fake_nextdns.py).

Pinned:
  * the mapping panel (GET/PUT /integrations/nextdns/{id}/profiles): admin+
    only, local state only (never a NextDNS call), name-match suggestions,
    many profiles → one tenant, the ignore choice, refusals, audit rows;
  * the card (/integrations): profile counts, the no-deadline wait;
  * source health: per-profile protection (scoped), throttled shown as such;
  * the alerts feed: the title, the masked detail, the live "seen N times".
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import paths
from apps.octo.adapters.nextdns import limiter as lim
from apps.octo.adapters.nextdns.tests.fake_nextdns import (
    API_KEY,
    CREDS,
    FakeClock,
    FakeNextDNSTransport,
    block_line,
    fake_limiter,
    nextdns_adapter_class,
)
from apps.octo.client_provisioning import create_client
from apps.octo.instances import ignored_tenants, tenant_map, vendor_contact, vendor_tenants
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_dashboard_throughput import _login

PW = "pw1234567890"
SEARCH = "/api/v1/search/nextdns"          # (the search tests import it)
A, B = "acme-corp", "example-bakery"


@pytest.fixture
def nd(auth_client, auth_data_root, monkeypatch, tmp_path):
    """The app with a registry holding the fake-wired NextDNS adapter, a
    saved + started instance, two tenants. The fake clock runs at real time
    (the search route's window is the wall clock)."""
    from apps.octo.credentials import ensure_key_file
    from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
    from apps.octo.instances import InstanceManager, create_instance

    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(tmp_path / "cred-key.env"))
    ensure_key_file()
    lim.reset_limiters()
    vendor_tenants.reset()
    vendor_contact.reset()
    clock = FakeClock(datetime.now(timezone.utc))
    transport = FakeNextDNSTransport(clock)
    limiter = fake_limiter(clock)
    registry = AdapterRegistry(backend=InMemoryRegistryBackend())
    registry.register_adapter_class(nextdns_adapter_class(transport, clock))
    app = auth_client.app
    app.state.adapter_registry = registry
    app.state.instance_manager = InstanceManager(adapter_registry=registry)
    create_client(A, "Acme Corp")
    create_client(B, "Example Bakery")
    record = create_instance(vendor_slug="nextdns", display_name="NextDNS",
                             credentials_dict=dict(CREDS), instance_config={})
    app.state.instance_manager.start_instance(record)
    yield auth_client, transport, clock, limiter, record
    app.state.instance_manager.stop_all_running()
    lim.reset_limiters()
    vendor_tenants.reset()
    vendor_contact.reset()


def _op(client, name: str, role: str, scope=None) -> dict:
    op = client.provision_operator(name, PW, role=role, athena_role=role, scope_slugs=scope)
    _login(client, op)
    return op


def _audit(action: str) -> list[dict]:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return [json.loads(r[0]) for r in conn.execute(
            "SELECT after_state FROM audit_log WHERE action = ? ORDER BY id", (action,))]
    finally:
        conn.close()


def _profiles_url(record) -> str:
    return f"/api/v1/integrations/nextdns/{record.id}/profiles"


# ---------------------------------------------------------------------------
# The mapping panel
# ---------------------------------------------------------------------------

def test_the_panel_is_admin_only_and_never_calls_nextdns(nd):
    client, transport, _clock, _lim, record = nd
    for role in ("viewer", "analyst"):
        _op(client, f"u-{role}", role)
        assert client.get(_profiles_url(record)).status_code == 403
        assert client.put(_profiles_url(record), json={}).status_code == 403
    _op(client, "admin1", "admin")
    r = client.get(_profiles_url(record))
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert r.json()["discovered"] is False and r.json()["profiles"] == []
    assert transport.calls == []


def test_discovery_is_one_call_then_suggestions_and_counts(nd):
    client, transport, _clock, _lim, record = nd
    _op(client, "admin1", "admin")
    r = client.post(f"/api/v1/admin/adapters/instances/{record.id}/vendor-tenants")
    assert r.status_code == 200, r.text
    assert transport.paths() == ["/profiles"]
    body = client.get(_profiles_url(record)).json()
    assert transport.paths() == ["/profiles"]                  # the panel never calls
    by_id = {p["profile_id"]: p for p in body["profiles"]}
    assert by_id["abc123"]["suggestion"] == {
        "tenant_slug": A, "tenant_name": "Acme Corp", "rule": "name-prefix", "bulk": True}
    assert by_id["def456"]["suggestion"]["rule"] == "same-name"
    assert by_id["tst001"]["suggestion"] is None and by_id["per001"]["suggestion"] is None
    assert body["counts"] == {"known": 5, "mapped": 0, "ignored": 0, "unmapped": 5,
                              "active": 0, "pending": 0, "lapsed": 0, "missing": 0}


def test_save_maps_many_profiles_to_one_tenant_and_ignores_others(nd):
    client, _t, _clock, _lim, record = nd
    _op(client, "admin1", "admin")
    client.post(f"/api/v1/admin/adapters/instances/{record.id}/vendor-tenants")
    r = client.put(_profiles_url(record), json={
        "mappings": [
            # A suggestion the operator confirmed on its row is THEIR decision.
            {"profile_id": "abc123", "tenant_slug": A, "match_source": "manual"},
            {"profile_id": "abc124", "tenant_slug": A},
        ],
        "ignored": ["tst001", "per001"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"]["mapped"] == 2 and body["counts"]["ignored"] == 2
    assert body["counts"]["unmapped"] == 1
    assert [p["profile_id"] for p in body["profiles"]][0] == "def456"   # attention first
    stored = {m.vendor_tenant_id: (m.octo_client_slug, m.vendor_tenant_label, m.match_source)
              for m in tenant_map.get_mappings(record.id)}
    assert stored == {"abc123": (A, "Acme Corp Office", "manual"),
                      "abc124": (A, "Acme Corp Warehouse", "manual")}
    assert ignored_tenants.ignored_ids(record.id) == {"tst001", "per001"}
    [replace] = _audit("adapter_tenant_map_replace")
    assert replace["mappings"] == {"abc123": A, "abc124": A}
    [ignore] = _audit("adapter_vendor_tenants_ignore")
    assert ignore["ignored"] == ["per001", "tst001"]
    # Mapping an ignored profile later just moves it.
    r = client.put(_profiles_url(record), json={
        "mappings": [{"profile_id": "tst001", "tenant_slug": B}], "ignored": ["per001"]})
    assert r.status_code == 200
    assert ignored_tenants.ignored_ids(record.id) == {"per001"}


def test_a_name_match_is_never_saved_by_itself_same_name(nd):
    """The same-name rule (2026-10-01): PUT refuses a NEW 'auto-name'
    mapping — a bulk "Use N suggestions" can no longer link profiles by name
    silently. A stored one (from before) may only come back UNCHANGED, and
    stays unconfirmed until the operator confirms its row ('manual')."""
    client, _t, _clock, _lim, record = nd
    _op(client, "admin1", "admin")
    client.post(f"/api/v1/admin/adapters/instances/{record.id}/vendor-tenants")
    r = client.put(_profiles_url(record), json={"mappings": [
        {"profile_id": "def456", "tenant_slug": B, "match_source": "auto-name"}]})
    assert r.status_code == 422 and "never stores a mapping made from a name" in r.text
    assert tenant_map.get_mappings(record.id) == []
    assert _audit("adapter_tenant_map_replace") == []
    # A pre-fix bulk accept left one behind:
    tenant_map.set_mappings(record.id, [TenantMapping("def456", B, "Example Bakery", "auto-name")])
    by_id = {p["profile_id"]: p for p in client.get(_profiles_url(record)).json()["profiles"]}
    assert by_id["def456"]["match_source"] == "auto-name"
    # …sent back unchanged it stays as it is (still unconfirmed)…
    r = client.put(_profiles_url(record), json={"mappings": [
        {"profile_id": "def456", "tenant_slug": B, "match_source": "auto-name"},
        {"profile_id": "abc124", "tenant_slug": A}]})
    assert r.status_code == 200, r.text
    assert {m.vendor_tenant_id: m.match_source for m in tenant_map.get_mappings(record.id)} == {
        "def456": "auto-name", "abc124": "manual"}
    # …re-pointed by name it is refused…
    r = client.put(_profiles_url(record), json={"mappings": [
        {"profile_id": "def456", "tenant_slug": A, "match_source": "auto-name"}]})
    assert r.status_code == 422
    # …and confirmed on its row it is the operator's decision.
    r = client.put(_profiles_url(record), json={"mappings": [
        {"profile_id": "def456", "tenant_slug": B, "match_source": "manual"},
        {"profile_id": "abc124", "tenant_slug": A}]})
    assert r.status_code == 200
    assert {m.vendor_tenant_id: m.match_source for m in tenant_map.get_mappings(record.id)} == {
        "def456": "manual", "abc124": "manual"}


def test_suggestions_keep_legal_suffixes_same_name():
    """"Acme Pharmacy, Inc." is not "Acme Pharmacy LLC": a profile is never
    suggested for a client whose name differs only by its legal suffix —
    neither as the same name nor as a leading part."""
    from apps.octo.api.routers.nextdns import suggest

    clients = {"acme-pharmacy": ("Acme Pharmacy, Inc.", "active")}
    assert suggest("Acme Pharmacy LLC", clients) is None
    assert suggest("Acme Pharmacy LLC - Main St", clients) is None
    assert suggest("ACME PHARMACY INC", clients) == ("acme-pharmacy", "Acme Pharmacy, Inc.", "same-name")
    assert suggest("Acme Pharmacy Inc Pharmacy", clients) == (
        "acme-pharmacy", "Acme Pharmacy, Inc.", "name-prefix")
    # Two clients with the same name: no guess at all.
    clients["acme-pharmacy-2"] = ("Acme Pharmacy Inc", "active")
    assert suggest("Acme Pharmacy, Inc.", clients) is None


@pytest.mark.parametrize("body,needle", [
    ({"mappings": [{"profile_id": "abc123", "tenant_slug": A}], "ignored": ["abc123"]},
     "both mapped and ignored"),
    ({"mappings": [{"profile_id": "../x", "tenant_slug": A}]}, "not a NextDNS profile id"),
    ({"mappings": [{"profile_id": "abc123", "tenant_slug": "no-such"}]}, "does not exist"),
    ({"mappings": [{"profile_id": "abc123", "tenant_slug": A},
                   {"profile_id": "abc123", "tenant_slug": B}]}, "listed twice"),
    ({"ignored": ["a b"]}, "not a NextDNS profile id"),
])
def test_save_refuses_what_can_never_work(nd, body, needle):
    client, _t, _clock, _lim, record = nd
    _op(client, "admin1", "admin")
    r = client.put(_profiles_url(record), json=body)
    assert r.status_code == 422 and needle in r.json()["message"], r.text
    assert tenant_map.get_mappings(record.id) == []
    assert _audit("adapter_vendor_tenants_ignore") == []


def test_the_card_counts_and_the_wait_without_deadline(nd):
    client, _t, _clock, _lim, record = nd
    _op(client, "admin1", "admin")
    card = client.get("/api/v1/integrations").json()["instances"]["nextdns"]
    assert card["waiting_for_tenant_mapping"] is True
    assert card["first_import_waiting_until"] is None
    assert card["profiles"]["mapped"] == 0
    adapter = client.app.state.instance_manager.running_adapter(record.id)
    adapter.poller.run_cycle()                       # the poller's own discovery
    client.put(_profiles_url(record), json={
        "mappings": [{"profile_id": "abc123", "tenant_slug": A}], "ignored": ["tst001"]})
    card = client.get("/api/v1/integrations").json()["instances"]["nextdns"]
    assert card["waiting_for_tenant_mapping"] is False
    assert (card["profiles"]["known"], card["profiles"]["mapped"], card["profiles"]["ignored"],
            card["profiles"]["unmapped"]) == (5, 1, 1, 3)
    assert API_KEY not in json.dumps(card)


# ---------------------------------------------------------------------------
# Source health
# ---------------------------------------------------------------------------

def test_source_health_shows_protection_scoped_and_throttled(nd):
    client, transport, clock, limiter, record = nd
    transport.set_rate("abc123")
    tenant_map.set_mappings(record.id, [
        TenantMapping("abc123", A, "Acme Corp Office", "manual"),
        TenantMapping("def456", B, "Example Bakery", "manual"),
    ])
    adapter = client.app.state.instance_manager.running_adapter(record.id)
    adapter.poller.run_cycle()
    _op(client, "carol", "analyst", [A])
    [row] = [s for s in client.get("/api/v1/dashboard/source-health").json()["sources"]
             if s["vendor"] == "nextdns"]
    prot = row["protection"]
    assert [p["profile_id"] for p in prot["profiles"]] == ["abc123"]   # B is out of scope
    assert prot["active"] == 1 and row["throttled"] is False
    limiter.refusal(403)
    adapter.poller._throttled_until = clock.now() + timedelta(seconds=30)
    [row] = [s for s in client.get("/api/v1/dashboard/source-health").json()["sources"]
             if s["vendor"] == "nextdns"]
    assert row["throttled"] is True and "not a failure" in row["detail"]
    assert row["status"] != "down"


def test_the_alerts_feed_shows_the_title_masked_detail_and_live_count(nd):
    client, transport, clock, _limiter, record = nd
    transport.set_rate("abc123")
    # Three hits within one minute five minutes ago: one clock hour, one bucket.
    base = (clock.now() - timedelta(minutes=5)).replace(second=0, microsecond=0)
    transport.add_lines("abc123", *[
        block_line(base + timedelta(seconds=i), domain="c2.bad-example.test")
        for i in range(3)
    ])
    tenant_map.set_mappings(record.id, [TenantMapping("abc123", A, "Acme Corp Office", "manual")])
    client.app.state.instance_manager.running_adapter(record.id).poller.run_cycle()
    _op(client, "carol", "analyst")
    items = client.get("/api/v1/dashboard/recent-events",
                       params={"min_severity": "info"}).json()["items"]
    [row] = [i for i in items if i["source"] == "nextdns"]
    assert row["title"] == "NextDNS blocked a threat-intelligence domain — alice-laptop"
    assert "c2.bad-example.test" not in row["title"] + row["summary"]
    assert "Seen 3 times in the hour" in row["summary"]
    assert row["vendor_links"][0]["url"] == "https://my.nextdns.io/abc123/logs"


# ---------------------------------------------------------------------------
# Suggestions: the platform's two-word floor; personal / test names
# ---------------------------------------------------------------------------

def test_a_one_word_client_never_claims_every_profile_that_starts_with_it():
    from apps.octo.api.routers.nextdns import suggest

    clients = {"globex": ("Globex", "active"), "acme-corp": ("Acme Corp", "active")}
    assert suggest("Globex Home", clients) is None
    assert suggest("Globex Personal Test", clients) is None
    assert suggest("Globex", clients) == ("globex", "Globex", "same-name")
    assert suggest("Acme Corp Office", clients) == ("acme-corp", "Acme Corp", "name-prefix")
    assert suggest("ACME CORP - Warehouse", clients) == ("acme-corp", "Acme Corp", "name-prefix")
    from apps.octo.instances.tenant_lifecycle import DUPLICATE_MIN_PREFIX_WORDS
    assert DUPLICATE_MIN_PREFIX_WORDS == 2


def test_personal_and_test_profiles_are_never_bulk_accepted(nd):
    client, transport, _clock, _lim, record = nd
    transport.profiles.append(
        {"id": "abc125", "name": "Acme Corp Home", "fingerprint": "fp0006", "role": "owner"})
    transport.profiles.append(
        {"id": "abc126", "name": "Acme Corp Test", "fingerprint": "fp0007", "role": "owner"})
    _op(client, "admin1", "admin")
    client.post(f"/api/v1/admin/adapters/instances/{record.id}/vendor-tenants")
    by_id = {p["profile_id"]: p for p in client.get(_profiles_url(record)).json()["profiles"]}
    assert by_id["abc123"]["suggestion"]["bulk"] is True
    for pid in ("abc125", "abc126"):
        assert by_id[pid]["suggestion"]["tenant_slug"] == A      # offered on the row…
        assert by_id[pid]["suggestion"]["bulk"] is False         # …never in "Use all"


# ---------------------------------------------------------------------------
# A missing profile is visible in the panel and in source health
# ---------------------------------------------------------------------------

def test_a_missing_profile_is_shown_and_degrades_its_tenant(nd):
    client, transport, clock, _limiter, record = nd
    transport.set_rate("abc123")
    transport.set_rate("def456")
    tenant_map.set_mappings(record.id, [
        TenantMapping("abc123", A, "Acme Corp Office", "manual"),
        TenantMapping("def456", B, "Example Bakery", "manual"),
    ])
    poller = client.app.state.instance_manager.running_adapter(record.id).poller
    poller.cycle_with_reporting()
    transport.profile_status["abc123"] = 404            # deleted: gone from the list too
    transport.profiles = [p for p in transport.profiles if p["id"] != "abc123"]
    for _ in range(2):
        clock.advance(600)
        poller.cycle_with_reporting()
    _op(client, "admin1", "admin")
    body = client.get(_profiles_url(record)).json()
    [p] = [x for x in body["profiles"] if x["profile_id"] == "abc123"]
    assert p["missing"] is True and "HTTP 404" in p["problem"]
    assert body["counts"]["missing"] == 1
    card = client.get("/api/v1/integrations").json()["instances"]["nextdns"]["profiles"]
    assert card["missing"] == 1
    [row] = [s for s in client.get("/api/v1/dashboard/source-health").json()["sources"]
             if s["vendor"] == "nextdns"]
    assert row["status"] == "degraded"
    assert "no longer shows 1 mapped profile" in row["detail"]
    [prof] = [x for x in row["protection"]["profiles"] if x["profile_id"] == "abc123"]
    assert prof["missing"] is True
    tenants = {t["slug"]: t["state"] for t in
               client.get("/api/v1/dashboard/source-health").json()["tenants"]}
    assert tenants.get(A) == "degraded" and tenants.get(B) != "degraded"
