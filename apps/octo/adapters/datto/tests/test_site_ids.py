"""The Datto site's own portal page (2026-10-08: "Datto RMM leads to the
homescreen"). The portal addresses a site as ``/site/<numeric id>/<name
slug>``; mappings hold the site UID. The inventory poller learns the MAPPED
sites' numeric ids from the account's site list — at most once a day, sooner
only for a newly mapped site, never on a page load — and keeps uid → id
(+ name) only; the link is rebuilt from the portal base, the digits and our
own slug.

The REAL DattoClient / InventoryPoller against the fake Datto transport —
only the socket is fake."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo.adapters.datto import site_ids
from apps.octo.adapters.datto.inventory import InventoryPoller
from apps.octo.adapters.datto.links import (
    SITE_SLUG_MAX,
    site_portal_id,
    site_portal_url,
    site_slug,
)
from apps.octo.adapters.datto.tests.fake_datto import CREDS, FakeDattoTransport, real_client
from apps.octo.client_provisioning import create_client
from apps.octo.entity import db as entity_db
from apps.octo.entity import switch
from apps.octo.entity.feeders.datto import DattoInventoryFeeder
from apps.octo.instances import create_instance, poller_state, tenant_map
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

BASE = "https://fixture.rmm.datto.com"
SITES_PATH = "/api/v2/account/sites"
T0 = datetime(2026, 10, 8, 14, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# The id, the slug, the link — pure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("site, expected", [
    ({"id": 1001}, "1001"),
    ({"id": "1001"}, "1001"),
    ({"id": 1001, "portalUrl": f"{BASE}/site/1001"}, "1001"),
    ({"id": 1001, "portalUrl": f"{BASE}/site/1001/example-site"}, "1001"),
    ({"portalUrl": f"{BASE}/site/1001/example-site"}, "1001"),     # no id: the URL's digits
    ({"id": 1001, "portalUrl": f"{BASE}/site/1002"}, None),        # they disagree: no guess
    ({"id": 1001, "portalUrl": "https://evil.example/site/9"}, "1001"),   # URL ignored
    ({"id": True}, None),
    ({"id": -1}, None),
    ({"id": 10 ** 12}, None),                                       # 13 digits
    ({"id": "10a"}, None),
    ({"id": " 1001"}, None),
    ({"id": "١٠"}, None),                                  # not ASCII digits
    ({"id": 41.0}, None),
    ({"id": None}, None),
    ({"portalUrl": "https://evil.example/site/1001"}, None),        # not under datto.com
    ({"portalUrl": "http://fixture.rmm.datto.com/site/1001"}, None),
    ({"portalUrl": f"{BASE}/site/1001?x=1"}, None),
    ({"portalUrl": f"{BASE}/site/1001#x"}, None),
    ({"portalUrl": "https://user@fixture.rmm.datto.com/site/1001"}, None),
    ({"portalUrl": "https://fixture.rmm.datto.com:8443/site/1001"}, None),
    ({"portalUrl": f"{BASE}/device/1001"}, None),
    ({"portalUrl": f"{BASE}/site/1001/a/b"}, None),
    ({"portalUrl": 1001}, None),
    ({}, None),
    ("1001", None),
    (None, None),
])
def test_the_numeric_id_of_a_site(site, expected):
    assert site_portal_id(site) == expected


@pytest.mark.parametrize("name, slug", [
    ("Example Site", "example-site"),
    ("  Example   Site  ", "example-site"),
    ("Café Zoë", "cafe-zoe"),
    ("Straße 9", "strasse-9"),
    ("Smith & Sons, LLC.", "smith-sons-llc"),
    ("Bob's Diner", "bobs-diner"),
    ("Bob’s Diner", "bobs-diner"),
    ("../../etc/passwd?x=1#y", "etc-passwd-x-1-y"),
    ("<script>alert(1)</script>", "script-alert-1-script"),
    ("Example Clinic\t#2", "example-clinic-2"),
    ("東京オフィス", ""),                   # nothing ascii left
    ("---", ""),
    ("", ""),
    (None, ""),
    (42, ""),
])
def test_the_name_slug(name, slug):
    assert site_slug(name) == slug


def test_the_slug_is_bounded_and_never_ends_in_a_hyphen():
    assert site_slug("a" * 200) == "a" * SITE_SLUG_MAX
    long = site_slug("ab " * 40)
    assert len(long) <= SITE_SLUG_MAX and not long.endswith("-")


@pytest.mark.parametrize("base, site_id, name, url", [
    (BASE, "1001", "Example Site", f"{BASE}/site/1001/example-site"),
    (BASE + "/", "1001", "Example Site", f"{BASE}/site/1001/example-site"),
    (BASE, "1001", "東京", f"{BASE}/site/1001"),             # no slug: the id alone
    (BASE, "1001", None, f"{BASE}/site/1001"),
    (BASE, "1001", "a/b?c#d@e", f"{BASE}/site/1001/a-b-c-d-e"),
    (BASE, "10a", "x", None),
    (BASE, "", "x", None),
    (BASE, None, "x", None),
    (BASE, 1001, "x", None),                                          # an int is not an id here
    (BASE, "../1", "x", None),
    (BASE, "1" * 13, "x", None),
    ("https://evil.example", "1001", "x", None),
    ("http://fixture.rmm.datto.com", "1001", "x", None),
    (f"{BASE}/path", "1001", "x", None),
    ("https://user@fixture.rmm.datto.com", "1001", "x", None),
    (None, "1001", "x", None),
])
def test_the_site_page_address(base, site_id, name, url):
    assert site_portal_url(base, site_id, name) == url


def test_only_mapped_sites_and_only_their_id_and_name_are_kept():
    sites = [
        {"uid": "s-1", "id": 1001, "name": "Example Site", "portalUrl": f"{BASE}/site/1001",
         "notes": "FIXTURE-NOTES", "proxy": {"password": "FIXTURE-PROXY"},
         "autotaskCompanyId": "9", "devicesStatus": {"numberOfDevices": 3}},
        {"uid": "s-2", "id": "bad", "name": "Bad id"},
        {"uid": "s-3", "id": 1003, "name": "Not mapped"},
        {"uid": "s-4", "id": 1004, "name": "Line\nbreak\x00 " + "x" * 300},
        {"uid": "s-5", "id": 1005},
        {"uid": "s-1", "id": 9999, "name": "a duplicate uid"},
        "junk", None, {"id": 1}, {"uid": 7, "id": 2},
    ]
    found = site_ids.extract(sites, ["s-1", "s-2", "s-4", "s-5", "s-9"])
    assert set(found) == {"s-1", "s-4", "s-5"}
    assert found["s-1"] == {"id": "1001", "name": "Example Site"}
    assert found["s-5"] == {"id": "1005"}
    assert found["s-4"]["name"].startswith("Line break ")
    assert len(found["s-4"]["name"]) == site_ids.NAME_MAX
    blob = json.dumps(found)
    for never in ("FIXTURE-NOTES", "FIXTURE-PROXY", "Not mapped", "portalUrl", "9999"):
        assert never not in blob


# ---------------------------------------------------------------------------
# The store (adapter_poller_state; no migration)
# ---------------------------------------------------------------------------

def test_the_store_round_trips_mapped_sites_only(bedrock_root):  # noqa: F811
    assert site_ids.known(1) == {} and site_ids.load(1) is None
    assert site_ids.save(1, mapped=["s-1", "s-2"], now=T0, found={
        "s-1": {"id": "1001", "name": "Example Site"}, "s-3": {"id": "1003"}})
    assert site_ids.known(1) == {"s-1": {"id": "1001", "name": "Example Site"}}
    state = site_ids.load(1)
    assert state["mapped"] == ["s-1", "s-2"] and state["at"] == "2026-10-08T14:00:00.000Z"
    assert site_ids.known(2) == {}                                    # another instance


def test_what_is_read_back_is_validated_again(bedrock_root):  # noqa: F811
    poller_state.save(1, site_ids.STATE_KEY, {
        "at": "2026-10-08T14:00:00.000Z", "mapped": ["a", "b", 3],
        "sites": {"a": {"id": "../1"}, "b": {"id": "12", "name": "x\x00y"}, "c": "nope",
                  "d": {"id": 12}, "e": {"id": "1" * 13}, "": {"id": "1"}}})
    assert site_ids.known(1) == {"b": {"id": "12", "name": "x y"}}
    assert site_ids.load(1)["mapped"] == ["a", "b"]
    for broken in ({"at": "yesterday", "mapped": [], "sites": {}},
                   {"at": "2026-10-08T14:00:00.000Z", "mapped": "a", "sites": {}},
                   ["not", "a", "dict"]):
        poller_state.save(1, site_ids.STATE_KEY, broken)
        assert site_ids.load(1) is None and site_ids.known(1) == {}


def test_when_a_read_is_due():
    state = {"at": "2026-10-08T14:00:00.000Z", "mapped": ["a", "b"], "sites": {}}
    assert site_ids.due(None, ["a"], T0) is True                      # none stored
    assert site_ids.due(state, ["a", "b"], T0 + timedelta(hours=23)) is False
    assert site_ids.due(state, ["a"], T0 + timedelta(hours=1)) is False    # a mapping removed
    assert site_ids.due(state, ["a", "b", "c"], T0 + timedelta(hours=1)) is True   # added
    assert site_ids.due(state, ["a", "b"], T0 + timedelta(days=1)) is True     # a day old
    assert site_ids.due(state, [], T0 + timedelta(days=9)) is False   # nothing mapped
    assert site_ids.due({**state, "at": "garbage"}, ["a"], T0) is True


def test_a_listing_that_stopped_early_keeps_what_it_did_not_reach(bedrock_root):  # noqa: F811
    site_ids.save(1, mapped=["a", "b"], now=T0,
                  found={"a": {"id": "1"}, "b": {"id": "2"}})
    previous = site_ids.load(1)
    site_ids.save(1, mapped=["a", "b"], now=T0 + timedelta(days=1), found={"a": {"id": "11"}},
                  previous=previous, complete=False)
    assert site_ids.known(1) == {"a": {"id": "11"}, "b": {"id": "2"}}
    # A complete listing that no longer has a site: gone.
    site_ids.save(1, mapped=["a", "b"], now=T0 + timedelta(days=2), found={"a": {"id": "11"}},
                  previous=site_ids.load(1), complete=True)
    assert site_ids.known(1) == {"a": {"id": "11"}}


# ---------------------------------------------------------------------------
# The inventory poller: when the site list is read
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t


@pytest.fixture
def world(bedrock_root):  # noqa: F811
    entity_db.reset_schema_cache()
    switch.reset()
    transport = FakeDattoTransport()
    transport.sites = [
        {"uid": "site-a", "id": 1001, "name": "Example Acme Main", "notes": "FIXTURE-NOTES"},
        {"uid": "site-b", "id": "1002", "name": "Example Bakery"},
        {"uid": "site-c", "id": 1003, "name": "Example Annex"},
        {"uid": "site-x", "id": 1099, "name": "Somebody else"},
    ]
    for uid in ("site-a", "site-b", "site-c"):
        transport.site_devices[uid] = []
    rec = create_instance(vendor_slug="datto", display_name="Datto RMM",
                          credentials_dict=dict(CREDS), instance_config={})
    create_client("acme-corp", "Acme Corp", kind="client")
    create_client("example-bakery", "Example Bakery", kind="client")
    mappings = [TenantMapping("site-a", "acme-corp", "Site A", "manual"),
                TenantMapping("site-b", "example-bakery", "Bakery", "manual")]
    tenant_map.set_mappings(rec.id, mappings)
    clock = _Clock()
    poller = InventoryPoller(client=real_client(transport), instance_id=rec.id, spacing_sec=0,
                             now=clock, consumer=DattoInventoryFeeder())
    yield transport, poller, clock, rec, mappings
    switch.reset()


def _round(poller, clock, minutes: float = 31) -> dict:
    clock.t += timedelta(minutes=minutes)
    return poller.run_once()


def test_the_site_list_is_read_once_a_day_and_keeps_the_mapped_sites_only(world):
    transport, poller, clock, rec, mappings = world
    out = poller.run_once()
    assert transport.count(SITES_PATH) == 1
    assert out["site_ids"] == {"mapped": 2, "found": 2}
    # After the round's device lists, before anything else.
    paths = [p for _m, p in transport.calls if p.startswith("/api/v2/")]
    assert paths.index(SITES_PATH) > max(i for i, p in enumerate(paths) if "/devices" in p)
    assert site_ids.known(rec.id) == {"site-a": {"id": "1001", "name": "Example Acme Main"},
                                      "site-b": {"id": "1002", "name": "Example Bakery"}}
    stored = json.dumps(poller_state.load(rec.id, site_ids.STATE_KEY))
    assert "Somebody else" not in stored and "1099" not in stored
    assert "FIXTURE-NOTES" not in stored
    # The same day: never again (the rounds go on every 30 minutes).
    for _ in range(5):
        assert "site_ids" not in _round(poller, clock)
    assert transport.count(SITES_PATH) == 1
    # A day later: once more.
    clock.t = T0 + timedelta(days=1, minutes=1)
    poller.run_once()
    assert transport.count(SITES_PATH) == 2


def test_a_newly_mapped_site_is_looked_up_at_the_next_round(world):
    transport, poller, clock, rec, mappings = world
    poller.run_once()
    tenant_map.set_mappings(rec.id, mappings + [
        TenantMapping("site-c", "acme-corp", "Annex", "manual")])
    out = _round(poller, clock)
    assert transport.count(SITES_PATH) == 2 and out["site_ids"] == {"mapped": 3, "found": 3}
    assert site_ids.known(rec.id)["site-c"] == {"id": "1003", "name": "Example Annex"}
    # A mapping REMOVED: no read (the fleet ignores what is not mapped).
    tenant_map.set_mappings(rec.id, mappings[:1])
    _round(poller, clock)
    assert transport.count(SITES_PATH) == 2


def test_a_failed_read_is_not_retried_the_same_day(world):
    transport, poller, clock, rec, _mappings = world
    transport.fail_sites_from_page, transport.fail_sites_status = 0, 500
    out = poller.run_once()
    assert out["site_ids"] == {"error": "DattoClientError"}
    assert site_ids.known(rec.id) == {} and "audits" in out          # the round goes on
    for _ in range(3):
        _round(poller, clock)
    assert transport.count(SITES_PATH) == 1
    transport.fail_sites_from_page = None
    clock.t = T0 + timedelta(days=1, minutes=1)
    poller.run_once()
    assert transport.count(SITES_PATH) == 2 and len(site_ids.known(rec.id)) == 2


def test_a_429_on_the_site_list_holds_the_inventory(world):
    transport, poller, clock, rec, _mappings = world
    transport.fail_sites_from_page, transport.fail_sites_status = 0, 429
    out = poller.run_once()
    assert out["site_ids"] == {"error": "DattoThrottledError"}
    assert out.get("held_until") and "audits" not in out              # nothing after a 429
    before = len(transport.calls)
    _round(poller, clock, minutes=5)
    assert len(transport.calls) == before                             # held: no call at all


def test_no_instance_id_no_read(world):
    transport, _poller, clock, _rec, _mappings = world
    poller = InventoryPoller(client=real_client(transport), instance_id=None, spacing_sec=0,
                             now=clock, consumer=DattoInventoryFeeder())
    poller.run_once()
    assert transport.count(SITES_PATH) == 0
