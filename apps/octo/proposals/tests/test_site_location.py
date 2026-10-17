"""Autotask addresses → site-location proposals, over a REAL registry with
Autotask (and the Fleet) faked: which site each address is for, the warnings
(a shared address never merges two clients), the refused-CompanyLocations
fallback, supersede / no re-propose, the lookup's warnings and what a
confirm writes. Made-up companies, Example streets, fictional towns."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from apps.octo import paths
from apps.octo.adapters.autotask.client import AutotaskClientError, AutotaskRefusedError
from apps.octo.client_provisioning import create_client
from apps.octo.fleet import build, geocode, locations
from apps.octo.proposals import site_location as sl
from apps.octo.proposals import store
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401

INSTANCE = 7
BAKERY, BOOKS, PHARMA, CITY, DENTAL = ("example-bakery", "example-books", "example-pharmacy",
                                       "example-city", "example-dental")


def ukey(n: int) -> str:
    return build.site_key("unifi", f"host{n}/site{n}")


@dataclass
class Entry:
    """The bits of a `build.SiteEntry` the proposer reads."""
    key: str
    tenant_slug: str
    kind: str
    name: str
    console_name: str = ""
    unifi: Optional[dict[str, Any]] = None
    location: Optional[locations.Location] = None


def site(n: int, slug: str, name: str, *, console: Optional[tuple[float, float]] = None,
         pin: Optional[locations.Location] = None) -> Entry:
    loc = locations.Location(console[0], console[1], "console", "unifi") if console else None
    return Entry(ukey(n), slug, "unifi", name, f"console-{n}",
                 {"console_location": loc}, pin or loc)


def company(cid: int, name: str, line1: str, city: str = "Exampleton", state: str = "IL",
            zip_: str = "00001", **extra: Any) -> dict[str, Any]:
    return {"id": cid, "companyName": name, "isActive": True, "address1": line1, "address2": "",
            "city": city, "state": state, "postalCode": zip_, "countryID": 237, **extra}


def location(lid: int, cid: int, name: str, line1: str, city: str = "Exampleton",
             state: str = "IL", zip_: str = "00001", **extra: Any) -> dict[str, Any]:
    return {"id": lid, "companyID": cid, "name": name, "isActive": True, "isPrimary": False,
            "address1": line1, "address2": "", "city": city, "state": state,
            "postalCode": zip_, "countryID": 237, **extra}


@dataclass
class FakeAutotask:
    companies: list[dict[str, Any]] = field(default_factory=list)
    locations: list[dict[str, Any]] = field(default_factory=list)
    locations_error: Optional[Exception] = None
    calls: list[tuple[str, list[int]]] = field(default_factory=list)

    def query_companies(self, ids, *, active_only=True):
        self.calls.append(("Companies", list(ids)))
        return [c for c in self.companies if c["id"] in ids and c.get("isActive") is not False]

    def query_company_locations(self, ids, *, active_only=True):
        self.calls.append(("CompanyLocations", list(ids)))
        if self.locations_error is not None:
            raise self.locations_error
        return [x for x in self.locations if x["companyID"] in ids
                and x.get("isActive") is not False]


@pytest.fixture
def reg(bedrock_root):  # noqa: F811
    for slug, name in ((BAKERY, "Example Bakery"), (BOOKS, "Example Books"),
                       (PHARMA, "Example Pharmacy"), (CITY, "City of Example"),
                       (DENTAL, "Example Dental")):
        create_client(slug, name, kind="client")
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.executemany(
            "INSERT INTO autotask_tenant_company_map (adapter_instance_id, tenant_slug, "
            "autotask_company_id) VALUES (?, ?, ?)",
            [(INSTANCE, BAKERY, 101), (INSTANCE, BOOKS, 102), (INSTANCE, PHARMA, 500),
             (INSTANCE, CITY, 600), (INSTANCE, DENTAL, 700)])
        conn.commit()
    finally:
        conn.close()
    yield


FLEET = [
    site(1, BAKERY, "Bakery main", console=(41.26, -100.75)),
    site(2, BOOKS, "Books main", console=(41.26, -100.75)),
    site(3, PHARMA, "Example Pharmacy Northside"),
    site(4, PHARMA, "Example Pharmacy Riverton"),
    site(5, CITY, "City Hall"),
    site(6, CITY, "Public Works"),
]


def _open(slug: Optional[str] = None) -> list[store.Proposal]:
    return store.list_proposals(sl.KIND, statuses=(store.OPEN,),
                                tenants=[slug] if slug else None)


def _flags(p: store.Proposal) -> dict[str, dict[str, Any]]:
    return {f["code"]: f for f in p.flags}


def _client() -> FakeAutotask:
    return FakeAutotask(
        companies=[company(101, "Example Bakery", "300 W 5th St"),
                   company(102, "Example Books", "300 W. 5th Street", zip_=""),
                   company(500, "Example Pharmacy", "1 Example Plaza", city="Northside"),
                   company(600, "City of Example", "100 Example Ave"),
                   company(700, "Example Dental", "700 Example Ln. Suite 400", state="Texas",
                           zip_="75001")],
        locations=[location(11, 500, "Example Pharmacy - Riverton", "9 River Rd",
                            city="Riverton"),
                   location(12, 500, "Example Pharmacy Northside", "1 Example Plaza",
                            city="Northside", isPrimary=True),
                   location(13, 600, "Public Works", "200 Example Ave")])


def test_the_refresh_reads_only_mapped_active_companies_and_proposes(reg):
    client = _client()
    client.companies.append(company(999, "Unmapped Co", "5 Nowhere Rd"))
    summary = sl.refresh(client, INSTANCE, fleet=FLEET)
    assert client.calls[0] == ("Companies", [101, 102, 500, 600, 700])
    assert client.calls[1] == ("CompanyLocations", [101, 102, 500, 600, 700])
    assert summary["locations"] == "read" and summary["companies_read"] == 5
    assert summary["created"] == 7 and summary["skipped_non_us"] == 0
    assert sl.last_refresh(INSTANCE)["created"] == 7          # kept for the panel
    assert len(_open()) == 7


def test_one_address_two_businesses_is_two_proposals_both_flagged(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (a,) = _open(BAKERY)
    (b,) = _open(BOOKS)
    assert a.target_key == ukey(1) and b.target_key == ukey(2)     # never merged
    assert _flags(a)["shared_address"]["tenants"] == [BOOKS]
    assert _flags(b)["shared_address"]["tenants"] == [BAKERY]
    assert _flags(b)["incomplete"]["missing"] == ["zip"]
    assert "incomplete" not in _flags(a)


def test_a_multi_site_client_matches_names_conservatively(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    pharm = {p.source_ref: p for p in _open(PHARMA)}
    # The company address and its primary location are ONE candidate (the
    # company record), whose names now include the location's.
    assert set(pharm) == {"company:500", "location:11"}
    assert pharm["company:500"].payload["names"] == ["Example Pharmacy",
                                                     "Example Pharmacy Northside"]
    assert pharm["company:500"].target_key == ukey(3)
    assert pharm["company:500"].payload["match"]["site"] == "Example Pharmacy Northside"
    assert pharm["location:11"].target_key == ukey(4)                # Riverton
    city = {p.source_ref: p for p in _open(CITY)}
    assert city["company:600"].target_key is None                   # "pick a site"
    assert city["company:600"].payload["target_mode"] == "pick"
    assert city["location:13"].target_key == ukey(6)                 # the public works site


def test_single_site_and_no_site_clients(reg):
    fleet = FLEET + [site(7, DENTAL, "Default")]
    client = _client()
    client.locations.append(location(14, 700, "Annex", "800 Example Ln", state="TX",
                                     zip_="75001"))
    sl.refresh(client, INSTANCE, fleet=fleet)
    dental = _open(DENTAL)
    assert {p.target_key for p in dental} == {ukey(7)}               # the only site
    assert all(_flags(p)["several_addresses"]["count"] == 2 for p in dental)
    # Without any UniFi site: the client's own tenant-level entry.
    store_reset()
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (only,) = _open(DENTAL)
    assert only.target_key == sl.tenant_key(DENTAL) and only.payload["target_mode"] == "tenant"
    assert "several_addresses" not in _flags(only)


def store_reset() -> None:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute("DELETE FROM proposals")
        conn.commit()
    finally:
        conn.close()


def test_the_suite_stays_in_the_label_never_in_the_query(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(DENTAL)
    assert p.payload["query"] == "700 Example Ln., Exampleton, TX 75001"
    assert p.payload["label"] == "700 Example Ln. Suite 400, Exampleton, TX 75001"
    assert p.payload["address"]["unit"] == "Suite 400"


def test_outside_the_us_is_skipped_and_counted(reg):
    client = _client()
    client.companies[-1]["countryID"] = 75
    summary = sl.refresh(client, INSTANCE, fleet=FLEET)
    assert summary["skipped_non_us"] == 1 and summary["skipped_tenants"] == [DENTAL]
    assert _open(DENTAL) == []


def test_refused_company_locations_fall_back_to_the_company_address(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert {p.source_ref for p in _open(CITY)} == {"company:600", "location:13"}
    client = _client()
    client.locations_error = AutotaskRefusedError("CompanyLocations cannot be read", status=403)
    summary = sl.refresh(client, INSTANCE, fleet=FLEET)
    assert summary["locations"] == "refused" and summary["locations_read"] == 0
    # The location proposals are NOT swept: they were not read this time.
    assert {p.source_ref for p in _open(CITY)} == {"company:600", "location:13"}
    client.locations_error = AutotaskClientError("CompanyLocations/query HTTP 503", status=503)
    assert sl.refresh(client, INSTANCE, fleet=FLEET)["locations"] == "unavailable"
    assert len(_open(CITY)) == 2


def test_a_rejection_is_not_reproposed_until_the_source_changes(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)
    sl.reject(p, actor=1, reason="not this client")
    summary = sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert summary["created"] == 0 and summary["kept_rejected"] == 1
    assert _open(BAKERY) == []
    # A cosmetic edit is the same data …
    client = _client()
    client.companies[0]["address1"] = "300 West 5th Street"
    assert sl.refresh(client, INSTANCE, fleet=FLEET)["created"] == 0
    # … a real change is proposed again, the previous one alongside.
    client.companies[0]["address1"] = "400 W 5th St"
    assert sl.refresh(client, INSTANCE, fleet=FLEET)["created"] == 1
    (again,) = _open(BAKERY)
    assert again.payload["previous"]["status"] == "rejected"
    assert again.payload["previous"]["label"].startswith("300 W 5th St")


def test_a_change_supersedes_the_open_one_and_keeps_the_confirmed_pin(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)
    sl.confirm(p, key=ukey(1), lat=41.2, lng=-100.7, label="300 W 5th St", actor=1,
               reason="verified")
    client = _client()
    client.companies[0]["address1"] = "400 W 5th St"
    sl.refresh(client, INSTANCE, fleet=FLEET)
    (new,) = _open(BAKERY)
    assert new.payload["previous"] == {"id": p.id, "status": "confirmed",
                                       "label": p.payload["label"], "target_key": ukey(1)}
    pin = locations.get_site(ukey(1), BAKERY)
    assert (pin["lat"], pin["origin"]) == (41.2, "autotask")      # stays until confirmed
    # Changed again before anyone looked: the open one is superseded.
    client.companies[0]["address1"] = "500 W 5th St"
    sl.refresh(client, INSTANCE, fleet=FLEET)
    (newest,) = _open(BAKERY)
    old = store.get(new.id)
    assert old.status == "superseded" and old.superseded_by == newest.id


def test_unmapped_or_inactive_companies_close_their_open_proposals(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    client = _client()
    client.companies[0]["isActive"] = False                         # Example Bakery
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute("DELETE FROM autotask_tenant_company_map WHERE tenant_slug = ?", (CITY,))
        conn.commit()
    finally:
        conn.close()
    summary = sl.refresh(client, INSTANCE, fleet=FLEET)
    assert summary["superseded"] == 3
    assert _open(BAKERY) == [] and _open(CITY) == []
    assert all(p.decision_reason == "no longer listed by the source"
               for p in store.list_proposals(sl.KIND, statuses=("superseded",)))


def test_live_flags_and_the_lookup(reg, monkeypatch):
    pin = locations.Location(41.3, -100.8, "Hand-set front door", "site", origin="manual",
                             set_by=1)
    fleet = [site(1, BAKERY, "Bakery main", console=(41.26, -100.75), pin=pin)] + FLEET[1:]
    sl.refresh(_client(), INSTANCE, fleet=fleet)
    (p,) = _open(BAKERY)
    refs = {r.key: r for r in sl.fleet_refs(fleet)}
    assert _flags(p)["current_pin_differs"]["pin"]["label"] == "Hand-set front door"
    sent: list[str] = []

    def far_away(query, **_kw):
        sent.append(query)
        return [geocode.Match(39.1, -94.5, "300 W 5TH ST, ELSEWHERE"),
                geocode.Match(41.3, -100.8, "300 W 5TH ST, EXAMPLETON")]

    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(geocode, "lookup", far_away)
    matches = sl.lookup(p, refs)
    assert sent == ["300 W 5th St, Exampleton, IL 00001"]         # the query only
    assert matches[0]["km_from_console"] > 25 and matches[1]["km_from_console"] < 25
    looked = store.get(p.id)
    assert _flags(looked)["far_from_console"]["km"] > 25
    live = {f["code"] for f in sl.live_flags(looked, refs)}
    assert {"far_from_console", "current_pin_differs", "shared_address"} <= live
    # A refresh keeps what the lookup settled.
    sl.refresh(_client(), INSTANCE, fleet=fleet)
    assert "far_from_console" in _flags(store.get(p.id))
    # A first match on the pin itself: the pin agrees — no "differs".
    monkeypatch.setattr(geocode, "lookup",
                        lambda q, **_kw: [geocode.Match(41.3, -100.8, "300 W 5TH ST")])
    sl.lookup(store.get(p.id), refs)
    live = {f["code"] for f in sl.live_flags(store.get(p.id), refs)}
    assert "current_pin_differs" not in live and "far_from_console" not in live


def test_confirm_writes_the_pin_with_its_provenance_once(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    city = {p.source_ref: p for p in _open(CITY)}
    p = city["company:600"]                                         # "pick a site"
    sl.confirm(p, key=ukey(5), lat=41.1, lng=-100.6, label=p.payload["label"], actor=4,
               reason="city hall is at the company address")
    done = store.get(p.id)
    assert (done.status, done.target_key, done.decided_by) == ("confirmed", ukey(5), 4)
    row = locations.all_site_overrides()[ukey(5)]
    assert (row["origin"], row["proposal_id"], row["set_by"]) == ("autotask", p.id, 4)
    with pytest.raises(store.ProposalError):
        sl.confirm(p, key=ukey(5), lat=1.0, lng=1.0, label="x", actor=4, reason="again")
    with pytest.raises(store.ProposalError):
        sl.reject(p, actor=4, reason="too late")
    # A hand edit afterwards is 'manual' again.
    locations.set_site_override(ukey(5), CITY, 41.11, -100.61, "City Hall (door)", actor=2)
    assert locations.all_site_overrides()[ukey(5)]["origin"] == "manual"
    # Confirmed and unchanged: never proposed again.
    assert sl.refresh(_client(), INSTANCE, fleet=FLEET)["kept_confirmed"] >= 1
    assert "company:600" not in {q.source_ref for q in _open(CITY)}


def test_a_confirmed_target_that_is_gone_is_proposed_for_the_new_site(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(DENTAL)                                             # no UniFi: tenant level
    sl.confirm(p, key=sl.tenant_key(DENTAL), lat=33.0, lng=-96.7, label="Dental", actor=1,
               reason="verified")
    assert sl.refresh(_client(), INSTANCE, fleet=FLEET)["kept_confirmed"] >= 1
    # The client gets a UniFi site: the tenant-level entry is gone.
    sl.refresh(_client(), INSTANCE, fleet=FLEET + [site(8, DENTAL, "Dental office")])
    (again,) = _open(DENTAL)
    assert again.target_key == ukey(8) and "previous" not in again.payload  # not a change
    assert again.payload["confirmed_before"] == {"id": p.id, "target_key": sl.tenant_key(DENTAL)}
    # Unchanged on the next run (refreshed in place, never a second copy).
    assert sl.refresh(_client(), INSTANCE, fleet=FLEET + [site(8, DENTAL, "Dental office")]
                      )["created"] == 0
    assert [q.id for q in _open(DENTAL)] == [again.id]


def test_due():
    now = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
    assert sl.due(INSTANCE, now=now)                                   # never ran


def test_due_after_a_run(reg):
    sl.refresh(FakeAutotask(), INSTANCE, fleet=[])
    now = datetime.now(timezone.utc)
    assert not sl.due(INSTANCE, now=now)
    assert sl.due(INSTANCE, now=now + timedelta(hours=25))
    assert sl.due(INSTANCE, 60.0, now=now + timedelta(minutes=2))


def test_one_refresh_at_a_time(reg):
    assert sl._refresh_lock.acquire(blocking=False)
    try:
        with pytest.raises(sl.RefreshBusy):
            sl.refresh(_client(), INSTANCE, fleet=FLEET)
    finally:
        sl._refresh_lock.release()


def test_the_generic_tenant_map_counts_too(reg):
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute("INSERT INTO adapter_tenant_map (adapter_instance_id, vendor_tenant_id, "
                     "octo_client_slug, match_source) VALUES (?, '801', ?, 'manual'), "
                     "(?, 'not-a-number', ?, 'manual')", (INSTANCE, DENTAL, INSTANCE, DENTAL))
        conn.commit()
    finally:
        conn.close()
    got = sl.mapped_companies(INSTANCE)
    assert got[801] == [DENTAL] and got[101] == [BAKERY] and len(got) == 6


# ---------------------------------------------------------------------------
# Records over time: what comes back, what changes back, what moves
# ---------------------------------------------------------------------------

def _sql(sql: str, *args: Any) -> None:
    conn = sqlite3.connect(paths.registry_db_path())
    try:
        conn.execute(sql, args)
        conn.commit()
    finally:
        conn.close()


def test_a_reactivated_company_is_proposed_again(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (first,) = _open(BAKERY)
    gone = _client()
    gone.companies[0]["isActive"] = False
    sl.refresh(gone, INSTANCE, fleet=FLEET)
    assert _open(BAKERY) == [] and store.get(first.id).status == "superseded"
    # Back, unchanged: a superseded proposal never blocks the same data.
    summary = sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (again,) = _open(BAKERY)
    assert summary["created"] == 1 and again.id != first.id
    assert again.payload["label"] == first.payload["label"] and "previous" not in again.payload
    # A run that briefly reads no company at all closes everything — and the
    # next one proposes it all again.
    sl.refresh(FakeAutotask(), INSTANCE, fleet=FLEET)
    assert _open() == []
    assert sl.refresh(_client(), INSTANCE, fleet=FLEET)["created"] == 7


@pytest.mark.parametrize("first_state", ["open", "rejected", "confirmed"])
def test_an_address_changed_and_changed_back(reg, first_state):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p1,) = _open(BAKERY)
    if first_state == "rejected":
        sl.reject(p1, actor=1, reason="not this client")
    elif first_state == "confirmed":
        sl.confirm(p1, key=ukey(1), lat=41.2, lng=-100.7, label="300 W 5th St", actor=1,
                   reason="verified")
    changed = _client()
    changed.companies[0]["address1"] = "400 W 5th St"
    sl.refresh(changed, INSTANCE, fleet=FLEET)
    (p2,) = _open(BAKERY)
    assert p2.payload["label"].startswith("400 W 5th St")
    # Changed back: "400" is not what Autotask says any more — never left
    # open to be confirmed.
    summary = sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert store.get(p2.id).status == "superseded"
    now_open = _open(BAKERY)
    if first_state == "open":
        (p3,) = now_open
        assert p3.payload["label"].startswith("300 W 5th St") and p3.id not in (p1.id, p2.id)
        assert p3.payload["previous"]["id"] == p2.id
    else:
        assert now_open == [] and summary[f"kept_{first_state}"] == 1
    if first_state == "confirmed":
        assert locations.get_site(ukey(1), BAKERY)["proposal_id"] == p1.id   # untouched


def test_a_company_moved_to_another_client_and_back(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p1,) = _open(BAKERY)
    _sql("DELETE FROM autotask_tenant_company_map WHERE tenant_slug = ?", BAKERY)
    _sql("UPDATE autotask_tenant_company_map SET autotask_company_id = 101 "
         "WHERE tenant_slug = ?", DENTAL)
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert _open(BAKERY) == []
    assert store.get(p1.id).decision_reason == "the source record belongs to another client now"
    (p2,) = _open(DENTAL)
    assert p2.source_ref == "company:101"
    assert "previous" not in p2.payload                  # never the other client's history
    # … and back.
    _sql("UPDATE autotask_tenant_company_map SET autotask_company_id = 700 "
         "WHERE tenant_slug = ?", DENTAL)
    _sql("INSERT INTO autotask_tenant_company_map (adapter_instance_id, tenant_slug, "
         "autotask_company_id) VALUES (?, ?, 101)", INSTANCE, BAKERY)
    assert sl.refresh(_client(), INSTANCE, fleet=FLEET)["created"] >= 1
    (p3,) = _open(BAKERY)
    assert p3.id not in (p1.id, p2.id) and store.get(p2.id).status == "superseded"
    assert {q.source_ref for q in _open(DENTAL)} == {"company:700"}


def test_a_company_on_two_clients_is_proposed_to_each_never_pre_assigned(reg):
    _sql("UPDATE autotask_tenant_company_map SET autotask_company_id = 101 "
         "WHERE tenant_slug = ?", BOOKS)
    assert sl.mapped_companies(INSTANCE)[101] == [BAKERY, BOOKS]
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (a,) = _open(BAKERY)
    (b,) = _open(BOOKS)
    assert a.source_ref == b.source_ref == "company:101" and a.id != b.id
    # Both one-site clients — still "pick a site": whose address it is, is
    # the operator's call.
    assert (a.target_key, a.payload["target_mode"]) == (None, "pick")
    assert (b.target_key, b.payload["target_mode"]) == (None, "pick")
    assert _flags(a)["shared_company"]["tenants"] == [BOOKS]
    assert _flags(b)["shared_company"]["tenants"] == [BAKERY]
    # Rejected for one client: the other's stays open.
    sl.reject(b, actor=1, reason="not this client's address")
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert [p.id for p in _open(BAKERY)] == [a.id] and _open(BOOKS) == []


def test_a_single_site_whose_name_differs_is_flagged(reg):
    # The city's ONLY UniFi site is public works; its Autotask
    # company address is city hall.
    fleet = [s for s in FLEET if s.tenant_slug != CITY] + [site(6, CITY, "Public Works")]
    sl.refresh(_client(), INSTANCE, fleet=fleet)
    city = {p.source_ref: p for p in _open(CITY)}
    hall = city["company:600"]
    assert hall.target_key == ukey(6)                            # the only site (the rule)
    assert _flags(hall)["site_name_differs"]["site"] == "Public Works"
    assert "site_name_differs" not in _flags(city["location:13"])     # "Public Works"
    # A site named for nothing in particular, or for the client: no warning.
    for name in ("Default", "Bakery main"):
        store_reset()
        sl.refresh(_client(), INSTANCE, fleet=[site(1, BAKERY, name)])
        assert "site_name_differs" not in _flags(_open(BAKERY)[0])


def test_unreadable_locations_never_flip_the_target_or_drop_the_lookup(reg, monkeypatch):
    fleet = [site(3, PHARMA, "Example Pharmacy Northside", console=(41.0, -100.0)),
             site(4, PHARMA, "Example Pharmacy Riverton", console=(41.5, -100.5))]
    sl.refresh(_client(), INSTANCE, fleet=fleet)
    (p,) = [q for q in _open(PHARMA) if q.source_ref == "company:500"]
    assert p.target_key == ukey(3)            # matched through the merged location's name
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(geocode, "lookup", lambda q, **_k: [geocode.Match(39.1, -94.5, "far")])
    sl.lookup(p, {r.key: r for r in sl.fleet_refs(fleet)})
    assert "far_from_console" in _flags(store.get(p.id))
    for err in (AutotaskRefusedError("CompanyLocations cannot be read", status=403),
                AutotaskClientError("CompanyLocations/query HTTP 503", status=503)):
        client = _client()
        client.locations_error = err
        sl.refresh(client, INSTANCE, fleet=fleet)
        kept = store.get(p.id)
        assert kept.status == "proposed" and kept.target_key == ukey(3)
        assert "far_from_console" in _flags(kept)


def test_a_dropped_company_closes_its_location_proposals_even_when_refused(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert "location:13" in {p.source_ref for p in _open(CITY)}
    _sql("DELETE FROM autotask_tenant_company_map WHERE tenant_slug = ?", CITY)
    client = _client()
    client.locations_error = AutotaskRefusedError("CompanyLocations cannot be read", status=403)
    sl.refresh(client, INSTANCE, fleet=FLEET)
    assert _open(CITY) == []
    # Another company's location proposals are not read either — and stay.
    assert "location:11" in {p.source_ref for p in _open(PHARMA)}


def test_a_disabled_unifi_instance_never_reoffers_a_confirmed_pin(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)
    sl.confirm(p, key=ukey(1), lat=41.2, lng=-100.7, label="300 W 5th St", actor=1,
               reason="verified")
    city = {q.source_ref: q for q in _open(CITY)}["company:600"]
    sl.confirm(city, key=ukey(5), lat=41.1, lng=-100.6, label="City Hall", actor=1,
               reason="verified")
    # The UniFi instance is disabled: no site at all for a while.
    summary = sl.refresh(_client(), INSTANCE, fleet=[])
    assert summary["kept_confirmed"] == 2
    assert _open(BAKERY) == [] and "company:600" not in {q.source_ref for q in _open(CITY)}
    # Enabled again: still nothing to review for them.
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    assert _open(BAKERY) == [] and "company:600" not in {q.source_ref for q in _open(CITY)}


def test_a_confirmed_site_remapped_away_is_offered_for_the_clients_new_site(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)
    sl.confirm(p, key=ukey(1), lat=41.2, lng=-100.7, label="300 W 5th St", actor=1,
               reason="verified")
    # Site 1 now belongs to another client (it still exists); the client
    # has a new site of its own.
    fleet = [site(1, BOOKS, "Books annex"), site(9, BAKERY, "Bakery main")] + FLEET[1:]
    sl.refresh(_client(), INSTANCE, fleet=fleet)
    (again,) = _open(BAKERY)
    assert again.target_key == ukey(9) and again.payload["confirmed_before"]["id"] == p.id


def test_two_instances_never_touch_each_others_proposals(reg):
    other = INSTANCE + 1
    _sql("INSERT INTO autotask_tenant_company_map (adapter_instance_id, tenant_slug, "
         "autotask_company_id) VALUES (?, ?, 101)", other, DENTAL)
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (bakery,) = _open(BAKERY)
    dental = {q.source_ref for q in _open(DENTAL)}
    # The other instance's company 101 is another company (mapped to Dental).
    summary = sl.refresh(_client(), other, fleet=FLEET)
    assert summary["created"] == 1 and summary["superseded"] == 0
    assert store.get(bakery.id).status == "proposed"
    mine = [q for q in _open(DENTAL) if q.payload["instance_id"] == other]
    assert [q.source_ref for q in mine] == ["company:101"] and "previous" not in mine[0].payload
    assert {q.source_ref for q in _open(DENTAL) if q.payload["instance_id"] == INSTANCE} == dental


def test_a_site_remapped_to_another_tenant_shows_nothing_of_it(reg, monkeypatch):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)                                  # → ukey(1), Bakery main
    pin = locations.Location(41.3, -100.8, "Their front door", "site", origin="manual")
    remapped = [Entry(ukey(1), BOOKS, "unifi", "Their site", "console-1",
                      {"console_location": locations.Location(39.0, -94.5, "c", "unifi")}, pin)]
    refs = {r.key: r for r in sl.fleet_refs(remapped)}
    assert sl.own_ref(refs, ukey(1), BAKERY) is None
    assert {f["code"] for f in sl.live_flags(p, refs)} & set(sl.LIVE_FLAGS) == set()
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(geocode, "lookup", lambda q, **_k: [geocode.Match(41.3, -100.8, "m")])
    (match,) = sl.lookup(p, refs)
    assert "km_from_console" not in match


def test_a_confirm_applies_only_to_what_the_operator_reviewed(reg):
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    (p,) = _open(BAKERY)
    stale = p.updated_at
    _sql("UPDATE proposals SET updated_at = '2099-01-01T00:00:00.000Z' WHERE id = ?", p.id)
    with pytest.raises(store.ProposalError):
        sl.confirm(p, key=ukey(1), lat=41.2, lng=-100.7, label="x", actor=1, reason="checked",
                   expected_updated_at=stale, expected_pin_set_at=None)
    fresh = store.get(p.id)
    # Someone pins the site by hand meanwhile: "no pin" is not what is there.
    locations.set_site_override(ukey(1), BAKERY, 41.3, -100.8, "Front door", actor=2)
    with pytest.raises(store.ProposalError, match="pin changed"):
        sl.confirm(fresh, key=ukey(1), lat=41.2, lng=-100.7, label="x", actor=1,
                   reason="checked", expected_updated_at=fresh.updated_at,
                   expected_pin_set_at=None)
    assert store.get(p.id).status == "proposed"
    assert locations.get_site(ukey(1), BAKERY)["label"] == "Front door"   # never replaced
    seen = sl.pin_set_at(ukey(1), BAKERY)
    sl.confirm(fresh, key=ukey(1), lat=41.2, lng=-100.7, label="x", actor=1, reason="checked",
               expected_updated_at=fresh.updated_at, expected_pin_set_at=seen)
    assert locations.get_site(ukey(1), BAKERY)["origin"] == "autotask"


def test_the_refresh_never_geocodes_and_never_logs_an_address(reg, monkeypatch, caplog):
    def no(*_a, **_k):
        raise AssertionError("the geocoder was called")

    monkeypatch.setattr(geocode, "lookup", no)
    caplog.set_level("DEBUG", logger="apps.octo")
    sl.refresh(_client(), INSTANCE, fleet=FLEET)
    refs = {r.key: r for r in sl.fleet_refs(FLEET)}
    for p in _open():
        sl.live_flags(p, refs)
    # The daily run (the poller's thread) too.
    from apps.octo.instances import manager as instance_manager

    monkeypatch.setattr(instance_manager, "current_manager", lambda: None)
    monkeypatch.setattr(build, "build", lambda _m: build.FleetModel(
        generated_at="x", sites=FLEET, partial=False, unmapped_unifi_sites=0, isp_outages=[],
        build_ms=0))
    store_reset()
    assert sl.refresh_scheduled(_client(), INSTANCE)["created"] == 7
    text = caplog.text
    for street in ("Example Ave", "W 5th", "Example Plaza", "River Rd", "Example Ln"):
        assert street not in text
    (p,) = _open(BAKERY)
    monkeypatch.setenv(geocode.GEOCODER_ENV, "census")
    monkeypatch.setattr(geocode, "lookup", lambda q, **_k: [geocode.Match(41.3, -100.8, "m")])
    sl.lookup(p, refs)
    fresh = store.get(p.id)
    sl.confirm(fresh, key=ukey(1), lat=41.3, lng=-100.8, label=p.payload["label"], actor=1,
               reason="checked", expected_updated_at=fresh.updated_at, expected_pin_set_at=None)
    assert "W 5th" not in caplog.text
