"""POST /api/v1/search/nextdns and RESTRICTED evidence (rule B7, CSAM —
v0.17.1 fixer round, review CSAM-3):

  * a CSAM line (or a line naming a domain the tenant holds as restricted
    evidence) is never returned — and only an ADMIN's note says lines were
    withheld: for anyone else that would name the device a restricted
    incident is about (the count is in the audit row either way);
  * a search for a restricted domain (or a name under it) makes NO vendor
    call; an admin is told why (422), anyone else gets exactly what a search
    with no hits returns — nothing confirms a guess. Audited either way;
  * the refusal is on the EXACT domain: a sibling under the same root is
    searched as usual.

Placeholders only: `csam-placeholder.example.test`, TEST-NET addresses.
"""
from __future__ import annotations

from datetime import timedelta

from apps.octo.adapters.nextdns.tests.fake_nextdns import block_line
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.instances import tenant_map
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_nextdns_profiles_api import (  # noqa: F401
    A,
    B,
    SEARCH,
    _audit,
    _op,
    nd,
)
from apps.octo.tests.auth.test_search_indicators import _elevate
from apps.octo.threat import restricted

DOMAIN = "csam-placeholder.example.test"
CSAM = (("csam", "Child Sexual Abuse Material"),)


def _seed(nd_tuple) -> None:
    client, transport, clock, _lim, record = nd_tuple
    now = clock.now()
    transport.add_lines(
        "abc123",
        # bob-pc: one ordinary block and one CSAM lookup.
        block_line(now - timedelta(hours=1), domain="c2.bad-example.test",
                   device_id="D9", device_name="bob-pc", client_ip="192.0.2.20"),
        block_line(now - timedelta(minutes=50), domain=DOMAIN, reason="csam",
                   reason_name="Child Sexual Abuse Material",
                   device_id="D9", device_name="bob-pc", client_ip="192.0.2.20"),
        block_line(now - timedelta(minutes=40), domain="sibling.example.test",
                   device_id="D7", device_name="carol-pc", client_ip="192.0.2.21"),
    )
    tenant_map.set_mappings(record.id, [TenantMapping("abc123", A, "Acme Corp Office",
                                                      "manual")])
    # The poller kept the CSAM line as restricted evidence.
    restricted.record_nextdns(
        A, profile_id="abc123", profile_name="Acme Corp Office",
        line=block_line(now - timedelta(minutes=50), domain=DOMAIN, reason="csam",
                        reason_name="Child Sexual Abuse Material", device_id="D9",
                        device_name="bob-pc", client_ip="192.0.2.20"),
        line_id="kept-1", observed_at=format_utc_ms(now - timedelta(minutes=50)))


def test_an_analyst_device_search_never_hears_of_withheld_lines(nd):  # noqa: F811
    client = nd[0]
    _seed(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A, "device": "bob-pc"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) == 1                            # the ordinary block only
    assert "withheld" not in body["note"] and "restricted" not in body["note"]
    assert "csam" not in r.text.lower()
    [row] = _audit("search.nextdns")
    assert row["restricted_withheld"] == 1 and row["restricted_refused"] is False


def test_an_admin_device_search_is_told_lines_were_withheld(nd):  # noqa: F811
    client = nd[0]
    _seed(nd)
    op = _op(client, "dana", "admin")
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A, "device": "bob-pc"})
    assert r.status_code == 200
    assert "1 restricted-category line withheld" in r.json()["note"]
    assert "csam-placeholder" not in r.text


def test_an_analyst_search_for_a_restricted_domain_looks_like_no_hits(nd):  # noqa: F811
    client, transport, *_ = nd
    _seed(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    plain = client.post(SEARCH, json={"tenant": A, "domain": "nothing-here.example.test"})
    calls = len(transport.calls)
    for asked in (DOMAIN, f"cdn.{DOMAIN}", DOMAIN.upper()):
        r = client.post(SEARCH, json={"tenant": A, "domain": asked})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["results"] == [] and body["note"] == plain.json()["note"]
        assert body["profiles_searched"] == plain.json()["profiles_searched"]
        assert "restricted" not in r.text.lower() and "csam" not in body["note"].lower()
    assert len(transport.calls) == calls                       # no vendor call at all
    rows = _audit("search.nextdns")
    assert [x["restricted_refused"] for x in rows] == [False, True, True, True]
    assert all(x["vendor_calls"] == 0 for x in rows[1:])
    assert all(DOMAIN not in str(x) for x in rows)


def test_an_admin_is_told_why_and_it_is_audited(nd):  # noqa: F811
    client, transport, *_ = nd
    _seed(nd)
    op = _op(client, "dana", "admin")
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A, "domain": DOMAIN})
    assert r.status_code == 422 and "restricted incident" in r.json()["message"]
    assert transport.calls == []
    [row] = _audit("search.nextdns")
    assert row["restricted_refused"] is True and row["outcome"] == "restricted_refused"


def test_a_sibling_under_the_same_root_is_searched_as_usual(nd):  # noqa: F811
    client, transport, *_ = nd
    _seed(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A, "domain": "sibling.example.test"})
    assert r.status_code == 200 and len(r.json()["results"]) == 1
    assert len(transport.calls) == 1
    # Another tenant's restricted list never refuses this one's search.
    r = client.post(SEARCH, json={"tenant": B, "domain": DOMAIN})
    assert r.status_code == 404                                 # B has no profile mapped
