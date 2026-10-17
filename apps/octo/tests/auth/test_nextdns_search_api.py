"""POST /api/v1/search/nextdns — the on-demand investigation, through the
real routes with the REAL adapter / client / limiter (fake socket only).

Pinned: 401 unauthenticated; a viewer gets 403 BEFORE any step-up prompt
(and even elevated); an analyst without step-up 401 STEP_UP_REQUIRED;
tenant scoping ('*' and invalid slugs 403, out of scope 403); domain (and
subdomains) / device (id, name, client IP) filters; results MASKED and never
stored; ONE audit row per call (the query as hashes); the SAME limiter at
investigation priority; a throttle is a 503 that is still audited.
"""
from __future__ import annotations

import json
from datetime import timedelta

from apps.octo import paths
from apps.octo.adapters.nextdns.limiter import PRIORITY_INVESTIGATION
from apps.octo.adapters.nextdns.tests.fake_nextdns import block_line
from apps.octo.client_provisioning import create_client
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


# ---------------------------------------------------------------------------
# POST /search/nextdns
# ---------------------------------------------------------------------------

def _seed_search(nd_tuple):
    client, transport, clock, _lim, record = nd_tuple
    now = clock.now()
    transport.add_lines(
        "abc123",
        block_line(now - timedelta(hours=2), domain="c2.bad-example.test"),
        block_line(now - timedelta(hours=3), domain="www.c2.bad-example.test",
                   device_id="D9", device_name="bob-pc", client_ip="192.0.2.20"),
        block_line(now - timedelta(hours=1), domain="notc2.bad-example.test"),
        {**block_line(now - timedelta(minutes=30), domain="portal.bank-alpha.test",
                      reason="blocklist:oisd"), "status": "default", "reasons": []},
    )
    transport.add_lines("def456", block_line(now - timedelta(hours=1),
                                             domain="c2.bad-example.test"))
    tenant_map.set_mappings(record.id, [
        TenantMapping("abc123", A, "Acme Corp Office", "manual"),
        TenantMapping("def456", B, "Example Bakery", "manual"),
    ])


def test_unauthenticated_viewer_and_no_step_up(nd):  # noqa: F811
    client = nd[0]
    _seed_search(nd)
    assert client.post(SEARCH, json={"tenant": A, "domain": "x.test"}).status_code == 401
    _op(client, "bob", "viewer", [A])
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"})
    assert r.status_code == 403 and r.json()["code"] == "ISOLATION_VIOLATION"
    _op(client, "carol", "analyst")
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"})
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    assert _audit("search.nextdns") == []
    assert nd[1].calls == []


def test_a_viewer_is_refused_even_elevated(nd):  # noqa: F811
    client = nd[0]
    _seed_search(nd)
    op = _op(client, "bob", "viewer", [A])
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"})
    assert r.status_code == 403 and "bad-example" not in r.text


def test_domain_search_masked_not_stored_audited(nd):  # noqa: F811
    client, transport, _clock, limiter, record = nd
    _seed_search(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    events_before = (paths.client_dir(A) / "events.db").stat().st_size
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test", "hours": 24})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["masked"] is True and body["stored"] is False
    assert body["profiles_searched"] == ["abc123"]            # this tenant's only
    assert [x["masked_domain"] for x in body["results"]] == ["*****.test", "w*****.test"]
    assert all("c2.bad-example" not in x["masked_domain"] for x in body["results"])
    assert body["results"][0]["signal_level"] == "high"
    assert body["results"][1]["device_name"] == "bob-pc"
    assert body["query_domain"] == "c2.bad-example.test"      # the analyst's own words
    # The search went to NextDNS with the domain, through the shared limiter.
    [call] = transport.calls
    assert call.path == "/profiles/abc123/logs" and call.query["search"] == "c2.bad-example.test"
    assert limiter.grants()[-1].priority == PRIORITY_INVESTIGATION
    # Nothing stored.
    assert (paths.client_dir(A) / "events.db").stat().st_size == events_before
    [row] = _audit("search.nextdns")
    assert row["tenants"] == [A] and row["rows_returned"] == 2 and row["outcome"] == "ok"
    assert row["has_domain_query"] and row["domain_query_hash"]
    assert "bad-example" not in json.dumps(row)
    client.post(SEARCH, json={"tenant": A, "device": "bob-pc"})
    assert len(_audit("search.nextdns")) == 2


def test_device_search_by_name_or_ip(nd):  # noqa: F811
    client = nd[0]
    _seed_search(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    by_name = client.post(SEARCH, json={"tenant": A, "device": "BOB-PC"}).json()
    by_ip = client.post(SEARCH, json={"tenant": A, "device": "192.0.2.20"}).json()
    assert len(by_name["results"]) == len(by_ip["results"]) == 1
    anything = client.post(SEARCH, json={"tenant": A, "device": "alice-laptop",
                                         "status": "any"}).json()
    assert {x["status"] for x in anything["results"]} == {"blocked", "default"}


def test_scope_and_invalid_tenants(nd):  # noqa: F811
    client = nd[0]
    _seed_search(nd)
    op = _op(client, "carol", "analyst", [B])
    _elevate(client, op)
    assert client.post(SEARCH, json={"tenant": A, "domain": "x.test"}).status_code == 403
    assert client.post(SEARCH, json={"tenant": B, "domain": "c2.bad-example.test"}).status_code == 200
    for bad in ("*", "Acme", "../etc"):
        assert client.post(SEARCH, json={"tenant": bad, "domain": "x.test"}).status_code == 403


def test_refusals(nd):  # noqa: F811
    client = nd[0]
    _seed_search(nd)
    create_client("globex", "Globex")
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    r = client.post(SEARCH, json={"tenant": A})
    assert r.status_code == 422 and "domain and/or a device" in r.json()["message"]
    assert client.post(SEARCH, json={"tenant": A, "domain": "x.test",
                                     "hours": 169}).status_code == 422
    r = client.post(SEARCH, json={"tenant": "globex", "domain": "x.test"})
    assert r.status_code == 404 and "no NextDNS profile" in r.json()["message"]


def test_a_throttle_is_a_503_and_still_audited(nd):  # noqa: F811
    client, transport, clock, limiter, _record = nd
    _seed_search(nd)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    limiter.success()
    limiter.refusal(403)                               # the poller just got throttled
    limiter.refusal(403)                               # 30 s: longer than the route waits
    for _ in range(3):
        limiter.refusal(403)
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"})
    assert r.status_code == 503 and "rate limiting" in r.json()["message"]
    assert transport.calls == []                        # nothing sent into the backoff
    [row] = _audit("search.nextdns")
    assert row["outcome"] == "throttled" and row["vendor_calls"] == 0
    assert clock is not None


# ---------------------------------------------------------------------------
# The investigation budget (fix round 2026-09-30): one search at a time, a
# rolling hourly call budget, a whole-search deadline.
# ---------------------------------------------------------------------------

def test_a_search_budget_that_is_used_up_is_a_503_and_audited(nd, monkeypatch):  # noqa: F811
    from apps.octo.adapters.nextdns import adapter as nd_adapter

    client, transport, _clock, _limiter, _record = nd
    _seed_search(nd)
    monkeypatch.setattr(nd_adapter, "INVESTIGATION_CALLS_PER_HOUR", 2)
    op = _op(client, "carol", "analyst")
    _elevate(client, op)
    for _ in range(2):
        assert client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"}
                           ).status_code == 200
    r = client.post(SEARCH, json={"tenant": A, "domain": "c2.bad-example.test"})
    assert r.status_code == 503 and "search budget" in r.json()["message"]
    assert len(transport.calls) == 2                         # nothing sent past the budget
    assert _audit("search.nextdns")[-1]["outcome"] == "throttled"


def test_only_one_search_runs_at_a_time(nd):  # noqa: F811
    from apps.octo.adapters.nextdns.client import NextDNSBusyError

    client, transport, clock, _limiter, record = nd
    _seed_search(nd)
    adapter = client.app.state.instance_manager.running_adapter(record.id)
    second: list = []

    def nested(path, query):
        if not second:
            try:
                adapter.investigate([("def456", "Example Bakery")], since=clock.now()
                                    - timedelta(hours=1), until=clock.now(), domain="x.test",
                                    device=None, status=None, limit=10)
                second.append("ran")
            except NextDNSBusyError as exc:
                second.append(str(exc))
    transport.before_request = nested
    adapter.investigate([("abc123", "Acme Corp Office")], since=clock.now() - timedelta(hours=4),
                        until=clock.now(), domain="c2.bad-example.test", device=None,
                        status=None, limit=10)
    assert second and "Another NextDNS search is running" in second[0]
    assert [c.path for c in transport.calls] == ["/profiles/abc123/logs"]


def test_a_search_stops_at_its_deadline(nd, monkeypatch):  # noqa: F811
    from apps.octo.adapters.nextdns import adapter as nd_adapter

    client, transport, clock, _limiter, record = nd
    _seed_search(nd)
    tenant_map.set_mappings(record.id, [
        TenantMapping(pid, A, pid, "manual") for pid in ("abc123", "abc124", "def456")])
    adapter = client.app.state.instance_manager.running_adapter(record.id)
    monkeypatch.setattr(nd_adapter, "INVESTIGATION_DEADLINE_SEC", 3.0)
    found, truncated, calls = adapter.investigate(
        [("abc123", "a"), ("abc124", "b"), ("def456", "c")],
        since=clock.now() - timedelta(hours=4), until=clock.now(), domain="c2.bad-example.test",
        device=None, status=None, limit=100)
    # 2 s spacing: the third page would start after the 3 s deadline.
    assert calls == 2 and truncated is True
