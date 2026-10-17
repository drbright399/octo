"""GET /api/v1/dashboard/dns-summary (masked) and POST /api/v1/search/dns
(step-up, unmasked) — the dashboard's view of the telemetry store.

Real sign-in, real tenants, telemetry written by the real store. Pins:
  * role matrix: unauth 401, viewer 403, analyst / admin / super_admin 200;
  * scope: a concrete scope sees only its tenants; '*' = ACTIVE tenants;
  * masking: no domain and no device leaves the dashboard route; counts do
    (lookups from ONE sensor — Pi-hole when present, else Suricata's query
    records; first-seen; blocked by the classifier; fallback rows);
  * unaudited + no-store for the dashboard route; the search route needs
    step-up, is analyst+, scope-checked, and writes ONE audit row per call;
    it answers "who looked this name up / what did this device look up".
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.tests._tiering_fixtures import insert_event, pihole_payload, write_telemetry
from apps.octo.tests.auth.test_dashboard_throughput import _login
from apps.octo.tests.auth.test_search_indicators import _elevate

URL = "/api/v1/dashboard/dns-summary"
SEARCH = "/api/v1/search/dns"
PW = "pw1234567890"
A, B, OFF = "acme-corp", "globex", "initech"
SECRET_DOMAINS = ("portal.bank-alpha.test", "clinic-records.example.test")


def _ago(**kw) -> str:
    t = datetime.now(timezone.utc) - timedelta(**kw)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


@pytest.fixture(autouse=True)
def _clean_fallback_counter():
    """The sink's refused-write counter is process-wide (one data root per
    server process); other tests' deliberate store faults must not show up
    as this module's tenants' faults."""
    from apps.octo.ingest import sink as sink_module

    sink_module.reset_telemetry_fallbacks()
    yield
    sink_module.reset_telemetry_fallbacks()


@pytest.fixture
def seeded(auth_client, auth_data_root):
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    for slug in (A, B, OFF):
        client_provisioning.create_client(slug, slug.title(), kind="client")
    reg = sqlite3.connect(paths.registry_db_path())
    reg.execute("UPDATE clients SET status = 'offboarded' WHERE slug = ?", (OFF,))
    reg.commit()
    reg.close()
    root = auth_data_root
    # acme: portal.bank-alpha.test seen by both sensors (3 pihole, 2 suricata)
    # from two devices; one first-seen domain an hour ago; a blocked lookup.
    for i in range(3):
        write_telemetry(root, A, received_at=_ago(minutes=30 + i), domain=SECRET_DOMAINS[0],
                        device=f"192.0.2.{10 + i % 2}", event_type="pihole.query", n=i)
    for i in range(2):
        write_telemetry(root, A, received_at=_ago(minutes=40 + i), domain=SECRET_DOMAINS[0],
                        device="192.0.2.10", event_type="suricata.dns", n=10 + i)
    write_telemetry(root, A, received_at=_ago(hours=1), domain=SECRET_DOMAINS[1],
                    device="alice-laptop", event_type="suricata.tls", n=20)
    # A domain first seen long ago (not "new" in the window).
    write_telemetry(root, A, received_at=_ago(days=6), domain="old.example.test", n=30)
    write_telemetry(root, A, received_at=_ago(minutes=5), domain="old.example.test", n=31)
    insert_event(root, A, event_type="pihole.query", payload=pihole_payload(1, "ads.example.test"),
                 received_at=_ago(minutes=10), severity="low")
    write_telemetry(root, B, received_at=_ago(minutes=20), domain="b.example.test", n=40)
    write_telemetry(root, OFF, received_at=_ago(minutes=20), domain="off.example.test", n=50)
    return root


def _op(auth_client, name: str, role: str, scope=None) -> dict:
    op = auth_client.provision_operator(name, PW, role=role, athena_role=role, scope_slugs=scope)
    _login(auth_client, op)
    return op


def _audit_count(action: str | None = None) -> int:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        if action:
            return conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = ?",
                                (action,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Role matrix + scope
# ---------------------------------------------------------------------------

def test_unauthenticated_is_401(auth_client, seeded):
    assert auth_client.get(URL).status_code == 401
    assert auth_client.post(SEARCH, json={"tenant": A}).status_code == 401


def test_viewer_is_403_and_sees_nothing(auth_client, seeded):
    _op(auth_client, "bob", "viewer", [A])
    r = auth_client.get(URL)
    assert r.status_code == 403 and r.json()["code"] == "ISOLATION_VIOLATION"
    assert "bank" not in r.text and "example" not in r.text


@pytest.mark.parametrize("role", ["analyst", "admin", "super_admin"])
def test_analyst_and_up_are_200(auth_client, seeded, role):
    _op(auth_client, "alice", role)
    r = auth_client.get(URL)
    assert r.status_code == 200, r.text
    assert {t["tenant"] for t in r.json()["tenants"]} == {A, B}   # OFF is offboarded


def test_concrete_scope_sees_only_its_tenants(auth_client, seeded):
    _op(auth_client, "alice", "analyst", [B])
    body = auth_client.get(URL).json()
    assert [t["tenant"] for t in body["tenants"]] == [B]
    assert body["totals"]["lookups"] == 1


def test_scope_of_only_offboarded_tenants(auth_client, seeded):
    _op(auth_client, "alice", "analyst", [OFF])
    body = auth_client.get(URL).json()
    assert body["tenants"] == [] and body["empty_reason"] == "no_tenants"


# ---------------------------------------------------------------------------
# Content + masking
# ---------------------------------------------------------------------------

def test_counts_first_seen_and_masking(auth_client, seeded):
    _op(auth_client, "alice", "analyst")
    before = _audit_count()
    r = auth_client.get(URL, params={"hours": 24})
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    assert _audit_count() == before                     # a polled, masked aggregate
    text = r.text.lower()
    for d in (*SECRET_DOMAINS, "old.example.test", "192.0.2.10", "alice-laptop"):
        assert d not in text, f"{d} leaked"
    acme = next(t for t in r.json()["tenants"] if t["tenant"] == A)
    [top, *rest] = acme["top_domains"]
    assert top == {"masked_domain": "po*****.test", "lookups": 3, "pihole": 3,
                   "suricata": 2, "devices": 2}
    assert acme["lookups"] == 4            # Pi-hole's answered lookups (the one sensor)
    assert acme["lookups_source"] == "pihole"
    assert acme["by_type"] == {"pihole.query": 4, "suricata.dns": 2, "suricata.tls": 1}
    assert acme["blocked"] == 1
    # First seen in the window: the bank portal and the clinic records host,
    # not old.example.test (first seen 6 days ago).
    assert acme["first_seen_count"] == 2
    assert {f["masked_domain"] for f in acme["first_seen"]} == {"po*****.test", "cl*****.test"}
    assert acme["baseline_building"] is True          # ledger younger than a week
    assert r.json()["masked"] is True


def test_no_telemetry_says_so(auth_client, auth_data_root):
    client_provisioning.create_client(A, "Acme", kind="client")
    _op(auth_client, "alice", "analyst")
    body = auth_client.get(URL).json()
    assert body["tenants"] == [] and body["empty_reason"] == "no_telemetry"
    assert body["empty_detail"]


# ---------------------------------------------------------------------------
# Step-up search (unmasked)
# ---------------------------------------------------------------------------

def test_search_requires_step_up_then_returns_full_values_audited(auth_client, seeded):
    op = _op(auth_client, "alice", "analyst")
    r = auth_client.post(SEARCH, json={"tenant": A})
    assert r.status_code == 401 and r.json()["code"] == "STEP_UP_REQUIRED"
    _elevate(auth_client, op)
    before = _audit_count("search.dns_summary")
    r = auth_client.post(SEARCH, json={"tenant": A, "hours": 24, "limit": 5})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["top_domains"][0]["domain"] == SECRET_DOMAINS[0]
    assert {f["domain"] for f in body["first_seen"]} == set(SECRET_DOMAINS)
    assert {f["first_device"] for f in body["first_seen"]} == {"192.0.2.10", "alice-laptop"}
    assert _audit_count("search.dns_summary") == before + 1
    auth_client.post(SEARCH, json={"tenant": A})
    assert _audit_count("search.dns_summary") == before + 2


def test_search_is_scoped_and_analyst_plus(auth_client, seeded):
    op = _op(auth_client, "alice", "analyst", [B])
    _elevate(auth_client, op)
    assert auth_client.post(SEARCH, json={"tenant": A}).status_code == 403
    assert auth_client.post(SEARCH, json={"tenant": B}).status_code == 200
    assert auth_client.post(SEARCH, json={"tenant": "../../etc"}).status_code == 403


def test_search_star_scope_refuses_inactive_or_unknown(auth_client, seeded):
    op = _op(auth_client, "alice", "super_admin")
    _elevate(auth_client, op)
    assert auth_client.post(SEARCH, json={"tenant": OFF}).status_code == 403
    assert auth_client.post(SEARCH, json={"tenant": "no-such-tenant"}).status_code == 403


def test_viewer_cannot_search_even_elevated(auth_client, seeded):
    op = _op(auth_client, "bob", "viewer", [A])
    _elevate(auth_client, op)
    r = auth_client.post(SEARCH, json={"tenant": A})
    assert r.status_code == 403
    assert "bank" not in r.text


def test_viewer_gets_403_before_any_step_up_prompt(auth_client, seeded):
    """The role is checked BEFORE the step-up: a viewer gets 403, never a
    401 STEP_UP_REQUIRED that sends the SPA into a pointless re-auth."""
    _op(auth_client, "bob", "viewer", [A])
    r = auth_client.post(SEARCH, json={"tenant": A})
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "ISOLATION_VIOLATION"


def test_search_star_or_invalid_tenant_is_403_not_500(auth_client, seeded):
    """'*' is IN a wildcard caller's scope list, but never a tenant: 403
    (it used to reach the path builder and raise → 500), nothing audited."""
    op = _op(auth_client, "alice", "super_admin")
    _elevate(auth_client, op)
    before = _audit_count("search.dns_summary")
    for bad in ("*", "Acme", "a..b", "-x"):
        r = auth_client.post(SEARCH, json={"tenant": bad})
        assert r.status_code == 403, (bad, r.text)
        assert r.json()["code"] == "ISOLATION_VIOLATION"
    assert _audit_count("search.dns_summary") == before


# ---------------------------------------------------------------------------
# Lookups are counted once; blocked is what was blocked
# ---------------------------------------------------------------------------

def _ingest(root, slug, event_type, payload, n):
    import hashlib
    import json

    from shared_adapter_contract.types import CanonicalEvent

    from apps.octo.ingest.sink import SqliteIngestSink

    payload = {**payload, "n": n}
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return SqliteIngestSink(root, publish_to_stream=False).ingest(
        slug, "buoy:acme", CanonicalEvent(
            vendor_event_id=str(n), received_at=_ago(minutes=n), severity="info",
            indicator=None, indicator_type=None, source_host="buoy-acme-1",
            summary=event_type, payload=payload,
            payload_sha256=hashlib.sha256(text.encode()).hexdigest()),
        event_type=event_type)


def _eve_dns(kind: str, name: str) -> dict:
    client, resolver = "192.0.2.10", "192.0.2.53"
    src, dst = (client, resolver) if kind == "query" else (resolver, client)
    return {"event_type": "suricata.dns", "severity": "info",
            "raw_eve": {"event_type": "dns", "src_ip": src, "dest_ip": dst,
                        "dns": {"type": kind, "rrname": name, "rrtype": "A"}}}


def _one_answered_one_blocked(root, slug, *, with_pihole=True):
    """One answered and one blocked lookup, each seen by Pi-hole (answered →
    telemetry, blocked → signal) and by Suricata as a query AND an answer."""
    n = 0
    for name in ("www.example.test", "ads.example.test"):
        if with_pihole:
            status = 2 if name.startswith("www") else 1
            n += 1
            _ingest(root, slug, "pihole.query", pihole_payload(status, name, n=n), n)
        for kind in ("query", "answer"):
            n += 1
            _ingest(root, slug, "suricata.dns", _eve_dns(kind, name), n)


@pytest.fixture
def fresh(auth_client, auth_data_root):
    from apps.octo.ingest import sink as sink_module
    from apps.octo.ingest import telemetry

    telemetry.reset_schema_cache()
    sink_module.reset_telemetry_fallbacks()
    client_provisioning.create_client(A, "Acme", kind="client")
    return auth_data_root


def test_a_lookup_is_counted_once_and_blocked_domains_are_not_top(auth_client, fresh):
    _one_answered_one_blocked(fresh, A)
    _op(auth_client, "alice", "analyst")
    acme = auth_client.get(URL).json()["tenants"][0]
    assert (acme["lookups"], acme["lookups_source"], acme["blocked"]) == (1, "pihole", 1)
    assert acme["by_type"] == {"pihole.query": 1, "suricata.dns": 2, "suricata.dns.answer": 2}
    assert [(d["lookups"], d["pihole"], d["suricata"], d["devices"])
            for d in acme["top_domains"]] == [(1, 1, 1, 1)]
    assert acme["top_domains"][0]["masked_domain"].startswith("w")   # not the ad domain
    assert acme["fallback_rows"] == 0


def test_without_pihole_suricata_queries_count(auth_client, fresh):
    _one_answered_one_blocked(fresh, A, with_pihole=False)
    _op(auth_client, "alice", "analyst")
    acme = auth_client.get(URL).json()["tenants"][0]
    assert (acme["lookups"], acme["lookups_source"], acme["blocked"]) == (2, "suricata", 0)
    assert [d["lookups"] for d in acme["top_domains"]] == [1, 1]        # not 2 each


def test_a_telemetry_store_fault_is_visible_and_not_counted_as_blocked(auth_client, fresh):
    """Answered lookups that landed in events.db (the telemetry store
    refused them) are reported as fallback rows — not as blocked."""
    import os

    _ingest(fresh, A, "pihole.query", pihole_payload(1, "ads.example.test", n=1), 1)
    tdb = fresh / "clients" / A / "telemetry.db"
    os.chmod(tdb, 0o444)
    try:
        outcome = _ingest(fresh, A, "pihole.query", pihole_payload(2, "www.example.test", n=2), 2)
    finally:
        for f in tdb.parent.glob("telemetry.db*"):
            os.chmod(f, 0o644)
    assert outcome.fallback is True
    insert_event(fresh, A, event_type="pihole.query", payload=pihole_payload(3, n=3),
                 received_at=_ago(minutes=3))              # an older process's fallback
    _op(auth_client, "alice", "analyst")
    body = auth_client.get(URL).json()
    acme = body["tenants"][0]
    assert acme["blocked"] == 1
    assert acme["fallback_rows"] == 2 and body["totals"]["fallback_rows"] == 2
    assert acme["recent_store_fallbacks"] == 1
    assert acme["store_fallback_window_hours"] == 24


def test_lookups_stored_before_the_upgrade_await_the_move_not_a_fault(auth_client, fresh):
    """Between deploy (step 2) and the one-off move (step 4) the tenant's
    answered lookups from BEFORE 036 are still in events.db, unstamped.
    They are NOT a telemetry-store fault (fallback_rows 0) — they are
    reported apart as awaiting the move, and never as blocked."""
    for n in range(1, 41):
        insert_event(fresh, A, event_type="pihole.query",
                     payload=pihole_payload(2, f"w{n}.example.test", n=n),
                     received_at=_ago(minutes=n), stamped=False)
    insert_event(fresh, A, event_type="pihole.query", payload=pihole_payload(1, n=99),
                 received_at=_ago(minutes=5), stamped=False)   # blocked: a signal
    _op(auth_client, "alice", "analyst")
    body = auth_client.get(URL).json()
    acme = body["tenants"][0]
    assert (acme["fallback_rows"], acme["awaiting_move_rows"], acme["blocked"]) == (0, 40, 1)
    assert acme["recent_store_fallbacks"] == 0
    assert (body["totals"]["fallback_rows"], body["totals"]["awaiting_move_rows"]) == (0, 40)
    # A pre-036 events.db (no arrival column at all) reads the same.
    import sqlite3

    conn = sqlite3.connect(fresh / "clients" / A / "events.db")
    conn.execute("DROP INDEX idx_events_ingested_at")
    conn.execute("ALTER TABLE events DROP COLUMN ingested_at")
    conn.commit()
    conn.close()
    acme = auth_client.get(URL).json()["tenants"][0]
    assert (acme["fallback_rows"], acme["awaiting_move_rows"]) == (0, 40)


# ---------------------------------------------------------------------------
# Who looked this name up?
# ---------------------------------------------------------------------------

def test_search_by_domain_answers_who_looked_it_up(auth_client, seeded):
    write_telemetry(seeded, A, received_at=_ago(minutes=2), domain="login." + SECRET_DOMAINS[0],
                    device="192.0.2.77", event_type="pihole.query", n=90)
    op = _op(auth_client, "alice", "analyst")
    _elevate(auth_client, op)
    r = auth_client.post(SEARCH, json={"tenant": A, "domain": SECRET_DOMAINS[0].upper() + "."})
    assert r.status_code == 200, r.text
    body = r.json()
    devices = {(s["domain"], s["device"], s["event_type"]): s["lookups"] for s in body["sightings"]}
    assert devices == {
        (SECRET_DOMAINS[0], "192.0.2.10", "pihole.query"): 2,
        (SECRET_DOMAINS[0], "192.0.2.11", "pihole.query"): 1,
        (SECRET_DOMAINS[0], "192.0.2.10", "suricata.dns"): 2,
        ("login." + SECRET_DOMAINS[0], "192.0.2.77", "pihole.query"): 1,
    }
    assert len(body["lookups_found"]) == 6
    assert {x["device"] for x in body["lookups_found"]} == {"192.0.2.10", "192.0.2.11", "192.0.2.77"}
    assert "7 days" in body["note"]
    exact = auth_client.post(SEARCH, json={"tenant": A, "domain": SECRET_DOMAINS[0],
                                           "include_subdomains": False}).json()
    assert {s["domain"] for s in exact["sightings"]} == {SECRET_DOMAINS[0]}
    # A lookalike that merely ENDS with the name is not a subdomain.
    write_telemetry(seeded, A, received_at=_ago(minutes=1), domain="evil" + SECRET_DOMAINS[0],
                    n=91)
    again = auth_client.post(SEARCH, json={"tenant": A, "domain": SECRET_DOMAINS[0]}).json()
    assert "evil" + SECRET_DOMAINS[0] not in {s["domain"] for s in again["sightings"]}
    # What did one device look up?
    dev = auth_client.post(SEARCH, json={"tenant": A, "device": "alice-laptop"}).json()
    assert [(s["domain"], s["event_type"]) for s in dev["sightings"]] == [
        (SECRET_DOMAINS[1], "suricata.tls")]
    # The audit row records THAT a name was searched, not the name.
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        after = conn.execute("SELECT after_state FROM audit_log WHERE action = "
                             "'search.dns_summary' ORDER BY id DESC LIMIT 1").fetchone()[0]
    finally:
        conn.close()
    assert "alice-laptop" not in after and "has_device_query" in after
    assert auth_client.post(SEARCH, json={"tenant": A, "domain": "a b"}).status_code == 422


def test_a_pihole_v6_named_client_is_found_by_ip_and_by_name(auth_client, fresh):
    """v0.11 T5: Pi-hole v6 reports a client by address AND name. The row is
    keyed by the address (Suricata's key: one device, one key), the name is
    stored beside it, and a device search finds it either way — through the
    real sink."""
    v6 = {"event_type": "pihole.query", "severity": "info",
          "raw_query": {"id": 7, "status": 2, "domain": "www.example.test",
                        "client": "192.0.2.44", "client_name": "Front-Desk-PC.lan"},
          "_adapter": "pihole", "_buoy": "buoy-acme-1"}
    assert _ingest(fresh, A, "pihole.query", v6, 1).tier == "telemetry"
    eve = _eve_dns("query", "www.example.test")
    eve["raw_eve"]["src_ip"] = "192.0.2.44"
    _ingest(fresh, A, "suricata.dns", eve, 2)
    op = _op(auth_client, "alice", "analyst")
    _elevate(auth_client, op)
    by_ip = auth_client.post(SEARCH, json={"tenant": A, "device": "192.0.2.44"}).json()
    assert {(s["device"], s["event_type"], s["device_name"]) for s in by_ip["sightings"]} == {
        ("192.0.2.44", "pihole.query", "Front-Desk-PC.lan"),
        ("192.0.2.44", "suricata.dns", ""),
    }
    assert {(x["event_type"], x["device"], x["device_name"])
            for x in by_ip["lookups_found"]} == {
        ("pihole.query", "192.0.2.44", "Front-Desk-PC.lan"),
        ("suricata.dns", "192.0.2.44", "")}
    by_name = auth_client.post(SEARCH, json={"tenant": A, "device": "front-desk-pc.lan"}).json()
    assert [(s["device"], s["event_type"]) for s in by_name["sightings"]] == [
        ("192.0.2.44", "pihole.query")]
    assert [x["device"] for x in by_name["lookups_found"]] == ["192.0.2.44"]
    # One device across both sensors in the summary.
    acme = auth_client.get(URL).json()["tenants"][0]
    assert [d["devices"] for d in acme["top_domains"]] == [1]


def test_search_by_domain_limit_and_truncation(auth_client, seeded):
    op = _op(auth_client, "alice", "analyst")
    _elevate(auth_client, op)
    body = auth_client.post(SEARCH, json={"tenant": A, "domain": SECRET_DOMAINS[0],
                                          "limit": 2}).json()
    assert len(body["sightings"]) == 2 and body["sightings_truncated"] is True
    assert len(body["lookups_found"]) == 2 and body["lookups_found_truncated"] is True
