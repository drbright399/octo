"""GET /api/v1/dashboard/ti-pulse — the threat-intel pulse widget's feed.

Analyst+, scoped through the shared resolver ('*' = ACTIVE tenants only),
values MASKED server-side (the raw value never leaves the API here), each row
resolvable to its full value only through the step-up-gated
/search/indicators via its `search_ref`. Read-only, no audit row, no-store.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.api.indicator_mask import MASK, mask_indicator
from apps.octo.api.routers.search import _VALID_INDICATOR_TYPES
from apps.octo.ingest.sink import SqliteIngestSink
from apps.octo.tests.auth.test_dashboard_throughput import _login
from apps.octo.tests.auth.test_search_indicators import _elevate
from shared_adapter_contract.types import CanonicalEvent

PULSE = "/api/v1/dashboard/ti-pulse"
PW = "pw1234567890"

# One value per indicators.db CHECK type — all RFC 5737 / 3849 / 2606 /
# documentation values — with the mask the pulse must show for it.
RAW_BY_TYPE: dict[str, tuple[str, str]] = {
    "ip":     ("203.0.113.77", "203.0.x.x"),
    "ipv6":   ("2001:db8:85a3::8a2e:370:7334", "2001:db8:x:x:x:x:x:x"),
    "cidr":   ("198.51.100.0/24", "198.51.x.x/24"),
    "domain": ("example.test", "ex*****.test"),
    "url":    ("https://login-verify.example.test/reset?token=abc123",
               "https://lo*****.test/…"),
    "email":  ("alice@example.test", "a***@ex*****.test"),
    "md5":    ("0123456789abcdef0123456789abcdef", "01234567…"),
    "sha1":   ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "da39a3ee…"),
    "sha256": ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               "e3b0c442…"),
    "cve":    ("CVE-2026-0001", "CVE-2026-…"),
    "other":  ("AS64500", MASK),
}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _ago(**kw) -> str:
    return _iso(datetime.now(timezone.utc) - timedelta(**kw))


def _tenant(slug: str, status: str = "active") -> None:
    """A real provisioned tenant (registry row + events.db + indicators.db)."""
    client_provisioning.create_client(slug, slug.replace("-", " ").title())
    if status != "active":
        reg = sqlite3.connect(paths.registry_db_path())
        try:
            reg.execute("UPDATE clients SET status = ? WHERE slug = ?", (status, slug))
            reg.commit()
        finally:
            reg.close()


def _indicator(
    slug: str, value: str, type_: str = "ip", *, last_seen: str | None = None,
    context: str | None = None, hits: int = 1, deleted: bool = False,
    severity: str = "medium",
) -> int:
    seen = last_seen or _ago(minutes=5)
    conn = sqlite3.connect(paths.client_db_path(slug, "indicators"))
    try:
        cur = conn.execute(
            "INSERT INTO indicators (value, type, source, severity, confidence, "
            " context, first_seen, last_seen, hits, deleted_at) "
            "VALUES (?, ?, 'wazuh', ?, 0.5, ?, ?, ?, ?, ?)",
            (value, type_, severity, context, seen, seen, hits,
             _ago(minutes=1) if deleted else None),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _operator(auth_client, name: str, role: str, scope: list[str] | None = None) -> dict:
    # `role` is set on BOTH role rows: the fixture's API-role default is
    # admin, which would otherwise lift every operator to admin tier.
    op = auth_client.provision_operator(
        name, PW, role=role, athena_role=role, scope_slugs=scope,
    )
    _login(auth_client, op)
    return op


def _audit_count() -> int:
    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Role matrix — analyst+; a viewer is a client user and gets 403.
# ---------------------------------------------------------------------------

def test_unauthenticated_is_401(auth_client, auth_data_root):
    r = auth_client.get(PULSE)
    assert r.status_code == 401


def test_viewer_is_403(auth_client, auth_data_root):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5")
    _operator(auth_client, "bob", "viewer", ["acme-corp"])
    r = auth_client.get(PULSE)
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"
    assert "203.0" not in r.text


@pytest.mark.parametrize("role", ["analyst", "admin", "super_admin"])
def test_analyst_and_up_are_200(auth_client, auth_data_root, role):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5")
    _operator(auth_client, "alice", role)
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [i["masked_value"] for i in body["items"]] == ["203.0.x.x"]
    assert body["pool_status"] == "not_running"


def test_no_store_and_no_audit_row(auth_client, auth_data_root):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5")
    _operator(auth_client, "alice", "analyst")
    before = _audit_count()
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    assert _audit_count() == before


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def test_star_scope_excludes_offboarded_and_disabled(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex", status="offboarded")
    _tenant("initech", status="disabled")
    _indicator("acme-corp", "203.0.113.5")
    _indicator("globex", "198.51.100.9")
    _indicator("initech", "192.0.2.44")
    _operator(auth_client, "alice", "super_admin")
    body = auth_client.get(PULSE).json()
    assert {i["tenant"] for i in body["items"]} == {"acme-corp"}


def test_concrete_scope_sees_only_its_tenants(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex")
    _indicator("acme-corp", "203.0.113.5")
    _indicator("globex", "198.51.100.9")
    _operator(auth_client, "alice", "analyst", ["acme-corp"])
    body = auth_client.get(PULSE).json()
    assert [i["tenant"] for i in body["items"]] == ["acme-corp"]
    assert all(i["search_ref"].startswith("acme-corp:") for i in body["items"])


def test_scope_of_only_offboarded_tenants_is_no_tenants(auth_client, auth_data_root):
    _tenant("globex", status="offboarded")
    _indicator("globex", "198.51.100.9")
    _operator(auth_client, "alice", "analyst", ["globex"])
    body = auth_client.get(PULSE).json()
    assert body["items"] == []
    assert body["empty_reason"] == "no_tenants"
    assert body["empty_detail"]


# ---------------------------------------------------------------------------
# Masking — no raw value anywhere in the response, for every type.
# ---------------------------------------------------------------------------

def test_every_type_is_masked_and_no_raw_value_leaks(auth_client, auth_data_root):
    _tenant("acme-corp")
    for type_, (raw, _mask) in RAW_BY_TYPE.items():
        # The stored context quotes the value, as the sink's does.
        _indicator("acme-corp", raw, type_, context=f"sighting of {raw} on web-01")
    _operator(auth_client, "alice", "analyst")
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    text = r.text.lower()
    for type_, (raw, _mask) in RAW_BY_TYPE.items():
        assert raw.lower() not in text, f"raw {type_} value leaked"
    assert "sighting of" not in text  # `context` is never read
    assert "token=" not in text and "reset" not in text  # no URL path/query
    shown = {i["type"]: i["masked_value"] for i in r.json()["items"]}
    assert shown == {t: m for t, (_raw, m) in RAW_BY_TYPE.items()}


def test_rows_written_by_the_ingest_sink(auth_client, auth_data_root):
    """The one real writer: the sink records an IOC from an ingested event
    and counts repeat sightings. The pulse shows it masked, as an
    integration-sourced row, and never echoes the event summary."""
    _tenant("acme-corp")
    sink = SqliteIngestSink(publish_to_stream=False)
    for n in (1, 2):
        payload = {"n": n, "data": {"srcip": "203.0.113.9"}}
        sink.ingest("acme-corp", "wazuh", CanonicalEvent(
            vendor_event_id=f"w-{n}",
            received_at=_ago(minutes=10 - n),
            severity="high",
            indicator="203.0.113.9",
            indicator_type="ip",
            source_host="web-01",
            summary="[authentication_failures] brute force from 203.0.113.9",
            payload=payload,
            payload_sha256=hashlib.sha256(json.dumps(payload).encode()).hexdigest(),
        ))
    _operator(auth_client, "alice", "analyst")
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    [item] = r.json()["items"]
    assert item["tenant"] == "acme-corp"
    assert item["type"] == "ip"
    assert item["masked_value"] == "203.0.x.x"
    assert item["count"] == 2
    assert item["severity"] == "high"
    assert item["source_kind"] == "integration"
    assert "203.0.113.9" not in r.text
    assert "brute force" not in r.text


@pytest.mark.parametrize("type_", ["ip", "ipv6"])
def test_a_scoped_ipv6_sighting_does_not_fail_the_pulse(auth_client, auth_data_root, type_):
    """An IPv6 value with a zone id parses as an address but `exploded`
    raises on it (Python 3.12): stored through the real sink in one tenant,
    it used to 500 the pulse for every analyst whose scope held that
    tenant, hiding every other tenant's sightings too."""
    _tenant("acme-corp")
    _tenant("globex")
    _indicator("acme-corp", "203.0.113.5")
    payload = {"data": {"srcip": "2001:db8::1%eth0"}}
    SqliteIngestSink(publish_to_stream=False).ingest("globex", "wazuh", CanonicalEvent(
        vendor_event_id="w-scoped",
        received_at=_ago(minutes=1),
        severity="high",
        indicator="2001:db8::1%eth0",
        indicator_type=type_,
        source_host="web-01",
        summary="[authentication_failures] brute force",
        payload=payload,
        payload_sha256=hashlib.sha256(json.dumps(payload).encode()).hexdigest(),
    ))
    _operator(auth_client, "alice", "analyst")
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    shown = {i["tenant"]: i["masked_value"] for i in r.json()["items"]}
    assert shown == {"acme-corp": "203.0.x.x", "globex": "2001:db8:x:x:x:x:x:x"}
    assert "2001:db8::1" not in r.text and "eth0" not in r.text


# ---------------------------------------------------------------------------
# Ordering + bounds
# ---------------------------------------------------------------------------

def test_merged_newest_first_and_capped(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex")
    for n in range(30):
        _indicator("acme-corp", f"203.0.113.{n + 1}", last_seen=_ago(minutes=2 * n))
        _indicator("globex", f"198.51.100.{n + 1}", last_seen=_ago(minutes=2 * n + 1))
    _operator(auth_client, "alice", "analyst")

    body = auth_client.get(PULSE, params={"limit": 5}).json()
    seen = [i["last_seen"] for i in body["items"]]
    assert len(seen) == 5 and seen == sorted(seen, reverse=True)
    assert [i["tenant"] for i in body["items"]] == [
        "acme-corp", "globex", "acme-corp", "globex", "acme-corp",
    ]
    assert len(auth_client.get(PULSE).json()["items"]) == 20  # default cap
    assert auth_client.get(PULSE, params={"limit": 51}).status_code == 422
    assert auth_client.get(PULSE, params={"lookback_days": 31}).status_code == 422


def test_deleted_rows_are_not_shown(auth_client, auth_data_root):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5", deleted=True)
    _operator(auth_client, "alice", "analyst")
    body = auth_client.get(PULSE).json()
    assert body["items"] == []
    assert body["empty_reason"] == "no_indicators"


# ---------------------------------------------------------------------------
# Empty states say WHY
# ---------------------------------------------------------------------------

def test_empty_no_indicators_names_the_sources_that_carry_iocs(auth_client, auth_data_root):
    _tenant("acme-corp")
    _operator(auth_client, "alice", "analyst")
    body = auth_client.get(PULSE).json()
    assert body["items"] == []
    assert body["empty_reason"] == "no_indicators"
    assert body["pool_status"] == "not_running"
    for word in ("Wazuh", "UniFi", "Datto"):
        assert word in body["empty_detail"]


def test_empty_none_recent_when_only_old_sightings(auth_client, auth_data_root):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5", last_seen=_ago(days=20))
    _operator(auth_client, "alice", "analyst")
    body = auth_client.get(PULSE, params={"lookback_days": 7}).json()
    assert body["items"] == []
    assert body["empty_reason"] == "none_recent"
    assert "7 days" in body["empty_detail"]
    assert body["lookback_days"] == 7
    # A wider window finds it.
    wide = auth_client.get(PULSE, params={"lookback_days": 30}).json()
    assert [i["masked_value"] for i in wide["items"]] == ["203.0.x.x"]
    assert wide["empty_reason"] is None and wide["empty_detail"] is None


def test_empty_unavailable_when_a_store_cannot_be_read(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex")
    db = paths.client_db_path("acme-corp", "indicators")
    db.unlink()
    sqlite3.connect(db).close()  # an indicators.db with no table in it
    paths.client_db_path("globex", "indicators").write_bytes(b"not a database" * 64)
    _operator(auth_client, "alice", "analyst")
    r = auth_client.get(PULSE)
    assert r.status_code == 200, r.text
    assert r.json()["empty_reason"] == "unavailable"
    assert r.json()["unreadable_tenants"] == 2


def test_one_unreadable_store_does_not_hide_the_others(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex")
    _indicator("acme-corp", "203.0.113.5")
    paths.client_db_path("globex", "indicators").write_bytes(b"not a database" * 64)
    _operator(auth_client, "alice", "analyst")
    body = auth_client.get(PULSE).json()
    assert [i["tenant"] for i in body["items"]] == ["acme-corp"]
    assert body["empty_reason"] is None
    # ...and the list says it is partial rather than passing for complete.
    assert body["unreadable_tenants"] == 1


def test_a_complete_read_reports_no_unreadable_tenants(auth_client, auth_data_root):
    _tenant("acme-corp")
    _indicator("acme-corp", "203.0.113.5")
    _operator(auth_client, "alice", "analyst")
    assert auth_client.get(PULSE).json()["unreadable_tenants"] == 0


# ---------------------------------------------------------------------------
# search_ref → the step-up-gated search, and only there.
# ---------------------------------------------------------------------------

def test_search_ref_resolves_only_through_step_up(auth_client, auth_data_root):
    _tenant("acme-corp")
    raw = "203.0.113.200"
    _indicator("acme-corp", "198.51.100.3", last_seen=_ago(minutes=30))
    row_id = _indicator("acme-corp", raw)
    op = _operator(auth_client, "alice", "analyst")

    [item, _older] = auth_client.get(PULSE).json()["items"]
    assert item["search_ref"] == f"acme-corp:{row_id}"
    tenant, _, rid = item["search_ref"].rpartition(":")
    query = {"tenants": [tenant], "indicator_ids": [int(rid)]}

    r = auth_client.post("/api/v1/search/indicators", json=query)
    assert r.status_code == 401
    assert r.json()["code"] == "STEP_UP_REQUIRED"
    assert raw not in r.text

    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json=query)
    assert r.status_code == 200, r.text
    [hit] = r.json()["results"]
    assert (hit["client_slug"], hit["indicator_id"], hit["value"]) == (
        "acme-corp", row_id, raw,
    )

    conn = sqlite3.connect(paths.global_audit_db_path())
    try:
        after = conn.execute(
            "SELECT after_state FROM audit_log WHERE action = 'search.indicators' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    finally:
        conn.close()
    assert json.loads(after)["filters"]["indicator_ids"] == [row_id]


def test_search_ref_for_another_tenant_is_refused(auth_client, auth_data_root):
    _tenant("acme-corp")
    _tenant("globex")
    other = _indicator("globex", "198.51.100.9")
    op = _operator(auth_client, "alice", "analyst", ["acme-corp"])
    _elevate(auth_client, op)
    r = auth_client.post("/api/v1/search/indicators", json={
        "tenants": ["globex"], "indicator_ids": [other],
    })
    assert r.status_code == 403
    assert r.json()["code"] == "ISOLATION_VIOLATION"
    assert "198.51.100.9" not in r.text


# ---------------------------------------------------------------------------
# The masker itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("type_", sorted(RAW_BY_TYPE))
def test_mask_for_each_type(type_):
    raw, expected = RAW_BY_TYPE[type_]
    assert mask_indicator(raw, type_) == expected


@pytest.mark.parametrize("value,type_,expected", [
    ("", "ip", MASK),
    (None, "domain", MASK),
    ("not-an-ip", "ip", MASK),
    ("2001:db8::1", "ip", "2001:db8:x:x:x:x:x:x"),     # v6 stored as 'ip'
    ("198.51.100.0/abc", "cidr", "198.51.x.x"),
    ("abcd1234", "sha256", MASK),                       # too short to prefix
    ("zz" * 32, "sha256", MASK),                        # not hex
    ("ab.test", "domain", "*****.test"),                # short label: keep none
    ("host.acme-corp", "domain", "h*****"),             # odd last label: drop it
    ("localhost", "domain", "lo*****"),
    ("https://192.0.2.10:8443/admin", "url", "https://192.0.x.x/…"),
    ("example.test/path", "url", "ex*****.test/…"),
    ("bob@example.test", "email", "***@ex*****.test"),  # short local part
    ("CVE-bogus", "cve", MASK),
    ("anything", "mystery-type", MASK),
    # A zone id names a local interface: dropped, the address masked as usual.
    ("2001:db8::1%eth0", "ip", "2001:db8:x:x:x:x:x:x"),
    ("fe80::1%eth0", "ipv6", "fe80:0:x:x:x:x:x:x"),
    ("fe80::1%eth0/64", "cidr", "fe80:0:x:x:x:x:x:x/64"),
    ("https://[2001:db8::1%25eth0]/p", "url", "https://2001:db8:x:x:x:x:x:x/…"),
    ("203.0.113.5%eth0", "ip", MASK),                   # v4 has no zone id
])
def test_mask_edge_cases(value, type_, expected):
    assert mask_indicator(value, type_) == expected
    if value:
        assert value not in mask_indicator(value, type_)


def test_mask_never_raises(monkeypatch):
    """Whatever a per-type parser trips on, the caller gets the opaque
    mask — never an exception, never the value."""
    from apps.octo.api import indicator_mask

    def _boom(_v: str) -> str:
        raise RuntimeError("unforeseen parse")

    monkeypatch.setattr(indicator_mask, "_mask_host", _boom)
    assert mask_indicator("example.test", "domain") == MASK


def test_mask_types_cover_the_indicators_db_check_list():
    """RAW_BY_TYPE (and so the masking test above) covers every type the
    indicators table accepts — a new CHECK type must get a mask test."""
    sql = (Path(__file__).resolve().parents[2] / "migrations"
           / "002-initialize-client-dbs.sql").read_text()
    m = re.search(r"type\s+TEXT NOT NULL\s+CHECK \(type IN \(([^)]*)\)\)", sql)
    assert m, "indicators.type CHECK list not found"
    check = {t.strip().strip("'") for t in m.group(1).split(",")}
    assert set(RAW_BY_TYPE) == check
    assert set(_VALID_INDICATOR_TYPES) == check
