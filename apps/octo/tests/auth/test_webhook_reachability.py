"""Webhook reachability — "did the vendor's request ever REACH us?", for every
webhook-capable adapter.

In production a vendor's "Test Webhook" answered 403 to the operator although
the request never arrived: something in front of the ingest hostname blocked
it. The receivers never answer 403, but nothing in the product said "no
webhook has ever reached me", so it read as the product's fault.

Everything here runs the REAL app: the real webhook routes, the real rate
limiter, the real receipt recorder, the real vault and a real registry.db
(migration 032). Nothing about the behaviour under test is stubbed — the only
stand-in is the adapter class used to CREATE an instance, which never touches
a webhook (the routes build the real Datto / Resend adapters themselves).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import sqlite3
import time

import pytest

from apps.octo import client_provisioning, paths
from apps.octo.instances import create_instance, tenant_map, webhook_receipt
from apps.octo.instances.tenant_map import TenantMapping
from apps.octo.tests.auth.test_adapter_catalog import _login, _with_test_registry
from apps.octo.tests.auth.test_adapter_instance_endpoint import (  # noqa: F401
    _StubAdapter,
    _register_stub_datto,
    instance_endpoint_client,
)

_CREATE = "/api/v1/admin/adapters/datto/instances"
_HOOK = "/api/v1/webhooks/datto"
_INGEST = "https://ingest.example.test"

_SVIX_KEY = b"fixture-signing-key-0123456789ab"
_SVIX_SECRET = "whsec_" + base64.b64encode(_SVIX_KEY).decode()


class _StubResend(_StubAdapter):
    """Registered under the real `resend` slug so its card exists; the webhook
    route itself uses the real ResendSourceAdapter."""
    vendor_slug = "resend"
    vendor_display_name = "Stub Resend"
    delivery_mode = "push"


@pytest.fixture
def hooks(instance_endpoint_client, monkeypatch):  # noqa: F811
    """(client, cookies) with a clean recorder and an ingest hostname."""
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", _INGEST)
    webhook_receipt.stop_flusher()
    webhook_receipt.reset()
    client = instance_endpoint_client
    _register_stub_datto(client)
    client.app.state.adapter_registry.register_adapter_class(_StubResend)
    cookies = client.login(client.provision_operator("alice", "password1234567"))
    yield client, cookies
    webhook_receipt.stop_flusher()
    webhook_receipt.reset()


def _create_datto(client, cookies, *, enable_webhook=True, creds=None) -> tuple[int, str | None]:
    body: dict = {"credentials": creds or {"DATTO_API_KEY": "k", "DATTO_WEBHOOK_SECRET": ""}}
    if enable_webhook is not None:
        body["enable_webhook"] = enable_webhook
    r = client.post(_CREATE, json=body, cookies=cookies)
    assert r.status_code == 200, r.text
    generated = r.json()["generated_webhook_secret"]
    return r.json()["instance"]["id"], (generated or {}).get("header_value")


def _card(client, cookies, slug="datto") -> dict:
    r = client.get("/api/v1/integrations", cookies=cookies)
    assert r.status_code == 200, r.text
    return r.json()["instances"][slug]


def _listed(client, cookies, slug="datto") -> dict:
    r = client.get("/api/v1/admin/adapters/instances", cookies=cookies)
    assert r.status_code == 200, r.text
    (row,) = [i for i in r.json()["instances"] if i["vendor_slug"] == slug]
    return row


def _map_site(instance_id: int, site: str = "site-1", slug: str = "client-a") -> None:
    client_provisioning.create_client(slug, "Client A")
    tenant_map.set_mappings(instance_id, [TenantMapping(site, slug)])


def _alert(site: str = "site-1", uid: str = "a-1") -> dict:
    return {
        "event": "alert_raised", "alertUid": uid, "siteUid": site,
        "alertContext": {"message": "An account failed to log in"},
        "device": {"hostname": "WS-1"},
    }


def _stored_rows() -> list[tuple]:
    reg = sqlite3.connect(paths.registry_db_path())
    try:
        return reg.execute(
            "SELECT adapter_instance_id, first_accepted_at, last_accepted_at, "
            "last_rejected_at, last_reject_reason FROM adapter_webhook_receipts "
            "ORDER BY adapter_instance_id"
        ).fetchall()
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# "Never" — the production case
# ---------------------------------------------------------------------------

def test_nothing_has_arrived_says_so_with_calm_edge_guidance(hooks):
    client, cookies = hooks
    _create_datto(client, cookies)

    for payload in (_card(client, cookies), _listed(client, cookies)):
        receipt = payload["webhook_receipt"]
        assert receipt["enabled"] is True and receipt["usable"] is True
        assert receipt["ever_reached"] is False
        assert receipt["last_accepted_at"] is None and receipt["last_rejected_at"] is None
        assert receipt["accepted_since_start"] == receipt["rejected_since_start"] == 0
        assert receipt["recent_rejections"] == []
        guidance = " ".join(receipt["guidance"])
        # Where to look, in the operator's words — and that it is NOT Athena.
        assert "stopped BEFORE Athena" in guidance
        assert "never answers 403" in guidance and "2xx, 401, 422 or 429" in guidance
        for word in ("403", "CDN", "WAF", "bot protection", "access gate"):
            assert word in guidance
        assert "INGEST hostname" in guidance and "not the console hostname" in guidance
        assert "free tiers cannot exempt a single hostname" in guidance
        # Guidance is not a fault: it never rides in `warnings`.
        assert payload["warnings"] == []
        # Generic: no vendor, CDN product or deployment is named.
        assert "Datto" not in guidance and "example.test" not in guidance


def test_poll_only_and_webhook_less_instances_say_nothing_about_webhooks(hooks):
    client, cookies = hooks
    _create_datto(client, cookies, enable_webhook=False,
                  creds={"DATTO_API_KEY": "k"})
    r = client.post(
        "/api/v1/admin/adapters/stub-adapter/instances",
        json={"credentials": {"API_KEY": "sample-fixture-key"}}, cookies=cookies,
    )
    assert r.status_code == 200, r.text

    for slug in ("datto", "stub-adapter"):
        receipt = _card(client, cookies, slug)["webhook_receipt"]
        assert receipt["enabled"] is False and receipt["guidance"] == []
        assert _card(client, cookies, slug)["receives_webhooks"] is False


# ---------------------------------------------------------------------------
# Accepted
# ---------------------------------------------------------------------------

def test_an_accepted_webhook_is_recorded_and_ends_the_guidance(hooks):
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    _map_site(iid)

    r = client.post(_HOOK, json=_alert(), headers={"X-Webhook-Token": token})
    assert r.status_code == 200 and r.json()["ingested"] is True, r.text

    for payload in (_card(client, cookies), _listed(client, cookies)):
        receipt = payload["webhook_receipt"]
        assert receipt["last_accepted_at"] is not None
        assert receipt["ever_reached"] is True
        assert receipt["accepted_since_start"] == 1 and receipt["rejected_since_start"] == 0
        assert receipt["guidance"] == [] and receipt["recent_rejections"] == []
    assert token not in client.get("/api/v1/integrations", cookies=cookies).text


# ---------------------------------------------------------------------------
# Every rejection class
# ---------------------------------------------------------------------------

def test_token_malformed_and_unmapped_rejections_are_classed_and_explained(hooks):
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    good = {"X-Webhook-Token": token}

    assert client.post(_HOOK, json=_alert()).status_code == 401                # missing
    assert client.post(_HOOK, json=_alert(),
                       headers={"X-Webhook-Token": "guess"}).status_code == 401  # wrong
    assert client.post(_HOOK, content=b"{not json", headers=good).status_code == 422
    assert client.post(_HOOK, content=b"[1, 2]", headers=good).status_code == 422
    # Unattributable events are HELD (quarantine), never dropped — a received,
    # verified, STORED webhook: it advances "last received" and is NOT a
    # rejection (the card's quarantine line states the held count, once —
    # Datto's Test Webhook holds every time and must not read as failing).
    held = client.post(_HOOK, json=_alert("site-nobody-mapped"), headers=good)
    assert held.status_code == 200 and held.json()["ingested"] is False
    assert held.json()["reason"] == "quarantined"
    unroutable = client.post(_HOOK, json={"alertUid": "a-9"}, headers=good)
    assert unroutable.json()["reason"] == "quarantined"
    assert unroutable.json()["quarantine_reason"] == "no-tenant-id"

    snap = webhook_receipt.snapshot(iid, "datto")
    assert snap["rejected_recent_by_reason"] == {"bad_token": 2, "malformed": 2}
    assert snap["rejected_since_start"] == 4 and snap["accepted_since_start"] == 2
    assert snap["last_reject_reason"] == "malformed" and snap["ever_reached"] is True
    assert snap["last_accepted_at"] is not None

    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["rejected_recent"] == 4
    assert receipt["recent_window"] == "since_start"
    lines = receipt["recent_rejections"]
    assert len(lines) == 2
    token_line, malformed_line = lines
    assert token_line.startswith("2 rejected since the service last started: ")
    assert "X-Webhook-Token header was missing or did not verify" in token_line
    assert "re-copy the header value" in token_line
    assert "not a JSON object" in malformed_line
    assert not any("HELD" in line for line in lines)
    card = _card(client, cookies)
    assert card["quarantined"] == 2
    assert sum("held in quarantine" in w for w in card["warnings"]) == 1
    # Requests ARE arriving: the edge is not the problem, so no edge checklist.
    assert receipt["guidance"] == []
    # Reason classes and sentences only — never what was presented.
    text = client.get("/api/v1/integrations", cookies=cookies).text
    assert token not in text and "guess" not in text


def test_a_verified_webhook_that_fails_to_store_still_counts_as_having_arrived(hooks):
    """A 5xx makes the vendor retry — but the request DID reach Athena, so the
    card must stop saying that none has (and must not blame the edge)."""
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    _map_site(iid)
    paths.client_db_path("client-a", "events").write_bytes(b"not a database " * 64)

    with pytest.raises(sqlite3.DatabaseError):      # TestClient re-raises the 500
        client.post(_HOOK, json=_alert(), headers={"X-Webhook-Token": token})

    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["ever_reached"] is True and receipt["guidance"] == []
    assert receipt["rejected_recent_by_reason"] == {"store_failed": 1}
    (line,) = receipt["recent_rejections"]
    assert "storing the event failed inside Athena" in line and "server log" in line


def test_a_request_to_an_instance_with_no_usable_secret_is_not_configured(hooks):
    client, cookies = hooks
    # Legacy create (no enable_webhook answer) with a blank token: saved, but
    # nothing can ever verify.
    iid, token = _create_datto(client, cookies, enable_webhook=None)
    assert token is None

    assert client.post(_HOOK, json=_alert(),
                       headers={"X-Webhook-Token": "anything"}).status_code == 401
    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["rejected_recent_by_reason"] == {"not_configured": 1}
    (line,) = receipt["recent_rejections"]
    assert "no usable webhook secret" in line
    assert receipt["guidance"] == []


def test_the_replay_window_is_its_own_class(hooks):
    client, cookies = hooks
    record = create_instance(
        vendor_slug="resend", display_name="Resend",
        credentials_dict={"RESEND_API_KEY": "k", "RESEND_WEBHOOK_SECRET": _SVIX_SECRET},
        instance_config={"webhooks": "on"},
    )
    body = b'{"type": "email.delivered", "data": {"email_id": "e-1"}}'

    def _signed(ts: int) -> dict:
        signed = f"msg_1.{ts}.".encode() + body
        sig = base64.b64encode(hmac.new(_SVIX_KEY, signed, hashlib.sha256).digest()).decode()
        return {"svix-id": "msg_1", "svix-timestamp": str(ts),
                "svix-signature": f"v1,{sig}", "content-type": "application/json"}

    hook = "/api/v1/webhooks/resend"
    # Correctly signed, but an hour old: a replay (or a clock far off).
    assert client.post(hook, content=body,
                       headers=_signed(int(time.time()) - 3600)).status_code == 401
    # Fresh timestamp, wrong signature.
    forged = _signed(int(time.time())) | {"svix-signature": "v1,AAAA"}
    assert client.post(hook, content=body, headers=forged).status_code == 401

    snap = webhook_receipt.snapshot(record.id, "resend")
    assert snap["rejected_recent_by_reason"] == {"bad_token": 1, "replay_window": 1}
    lines = _card(client, cookies, "resend")["webhook_receipt"]["recent_rejections"]
    bad, replay = lines
    # A vendor-issued signing secret has no "header value" to re-copy.
    assert "signature did not verify" in bad and "header value" not in bad
    assert "Webhook Signing Secret" in bad
    assert "5 minutes" in replay and "time sync" in replay


def test_the_job_output_relay_is_not_the_vendors_webhook(hooks):
    """Endpoints post there, not the vendor's cloud: it proves nothing about
    whether the VENDOR can reach the ingest hostname."""
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)
    r = client.post("/api/v1/webhooks/datto/job-output", json={},
                    headers={"X-Webhook-Token": "guess"})
    assert r.status_code == 401
    assert webhook_receipt.snapshot(iid, "datto")["ever_reached"] is False
    assert webhook_receipt.webhook_vendor_for_path("/api/v1/webhooks/datto/job-output") is None
    assert webhook_receipt.webhook_vendor_for_path("/api/v1/webhooks/datto/") == "datto"
    assert webhook_receipt.webhook_vendor_for_path("/api/v1/webhooks/" + "x" * 500) is None


# ---------------------------------------------------------------------------
# A flood from the internet: no write amplification, bounded memory
# ---------------------------------------------------------------------------

def test_a_flood_of_bad_requests_costs_one_write_not_one_per_request(hooks, monkeypatch):
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)

    writes: list[str] = []
    real_connect = webhook_receipt.connect

    def _counting_connect(path, read_only=False):
        if not read_only:
            writes.append(str(path))
        return real_connect(path, read_only=read_only)

    monkeypatch.setattr(webhook_receipt, "connect", _counting_connect)

    # The REAL flusher thread, holding off an hour between writes.
    webhook_receipt.start_flusher(paths.registry_db_path(), interval_sec=3600)
    statuses = [
        client.post(_HOOK, json=_alert(), headers={"X-Webhook-Token": f"guess-{i}"}).status_code
        for i in range(200)
    ]
    # The real rate limiter cut in part-way (the fixture's own POSTs share the
    # per-minute budget); both outcomes reached Athena and both count.
    refused, throttled = statuses.count(401), statuses.count(429)
    assert refused + throttled == 200 and refused >= 100 and throttled >= 50

    deadline = time.monotonic() + 5.0
    while not writes and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.2)  # anything that was going to write again has had its chance
    assert len(writes) == 1, "200 unauthenticated requests must not cost 200 writes"

    snap = webhook_receipt.snapshot(iid, "datto")
    assert snap["rejected_recent_by_reason"] == {
        "bad_token": refused, "rate_limited": throttled,
    }
    # Bounded memory: minute buckets, not one entry per request.
    with webhook_receipt._lock:
        entries = [webhook_receipt._instances[iid], webhook_receipt._vendors["datto"]]
    assert all(len(e.recent) <= 2 for e in entries)

    lines = _card(client, cookies)["webhook_receipt"]["recent_rejections"]
    assert any(
        line.startswith(f"{throttled} rejected") and "answered 429" in line
        for line in lines
    )

    # Shutdown writes what arrived during the hold-off — once.
    webhook_receipt.stop_flusher()
    assert len(writes) == 2
    ((row_id, first_ok, last_ok, last_bad, reason),) = _stored_rows()
    assert row_id == iid and first_ok is None and last_ok is None
    assert last_bad == snap["last_rejected_at"] and reason == snap["last_reject_reason"]


def test_recording_happens_in_memory_only_on_the_request_path(hooks, monkeypatch):
    """No flusher running (as in every unit test): a webhook must not open the
    registry for bookkeeping at all — nor go through flush() to try. (flush()
    swallows every Exception by design, so a raising `connect` alone would
    not notice a synchronous flush on the request path; the calls are
    counted instead.)"""
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    assert webhook_receipt._flusher is None

    def _no_db(*a, **k):
        raise AssertionError("the webhook request path must not touch the receipt store")

    flushes: list[tuple] = []
    monkeypatch.setattr(webhook_receipt, "connect", _no_db)
    monkeypatch.setattr(webhook_receipt, "flush", lambda *a, **k: flushes.append(a) or 0)
    assert client.post(_HOOK, json=_alert("site-x"),
                       headers={"X-Webhook-Token": token}).status_code == 200
    assert client.post(_HOOK, json=_alert()).status_code == 401
    with webhook_receipt._lock:
        # The held (quarantined) one is a RECEIVED webhook; the 401 a rejection.
        assert webhook_receipt._instances[iid].accepted == 1
        assert webhook_receipt._instances[iid].rejected == 1
    assert flushes == [], "a webhook request must never flush receipts itself"


def test_a_broken_recorder_never_fails_or_changes_a_webhook_response(hooks, monkeypatch):
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    _map_site(iid)

    def _boom():
        raise RuntimeError("clock exploded")

    with monkeypatch.context() as broken:
        broken.setattr(webhook_receipt, "_clock", _boom)
        ok = client.post(_HOOK, json=_alert(), headers={"X-Webhook-Token": token})
        assert ok.status_code == 200 and ok.json()["ingested"] is True
        assert client.post(_HOOK, json=_alert()).status_code == 401
        assert client.post(_HOOK, content=b"nope",
                           headers={"X-Webhook-Token": token}).status_code == 422


# ---------------------------------------------------------------------------
# Restart semantics — "never" has to stay true across a restart
# ---------------------------------------------------------------------------

def test_receipts_survive_a_restart_and_counts_say_they_did_not(hooks):
    client, cookies = hooks
    iid, token = _create_datto(client, cookies)
    _map_site(iid)
    assert client.post(_HOOK, json=_alert(), headers={"X-Webhook-Token": token}).status_code == 200
    assert client.post(_HOOK, json=_alert()).status_code == 401
    before = webhook_receipt.snapshot(iid, "datto")

    assert webhook_receipt.flush() == 1
    assert webhook_receipt.flush() == 0          # nothing dirty → no write
    webhook_receipt.reset()                      # the process restarted

    after = webhook_receipt.snapshot(iid, "datto")
    assert after["last_accepted_at"] == before["last_accepted_at"]
    assert after["last_rejected_at"] == before["last_rejected_at"]
    assert after["last_reject_reason"] == "bad_token" and after["ever_reached"] is True
    # Counters are in-memory and say so.
    assert after["accepted_since_start"] == after["rejected_since_start"] == 0
    assert after["rejected_recent"] == 0
    assert after["counting_since"] >= before["counting_since"]

    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["last_accepted_at"] == before["last_accepted_at"]
    assert receipt["guidance"] == []             # it HAS reached Athena — still true
    assert receipt["recent_rejections"] == []
    assert "X-Webhook-Token header" in receipt["last_reject_detail"]


def test_never_is_still_never_after_a_restart(hooks):
    client, cookies = hooks
    _create_datto(client, cookies)
    assert webhook_receipt.flush() == 0
    webhook_receipt.reset()
    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["ever_reached"] is False and receipt["guidance"]
    assert _stored_rows() == []


def test_first_accepted_is_kept_and_an_older_flush_never_rewinds_the_row(hooks, monkeypatch):
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)
    now = [1_800_000_000.0]
    monkeypatch.setattr(webhook_receipt, "_clock", lambda: now[0])
    webhook_receipt.reset()

    webhook_receipt.record_accepted(iid)
    webhook_receipt.flush()
    ((_, first, last, _bad, _why),) = _stored_rows()
    assert first == last == "2027-01-15T08:00:00.000Z"

    webhook_receipt.reset()                      # restart
    now[0] += 600
    webhook_receipt.record_accepted(iid)
    webhook_receipt.record_rejected(iid, "malformed")
    webhook_receipt.flush()
    ((_, first, last, bad, why),) = _stored_rows()
    assert first == "2027-01-15T08:00:00.000Z"   # the FIRST ever, not this process's
    assert last == bad == "2027-01-15T08:10:00.000Z" and why == "malformed"


def test_the_rolling_window_is_an_hour_and_is_worded_by_what_it_covers(hooks, monkeypatch):
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)
    now = [1_800_000_000.0]
    monkeypatch.setattr(webhook_receipt, "_clock", lambda: now[0])
    webhook_receipt.reset()

    for _ in range(12):
        webhook_receipt.record_rejected(iid, "bad_token")
    (line,) = _card(client, cookies)["webhook_receipt"]["recent_rejections"]
    assert line.startswith("12 rejected since the service last started: ")

    now[0] += 3000                               # 50 min later, up > 1 h soon
    webhook_receipt.record_rejected(iid, "bad_token")
    now[0] += 900                                # 65 min after the first twelve
    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["recent_window"] == "hour"
    (line,) = receipt["recent_rejections"]
    assert line.startswith("1 rejected in the last hour: ")
    assert receipt["rejected_since_start"] == 13   # the total is not windowed

    now[0] += 7200                               # quiet for two hours
    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["recent_rejections"] == [] and receipt["rejected_recent"] == 0
    assert "X-Webhook-Token header" in receipt["last_reject_detail"]


# ---------------------------------------------------------------------------
# Flush safety
# ---------------------------------------------------------------------------

def test_flush_never_creates_a_database_or_a_row_for_an_unknown_instance(hooks, tmp_path):
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)

    webhook_receipt.record_rejected(iid, "bad_token")
    missing = tmp_path / "elsewhere" / "registry.db"
    assert webhook_receipt.flush(missing) == 0 and not missing.exists()

    # A registry that predates migration 032: no raise, and nothing is lost —
    # the receipt stays dirty and lands on the next good flush.
    stale = tmp_path / "stale-registry.db"
    sqlite3.connect(stale).close()
    assert webhook_receipt.flush(stale) == 0
    assert webhook_receipt.snapshot(iid, "datto", db_path=stale)["ever_reached"] is True

    webhook_receipt.record_rejected(987_654, "bad_token")   # no such instance
    webhook_receipt.flush()
    assert [row[0] for row in _stored_rows()] == [iid]


def test_disable_forgets_memory_and_a_replacement_starts_at_never(hooks, monkeypatch):
    client, cookies = hooks
    iid, _token = _create_datto(client, cookies)
    now = [1_800_000_000.0]
    monkeypatch.setattr(webhook_receipt, "_clock", lambda: now[0])
    assert client.post(_HOOK, json=_alert()).status_code == 401
    webhook_receipt.flush()
    assert _card(client, cookies)["webhook_receipt"]["ever_reached"] is True
    history = _stored_rows()                     # the row as it is BEFORE the disable
    assert [row[0] for row in history] == [iid] and history[0][3] == "2027-01-15T08:00:00.000Z"

    d = client.post(f"/api/v1/admin/adapters/instances/{iid}/disable",
                    json={"reason": "fixture: replace the token"}, cookies=cookies)
    assert d.status_code == 200, d.text
    # While disabled, nothing is attributed (there is no card to show it on)…
    now[0] += 600                                # a LATER rejection, which would win an upsert
    assert client.post(_HOOK, json=_alert()).status_code == 401
    webhook_receipt.record_rejected(iid, "bad_token")
    with webhook_receipt._lock:
        assert webhook_receipt._instances[iid].last_rejected_at == "2027-01-15T08:10:00.000Z"
    webhook_receipt.flush()                      # …and a disabled row is never written
    assert _stored_rows() == history

    new_id, _new_token = _create_datto(client, cookies)
    assert new_id != iid
    receipt = _card(client, cookies)["webhook_receipt"]
    assert receipt["ever_reached"] is False and receipt["guidance"]
    assert receipt["rejected_since_start"] == 0
    assert _stored_rows() == history             # history kept, untouched


# ---------------------------------------------------------------------------
# The no-secret defect: never claim a path works that cannot
# ---------------------------------------------------------------------------

def test_an_instance_without_a_usable_secret_is_not_reported_as_receiving(hooks):
    client, cookies = hooks
    _create_datto(client, cookies, enable_webhook=None)      # saved with a blank token

    for payload in (_card(client, cookies), _listed(client, cookies)):
        assert payload["receives_webhooks"] is False
        receipt = payload["webhook_receipt"]
        assert receipt["enabled"] is True and receipt["usable"] is False
        # The fix is the secret, not the edge: the warning says so, and the
        # edge checklist stays out of the way.
        assert receipt["guidance"] == []
        (warning,) = payload["warnings"]
        assert "rejected (401)" in warning


def test_an_instance_with_a_usable_secret_is(hooks):
    client, cookies = hooks
    _create_datto(client, cookies)
    assert _card(client, cookies)["receives_webhooks"] is True
    assert _listed(client, cookies)["receives_webhooks"] is True


# ---------------------------------------------------------------------------
# Onboarding: the same guidance for EVERY webhook-capable adapter
# ---------------------------------------------------------------------------

def test_every_webhook_capable_adapter_gets_the_shared_edge_step(auth_client, monkeypatch):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", _INGEST)
    from apps.octo.adapters.resend import ResendSourceAdapter
    from apps.octo.instances.webhook_auth import WEBHOOK_SECRET_FIELDS

    op = auth_client.provision_operator("alice", "pw1234567890", athena_role="admin")
    cookies = _login(auth_client, op)
    _with_test_registry(auth_client).register_adapter_class(ResendSourceAdapter)
    r = auth_client.get("/api/v1/admin/adapters/catalog", cookies=cookies)
    assert r.status_code == 200, r.text
    adapters = {a["vendor_slug"]: a for a in r.json()["adapters"]}

    assert set(WEBHOOK_SECRET_FIELDS) <= set(adapters)      # datto AND resend
    for slug in WEBHOOK_SECRET_FIELDS:
        steps = adapters[slug]["onboarding"]["steps"]
        last = steps[-1]
        assert last["title"] == f"{len(steps)} · {webhook_receipt.EDGE_STEP_TITLE}"
        assert last["body"] == webhook_receipt.edge_step_body()
        assert "Last webhook received" in last["body"]
        assert "stopped BEFORE Athena" in last["body"] and "INGEST hostname" in last["body"]
        assert "Edge requirements for the ingest hostname" in last["body"]
        # Platform text: no vendor named, so it is right for the next adapter too.
        assert "Datto" not in last["body"] and "Resend" not in last["body"]
        assert [s["title"] for s in steps].count(last["title"]) == 1

    # A poll-only adapter has no webhook to be blocked.
    wazuh_steps = (adapters["wazuh"]["onboarding"] or {}).get("steps", [])
    assert all(webhook_receipt.EDGE_STEP_TITLE not in s["title"] for s in wazuh_steps)
