"""Resend webhook receiver — signature verification + routing/ingest."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import pytest

from apps.octo.api.errors import APIError
from apps.octo.api.routers import webhooks

SECRET_CORE = base64.b64encode(b"super-secret-key-bytes").decode()
SECRET = "whsec_" + SECRET_CORE


class _FakeRequest:
    def __init__(self, body: bytes, headers=None):
        self._body = body
        self.headers = headers or {}

    async def body(self) -> bytes:
        return self._body


def _record(*, default_tenant_slug=None, cred_ref="ref-1"):
    return SimpleNamespace(
        vendor_slug="resend", cred_ref=cred_ref, default_tenant_slug=default_tenant_slug
    )


def _svix_headers(body: bytes, *, msg_id="msg_1", ts=None):
    # Default to NOW: the receiver enforces a ±5 min replay window, and the
    # timestamp is inside the signed content so it can't be patched afterwards.
    ts = str(int(time.time())) if ts is None else ts
    key = base64.b64decode(SECRET_CORE)
    signed = f"{msg_id}.{ts}.".encode() + body
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {"svix-id": msg_id, "svix-timestamp": ts, "svix-signature": f"v1,{sig}"}


def _run(coro):
    return asyncio.run(coro)


CREDS = {"RESEND_WEBHOOK_SECRET": SECRET}


def _signed(body: bytes) -> _FakeRequest:
    """A correctly-signed delivery — the only kind the handler accepts."""
    return _FakeRequest(body, headers=_svix_headers(body))


def _patch(monkeypatch, *, instance, creds, sink_records, sink_error=None):
    monkeypatch.setattr(
        webhooks, "list_instances", lambda **k: ([instance] if instance else [])
    )
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: creds))

    class _FakeSink:
        def ingest(self, tenant, source, event):
            if sink_error is not None:
                raise sink_error
            sink_records.append((tenant, source, event))

    monkeypatch.setattr(webhooks, "SqliteIngestSink", _FakeSink)


# --- signature verification ---

def test_signature_valid():
    body = b'{"type":"email.bounced"}'
    assert webhooks._verify_svix_signature(SECRET, _svix_headers(body), body) is True


def test_signature_tampered_body_fails():
    body = b'{"type":"email.bounced"}'
    headers = _svix_headers(body)
    assert webhooks._verify_svix_signature(SECRET, headers, b'{"type":"x"}') is False


def test_signature_missing_headers_fails():
    assert webhooks._verify_svix_signature(SECRET, {}, b"{}") is False


# --- replay window: |now - svix-timestamp| <= 300 s, integer only ---

@pytest.mark.parametrize("offset", [-301, -3600, 301, 3600, -(23 * 365 * 86400)])
def test_correctly_signed_but_stale_or_future_timestamp_is_rejected(offset):
    """The HMAC is valid — only freshness fails. One captured request must
    not be re-injectable forever."""
    body = b'{"type":"email.bounced"}'
    headers = _svix_headers(body, ts=str(int(time.time()) + offset))
    assert webhooks._verify_svix_signature(SECRET, headers, body) is False


@pytest.mark.parametrize("offset", [-290, 0, 290])
def test_timestamp_inside_the_window_is_accepted(offset):
    body = b'{"type":"email.bounced"}'
    headers = _svix_headers(body, ts=str(int(time.time()) + offset))
    assert webhooks._verify_svix_signature(SECRET, headers, body) is True


@pytest.mark.parametrize("ts", ["soon", "1.5e9", "1700000000.5", "+1700000000",
                                " 1700000000", "-5", "１７０００００００００"])
def test_non_integer_timestamp_is_rejected_even_when_signed(ts):
    body = b'{"type":"email.bounced"}'
    assert webhooks._verify_svix_signature(SECRET, _svix_headers(body, ts=ts), body) is False


def test_handler_rejects_a_replayed_delivery_with_the_generic_401(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(default_tenant_slug="acme"), creds=CREDS,
           sink_records=sink)
    body = json.dumps({"type": "email.delivered",
                       "data": {"email_id": "em-old", "to": ["bob@example.com"]}}).encode()
    stale = _FakeRequest(body, headers=_svix_headers(body, ts="1000000000"))  # 2001
    with pytest.raises(APIError) as ei:
        _run(webhooks.resend_webhook(stale))
    assert ei.value.code == "AUTH_INVALID" and sink == []


# --- handler ---

def test_handler_ingests_with_tenant_tag(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(), creds=CREDS, sink_records=sink)
    body = json.dumps({
        "type": "email.bounced",
        "data": {"email_id": "em1", "to": ["alice@example.com"],
                 "tags": [{"name": "octo_tenant", "value": "acme"}]},
    }).encode()
    res = _run(webhooks.resend_webhook(_signed(body)))
    assert res["ingested"] is True and res["tenant"] == "acme"
    assert sink and sink[0][0] == "acme" and sink[0][1] == "resend"


def test_handler_no_instance_is_the_generic_401_not_a_404(monkeypatch, caplog):
    # A 404 here let an unauthenticated caller enumerate which integrations
    # exist. The operator-facing reason goes to the log instead.
    _patch(monkeypatch, instance=None, creds={}, sink_records=[])
    with caplog.at_level("WARNING", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:
            _run(webhooks.resend_webhook(_FakeRequest(b"{}")))
    assert ei.value.code == "AUTH_INVALID"
    assert "no active resend integration" in caplog.text


def test_handler_bad_signature_rejected(monkeypatch):
    _patch(monkeypatch, instance=_record(),
           creds={"RESEND_WEBHOOK_SECRET": SECRET}, sink_records=[])
    body = b'{"type":"email.bounced","data":{"email_id":"x"}}'
    with pytest.raises(APIError) as ei:
        _run(webhooks.resend_webhook(_FakeRequest(body, headers={})))
    assert ei.value.code == "AUTH_INVALID"


def test_handler_valid_signature_ingests(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(default_tenant_slug="acme"),
           creds={"RESEND_WEBHOOK_SECRET": SECRET}, sink_records=sink)
    body = json.dumps({"type": "email.delivered",
                       "data": {"email_id": "em2", "to": ["bob@example.com"]}}).encode()
    res = _run(webhooks.resend_webhook(_FakeRequest(body, headers=_svix_headers(body))))
    assert res["ingested"] is True and res["tenant"] == "acme"


def test_handler_unroutable_returns_accepted_not_ingested(monkeypatch):
    sink: list = []
    _patch(monkeypatch, instance=_record(default_tenant_slug=None), creds=CREDS, sink_records=sink)
    body = json.dumps({"type": "email.delivered",
                       "data": {"email_id": "em3", "to": ["bob@example.com"]}}).encode()
    res = _run(webhooks.resend_webhook(_signed(body)))
    assert res["ingested"] is False and res["reason"] == "unroutable"
    assert sink == []


def test_handler_tenant_not_provisioned(monkeypatch):
    _patch(monkeypatch, instance=_record(default_tenant_slug="ghost"), creds=CREDS,
           sink_records=[], sink_error=FileNotFoundError("no db"))
    body = json.dumps({"type": "email.bounced",
                       "data": {"email_id": "em4", "to": ["bob@example.com"]}}).encode()
    res = _run(webhooks.resend_webhook(_signed(body)))
    assert res["ingested"] is False and res["reason"] == "tenant-not-provisioned"


# --- fail closed: no secret configured ---

@pytest.mark.parametrize("creds", [{}, {"RESEND_WEBHOOK_SECRET": ""},
                                   {"RESEND_WEBHOOK_SECRET": "  "},
                                   {"RESEND_WEBHOOK_SECRET": None}])
def test_handler_no_secret_fails_closed(monkeypatch, caplog, creds):
    sink: list = []
    _patch(monkeypatch, instance=_record(default_tenant_slug="acme"), creds=creds,
           sink_records=sink)
    body = json.dumps({"type": "email.delivered",
                       "data": {"email_id": "em5", "to": ["bob@example.com"]}}).encode()
    # Even a request carrying a well-formed signature is refused: with no
    # secret on the instance there is nothing to verify it against.
    for request in (_FakeRequest(body), _signed(body)):
        with caplog.at_level("ERROR", logger=webhooks.logger.name):
            with pytest.raises(APIError) as ei:
                _run(webhooks.resend_webhook(request))
        assert ei.value.code == "AUTH_INVALID"
    assert sink == []
    # The operator-visible line names the exact field to configure.
    assert "RESEND_WEBHOOK_SECRET is not set" in caplog.text


def test_handler_empty_key_secret_does_not_verify_everything(monkeypatch):
    # "whsec_" is non-blank but decodes to an EMPTY hmac key, which a caller
    # could forge against. A signature made with that empty key must not pass.
    _patch(monkeypatch, instance=_record(default_tenant_slug="acme"),
           creds={"RESEND_WEBHOOK_SECRET": "whsec_"}, sink_records=[])
    body = b'{"type":"email.delivered","data":{"email_id":"em6"}}'
    now = str(int(time.time()))  # fresh, so ONLY the empty key is at issue
    forged = base64.b64encode(
        hmac.new(b"", f"msg_1.{now}.".encode() + body, hashlib.sha256).digest()
    ).decode()
    headers = {"svix-id": "msg_1", "svix-timestamp": now,
               "svix-signature": f"v1,{forged}"}
    with pytest.raises(APIError) as ei:
        _run(webhooks.resend_webhook(_FakeRequest(body, headers=headers)))
    assert ei.value.code == "AUTH_INVALID"


@pytest.mark.parametrize("bad", ["whsec_", "whsec_!!!not-base64!!!", "whsec_abc"])
def test_set_but_unusable_secret_is_as_loud_as_an_unset_one(monkeypatch, caplog, bad):
    """Previously: 401 with NOTHING in the log and no UI warning, so every
    webhook was refused and nobody was told why."""
    _patch(monkeypatch, instance=_record(default_tenant_slug="acme"),
           creds={"RESEND_WEBHOOK_SECRET": bad}, sink_records=[])
    body = b'{"type":"email.delivered","data":{"email_id":"em8"}}'
    with caplog.at_level("ERROR", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:
            _run(webhooks.resend_webhook(_signed(body)))
    assert ei.value.code == "AUTH_INVALID"
    assert "[webhook:resend] REJECTED" in caplog.text
    assert "RESEND_WEBHOOK_SECRET is set but unusable" in caplog.text
    # The value itself is never echoed (the help text mentions the 'whsec_'
    # prefix, so check the part after it).
    tail = bad[len("whsec_"):]
    assert not tail or tail not in caplog.text


def test_rejections_are_indistinguishable_to_the_caller(monkeypatch):
    # No instance, unset secret, unusable secret, bad signature and a stale
    # replay all return the same code + message — the public endpoint must not
    # tell a prober which integrations exist or what state they are in.
    body = b'{"type":"email.delivered","data":{"email_id":"em7"}}'
    stale = _FakeRequest(body, headers=_svix_headers(body, ts="1000000000"))
    seen = set()
    for instance, creds, request in (
        (None, {}, _FakeRequest(body)),
        (_record(), {}, _FakeRequest(body)),
        (_record(), {"RESEND_WEBHOOK_SECRET": "whsec_"}, _FakeRequest(body)),
        (_record(), CREDS, _FakeRequest(body)),
        (_record(), CREDS, stale),
    ):
        _patch(monkeypatch, instance=instance, creds=creds, sink_records=[])
        with pytest.raises(APIError) as ei:
            _run(webhooks.resend_webhook(request))
        seen.add((ei.value.code, str(ei.value)))
    assert len(seen) == 1
