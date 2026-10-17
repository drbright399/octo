"""No webhook secret — stored or presented, whole or a prefix — reaches a log.

The public webhook receivers log every rejection for the operator (the
caller only ever sees one generic 401). Those log lines name the credential
FIELD and a fixed reason phrase; this pins that they never carry any part of
a secret value, on every path: not set, set but unusable, wrong token, bad
signature, and the accepted request. Every logger is captured at DEBUG.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import time
from types import SimpleNamespace

import pytest

from apps.octo.api.errors import APIError
from apps.octo.api.routers import webhooks
from apps.octo.instances import webhook_receipt

# Distinctive fixture values, so any 8-character window of one in a log is a leak.
STORED_TOKEN = "Zq7Xv9Wk3Jr5Ty8Pn2Lm4Hb6Gd1Fs0Qa-stored-fixture"
PRESENTED_TOKEN = "Kp4Rw8Nt2Vy6Bx0Mc3Ld7Hj5Gf9Sz1-presented-fixture"
SVIX_KEY = b"svix-fixture-key-Yh3Tn8Wq2Rk6Pb0"
SVIX_KEY_B64 = base64.b64encode(SVIX_KEY).decode()
SVIX_SECRET = "whsec_" + SVIX_KEY_B64
# Set but unusable (not base64): its text must not be echoed either.
UNUSABLE_KEY_PART = "Uv5Dn9Xc1Jw7Mq3!not-base64-fixture"
UNUSABLE_SVIX = "whsec_" + UNUSABLE_KEY_PART

WINDOW = 8


class _FakeRequest:
    def __init__(self, body: bytes = b"{}", headers=None):
        self._body = body
        self.headers = headers or {}
        self.query_params: dict = {}

    async def body(self) -> bytes:
        return self._body


def _windows(value: str) -> set[str]:
    return {value[i:i + WINDOW] for i in range(len(value) - WINDOW + 1)}


def _assert_no_leak(text: str, *values: str) -> None:
    for value in values:
        assert value not in text
        leaked = sorted(w for w in _windows(value) if w in text)
        assert not leaked, f"part of a secret reached the log: {leaked[:3]}"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    webhook_receipt.reset()
    # Anything past auth that would write must be stubbed by the test itself.
    monkeypatch.setattr(webhooks, "SqliteIngestSink", None)
    monkeypatch.setattr(webhooks, "JobOutputStore", None)
    yield
    webhook_receipt.reset()


def _configure(monkeypatch, vendor_slug: str, creds: dict) -> None:
    record = SimpleNamespace(
        id=1, vendor_slug=vendor_slug, cred_ref="ref-1", default_tenant_slug="tenant-a",
    )
    monkeypatch.setattr(webhooks, "list_instances", lambda **k: [record])
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: dict(creds)))


def _endpoint(path: str):
    for route in webhooks.router.routes:
        if getattr(route, "path", None) == path and "POST" in getattr(route, "methods", ()):
            return route.endpoint
    raise AssertionError(f"no POST route {path}")


def _reject(endpoint, request) -> None:
    with pytest.raises(APIError) as ei:
        asyncio.run(endpoint(request))
    assert ei.value.code == "AUTH_INVALID"


def _svix_headers(body: bytes, key: bytes) -> dict:
    msg_id, ts = "msg_fixture_1", str(int(time.time()))
    signed = f"{msg_id}.{ts}.".encode() + body
    sig = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
    return {"svix-id": msg_id, "svix-timestamp": ts, "svix-signature": f"v1,{sig}"}


@pytest.mark.parametrize("path,field", [
    ("/webhooks/datto", "DATTO_WEBHOOK_SECRET"),
    ("/webhooks/datto/job-output", "DATTO_JOB_OUTPUT_TOKEN"),
])
def test_a_wrong_token_logs_neither_the_stored_nor_the_presented_token(
    monkeypatch, caplog, path, field,
):
    _configure(monkeypatch, "datto", {field: STORED_TOKEN})
    caplog.set_level(logging.DEBUG)
    _reject(_endpoint(path), _FakeRequest(headers={"x-webhook-token": PRESENTED_TOKEN}))
    assert "REJECTED" in caplog.text and "X-Webhook-Token" in caplog.text
    _assert_no_leak(caplog.text, STORED_TOKEN, PRESENTED_TOKEN)


@pytest.mark.parametrize("path,field", [
    ("/webhooks/datto", "DATTO_WEBHOOK_SECRET"),
    ("/webhooks/datto/job-output", "DATTO_JOB_OUTPUT_TOKEN"),
    ("/webhooks/resend", "RESEND_WEBHOOK_SECRET"),
])
def test_an_unset_secret_logs_the_field_name_and_not_the_presented_value(
    monkeypatch, caplog, path, field,
):
    vendor = "resend" if "resend" in path else "datto"
    _configure(monkeypatch, vendor, {field: "   "})
    caplog.set_level(logging.DEBUG)
    _reject(_endpoint(path), _FakeRequest(headers={
        "x-webhook-token": PRESENTED_TOKEN, "svix-signature": f"v1,{PRESENTED_TOKEN}",
    }))
    # The operator is told WHICH credential to fix — by name, nothing more.
    assert f"{field} is not set" in caplog.text
    _assert_no_leak(caplog.text, PRESENTED_TOKEN)


def test_a_set_but_unusable_svix_secret_is_not_echoed(monkeypatch, caplog):
    _configure(monkeypatch, "resend", {"RESEND_WEBHOOK_SECRET": UNUSABLE_SVIX})
    caplog.set_level(logging.DEBUG)
    _reject(_endpoint("/webhooks/resend"), _FakeRequest())
    assert "RESEND_WEBHOOK_SECRET is set but unusable" in caplog.text
    # "whsec_" is the documented scheme prefix the hint names; the key part
    # after it is the operator's value and must not appear in any form.
    _assert_no_leak(caplog.text, UNUSABLE_KEY_PART)


def test_a_bad_svix_signature_logs_no_part_of_the_signing_secret(monkeypatch, caplog):
    _configure(monkeypatch, "resend", {"RESEND_WEBHOOK_SECRET": SVIX_SECRET})
    body = b'{"type": "email.delivered"}'
    forged = _svix_headers(body, b"not-the-configured-key")
    caplog.set_level(logging.DEBUG)
    _reject(_endpoint("/webhooks/resend"), _FakeRequest(body, headers=forged))
    assert "did not verify" in caplog.text
    _assert_no_leak(
        caplog.text, SVIX_KEY_B64, SVIX_KEY.decode(), forged["svix-signature"][3:],
    )


def test_an_accepted_delivery_logs_no_part_of_the_signing_secret(monkeypatch, caplog):
    _configure(monkeypatch, "resend", {"RESEND_WEBHOOK_SECRET": SVIX_SECRET})
    delivered = []
    monkeypatch.setattr(
        webhooks, "_route_and_ingest",
        lambda adapter, slug, envelope, instance: delivered.append(envelope) or {"status": "accepted"},
    )
    body = b'{"type": "email.delivered"}'
    headers = _svix_headers(body, SVIX_KEY)
    caplog.set_level(logging.DEBUG)
    assert asyncio.run(_endpoint("/webhooks/resend")(_FakeRequest(body, headers=headers))) == {
        "status": "accepted",
    }
    assert delivered == [{"type": "email.delivered"}]
    _assert_no_leak(caplog.text, SVIX_KEY_B64, SVIX_KEY.decode(), headers["svix-signature"][3:])
