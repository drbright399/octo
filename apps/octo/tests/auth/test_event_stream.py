"""SSE event-stream — auth gating, channel filtering, broker fan-out.

Tests the in-process broker without spinning up the full SSE HTTP
stream (which is best tested with an integration harness). The HTTP
endpoint's auth gating is covered via a simple unauthenticated probe.
"""
from __future__ import annotations

import asyncio

import pyotp
import pytest

from apps.octo.api import event_stream


def _login(client, op):
    r = client.post("/api/v1/auth/password/begin", json={
        "username": op["username"], "password": op["password"],
    })
    challenge = r.json()["challenge_id"]
    code = pyotp.TOTP(op["totp_secret_b32"]).now()
    r2 = client.post("/api/v1/auth/password/totp", json={
        "challenge_id": challenge, "totp_code": code,
    })
    assert r2.status_code == 200, r2.text
    return dict(r2.cookies)


# ---------------------------------------------------------------------------
# Broker — in-process pub-sub
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_broker_publishes_to_matching_subscriber():
    """Subscriber listening on 'alerts' receives an 'alerts' publish."""
    broker = event_stream._Broker()
    sub = await broker.subscribe(frozenset({"alerts"}))
    await broker.publish("alerts", {"id": "evt-1"})
    channel, payload = await asyncio.wait_for(sub.queue.get(), timeout=1.0)
    assert channel == "alerts"
    assert payload == {"id": "evt-1"}


@pytest.mark.asyncio
async def test_broker_skips_subscribers_on_non_matching_channel():
    """A subscriber listening on 'alerts' does NOT receive a 'fleet'
    publish. Cross-channel leakage would let one tenant see another
    tenant's events."""
    broker = event_stream._Broker()
    sub = await broker.subscribe(frozenset({"alerts"}))
    await broker.publish("fleet", {"buoy": "acme-1"})
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(sub.queue.get(), timeout=0.1)


@pytest.mark.asyncio
async def test_broker_fans_out_to_multiple_subscribers():
    broker = event_stream._Broker()
    a = await broker.subscribe(frozenset({"alerts"}))
    b = await broker.subscribe(frozenset({"alerts"}))
    await broker.publish("alerts", {"id": "evt-shared"})
    chan_a, payload_a = await asyncio.wait_for(a.queue.get(), timeout=1.0)
    chan_b, payload_b = await asyncio.wait_for(b.queue.get(), timeout=1.0)
    assert payload_a == payload_b == {"id": "evt-shared"}


@pytest.mark.asyncio
async def test_broker_tenant_scoped_channel():
    """`alerts.<slug>` is its own channel — a subscriber listening on
    `alerts` (global) does NOT see tenant-scoped messages by default."""
    broker = event_stream._Broker()
    global_sub = await broker.subscribe(frozenset({"alerts"}))
    tenant_sub = await broker.subscribe(frozenset({"alerts.acme"}))
    await broker.publish("alerts.acme", {"id": "tenant-evt"})
    # tenant subscriber gets it
    chan, payload = await asyncio.wait_for(tenant_sub.queue.get(), timeout=1.0)
    assert chan == "alerts.acme"
    # global subscriber does NOT
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(global_sub.queue.get(), timeout=0.1)


@pytest.mark.asyncio
async def test_broker_unsubscribe_removes_from_fanout():
    broker = event_stream._Broker()
    sub = await broker.subscribe(frozenset({"alerts"}))
    await broker.unsubscribe(sub)
    await broker.publish("alerts", {"id": "post-unsubscribe"})
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(sub.queue.get(), timeout=0.1)


@pytest.mark.asyncio
async def test_broker_overflow_drops_oldest():
    """Slow subscriber whose queue fills up doesn't block the publisher;
    oldest message is dropped to make room for new."""
    broker = event_stream._Broker()
    sub = await broker.subscribe(frozenset({"alerts"}))
    # Stuff one more than queue capacity (256) without consuming
    for i in range(258):
        await broker.publish("alerts", {"seq": i})
    # Latest item should still be present
    seqs = []
    while not sub.queue.empty():
        _, payload = sub.queue.get_nowait()
        seqs.append(payload["seq"])
    assert max(seqs) == 257
    # Oldest dropped — should never see seq=0 or seq=1
    assert 0 not in seqs


# ---------------------------------------------------------------------------
# SSE formatting
# ---------------------------------------------------------------------------

def test_sse_format_wraps_payload_correctly():
    frame = event_stream._sse_format("alerts", {"id": "evt-1", "severity": "high"})
    assert b"event: alerts" in frame
    assert b"data: " in frame
    assert b'"id":"evt-1"' in frame
    assert frame.endswith(b"\n\n")


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------

def test_events_stream_requires_session(auth_client):
    """Unauthenticated subscriber gets 401, not a stream."""
    auth_client.cookies.clear()
    r = auth_client.get("/api/v1/events/stream", follow_redirects=False)
    assert r.status_code in (401, 403)


def test_events_stream_route_registered(auth_client):
    """The SSE endpoint is wired into the FastAPI app. Streaming behavior
    itself is tested via the broker unit tests above — the SSE wire format
    is a thin wrapper around the broker. Streaming over the sync TestClient
    is unreliable (long-lived connections + sync client don't compose);
    integration-level streaming behavior gets tested via a live deploy."""
    from apps.octo.api import create_app
    app = create_app()
    sse_routes = [r for r in app.routes if hasattr(r, "path") and r.path == "/api/v1/events/stream"]
    assert len(sse_routes) == 1, "SSE stream route is registered"
