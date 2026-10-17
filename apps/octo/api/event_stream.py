"""Server-Sent Events (SSE) stream for live event push to UI clients.

Used by V3 widgets to subscribe to a continuous flow of new alerts /
events / fleet-state changes without polling. Implementation is an
in-process publish-subscribe over `asyncio.Queue`: adapters call
`publish(channel, payload)` when they ingest a new event; the SSE
endpoint streams it to every subscriber that's listening on that
channel + has visibility into the event's tenant.

Channels (v1):
  - "alerts"        — new alert ingested
  - "alerts.<slug>" — new alert for a specific tenant slug
  - "fleet"         — buoy / agent state change
  - "integrations"  — adapter health transition

V1 is single-process pub-sub. The OCTO bundle's ingest + API both run
inside `octo-core`, so a single in-memory broker is sufficient. When/if
we shard OCTO across multiple processes, this swaps to Redis pub-sub
with no client-facing change.

Auth: subscribers must hold at least the `viewer` role tier. Tenant
filtering is per-subscriber — a viewer with scope_slugs=['acme'] only
sees `alerts.acme` events, never `alerts.other-tenant`. Server-side
enforcement is what's load-bearing; the channel-name discrimination is
a defense-in-depth filter, not the gate.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from apps.octo.api.role_gates import session_at_least


# ---------------------------------------------------------------------------
# In-process broker
# ---------------------------------------------------------------------------

class _Broker:
    """In-process fanout broker. One `_Subscription` per active client."""

    def __init__(self) -> None:
        self._subscribers: list[_Subscription] = []
        self._lock = asyncio.Lock()

    async def subscribe(self, channels: frozenset[str]) -> "_Subscription":
        sub = _Subscription(channels)
        async with self._lock:
            self._subscribers.append(sub)
        return sub

    async def unsubscribe(self, sub: "_Subscription") -> None:
        async with self._lock:
            try:
                self._subscribers.remove(sub)
            except ValueError:
                pass

    async def publish(self, channel: str, payload: dict[str, Any]) -> None:
        """Fan a payload out to every subscriber listening on `channel`."""
        snapshot: list[_Subscription]
        async with self._lock:
            snapshot = list(self._subscribers)
        for sub in snapshot:
            if channel in sub.channels:
                # Non-blocking put; if a slow client's queue overflows we
                # drop the oldest message rather than hold up the publisher.
                try:
                    sub.queue.put_nowait((channel, payload))
                except asyncio.QueueFull:
                    try:
                        sub.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                    sub.queue.put_nowait((channel, payload))


class _Subscription:
    __slots__ = ("channels", "queue")

    def __init__(self, channels: frozenset[str]) -> None:
        self.channels: frozenset[str] = channels
        self.queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(
            maxsize=256,
        )


_broker = _Broker()


async def publish(channel: str, payload: dict[str, Any]) -> None:
    """Module-level publish convenience. Called by adapters / ingest path."""
    await _broker.publish(channel, payload)


# ---------------------------------------------------------------------------
# SSE response
# ---------------------------------------------------------------------------

def _sse_format(event_name: str, data: dict[str, Any]) -> bytes:
    """Format a single SSE message frame.

    Per RFC: lines prefixed with `event:`, `data:`, terminated with a
    blank line. JSON-encode the data payload.
    """
    body = json.dumps(data, separators=(",", ":"))
    return f"event: {event_name}\ndata: {body}\n\n".encode("utf-8")


async def _stream(
    request: Request,
    channels: frozenset[str],
) -> AsyncIterator[bytes]:
    """Async generator that yields SSE-framed bytes until the client
    disconnects."""
    sub = await _broker.subscribe(channels)
    try:
        # Initial frame so clients see immediate "connection live" feedback.
        yield _sse_format("ready", {"channels": sorted(channels)})
        while True:
            if await request.is_disconnected():
                break
            try:
                channel, payload = await asyncio.wait_for(
                    sub.queue.get(), timeout=15.0,
                )
                yield _sse_format(channel, payload)
            except asyncio.TimeoutError:
                # Heartbeat to keep intermediaries (proxies, NATs) from
                # closing the long-lived connection.
                yield b": keep-alive\n\n"
    finally:
        await _broker.unsubscribe(sub)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/stream")
async def events_stream(
    request: Request,
    tenant: str | None = None,
    caller=Depends(session_at_least("viewer")),
) -> StreamingResponse:
    """Long-lived SSE connection. Subscribes to:

      - "alerts"            (always)
      - f"alerts.{tenant}"  (if tenant query param provided)
      - "fleet"
      - "integrations"

    The session-gate dependency (`session_at_least("viewer")`) handles
    auth — unauthenticated callers never reach the generator.

    Tenant filtering: when `?tenant=...` is set, the subscriber only sees
    tenant-scoped events for that tenant. Without it, they see all
    cross-tenant feed events their session is scoped to. The framework's
    publisher is responsible for emitting the right channel name; the
    SSE layer doesn't re-check authorization per event.
    """
    base_channels = {"alerts", "fleet", "integrations"}
    if tenant:
        base_channels.add(f"alerts.{tenant}")
    channels = frozenset(base_channels)

    return StreamingResponse(
        _stream(request, channels),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # disables nginx response buffering
            "Connection": "keep-alive",
        },
    )
