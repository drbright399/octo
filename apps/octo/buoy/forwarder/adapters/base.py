"""Sensor adapter Protocol — buoy-forwarder v2.

Each sensor (Suricata, Pi-hole, OpenCanary, ...) implements `SensorAdapter`.
The main daemon polls every adapter, batches the events each yields, and POSTs
each as a single event to OCTO `/api/v1/ingest/<slug>/events`.

ForwardEvent is the wire-format-ready dict the adapter produces. The daemon
adds nothing to it before posting (the adapter is responsible for everything
the OCTO side will see in `event_type`/`severity`/`source_host`/`data`).
"""
from __future__ import annotations

from typing import Iterable, Iterator, Literal, Protocol, TypedDict


# OCTO's EventIngest accepts these severity levels (matches v1.2 spec §6.2)
EventSeverity = Literal["info", "low", "medium", "high", "critical"]


class ForwardEvent(TypedDict):
    """Shape that becomes the body of POST /api/v1/ingest/<slug>/events."""
    event_type: str          # e.g. "suricata.alert", "pihole.query"
    severity: EventSeverity
    source_host: str         # buoy hostname; receivers use this for routing/filtering
    data: dict               # full sensor record + adapter-derived context


class SensorAdapter(Protocol):
    """Contract for a single sensor source on a buoy.

    Adapters are stateful — they manage their own offset/state file under
    STATE_DIR/<adapter.name>/ . The daemon owns no per-adapter state; it only
    drives the polling loop and HTTP delivery.

    Implementations should:
      * Be safe to call iter_events() repeatedly; each call yields events
        observed since the last call (or, on first call, since the saved
        offset). Empty iterables on idle cycles are fine.
      * Survive process restart cleanly via STATE_DIR.
      * Survive log rotation if applicable (track inode, not just byte offset).
      * Yield ForwardEvent dicts directly — no further adapter-or-daemon
        translation step. What you yield is what OCTO sees.
      * Never raise on a single bad input record — log + skip + continue.
        Raise only on unrecoverable adapter errors (config wrong, source
        missing entirely, etc.).
    """

    name: str  # short identifier, e.g. "suricata"; used for state dir + logs

    def iter_events(self) -> Iterator[ForwardEvent]:
        """Yield events observed since last call. Idempotent; non-blocking."""
        ...

    def graceful_shutdown(self) -> None:
        """Flush any buffered state to disk. Called on SIGTERM."""
        ...


__all__ = ["SensorAdapter", "ForwardEvent", "EventSeverity"]
