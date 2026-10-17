"""Start/stop plumbing shared by every polling adapter.

Adapters expose SYNC start()/stop(), but their pollers are asyncio tasks that
live on the API's event loop. stop() used to do

    try: asyncio.get_running_loop().create_task(poller.stop())
    except RuntimeError: pass

which silently did NOTHING whenever stop() ran off the loop — e.g. from a
sync FastAPI route (threadpool) such as "disable this integration". The
poller kept running with the old decrypted credentials, kept writing into
client databases, and its last reference was dropped so nothing could ever
stop it short of a process restart. This module is the one correct
implementation; adapters remember the loop their poller started on and hand
both to `stop_poller`.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

_STOP_TIMEOUT_SEC = 20.0


def start_on_running_loop(
    coro_factory: Callable[[], Awaitable[Any]], *, what: str,
) -> Optional[asyncio.AbstractEventLoop]:
    """Schedule `coro_factory()` on the current running loop and return that
    loop (the caller keeps it for stop_poller). Returns None — nothing
    scheduled — when there is no running loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.info("[%s] no running event loop; poller deferred", what)
        return None
    loop.create_task(coro_factory())
    return loop


def stop_poller(
    stop_coro_factory: Callable[[], Awaitable[Any]],
    owner_loop: Optional[asyncio.AbstractEventLoop],
    *,
    what: str,
) -> bool:
    """Stop a poller from ANY thread. True when the stop was delivered.

    - on the owner loop's own thread: schedule it (cannot block the loop)
    - off-loop (threadpool route, CLI): run it on the owner loop and WAIT,
      so the caller can truthfully report "stopped"
    - poller never started (no owner loop): nothing is running; True
    Never raises; a failed stop is logged at ERROR, never swallowed.
    """
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None

    if owner_loop is None or owner_loop.is_closed():
        return True

    if running is owner_loop:
        owner_loop.create_task(stop_coro_factory())
        return True

    if not owner_loop.is_running():
        logger.error("[%s] poller's event loop is not running — cannot deliver stop", what)
        return False
    try:
        fut = asyncio.run_coroutine_threadsafe(stop_coro_factory(), owner_loop)
        fut.result(timeout=_STOP_TIMEOUT_SEC)
        return True
    except Exception:  # noqa: BLE001 — must not raise; must not be silent
        logger.exception("[%s] poller stop FAILED — it may still be running", what)
        return False
