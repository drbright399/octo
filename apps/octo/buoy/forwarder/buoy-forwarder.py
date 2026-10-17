#!/usr/bin/env python3
"""buoy-forwarder.py — Athena Buoy Forwarder v2 (multi-sensor, event-shaped).

Single daemon, pluggable sensor adapters. Posts events (full payload) to
OCTO `/api/v1/ingest/<slug>/events`. Per-client routing via explicit
OCTO_SLUG; bearer's resolved slug is asserted against OCTO_SLUG on startup
via `/api/v1/whoami` — refuses to run on mismatch (loud failure).

Phase F.1 ships only the Suricata adapter; F.2 adds Pi-hole, F.3 adds
OpenCanary. Daemon is adapter-pluggable so future sensors are drop-in.

Coexists with legacy `octo-forwarder.service` during validation. No state
or config overlap (separate /etc, separate /var/lib).

Environment:
  OCTO_URL          Base URL of the OCTO API (e.g. http://octo.example.test:8001)
  OCTO_SLUG         This buoy's tenant slug (e.g. "acme-corp")
  OCTO_TOKEN_FILE   Path to bearer token file
  SENSORS           Comma-separated adapter names (e.g. "suricata")
  EVE_PATH          Suricata eve.json path
  STATE_DIR         State dir
  POLL_INTERVAL_SEC (default 10)
  HTTP_TIMEOUT_SEC  (default 15)
  QUEUE_MAX         (default 10000) — local JSONL queue cap on OCTO unreachability
  LOG_LEVEL         (default INFO)

Stdlib-only (matches octo-forwarder.py style).

Doc + Claude Code, 2026-04-26 — Phase F.1.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Iterable, Optional


# ---- adapters/ as importable package ----
# Daemon runs from /usr/local/bin/buoy-forwarder.py with adapters at
# /usr/local/lib/buoy-forwarder/adapters/. Add the lib dir to sys.path so
# `from adapters.base import ...` works without packaging ceremony.
_ADAPTER_LIB = Path(os.environ.get(
    "BUOY_ADAPTER_LIB", "/usr/local/lib/buoy-forwarder"
))
if _ADAPTER_LIB.is_dir():
    sys.path.insert(0, str(_ADAPTER_LIB))
# In sandbox/dev, sys.path may already include the buoy/ directory — both work.
from adapters.base import ForwardEvent, SensorAdapter  # noqa: E402
from adapters.suricata import SuricataAdapter  # noqa: E402
from adapters.pihole import PiholeAdapter  # noqa: E402
from adapters.opencanary import OpenCanaryAdapter  # noqa: E402


# ---- Configuration ----
OCTO_URL = os.environ.get("OCTO_URL", "").rstrip("/")
OCTO_SLUG = os.environ.get("OCTO_SLUG", "").strip()
OCTO_TOKEN_FILE = Path(os.environ.get("OCTO_TOKEN_FILE", "/etc/buoy-forwarder/token"))
SENSORS = [s.strip() for s in os.environ.get("SENSORS", "suricata").split(",") if s.strip()]
EVE_PATH = Path(os.environ.get("EVE_PATH", "/var/log/suricata/eve.json"))
PIHOLE_DB_PATH = Path(os.environ.get("PIHOLE_DB_PATH", "/etc/pihole/pihole-FTL.db"))
OPENCANARY_LOG_PATH = Path(os.environ.get("OPENCANARY_LOG_PATH", "/var/log/opencanary.log"))
STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/buoy-forwarder"))
POLL_INTERVAL_SEC = float(os.environ.get("POLL_INTERVAL_SEC", "10"))
HTTP_TIMEOUT_SEC = float(os.environ.get("HTTP_TIMEOUT_SEC", "15"))
QUEUE_MAX = int(os.environ.get("QUEUE_MAX", "10000"))
HOSTNAME = socket.gethostname()

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("buoy-forwarder")

QUEUE_FILE = STATE_DIR / "queue.jsonl"

_running = True
_token_cache: Optional[str] = None


def _on_sigterm(_signum, _frame):  # type: ignore[no-untyped-def]
    global _running
    log.info("shutdown signal received, draining…")
    _running = False


# ---- Token loading ----

def load_token() -> str:
    """Load + cache the bearer from OCTO_TOKEN_FILE. Fail loud if missing/empty."""
    global _token_cache
    if _token_cache:
        return _token_cache
    if not OCTO_TOKEN_FILE.exists():
        log.error("bearer token file not found: %s", OCTO_TOKEN_FILE)
        sys.exit(2)
    text = OCTO_TOKEN_FILE.read_text().strip()
    if not text:
        log.error("bearer token file is empty: %s", OCTO_TOKEN_FILE)
        sys.exit(2)
    _token_cache = text
    return _token_cache


# ---- Startup validation: bearer's resolved slug == OCTO_SLUG ----

def assert_whoami_matches_slug() -> None:
    """Call OCTO /api/v1/whoami; refuse to start on slug mismatch.

    Loud failure mode: misconfigured deployment fails immediately, not on
    first event POST. Decided 2026-04-26 with Doc as part of Phase F.1.
    """
    if not OCTO_URL:
        log.error("OCTO_URL is not set; refusing to start")
        sys.exit(2)
    if not OCTO_SLUG:
        log.error("OCTO_SLUG is not set; refusing to start")
        sys.exit(2)
    bearer = load_token()
    req = urllib.request.Request(
        f"{OCTO_URL}/api/v1/whoami",
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log.error("whoami probe failed: HTTP %s; refusing to start", e.code)
        sys.exit(3)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.error("whoami probe network error: %s; refusing to start", e)
        sys.exit(3)
    except (json.JSONDecodeError, ValueError) as e:
        log.error("whoami probe returned malformed JSON: %s; refusing to start", e)
        sys.exit(3)

    actual_slug = body.get("slug")
    actual_kind = body.get("kind")
    if actual_kind != "buoy":
        log.error(
            "whoami: bearer is kind=%r, expected 'buoy'; refusing to start",
            actual_kind,
        )
        sys.exit(4)
    if actual_slug != OCTO_SLUG:
        log.error(
            "whoami slug mismatch: bearer resolves to %r but OCTO_SLUG is %r; "
            "refusing to start (this is the right failure — fix /etc/buoy-forwarder/forwarder.env)",
            actual_slug, OCTO_SLUG,
        )
        sys.exit(4)
    log.info(
        "whoami OK: kind=%s slug=%s label=%s token_id=%s",
        actual_kind, actual_slug, body.get("label"), body.get("token_id"),
    )


# ---- HTTP delivery ----

def post_event(event: ForwardEvent) -> tuple[int, str]:
    """POST one event. Returns (http_status, body). Raises on network failure."""
    url = f"{OCTO_URL}/api/v1/ingest/{OCTO_SLUG}/events"
    body = json.dumps(event, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {load_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SEC) as resp:
            return resp.getcode(), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace") if e.fp else ""


# ---- Local queue (when OCTO unreachable) ----

class LocalQueue:
    """Bounded JSONL queue persisted to disk. FIFO, drop-oldest at QUEUE_MAX."""

    def __init__(self, path: Path, max_size: int) -> None:
        self.path = path
        self.max_size = max_size
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._mem: deque[dict] = deque(maxlen=max_size)
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self.path.exists():
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._mem.append(json.loads(line))
                    except json.JSONDecodeError:
                        log.warning("dropping unparseable queue line")
            log.info("loaded %s queued events from %s", len(self._mem), self.path)
        except OSError as e:
            log.warning("queue load failed: %s; starting empty", e)

    def _persist(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for item in self._mem:
                    f.write(json.dumps(item, separators=(",", ":")))
                    f.write("\n")
            os.replace(tmp, self.path)
        except OSError as e:
            log.warning("queue persist failed: %s", e)

    def append(self, event: ForwardEvent) -> None:
        was_full = len(self._mem) >= self.max_size
        self._mem.append(event)  # deque(maxlen=...) drops oldest automatically
        if was_full:
            log.warning(
                "local queue full (%s); dropping oldest event to make room",
                self.max_size,
            )
        self._persist()

    def drain(self) -> Iterable[ForwardEvent]:
        """Pop events one at a time; caller decides whether to re-queue on failure."""
        while self._mem and _running:
            yield self._mem.popleft()
            self._persist()

    def __len__(self) -> int:
        return len(self._mem)


# ---- Adapter factory ----

def build_adapters() -> list[SensorAdapter]:
    """Instantiate each adapter named in SENSORS env var."""
    adapters: list[SensorAdapter] = []
    for name in SENSORS:
        if name == "suricata":
            adapters.append(SuricataAdapter(
                eve_path=EVE_PATH,
                state_dir=STATE_DIR,
                hostname=HOSTNAME,
            ))
        elif name == "pihole":
            adapters.append(PiholeAdapter(
                db_path=PIHOLE_DB_PATH,
                state_dir=STATE_DIR,
                hostname=HOSTNAME,
            ))
        elif name == "opencanary":
            adapters.append(OpenCanaryAdapter(
                log_path=OPENCANARY_LOG_PATH,
                state_dir=STATE_DIR,
                hostname=HOSTNAME,
            ))
        else:
            log.error(
                "unknown sensor adapter: %r (known: suricata, pihole, opencanary)",
                name,
            )
            sys.exit(5)
    return adapters


# ---- Main loop ----

def deliver_with_queue_fallback(event: ForwardEvent, queue: LocalQueue) -> bool:
    """POST event. On 2xx success → return True. On 5xx/network → enqueue. On 4xx → log + drop (dead-letter)."""
    try:
        status, body = post_event(event)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning("network error posting event; queuing locally: %s", e)
        queue.append(event)
        return False

    if 200 <= status < 300:
        return True
    if 400 <= status < 500:
        # 4xx = our request is wrong; queueing won't help. Log + drop.
        log.error(
            "4xx posting event; dead-lettering (event_type=%r): HTTP %s body=%s",
            event.get("event_type"), status, body[:300],
        )
        return False
    # 5xx — server side; queue and retry next cycle.
    log.warning(
        "5xx posting event; queuing locally (event_type=%r): HTTP %s",
        event.get("event_type"), status,
    )
    queue.append(event)
    return False


def flush_queue(queue: LocalQueue) -> int:
    """Drain queued events; return count actually delivered."""
    sent = 0
    # We iterate by repeatedly calling drain() so each event is popped only on success.
    # If a delivery fails, append it back to the front (via the same enqueue path).
    pending: list[ForwardEvent] = list(queue.drain())
    queue._persist()  # noqa: SLF001 — we just emptied via drain()
    for event in pending:
        try:
            status, _body = post_event(event)
        except (urllib.error.URLError, TimeoutError, OSError):
            # Re-queue everything left, including this one
            queue.append(event)
            continue
        if 200 <= status < 300:
            sent += 1
        elif 400 <= status < 500:
            log.error("4xx during queue flush; dead-lettering one event")
        else:
            queue.append(event)
    return sent


def run_once(adapters: list[SensorAdapter], queue: LocalQueue) -> dict:
    """One full polling cycle across all adapters + queue flush."""
    stats = {"adapters": {}, "delivered": 0, "queued": 0, "failed_4xx": 0}
    # Try the queue first (gets stale events out the door before adding new ones).
    flushed = flush_queue(queue)
    stats["delivered"] += flushed

    for adapter in adapters:
        a_stats = {"seen": 0, "delivered": 0, "queued": 0, "failed_4xx": 0}
        try:
            for event in adapter.iter_events():
                a_stats["seen"] += 1
                ok = deliver_with_queue_fallback(event, queue)
                if ok:
                    a_stats["delivered"] += 1
                    stats["delivered"] += 1
                else:
                    a_stats["queued"] += 1
                    stats["queued"] += 1
        except Exception as e:  # noqa: BLE001 — never crash whole daemon for one adapter
            log.exception("adapter %s raised: %s; continuing", adapter.name, e)
        stats["adapters"][adapter.name] = a_stats

    stats["queue_depth"] = len(queue)
    return stats


def main() -> int:
    signal.signal(signal.SIGTERM, _on_sigterm)
    signal.signal(signal.SIGINT, _on_sigterm)

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    log.info(
        "buoy-forwarder starting: octo=%s slug=%s sensors=%s eve=%s state=%s poll=%ss",
        OCTO_URL, OCTO_SLUG, SENSORS, EVE_PATH, STATE_DIR, POLL_INTERVAL_SEC,
    )

    assert_whoami_matches_slug()

    adapters = build_adapters()
    queue = LocalQueue(QUEUE_FILE, QUEUE_MAX)

    while _running:
        cycle_start = time.monotonic()
        try:
            stats = run_once(adapters, queue)
            # Log only when something happened (avoid noisy idle ticks).
            if stats["delivered"] or stats["queued"] or stats["failed_4xx"]:
                log.info("cycle: %s", stats)
        except Exception as e:  # noqa: BLE001
            log.exception("unexpected error in cycle: %s", e)

        elapsed = time.monotonic() - cycle_start
        sleep_for = max(1.0, POLL_INTERVAL_SEC - elapsed)
        # Sleep in 1-second slices so SIGTERM is responsive
        for _ in range(int(sleep_for)):
            if not _running:
                break
            time.sleep(1)

    for adapter in adapters:
        try:
            adapter.graceful_shutdown()
        except Exception:  # noqa: BLE001
            log.exception("adapter %s graceful_shutdown failed", adapter.name)
    log.info("buoy-forwarder shutdown clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
