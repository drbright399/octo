"""Suricata adapter for buoy-forwarder v2.

Tails /var/log/suricata/eve.json. Filters to a curated event_type subset
(alert / anomaly / dns / http / tls; drops flow + netflow + stats + fileinfo
+ ssh — see below). Yields one ForwardEvent per surviving record with the
full eve record preserved under data.raw_eve so Shallow gets ground truth.

Curated subset rationale (decided 2026-04-26 with Doc):
  - alert    — IDS rule fires; the historical "indicator-shaped" core
  - anomaly  — Suricata's protocol anomaly detector
  - dns      — DNS query/response (high volume but low per-event cost)
  - http     — HTTP request metadata
  - tls      — TLS handshake fingerprint (JA3/JA4-style)
  Dropped: flow / netflow (90%+ of volume, low per-event signal density),
           stats (Suricata's own internal metrics), fileinfo (rare but
           noisy), ssh (Suricata's ssh inspector — overlaps with sshd logs).

Severity mapping:
  - alert   — derived from alert.severity (1=high, 2=medium, 3=low)
  - anomaly — medium (Suricata's own protocol-anomaly bucket)
  - others  — info (decided 2026-04-26: severity is the UI-signal-to-noise
              dial; Shallow examines all events regardless. info keeps
              known-benign sensor traffic out of human's default view.)

Coalescing: NONE in v1. Recurrence detection moves UP to Shallow (see
`shallow-deep-hadal-tiers` zettel). Buoy is dumb-but-faithful pipe.

State file: STATE_DIR/suricata/state.json
  { "inode": int, "offset": int, "rotated_at": iso8601 }
  - inode tracks log rotation; if eve.json's inode changes, we know to start
    from offset 0 of the new file (and emit a debug log noting rotation).
  - offset is the byte position within the current file.
"""
from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path
from typing import Iterator, Optional

from .base import EventSeverity, ForwardEvent, SensorAdapter


log = logging.getLogger("suricata-adapter")

# event_type values we forward; everything else is dropped.
_FORWARDED_EVENT_TYPES = frozenset({"alert", "anomaly", "dns", "http", "tls"})

# Per-call yield caps. Prevent the inner readline loop from running forever
# on busy buoys where suricata writes faster than the daemon delivers (which
# would starve pihole + opencanary adapters in the same cycle).
#
# Two caps fire whichever comes first:
#   _BATCH_MAX  — hard event count (also bounds memory in catch-up scenarios)
#   _TIME_MAX_S — wall-clock seconds spent in iter_events. Important because
#                 delivery is network-bound (~1 event/sec on Tailscale), so
#                 even 100 events could take 100s. The time cap ensures other
#                 adapters get polled within a reasonable cycle window.
#
# Bug history: pre-2026-04-29, neither cap existed. Suricata's loop ran
# indefinitely on busy fleet buoys, never reaching _persist_state(), starving
# pihole + opencanary adapters. See
# followups/buoy-forwarder-secondary-adapters-frozen-2026-04-29.md
_BATCH_MAX = 200
_TIME_MAX_S = 5.0


def _suricata_alert_severity_to_octo(suri_severity: int) -> EventSeverity:
    """Suricata's alert.severity is 1=high, 2=medium, 3=low; else default info."""
    return {1: "high", 2: "medium", 3: "low"}.get(suri_severity, "info")


def _derive_severity(record: dict) -> EventSeverity:
    """Map a parsed eve record to OCTO's severity scale."""
    et = record.get("event_type", "")
    if et == "alert":
        return _suricata_alert_severity_to_octo(record.get("alert", {}).get("severity", 0))
    if et == "anomaly":
        return "medium"
    return "info"  # dns, http, tls — visible-but-quiet by default


class SuricataAdapter:
    """Tails Suricata's eve.json and yields curated-subset events."""

    name = "suricata"

    def __init__(
        self,
        eve_path: Path,
        state_dir: Path,
        hostname: Optional[str] = None,
    ) -> None:
        self.eve_path = Path(eve_path)
        self.state_dir = Path(state_dir) / self.name
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self._hostname = hostname or socket.gethostname()
        self._inode: Optional[int] = None
        self._offset: int = 0
        self._load_state()

    # --- state file ---

    def _load_state(self) -> None:
        if not self.state_file.exists():
            log.info("no prior state at %s — will start at end of log", self.state_file)
            # First run: skip existing log content, start at the tail. This avoids
            # backfilling the entire historical log on first deploy.
            try:
                st = self.eve_path.stat()
                self._inode = st.st_ino
                self._offset = st.st_size
            except FileNotFoundError:
                self._inode = None
                self._offset = 0
            self._persist_state()
            return
        try:
            data = json.loads(self.state_file.read_text())
            self._inode = int(data.get("inode")) if data.get("inode") is not None else None
            self._offset = int(data.get("offset", 0))
            log.info("resumed from inode=%s offset=%s", self._inode, self._offset)
        except (json.JSONDecodeError, ValueError, OSError) as e:
            log.warning("state file corrupt (%s); resetting to tail", e)
            self._inode = None
            self._offset = 0

    def _persist_state(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": self._inode, "offset": self._offset}))
        os.replace(tmp, self.state_file)

    # --- main API ---

    def iter_events(self) -> Iterator[ForwardEvent]:
        """Yield events appended since last call. Handles log rotation."""
        if not self.eve_path.exists():
            # Suricata not running yet, or no events written. Wait it out.
            return

        try:
            st = self.eve_path.stat()
        except FileNotFoundError:
            return

        # Detect rotation: inode changed → new file. Reset offset to 0.
        if self._inode is not None and st.st_ino != self._inode:
            log.info(
                "log rotation detected (old inode=%s, new inode=%s); resuming from offset 0",
                self._inode, st.st_ino,
            )
            self._inode = st.st_ino
            self._offset = 0
        elif self._inode is None:
            self._inode = st.st_ino

        # Guard: if file shrunk under us (truncate without rotation), reset.
        if st.st_size < self._offset:
            log.warning(
                "log file shrank (was %s, now %s) without inode change; resetting to 0",
                self._offset, st.st_size,
            )
            self._offset = 0

        if st.st_size == self._offset:
            return  # nothing new

        # Read new content from offset to EOF.
        # Cap at _BATCH_MAX events OR _TIME_MAX_S seconds (whichever first) so
        # other adapters get polled this cycle even when the source file is
        # being written faster than we drain.
        import time as _time
        yielded_count = 0
        deadline = _time.monotonic() + _TIME_MAX_S
        try:
            with open(self.eve_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                # Read all available now; track each line's end position so we
                # only persist offsets at line boundaries (no half-line resumes).
                while True:
                    line_start = f.tell()
                    line = f.readline()
                    if not line:
                        # EOF
                        break
                    if not line.endswith("\n"):
                        # Partial trailing line — wait for next cycle to complete it.
                        # Roll back to before this partial line.
                        self._offset = line_start
                        break
                    self._offset = f.tell()
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    event = self._line_to_event(line)
                    if event is not None:
                        yield event
                        yielded_count += 1
                        if yielded_count >= _BATCH_MAX or _time.monotonic() >= deadline:
                            # Either cap reached — exit so other adapters
                            # (pihole, opencanary) get polled this cycle. Next
                            # cycle resumes from current offset (already saved
                            # as self._offset = f.tell() above).
                            break
        except OSError as e:
            log.warning("read error on %s: %s; will retry next cycle", self.eve_path, e)
            return

        self._persist_state()

    def graceful_shutdown(self) -> None:
        """Flush state. iter_events already persists per cycle, but we double-check."""
        self._persist_state()

    # --- per-line transform ---

    def _line_to_event(self, line: str) -> Optional[ForwardEvent]:
        """Parse one eve.json line; return ForwardEvent or None to drop."""
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            log.debug("skipping unparseable eve line: %s; line[:200]=%r", e, line[:200])
            return None

        et = record.get("event_type")
        if et not in _FORWARDED_EVENT_TYPES:
            return None  # curated-subset filter

        return {
            "event_type": f"suricata.{et}",
            "severity": _derive_severity(record),
            "source_host": self._hostname,
            "data": {
                "raw_eve": record,
                "_buoy": self._hostname,
                "_adapter": self.name,
                "_adapter_version": "1.0",
            },
        }


__all__ = ["SuricataAdapter"]
