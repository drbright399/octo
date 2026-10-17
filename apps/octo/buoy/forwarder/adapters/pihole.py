"""Pi-hole adapter for buoy-forwarder v2.

Source: /etc/pihole/pihole-FTL.db (SQLite). Polls for new DNS query rows
every cycle; yields one `pihole.query` ForwardEvent per row.

All-DNS posture (decided 2026-04-26 with Doc): every query is forwarded —
allowed + blocked. The blocked/allowed dimension is reflected in severity
(answered → info; blocked → low) so default UI can hide allowed traffic;
Shallow examines all of it. The label and severity come from Pi-hole FTL's
DOCUMENTED query status codes (`_STATUS_TABLE`); the server classifies by
the numeric `status` itself and never trusts either.

Schema versions handled:
  - v5: single flat `queries` table
  - v6 (FTL DB v17+): split into `query_storage` + `domain_by_id`,
    `client_by_id`, `forward_by_id` lookup tables
Adapter detects on first state-load via sqlite_master.

State file: STATE_DIR/pihole/state.json
  { "last_id": int, "schema": "v5"|"v6" }

last_id = largest queries.id we've already emitted. Resume position is
`WHERE id > last_id`. First run sets last_id = MAX(id) currently in the DB
(start at tail; no backfill — same posture as Suricata adapter).

Concurrency: opened read-only via URI (`file:<path>?mode=ro`) so FTL's
writer lock doesn't conflict. SQLITE_BUSY is treated as transient — the
cycle is skipped and the next cycle retries.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sqlite3
from pathlib import Path
from typing import Iterator, Optional

from .base import EventSeverity, ForwardEvent, SensorAdapter


log = logging.getLogger("pihole-adapter")

# Status code → (label, severity): Pi-hole FTL's documented query status
# codes (docs.pi-hole.net → Database → Query database → "Query status";
# the same numbers in FTL v5 and v6, v6 adding 18). A block is "low", an
# answered / in-flight query "info". Unmapped codes default to (`unknown`,
# `info`) — unknown territory shouldn't auto-promote to "low"; Shallow gets
# the raw record either way.
#
# v0.11 fix: the table used to be SHIFTED against these codes (it called 1
# "allowed" and 2 "blocked-gravity", …) — backwards for the two commonest
# codes, so nearly every forwarded lookup was labelled blocked (and "low")
# and every gravity block allowed ("info"). The server never used the label
# or this severity to classify (it reads the numeric status); a buoy still
# running the old forwarder keeps sending wrong labels until it is updated.
_STATUS_TABLE: dict[int, tuple[str, EventSeverity]] = {
    0: ("unknown", "info"),                     # not (yet) answered
    1: ("blocked-gravity", "low"),              # domain in gravity
    2: ("forwarded", "info"),                   # forwarded upstream
    3: ("cached", "info"),                      # replied from cache
    4: ("blocked-regex", "low"),                # regex denylist
    5: ("blocked-denylist", "low"),             # exact denylist
    6: ("blocked-upstream-ip", "low"),          # upstream: known blocking-page IP
    7: ("blocked-upstream-null", "low"),        # upstream: 0.0.0.0 / ::
    8: ("blocked-upstream-nxdomain", "low"),    # upstream: NXDOMAIN, RA bit unset
    9: ("blocked-gravity-cname", "low"),        # gravity, deep CNAME inspection
    10: ("blocked-regex-cname", "low"),         # regex, deep CNAME inspection
    11: ("blocked-denylist-cname", "low"),      # exact denylist, deep CNAME
    12: ("retried", "info"),                    # retried query
    13: ("retried-dnssec", "info"),             # retried but ignored (DNSSEC)
    14: ("in-progress", "info"),                # already forwarded, not again
    15: ("blocked-dbbusy", "low"),              # blocked: database busy
    16: ("blocked-special-domain", "low"),      # blocked: special domain
    17: ("cached-stale", "info"),               # replied from stale cache
    18: ("blocked-upstream-ede15", "low"),      # upstream: EDE 15 "Blocked"
}

_BATCH_MAX = 200  # max rows fetched per cycle (was 1000 pre-2026-04-29; lowered
# to match suricata + opencanary adapters and keep per-adapter call short).
_TIME_MAX_S = 5.0  # wall-clock seconds spent in iter_events; bounds delivery
# time even if BATCH_MAX events are queued (each delivery is ~1s on tailnet).
# Without this cap, the for-loop over fetched rows could block for 1000s with
# the original BATCH_MAX. Same fix as suricata + opencanary adapters.

_QUERY_V5 = """
    SELECT id, timestamp, type, status, domain, client, forward,
           reply_type, reply_time
    FROM queries
    WHERE id > ?
    ORDER BY id
    LIMIT ?
"""

_QUERY_V6 = """
    SELECT q.id, q.timestamp, q.type, q.status,
           d.domain  AS domain,
           c.ip      AS client,
           c.name    AS client_name,
           f.forward AS forward,
           q.reply_type, q.reply_time
    FROM query_storage q
    LEFT JOIN domain_by_id  d ON q.domain  = d.id
    LEFT JOIN client_by_id  c ON q.client  = c.id
    LEFT JOIN forward_by_id f ON q.forward = f.id
    WHERE q.id > ?
    ORDER BY q.id
    LIMIT ?
"""


class PiholeSchemaError(RuntimeError):
    """Raised when the FTL DB doesn't look like either v5 or v6."""


def _detect_schema(conn: sqlite3.Connection) -> str:
    """Return 'v5' or 'v6' by inspecting sqlite_master. Raises on neither."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {r[0] for r in rows}
    if "query_storage" in names and "domain_by_id" in names:
        return "v6"
    if "queries" in names:
        return "v5"
    raise PiholeSchemaError(
        f"pihole-FTL.db has neither 'queries' (v5) nor 'query_storage' (v6); "
        f"saw tables: {sorted(names)}"
    )


def _open_ro(db_path: Path) -> sqlite3.Connection:
    """Open the FTL DB read-only via URI. Short busy-timeout (FTL is the writer)."""
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    conn.row_factory = sqlite3.Row
    # FTL stores whatever bytes a client asked for — mDNS/DNS-SD service
    # names in particular can carry non-UTF-8 bytes. sqlite3's default text
    # decoding raises OperationalError on such a row, which the poll loop
    # used to treat as "DB busy" and retry FOREVER at the same last_id
    # (the adapter silently stopped forwarding). Decode leniently instead:
    # an undecodable byte becomes U+FFFD and the row flows through.
    conn.text_factory = lambda b: b.decode("utf-8", "replace")
    return conn


class PiholeAdapter:
    """Polls Pi-hole-FTL.db for new query rows since `last_id`."""

    name = "pihole"

    def __init__(
        self,
        db_path: Path,
        state_dir: Path,
        hostname: Optional[str] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.state_dir = Path(state_dir) / self.name
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self._hostname = hostname or socket.gethostname()
        self._last_id: int = 0
        self._schema: Optional[str] = None
        self._load_state()

    # --- state ---

    def _load_state(self) -> None:
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text())
                self._last_id = int(data.get("last_id", 0))
                schema = data.get("schema")
                if schema in ("v5", "v6"):
                    self._schema = schema
                log.info("resumed from last_id=%s schema=%s",
                         self._last_id, self._schema)
                return
            except (json.JSONDecodeError, ValueError, OSError) as e:
                log.warning("state file corrupt (%s); resetting to tail", e)
                self._last_id = 0
                self._schema = None

        # First run (or recovery from corrupt state): detect schema + start at tail.
        if not self.db_path.exists():
            log.info("FTL DB not present yet at %s; will detect on first cycle",
                     self.db_path)
            return
        try:
            with _open_ro(self.db_path) as conn:
                self._schema = _detect_schema(conn)
                table = "query_storage" if self._schema == "v6" else "queries"
                row = conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()
                self._last_id = int(row[0]) if row and row[0] is not None else 0
        except (sqlite3.Error, PiholeSchemaError) as e:
            log.warning(
                "could not initialize pihole state (%s); will retry next cycle", e,
            )
            return
        log.info("first-run init: schema=%s last_id=%s (starting at tail)",
                 self._schema, self._last_id)
        self._persist_state()

    def _persist_state(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "last_id": self._last_id,
            "schema": self._schema,
        }))
        os.replace(tmp, self.state_file)

    # --- main API ---

    def iter_events(self) -> Iterator[ForwardEvent]:
        """Yield events for any new rows since last call."""
        if not self.db_path.exists():
            return  # Pi-hole not installed yet, or DB hasn't been created
        if self._schema is None:
            # State load couldn't detect earlier; retry now.
            try:
                with _open_ro(self.db_path) as conn:
                    self._schema = _detect_schema(conn)
                    table = "query_storage" if self._schema == "v6" else "queries"
                    row = conn.execute(f"SELECT MAX(id) FROM {table}").fetchone()
                    self._last_id = int(row[0]) if row and row[0] is not None else 0
                log.info("schema detected: %s; starting at last_id=%s",
                         self._schema, self._last_id)
                self._persist_state()
            except PiholeSchemaError as e:
                log.error("pihole schema unrecognized; cannot poll: %s", e)
                raise
            except sqlite3.OperationalError as e:
                log.warning("FTL DB busy on schema detect; retrying next cycle: %s", e)
                return
            except sqlite3.Error as e:
                log.warning("FTL DB error on schema detect: %s; will retry", e)
                return

        sql = _QUERY_V6 if self._schema == "v6" else _QUERY_V5

        try:
            with _open_ro(self.db_path) as conn:
                rows = conn.execute(sql, (self._last_id, _BATCH_MAX)).fetchall()
        except sqlite3.OperationalError as e:
            # SQLITE_BUSY or similar — treat as transient.
            log.warning("FTL DB busy on poll; skipping cycle: %s", e)
            return
        except sqlite3.Error as e:
            log.warning("FTL DB error on poll: %s; skipping cycle", e)
            return

        if not rows:
            return

        # Cap iteration time so other adapters in run_once get polled.
        # Each delivery is ~1s on tailnet; without this cap, draining
        # _BATCH_MAX rows could take hundreds of seconds, blocking the cycle.
        import time as _time
        deadline = _time.monotonic() + _TIME_MAX_S
        max_id_seen = self._last_id
        for r in rows:
            row_id = int(r["id"])
            if row_id <= max_id_seen and max_id_seen > 0:
                continue  # defensive; shouldn't happen with `WHERE id > ?`
            max_id_seen = max(max_id_seen, row_id)
            event = self._row_to_event(r)
            if event is not None:
                yield event
                if _time.monotonic() >= deadline:
                    # Time cap fired — persist progress + return so other
                    # adapters get polled. Next cycle resumes from max_id_seen.
                    break

        self._last_id = max_id_seen
        self._persist_state()

    def graceful_shutdown(self) -> None:
        self._persist_state()

    # --- per-row transform ---

    def _row_to_event(self, row: sqlite3.Row) -> Optional[ForwardEvent]:
        try:
            status = int(row["status"]) if row["status"] is not None else 0
        except (TypeError, ValueError):
            status = 0
        label, severity = _STATUS_TABLE.get(status, ("unknown", "info"))

        # Build a JSON-safe dict (sqlite3.Row → dict, ints/strs only).
        raw = {k: row[k] for k in row.keys()}
        raw["status_label"] = label

        return {
            "event_type": "pihole.query",
            "severity": severity,
            "source_host": self._hostname,
            "data": {
                "raw_query": raw,
                "_buoy": self._hostname,
                "_adapter": self.name,
                "_adapter_version": "1.0",
            },
        }


__all__ = ["PiholeAdapter", "PiholeSchemaError", "_STATUS_TABLE"]
