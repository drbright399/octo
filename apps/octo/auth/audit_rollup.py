"""Hourly roll-up of POLLED reads into the hash-chained global audit log.

The dashboard polls four ticket counters/feeds every 20-30 s, the tickets
page polls the agent-activity feed every 15 s and the super_admin System page
polls storage + retention every 30 s. One chain row per poll buried every
decision in the log: on one bundle, 14,172 of 14,416 global rows were
`tickets.list`. The audit policy (docs/audit-policy.md) keeps every write,
every auth event and every on-demand sensitive read at one row per call, and
rolls these polled reads up per (operator, session, action, UTC clock hour)
into at most two rows:

  open   written by the FIRST call of the window, synchronously, before the
         response. "Session S of operator X read <action> during hour H" is
         on disk the moment it first happens, so a crash cannot lose it.
  close  written once the hour is over — by the next polled read of ANY
         caller, or by the app's shutdown hook (then `partial: true`) — with
         the call count, first/last call time, rows returned and the
         distinct request shapes (so a scrape through the list endpoint still
         shows up as volume and variety, not as one quiet row).

An open row without a close means the process died inside the window: the
count is lost, the access is not. A restart mid-window starts a fresh open
row for that window.

Both rows go through `audit.append`: same chain, no UPDATE, no rewritten
history, and `audit.verify` walks them like any other row. Failure to audit
is fatal here too — a polled read whose open row cannot be written fails.

State is per app (`for_app`), so two apps in one process (tests) never write
into each other's audit DB, and each window remembers the audit DB its open
row went to.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.auth import audit
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms

WINDOW = timedelta(hours=1)
# Distinct request shapes kept per window; the rest are counted under one key
# so a caller varying its filters cannot grow memory or the close row.
MAX_SHAPES = 20
OTHER_SHAPES = "(other)"

_STATE_ATTR = "polled_read_audit"
_create_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def window_start(at: datetime) -> datetime:
    """The UTC clock hour `at` falls in."""
    return at.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def _hour_iso(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class _Window:
    action: str
    actor: str
    session_prefix: str
    reason: str
    start: datetime
    audit_path: Path
    open_row_id: int
    open_request_id: str
    first_at: datetime
    last_at: datetime
    calls: int = 0
    rows: Optional[int] = None
    shapes: dict[str, int] = field(default_factory=dict)

    def note(self, at: datetime, rows: Optional[int], shape: Optional[str]) -> None:
        self.calls += 1
        self.last_at = max(self.last_at, at)
        if rows is not None:
            self.rows = (self.rows or 0) + rows
        if shape is not None:
            key = shape if (shape in self.shapes or len(self.shapes) < MAX_SHAPES) \
                else OTHER_SHAPES
            self.shapes[key] = self.shapes.get(key, 0) + 1


def _append(path: Path, entry: audit.AuditEntry) -> int:
    conn = connect(path)
    try:
        return audit.append(conn, entry)
    finally:
        conn.close()


class PolledReadAudit:
    """One per app. Thread-safe: sync routes run on the threadpool, and the
    dashboard fires its polls in parallel. The lock is held across the audit
    write so the open row of a window is written exactly once and a window is
    never closed twice; that serialises polled reads on one small SQLite
    append each, which the audit chain serialises anyway (BEGIN IMMEDIATE)."""

    def __init__(self, clock: Callable[[], datetime] = _utcnow) -> None:
        # Indirection so tests can move time across an hour without sleeping.
        self.clock = clock
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, int, str], _Window] = {}

    @classmethod
    def for_app(cls, app: Any) -> "PolledReadAudit":
        """The app's instance, created on first use (`create_app` creates it
        up front and flushes it on shutdown)."""
        existing = getattr(app.state, _STATE_ATTR, None)
        if existing is not None:
            return existing
        with _create_lock:
            existing = getattr(app.state, _STATE_ATTR, None)
            if existing is None:
                existing = cls()
                setattr(app.state, _STATE_ATTR, existing)
            return existing

    def record(
        self,
        action: str,
        *,
        operator_id: int,
        session_id: str,
        reason: str,
        rows: Optional[int] = None,
        shape: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        """Account for one polled read. Writes the window's open row on its
        first call (and first closes every window that has ended); later
        calls in the same window only count. `shape` must never carry
        free text a caller typed — pass `*` for its presence instead."""
        key = (action, operator_id, session_id)
        with self._lock:
            now = self.clock()
            start = window_start(now)
            self._close_ended(start)
            win = self._windows.get(key)
            if win is None:
                win = self._open(action, operator_id, session_id, reason,
                                 start, now, detail or {})
                self._windows[key] = win
            win.note(now, rows, shape)

    def flush(self) -> int:
        """Close every window now — the app is stopping. Windows whose hour
        has not ended are marked partial. Returns the number of close rows."""
        with self._lock:
            now = self.clock()
            current = window_start(now)
            closed = 0
            for key, win in self._ordered():
                self._write_close(win, partial=win.start >= current)
                del self._windows[key]
                closed += 1
            return closed

    # ------------------------------------------------------------------

    def _ordered(self, *, before: Optional[datetime] = None
                 ) -> list[tuple[tuple[str, int, str], _Window]]:
        items = [kv for kv in self._windows.items()
                 if before is None or kv[1].start < before]
        return sorted(items, key=lambda kv: (kv[1].start, kv[1].first_at))

    def _close_ended(self, current: datetime) -> None:
        # Oldest first, so close rows land in window order. A window is only
        # forgotten once its close row is written: if the write fails the
        # error propagates and the next polled read retries it.
        for key, win in self._ordered(before=current):
            self._write_close(win, partial=False)
            del self._windows[key]

    def _open(
        self, action: str, operator_id: int, session_id: str, reason: str,
        start: datetime, now: datetime, detail: dict[str, Any],
    ) -> _Window:
        actor = f"operator:{operator_id}"
        prefix = session_id[:8]
        path = paths.global_audit_db_path()
        request_id = str(uuid.uuid4())
        row_id = _append(path, audit.AuditEntry(
            actor=actor,
            actor_kind="human",
            action=action,
            target_kind="operator",
            client_slug="global",
            after_state={
                **detail,
                "rollup": "open",
                "window_start": _hour_iso(start),
                "window_end": _hour_iso(start + WINDOW),
                "session_id_prefix": prefix,
            },
            reason=f"{reason} (polled read: hourly roll-up opened)",
            request_id=request_id,
        ))
        return _Window(
            action=action, actor=actor, session_prefix=prefix, reason=reason,
            start=start, audit_path=path, open_row_id=row_id,
            open_request_id=request_id, first_at=now, last_at=now,
        )

    def _write_close(self, win: _Window, *, partial: bool) -> None:
        after: dict[str, Any] = {
            "rollup": "close",
            "window_start": _hour_iso(win.start),
            "window_end": _hour_iso(win.start + WINDOW),
            "session_id_prefix": win.session_prefix,
            "calls": win.calls,
            "first_call_at": format_utc_ms(win.first_at),
            "last_call_at": format_utc_ms(win.last_at),
            "open_row_id": win.open_row_id,
            "open_request_id": win.open_request_id,
            "partial": partial,
        }
        if win.rows is not None:
            after["rows_returned"] = win.rows
        if win.shapes:
            after["shapes"] = dict(sorted(win.shapes.items()))
        _append(win.audit_path, audit.AuditEntry(
            actor=win.actor,
            actor_kind="human",
            action=win.action,
            target_kind="operator",
            client_slug="global",
            after_state=after,
            reason=(f"{win.reason} (polled read: hourly roll-up closed"
                    f"{' early, app stopping' if partial else ''})"),
            request_id=str(uuid.uuid4()),
        ))
