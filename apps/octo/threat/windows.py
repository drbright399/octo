"""Evidence windows — the record (Tier Black, 044).

Rick, 2026-10-05: "Ingestion should not stop but if a threat is confirmed
everything from first detection up until the all clear should be treated as
event evidence."

A Red or Black incident IS a confirmed threat — only a rule or a person opens
one. So the incident store (`apps.octo.threat.store`) keeps, in the SAME
transaction as every lifecycle change, the tenant's `evidence_windows`
(migration 044, events.db):

  open      an AUTOMATIC window: from the incident's FIRST DETECTION — the
            earliest time of the evidence linked to it (its events' vendor
            time and arrival, its facts' observation), else its open — and
            OPEN (no end) until the all-clear;
  evidence  earlier evidence linked later widens it back to the new first
            detection (never forward);
  raise     Red → Black in place: the same window;
  close     the all-clear: its end = the close's time; the window stays HELD
            (every retention path keeps what lies inside it) until an admin
            releases it — no automatic expiry;
  reopen    (the same key within 14 days of a close — the existing rule) its
            held window is open again; a released one is not revived: a NEW
            window opens from the incident's first detection;
  reclassify a Black closed as reclassified carries its window to the linked
            Red, still open (the Red's close ends it).

A person may also (the API checks roles, step-up and reasons; the store
records):
  widen     analyst+ — an earlier start (dwell time found later), a reason;
  add       admin — a MANUAL window (the former legal hold): an explicit
            start and an end, or none (held open until released);
  extend    admin — a window's start earlier and/or its end later;
  release   admin — after the all-clear only; the window is then history.
Nobody shrinks a window except by releasing it; nothing is ever deleted (the
triggers keep both rules again under this code).

Timestamps are canonical UTC ms (`format_utc_ms`). A vendor time before
`FIRST_DETECTION_FLOOR` (a dead clock's 1970, say) is never a first
detection — it would hold the tenant's whole history.

Nothing here is read by ingest: a window never stops nor slows ingestion.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo.ingest.timestamps import normalize_timestamp

TABLE = "evidence_windows"
AUTO, MANUAL = "incident", "manual"
KINDS = (AUTO, MANUAL)
_CLOSED = ("closed", "false_positive")
FIRST_DETECTION_FLOOR = "2000-01-01T00:00:00.000Z"


class WindowRefused(Exception):
    """A change the window record refuses (the store maps it to Refused)."""


@dataclass
class EvidenceWindow:
    id: int
    incident_id: int
    origin_incident_id: int
    kind: str
    start: str
    end: Optional[str]
    opened_by: str
    opened_at: str
    reason: str
    released_at: Optional[str] = None
    released_by: Optional[str] = None
    release_reason: Optional[str] = None
    kept_rows: Optional[int] = None
    kept_counted_at: Optional[str] = None
    # The latest end it ever had (an admin's extension, an end a reopen
    # opened again): the next all-clear never ends it earlier.
    min_end: Optional[str] = None

    @property
    def held(self) -> bool:
        return self.released_at is None

    @property
    def is_open(self) -> bool:
        return self.end is None

    def as_dict(self) -> dict[str, Any]:
        out = {k: getattr(self, k) for k in self.__dataclass_fields__}
        out["held"] = self.held
        out["open"] = self.is_open
        return out


def canonical(value: Any) -> Optional[str]:
    """Canonical UTC ms, or None (unparseable / empty)."""
    text = normalize_timestamp(value, naive_is_utc=True) if value else ""
    return text or None


def _window(r: sqlite3.Row) -> EvidenceWindow:
    return EvidenceWindow(
        id=int(r["id"]), incident_id=int(r["incident_id"]),
        origin_incident_id=int(r["origin_incident_id"]), kind=r["kind"], start=r["start_at"],
        end=r["end_at"], opened_by=r["opened_by"], opened_at=r["opened_at"], reason=r["reason"],
        released_at=r["released_at"], released_by=r["released_by"],
        release_reason=r["release_reason"],
        kept_rows=int(r["kept_rows"]) if r["kept_rows"] is not None else None,
        kept_counted_at=r["kept_counted_at"], min_end=r["min_end_at"])


def has_table(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (TABLE,)).fetchone() is not None


def get(conn: sqlite3.Connection, window_id: int) -> Optional[EvidenceWindow]:
    r = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (window_id,)).fetchone()
    return _window(r) if r is not None else None


def for_incident(conn: sqlite3.Connection, incident_id: int) -> list[EvidenceWindow]:
    """Every window the incident owns or opened (a reclassified Black's
    carried window shows on both), newest first."""
    return [_window(r) for r in conn.execute(
        f"SELECT * FROM {TABLE} WHERE incident_id = ? OR origin_incident_id = ? "
        "ORDER BY id DESC", (incident_id, incident_id)).fetchall()]


def listing(conn: sqlite3.Connection, *, held_only: bool = False,
            released_only: bool = False) -> list[EvidenceWindow]:
    sql = f"SELECT * FROM {TABLE}"
    if held_only:
        sql += " WHERE released_at IS NULL"
    elif released_only:
        sql += " WHERE released_at IS NOT NULL"
    return [_window(r) for r in conn.execute(sql + " ORDER BY id DESC").fetchall()]


def held_incident_ids(conn: sqlite3.Connection) -> set[int]:
    out: set[int] = set()
    for a, b in conn.execute(f"SELECT incident_id, origin_incident_id FROM {TABLE} "
                             "WHERE released_at IS NULL").fetchall():
        out.update((int(a), int(b)))
    return out


def _auto_held(conn: sqlite3.Connection, incident_id: int) -> Optional[EvidenceWindow]:
    r = conn.execute(f"SELECT * FROM {TABLE} WHERE incident_id = ? AND kind = ? "
                     "AND released_at IS NULL", (incident_id, AUTO)).fetchone()
    return _window(r) if r is not None else None


# ---------------------------------------------------------------------------
# First detection
# ---------------------------------------------------------------------------

def first_detection(conn: sqlite3.Connection, incident_id: int, fallback: str) -> str:
    """The earliest time of the evidence linked to the incident — its
    events' vendor time AND arrival (`incident_events`), the facts recorded
    against it (`threat_fact.incident_id`) — and never later than
    `fallback` (its open). A time before `FIRST_DETECTION_FLOOR`, or one
    that cannot be read, is not a detection."""
    candidates: list[str] = []
    cols = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    picks = ["e.received_at"] + (["e.ingested_at"] if "ingested_at" in cols else [])
    for row in conn.execute(
            f"SELECT {', '.join(picks)} FROM incident_events ie JOIN events e "
            "ON e.id = ie.event_id WHERE ie.incident_id = ?", (incident_id,)).fetchall():
        candidates.extend(v for v in row if v)
    candidates.extend(r[0] for r in conn.execute(
        "SELECT observed_at FROM threat_fact WHERE incident_id = ?", (incident_id,)).fetchall()
        if r[0])
    # A restricted incident's (B7) evidence is not an event: its rows in
    # `restricted_evidence` — the first CSAM lookup opens the window.
    from apps.octo.threat import restricted

    candidates.extend(restricted.first_seen(conn, incident_id))
    best = canonical(fallback) or fallback
    for value in candidates:
        c = canonical(value)
        if c is None or c < FIRST_DETECTION_FLOOR:
            continue
        if c < best:
            best = c
    return best


# ---------------------------------------------------------------------------
# The automatic window — called by the store inside its write transaction.
# Each returns the timeline line to record (None: nothing changed).
# ---------------------------------------------------------------------------

def _insert(conn: sqlite3.Connection, *, incident_id: int, origin: int, kind: str, start: str,
            end: Optional[str], by: str, at_s: str, reason: str) -> int:
    cur = conn.execute(
        f"INSERT INTO {TABLE} (incident_id, origin_incident_id, kind, start_at, end_at, "
        "opened_by, opened_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, origin, kind, start, end, by, at_s, reason[:2000]))
    return int(cur.lastrowid)


def open_auto(conn: sqlite3.Connection, incident_id: int, *, by: str, at_s: str,
              detected_at: str, why: str = "a confirmed threat (Red / Black)") -> str:
    """The incident's automatic window: first detection → open."""
    start = first_detection(conn, incident_id, detected_at)
    wid = _insert(conn, incident_id=incident_id, origin=incident_id, kind=AUTO, start=start,
                  end=None, by=by, at_s=at_s, reason=why)
    return (f"evidence window #{wid} opened: everything of this client from {start} (first "
            "detection) until the all-clear is kept as evidence")


def on_evidence(conn: sqlite3.Connection, incident_id: int, *, detected_at: str) -> Optional[str]:
    """Evidence linked: earlier evidence widens the held window back to the
    new first detection (never forward)."""
    w = _auto_held(conn, incident_id)
    if w is None:
        return None
    start = first_detection(conn, incident_id, detected_at)
    if start >= w.start:
        return None
    conn.execute(f"UPDATE {TABLE} SET start_at = ? WHERE id = ?", (start, w.id))
    return (f"evidence window #{w.id} widened to {start}: earlier evidence was linked (first "
            "detection)")


def on_close(conn: sqlite3.Connection, incident_id: int, *, closed_at: str) -> Optional[str]:
    """The all-clear: the open automatic window ends at the close — and is
    kept until an admin releases it. (A close stamped before the window's
    start — a host clock stepped back — ends it at its start: a close never
    fails because of its window. Never before the latest end it ever had —
    `min_end`: an admin's extension past an earlier close survives the
    reopen and this close; nobody shrinks a window except by release.)"""
    w = _auto_held(conn, incident_id)
    if w is None or w.end is not None:
        return None
    end = max(closed_at, w.start, w.min_end or w.start)
    conn.execute(f"UPDATE {TABLE} SET end_at = ? WHERE id = ?", (end, w.id))
    return (f"evidence window #{w.id} ends at the all-clear ({end}); it is kept "
            "until an admin releases it")


def on_reopen(conn: sqlite3.Connection, incident_id: int, *, by: str, at_s: str,
              detected_at: str) -> str:
    """A reopen: the held window is open again (and widened to the first
    detection if earlier); none held (released) — a new one."""
    w = _auto_held(conn, incident_id)
    if w is None:
        return open_auto(conn, incident_id, by=by, at_s=at_s, detected_at=detected_at,
                         why="the incident reopened (a confirmed threat again)")
    start = min(w.start, first_detection(conn, incident_id, detected_at))
    # The end it had (the last close's — or an admin's extension past it) is
    # kept as its floor: the next all-clear never ends it earlier.
    floor = max(x for x in (w.end, w.min_end) if x) if (w.end or w.min_end) else None
    conn.execute(f"UPDATE {TABLE} SET end_at = NULL, min_end_at = ?, start_at = ? WHERE id = ?",
                 (floor, start, w.id))
    return f"evidence window #{w.id} is open again from {start}: the incident reopened"


def on_reclassify(conn: sqlite3.Connection, black_id: int, red_id: int, *, by: str,
                  at_s: str, detected_at: str) -> str:
    """The Black's held window goes on with the linked Red (still open)."""
    w = _auto_held(conn, black_id)
    if w is None:
        return open_auto(conn, red_id, by=by, at_s=at_s, detected_at=detected_at,
                         why=f"reclassified from Black #{black_id}")
    conn.execute(f"UPDATE {TABLE} SET incident_id = ? WHERE id = ?", (red_id, w.id))
    return (f"evidence window #{w.id} (from {w.start}) carried to Red #{red_id}: it stays "
            "open until that incident's all-clear")


# ---------------------------------------------------------------------------
# A person's changes — the API has checked role, step-up and reason.
# ---------------------------------------------------------------------------

def _owned(conn: sqlite3.Connection, incident_id: int, window_id: int) -> EvidenceWindow:
    w = get(conn, window_id)
    if w is None or incident_id not in (w.incident_id, w.origin_incident_id):
        raise LookupError(f"no evidence window {window_id} on incident {incident_id}")
    return w


def widen(conn: sqlite3.Connection, incident_id: int, window_id: int, *,
          start: str) -> tuple[EvidenceWindow, str]:
    """An earlier start (dwell time found later). Never later."""
    w = _owned(conn, incident_id, window_id)
    if not w.held:
        raise WindowRefused("the window was released — add a new one instead")
    if start >= w.start:
        raise WindowRefused(f"a window only widens: the new start must be before {w.start}")
    conn.execute(f"UPDATE {TABLE} SET start_at = ? WHERE id = ?", (start, w.id))
    return get(conn, w.id), f"evidence window #{w.id} widened from {w.start} to {start}"  # type: ignore[return-value]


def add_manual(conn: sqlite3.Connection, incident_id: int, *, start: str, end: Optional[str],
               by: str, at_s: str, reason: str) -> tuple[EvidenceWindow, str]:
    if end is not None and end < start:
        raise WindowRefused("the end is before the start")
    wid = _insert(conn, incident_id=incident_id, origin=incident_id, kind=MANUAL, start=start,
                  end=end, by=by, at_s=at_s, reason=reason)
    return get(conn, wid), (  # type: ignore[return-value]
        f"evidence window #{wid} added: {start} → "
        + (end if end else "open, until an admin releases it"))


def extend(conn: sqlite3.Connection, incident_id: int, window_id: int, *, start: str,
           end: Optional[str]) -> tuple[EvidenceWindow, str]:
    """An earlier start and / or a later end. An open window's end is
    already "until the all-clear / release": it takes no end."""
    w = _owned(conn, incident_id, window_id)
    if not w.held:
        raise WindowRefused("the window was released — add a new one instead")
    if start > w.start:
        raise WindowRefused(f"a window never shrinks: the start must be {w.start} or earlier "
                            "(release it instead)")
    if end is not None:
        if w.end is None:
            raise WindowRefused("the window is open — it has no end to extend")
        if end < w.end:
            raise WindowRefused(f"a window never shrinks: the end must be {w.end} or later "
                                "(release it instead)")
    new_end = end if end is not None else w.end
    if start == w.start and new_end == w.end:
        raise WindowRefused("nothing to extend: the window already covers that")
    conn.execute(f"UPDATE {TABLE} SET start_at = ?, end_at = ? WHERE id = ?",
                 (start, new_end, w.id))
    return get(conn, w.id), (  # type: ignore[return-value]
        f"evidence window #{w.id} extended: {start} → " + (new_end or "open"))


def release(conn: sqlite3.Connection, incident_id: int, window_id: int, *, by: str, at_s: str,
            reason: str) -> tuple[EvidenceWindow, str]:
    w = _owned(conn, incident_id, window_id)
    if not w.held:
        raise WindowRefused("the window is already released")
    owner = conn.execute("SELECT status FROM incidents WHERE id = ?", (w.incident_id,)).fetchone()
    if owner is None or owner["status"] not in _CLOSED:
        raise WindowRefused("evidence is kept until the all-clear: close the incident first")
    conn.execute(f"UPDATE {TABLE} SET released_at = ?, released_by = ?, release_reason = ? "
                 "WHERE id = ?", (at_s, by, reason[:2000], w.id))
    return get(conn, w.id), (  # type: ignore[return-value]
        f"evidence window #{w.id} ({w.start} → {w.end or 'open'}) RELEASED — its rows age "
        f"out under normal retention from the next nightly run: {reason}")
