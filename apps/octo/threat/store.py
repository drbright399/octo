"""Incident records — a tenant's `incidents` table in its events.db
(migration 044's events section) and the tables around it.

THE RULES THE STORE KEEPS (and the triggers keep again under it):
  * an incident is RED or BLACK; it is opened by a rule or a person
    (`open_incident`), never by a health condition;
  * one OPEN incident per dedupe key: the same key again APPENDS evidence
    (and RAISES Red → Black when the new fact is Black — the acknowledgement
    AND any containment are cleared and the paging ladder restarts); the same
    key within 14 days of a close REOPENS it (the client's 60-minute clock
    restarts too), unless an analyst verdict blocks the key — and a verdict
    only ever blocks an AUTOMATED rule: a person's declaration (B6 / R8) is
    never refused by one (G10 blocks re-FIRING; "the client calls: someone is
    controlling my screen" is always heard);
  * only a PERSON closes (`close` refuses the system actor); there is no
    lower, mute or snooze (a Black is never written as a Red: "close as
    reclassified" closes the Black and opens a linked Red);
  * what it was opened on is frozen (detected_at, rule_id, the evidence
    snapshot and its sha256);
  * nothing is ever deleted; every human step lands on the timeline
    (`incident_notes`);
  * a Red / Black is a confirmed threat: its EVIDENCE WINDOW (Rick,
    2026-10-05 — first detection → the all-clear, held until an admin
    releases it; `apps.octo.threat.windows`) opens, widens, ends, reopens
    and is carried by a reclassify IN THE SAME TRANSACTION as the change —
    the retention job keeps everything of the tenant inside it.

THE SIGNAL EVENTS (design 6.3). Every lifecycle change — open, append,
raise, reopen, acknowledge, assign, note, contain, close, reclassify, a
decision and its answer — also appends ONE `athena.incident` event to the
tenant's events.db, IN THE SAME TRANSACTION as the change: source `athena`,
source_host = the device, severity critical (Black) / high (Red), summary
`[black] raise: …`, payload an OCSF 2005 Incident Finding (activity Create /
Update / Close, severity_id 5 / 4, is_suspected_breach for Black, the
verdict at close, finding_info.uid = the rule, the related events from
`incident_events`). The `incidents` row is the mutable projection; these
events are the immutable timeline. `incident_signals` lists them, so the
retention job keeps every one (an incident is never deleted). The engine's
own bookkeeping (a paging step, the client-visibility stamp) is audited,
not an event. Events from source `athena` are Athena's OWN records: the
triage worker never triages them, a client user's search never returns
them, the site's alert list never lists them and R8 never "confirms" one.

LAZY SCHEMA. A tenant provisioned from 044 on has the schema; an older
events.db gets 044's events section the first time the store is used for it
(`ensure_schema`, under BEGIN IMMEDIATE, re-checked inside the lock). A read
path never creates anything: `read()` answers None for a file without the
schema ("no incidents yet" — the caller decides what that means; the Fleet
keeps its last-known set rather than reading it as Green).

The store never audits: the API audits BEFORE it calls a writer here, and
the engine audits its own steps.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional, Union

from apps.octo import paths
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.threat import registry, rules, windows
from apps.octo.threat import restricted as _restricted

logger = logging.getLogger(__name__)

RED, BLACK = "red", "black"
TIERS = (RED, BLACK)
SEVERITY = {RED: "high", BLACK: "critical"}
OPEN_STATUSES = ("open", "acknowledged", "notified", "investigating")
CLOSED_STATUSES = ("closed", "false_positive")
CLOSE_CODES = ("remediated", "authorized_activity", "duplicate", "false_positive",
               "reclassified_red")
# Codes that close a TRUE positive (they start the post-incident watch).
TRUE_POSITIVE_CODES = ("remediated",)
SCOPES = ("device", "site", "tenant")
EVENT_ROLES = ("trigger", "corroboration", "context", "action")
DECISION_KINDS = ("lockdown", "allow")
REOPEN_WINDOW = timedelta(days=14)
RECENT_WINDOW = timedelta(days=30)
SYSTEM_ACTOR = "system:tier-engine"
BUSY_TIMEOUT_SEC = 10.0
# A restricted incident (B7, CSAM): nothing is done to the device — the
# evidence is preserved and the user is not tipped off.
RESTRICTED_NO_ACTION = ("no device action of any kind for a restricted incident — preserve "
                        "the device as-is (see the checklist)")
MIGRATION = 44
# The lifecycle events (design 6.3): Athena's own records in events.db.
EVENT_SOURCE = "athena"
EVENT_TYPE = "athena.incident"
# Timeline kinds that are the engine's bookkeeping (audited, not an event).
_NOT_SIGNALS = ("escalation", "client_visible")
# OCSF 2005 Incident Finding.
_OCSF_ACTIVITY = {1: "Create", 2: "Update", 3: "Close"}
_OCSF_STATUS = {"open": (1, "New"), "acknowledged": (2, "In Progress"),
                "notified": (2, "In Progress"), "investigating": (2, "In Progress"),
                "closed": (5, "Closed"), "false_positive": (5, "Closed")}
_OCSF_VERDICT = {"remediated": (2, "True Positive"), "false_positive": (1, "False Positive"),
                 "authorized_activity": (5, "Benign"), "duplicate": (10, "Duplicate"),
                 "reclassified_red": (99, "Reclassified (Red)")}

_lock = threading.Lock()
_ensured: set[str] = set()


class StoreError(Exception):
    """A request the record refuses (the API maps it to 409 / 404)."""


class NotFound(StoreError):
    pass


class Refused(StoreError):
    pass


def _iso(dt: Optional[datetime] = None) -> str:
    return format_utc_ms(dt or datetime.now(timezone.utc))


def parse(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def events_db_path(slug: str) -> Path:
    return paths.client_dir(slug) / "events.db"


def has_schema(conn: sqlite3.Connection) -> bool:
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
    except sqlite3.Error:
        return False
    return "tier" in cols and "ladder_started_at" in cols


def _section(target: str = "events") -> str:
    from apps.octo.migration import list_migrations

    mig = next(m for m in list_migrations(kind="forward") if m.number == MIGRATION)
    out: list[str] = []
    current: Optional[str] = None
    for line in mig.sql.splitlines():
        m = re.match(r"^--\s*@target:\s*(\w+)\s*$", line)
        if m:
            current = m.group(1)
            continue
        if current == target:
            out.append(line)
    return "\n".join(out)


def _statements(sql: str) -> list[str]:
    """The section's statements, without its own BEGIN / COMMIT (the caller
    holds the transaction)."""
    stmts: list[str] = []
    buf = ""
    for line in sql.splitlines(keepends=True):
        if not buf and (not line.strip() or line.strip().startswith("--")):
            continue
        buf += line
        if sqlite3.complete_statement(buf):
            text = buf.strip()
            buf = ""
            if text.upper().rstrip(";").strip() in ("BEGIN IMMEDIATE", "COMMIT", "BEGIN"):
                continue
            stmts.append(text)
    return stmts


def ensure_schema(slug: str) -> bool:
    """Give the tenant's events.db 044's events section if it lacks it.
    False when the tenant has no events.db (not provisioned — nothing is
    created). Raises sqlite3.Error on a real fault."""
    path = events_db_path(slug)
    key = str(path)
    if key in _ensured and path.exists():
        return True
    if not path.exists():
        return False
    with _lock:
        conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
        try:
            if not has_schema(conn):
                conn.execute("BEGIN IMMEDIATE")
                try:
                    if not has_schema(conn):          # re-checked under the lock
                        for stmt in _statements(_section()):
                            conn.execute(stmt)
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                logger.info("[threat-store] %s: incident schema (044) added", slug)
        finally:
            conn.close()
        _ensured.add(key)
    return True


def restore_parked_windows() -> list[str]:
    """Startup, EVERY tenant whatever its status: an events.db holding
    evidence windows a 044 rollback parked (`evidence_windows_rolled_back_
    044` — still held) but not 044's schema gets 044's events section again
    (`ensure_schema`), which puts the windows back: listed in the console,
    releasable by an admin. Without this a re-upgrade would leave them
    parked until the tier worker reached the tenant — and it reaches ACTIVE
    tenants only, and only when it runs. (Retention honours parked windows
    meanwhile: `apps.octo.retention.evidence.held_on`.) Returns the slugs
    restored; a tenant that fails is logged and skipped (it is retried at
    the next start)."""
    from apps.octo.retention import evidence as retention_evidence

    out: list[str] = []
    clients = paths.data_root() / "clients"
    if not clients.is_dir():
        return out
    for child in sorted(clients.iterdir()):
        db = child / "events.db"
        if not child.is_dir() or not db.exists() or not paths.SLUG_RE.match(child.name):
            continue
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_SEC)
            try:
                parked = (not has_schema(conn)) and any(
                    w for w in retention_evidence.held_on(conn))
            finally:
                conn.close()
            if parked:
                _ensured.discard(str(events_db_path(child.name)))
                ensure_schema(child.name)
                out.append(child.name)
                logger.warning("[threat-store] %s: evidence windows a rollback had parked are "
                               "back (044 re-applied)", child.name)
        except (sqlite3.Error, OSError, ValueError) as exc:
            logger.error("[threat-store] %s: parked evidence windows not restored (%s)",
                         child.name, type(exc).__name__)
    return out


def reset_schema_cache() -> None:
    """Tests: forget which files were ensured."""
    with _lock:
        _ensured.clear()


@contextmanager
def write(slug: str) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE … COMMIT on the tenant's events.db (schema ensured).
    Raises NotFound when the tenant has no events.db."""
    if not ensure_schema(slug):
        raise NotFound("the tenant has no event store")
    conn = sqlite3.connect(events_db_path(slug), timeout=BUSY_TIMEOUT_SEC, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


@contextmanager
def read(slug: str) -> Iterator[Optional[sqlite3.Connection]]:
    """A read-only connection, or None (no file, or no 044 schema yet).
    Raises sqlite3.Error when the file exists but cannot be read — the
    caller must not read that as "no incidents"."""
    path = events_db_path(slug)
    if not path.exists():
        yield None
        return
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
        yield conn if has_schema(conn) else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    slug: str
    id: int
    tier: str
    status: str
    severity: str
    rule_id: str
    rule_version: int
    dedupe_key: str
    summary: str
    detected_at: str
    site_key: Optional[str] = None
    device_ref: Optional[str] = None
    device_label: Optional[str] = None
    scope: str = "tenant"
    stages: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    event_ids: list[int] = field(default_factory=list)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    assigned_to: Optional[str] = None
    contained_at: Optional[str] = None
    contained_by: Optional[str] = None
    closed_by: Optional[str] = None
    closed_at: Optional[str] = None
    close_reason: Optional[str] = None
    close_reason_code: Optional[str] = None
    reclassified_from: Optional[int] = None
    reopened_count: int = 0
    client_visible_at: Optional[str] = None
    escalation_step: int = 0
    last_escalated_at: Optional[str] = None
    ladder_started_at: Optional[str] = None
    last_evidence_at: Optional[str] = None
    opened_by: Optional[str] = None
    open_reason: Optional[str] = None
    snapshot_sha256: Optional[str] = None
    autonomy_mode_at_open: Optional[str] = None

    @property
    def is_open(self) -> bool:
        return self.status not in CLOSED_STATUSES

    @property
    def acked(self) -> bool:
        return self.acknowledged_at is not None

    @property
    def contained(self) -> bool:
        return self.contained_at is not None

    @property
    def true_positive(self) -> bool:
        return self.close_reason_code in TRUE_POSITIVE_CODES

    @property
    def restricted(self) -> bool:
        """A RESTRICTED rule's incident (B7, CSAM): admin+ only, every view
        audited, no device action, neutral paging (`threat.restricted`)."""
        return rules.restricted(self.rule_id)

    def ladder_t0(self) -> Optional[datetime]:
        return parse(self.ladder_started_at) or parse(self.detected_at)

    def age_s(self, now: datetime) -> int:
        t0 = parse(self.detected_at)
        return max(0, int((now - t0).total_seconds())) if t0 else 0

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _loads(value: Any, default: Any) -> Any:
    if not isinstance(value, str) or not value:
        return default
    try:
        out = json.loads(value)
    except (ValueError, RecursionError):
        return default
    return out if isinstance(out, type(default)) else default


def _incident(slug: str, r: sqlite3.Row) -> Incident:
    return Incident(
        slug=slug, id=int(r["id"]), tier=r["tier"], status=r["status"], severity=r["severity"],
        rule_id=r["rule_id"] or "", rule_version=int(r["rule_version"] or 0),
        dedupe_key=r["dedupe_key"] or "", summary=r["summary"] or "",
        detected_at=r["detected_at"], site_key=r["site_key"], device_ref=r["device_ref"],
        device_label=r["device_label"], scope=r["scope"] or "tenant",
        stages=_loads(r["stages"], []), evidence=_loads(r["evidence_refs"], {}),
        event_ids=[int(i) for i in _loads(r["event_ids"], []) if isinstance(i, int)],
        acknowledged_by=r["acknowledged_by"], acknowledged_at=r["acknowledged_at"],
        assigned_to=r["assigned_to"], contained_at=r["contained_at"],
        contained_by=r["contained_by"], closed_by=r["closed_by"], closed_at=r["closed_at"],
        close_reason=r["close_reason"], close_reason_code=r["close_reason_code"],
        reclassified_from=r["reclassified_from"], reopened_count=int(r["reopened_count"] or 0),
        client_visible_at=r["client_visible_at"],
        escalation_step=int(r["escalation_step"] or 0),
        last_escalated_at=r["last_escalated_at"], ladder_started_at=r["ladder_started_at"],
        last_evidence_at=r["last_evidence_at"], opened_by=r["opened_by"],
        open_reason=r["open_reason"], snapshot_sha256=r["snapshot_sha256"],
        autonomy_mode_at_open=r["autonomy_mode_at_open"],
    )


def _row(conn: sqlite3.Connection, slug: str, incident_id: int) -> Incident:
    r = conn.execute("SELECT * FROM incidents WHERE id = ? AND tier IS NOT NULL",
                     (incident_id,)).fetchone()
    if r is None:
        raise NotFound(f"no incident {incident_id}")
    return _incident(slug, r)


def _note(conn: sqlite3.Connection, incident_id: int, author: str, kind: str, text: str,
          at: str, *, signal: bool = True) -> None:
    """One timeline entry — and, for a lifecycle change, its signal event
    (the caller has already written the change: the event carries the
    record as it now is). `signal=False`: a consequence of a change that
    has its own event (the automatic evidence window of an open / close)."""
    conn.execute("INSERT INTO incident_notes (incident_id, author, kind, text, created_at) "
                 "VALUES (?, ?, ?, ?, ?)", (incident_id, author, kind, text[:4000], at))
    if signal and kind not in _NOT_SIGNALS:
        _signal(conn, incident_id, change=kind, by=author, at=at)


def _window_note(conn: sqlite3.Connection, incident_id: int, text: Optional[str],
                 at: str) -> None:
    """The automatic evidence window's change on the timeline (no event of
    its own: the incident change that caused it has one)."""
    if text:
        _note(conn, incident_id, SYSTEM_ACTOR, "evidence_window", text, at, signal=False)


def _auto_window(conn: sqlite3.Connection, change) -> Optional[str]:  # noqa: ANN001
    """Run an automatic evidence-window change inside the incident's write,
    in a SAVEPOINT: should it fail, the incident change still happens (a
    person is always heard, the paging goes on) and the timeline says the
    window was NOT recorded, so a person adds it by hand."""
    conn.execute("SAVEPOINT evidence_window")
    try:
        text = change()
    except sqlite3.Error as exc:
        conn.execute("ROLLBACK TO SAVEPOINT evidence_window")
        conn.execute("RELEASE SAVEPOINT evidence_window")
        logger.error("[threat-store] evidence window not recorded (%s: %s)",
                     type(exc).__name__, exc)
        return (f"evidence window NOT recorded ({type(exc).__name__}) — an admin must add one "
                "by hand (evidence window → add) so this client's evidence is kept")
    conn.execute("RELEASE SAVEPOINT evidence_window")
    return text


def _signal(conn: sqlite3.Connection, incident_id: int, *, change: str, by: str,
            at: str) -> int:
    """Append the `athena.incident` lifecycle event (OCSF 2005) for the
    record as it is now, inside the caller's transaction. Returns its id."""
    from apps.octo.ingest import arrival

    inc = _incident("", conn.execute("SELECT * FROM incidents WHERE id = ?",
                                     (incident_id,)).fetchone())
    activity = 1 if change == "open" else 3 if change in ("close", "reclassify") else 2
    # A RESTRICTED incident's own records are searchable by every operator:
    # they say "restricted incident" and nothing else (no rule, device,
    # category or summary — the incident itself is admin-only).
    hidden = inc.restricted
    status_id, status_name = _OCSF_STATUS.get(inc.status, (99, "Other"))
    related = [int(r[0]) for r in conn.execute(
        "SELECT event_id FROM incident_events WHERE incident_id = ? ORDER BY event_id",
        (incident_id,)).fetchall()]
    rule = rules.rule(inc.rule_id)
    payload: dict[str, Any] = {
        "class_uid": 2005, "class_name": "Incident Finding",
        "category_uid": 2, "category_name": "Findings",
        "activity_id": activity, "activity_name": _OCSF_ACTIVITY[activity],
        "type_uid": 2005 * 100 + activity,
        "time": at,
        "severity_id": 5 if inc.tier == BLACK else 4,
        "severity": "Critical" if inc.tier == BLACK else "High",
        "is_suspected_breach": inc.tier == BLACK,
        "status_id": status_id, "status": status_name,
        "finding_info": {
            "uid": "restricted" if hidden else inc.rule_id, "uid_alt": f"incident:{inc.id}",
            "title": (_restricted.NEUTRAL_SUMMARY if hidden else inc.summary)[:300],
            "desc": "restricted" if hidden else (rule.title if rule else inc.rule_id),
            "related_events": [] if hidden else [{"uid": str(e)} for e in related[:500]],
        },
        "metadata": {"product": {"name": "Athena"}, "version": "1.1.0"},
        "athena": {"incident_id": inc.id, "tier": inc.tier, "change": change,
                   "by": "restricted" if hidden else by,
                   "rule_version": None if hidden else inc.rule_version,
                   "scope": None if hidden else inc.scope,
                   "site_key": None if hidden else inc.site_key,
                   "reopened_count": inc.reopened_count,
                   "reclassified_from": inc.reclassified_from,
                   **({"restricted": True} if hidden else {})},
    }
    if activity == 3 and inc.close_reason_code in _OCSF_VERDICT:
        payload["verdict_id"], payload["verdict"] = _OCSF_VERDICT[inc.close_reason_code]
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    arrival.add_column(conn)
    summary = _restricted.NEUTRAL_SUMMARY if hidden else inc.summary
    cur = conn.execute(
        "INSERT INTO events (received_at, source, source_host, event_type, severity, payload, "
        "payload_sha256, relay_status, summary, ingested_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'skipped', ?, ?)",
        (at, EVENT_SOURCE, None if hidden else inc.device_ref, EVENT_TYPE, SEVERITY[inc.tier],
         text, hashlib.sha256(text.encode()).hexdigest(),
         f"[{inc.tier}] {change}: {summary}"[:500], at))
    eid = int(cur.lastrowid)
    conn.execute("INSERT INTO incident_signals (incident_id, event_id, change, added_at) "
                 "VALUES (?, ?, ?, ?)", (incident_id, eid, change, at))
    return eid


def _stage(inc: Incident, kind: str, at: str, **extra: Any) -> str:
    stages = list(inc.stages) + [{"kind": kind, "at": at, "tier": extra.pop("tier", inc.tier),
                                  **extra}]
    return json.dumps(stages[-200:], sort_keys=True, separators=(",", ":"))


def link_events(conn: sqlite3.Connection, incident_id: int, event_ids: list[int], role: str,
                at: str) -> int:
    if role not in EVENT_ROLES:
        raise ValueError("bad evidence role")
    n = 0
    for eid in event_ids:
        if not isinstance(eid, int) or isinstance(eid, bool):
            continue
        n += conn.execute("INSERT OR IGNORE INTO incident_events (incident_id, event_id, role, "
                          "added_at) VALUES (?, ?, ?, ?)", (incident_id, eid, role, at)).rowcount
    return n


def dedupe_key(slug: str, *, device_ref: Optional[str] = None, site_key: Optional[str] = None,
               family: str, anchor: str = "", multi_device: bool = False) -> str:
    """`tenant|device-or-site|rule_family|anchor_key` (design 6.3). A
    multi-device rule's device part is '*'; a site-level one 'site:<key>'."""
    if multi_device:
        where = "*"
    elif device_ref:
        where = device_ref.strip().lower()
    elif site_key:
        where = f"site:{site_key}"
    else:
        where = "tenant"
    return f"{slug}|{where}|{family}|{anchor}"


def snapshot(evidence: dict[str, Any]) -> tuple[str, str]:
    text = json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str)
    return text, hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def get(slug: str, incident_id: int) -> Incident:
    with read(slug) as conn:
        if conn is None:
            raise NotFound(f"no incident {incident_id}")
        return _row(conn, slug, incident_id)


def list_incidents(slug: str, *, statuses: Optional[tuple[str, ...]] = None,
                   tiers: Optional[tuple[str, ...]] = None, limit: int = 200) -> list[Incident]:
    with read(slug) as conn:
        if conn is None:
            return []
        sql = "SELECT * FROM incidents WHERE tier IS NOT NULL"
        args: list[Any] = []
        if statuses:
            sql += f" AND status IN ({','.join('?' * len(statuses))})"
            args.extend(statuses)
        if tiers:
            sql += f" AND tier IN ({','.join('?' * len(tiers))})"
            args.extend(tiers)
        sql += " ORDER BY id DESC LIMIT ?"
        return [_incident(slug, r) for r in conn.execute(sql, (*args, limit)).fetchall()]


def open_and_recent(slug: str, now: datetime) -> Optional[list[Incident]]:
    """Every OPEN incident, and every one closed in the last 30 days (the
    watch / notice tail). None when the tenant has no schema yet (nothing
    was ever opened). Raises sqlite3.Error when unreadable."""
    with read(slug) as conn:
        if conn is None:
            return None
        rows = conn.execute(
            "SELECT * FROM incidents WHERE tier IS NOT NULL AND "
            "(status NOT IN ('closed', 'false_positive') OR closed_at > ?) ORDER BY id",
            (_iso(now - RECENT_WINDOW),)).fetchall()
        return [_incident(slug, r) for r in rows]


def notes(slug: str, incident_id: int) -> list[dict[str, Any]]:
    with read(slug) as conn:
        if conn is None:
            return []
        return [dict(r) for r in conn.execute(
            "SELECT id, author, kind, text, created_at FROM incident_notes "
            "WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()]


def evidence_events(slug: str, incident_id: int) -> list[dict[str, Any]]:
    with read(slug) as conn:
        if conn is None:
            return []
        return [dict(r) for r in conn.execute(
            "SELECT ie.event_id, ie.role, ie.added_at, e.received_at, e.source, e.event_type, "
            "e.severity FROM incident_events ie LEFT JOIN events e ON e.id = ie.event_id "
            "WHERE ie.incident_id = ? ORDER BY ie.added_at, ie.event_id",
            (incident_id,)).fetchall()]


def decisions(slug: str, incident_id: int) -> list[dict[str, Any]]:
    with read(slug) as conn:
        if conn is None:
            return []
        out = []
        for r in conn.execute("SELECT * FROM incident_decisions WHERE incident_id = ? "
                              "ORDER BY id", (incident_id,)).fetchall():
            d = dict(r)
            d["scope"] = _loads(d.pop("scope_json"), [])
            d["excluded"] = _loads(d.pop("excluded_json"), [])
            out.append(d)
        return out


def event_row(slug: str, event_id: int) -> Optional[dict[str, Any]]:
    with read(slug) as conn:
        if conn is None:
            # No 044 schema yet: the event itself may still exist.
            path = events_db_path(slug)
            if not path.exists():
                return None
            raw = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
            raw.row_factory = sqlite3.Row
            try:
                r = raw.execute("SELECT id, received_at, source, source_host, event_type, "
                                "severity FROM events WHERE id = ?", (event_id,)).fetchone()
            finally:
                raw.close()
            return dict(r) if r else None
        r = conn.execute("SELECT id, received_at, source, source_host, event_type, severity "
                         "FROM events WHERE id = ?", (event_id,)).fetchone()
        return dict(r) if r else None


# ---------------------------------------------------------------------------
# Writes — open / append / raise / reopen
# ---------------------------------------------------------------------------

@dataclass
class Opened:
    incident: Optional[Incident]
    outcome: str
    """'opened' | 'appended' | 'raised' | 'reopened' | 'blocked' (an analyst
    verdict on the key — automated rules only)."""


def _honours_verdicts(rule_id: str) -> bool:
    """An analyst verdict blocks an AUTOMATED rule re-firing on its exact
    key (G10). A person's declaration is never blocked by one: B6 / R8 are
    how a human overrides every automated judgement, a verdict included.
    Nor is a RESTRICTED rule (B7, CSAM): every CSAM lookup opens — or
    reopens — a Black (Rick's B1); a verdict never silences a device."""
    r = rules.rule(rule_id)
    return r is None or (r.automated and not r.restricted)


def predict(slug: str, key: str, tier: str, now: Optional[datetime] = None) -> str:
    """What `open_incident` WOULD do on `key` now — 'open' | 'append' |
    'raise' | 'reopen' — so the caller's audit row (written BEFORE the
    write) names the action that is about to happen. A race can still
    change it; the caller then appends a correcting row."""
    at = now or datetime.now(timezone.utc)
    with read(slug) as conn:
        if conn is None:
            return "open"
        live = conn.execute(
            "SELECT tier FROM incidents WHERE dedupe_key = ? AND tier IS NOT NULL "
            "AND status NOT IN ('closed', 'false_positive')", (key,)).fetchone()
        if live is not None:
            return "raise" if (tier == BLACK and live["tier"] == RED) else "append"
        closed = conn.execute(
            "SELECT 1 FROM incidents WHERE dedupe_key = ? AND tier IS NOT NULL AND closed_at > ? "
            "AND COALESCE(close_reason_code, '') <> 'reclassified_red' LIMIT 1",
            (key, _iso(at - REOPEN_WINDOW))).fetchone()
        return "reopen" if closed is not None else "open"


OUTCOME_ACTION = {"opened": "open", "appended": "append", "raised": "raise",
                  "reopened": "reopen"}


def open_incident(
    slug: str, *, tier: str, rule_id: str, rule_version: int, key: str, summary: str,
    scope: str, opened_by: str, reason: Optional[str] = None,
    site_key: Optional[str] = None, device_ref: Optional[str] = None,
    device_label: Optional[str] = None, evidence: Optional[dict[str, Any]] = None,
    event_ids: Optional[list[int]] = None, event_role: str = "trigger",
    autonomy_mode: str = "propose_only", now: Optional[datetime] = None,
    restricted_ids: Optional[list[int]] = None,
) -> Opened:
    """Open an incident, or — the same key — append to / raise / reopen the
    one there is. Never lowers a tier, never closes. `restricted_ids`: rows
    of `restricted_evidence` (B7) linked to it in the same transaction —
    before its evidence window is opened or widened, so the window starts at
    the first of them."""
    if tier not in TIERS:
        raise ValueError("an incident is red or black")
    if scope not in SCOPES:
        raise ValueError("bad scope")
    at = now or datetime.now(timezone.utc)
    at_s = _iso(at)
    ids = [int(i) for i in (event_ids or []) if isinstance(i, int) and not isinstance(i, bool)]
    if _honours_verdicts(rule_id) and registry.verdict_blocks(slug, key, at):
        return Opened(None, "blocked")
    with write(slug) as conn:
        live = conn.execute(
            "SELECT * FROM incidents WHERE dedupe_key = ? AND tier IS NOT NULL "
            "AND status NOT IN ('closed', 'false_positive')", (key,)).fetchone()
        if live is not None:
            inc = _incident(slug, live)
            return _append(conn, inc, tier=tier, rule_id=rule_id, by=opened_by, reason=reason,
                           event_ids=ids, role=event_role, at_s=at_s,
                           restricted_ids=restricted_ids)
        closed = conn.execute(
            "SELECT * FROM incidents WHERE dedupe_key = ? AND tier IS NOT NULL AND closed_at > ? "
            "AND COALESCE(close_reason_code, '') <> 'reclassified_red' "
            "ORDER BY closed_at DESC, id DESC LIMIT 1",
            (key, _iso(at - REOPEN_WINDOW))).fetchone()
        if closed is not None:
            inc = _incident(slug, closed)
            new_tier = BLACK if BLACK in (tier, inc.tier) else RED
            conn.execute(
                "UPDATE incidents SET status = 'open', tier = ?, severity = ?, closed_at = NULL, "
                "closed_by = NULL, close_reason = NULL, close_reason_code = NULL, "
                "acknowledged_at = NULL, acknowledged_by = NULL, contained_at = NULL, "
                "contained_by = NULL, client_visible_at = NULL, "
                "reopened_count = reopened_count + 1, "
                "escalation_step = 0, last_escalated_at = NULL, ladder_started_at = ?, "
                "last_evidence_at = ?, stages = ? WHERE id = ?",
                (new_tier, SEVERITY[new_tier], at_s, at_s,
                 _stage(inc, "reopen", at_s, tier=new_tier, rule=rule_id, by=opened_by), inc.id))
            link_events(conn, inc.id, ids, event_role, at_s)
            _restricted.link(conn, restricted_ids or [], inc.id, at_s)
            _note(conn, inc.id, opened_by, "reopen",
                  f"reopened ({rule_id}): the same key within 14 days of its close"
                  + (f" — {reason}" if reason else ""), at_s)
            # The evidence window: open again (or, released, a new one).
            _window_note(conn, inc.id, _auto_window(conn, lambda: windows.on_reopen(
                conn, inc.id, by=opened_by, at_s=at_s, detected_at=inc.detected_at)), at_s)
            return Opened(_row(conn, slug, inc.id), "reopened")
        ev = dict(evidence or {})
        ev.setdefault("rule", f"{rule_id}@{rule_version}")
        ev.setdefault("opened_by", opened_by)
        ev.setdefault("opened_at", at_s)
        ev.setdefault("event_ids", ids)
        if reason:
            ev.setdefault("reason", reason)
        text, sha = snapshot(ev)
        cur = conn.execute(
            "INSERT INTO incidents (detected_at, severity, indicator_ids, event_ids, summary, "
            "evidence_refs, status, tier, rule_id, rule_version, dedupe_key, site_key, "
            "device_ref, device_label, scope, stages, last_evidence_at, ladder_started_at, "
            "autonomy_mode_at_open, snapshot_sha256, opened_by, open_reason) "
            "VALUES (?, ?, '[]', ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (at_s, SEVERITY[tier], json.dumps(ids), summary[:500], text, tier, rule_id,
             int(rule_version), key, site_key, device_ref, device_label, scope,
             json.dumps([{"kind": "open", "at": at_s, "tier": tier, "rule": rule_id,
                          "by": opened_by}], separators=(",", ":")),
             at_s, at_s, autonomy_mode, sha, opened_by, (reason or "")[:2000] or None))
        iid = int(cur.lastrowid)
        link_events(conn, iid, ids, event_role, at_s)
        _restricted.link(conn, restricted_ids or [], iid, at_s)
        _note(conn, iid, opened_by, "open",
              f"opened {tier.upper()} ({rule_id})" + (f" — {reason}" if reason else ""), at_s)
        # A Red / Black IS a confirmed threat: its evidence window opens in
        # the same transaction — first detection → the all-clear.
        _window_note(conn, iid, _auto_window(conn, lambda: windows.open_auto(
            conn, iid, by=opened_by, at_s=at_s, detected_at=at_s)), at_s)
        return Opened(_row(conn, slug, iid), "opened")


def _append(conn: sqlite3.Connection, inc: Incident, *, tier: str, rule_id: str, by: str,
            reason: Optional[str], event_ids: list[int], role: str, at_s: str,
            restricted_ids: Optional[list[int]] = None) -> Opened:
    linked = link_events(conn, inc.id, event_ids, role, at_s)
    linked += _restricted.link(conn, restricted_ids or [], inc.id, at_s)
    if linked:
        # Earlier evidence widens the evidence window back (never forward).
        _window_note(conn, inc.id, _auto_window(conn, lambda: windows.on_evidence(
            conn, inc.id, detected_at=inc.detected_at)), at_s)
    if tier == BLACK and inc.tier == RED:
        # Raised within the same incident: its acknowledgement AND any
        # containment are cleared (the attacker is back — a Black that read
        # "contained" would never pulse and would tell the client it was
        # over) and the ladder restarts at T0.
        conn.execute(
            "UPDATE incidents SET tier = 'black', severity = 'critical', status = 'open', "
            "acknowledged_at = NULL, acknowledged_by = NULL, contained_at = NULL, "
            "contained_by = NULL, escalation_step = 0, "
            "last_escalated_at = NULL, ladder_started_at = ?, last_evidence_at = ?, "
            "stages = ? WHERE id = ?",
            (at_s, at_s, _stage(inc, "raise", at_s, tier=BLACK, rule=rule_id, by=by), inc.id))
        _note(conn, inc.id, by, "raise", f"raised to BLACK ({rule_id})"
              + (f" — {reason}" if reason else ""), at_s)
        return Opened(_row(conn, inc.slug, inc.id), "raised")
    conn.execute("UPDATE incidents SET last_evidence_at = ? WHERE id = ?", (at_s, inc.id))
    if event_ids or reason or restricted_ids:
        _note(conn, inc.id, by, "evidence", f"evidence appended ({rule_id})"
              + (f" — {reason}" if reason else ""), at_s)
    return Opened(_row(conn, inc.slug, inc.id), "appended")


def raise_to_black(slug: str, incident_id: int, *, by: str, reason: str,
                   now: Optional[datetime] = None) -> Incident:
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        if not inc.is_open:
            raise Refused("a closed incident is not raised — declare a new one")
        if inc.tier == BLACK:
            raise Refused("already Black")
        return _append(conn, inc, tier=BLACK, rule_id="B6", by=by, reason=reason,
                       event_ids=[], role="context", at_s=at_s).incident  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Writes — the human lifecycle
# ---------------------------------------------------------------------------

def _require_open(inc: Incident) -> None:
    if not inc.is_open:
        raise Refused("the incident is closed")


def ack(slug: str, incident_id: int, *, by: str, note: Optional[str] = None,
        now: Optional[datetime] = None) -> Incident:
    """Stops the ladder and the pulse — never the pin."""
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        if inc.acked:
            raise Refused("already acknowledged")
        conn.execute(
            "UPDATE incidents SET acknowledged_at = ?, acknowledged_by = ?, "
            "status = CASE WHEN status = 'open' THEN 'acknowledged' ELSE status END, "
            "client_visible_at = COALESCE(client_visible_at, ?) WHERE id = ?",
            (at_s, by, at_s, incident_id))
        _note(conn, incident_id, by, "ack", "acknowledged" + (f" — {note}" if note else ""),
              at_s)
        return _row(conn, slug, incident_id)


def assign(slug: str, incident_id: int, *, by: str, to: str,
           now: Optional[datetime] = None) -> Incident:
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        conn.execute("UPDATE incidents SET assigned_to = ? WHERE id = ?", (to, incident_id))
        _note(conn, incident_id, by, "assign", f"assigned to operator #{to}", at_s)
        return _row(conn, slug, incident_id)


def add_note(slug: str, incident_id: int, *, by: str, text: str,
             now: Optional[datetime] = None) -> Incident:
    at_s = _iso(now)
    with write(slug) as conn:
        _row(conn, slug, incident_id)
        _note(conn, incident_id, by, "note", text, at_s)
        conn.execute("UPDATE incidents SET last_evidence_at = COALESCE(last_evidence_at, ?) "
                     "WHERE id = ?", (at_s, incident_id))
        return _row(conn, slug, incident_id)


def contain(slug: str, incident_id: int, *, by: str, receipt: str,
            now: Optional[datetime] = None) -> Incident:
    """Marked contained (a receipt or a reason) — the static double ring.
    Records only: nothing is executed."""
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        if inc.restricted:
            raise Refused(RESTRICTED_NO_ACTION)
        if inc.contained:
            raise Refused("already marked contained")
        conn.execute("UPDATE incidents SET contained_at = ?, contained_by = ?, stages = ? "
                     "WHERE id = ?",
                     (at_s, by, _stage(inc, "contain", at_s, by=by), incident_id))
        _note(conn, incident_id, by, "contain", f"marked contained — {receipt}", at_s)
        return _row(conn, slug, incident_id)


def close(slug: str, incident_id: int, *, by: str, code: str, text: str,
          checklist: Optional[dict[str, Any]] = None, expected_tier: Optional[str] = None,
          now: Optional[datetime] = None) -> Incident:
    """Only a PERSON closes. 'false_positive' sets that status; every other
    code 'closed'. `expected_tier`: the tier the caller's role checks were
    made for — re-checked INSIDE the write transaction, so a Red raised to
    Black between the check and the write is never closed by a Red's rules
    (an analyst, no step-up, no checklist)."""
    if not by or by.startswith("system"):
        raise Refused("only a person closes an incident")
    if code not in CLOSE_CODES or code == "reclassified_red":
        raise ValueError("bad close code")
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        if expected_tier is not None and inc.tier != expected_tier:
            raise Refused(f"the incident is now {inc.tier.upper()} — it changed while you were "
                          "closing it; reload it and try again")
        status = "false_positive" if code == "false_positive" else "closed"
        conn.execute(
            "UPDATE incidents SET status = ?, closed_at = ?, closed_by = ?, close_reason = ?, "
            "close_reason_code = ?, stages = ? WHERE id = ?",
            (status, at_s, by, text[:2000], code,
             _stage(inc, "close", at_s, by=by, code=code), incident_id))
        _note(conn, incident_id, by, "close", f"closed ({code}) — {text}"
              + (f" · checklist {json.dumps(checklist, sort_keys=True)}" if checklist else ""),
              at_s)
        # The all-clear: the evidence window ends here — and stays held
        # until an admin releases it.
        _window_note(conn, incident_id, _auto_window(conn, lambda: windows.on_close(
            conn, incident_id, closed_at=at_s)), at_s)
        if code == "authorized_activity":
            # Design 6.4: an `authorized_activity` close creates a PROPOSAL
            # fact — what to register (a registry / roster / IR entry, an
            # exception) so the same activity does not fire again. A
            # proposal only: a person turns it into an entry later.
            conn.execute(
                "INSERT OR IGNORE INTO threat_fact (fact_key, kind, stage, device_ref, "
                "site_key, observed_at, source, attrs, incident_id) "
                "VALUES (?, 'authorized_activity_proposal', 'live', ?, ?, ?, ?, ?, ?)",
                (f"proposal:incident:{incident_id}:{at_s}", inc.device_ref, inc.site_key, at_s,
                 EVENT_SOURCE,
                 json.dumps({"rule": inc.rule_id, "dedupe_key": inc.dedupe_key,
                             "closed_by": by, "why": text[:500],
                             "propose": "registry, roster, IR entry or exception"},
                            sort_keys=True), incident_id))
        return _row(conn, slug, incident_id)


# ---------------------------------------------------------------------------
# Evidence windows — reads and a person's changes (`apps.octo.threat.windows`).
# The former tenant-wide legal hold is gone (Rick, 2026-10-05): an admin adds
# or extends an evidence window instead, which keeps what lies inside it.
# ---------------------------------------------------------------------------

def evidence_windows(slug: str, *, incident_id: Optional[int] = None,
                     state: str = "all") -> list[windows.EvidenceWindow]:
    """The tenant's windows (`state` held | released | all), or those of one
    incident (it owns or opened them). Raises sqlite3.Error when the store
    cannot be read."""
    with read(slug) as conn:
        if conn is None or not windows.has_table(conn):
            return []
        if incident_id is not None:
            out = windows.for_incident(conn, incident_id)
            return [w for w in out if state == "all" or (w.held == (state == "held"))]
        return windows.listing(conn, held_only=state == "held",
                               released_only=state == "released")


EVENTS_COUNT_CAP = 100_000


def events_in_window(slug: str, start: str, end: Optional[str], *,
                     cap: int = EVENTS_COUNT_CAP) -> Optional[tuple[int, bool]]:
    """About how many events of the tenant ARRIVED inside [start, end] — an
    index range count, stopped at `cap` (returns (n, capped)). None when it
    is not cheap (no arrival index) or there is no store."""
    from apps.octo.ingest import arrival

    with read(slug) as conn:
        if conn is None or not (arrival.has_column(conn) and arrival.has_index(conn)):
            return None
        sql = "SELECT 1 FROM events WHERE ingested_at >= ?"
        args: list[Any] = [start]
        if end:
            sql += " AND ingested_at <= ?"
            args.append(end)
        n = int(conn.execute(f"SELECT COUNT(*) FROM ({sql} LIMIT ?)",
                             (*args, cap + 1)).fetchone()[0])
        return min(n, cap), n > cap


def held_window_incidents(slug: str) -> set[int]:
    """Incident ids with a held evidence window (owned or opened)."""
    with read(slug) as conn:
        if conn is None or not windows.has_table(conn):
            return set()
        return windows.held_incident_ids(conn)


def _window_change(slug: str, incident_id: int, by: str, at_s: str, change) -> windows.EvidenceWindow:  # noqa: ANN001
    with write(slug) as conn:
        _row(conn, slug, incident_id)
        try:
            w, text = change(conn)
        except windows.WindowRefused as exc:
            raise Refused(str(exc)) from None
        except LookupError as exc:
            raise NotFound(str(exc)) from None
        _note(conn, incident_id, by, "evidence_window", text, at_s)
        return w


def _ts(value: str, what: str) -> str:
    out = windows.canonical(value)
    if out is None:
        raise ValueError(f"the {what} is not a date and time")
    return out


def _start(value: str, at_s: str) -> str:
    """A person's window start: a date and time, not in the future, and not
    before `windows.FIRST_DETECTION_FLOOR` (a slip — 0001, or 1970 from an
    empty field — would hold the tenant's whole history until a release)."""
    out = _ts(value, "start")
    if out > at_s:
        raise ValueError("the start is in the future")
    if out < windows.FIRST_DETECTION_FLOOR:
        raise ValueError(f"the start is before {windows.FIRST_DETECTION_FLOOR[:10]} — "
                         "check the year")
    return out


def widen_window(slug: str, incident_id: int, window_id: int, *, start: str, by: str,
                 reason: str, now: Optional[datetime] = None) -> windows.EvidenceWindow:
    """analyst+ (the API checks): an earlier start — dwell time found later."""
    at_s = _iso(now)
    start_s = _start(start, at_s)

    def change(conn: sqlite3.Connection):  # noqa: ANN202
        w, text = windows.widen(conn, incident_id, window_id, start=start_s)
        return w, f"{text} — {reason}"

    return _window_change(slug, incident_id, by, at_s, change)


def add_window(slug: str, incident_id: int, *, start: str, end: Optional[str], by: str,
               reason: str, now: Optional[datetime] = None) -> windows.EvidenceWindow:
    """admin (the API checks, with step-up): a MANUAL window — the former
    legal hold — an explicit start and an end, or none (held open until
    released). Open or closed incidents alike (a claim often follows the
    close)."""
    at_s = _iso(now)
    start_s = _start(start, at_s)
    end_s = _ts(end, "end") if end else None

    def change(conn: sqlite3.Connection):  # noqa: ANN202
        w, text = windows.add_manual(conn, incident_id, start=start_s, end=end_s, by=by,
                                     at_s=at_s, reason=reason)
        return w, f"{text} — {reason}"

    return _window_change(slug, incident_id, by, at_s, change)


def extend_window(slug: str, incident_id: int, window_id: int, *, start: str,
                  end: Optional[str], by: str, reason: str,
                  now: Optional[datetime] = None) -> windows.EvidenceWindow:
    """admin (the API checks, with step-up): an earlier start and / or a
    later end. Never a shrink."""
    at_s = _iso(now)
    start_s = _start(start, at_s)
    end_s = _ts(end, "end") if end else None

    def change(conn: sqlite3.Connection):  # noqa: ANN202
        w, text = windows.extend(conn, incident_id, window_id, start=start_s, end=end_s)
        return w, f"{text} — {reason}"

    return _window_change(slug, incident_id, by, at_s, change)


def release_window(slug: str, incident_id: int, window_id: int, *, by: str, reason: str,
                   now: Optional[datetime] = None) -> windows.EvidenceWindow:
    """admin (the API checks, with step-up): after the all-clear only. The
    window is history from then on; its rows age out normally."""
    at_s = _iso(now)
    return _window_change(slug, incident_id, by, at_s, lambda conn: windows.release(
        conn, incident_id, window_id, by=by, at_s=at_s, reason=reason))


def reclassify(slug: str, incident_id: int, *, by: str, reason: str,
               now: Optional[datetime] = None) -> tuple[Incident, Incident]:
    """Close a Black as 'reclassified_red' (its tier stays black — the
    record is immutable) and open a LINKED Red on the same key. Returns
    (the closed Black, the new Red)."""
    if not by or by.startswith("system"):
        raise Refused("only a person reclassifies an incident")
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        if inc.tier != BLACK:
            raise Refused("only a Black is reclassified")
        if inc.restricted:
            raise Refused("a restricted incident is not reclassified — an admin closes it "
                          "(step-up and a reason)")
        conn.execute(
            "UPDATE incidents SET status = 'closed', closed_at = ?, closed_by = ?, "
            "close_reason = ?, close_reason_code = 'reclassified_red', stages = ? WHERE id = ?",
            (at_s, by, reason[:2000], _stage(inc, "reclassify", at_s, by=by), incident_id))
        _note(conn, incident_id, by, "reclassify", f"closed as reclassified to Red — {reason}",
              at_s)
        ev = {"rule": f"{inc.rule_id}@{inc.rule_version}", "reclassified_from": inc.id,
              "opened_by": by, "opened_at": at_s, "reason": reason, "event_ids": inc.event_ids}
        text, sha = snapshot(ev)
        cur = conn.execute(
            "INSERT INTO incidents (detected_at, severity, indicator_ids, event_ids, summary, "
            "evidence_refs, status, tier, rule_id, rule_version, dedupe_key, site_key, "
            "device_ref, device_label, scope, stages, last_evidence_at, ladder_started_at, "
            "autonomy_mode_at_open, snapshot_sha256, opened_by, open_reason, "
            "reclassified_from) "
            "VALUES (?, 'high', '[]', ?, ?, ?, 'open', 'red', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?)",
            (at_s, json.dumps(inc.event_ids), inc.summary, text, inc.rule_id, inc.rule_version,
             inc.dedupe_key, inc.site_key, inc.device_ref, inc.device_label, inc.scope,
             json.dumps([{"kind": "reclassified", "at": at_s, "tier": RED, "from": inc.id,
                          "by": by}], separators=(",", ":")),
             at_s, at_s, inc.autonomy_mode_at_open, sha, by, reason[:2000], inc.id))
        new_id = int(cur.lastrowid)
        for e in conn.execute("SELECT event_id, role FROM incident_events WHERE incident_id = ?",
                              (inc.id,)).fetchall():
            link_events(conn, new_id, [int(e["event_id"])], e["role"], at_s)
        _note(conn, new_id, by, "open", f"opened RED, reclassified from Black #{inc.id} — "
              f"{reason}", at_s)
        # A reclassify keeps the window: the Black's goes on with the Red,
        # still open until the Red's all-clear.
        carried = _auto_window(conn, lambda: windows.on_reclassify(
            conn, inc.id, new_id, by=by, at_s=at_s, detected_at=inc.detected_at))
        _window_note(conn, inc.id, carried, at_s)
        _window_note(conn, new_id, carried, at_s)
        return _row(conn, slug, incident_id), _row(conn, slug, new_id)


# ---------------------------------------------------------------------------
# Writes — the engine's bookkeeping (never a tier, never a close)
# ---------------------------------------------------------------------------

def set_ladder(slug: str, incident_id: int, *, step: int, at: datetime,
               note: Optional[str] = None) -> None:
    at_s = _iso(at)
    with write(slug) as conn:
        conn.execute("UPDATE incidents SET escalation_step = MAX(escalation_step, ?), "
                     "last_escalated_at = ? WHERE id = ?", (step, at_s, incident_id))
        if note:
            _note(conn, incident_id, SYSTEM_ACTOR, "escalation", note, at_s)


def set_client_visible(slug: str, incident_id: int, at: datetime) -> None:
    at_s = _iso(at)
    with write(slug) as conn:
        changed = conn.execute("UPDATE incidents SET client_visible_at = ? WHERE id = ? "
                               "AND client_visible_at IS NULL", (at_s, incident_id)).rowcount
        if changed:
            _note(conn, incident_id, SYSTEM_ACTOR, "client_visible",
                  "visible to the client's users (60 minutes unacknowledged)", at_s)


def record_decision(slug: str, incident_id: int, *, kind: str, requested_by: str,
                    requested_role: str, status: str, scope: list[Any],
                    excluded: list[Any], notice: str, note: Optional[str] = None,
                    now: Optional[datetime] = None) -> dict[str, Any]:
    if kind not in DECISION_KINDS:
        raise ValueError("a decision is 'lockdown' or 'allow'")
    at_s = _iso(now)
    with write(slug) as conn:
        inc = _row(conn, slug, incident_id)
        _require_open(inc)
        if inc.restricted:
            # Neither a lockdown nor an allow — by a client or an analyst.
            raise Refused(RESTRICTED_NO_ACTION)
        cur = conn.execute(
            "INSERT INTO incident_decisions (incident_id, kind, requested_by, requested_role, "
            "tier_at_request, status, scope_json, excluded_json, notice, note, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (incident_id, kind, requested_by, requested_role, inc.tier, status,
             json.dumps(scope, sort_keys=True), json.dumps(excluded, sort_keys=True), notice,
             (note or "")[:500] or None, at_s))
        did = int(cur.lastrowid)
        who = "the client" if requested_role == "client" else "an analyst"
        _note(conn, incident_id, requested_by, "decision",
              f"{who} recorded '{kind}' ({status})" + (f" — {notice}" if notice else ""), at_s)
        r = conn.execute("SELECT * FROM incident_decisions WHERE id = ?", (did,)).fetchone()
        d = dict(r)
        d["scope"] = _loads(d.pop("scope_json"), [])
        d["excluded"] = _loads(d.pop("excluded_json"), [])
        return d


def recent_decision(slug: str, incident_id: int, *, requested_by: str, kind: str,
                    since: datetime) -> Optional[dict[str, Any]]:
    """The same person's same decision on this incident since `since` (the
    throttle: a client pressing "lock down" again — or a stolen session in
    a loop — never pages everyone again)."""
    with read(slug) as conn:
        if conn is None:
            return None
        r = conn.execute(
            "SELECT kind, status, created_at, tier_at_request FROM incident_decisions "
            "WHERE incident_id = ? AND requested_by = ? AND kind = ? AND created_at >= ? "
            "ORDER BY id DESC LIMIT 1", (incident_id, requested_by, kind, _iso(since))).fetchone()
        return dict(r) if r else None


def answer_decision(slug: str, incident_id: int, decision_id: int, *, by: str, confirm: bool,
                    note: str, now: Optional[datetime] = None) -> dict[str, Any]:
    """An analyst confirms / declines a client's PENDING request (Black
    'allow'). Records only."""
    at_s = _iso(now)
    with write(slug) as conn:
        _row(conn, slug, incident_id)
        r = conn.execute("SELECT * FROM incident_decisions WHERE id = ? AND incident_id = ?",
                         (decision_id, incident_id)).fetchone()
        if r is None:
            raise NotFound(f"no decision {decision_id}")
        if r["status"] != "pending_analyst":
            raise Refused("this decision is not waiting for an analyst")
        status = "confirmed" if confirm else "declined"
        conn.execute("UPDATE incident_decisions SET status = ?, decided_by = ?, decided_at = ?, "
                     "decision_note = ? WHERE id = ?",
                     (status, by, at_s, note[:500], decision_id))
        _note(conn, incident_id, by, "decision",
              f"analyst {status} the client's '{r['kind']}' request — {note}", at_s)
        d = dict(conn.execute("SELECT * FROM incident_decisions WHERE id = ?",
                              (decision_id,)).fetchone())
        d["scope"] = _loads(d.pop("scope_json"), [])
        d["excluded"] = _loads(d.pop("excluded_json"), [])
        return d


def add_fact(slug: str, *, fact_key: str, kind: str, stage: str, observed_at: str,
             source: str, source_event_id: Optional[int] = None,
             device_ref: Optional[str] = None, site_key: Optional[str] = None,
             attrs: Optional[dict[str, Any]] = None, prevented: bool = False) -> bool:
    """One fact, once (G11 fact key). True when new."""
    with write(slug) as conn:
        return conn.execute(
            "INSERT OR IGNORE INTO threat_fact (fact_key, kind, stage, device_ref, site_key, "
            "observed_at, source, source_event_id, prevented, attrs) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (fact_key, kind, stage, device_ref, site_key, observed_at, source, source_event_id,
             1 if prevented else 0, json.dumps(attrs or {}, sort_keys=True))).rowcount == 1


def fact_counts(slug: str, kind: Union[str, tuple[str, ...]], since: datetime) -> Optional[int]:
    """How many facts of `kind` (one, or any of several) since `since`; None
    when unreadable."""
    kinds = (kind,) if isinstance(kind, str) else tuple(kind)
    try:
        with read(slug) as conn:
            if conn is None:
                return 0
            return int(conn.execute(
                f"SELECT COUNT(*) FROM threat_fact WHERE kind IN ({','.join('?' * len(kinds))}) "
                "AND observed_at >= ?", (*kinds, _iso(since))).fetchone()[0])
    except sqlite3.Error:
        return None


def fact_event_ids(slug: str, kind: str, since: datetime) -> list[int]:
    """The source events of the facts of `kind` since `since` (one per fact;
    a fact without one is left out). [] when unreadable."""
    try:
        with read(slug) as conn:
            if conn is None:
                return []
            return [int(r[0]) for r in conn.execute(
                "SELECT source_event_id FROM threat_fact WHERE kind = ? AND observed_at >= ? "
                "AND source_event_id IS NOT NULL ORDER BY id", (kind, _iso(since))).fetchall()]
    except sqlite3.Error:
        return []


def would_fire(slug: str, *, rule_id: str, rule_version: int, tier: str, key: str,
               fact_key: str, summary: str, device_ref: Optional[str] = None,
               site_key: Optional[str] = None, now: Optional[datetime] = None) -> bool:
    """A SHADOW rule's "would have opened" — never a colour. True when new."""
    with write(slug) as conn:
        return conn.execute(
            "INSERT OR IGNORE INTO threat_would_fire (rule_id, rule_version, tier, dedupe_key, "
            "fact_key, device_ref, site_key, summary, fired_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rule_id, rule_version, tier, key, fact_key, device_ref, site_key, summary[:300],
             _iso(now))).rowcount == 1


def would_fires(slug: str, since: datetime) -> Optional[list[dict[str, Any]]]:
    try:
        with read(slug) as conn:
            if conn is None:
                return []
            return [dict(r) for r in conn.execute(
                "SELECT * FROM threat_would_fire WHERE fired_at >= ? ORDER BY id",
                (_iso(since),)).fetchall()]
    except sqlite3.Error:
        return None
