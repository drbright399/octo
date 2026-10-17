"""The entity worker — one pass a minute over every tenant whose switch is
shadow / on (design slice 1, item 5). Per tenant, in order:

  1. link rules (`linkrules.run_all`): UniFi sites no longer mapped are
     retired, L-SOLE / L-EGRESS / N-SITE, routing sanity, NextDNS ↔ Datto
     device links — idempotent, so a pass that changes nothing writes nothing;
  2. SWEEP: the tenant's events.db after its cursor — NextDNS security blocks
     and UniFi IPS signals — each resolved and stored (`resolution`). A
     tenant without a cursor (first switched on, or off → on again) starts
     at its newest event, or OCTO_ENTITY_SWEEP_HISTORY_DAYS back — never its
     whole history;
  3. REVISIT: provisional answers whose watermarks have caught up are redone;
     after 30 minutes (an answer waiting for T's NextDNS presence hour: once
     that hour is due + slack) they are finalised with `lookup_stale` (+
     `data_gap`);
     `stale` answers (an operator changed a link they relied on) are redone
     at once;
  4. BACKFILL (G7): a stale / data-gap answer from the last 7 days whose
     watermark has now passed its moment is redone (`backfill`), the old one
     kept as superseded;
  5. BUCKET CLOSE: a NextDNS alert whose coalescing bucket gathered later
     hits is re-ranked with the last hit (F2), the old answer superseded,
     flagged `bucket_later_hits`;
  6. NOTICES: every new conflict (a rule refused by an operator decision,
     two sites claiming one event, a profile whose traffic comes from none of
     the tenant's sites) becomes ONE `entity_review` notice for the admins —
     and so does one an operator resolved whose evidence MATERIALLY changed
     (reopened); seeing the same condition again raises nothing.

RECORDS — only REAL changes are recorded: a pass that stored an answer,
changed a link or raised a notice writes one `resolution_run` row and one
audit summary row (global chain, client_slug = the tenant, actor
`entity-resolver`, non-zero counts only). A pass that changed nothing writes
nothing; a quiet tenant gets at most ONE `heartbeat` run row an hour (in its
own file: passes since the last row), and the worker ONE global audit
heartbeat an hour (`entity_worker_heartbeat`: passes, tenants, changed runs,
errors) — never a row per tenant per minute.
The worker never takes two tenants at once and never reads another tenant's
file: each pass builds `Resolver.for_tenant(slug)`.
"""
from __future__ import annotations

import hashlib

import asyncio
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.entity import linkrules, switch
from apps.octo.entity import normalize as nz
from apps.octo.entity import resolver as rv
from apps.octo.entity.db import TenantDB

logger = logging.getLogger(__name__)

INTERVAL_SEC = 60.0
SWEEP_BATCH = 500
REVISIT_BATCH = 200
BUCKET_SETTLE = timedelta(minutes=10)
ACTOR = "entity-resolver"
SWEEP_KINDS = (("nextdns", "nextdns.security_block"), ("unifi", "unifi.ips_threat"))
# Where a tenant's sweep STARTS when it has no cursor (switched on for the
# first time, or off → on again): its newest event (0, the default) or that
# many days back. Lookups only exist from switch-on, so older alerts would
# get answers with nothing behind them.
HISTORY_ENV = "OCTO_ENTITY_SWEEP_HISTORY_DAYS"
MAX_HISTORY_DAYS = 30
# What makes a pass a REAL change (recorded); anything else is a quiet pass.
CHANGE_KEYS = ("scanned", "revisited", "backfill", "bucket_close", "links", "conflicts")
HEARTBEAT = timedelta(hours=1)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def enabled() -> bool:
    return os.environ.get("OCTO_ENTITY_WORKER", "1").strip() not in ("0", "false", "no", "off")


def history_days() -> int:
    """OCTO_ENTITY_SWEEP_HISTORY_DAYS: 0 (default, also for anything
    unreadable or negative) … MAX_HISTORY_DAYS (larger values are capped)."""
    raw = os.environ.get(HISTORY_ENV, "").strip()
    try:
        days = int(raw)
    except ValueError:
        return 0
    return max(0, min(MAX_HISTORY_DAYS, days))


def start_cursor(events: sqlite3.Connection, now: datetime) -> int:
    """Where a tenant's sweep starts: its newest event, or — with
    OCTO_ENTITY_SWEEP_HISTORY_DAYS — just before the first event of that
    window. (It used to start at 0: switching a client on resolved its whole
    history — thousands of 'final / none' answers on old alerts, which have
    no lookups behind them.)"""
    days = history_days()
    if days > 0:
        first = events.execute("SELECT MIN(id) FROM events WHERE received_at >= ?",
                               (nz.iso(now - timedelta(days=days)),)).fetchone()[0]
        if first is not None:
            return int(first) - 1
    return int(events.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])


def _events_ro(slug: str) -> Optional[sqlite3.Connection]:
    path = paths.client_dir(slug) / "events.db"
    if not path.exists():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def switched(slug: str, before: Optional[str], after: str,
             now: Optional[datetime] = None) -> None:
    """The tenant's switch moved. Off → shadow / on: its sweep starts HERE —
    at its newest event (or the history window) — the alerts stored while it
    was off have no lookups behind them. Never raises."""
    if before != "off" or after not in ("shadow", "on"):
        return
    try:
        at = now or _utcnow()
        events = _events_ro(slug)
        try:
            cursor = start_cursor(events, at) if events is not None else 0
        finally:
            if events is not None:
                events.close()
        with TenantDB.for_tenant(slug).write() as conn:
            conn.execute("INSERT INTO resolver_cursor (store, last_event_id, updated_at) "
                         "VALUES ('events', ?, ?) ON CONFLICT (store) DO UPDATE SET "
                         "last_event_id = excluded.last_event_id, updated_at = excluded.updated_at",
                         (cursor, nz.iso(at)))
    except Exception as exc:  # noqa: BLE001 — the switch itself already moved
        logger.warning("[entity-worker] %s: the sweep cursor was not set (%s)", slug,
                       type(exc).__name__)


def _notice_key(fresh) -> str:
    """The notice's dedupe key. A conflict keeps its id when it reopens, so the
    id alone made every reopen look like a notice already sent; `hits` grows
    on each reopen (and each re-sighting), so id + hits + last_seen names
    THIS round of the conflict(s) — one notice per round, never one per pass
    (only rows with notified = 0 reach here)."""
    raw = ";".join(f"{r['id']}:{r['hits']}:{r['last_seen']}" for r in fresh)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class EntityWorker:
    def __init__(self, *, now: Callable[[], datetime] = _utcnow,
                 interval_sec: float = INTERVAL_SEC) -> None:
        self._now = now
        self._interval = interval_sec
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self.last_pass: dict[str, Any] = {}
        # slug → the quiet passes since its last recorded row (heartbeat)
        self._quiet: dict[str, dict[str, Any]] = {}
        # the global heartbeat's window (all tenants)
        self._fleet_since: Optional[datetime] = None
        self._fleet = {"passes": 0, "tenants": set(), "changed": 0, "errors": 0}

    # ----- one pass, synchronous (tests drive it directly) -----

    def run_once(self) -> dict[str, dict[str, int]]:
        out = {}
        for slug in switch.tenants():
            try:
                out[slug] = self.run_tenant(slug)
            except Exception as exc:  # noqa: BLE001 — one tenant never stops the others
                logger.warning("[entity-worker] %s failed (%s)", slug, type(exc).__name__)
                out[slug] = {"error": 1}
        self.last_pass = {"at": nz.iso(self._now()), "tenants": out}
        self._fleet_heartbeat(out)
        return out

    def run_tenant(self, slug: str) -> dict[str, int]:
        if not switch.enabled(slug):
            return {}
        tdb = TenantDB.for_tenant(slug)
        now = self._now()
        now_s = nz.iso(now)
        counts = {"scanned": 0, "final": 0, "provisional": 0, "conflicts": 0, "errors": 0,
                  "links": 0, "revisited": 0, "backfill": 0, "bucket_close": 0}
        with tdb.write() as conn:
            changes = linkrules.run_all(conn, slug, now_s)
            counts["links"] = sum(changes.values())
        resolver = rv.Resolver.for_tenant(slug, now=self._now)
        self._sweep(slug, tdb, resolver, counts)
        self._revisit(tdb, resolver, counts, now)
        self._bucket_close(slug, tdb, resolver, counts, now)
        notified = self._notices(slug, tdb, now_s)
        counts["conflicts"] = notified
        if any(counts[k] for k in CHANGE_KEYS):
            self._record(slug, tdb, counts, now_s)
            self._quiet[slug] = {"since": now, "passes": 0, "errors": 0}
            counts["recorded"] = 1
        else:
            self._heartbeat(slug, tdb, counts, now)
        return counts

    def _events(self, slug: str) -> Optional[sqlite3.Connection]:
        path = paths.client_dir(slug) / "events.db"
        if not path.exists():
            return None
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _sweep(self, slug: str, tdb: TenantDB, resolver: rv.Resolver,
               counts: dict[str, int]) -> None:
        with tdb.connect() as conn:
            row = conn.execute("SELECT last_event_id FROM resolver_cursor WHERE store = 'events'"
                               ).fetchone()
        events = self._events(slug)
        if events is None:
            return
        if row is None:
            # No cursor (the switch did not set one — e.g. turned on outside
            # PUT /mode): the same start point, now.
            try:
                cursor = start_cursor(events, self._now())
            except sqlite3.Error:
                events.close()
                return
            with tdb.write() as conn:
                conn.execute("INSERT INTO resolver_cursor (store, last_event_id, updated_at) "
                             "VALUES ('events', ?, ?) ON CONFLICT (store) DO NOTHING",
                             (cursor, nz.iso(self._now())))
        else:
            cursor = int(row["last_event_id"])
        try:
            clauses = " OR ".join("(source = ? AND event_type = ?)" for _ in SWEEP_KINDS)
            args: list[Any] = [x for pair in SWEEP_KINDS for x in pair]
            rows = events.execute(
                f"SELECT id FROM events WHERE id > ? AND ({clauses}) ORDER BY id LIMIT ?",
                (cursor, *args, SWEEP_BATCH)).fetchall()
            top = events.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        except sqlite3.Error:
            return
        finally:
            events.close()
        last = cursor
        for r in rows:
            try:
                res = resolver.resolve_event(int(r["id"]), mode="sweep", created_by="rule:sweep")
            except Exception as exc:  # noqa: BLE001
                logger.warning("[entity-worker] %s event %s: %s", slug, r["id"], type(exc).__name__)
                counts["errors"] += 1
                res = None
            last = int(r["id"])
            counts["scanned"] += 1
            if res is not None:
                counts["final" if res["status"] == "final" else "provisional"] += 1
        if len(rows) < SWEEP_BATCH:
            last = max(last, int(top or 0))
        if last != cursor:
            with tdb.write() as conn:
                conn.execute("INSERT INTO resolver_cursor (store, last_event_id, updated_at) "
                             "VALUES ('events', ?, ?) ON CONFLICT (store) DO UPDATE SET "
                             "last_event_id = excluded.last_event_id, "
                             "updated_at = excluded.updated_at", (last, nz.iso(self._now())))

    def _revisit(self, tdb: TenantDB, resolver: rv.Resolver, counts: dict[str, int],
                 now: datetime) -> None:
        with tdb.connect() as conn:
            prov = conn.execute(
                "SELECT res_id, event_id, event_source, status FROM resolution WHERE status IN "
                "('provisional','stale') ORDER BY created_at LIMIT ?", (REVISIT_BATCH,)).fetchall()
            stale = conn.execute(
                "SELECT res_id, event_id, event_source, at, lookup_watermark FROM resolution "
                "WHERE status = 'final' AND flags LIKE '%lookup_stale%' AND at >= ? "
                "ORDER BY created_at LIMIT ?",
                (nz.iso(now - rv.BACKFILL_WINDOW), REVISIT_BATCH)).fetchall()
        for r in prov:
            if r["event_id"] is None:
                continue
            if r["status"] == "provisional" and not self._due(tdb, r["res_id"], now):
                continue                     # nothing it waits for has moved yet
            res = resolver.resolve_event(int(r["event_id"]), mode="revisit",
                                         created_by="rule:revisit")
            if res is not None:
                counts["revisited"] += 1
        for r in stale:
            if r["event_id"] is None or not self._caught_up(tdb, r):
                continue
            res = resolver.resolve_event(int(r["event_id"]), mode="backfill",
                                         created_by="rule:backfill")
            if res is not None and not res.get("noop"):
                counts["backfill"] += 1

    def _due(self, tdb: TenantDB, res_id: str, now: datetime) -> bool:
        """A provisional answer is redone when a watermark it waited for has
        moved since, or when it is old enough to be finalised."""
        with tdb.connect() as conn:
            row = conn.execute("SELECT at, lookup_watermark FROM resolution WHERE res_id = ?",
                               (res_id,)).fetchone()
            if row is None:
                return False
            at = nz.dt(row["at"])
            if at is not None and now >= rv.finalise_deadline(
                    at, rv.parse_waits(row["lookup_watermark"])):
                return True
            for source, scope, have, need in rv.parse_waits(row["lookup_watermark"]):
                current, met = rv.wait_state(conn, source, scope, need)
                if met or (current and current != have):
                    return True
        return False

    def _caught_up(self, tdb: TenantDB, row: sqlite3.Row) -> bool:
        """Every wait of this stale answer has reached what it NEEDED (stored
        with the answer: T + skew + the join window for the client list and
        the system log, T for the fleet report, T's hour for NextDNS
        presence) — never merely T: a feed that stopped between T and its
        need would otherwise redo the same answer every minute for 7 days."""
        waits = rv.parse_waits(row["lookup_watermark"])
        if not waits:
            return False
        with tdb.connect() as conn:
            for source, scope, _have, need in waits:
                if need is None:
                    need = row["at"]         # an answer stored before needs were kept
                _current, met = rv.wait_state(conn, source, scope, need)
                if not met:
                    return False
        return True

    def _bucket_close(self, slug: str, tdb: TenantDB, resolver: rv.Resolver,
                      counts: dict[str, int], now: datetime) -> None:
        tpath = paths.client_dir(slug) / "telemetry.db"
        if not tpath.exists():
            return
        with tdb.connect() as conn:
            rows = conn.execute(
                "SELECT res_id, event_id, bucket_last_seen FROM resolution WHERE "
                "event_source = 'nextdns' AND status = 'final' AND event_id IS NOT NULL AND "
                "created_at >= ? ORDER BY created_at",
                (nz.iso(now - timedelta(days=2)),)).fetchall()
        if not rows:
            return
        try:
            tel = sqlite3.connect(f"file:{tpath}?mode=ro", uri=True, timeout=5.0)
            tel.row_factory = sqlite3.Row
        except sqlite3.Error:
            return
        try:
            for r in rows:
                b = tel.execute("SELECT hits, last_seen, hour, span FROM nextdns_signal_buckets "
                                "WHERE event_id = ?", (int(r["event_id"]),)).fetchone()
                if b is None or int(b["hits"] or 1) <= 1:
                    continue
                last = nz.ts(b["last_seen"])
                if not last or last == r["bucket_last_seen"]:
                    continue
                span_end = nz.shift(nz.ts(b["hour"]) or last,
                                    86400 if b["span"] == "day" else 3600)
                if nz.iso(now) < nz.shift(span_end, BUCKET_SETTLE.total_seconds()):
                    continue                     # the bucket is still filling
                res = resolver.resolve_event(int(r["event_id"]), mode="bucket_close",
                                             created_by="rule:bucket_close")
                if res is not None:
                    counts["bucket_close"] += 1
        except sqlite3.Error:
            return
        finally:
            tel.close()

    def _notices(self, slug: str, tdb: TenantDB, now_s: str) -> int:
        with tdb.connect() as conn:
            fresh = conn.execute("SELECT * FROM link_conflict WHERE notified = 0 AND "
                                 "resolved_at IS NULL ORDER BY id").fetchall()
        if not fresh:
            return 0
        from apps.octo.auth import operator_notices
        from apps.octo.db import connect, transaction

        titles = {"operator_decision": "a rule disagreed with an operator decision",
                  "site_conflict": "two sites claimed one alert",
                  "routing": "a NextDNS profile's traffic comes from none of its client's sites",
                  "device_link": "a device link disagreed with an operator decision"}
        lines = [f"- {titles.get(r['kind'], r['kind'])}: {r['subject'][:120]}" for r in fresh]
        body = (f"Entity resolution for {slug} needs a look ({len(fresh)} item(s)). Open the "
                "client's Links to review → Conflicts.\n" + "\n".join(lines))[:1900]
        try:
            reg = connect(paths.registry_db_path())
            try:
                with transaction(reg):
                    operator_notices.notify_admins_system(
                        reg, kind="entity_review",
                        title=f"Entity links to review — {slug}"[:200], body=body,
                        request_id=f"entity-review:{slug}:{_notice_key(fresh)}",
                        subject_slug=slug)
            finally:
                reg.close()
        except Exception as exc:  # noqa: BLE001 — a notice never stops resolution
            logger.warning("[entity-worker] notice for %s not raised (%s)", slug,
                           type(exc).__name__)
            return 0
        with tdb.write() as conn:
            conn.executemany("UPDATE link_conflict SET notified = 1 WHERE id = ?",
                             [(r["id"],) for r in fresh])
        return len(fresh)

    def _heartbeat(self, slug: str, tdb: TenantDB, counts: dict[str, int],
                   now: datetime) -> None:
        """A quiet pass: nothing is written — except, at most once an hour, ONE
        `heartbeat` run row in the tenant's own file (passes since its last
        row). The first quiet pass after a start counts from the tenant's
        last row, so a restart never adds an early one."""
        q = self._quiet.get(slug)
        if q is None:
            with tdb.connect() as conn:
                row = conn.execute("SELECT started_at FROM resolution_run ORDER BY id DESC "
                                   "LIMIT 1").fetchone()
            last = nz.dt(row["started_at"]) if row is not None else None
            q = {"since": last or now, "passes": 0, "errors": 0}
            self._quiet[slug] = q
        q["passes"] += 1
        q["errors"] += int(counts.get("errors") or 0)
        if now - q["since"] < HEARTBEAT:
            return
        now_s = nz.iso(now)
        notes = {"passes": q["passes"], "since": nz.iso(q["since"]), "errors": q["errors"]}
        with tdb.write() as conn:
            conn.execute(
                "INSERT INTO resolution_run (mode, resolver_version, started_at, finished_at, "
                " errors, notes) VALUES ('heartbeat', ?, ?, ?, ?, ?)",
                (rv.RESOLVER_VERSION, now_s, nz.iso(self._now()), q["errors"],
                 json.dumps(notes, sort_keys=True)))
        q.update(since=now, passes=0, errors=0)
        counts["heartbeat"] = 1

    def _fleet_heartbeat(self, out: dict[str, dict[str, int]]) -> None:
        """At most ONE global audit row an hour for the whole worker (only
        when it ran tenants): passes, tenants, recorded runs, errors."""
        now = self._now()
        if self._fleet_since is None:
            self._fleet_since = now
        f = self._fleet
        if out:
            f["passes"] += 1
            f["tenants"].update(out)
            f["changed"] += sum(1 for c in out.values() if c.get("recorded"))
            f["errors"] += sum(1 for c in out.values() if c.get("error") or c.get("errors"))
        if now - self._fleet_since < HEARTBEAT:
            return
        since, summary = self._fleet_since, dict(f)
        self._fleet_since = now
        self._fleet = {"passes": 0, "tenants": set(), "changed": 0, "errors": 0}
        if not summary["passes"]:
            return                      # no tenant is switched on: nothing to say
        try:
            from apps.octo.auth import audit
            from apps.octo.db import connect

            g = connect(paths.global_audit_db_path())
            try:
                audit.append(g, audit.AuditEntry(
                    actor=ACTOR, actor_kind="system", action="entity_worker_heartbeat",
                    target_kind="entity_worker", target_id=None, client_slug="global",
                    after_state={"since": nz.iso(since), "passes": summary["passes"],
                                 "tenants": len(summary["tenants"]),
                                 "changed_runs": summary["changed"],
                                 "tenant_errors": summary["errors"],
                                 "resolver_version": rv.RESOLVER_VERSION},
                    reason="entity resolution: hourly summary", request_id=str(uuid.uuid4())))
            finally:
                g.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[entity-worker] heartbeat audit row not written (%s)",
                           type(exc).__name__)

    def _record(self, slug: str, tdb: TenantDB, counts: dict[str, int], now_s: str) -> None:
        mode = ("bucket_close" if counts["bucket_close"] and not counts["scanned"] else
                "backfill" if counts["backfill"] and not counts["scanned"] else
                "revisit" if counts["revisited"] and not counts["scanned"] else "sweep")
        with tdb.write() as conn:
            cur = conn.execute(
                "INSERT INTO resolution_run (mode, resolver_version, started_at, finished_at, "
                " scanned, final, provisional, suggested, conflicts, errors, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (mode, rv.RESOLVER_VERSION, now_s, nz.iso(self._now()), counts["scanned"],
                 counts["final"], counts["provisional"], counts["links"], counts["conflicts"],
                 counts["errors"], json.dumps(counts, sort_keys=True)))
            run_id = int(cur.lastrowid)
        try:
            from apps.octo.auth import audit
            from apps.octo.db import connect

            g = connect(paths.global_audit_db_path())
            try:
                audit.append(g, audit.AuditEntry(
                    actor=ACTOR, actor_kind="system", action="entity_resolution_run",
                    target_kind="resolution_run", target_id=str(run_id), client_slug=slug,
                    after_state={**{k: v for k, v in sorted(counts.items()) if v},
                                 "resolver_version": rv.RESOLVER_VERSION},
                    reason="entity resolution pass", request_id=str(uuid.uuid4())))
            finally:
                g.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[entity-worker] audit row for %s not written (%s)", slug,
                           type(exc).__name__)

    # ----- async lifecycle -----

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="entity-worker")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        try:
            await asyncio.wait_for(self._task, timeout=20.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self.run_once)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[entity-worker] pass failed (%s)", type(exc).__name__)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                pass
