"""Entity retention classes (design 7.5, G11) — what the nightly retention job
(`apps.octo.retention.job`) prunes in each tenant's entities.db.

  entity_lookup_lease   90 d   closed leases (guest networks: 7 d whatever the
                               setting), system-log joins, MAC anomalies, IP
                               conflicts, uplink changes —
                               they name people's devices; then G11: every
                               stored answer whose candidate leases are gone is
                               cut to its COUNT (a year-long list of whose
                               phones were in the office is not kept)
  entity_lookup_egress  400 d  closed egress intervals and subnets
  entity_resolution     365 d  stored answers (+ their dependency rows)
  entity_links          400 d  retired / rejected links (counted from their
                               end), expired suppressions, resolved conflicts,
                               run rows — an ACTIVE link is never pruned; an
                               operator's decision only goes through the
                               `maint` flag, set and cleared inside the
                               retention job's own transaction
  entity_inventory      90 d   Datto devices missing that long, NextDNS
                               presence hours / seed days / IP days / devices
                               not seen

Open intervals are never pruned. Every count is exact (what is planned is
what is deleted); deletes run in short batches.

EVIDENCE WINDOWS (Tier Black, 044 — `apps.octo.retention.evidence`): a row
inside a held window of the tenant (a confirmed threat's first detection →
its all-clear, until an admin releases it) is never deleted nor trimmed —
an interval when it OVERLAPS the window, an hour or a day bucket likewise,
a point in time when it falls inside. The windows are re-read before every
batch (the retention job's `windows` callable).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, Optional

from apps.octo.entity import normalize as nz
from apps.octo.retention import evidence

CLASSES = ("entity_lookup_lease", "entity_lookup_egress", "entity_resolution", "entity_links",
           "entity_inventory")
GUEST_DAYS = 7
WITHOUT_ROWID = frozenset({"inv_device", "ndns_device", "ndns_device_hour", "ndns_presence_hour",
                           "ndns_ip_day", "ndns_device_day", "ndns_seed_day"})

# class → [(table, WHERE with :cutoff / :guest_cutoff, needs the maint flag)]
_RULES: dict[str, list[tuple[str, str, bool]]] = {
    "entity_lookup_lease": [
        ("lk_ip_lease", "valid_to IS NOT NULL AND (valid_to < :cutoff OR "
                        "(is_guest = 1 AND valid_to < :guest_cutoff))", False),
        ("lk_join", "at < :cutoff", False),
        ("lk_mac_anomaly", "to_ts < :cutoff", False),
        ("lk_ip_conflict", "at < :cutoff", False),
        ("lk_uplink", "at < :cutoff", False),
    ],
    "entity_lookup_egress": [
        ("lk_site_egress", "valid_to IS NOT NULL AND valid_to < :cutoff", False),
        ("lk_site_subnet", "valid_to IS NOT NULL AND valid_to < :cutoff", False),
    ],
    "entity_resolution": [
        ("resolution", "created_at < :cutoff", False),
    ],
    "entity_links": [
        ("site_vendor_ref", "state IN ('retired','rejected') AND "
                            "COALESCE(valid_to, decided_at) < :cutoff", True),
        ("device_link", "state IN ('retired','rejected') AND "
                        "COALESCE(valid_to, decided_at) < :cutoff", True),
        ("link_suppression", "expires_at IS NOT NULL AND expires_at < :cutoff", False),
        ("link_conflict", "resolved_at IS NOT NULL AND resolved_at < :cutoff", False),
        ("resolution_run", "started_at < :cutoff", False),
    ],
    "entity_inventory": [
        ("inv_device", "missing_since IS NOT NULL AND missing_since < :cutoff", False),
        ("ndns_device_hour", "hour < :cutoff", False),
        ("ndns_presence_hour", "hour < :cutoff", False),
        ("ndns_ip_day", "day < substr(:cutoff, 1, 10)", False),
        ("ndns_device_day", "day < substr(:cutoff, 1, 10)", False),
        ("ndns_seed_day", "day < substr(:cutoff, 1, 10)", False),
        ("ndns_device", "last_seen < :cutoff AND NOT EXISTS (SELECT 1 FROM device_link l WHERE "
                        "l.a_value = ndns_device.profile_id || ':' || ndns_device.device_id AND "
                        "l.valid_to IS NULL)", False),
    ],
}


def _connect(db: Path, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10.0,
                               isolation_level=None)
    else:
        conn = sqlite3.connect(db, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _has(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (table,)).fetchone() is not None


def _args(cutoff: str, now: datetime) -> dict[str, str]:
    return {"cutoff": cutoff, "guest_cutoff": nz.iso(now - timedelta(days=GUEST_DAYS))}


def _keep(table: str) -> str:
    """` AND NOT (inside an evidence window)` — the windows in the
    connection's temp copy (`evidence.load_temp`)."""
    return evidence.guard("entities", table)


def count(db: Path, data_class: str, cutoff: str, now: datetime,
          windows: Optional[Iterable["evidence.Window"]] = None) -> int:
    """Rows of the class that expire and may go (never one inside an
    evidence window in `windows`)."""
    return count_with_evidence(db, data_class, cutoff, now, windows)[0]


def count_with_evidence(
    db: Path, data_class: str, cutoff: str, now: datetime,
    windows: Optional[Iterable["evidence.Window"]] = None,
) -> tuple[int, int, dict[int, int]]:
    """(may go, kept by an evidence window, kept per window id)."""
    if not db.exists():
        return 0, 0, {}
    wins = list(windows or [])
    conn = _connect(db, read_only=True)
    try:
        evidence.load_temp(conn, wins)
        n = kept = 0
        per: dict[int, int] = {}
        for table, where, _maint in _RULES[data_class]:
            if not _has(conn, table):
                continue
            held = evidence.held_expr("entities", table)
            go, stay = conn.execute(
                f"SELECT COALESCE(SUM(NOT {held}), 0), COALESCE(SUM({held}), 0) "
                f"FROM {table} WHERE {where}", _args(cutoff, now)).fetchone()
            n += int(go)
            kept += int(stay)
            if stay:
                evidence.merge_counts(per, evidence.per_window(
                    conn, "entities", table, where, _args(cutoff, now)))
        return n, kept, per
    finally:
        conn.close()


def prune(db: Path, data_class: str, cutoff: str, now: datetime, *, batch: int = 2000,
          windows: Optional[Callable[[], list["evidence.Window"]]] = None) -> int:
    """Delete what `count` counted, in short transactions — never a row
    inside an evidence window: `windows` (the retention job's) is called
    before EVERY batch, inside its transaction (the windows held at planning
    and now); it raises `evidence.WindowsUnavailable` when they cannot be
    read, and nothing more is deleted. Returns rows deleted. After leases
    go, the answers that pointed at them are cut to their count (G11) —
    never an answer inside an evidence window."""
    if not db.exists():
        return 0
    conn = _connect(db)

    def refresh() -> None:
        evidence.load_temp(conn, windows() if windows is not None else [])

    deleted = 0
    try:
        for table, where, maint in _RULES[data_class]:
            if not _has(conn, table):
                continue
            keep = _keep(table)
            if table in WITHOUT_ROWID:
                # Small per-tenant tables keyed by their columns: one statement.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    refresh()
                    deleted += conn.execute(f"DELETE FROM {table} WHERE {where}{keep}",
                                            _args(cutoff, now)).rowcount
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                continue
            # KEYSET by rowid, candidates picked OUTSIDE the write lock (WAL:
            # a reader never holds up the feeders): rows a window keeps are
            # passed over once, never re-examined under the lock — a batch
            # re-checks only the ≤ `batch` rows it picked.
            last = 0
            refresh()
            while True:
                picked = [r[0] for r in conn.execute(
                    f"SELECT rowid FROM {table} WHERE ({where}) AND rowid > :after{keep} "
                    f"ORDER BY rowid LIMIT {int(batch)}",
                    {**_args(cutoff, now), "after": last}).fetchall()]
                if not picked:
                    break
                last = picked[-1]
                conn.execute("BEGIN IMMEDIATE")
                try:
                    refresh()
                    # Re-checked under the lock: still expired, and no
                    # window (held at planning or now) holds it.
                    args = _args(cutoff, now)
                    named = {f"k{i}": v for i, v in enumerate(picked)}
                    ids = [r[0] for r in conn.execute(
                        f"SELECT rowid FROM {table} WHERE rowid IN "
                        f"({','.join(':' + k for k in named)}) AND ({where}){keep}",
                        {**args, **named}).fetchall()]
                    if ids:
                        marks = ",".join("?" * len(ids))
                        if maint:
                            conn.execute("UPDATE maint SET allow_operator_delete = 1 WHERE id = 1")
                        if table == "resolution":
                            conn.execute(f"DELETE FROM resolution_dep WHERE res_id IN "
                                         f"(SELECT res_id FROM resolution WHERE rowid IN "
                                         f"({marks}))", ids)
                        conn.execute(f"DELETE FROM {table} WHERE rowid IN ({marks})", ids)
                        deleted += len(ids)
                        if maint:
                            conn.execute("UPDATE maint SET allow_operator_delete = 0 WHERE id = 1")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                if len(picked) < batch:
                    break
        if data_class == "entity_lookup_lease":
            deleted_leases_trim(conn, windows)
    finally:
        conn.close()
    return deleted


def deleted_leases_trim(
    conn: sqlite3.Connection,
    windows: Optional[Callable[[], list["evidence.Window"]]] = None,
) -> int:
    """G11 / AT-R15: an answer whose candidate leases no longer exist keeps
    its COUNT (n_candidates) and nothing else of the list (managed devices
    would stay — slice 2). An answer inside an evidence window is evidence:
    never trimmed."""
    trimmed = 0
    evidence.load_temp(conn, windows() if windows is not None else [])
    rows = conn.execute("SELECT res_id, candidates FROM resolution WHERE candidates <> '[]'"
                        + _keep("resolution")).fetchall()
    for r in rows:
        try:
            cands = json.loads(r["candidates"] or "[]")
        except ValueError:
            continue
        lease_ids = [c.get("lease_id") for c in cands if isinstance(c, dict) and c.get("lease_id")]
        if not lease_ids:
            continue
        marks = ",".join("?" * len(lease_ids))
        alive = conn.execute(f"SELECT COUNT(*) FROM lk_ip_lease WHERE id IN ({marks})",
                             lease_ids).fetchone()[0]
        if alive == len(lease_ids):
            continue
        kept = [c for c in cands if isinstance(c, dict) and c.get("managed")]
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Re-checked under the write lock: a window opened since keeps it.
            if windows is not None:
                evidence.load_temp(conn, windows())
            conn.execute("UPDATE resolution SET candidates = ? WHERE res_id = ?"
                         + _keep("resolution"), (json.dumps(kept), r["res_id"]))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        trimmed += 1
    return trimmed


def cutoff_for(days: Optional[int], now: datetime) -> Optional[str]:
    return None if days is None else nz.iso(now - timedelta(days=int(days)))
