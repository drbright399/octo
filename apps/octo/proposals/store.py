"""The `proposals` table (registry, 043) — generic over kinds and sources.

  sync(...)      what an integration says NOW → the table, in one transaction.
                 A source RECORD is (source_ref, tenant): a company mapped to
                 two tenants is two records; one re-mapped to another tenant
                 is a new record there (its old tenant's is closed). Per
                 record:
                 * new source data → a new proposal (status 'proposed');
                 * the same data already proposed → its derived fields (the
                   target, the warnings, the payload) refreshed in place;
                 * the same data REJECTED → nothing (never re-proposed while
                   the source is unchanged);
                 * the same data CONFIRMED → nothing — unless the caller says
                   the confirmed target is gone and the new one may take it
                   (`may_retarget`: e.g. a client that gained UniFi sites):
                   then it is proposed for the new target
                   (`payload.confirmed_before` names the confirmed one);
                 * CHANGED data → the open proposal of that record is
                   superseded and the new data proposed, the previous one
                   alongside (`payload.previous`: the diff). What is in force
                   (a confirmed pin) stays until the new one is confirmed;
                 * whatever the data is now, every OTHER open proposal of the
                   record (older data — an address changed, then changed
                   back) is superseded: only the current data is reviewable;
                 * a record no longer listed (company inactive or unmapped, a
                   location removed) → its open proposal is superseded — only
                   where the run READ in full (`may_sweep`).
                 A superseded row is history: the same data may come back
                 (043's identity index ignores superseded rows).
  decide(...)    an operator's confirm / reject (the caller audited first);
                 guarded: only an OPEN proposal — and, given the operator's
                 `expected_updated_at`, only as the operator saw it — is
                 decided (a race loses).
  list / get     for the API (which filters by scope).

Rows carry JSON (payload, flags, geocode) — parsed on read, never trusted
blindly by the caller.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect, transaction

STATUSES = ("proposed", "confirmed", "rejected", "superseded")
OPEN = "proposed"

_COLS = ("id, kind, source, tenant_slug, target_key, source_ref, payload_json, source_hash, "
         "flags_json, status, geocode_json, created_at, updated_at, decided_by, decided_at, "
         "decision_reason, superseded_by")
_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
# What `sync` adds to a payload (the record's history) — kept when an open
# proposal's derived fields are refreshed.
_CARRIED = ("previous", "confirmed_before")


class ProposalError(Exception):
    """Operator-safe text."""

    def __init__(self, message: str, *, code: str = "CONFLICT") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Item:
    """One thing an integration says now (the input of `sync`). `source_hash`
    is taken over the normalized data AND the tenant (two tenants' records
    never share one — the identity index does not name the tenant)."""
    tenant_slug: str
    target_key: Optional[str]
    source_ref: str
    source_hash: str
    payload: dict[str, Any]
    flags: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Proposal:
    id: int
    kind: str
    source: str
    tenant_slug: str
    target_key: Optional[str]
    source_ref: str
    payload: dict[str, Any]
    source_hash: str
    flags: list[dict[str, Any]]
    status: str
    geocode: Optional[dict[str, Any]]
    created_at: str
    updated_at: str
    decided_by: Optional[int]
    decided_at: Optional[str]
    decision_reason: Optional[str]
    superseded_by: Optional[int]

    @property
    def open(self) -> bool:
        return self.status == OPEN


def _loads(text: Any, default: Any) -> Any:
    if not isinstance(text, str) or not text:
        return default
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return default
    return value if isinstance(value, type(default)) else default


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def clean_reason(text: Any) -> str:
    """A decision's reason as recorded: whitespace collapsed, ≤ 500 chars."""
    return " ".join(str(text or "").split())[:500]


def _row(r: Any) -> Proposal:
    return Proposal(
        id=int(r[0]), kind=r[1], source=r[2], tenant_slug=r[3], target_key=r[4],
        source_ref=r[5], payload=_loads(r[6], {}), source_hash=r[7], flags=_loads(r[8], []),
        status=r[9], geocode=_loads(r[10], {}) or None, created_at=r[11], updated_at=r[12],
        decided_by=r[13], decided_at=r[14], decision_reason=r[15], superseded_by=r[16])


def list_proposals(kind: str, *, statuses: Optional[Iterable[str]] = None,
                   tenants: Optional[Iterable[str]] = None,
                   conn: Optional[sqlite3.Connection] = None) -> list[Proposal]:
    """Newest first. `tenants` None = every tenant (the caller scopes)."""
    sql = f"SELECT {_COLS} FROM proposals WHERE kind = ?"
    args: list[Any] = [kind]
    if statuses is not None:
        st = [s for s in statuses if s in STATUSES]
        if not st:
            return []
        sql += f" AND status IN ({','.join('?' * len(st))})"
        args.extend(st)
    if tenants is not None:
        tn = sorted(set(tenants))
        if not tn:
            return []
        sql += f" AND tenant_slug IN ({','.join('?' * len(tn))})"
        args.extend(tn)
    sql += " ORDER BY id DESC"
    own = conn is None
    c = conn if conn is not None else connect(paths.registry_db_path(), read_only=True)
    try:
        return [_row(r) for r in c.execute(sql, args).fetchall()]
    except sqlite3.OperationalError:
        return []                                   # before 043
    finally:
        if own:
            c.close()


def get(proposal_id: int, *, conn: Optional[sqlite3.Connection] = None) -> Optional[Proposal]:
    own = conn is None
    c = conn if conn is not None else connect(paths.registry_db_path(), read_only=True)
    try:
        r = c.execute(f"SELECT {_COLS} FROM proposals WHERE id = ?", (int(proposal_id),)
                      ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        if own:
            c.close()
    return _row(r) if r is not None else None


def count_open(kind: str, tenants: Optional[Iterable[str]] = None) -> int:
    return len(list_proposals(kind, statuses=(OPEN,), tenants=tenants))


def _supersede(conn: sqlite3.Connection, ids: list[int], *, by: Optional[int],
               reason: str) -> int:
    n = 0
    for pid in ids:
        n += conn.execute(
            f"UPDATE proposals SET status = 'superseded', decided_at = {_NOW}, "
            f"updated_at = {_NOW}, superseded_by = ?, decision_reason = ? "
            f"WHERE id = ? AND status = 'proposed'", (by, reason[:500], pid)).rowcount
    return n


def sync(kind: str, source: str, items: list[Item], *,
         keep_flags: tuple[str, ...] = (),
         owns: Optional[Callable[[Proposal], bool]] = None,
         may_sweep: Optional[Callable[[Proposal], bool]] = None,
         may_retarget: Optional[Callable[[Proposal, Item], bool]] = None) -> dict[str, int]:
    """Apply what the source says now (module docstring). Returns counts:
    created, refreshed, kept (rejected / confirmed, unchanged), superseded.

    `owns`: the existing rows this run speaks for (e.g. one integration
    instance's) — the others are never superseded nor used as `previous`.
    `may_sweep`: which unlisted open proposals this run may supersede (what
    it read in full); default none.
    `may_retarget`: a CONFIRMED proposal of the same data and today's item
    — may that data be proposed again for the item's target (the confirmed
    target is gone)? Default no.
    `keep_flags`: warning codes an operator's action settled (a lookup's
    distance) — kept on an open proposal when its warnings are refreshed
    and its target stays."""
    counts = {"created": 0, "refreshed": 0, "kept_rejected": 0, "kept_confirmed": 0,
              "superseded": 0}
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            rows = [p for p in (_row(r) for r in reg.execute(
                f"SELECT {_COLS} FROM proposals WHERE kind = ? AND source = ? ORDER BY id",
                (kind, source)).fetchall()) if owns is None or owns(p)]
            by_record: dict[tuple[str, str], list[Proposal]] = {}
            for p in rows:
                by_record.setdefault((p.source_ref, p.tenant_slug), []).append(p)
            seen: set[tuple[str, str]] = set()
            for item in items:
                record = (item.source_ref, item.tenant_slug)
                if record in seen:
                    raise ValueError(f"{item.source_ref} listed twice for one tenant")
                seen.add(record)
                _sync_one(reg, kind, source, item, by_record.get(record, []), keep_flags,
                          may_retarget, counts)
            listed = {ref for ref, _slug in seen}
            moved: list[int] = []
            gone: list[int] = []
            for p in rows:
                if not p.open or (p.source_ref, p.tenant_slug) in seen or may_sweep is None \
                        or not may_sweep(p):
                    continue
                (moved if p.source_ref in listed else gone).append(p.id)
            counts["superseded"] += _supersede(
                reg, moved, by=None, reason="the source record belongs to another client now")
            counts["superseded"] += _supersede(
                reg, gone, by=None, reason="no longer listed by the source")
    finally:
        reg.close()
    return counts


def _sync_one(conn: sqlite3.Connection, kind: str, source: str, item: Item,
              rows: list[Proposal], keep_flags: tuple[str, ...],
              may_retarget: Optional[Callable[[Proposal, Item], bool]],
              counts: dict[str, int]) -> None:
    """One record (its rows, oldest first) against what the source says now."""
    live = [p for p in rows if p.status != "superseded"]
    same = [p for p in live if p.source_hash == item.source_hash]
    # Open proposals of OTHER data of this record: never reviewable once the
    # source says something else (an address changed, or changed back).
    stale = [p.id for p in rows if p.open and p.source_hash != item.source_hash]

    if any(p.status == "rejected" for p in same):
        counts["kept_rejected"] += 1
        counts["superseded"] += _supersede(conn, stale, by=None, reason="the source changed")
        return

    confirmed = [p for p in same if p.status == "confirmed"]
    open_same = [p for p in same if p.open]
    if confirmed and (
            item.target_key is None
            or any(c.target_key == item.target_key for c in confirmed)
            or not any(may_retarget is not None and may_retarget(c, item) for c in confirmed)):
        # In force and unchanged: nothing to review. An open copy of the
        # same data (offered for another target while the confirmed one was
        # gone) is closed too.
        counts["kept_confirmed"] += 1
        counts["superseded"] += _supersede(conn, stale, by=None, reason="the source changed")
        counts["superseded"] += _supersede(conn, [p.id for p in open_same], by=None,
                                           reason="already confirmed for this site")
        return

    if open_same:
        p = open_same[-1]
        payload = {**item.payload, **{k: p.payload[k] for k in _CARRIED if k in p.payload}}
        target = item.target_key                  # derived: today's assignment wins
        flags = list(item.flags)
        if target == p.target_key:
            flags += [f for f in p.flags if isinstance(f, dict) and f.get("code") in keep_flags]
        if (target, dumps(flags), dumps(payload)) != \
                (p.target_key, dumps(p.flags), dumps(p.payload)):
            try:
                conn.execute(
                    f"UPDATE proposals SET target_key = ?, flags_json = ?, payload_json = ?, "
                    f"updated_at = {_NOW} WHERE id = ?",
                    (target, dumps(flags), dumps(payload), p.id))
            except sqlite3.IntegrityError:
                # The same data is already decided for that target: this
                # open copy is not reviewable any more.
                counts["superseded"] += _supersede(conn, [p.id], by=None,
                                                   reason="already decided for that site")
                counts["superseded"] += _supersede(conn, stale, by=None,
                                                   reason="the source changed")
                return
            counts["refreshed"] += 1
        counts["superseded"] += _supersede(conn, stale + [q.id for q in open_same[:-1]],
                                           by=p.id, reason="the source changed")
        return

    # New data for this record (or data that came back after it was
    # superseded): propose it, the record's previous data alongside.
    prior = [p for p in rows if p.source_hash != item.source_hash]
    previous = prior[-1] if prior else None
    payload = dict(item.payload)
    if previous is not None:
        payload["previous"] = {
            "id": previous.id, "status": previous.status,
            "label": (previous.payload or {}).get("label"),
            "target_key": previous.target_key,
        }
    if confirmed:
        # The same data, confirmed earlier for a target that is gone:
        # offered again for the new one (not a change in the source).
        c = confirmed[-1]
        payload["confirmed_before"] = {"id": c.id, "target_key": c.target_key}
    # A plain INSERT: nothing live holds this data for this target (above).
    # Should the identity index ever match, the whole sync rolls back — a
    # proposal is never dropped silently.
    cur = conn.execute(
        "INSERT INTO proposals (kind, source, tenant_slug, target_key, source_ref, "
        "payload_json, source_hash, flags_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (kind, source, item.tenant_slug, item.target_key, item.source_ref, dumps(payload),
         item.source_hash, dumps(item.flags)))
    new_id = int(cur.lastrowid or 0)
    counts["created"] += 1
    counts["superseded"] += _supersede(
        conn, [p.id for p in rows if p.open], by=new_id, reason="the source changed")


def set_lookup(proposal_id: int, geocode: dict[str, Any], flags: list[dict[str, Any]]) -> bool:
    """Store an operator's lookup (matches) and the warnings it settles —
    open proposals only."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            return reg.execute(
                f"UPDATE proposals SET geocode_json = ?, flags_json = ?, updated_at = {_NOW} "
                f"WHERE id = ? AND status = 'proposed'",
                (dumps(geocode), dumps(flags), int(proposal_id))).rowcount > 0
    finally:
        reg.close()


def decide(conn: sqlite3.Connection, proposal_id: int, status: str, *, actor: int,
           reason: str, target_key: Optional[str] = None,
           expected_updated_at: Optional[str] = None) -> None:
    """Close an OPEN proposal as `status` ('confirmed' | 'rejected') on the
    caller's connection, inside ITS transaction. ProposalError when it is
    no longer open (another operator decided first) or — given
    `expected_updated_at` — no longer as the operator saw it (a refresh
    re-targeted it or changed its warnings; a lookup ran)."""
    if status not in ("confirmed", "rejected"):
        raise ValueError(status)
    reason = clean_reason(reason)
    if len(reason) < 3:
        raise ProposalError("a reason is required", code="VALIDATION_FAILED")
    sets = ["status = ?", "decided_by = ?", f"decided_at = {_NOW}", "decision_reason = ?",
            f"updated_at = {_NOW}"]
    args: list[Any] = [status, int(actor), reason]
    if target_key is not None:
        sets.append("target_key = ?")
        args.append(target_key)
    where = "id = ? AND status = 'proposed'"
    args.append(int(proposal_id))
    if expected_updated_at is not None:
        where += " AND updated_at = ?"
        args.append(expected_updated_at)
    try:
        n = conn.execute(f"UPDATE proposals SET {', '.join(sets)} WHERE {where}", args).rowcount
    except sqlite3.IntegrityError as exc:
        if "UNIQUE" not in str(exc).upper():
            raise
        raise ProposalError("the same proposal was already decided for that site") from None
    if n != 1:
        raise ProposalError("this proposal was decided or changed meanwhile — reload")
