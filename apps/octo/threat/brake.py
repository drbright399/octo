"""The storm brake (design 6.2): a super_admin may hold ONE automated rule at
a Red ceiling for at most 24 hours — with step-up, a reason, an audit row and
a notice to every other admin (the route does those). Bounds kept here and
again by the table's CHECKs:
  * automated rules only — an analyst's B6 / R8 is never braked, nor the
    restricted B7 (CSAM: an automated Black by the owner's decision);
  * ceiling 'red' only, ≤ 24 h, one live brake per rule;
  * it auto-expires; a super_admin may release it early;
  * existing Blacks are untouched: the brake only caps what the rule OPENS
    from now on (`ceiling`), never an incident's tier;
  * a false positive never demotes a rule automatically — the brake is the
    only lever, and it is manual.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.threat import rules
from apps.octo.threat.store import BLACK, RED, parse

MAX_HOURS = 24


class BrakeError(ValueError):
    pass


@dataclass(frozen=True)
class Brake:
    id: int
    rule_id: str
    set_by: int
    set_at: str
    expires_at: str
    reason: str
    released_at: Optional[str]

    def live(self, now: datetime) -> bool:
        exp = parse(self.expires_at)
        return self.released_at is None and exp is not None and exp > now

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "rule_id": self.rule_id, "ceiling": RED, "set_by": self.set_by,
                "set_at": self.set_at, "expires_at": self.expires_at, "reason": self.reason,
                "released_at": self.released_at}


def validate(rule_id: str, hours: float) -> rules.Rule:
    r = rules.rule(rule_id)
    if r is None:
        raise BrakeError(f"no rule {rule_id!r}")
    if not r.automated:
        raise BrakeError("an analyst's declaration (B6 / R8) is never braked")
    if r.restricted:
        # Rick, 2026-10-06: a CSAM lookup is an automated Black — law
        # enforcement territory, handled immediately; no storm valve holds it.
        raise BrakeError("a restricted rule (B7, CSAM) is never braked")
    if not (0 < float(hours) <= MAX_HOURS):
        raise BrakeError(f"a brake lasts more than 0 and at most {MAX_HOURS} hours")
    return r


def brakes(*, now: Optional[datetime] = None, live_only: bool = True) -> list[Brake]:
    now = now or datetime.now(timezone.utc)
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            found = reg.execute("SELECT * FROM rule_brake ORDER BY id DESC LIMIT 200").fetchall()
        finally:
            reg.close()
    except sqlite3.Error:
        return []
    out = [Brake(int(r["id"]), r["rule_id"], int(r["set_by"]), r["set_at"], r["expires_at"],
                 r["reason"], r["released_at"]) for r in found]
    return [b for b in out if b.live(now)] if live_only else out


def live_brake(rule_id: str, now: Optional[datetime] = None) -> Optional[Brake]:
    return next((b for b in brakes(now=now) if b.rule_id == rule_id), None)


def set_brake(conn: sqlite3.Connection, rule_id: str, *, by: int, reason: str, hours: float,
              now: Optional[datetime] = None) -> int:
    """Inside the caller's registry transaction (after its audit row)."""
    validate(rule_id, hours)
    at = now or datetime.now(timezone.utc)
    if any(b.rule_id == rule_id for b in brakes(now=at)):
        raise BrakeError(f"{rule_id} is already braked")
    cur = conn.execute(
        "INSERT INTO rule_brake (rule_id, ceiling, set_by, set_at, expires_at, reason) "
        "VALUES (?, 'red', ?, ?, ?, ?)",
        (rule_id, by, format_utc_ms(at), format_utc_ms(at + timedelta(hours=float(hours))),
         reason))
    return int(cur.lastrowid)


def release(conn: sqlite3.Connection, brake_id: int, *, by: int,
            now: Optional[datetime] = None) -> bool:
    return conn.execute("UPDATE rule_brake SET released_at = ?, released_by = ? "
                        "WHERE id = ? AND released_at IS NULL",
                        (format_utc_ms(now or datetime.now(timezone.utc)), by,
                         brake_id)).rowcount == 1


def ceiling(rule_id: str, tier: str, now: Optional[datetime] = None) -> str:
    """The tier an AUTOMATED rule may open now: its own, held at Red while a
    brake is live. Human rules pass through untouched."""
    r = rules.rule(rule_id)
    if r is None or not r.automated or r.restricted or tier != BLACK:
        return tier
    return RED if live_brake(rule_id, now) is not None else tier
