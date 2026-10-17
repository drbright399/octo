"""The registry rows of human verdicts on ALERTS (migration 046) — the
`alert_verdict` labels (ack / confirmed / expected) and the
`expected_condition` rules — and what was said AFTER an acknowledgement
(migration 048, v0.17.5): `alert_verdict_followup` notes and its recall.

Writers take the caller's registry connection (inside its transaction: the
API audits FIRST, then writes — `threat.audit` / the tiers router's
pattern). Readers are fail-soft: a registry that cannot be read answers
"no verdict, no rule" — which only ever makes the Fleet LOUDER (nothing
hidden), never quieter.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.verdicts.keys import (
    CSAM,
    ROCKETCYBER_REFUSAL,
    ROCKETCYBER_REPEAT,
    AlertKey,
    ack_only_key,
)

logger = logging.getLogger(__name__)

ACK, CONFIRMED, EXPECTED = "ack", "confirmed", "expected"
VERDICTS = (ACK, CONFIRMED, EXPECTED)
# Follow-ups on an acknowledgement (048): additive notes, and ONE recall.
NOTE, RECALL = "note", "recall"
FOLLOWUPS = (NOTE, RECALL)
NOTE_MAX = 500
REASON_MIN = 10
REVIEW_MAX_DAYS = 90
REVIEW_DEFAULT_DAYS = 90
REPEAT_HOURS = 24
REMINDER_BEFORE = timedelta(days=7)
# How far back acknowledgements are read for a 24-hour view: an ack is
# never older than its alert, and a repeat-ack covers at most 24 h more.
ACK_LOOKBACK = timedelta(hours=48)
# A remote NETWORK in an expected condition is never wider than this.
MIN_PREFIX = {4: 16, 6: 32}
_HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def iso(dt: Optional[datetime] = None) -> str:
    return format_utc_ms(dt or datetime.now(timezone.utc))


def parse(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        out = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Verdict:
    id: int
    slug: str
    event_id: int
    source: str
    device_key: str
    signature_key: str
    verdict: str
    actor: int
    at: str
    note: Optional[str] = None
    hits_at: Optional[int] = None
    last_seen_at: Optional[str] = None
    repeat_until: Optional[str] = None
    rule_id: Optional[int] = None
    incident_id: Optional[int] = None
    alert_ref: Optional[str] = None
    recalled_at: Optional[str] = None
    """When an ACK was recalled (048) — it then covers nothing."""

    @property
    def recalled(self) -> bool:
        return bool(self.recalled_at)


@dataclass(frozen=True)
class FollowUp:
    """A note on an acknowledgement, or its recall (048)."""
    id: int
    verdict_id: int
    slug: str
    kind: str
    actor: int
    at: str
    text: str


class FollowUpConflict(ValueError):
    """The follow-up contradicts the verdict's state (a second recall, a
    recall or a note on a label that is not an ack) — the API's 409."""


ALREADY_RECALLED = "this acknowledgement is already recalled"
NOT_AN_ACK = ("only an acknowledgement can be recalled or noted — an expected condition is "
              "revoked under Settings → Threats")


@dataclass(frozen=True)
class ExpectedRule:
    id: int
    slug: str
    source: str
    device_key: str
    signature_key: str
    remote: Optional[str]
    label: str
    reason: str
    origin_event_id: int
    created_by: int
    created_at: str
    review_at: str
    reminded_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revoked_by: Optional[int] = None
    revoke_reason: Optional[str] = None

    def status(self, now: datetime) -> str:
        if self.revoked_at:
            return "revoked"
        review = parse(self.review_at)
        if review is None or now >= review:
            return "expired"
        return "active"

    def active(self, now: datetime) -> bool:
        return self.status(now) == "active"

    def as_dict(self, now: datetime) -> dict[str, Any]:
        return {"id": self.id, "tenant_slug": self.slug, "source": self.source,
                "device_key": self.device_key, "signature_key": self.signature_key,
                "remote": self.remote, "label": self.label, "reason": self.reason,
                "origin_event_id": self.origin_event_id, "created_by": self.created_by,
                "created_at": self.created_at, "review_at": self.review_at,
                "reminded_at": self.reminded_at, "revoked_at": self.revoked_at,
                "revoked_by": self.revoked_by, "revoke_reason": self.revoke_reason,
                "status": self.status(now)}


def _verdict(r: sqlite3.Row) -> Verdict:
    names = r.keys()
    return Verdict(int(r["id"]), r["tenant_slug"], int(r["event_id"]), r["source"],
                   r["device_key"] or "", r["signature_key"], r["verdict"], int(r["actor"]),
                   r["at"], r["note"], r["hits_at"], r["last_seen_at"], r["repeat_until"],
                   r["rule_id"], r["incident_id"],
                   r["alert_ref"] if "alert_ref" in names else None,
                   r["recalled_at"] if "recalled_at" in names else None)


def _followup(r: sqlite3.Row) -> FollowUp:
    return FollowUp(int(r["id"]), int(r["verdict_id"]), r["tenant_slug"], r["kind"],
                    int(r["actor"]), r["at"], r["text"])


# Every verdict read carries its recall (048): a recalled ack covers nothing.
# A registry without the follow-up table is unreadable here — no verdict at
# all (louder), never a recalled ack that covers again.
_VERDICT_SELECT = ("SELECT v.*, (SELECT f.at FROM alert_verdict_followup f "
                   "WHERE f.verdict_id = v.id AND f.kind = 'recall' "
                   "ORDER BY f.id LIMIT 1) AS recalled_at FROM alert_verdict v")


def _rule(r: sqlite3.Row) -> ExpectedRule:
    return ExpectedRule(int(r["id"]), r["tenant_slug"], r["source"], r["device_key"] or "",
                        r["signature_key"], r["remote"], r["label"], r["reason"],
                        int(r["origin_event_id"]), int(r["created_by"]), r["created_at"],
                        r["review_at"], r["reminded_at"], r["revoked_at"], r["revoked_by"],
                        r["revoke_reason"])


def _read() -> Optional[sqlite3.Connection]:
    try:
        return connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# The remote of an expected condition (a network alert)
# ---------------------------------------------------------------------------

def normalize_remote(value: Any) -> str:
    """An IP, a network (never wider than /16 · /32 for IPv6) or a host
    name (matched against a FORWARD-CONFIRMED PTR only — a PTR alone is the
    remote's owner's word). ValueError with operator wording."""
    from apps.octo.adapters.unifi.catalogue import is_local

    text = str(value or "").strip().lower()
    if not text:
        raise ValueError("a remote address, network or host is required")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        if is_local(str(ip)):
            raise ValueError("that is a local address — the remote end is outside the site")
        return str(ip)
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ValueError("not an address, a network or a host name") from None
        if net.prefixlen < MIN_PREFIX[net.version]:
            raise ValueError(f"a network is at most /{MIN_PREFIX[net.version]} wide here")
        if is_local(str(net.network_address)):
            raise ValueError("that is a local network — the remote end is outside the site")
        return str(net)
    host = text[2:] if text.startswith("*.") else text
    host = host.rstrip(".")
    if not _HOST_RE.fullmatch(host):
        raise ValueError("not an address, a network or a host name")
    return host


def is_host_remote(remote: str) -> bool:
    """A host-name remote (matched by forward-confirmed PTR), not an
    address or a network."""
    if "/" in remote:
        return False
    try:
        ipaddress.ip_address(remote)
    except ValueError:
        return True
    return False


def remote_matches(remote: str, ip: Optional[str], ptr: Optional[dict[str, Any]]) -> bool:
    """Does `ip` fall under an expected condition's remote? A host name
    matches only a forward-confirmed PTR (`ptr`: the enrichment cache's
    answer for `ip`)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    try:
        return addr == ipaddress.ip_address(remote)
    except ValueError:
        pass
    if "/" in remote:
        try:
            net = ipaddress.ip_network(remote, strict=False)
        except ValueError:
            return False
        return addr.version == net.version and addr in net
    if not ptr or not ptr.get("ptr_confirmed"):
        return False
    name = str(ptr.get("ptr") or "").lower().rstrip(".")
    return bool(name) and (name == remote or name.endswith("." + remote))


# ---------------------------------------------------------------------------
# Writes (the caller's connection, inside its transaction)
# ---------------------------------------------------------------------------

def record(conn: sqlite3.Connection, *, slug: str, event_id: int, key: AlertKey, verdict: str,
           actor: int, at: Optional[datetime] = None, note: Optional[str] = None,
           hits_at: Optional[int] = None, last_seen_at: Optional[str] = None,
           repeat_until: Optional[datetime] = None, rule_id: Optional[int] = None,
           incident_id: Optional[int] = None) -> int:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
    if repeat_until is not None and not key.device_key.strip():
        raise ValueError("this alert names no device — \"repeats for 24 h\" would cover the "
                         "whole client")
    if repeat_until is not None and ack_only_key(key):
        raise ValueError(ROCKETCYBER_REPEAT)
    cur = conn.execute(
        "INSERT INTO alert_verdict (tenant_slug, event_id, source, device_key, signature_key, "
        "verdict, actor, at, note, hits_at, last_seen_at, repeat_until, rule_id, incident_id, "
        "alert_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, int(event_id), key.source[:40], key.device_key, key.signature_key, verdict,
         int(actor), iso(at), (note or None) and note[:NOTE_MAX],
         int(hits_at) if hits_at else None, last_seen_at,
         iso(repeat_until) if repeat_until else None, rule_id, incident_id,
         key.ref[:200] if key.ref else None))
    return int(cur.lastrowid or 0)


def collapse(text: Any) -> str:
    """A note / reason as it is recorded: whitespace collapsed."""
    return " ".join(str(text or "").split())


def add_followup(conn: sqlite3.Connection, *, verdict_id: int, slug: str, kind: str,
                 actor: int, text: str, at: Optional[datetime] = None) -> int:
    """A note on an acknowledgement, or its recall (final: one per ack).
    ValueError for a bad text, `FollowUpConflict` for a verdict that takes
    no such follow-up (checked again inside the caller's transaction — the
    schema's triggers hold it too)."""
    if kind not in FOLLOWUPS:
        raise ValueError(f"a follow-up is one of {', '.join(FOLLOWUPS)}")
    body = collapse(text)
    if kind == RECALL and len(body) < REASON_MIN:
        raise ValueError(f"a reason of at least {REASON_MIN} characters is required")
    if not body:
        raise ValueError("a note is required")
    if len(body) > NOTE_MAX:
        raise ValueError(f"a note or reason is at most {NOTE_MAX} characters")
    row = conn.execute("SELECT verdict, tenant_slug FROM alert_verdict WHERE id = ?",
                       (int(verdict_id),)).fetchone()
    if row is None or row[1] != slug:
        raise ValueError("no such acknowledgement of this tenant")
    if row[0] != ACK:
        raise FollowUpConflict(NOT_AN_ACK)
    if kind == RECALL and conn.execute(
            "SELECT 1 FROM alert_verdict_followup WHERE verdict_id = ? AND kind = 'recall'",
            (int(verdict_id),)).fetchone() is not None:
        raise FollowUpConflict(ALREADY_RECALLED)
    cur = conn.execute(
        "INSERT INTO alert_verdict_followup (verdict_id, tenant_slug, kind, actor, at, text) "
        "VALUES (?, ?, ?, ?, ?, ?)", (int(verdict_id), slug, kind, int(actor), iso(at), body))
    return int(cur.lastrowid or 0)


def add_expected(conn: sqlite3.Connection, *, slug: str, key: AlertKey, remote: Optional[str],
                 label: str, reason: str, origin_event_id: int, by: int, now: datetime,
                 review_at: datetime) -> int:
    if key.signature_key.startswith(f"nextdns:{CSAM}|"):
        raise ValueError("a CSAM lookup is never expected")
    if ack_only_key(key):
        raise ValueError(ROCKETCYBER_REFUSAL)
    if not key.device_key.strip():
        raise ValueError("this alert names no device — an expected condition would cover the "
                         "whole client")
    if len(reason.strip()) < REASON_MIN:
        raise ValueError(f"a reason of at least {REASON_MIN} characters is required")
    if not now < review_at <= now + timedelta(days=REVIEW_MAX_DAYS):
        raise ValueError(f"the review date is within the next {REVIEW_MAX_DAYS} days")
    cur = conn.execute(
        "INSERT INTO expected_condition (tenant_slug, source, device_key, signature_key, remote, "
        "label, reason, origin_event_id, created_by, created_at, review_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (slug, key.source[:40], key.device_key, key.signature_key, remote,
         (label or key.signature_key)[:240], reason.strip()[:500], int(origin_event_id),
         int(by), iso(now), iso(review_at)))
    return int(cur.lastrowid or 0)


def revoke_expected(conn: sqlite3.Connection, rule_id: int, *, by: int, reason: str,
                    now: Optional[datetime] = None) -> bool:
    return conn.execute(
        "UPDATE expected_condition SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
        "WHERE id = ? AND revoked_at IS NULL", (iso(now), int(by), reason[:500], int(rule_id)),
    ).rowcount == 1


def mark_reminded(conn: sqlite3.Connection, rule_id: int, now: datetime) -> bool:
    return conn.execute(
        "UPDATE expected_condition SET reminded_at = ? WHERE id = ? AND reminded_at IS NULL",
        (iso(now), int(rule_id))).rowcount == 1


# ---------------------------------------------------------------------------
# Reads (fail-soft)
# ---------------------------------------------------------------------------

def verdicts(slug: str, *, since: Optional[datetime] = None,
             event_ids: Optional[Iterable[int]] = None,
             refs: Optional[Iterable[str]] = None,
             kinds: tuple[str, ...] = VERDICTS) -> list[Verdict]:
    """The tenant's verdicts — since a time, and/or of some events, or of
    some vendor alerts (`alert_ref`; not both lists at once)."""
    if event_ids is not None and refs is not None:
        raise ValueError("event ids or refs, not both")
    column, values = None, None
    if event_ids is not None:
        column, values = "event_id", sorted({int(i) for i in event_ids})
    elif refs is not None:
        column, values = "alert_ref", sorted({str(r) for r in refs if r})
    if values is not None and not values:
        return []
    reg = _read()
    if reg is None:
        return []
    try:
        sql = (f"{_VERDICT_SELECT} WHERE v.tenant_slug = ? "
               f"AND v.verdict IN ({','.join('?' * len(kinds))})")
        args: list[Any] = [slug, *kinds]
        if since is not None:
            sql += " AND v.at >= ?"
            args.append(iso(since))
        if values is None:
            return [_verdict(r) for r in reg.execute(sql + " ORDER BY v.at, v.id",
                                                     args).fetchall()]
        out: list[Verdict] = []
        for i in range(0, len(values), 400):
            chunk = values[i:i + 400]
            out += [_verdict(r) for r in reg.execute(
                f"{sql} AND v.{column} IN ({','.join('?' * len(chunk))}) ORDER BY v.at, v.id",
                [*args, *chunk]).fetchall()]
        return sorted(out, key=lambda v: (v.at, v.id))
    except sqlite3.Error as exc:
        logger.warning("[verdicts] %s not read (%s)", slug, type(exc).__name__)
        return []
    finally:
        reg.close()


def get_verdict(verdict_id: int) -> Optional[Verdict]:
    """One verdict (with its recall), or None — also when the registry
    cannot be read."""
    reg = _read()
    if reg is None:
        return None
    try:
        r = reg.execute(f"{_VERDICT_SELECT} WHERE v.id = ?", (int(verdict_id),)).fetchone()
        return _verdict(r) if r else None
    except sqlite3.Error as exc:
        logger.warning("[verdicts] verdict not read (%s)", type(exc).__name__)
        return None
    finally:
        reg.close()


def followups(slug: str, verdict_ids: Iterable[int]) -> dict[int, list[FollowUp]]:
    """The notes and recalls of these verdicts of the tenant, oldest first
    (newest last). Fail-soft: {} when the registry cannot be read."""
    ids = sorted({int(i) for i in verdict_ids})
    if not ids:
        return {}
    reg = _read()
    if reg is None:
        return {}
    out: dict[int, list[FollowUp]] = {}
    try:
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            for r in reg.execute(
                    f"SELECT * FROM alert_verdict_followup WHERE tenant_slug = ? AND verdict_id "
                    f"IN ({','.join('?' * len(chunk))}) ORDER BY at, id", [slug, *chunk]):
                f = _followup(r)
                out.setdefault(f.verdict_id, []).append(f)
        return out
    except sqlite3.Error as exc:
        logger.warning("[verdicts] follow-ups of %s not read (%s)", slug, type(exc).__name__)
        return {}
    finally:
        reg.close()


def expected_rules(slug: Optional[str] = None) -> list[ExpectedRule]:
    """Every expected condition (active, expired, revoked), newest first."""
    reg = _read()
    if reg is None:
        return []
    try:
        if slug is None:
            rows = reg.execute("SELECT * FROM expected_condition ORDER BY id DESC").fetchall()
        else:
            rows = reg.execute("SELECT * FROM expected_condition WHERE tenant_slug = ? "
                               "ORDER BY id DESC", (slug,)).fetchall()
        return [_rule(r) for r in rows]
    except sqlite3.Error as exc:
        logger.warning("[verdicts] expected conditions not read (%s)", type(exc).__name__)
        return []
    finally:
        reg.close()


def active_rules(slug: str, now: datetime) -> list[ExpectedRule]:
    return [r for r in expected_rules(slug) if r.active(now)]


def get_rule(rule_id: int) -> Optional[ExpectedRule]:
    reg = _read()
    if reg is None:
        return None
    try:
        r = reg.execute("SELECT * FROM expected_condition WHERE id = ?",
                        (int(rule_id),)).fetchone()
        return _rule(r) if r else None
    except sqlite3.Error:
        return None
    finally:
        reg.close()


def due_reminders(now: datetime) -> list[ExpectedRule]:
    """Live conditions within 7 days of their review date, not yet reminded."""
    reg = _read()
    if reg is None:
        return []
    try:
        rows = reg.execute(
            "SELECT * FROM expected_condition WHERE revoked_at IS NULL AND reminded_at IS NULL "
            "AND review_at > ? AND review_at <= ? ORDER BY review_at, id",
            (iso(now), iso(now + REMINDER_BEFORE))).fetchall()
        return [_rule(r) for r in rows]
    except sqlite3.Error:
        return []
    finally:
        reg.close()
