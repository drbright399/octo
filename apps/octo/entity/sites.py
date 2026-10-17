"""Sites and vendor refs — "vendor scope X belongs to site Y" — with the
operator's decisions winning (design 2.3 + G8).

States: auto (a narrow evidence rule), suggested (needs a human), confirmed /
rejected (a human), retired (ended: unmapped, superseded). A rule writes only
auto / suggested (`propose`); the DATABASE refuses a rule's UPDATE of a
confirmed / rejected row, a rule's INSERT for a scope an operator confirmed
(or for the very pair an operator rejected), and any DELETE of an operator
decision except the retention job's — so a rule bug cannot overwrite a human
(the triggers in migration 040). An INSERT the trigger refuses becomes a
Conflicts card (`link_conflict`) and one `entity_review` notice.

A rejected pair is also SUPPRESSED (`link_suppression`): the rule stops
suggesting it. When a suppression with an expiry runs out, the pair can only
come back as `suggested`, never `auto` (AT-R10).

Every function takes ONE open connection to ONE tenant's entities.db.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo.entity import ids
from apps.octo.entity import normalize as nz

OPERATOR_MAPPING = "operator:mapping"
CONFIRMED_SCORE = 95
NAME_CAP = 45


@dataclass(frozen=True)
class Ref:
    id: int
    site_id: str
    vendor: str
    adapter_instance_id: int
    vendor_scope_id: str
    state: str
    score: int
    rule_id: str
    rule_version: int
    evidence: dict[str, Any]
    valid_from: str
    valid_to: Optional[str]
    decided_by: str
    decided_at: str
    reason: Optional[str]

    @classmethod
    def of(cls, row: sqlite3.Row) -> "Ref":
        try:
            evidence = json.loads(row["evidence"] or "{}")
        except ValueError:
            evidence = {}
        return cls(int(row["id"]), row["site_id"], row["vendor"], int(row["adapter_instance_id"]),
                   row["vendor_scope_id"], row["state"], int(row["score"]), row["rule_id"],
                   int(row["rule_version"]), evidence if isinstance(evidence, dict) else {},
                   row["valid_from"], row["valid_to"], row["decided_by"], row["decided_at"],
                   row["reason"])

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "site_id": self.site_id, "vendor": self.vendor,
                "adapter_instance_id": self.adapter_instance_id,
                "vendor_scope_id": self.vendor_scope_id, "state": self.state,
                "score": self.score, "rule_id": self.rule_id, "rule_version": self.rule_version,
                "evidence": self.evidence, "valid_from": self.valid_from,
                "valid_to": self.valid_to, "decided_by": self.decided_by,
                "decided_at": self.decided_at, "reason": self.reason}


def _sha(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Sites
# ---------------------------------------------------------------------------

def create_site(conn: sqlite3.Connection, *, label: str, anchor: str, now: str, created_by: str,
                tz: Optional[str] = None, location: Optional[dict[str, Any]] = None,
                site_id: Optional[str] = None) -> str:
    site_id = site_id or ids.new("st")
    loc = location or {}
    conn.execute(
        "INSERT INTO site (site_id, label, anchor, tz, lat, lng, geo_radius_m, geo_text, "
        " geo_source, created_at, created_by, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (site_id, (label or "Site")[:200], anchor, tz or None, loc.get("lat"), loc.get("long"),
         loc.get("radius"), loc.get("text"),
         ("unifi" if anchor == "unifi" else "manual") if loc else None,
         now, created_by, now),
    )
    return site_id


def site(conn: sqlite3.Connection, site_id: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM site WHERE site_id = ?", (site_id,)).fetchone()


def active_sites(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM site WHERE status = 'active' ORDER BY created_at, site_id").fetchall()


def update_site_geo(conn: sqlite3.Connection, site_id: str, *, label: Optional[str],
                    tz: Optional[str], location: dict[str, Any], now: str) -> None:
    """The UniFi console's name / zone / location, refreshed from the fleet
    report (an operator-edited label is kept: only an anchor-named label
    that no operator renamed follows the vendor)."""
    row = site(conn, site_id)
    if row is None:
        return
    new_label = row["label"]
    if label and row["created_by"] == "rule:L-UNIFI" and not row["label_by"] \
            and row["label"] != label:
        new_label = label[:200]
    loc = location or {}
    conn.execute(
        "UPDATE site SET label = ?, tz = COALESCE(?, tz), lat = COALESCE(?, lat), "
        " lng = COALESCE(?, lng), geo_radius_m = COALESCE(?, geo_radius_m), "
        " geo_text = COALESCE(?, geo_text), "
        " geo_source = CASE WHEN geo_source = 'manual' THEN geo_source ELSE "
        "   COALESCE(?, geo_source) END, updated_at = ? WHERE site_id = ?",
        (new_label, tz or None, loc.get("lat"), loc.get("long"), loc.get("radius"),
         loc.get("text"), "unifi" if loc else None, now, site_id),
    )


def rename_site(conn: sqlite3.Connection, site_id: str, *, label: str, operator_id: int,
                now: str) -> Optional[sqlite3.Row]:
    """An operator names the site (two offices of one client must be told
    apart): the vendor's name no longer replaces it."""
    if site(conn, site_id) is None:
        return None
    conn.execute("UPDATE site SET label = ?, label_by = ?, updated_at = ? WHERE site_id = ?",
                 (label.strip()[:200], f"operator:{int(operator_id)}", now, site_id))
    return site(conn, site_id)


# ---------------------------------------------------------------------------
# Refs
# ---------------------------------------------------------------------------

def refs(conn: sqlite3.Connection, vendor: str, scope_id: str, *,
         instance_id: Optional[int] = None, at: Optional[str] = None,
         states: tuple[str, ...] = ("auto", "suggested", "confirmed", "rejected")) -> list[Ref]:
    """The refs of one vendor scope, valid at `at` (default: open now)."""
    marks = ",".join("?" * len(states))
    sql = (f"SELECT * FROM site_vendor_ref WHERE vendor = ? AND vendor_scope_id = ? "
           f"AND state IN ({marks})")
    args: list[Any] = [vendor, scope_id, *states]
    if instance_id is not None:
        sql += " AND adapter_instance_id = ?"
        args.append(int(instance_id))
    if at is None:
        sql += " AND valid_to IS NULL"
    else:
        sql += " AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)"
        args += [at, at]
    sql += " ORDER BY id"
    return [Ref.of(r) for r in conn.execute(sql, args).fetchall()]


def ref(conn: sqlite3.Connection, ref_id: int) -> Optional[Ref]:
    row = conn.execute("SELECT * FROM site_vendor_ref WHERE id = ?", (int(ref_id),)).fetchone()
    return Ref.of(row) if row else None


def refs_of_site(conn: sqlite3.Connection, site_id: str) -> list[Ref]:
    return [Ref.of(r) for r in conn.execute(
        "SELECT * FROM site_vendor_ref WHERE site_id = ? AND valid_to IS NULL ORDER BY id",
        (site_id,)).fetchall()]


def suppressed(conn: sqlite3.Connection, a_type: str, a_value: str, b_type: str, b_value: str,
               *, now: str, rule_id: Optional[str] = None) -> Optional[str]:
    """'active' (an operator said NOT the same, still in force), 'expired'
    (they did, and it ran out: only a suggestion may come back) or None."""
    rows = conn.execute(
        "SELECT expires_at, rule_id FROM link_suppression WHERE a_type = ? AND a_value = ? "
        "AND b_type = ? AND b_value = ?", (a_type, a_value, b_type, b_value)).fetchall()
    state = None
    for r in rows:
        if r["rule_id"] is not None and rule_id is not None and r["rule_id"] != rule_id:
            continue
        if r["expires_at"] is None or r["expires_at"] > now:
            return "active"
        state = "expired"
    return state


def suppress(conn: sqlite3.Connection, a_type: str, a_value: str, b_type: str, b_value: str, *,
             reason: str, decided_by: str, now: str, rule_id: Optional[str] = None,
             expires_at: Optional[str] = None) -> int:
    cur = conn.execute(
        "INSERT INTO link_suppression (a_type, a_value, b_type, b_value, rule_id, reason, "
        " decided_by, decided_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (a_type, a_value, b_type, b_value, rule_id, reason[:500], decided_by, now, expires_at),
    )
    return int(cur.lastrowid)


def scope_key(vendor: str, instance_id: int, scope_id: str) -> str:
    return f"{vendor}:{int(instance_id)}:{scope_id}"


@dataclass(frozen=True)
class Proposal:
    # inserted | updated | unchanged | refreshed (the evidence's counts only,
    # at most once a day — not a change) | suppressed | conflict
    outcome: str
    ref_id: Optional[int] = None


def propose(conn: sqlite3.Connection, *, site_id: str, vendor: str, instance_id: int,
            scope_id: str, state: str, score: int, rule_id: str, rule_version: int,
            evidence: dict[str, Any], now: str, scope_alt: Optional[str] = None,
            provenance: Optional[list[str]] = None) -> Proposal:
    """A RULE's opinion that (vendor scope) belongs to `site_id`, as `auto`
    or `suggested`. Idempotent: the same inputs change nothing. Never touches
    an operator decision (the triggers enforce it; a refused INSERT is a
    Conflicts card). Names are capped at `suggested` 45.

    `provenance` (the rules that agree on this pair — the link rules' ONE
    combined suggestion per (site, scope)): the row changes only when its
    EFFECTIVE state does (state, score, the strongest rule, the agreeing
    rules); evidence whose counts merely drifted (a coverage share read the
    next day) is refreshed at most once a day (`evidence.as_of`) and is not
    a change. Without it, any change of the evidence is a change."""
    assert state in ("auto", "suggested"), state
    if rule_id.startswith("N-"):
        state, score = "suggested", min(score, NAME_CAP)
    pair = ("scope", scope_key(vendor, instance_id, scope_id), "site", site_id)
    supp = suppressed(conn, *pair, now=now, rule_id=rule_id)
    if supp == "active":
        return Proposal("suppressed")
    if supp == "expired" and state == "auto":
        state = "suggested"          # a once-rejected pair never comes back as auto
    inputs = _sha(site_id, vendor, instance_id, scope_id, state, score, rule_id, rule_version,
                  sorted(provenance) if provenance is not None else evidence)
    open_rows = refs(conn, vendor, scope_id, instance_id=instance_id,
                     states=("auto", "suggested", "confirmed", "rejected"))
    same = [r for r in open_rows if r.site_id == site_id]
    for r in same:
        if r.state in ("confirmed", "rejected"):
            return Proposal("unchanged", r.id)      # the operator decided this pair
    if same:
        r = same[0]
        row = conn.execute("SELECT inputs_sha256 FROM site_vendor_ref WHERE id = ?",
                           (r.id,)).fetchone()
        if row is not None and row["inputs_sha256"] == inputs:
            if provenance is not None and r.evidence != evidence and \
                    str(r.evidence.get("as_of") or "") < str(evidence.get("as_of") or ""):
                conn.execute("UPDATE site_vendor_ref SET evidence = ? WHERE id = ?",
                             (json.dumps(evidence, sort_keys=True,
                                         separators=(",", ":"))[:8000], r.id))
                return Proposal("refreshed", r.id)
            return Proposal("unchanged", r.id)
        conn.execute(
            "UPDATE site_vendor_ref SET state = ?, score = ?, rule_id = ?, rule_version = ?, "
            " evidence = ?, inputs_sha256 = ?, decided_by = ?, decided_at = ? WHERE id = ?",
            (state, int(score), rule_id, int(rule_version),
             json.dumps(evidence, sort_keys=True, separators=(",", ":"))[:8000], inputs,
             f"rule:{rule_id}@{rule_version}", now, r.id),
        )
        return Proposal("updated", r.id)
    try:
        cur = conn.execute(
            "INSERT INTO site_vendor_ref (site_id, vendor, adapter_instance_id, vendor_scope_id, "
            " vendor_scope_alt, state, score, rule_id, rule_version, evidence, inputs_sha256, "
            " valid_from, decided_by, decided_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (site_id, vendor, int(instance_id), scope_id, scope_alt, state, int(score), rule_id,
             int(rule_version), json.dumps(evidence, sort_keys=True, separators=(",", ":"))[:8000],
             inputs, now, f"rule:{rule_id}@{rule_version}", now, now),
        )
    except sqlite3.IntegrityError as exc:
        if "operator decision" not in str(exc):
            raise
        record_conflict(conn, "operator_decision", scope_key(vendor, instance_id, scope_id),
                        {"rule": rule_id, "wanted_site": site_id, "wanted_state": state,
                         "score": int(score)}, now)
        return Proposal("conflict")
    return Proposal("inserted", int(cur.lastrowid))


def retire_rule_refs(conn: sqlite3.Connection, *, vendor: str, scope_id: str, keep_site: str,
                     rule_id: str, now: str, instance_id: Optional[int] = None) -> int:
    """A rule's own open auto / suggested refs of a scope to OTHER sites
    (its opinion changed): retired, never deleted."""
    sql = ("UPDATE site_vendor_ref SET state = 'retired', valid_to = ?, decided_at = ?, "
           " decided_by = ? WHERE vendor = ? AND vendor_scope_id = ? AND rule_id = ? "
           " AND site_id <> ? AND state IN ('auto','suggested') AND valid_to IS NULL")
    args: list[Any] = [now, now, f"rule:{rule_id}", vendor, scope_id, rule_id, keep_site]
    if instance_id is not None:
        sql += " AND adapter_instance_id = ?"
        args.append(int(instance_id))
    return conn.execute(sql, args).rowcount


def operator_confirm(conn: sqlite3.Connection, ref_id: int, *, operator_id: int, now: str,
                     reason: Optional[str] = None) -> tuple[Ref, Ref]:
    """A human confirms a ref: it becomes `confirmed` (95), and every OTHER
    open auto / suggested ref of the same scope is retired (the operator
    decided where it belongs)."""
    before = ref(conn, ref_id)
    if before is None or before.valid_to is not None:
        raise LookupError("no open link with that id")
    who = f"operator:{int(operator_id)}"
    conn.execute(
        "UPDATE site_vendor_ref SET state = 'confirmed', score = ?, decided_by = ?, "
        " decided_at = ?, reason = ? WHERE id = ?",
        (max(before.score, CONFIRMED_SCORE) if not before.rule_id.startswith("N-")
         else CONFIRMED_SCORE, who, now, (reason or None), before.id),
    )
    conn.execute(
        "UPDATE site_vendor_ref SET state = 'retired', valid_to = ?, decided_by = ?, "
        " decided_at = ?, reason = 'another site was confirmed for this scope' "
        "WHERE vendor = ? AND adapter_instance_id = ? AND vendor_scope_id = ? AND id <> ? "
        " AND state IN ('auto','suggested') AND valid_to IS NULL",
        (now, who, now, before.vendor, before.adapter_instance_id, before.vendor_scope_id,
         before.id),
    )
    after = ref(conn, ref_id)
    assert after is not None
    return before, after


def operator_reject(conn: sqlite3.Connection, ref_id: int, *, operator_id: int, now: str,
                    reason: str, expires_at: Optional[str] = None) -> tuple[Ref, Ref]:
    """A human says "not this site" (or revokes an auto link): `rejected` +
    a suppression of the pair, so the rule stops suggesting it."""
    before = ref(conn, ref_id)
    if before is None or before.valid_to is not None:
        raise LookupError("no open link with that id")
    who = f"operator:{int(operator_id)}"
    conn.execute(
        "UPDATE site_vendor_ref SET state = 'rejected', decided_by = ?, decided_at = ?, "
        " reason = ? WHERE id = ?", (who, now, reason[:500], before.id))
    suppress(conn, "scope", scope_key(before.vendor, before.adapter_instance_id,
                                      before.vendor_scope_id),
             "site", before.site_id, reason=reason, decided_by=who, now=now,
             expires_at=expires_at)
    after = ref(conn, ref_id)
    assert after is not None
    return before, after


def operator_link(conn: sqlite3.Connection, *, site_id: str, vendor: str, instance_id: int,
                  scope_id: str, operator_id: "int | str", now: str, reason: Optional[str] = None,
                  rule_id: str = "op", evidence: Optional[dict[str, Any]] = None) -> int:
    """A human's own ref (mapping a UniFi site, asserting a profile's site):
    `confirmed` from the start."""
    who = f"operator:{int(operator_id)}" if isinstance(operator_id, int) else str(operator_id)
    inputs = _sha(site_id, vendor, instance_id, scope_id, "confirmed", rule_id)
    conn.execute(
        "UPDATE site_vendor_ref SET state = 'retired', valid_to = ?, decided_by = ?, "
        " decided_at = ?, reason = 'superseded by an operator decision' "
        "WHERE vendor = ? AND adapter_instance_id = ? AND vendor_scope_id = ? "
        " AND state IN ('auto','suggested','confirmed') AND valid_to IS NULL",
        (now, who, now, vendor, int(instance_id), scope_id))
    cur = conn.execute(
        "INSERT INTO site_vendor_ref (site_id, vendor, adapter_instance_id, vendor_scope_id, "
        " state, score, rule_id, rule_version, evidence, inputs_sha256, valid_from, decided_by, "
        " decided_at, reason, created_at) "
        "VALUES (?, ?, ?, ?, 'confirmed', ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
        (site_id, vendor, int(instance_id), scope_id, CONFIRMED_SCORE, rule_id,
         json.dumps(evidence or {}, sort_keys=True), inputs, now, who, now, reason, now))
    return int(cur.lastrowid)


def retire_scope(conn: sqlite3.Connection, *, vendor: str, instance_id: int, scope_id: str,
                 now: str, reason: str, by: str = OPERATOR_MAPPING) -> int:
    """The scope is no longer this tenant's (unmapped, moved): every open ref
    ends (`retired`, valid_to = now) — an operator action (the mapping)."""
    return conn.execute(
        "UPDATE site_vendor_ref SET state = 'retired', valid_to = ?, decided_by = ?, "
        " decided_at = ?, reason = ? WHERE vendor = ? AND adapter_instance_id = ? "
        " AND vendor_scope_id = ? AND valid_to IS NULL AND state <> 'rejected'",
        (now, by, now, reason[:500], vendor, int(instance_id), scope_id)).rowcount


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------

# What makes a conflict's evidence MATERIALLY different, per kind: a closed
# (resolved) conflict reopens only when these change — never because the
# same condition was seen again (the old behaviour reopened a Resolve within
# a minute and counted every pass as a change).
MATERIAL: dict[str, tuple[str, ...]] = {
    "routing": ("profile_id", "egress"),
    "site_conflict": ("policy_site", "located_site"),
    "operator_decision": ("rule", "wanted_site", "wanted_state"),
    "device_link": ("wanted", "rule"),
}
# An open conflict seen again with the same detail refreshes last_seen / hits
# at most this often (no write per pass).
SEEN_REFRESH_S = 3600


def material(kind: str, detail: dict[str, Any]) -> str:
    keys = MATERIAL.get(kind)
    basis = {k: detail.get(k) for k in keys} if keys else detail
    return json.dumps(basis, sort_keys=True, separators=(",", ":"), default=str)


def observe_conflict(conn: sqlite3.Connection, kind: str, subject: str, detail: dict[str, Any],
                     now: str) -> tuple[int, str]:
    """A rule saw the condition behind a conflict. Returns (id, outcome):
      'opened'    new — a Conflicts card (+ one notice)
      'reopened'  it was closed (an operator resolved it) and its evidence
                  MATERIALLY changed since (`material`): open again, notified
                  again
      'open'      still open (detail / last_seen refreshed only when the
                  detail changed or once an hour)
      'closed'    closed and nothing material changed: stays closed, nothing
                  written. A row closed without a recorded basis (an older
                  build, a direct edit) adopts the evidence of now."""
    row = conn.execute("SELECT * FROM link_conflict WHERE kind = ? AND subject = ?",
                       (kind, subject)).fetchone()
    text = json.dumps(detail, sort_keys=True, separators=(",", ":"))[:4000]
    if row is None:
        cur = conn.execute(
            "INSERT INTO link_conflict (kind, subject, detail, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)", (kind, subject, text, now, now))
        return int(cur.lastrowid), "opened"
    cid = int(row["id"])
    if row["resolved_at"] is None:
        stale = not row["last_seen"] or row["last_seen"] < nz.shift(now, -SEEN_REFRESH_S)
        if row["detail"] != text or stale:
            conn.execute("UPDATE link_conflict SET detail = ?, last_seen = ?, hits = hits + 1 "
                         "WHERE id = ?", (text, now, cid))
        return cid, "open"
    basis = material(kind, detail)
    if row["basis"] is None:
        conn.execute("UPDATE link_conflict SET basis = ? WHERE id = ?", (basis, cid))
        return cid, "closed"
    if row["basis"] == basis or row["resolution"] == "accepted":
        return cid, "closed"
    reopen(conn, cid, detail=text, now=now)
    return cid, "reopened"


def reopen(conn: sqlite3.Connection, conflict_id: int, *, now: str,
           detail: Optional[str] = None, notify: bool = True) -> None:
    conn.execute(
        "UPDATE link_conflict SET detail = COALESCE(?, detail), last_seen = ?, hits = hits + 1, "
        " resolved_at = NULL, resolved_by = NULL, resolution = NULL, basis = NULL, "
        " cleared_at = NULL, notified = ? WHERE id = ?",
        (detail, now, 0 if notify else 1, int(conflict_id)))


def close_conflict(conn: sqlite3.Connection, conflict_id: int, *, resolution: str, by: str,
                   now: str) -> int:
    """An operator closes an open conflict: 'resolved' (it stays closed until
    its evidence materially changes) or 'accepted' (expected — the caller
    suppresses the rule for its subject)."""
    assert resolution in ("resolved", "accepted"), resolution
    row = conn.execute("SELECT kind, detail FROM link_conflict WHERE id = ? AND resolved_at IS "
                       "NULL", (int(conflict_id),)).fetchone()
    if row is None:
        return 0
    try:
        detail = json.loads(row["detail"] or "{}")
    except ValueError:
        detail = {}
    return conn.execute(
        "UPDATE link_conflict SET resolved_at = ?, resolved_by = ?, resolution = ?, basis = ?, "
        " cleared_at = NULL WHERE id = ? AND resolved_at IS NULL",
        (now, by, resolution, material(row["kind"], detail if isinstance(detail, dict) else {}),
         int(conflict_id))).rowcount


def record_conflict(conn: sqlite3.Connection, kind: str, subject: str, detail: dict[str, Any],
                    now: str) -> int:
    return observe_conflict(conn, kind, subject, detail, now)[0]


def open_conflicts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM link_conflict WHERE resolved_at IS NULL ORDER BY id").fetchall()
