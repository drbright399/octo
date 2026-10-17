"""Entity resolution — the alert panel's "Where / Device / Why?", the review
queue ("Links to review"), operator decisions, and the per-tenant switch.

  GET  /api/v1/entity/{slug}/status                          analyst+
  GET  /api/v1/entity/{slug}/events/{event_id}/resolution    analyst+
  POST /api/v1/entity/{slug}/events/{event_id}/resolve       analyst+, audited
  GET  /api/v1/entity/{slug}/sites                           analyst+
  GET  /api/v1/entity/{slug}/review                          analyst+
  POST /api/v1/entity/{slug}/links/{kind}/{id}/confirm       analyst+, audited
  POST /api/v1/entity/{slug}/links/{kind}/{id}/reject        analyst+, reason, audited
  POST /api/v1/entity/{slug}/conflicts/{id}/resolve          analyst+, reason, audited
                                                             (stays resolved until its
                                                             evidence materially changes)
  POST /api/v1/entity/{slug}/conflicts/{id}/accept           analyst+, reason, audited
                                                             (routing: "expected" — a
                                                             branch office without UniFi;
                                                             suppresses the check)
  POST /api/v1/entity/{slug}/conflicts/{id}/reopen           analyst+, reason, audited
                                                             (stop accepting it)
  POST /api/v1/entity/{slug}/sites                           admin+, audited (a site
                                                             without UniFi)
  POST /api/v1/entity/{slug}/sites/{site_id}                 admin+, audited (rename
                                                             a site: two offices of
                                                             one client told apart)
  POST /api/v1/entity/{slug}/sites/{site_id}/egress          admin+, audited (an
                                                             asserted public address)
  PUT  /api/v1/entity/{slug}/mode                            admin+, audited (off |
                                                             shadow | on)

Every route takes ONE tenant slug, checked against the caller's scope (a
tenant outside it answers the same 404 as one that does not exist — no
oracle), and reads / writes only that tenant's entities.db. A tenant whose
file predates 040 (or is empty) answers "unresolved", never a 500. Shadow:
answers are computed and stored but shown to nobody below admin — neither the
stored answer (GET) nor one computed on request (POST /resolve). An alert of
a kind entity resolution never reads answers `not_applicable` (the panel
hides itself). Every operator decision and the switch are AUDITED BEFORE
they are written (an audit failure leaves nothing changed).
Operator decisions are `operator:<id>` rows — the database refuses any rule
that would change them (operator wins). Device names are shown unmasked
(Rick, 2026-10-01); no route returns another tenant's anything.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import resolve_caller_scope, session_at_least
from apps.octo.auth import audit, sessions
from apps.octo.db import connect
from apps.octo.entity import explain, intervals, sites, switch
from apps.octo.entity import normalize as nz
from apps.octo.entity import ocsf as entity_ocsf
from apps.octo.entity import resolver as rv
from apps.octo.entity.db import TenantDB

router = APIRouter(prefix="/entity", tags=["entity"])

session_analyst_plus = session_at_least("analyst")
session_admin_plus = session_at_least("admin")
_NOT_YOURS = "no such tenant in your scope"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tenant(caller: sessions.SessionInfo, slug: str) -> TenantDB:
    try:
        paths.validate_slug(slug)
    except ValueError:
        raise APIError("NOT_FOUND", _NOT_YOURS) from None
    scope = resolve_caller_scope(caller.operator_id)
    if scope != ["*"] and slug not in scope:
        raise APIError("NOT_FOUND", _NOT_YOURS)
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        row = reg.execute("SELECT status FROM clients WHERE slug = ?", (slug,)).fetchone()
    finally:
        reg.close()
    if row is None:
        raise APIError("NOT_FOUND", _NOT_YOURS)
    return TenantDB.for_tenant(slug)


def _audit(caller: sessions.SessionInfo, slug: str, action: str, target_kind: str,
           target_id: str, before: Any, after: Any, reason: Optional[str]) -> None:
    g = connect(paths.global_audit_db_path())
    try:
        audit.append(g, audit.AuditEntry(
            actor=str(caller.operator_id), actor_kind="human", action=action,
            target_kind=target_kind, target_id=target_id, client_slug=slug,
            before_state=before, after_state=after, reason=reason,
            request_id=str(uuid.uuid4())))
    finally:
        g.close()


# ---------------------------------------------------------------------------
# Status and the alert panel
# ---------------------------------------------------------------------------

class StatusOut(BaseModel):
    slug: str
    mode: str
    resolved: bool
    sites: int = 0
    open_leases: int = 0
    resolutions: int = 0
    to_review: int = 0
    conflicts: int = 0
    watermarks: list[dict[str, Any]] = Field(default_factory=list)


@router.get("/{slug}/status", response_model=StatusOut)
def get_status(response: Response, slug: str = Path(...),
               caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> StatusOut:
    response.headers["Cache-Control"] = "no-store"
    tdb = _tenant(caller, slug)
    mode = switch.mode(slug, fresh=True)
    with tdb.read() as conn:
        if conn is None:
            return StatusOut(slug=slug, mode=mode, resolved=False)
        q = lambda sql: int(conn.execute(sql).fetchone()[0])  # noqa: E731
        return StatusOut(
            slug=slug, mode=mode, resolved=True,
            sites=q("SELECT COUNT(*) FROM site WHERE status = 'active'"),
            open_leases=q("SELECT COUNT(*) FROM lk_ip_lease WHERE valid_to IS NULL"),
            resolutions=q("SELECT COUNT(*) FROM resolution WHERE status <> 'superseded'"),
            to_review=q("SELECT COUNT(*) FROM site_vendor_ref WHERE state = 'suggested' AND "
                        "valid_to IS NULL") + q("SELECT COUNT(*) FROM device_link WHERE state = "
                                                "'suggested' AND valid_to IS NULL"),
            conflicts=q("SELECT COUNT(*) FROM link_conflict WHERE resolved_at IS NULL"),
            watermarks=[dict(r) for r in conn.execute(
                "SELECT source, scope, last_ok_at, last_attempt_at, last_error FROM lk_watermark "
                "ORDER BY source, scope").fetchall()],
        )


class ResolutionOut(BaseModel):
    slug: str
    event_id: int
    mode: str
    visible: bool
    resolved: bool
    reason: Optional[str] = None
    status: Optional[str] = None
    at: Optional[str] = None
    where: Optional[dict[str, Any]] = None
    device: Optional[dict[str, Any]] = None
    why: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    candidates_aged_out: bool = False
    review: list[dict[str, Any]] = Field(default_factory=list)
    enrichment: Optional[dict[str, Any]] = None
    resolver_version: Optional[str] = None
    created_at: Optional[str] = None


def _review_for(conn: sqlite3.Connection, row: sqlite3.Row) -> list[dict[str, Any]]:
    """The links on this answer an operator can settle from the alert: a
    suggested ref of the site (one click)."""
    if not row["site_id"]:
        return []
    out = []
    for r in conn.execute("SELECT * FROM site_vendor_ref WHERE site_id = ? AND state IN "
                          "('suggested','auto') AND valid_to IS NULL ORDER BY id",
                          (row["site_id"],)).fetchall():
        out.append({"kind": "site", "id": int(r["id"]), "vendor": r["vendor"],
                    "scope": r["vendor_scope_id"], "state": r["state"], "rule": r["rule_id"],
                    "score": int(r["score"])})
    return out


def _resolution_out(slug: str, event_id: int, mode: str, row: Optional[sqlite3.Row],
                    conn: Optional[sqlite3.Connection], show: bool) -> ResolutionOut:
    if row is None:
        return ResolutionOut(slug=slug, event_id=event_id, mode=mode, visible=show,
                             resolved=False,
                             reason="not resolved yet" if mode != "off" else
                             "entity resolution is off for this client")
    data = dict(row)
    ex = explain.explain(data, conn)
    return ResolutionOut(
        slug=slug, event_id=event_id, mode=mode, visible=show, resolved=True,
        status=data["status"], at=data["at"], where=ex["where"], device=ex["device"],
        why=ex["why"], flags=ex["flags"], candidates=ex["candidates"],
        candidates_aged_out=ex["candidates_aged_out"],
        review=_review_for(conn, row) if conn is not None else [],
        enrichment=entity_ocsf.enrichment(data), resolver_version=data["resolver_version"],
        created_at=data["created_at"])


def _shown(caller: sessions.SessionInfo, mode: str, include_shadow: bool = True) -> bool:
    """On: shown. Shadow: shown to admins (and above) only — when they ask.
    Off: never."""
    if mode == "on":
        return True
    if mode == "shadow" and include_shadow:
        from apps.octo.api.role_gates import ROLE_TIER, operator_max_tier

        return operator_max_tier(caller.operator_id) >= ROLE_TIER["admin"]
    return False


def _hidden(slug: str, event_id: int, mode: str, resolved: bool) -> ResolutionOut:
    return ResolutionOut(slug=slug, event_id=event_id, mode=mode, visible=False,
                         resolved=resolved,
                         reason="shadow mode: computed, not shown" if mode == "shadow"
                         else "entity resolution is off for this client")


def _applicable(slug: str, event_id: int) -> Optional[bool]:
    """Whether the stored event is a kind entity resolution reads (a NextDNS
    security block, a UniFi IPS alert). None: no such event."""
    path = paths.client_dir(slug) / "events.db"
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute("SELECT source, event_type FROM events WHERE id = ?",
                           (int(event_id),)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    return (str(row[0]), str(row[1])) in RESOLVED_KINDS


# The (source, event_type) pairs entity resolution reads (`resolver.subject_of`).
RESOLVED_KINDS = frozenset({("nextdns", "nextdns.security_block"), ("unifi", "unifi.ips_threat")})
NOT_APPLICABLE = "not_applicable"


@router.get("/{slug}/events/{event_id}/resolution", response_model=ResolutionOut)
def get_resolution(response: Response, slug: str = Path(...), event_id: int = Path(..., ge=1),
                   include_shadow: bool = False,
                   caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> ResolutionOut:
    """The stored answer for one alert (no vendor call, no write). In shadow
    the panel is told not to show it (an admin may ask with include_shadow).
    An alert of a kind entity resolution never reads: `not_applicable`, not
    shown (the panel hides itself)."""
    response.headers["Cache-Control"] = "no-store"
    tdb = _tenant(caller, slug)
    mode = switch.mode(slug, fresh=True)
    if _applicable(slug, event_id) is False:
        return ResolutionOut(slug=slug, event_id=event_id, mode=mode, visible=False,
                             resolved=False, reason=NOT_APPLICABLE)
    show = _shown(caller, mode, include_shadow)
    with tdb.read() as conn:
        if conn is None:
            return ResolutionOut(slug=slug, event_id=event_id, mode=mode, visible=False,
                                 resolved=False, reason="unresolved")
        row = rv.current(conn, event_id)
        if not show:
            return _hidden(slug, event_id, mode, row is not None)
        return _resolution_out(slug, event_id, mode, row, conn, show)


@router.post("/{slug}/events/{event_id}/resolve", response_model=ResolutionOut)
def post_resolve(response: Response, slug: str = Path(...), event_id: int = Path(..., ge=1),
                 caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> ResolutionOut:
    """Resolve one alert now (the worker does it within a minute anyway).
    Audited (before it runs); refused while the switch is off. In shadow the
    answer is computed and stored, and shown only to an admin — the same
    shadow contract as GET."""
    response.headers["Cache-Control"] = "no-store"
    tdb = _tenant(caller, slug)
    mode = switch.mode(slug, fresh=True)
    if mode == "off":
        raise APIError("CONFLICT", "entity resolution is off for this client")
    if _applicable(slug, event_id) is not True:
        raise APIError("NOT_FOUND", "no alert of a kind entity resolution reads")
    _audit(caller, slug, "entity_resolve", "event", str(event_id), None,
           {"requested": True, "mode": mode}, "resolve on request")
    row = rv.Resolver.for_tenant(slug).resolve_event(
        event_id, mode="sweep", created_by=f"operator:{caller.operator_id}")
    if row is None:
        raise APIError("NOT_FOUND", "no alert of a kind entity resolution reads")
    show = _shown(caller, mode)
    with tdb.read() as conn:
        current = rv.current(conn, event_id) if conn is not None else None
        if not show:
            return _hidden(slug, event_id, mode, current is not None)
        return _resolution_out(slug, event_id, mode, current, conn, show)


# ---------------------------------------------------------------------------
# Sites, the review queue
# ---------------------------------------------------------------------------

@router.get("/{slug}/sites")
def get_sites(response: Response, slug: str = Path(...),
              caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    tdb = _tenant(caller, slug)
    with tdb.read() as conn:
        if conn is None:
            return {"slug": slug, "resolved": False, "sites": []}
        out = []
        for s in sites.active_sites(conn):
            out.append({
                "site_id": s["site_id"], "label": s["label"], "anchor": s["anchor"],
                "tz": s["tz"], "geo_text": s["geo_text"],
                "refs": [r.as_dict() for r in sites.refs_of_site(conn, s["site_id"])],
                "egress": [dict(e) for e in conn.execute(
                    "SELECT id, addr, wan, nat_kind, source, valid_from, valid_to, flags "
                    "FROM lk_site_egress WHERE site_id = ? AND valid_to IS NULL ORDER BY id",
                    (s["site_id"],)).fetchall()],
            })
        return {"slug": slug, "resolved": True, "sites": out}


@router.get("/{slug}/review")
def get_review(response: Response, slug: str = Path(...),
               caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> dict[str, Any]:
    """"Links to review": Sites (profile → site suggestions), Name matches
    (names only — never proof), Devices (NextDNS app ↔ Datto), Conflicts."""
    response.headers["Cache-Control"] = "no-store"
    tdb = _tenant(caller, slug)
    with tdb.read() as conn:
        if conn is None:
            return {"slug": slug, "resolved": False, "sites": [], "names": [], "devices": [],
                    "conflicts": []}
        site_info = {r["site_id"]: r for r in conn.execute(
            "SELECT site_id, label, geo_text FROM site")}
        vendor_labels = _vendor_labels(slug)
        site_rows, name_rows = [], []
        for r in conn.execute("SELECT * FROM site_vendor_ref WHERE state IN ('suggested','auto') "
                              "AND valid_to IS NULL AND vendor <> 'unifi' ORDER BY id").fetchall():
            item = sites.Ref.of(r).as_dict()
            info = site_info.get(r["site_id"])
            item["site_label"] = info["label"] if info is not None else None
            item["site_location"] = info["geo_text"] if info is not None else None
            item["vendor_label"] = vendor_labels.get((r["vendor"], r["vendor_scope_id"]))
            (name_rows if r["rule_id"].startswith("N-") else site_rows).append(item)
        devices = []
        for r in conn.execute("SELECT * FROM device_link WHERE state IN ('suggested','auto',"
                              "'confirmed') AND valid_to IS NULL ORDER BY id").fetchall():
            pid, _, did = r["a_value"].partition(":")
            inst, _, uid = r["b_value"].partition(":")
            nd = conn.execute("SELECT name, model, client, last_seen FROM ndns_device WHERE "
                              "profile_id = ? AND device_id = ?", (pid, did)).fetchone()
            dd = conn.execute("SELECT hostname, online, last_seen, os FROM inv_device WHERE "
                              "adapter_instance_id = ? AND device_uid = ?",
                              (int(inst or 0), uid)).fetchone()
            watch = conn.execute("SELECT state, since, alert_event_id FROM device_watch WHERE "
                                 "link_id = ?", (r["id"],)).fetchone()
            devices.append({"id": int(r["id"]), "state": r["state"], "rule": r["rule_id"],
                            "score": int(r["score"]), "evidence": json.loads(r["evidence"] or "{}"),
                            "nextdns": dict(nd) if nd else None, "datto": dict(dd) if dd else None,
                            "watch": dict(watch) if watch else None})
        conflicts = [_conflict_out(r) for r in sites.open_conflicts(conn)]
        accepted = [_conflict_out(r) for r in conn.execute(
            "SELECT * FROM link_conflict WHERE resolution = 'accepted' ORDER BY id").fetchall()]
        return {"slug": slug, "resolved": True, "sites": site_rows, "names": name_rows,
                "devices": devices, "conflicts": conflicts, "accepted": accepted}


def _conflict_out(r: sqlite3.Row) -> dict[str, Any]:
    return {"id": int(r["id"]), "kind": r["kind"], "subject": r["subject"],
            "detail": json.loads(r["detail"] or "{}"), "first_seen": r["first_seen"],
            "last_seen": r["last_seen"], "hits": int(r["hits"]),
            "resolution": r["resolution"], "resolved_at": r["resolved_at"],
            "resolved_by": r["resolved_by"]}


def _vendor_labels(slug: str) -> dict[tuple[str, str], str]:
    """(vendor, scope) → the vendor's own name for it (a NextDNS profile's
    name, from this tenant's mappings) — a review card names the profile,
    never only its id."""
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return {}
    try:
        rows = reg.execute(
            "SELECT i.vendor_slug, m.vendor_tenant_id, m.vendor_tenant_label "
            "FROM adapter_tenant_map m JOIN adapter_instances i ON i.id = m.adapter_instance_id "
            "WHERE m.octo_client_slug = ?", (slug,)).fetchall()
    except sqlite3.Error:
        return {}
    finally:
        reg.close()
    return {(str(r[0]), str(r[1])): str(r[2]) for r in rows if r[2]}


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(default=None, max_length=500)


class RejectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=500)
    expires_days: Optional[int] = Field(default=None, ge=1, le=3650)


def _link_row(conn: sqlite3.Connection, kind: str, link_id: int) -> sqlite3.Row:
    table = "site_vendor_ref" if kind == "site" else "device_link"
    row = conn.execute(f"SELECT * FROM {table} WHERE id = ? AND valid_to IS NULL",
                       (link_id,)).fetchone()
    if row is None:
        raise APIError("NOT_FOUND", "no open link with that id")
    return row


@router.post("/{slug}/links/{kind}/{link_id}/confirm")
def post_confirm(body: DecisionIn, slug: str = Path(...),
                 kind: Literal["site", "device"] = Path(...), link_id: int = Path(..., ge=1),
                 caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> dict[str, Any]:
    tdb = _tenant(caller, slug)
    now = nz.iso(_now())
    before = _link_before(tdb, kind, link_id)
    _audit(caller, slug, "entity_link_confirm", f"{kind}_link", str(link_id),
           {"state": before["state"], "rule": before["rule_id"]},
           {"state": "confirmed"}, body.reason)
    with tdb.write() as conn:
        before = dict(_link_row(conn, kind, link_id))
        if kind == "site":
            _b, after = sites.operator_confirm(conn, link_id, operator_id=caller.operator_id,
                                               now=now, reason=body.reason)
            after_d = after.as_dict()
        else:
            who = f"operator:{caller.operator_id}"
            conn.execute("UPDATE device_link SET state = 'confirmed', decided_by = ?, "
                         "decided_at = ?, reason = ? WHERE id = ?",
                         (who, now, body.reason, link_id))
            # The same NextDNS device (or Datto device) linked elsewhere by a
            # rule: retired (the operator decided).
            conn.execute("UPDATE device_link SET state = 'retired', valid_to = ?, decided_by = ?, "
                         "decided_at = ? WHERE id <> ? AND valid_to IS NULL AND state IN "
                         "('auto','suggested') AND (a_value = ? OR b_value = ?)",
                         (now, who, now, link_id, before["a_value"], before["b_value"]))
            after_d = dict(conn.execute("SELECT * FROM device_link WHERE id = ?",
                                        (link_id,)).fetchone())
        _mark_dependants_stale(conn, kind, link_id)
    return {"ok": True, "link": after_d}


@router.post("/{slug}/links/{kind}/{link_id}/reject")
def post_reject(body: RejectIn, slug: str = Path(...),
                kind: Literal["site", "device"] = Path(...), link_id: int = Path(..., ge=1),
                caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> dict[str, Any]:
    """Reject a suggestion, or revoke an auto link: `rejected` + a
    suppression of the pair (the rule stops suggesting it; once expired it
    may only come back as a suggestion)."""
    tdb = _tenant(caller, slug)
    now = _now()
    expires = None
    if body.expires_days:
        from datetime import timedelta

        expires = nz.iso(now + timedelta(days=body.expires_days))
    before = _link_before(tdb, kind, link_id)
    _audit(caller, slug, "entity_link_reject", f"{kind}_link", str(link_id),
           {"state": before["state"], "rule": before["rule_id"]},
           {"state": "rejected", "expires_at": expires}, body.reason)
    with tdb.write() as conn:
        before = dict(_link_row(conn, kind, link_id))
        if kind == "site":
            _b, after = sites.operator_reject(conn, link_id, operator_id=caller.operator_id,
                                              now=nz.iso(now), reason=body.reason,
                                              expires_at=expires)
            after_d = after.as_dict()
        else:
            who = f"operator:{caller.operator_id}"
            conn.execute("UPDATE device_link SET state = 'rejected', decided_by = ?, "
                         "decided_at = ?, reason = ? WHERE id = ?",
                         (who, nz.iso(now), body.reason, link_id))
            sites.suppress(conn, "nextdns_device", before["a_value"], "datto_device",
                           before["b_value"], reason=body.reason, decided_by=who,
                           now=nz.iso(now), expires_at=expires)
            after_d = dict(conn.execute("SELECT * FROM device_link WHERE id = ?",
                                        (link_id,)).fetchone())
        _mark_dependants_stale(conn, kind, link_id)
    return {"ok": True, "link": after_d}


def _link_before(tdb: TenantDB, kind: str, link_id: int) -> dict[str, Any]:
    """The open link as it is now (read-only) — for the audit row written
    BEFORE the change."""
    with tdb.read() as conn:
        if conn is None:
            raise APIError("NOT_FOUND", "no open link with that id")
        return dict(_link_row(conn, kind, link_id))


def _mark_dependants_stale(conn: sqlite3.Connection, kind: str, link_id: int) -> None:
    """Answers that relied on a link an operator just changed are `stale`;
    the worker redoes them (closed incidents keep their answer)."""
    if kind != "site":
        return
    conn.execute(
        "UPDATE resolution SET status = 'stale' WHERE status IN ('final','provisional') AND "
        "res_id IN (SELECT res_id FROM resolution_dep WHERE dep_kind = 'ref' AND dep_id = ?)",
        (str(link_id),))


def _open_conflict(tdb: TenantDB, conflict_id: int) -> sqlite3.Row:
    with tdb.read() as conn:
        row = None if conn is None else conn.execute(
            "SELECT * FROM link_conflict WHERE id = ? AND resolved_at IS NULL",
            (conflict_id,)).fetchone()
    if row is None:
        raise APIError("NOT_FOUND", "no open conflict with that id")
    return row


@router.post("/{slug}/conflicts/{conflict_id}/resolve")
def post_resolve_conflict(body: RejectIn, slug: str = Path(...),
                          conflict_id: int = Path(..., ge=1),
                          caller: sessions.SessionInfo = Depends(session_analyst_plus)
                          ) -> dict[str, Any]:
    """Looked at: it stays resolved until its evidence MATERIALLY changes (a
    routing conflict: a new egress, or the condition coming back after days
    away) — never because the same condition is seen again."""
    tdb = _tenant(caller, slug)
    now = nz.iso(_now())
    _open_conflict(tdb, conflict_id)
    _audit(caller, slug, "entity_conflict_resolve", "link_conflict", str(conflict_id), None,
           {"resolved_at": now, "resolution": "resolved"}, body.reason)
    with tdb.write() as conn:
        n = sites.close_conflict(conn, conflict_id, resolution="resolved",
                                 by=f"operator:{caller.operator_id}", now=now)
    if not n:
        raise APIError("NOT_FOUND", "no open conflict with that id")
    return {"ok": True}


@router.post("/{slug}/conflicts/{conflict_id}/accept")
def post_accept_conflict(body: RejectIn, slug: str = Path(...),
                         conflict_id: int = Path(..., ge=1),
                         caller: sessions.SessionInfo = Depends(session_analyst_plus)
                         ) -> dict[str, Any]:
    """"Accept as expected" — a routing conflict only: the profile's traffic
    legitimately comes from elsewhere (a branch office without UniFi, a
    second site, roaming laptops). The check is suppressed for that profile
    (for `expires_days`, or until reopened)."""
    from datetime import timedelta

    from apps.octo.entity import linkrules

    tdb = _tenant(caller, slug)
    now = _now()
    row = _open_conflict(tdb, conflict_id)
    if row["kind"] != "routing":
        raise APIError("CONFLICT", "only a routing conflict can be accepted as expected")
    expires = nz.iso(now + timedelta(days=body.expires_days)) if body.expires_days else None
    _audit(caller, slug, "entity_conflict_accept", "link_conflict", str(conflict_id), None,
           {"resolution": "accepted", "subject": row["subject"], "expires_at": expires},
           body.reason)
    who = f"operator:{caller.operator_id}"
    with tdb.write() as conn:
        n = sites.close_conflict(conn, conflict_id, resolution="accepted", by=who,
                                 now=nz.iso(now))
        if n:
            sites.suppress(conn, "routing", row["subject"], *linkrules.ROUTING_EXPECTED,
                           reason=body.reason, decided_by=who, now=nz.iso(now),
                           rule_id="routing", expires_at=expires)
    if not n:
        raise APIError("NOT_FOUND", "no open conflict with that id")
    return {"ok": True, "expires_at": expires}


@router.post("/{slug}/conflicts/{conflict_id}/reopen")
def post_reopen_conflict(body: RejectIn, slug: str = Path(...),
                         conflict_id: int = Path(..., ge=1),
                         caller: sessions.SessionInfo = Depends(session_analyst_plus)
                         ) -> dict[str, Any]:
    """Stop accepting a conflict: its suppression ends now and the card is
    open again (no new notice — an operator did it)."""
    from apps.octo.entity import linkrules

    tdb = _tenant(caller, slug)
    now = nz.iso(_now())
    with tdb.read() as conn:
        row = None if conn is None else conn.execute(
            "SELECT * FROM link_conflict WHERE id = ? AND resolution = 'accepted'",
            (conflict_id,)).fetchone()
    if row is None:
        raise APIError("NOT_FOUND", "no accepted conflict with that id")
    _audit(caller, slug, "entity_conflict_reopen", "link_conflict", str(conflict_id),
           {"resolution": "accepted"}, {"resolution": None}, body.reason)
    with tdb.write() as conn:
        conn.execute(
            "UPDATE link_suppression SET expires_at = ? WHERE a_type = 'routing' AND a_value = ? "
            "AND b_type = ? AND b_value = ? AND (expires_at IS NULL OR expires_at > ?)",
            (now, row["subject"], *linkrules.ROUTING_EXPECTED, now))
        sites.reopen(conn, conflict_id, now=now, notify=False)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin: a site without UniFi, an asserted egress, the switch
# ---------------------------------------------------------------------------

class SiteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)
    anchor: Literal["datto", "nextdns", "operator"]
    vendor: Optional[Literal["datto", "nextdns"]] = None
    vendor_scope_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=500)


@router.post("/{slug}/sites")
def post_site(body: SiteIn, slug: str = Path(...),
              caller: sessions.SessionInfo = Depends(session_admin_plus)) -> dict[str, Any]:
    """A site for a client WITHOUT UniFi (Rick: allowed as a fallback),
    anchored on its Datto site / NextDNS profile; the vendor scope, when
    given, must be mapped to THIS tenant."""
    tdb = _tenant(caller, slug)
    instance_id = 0
    if body.vendor and body.vendor_scope_id:
        from apps.octo.entity.feeders.mapping import mapped

        m = mapped(body.vendor, body.vendor_scope_id, slug)
        if m is None:
            raise APIError("VALIDATION_FAILED",
                           f"that {body.vendor} scope is not mapped to this client")
        instance_id = m.instance_id
    now = nz.iso(_now())
    from apps.octo.entity import ids

    site_id = ids.new("st")
    _audit(caller, slug, "entity_site_create", "site", site_id, None,
           {"label": body.label, "anchor": body.anchor, "vendor": body.vendor,
            "vendor_scope_id": body.vendor_scope_id}, body.reason)
    with tdb.write() as conn:
        sites.create_site(conn, label=body.label, anchor=body.anchor, now=now,
                          created_by=f"operator:{caller.operator_id}", site_id=site_id)
        ref_id = None
        if body.vendor and body.vendor_scope_id:
            ref_id = sites.operator_link(conn, site_id=site_id, vendor=body.vendor,
                                         instance_id=instance_id,
                                         scope_id=body.vendor_scope_id,
                                         operator_id=caller.operator_id, now=now,
                                         reason=body.reason)
    return {"ok": True, "site_id": site_id, "ref_id": ref_id}


class SiteRenameIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=3, max_length=500)


@router.post("/{slug}/sites/{site_id}")
def post_site_rename(body: SiteRenameIn, slug: str = Path(...),
                     site_id: str = Path(..., max_length=40),
                     caller: sessions.SessionInfo = Depends(session_admin_plus)
                     ) -> dict[str, Any]:
    """Name a site (UniFi calls most single-site consoles' site "Default";
    two offices of one client must be told apart). The vendor's name no
    longer replaces it. Audited before it is written."""
    tdb = _tenant(caller, slug)
    label = " ".join(body.label.split())
    if not label:
        raise APIError("VALIDATION_FAILED", "a name is required")
    with tdb.read() as conn:
        row = sites.site(conn, site_id) if conn is not None else None
    if row is None:
        raise APIError("NOT_FOUND", "no such site")
    _audit(caller, slug, "entity_site_rename", "site", site_id, {"label": row["label"]},
           {"label": label}, body.reason)
    with tdb.write() as conn:
        after = sites.rename_site(conn, site_id, label=label, operator_id=caller.operator_id,
                                  now=nz.iso(_now()))
    if after is None:
        raise APIError("NOT_FOUND", "no such site")
    return {"ok": True, "site_id": site_id, "label": after["label"]}


class EgressIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    addr: str = Field(min_length=2, max_length=45)
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    reason: str = Field(min_length=3, max_length=500)


def _shared_external(request: Request, slug: str, addr: str) -> bool:
    """Whether `addr` is the WAN address of a UniFi console site that is NOT
    this tenant's, in the running UniFi poller's last fleet snapshot (in
    memory — the design's S-1 check for operator-asserted egress). ONE bit
    comes out; nothing about the other network is kept."""
    from apps.octo.entity.feeders.mapping import mapped

    manager = getattr(request.app.state, "instance_manager", None)
    if manager is None:
        return False
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
        try:
            ids_ = [int(r[0]) for r in reg.execute(
                "SELECT id FROM adapter_instances WHERE vendor_slug = 'unifi' AND "
                "disabled_at IS NULL ORDER BY id")]
        finally:
            reg.close()
    except (sqlite3.Error, FileNotFoundError):
        return False
    for instance_id in ids_:
        try:
            adapter = manager.running_adapter(instance_id)
            poller = getattr(adapter, "poller", None) if adapter is not None else None
            fleet = poller.fleet_view() if poller is not None else {}
        except Exception:  # noqa: BLE001 — the check is best effort, never a 500
            continue
        for scope, info in (fleet or {}).items():
            wans = info.get("wans") if isinstance(info, dict) else None
            if any(isinstance(w, dict) and nz.ip(str(w.get("external_ip") or "")) == addr
                   for w in (wans or [])) and mapped("unifi", scope, slug) is None:
                return True
    return False


@router.post("/{slug}/sites/{site_id}/egress")
def post_egress(body: EgressIn, request: Request, slug: str = Path(...),
                site_id: str = Path(..., max_length=40),
                caller: sessions.SessionInfo = Depends(session_admin_plus)) -> dict[str, Any]:
    """"This public address is that site's internet connection" — a bounded
    interval, audited before it is written (sites without UniFi). An address
    another UniFi network of the fleet also uses (a shared building, a
    landlord's network, a carrier NAT) is flagged `shared_external`: it never
    corroborates the site's policy (design R.2 S-1, R3.2)."""
    tdb = _tenant(caller, slug)
    addr = nz.ip(body.addr)
    if addr is None or not nz.is_public(addr):
        raise APIError("VALIDATION_FAILED", "a public IPv4 / IPv6 address is required")
    start = nz.ts(body.valid_from) if body.valid_from else nz.iso(_now())
    end = nz.ts(body.valid_to) if body.valid_to else None
    if not start or (body.valid_to and not end) or (end and end <= start):
        raise APIError("VALIDATION_FAILED", "valid_from / valid_to must be times, from before to")
    flags = []
    with tdb.read() as conn:
        if conn is None or sites.site(conn, site_id) is None:
            raise APIError("NOT_FOUND", "no such site")
        # The same address as another site of this tenant: shared (S2 gives a set).
        if conn.execute("SELECT 1 FROM lk_site_egress WHERE addr = ? AND site_id <> ? AND "
                        "valid_to IS NULL", (addr, site_id)).fetchone():
            flags.append("shared_in_tenant")
    if _shared_external(request, slug, addr):
        flags.append("shared_external")
    _audit(caller, slug, "entity_egress_assert", "site", site_id, None,
           {"addr_class": nz.ip_class(addr), "valid_from": start, "valid_to": end,
            "flags": sorted(flags)}, body.reason)
    with tdb.write() as conn:
        row_id = intervals.assert_egress(conn, site_id=site_id, addr=addr, valid_from=start,
                                         valid_to=end, asserted_by=str(caller.operator_id),
                                         reason=body.reason, flags=flags)
    return {"ok": True, "egress_id": row_id, "flags": sorted(flags)}


class ModeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["off", "shadow", "on"]
    reason: str = Field(min_length=3, max_length=500)


@router.put("/{slug}/mode")
def put_mode(body: ModeIn, slug: str = Path(...),
             caller: sessions.SessionInfo = Depends(session_admin_plus)) -> dict[str, Any]:
    _tenant(caller, slug)
    current = switch.mode(slug, fresh=True)
    _audit(caller, slug, "entity_resolution_mode", "client", slug, {"mode": current},
           {"mode": body.mode}, body.reason)
    before = switch.set_mode(slug, body.mode)
    if before is None:
        raise APIError("NOT_FOUND", _NOT_YOURS)
    from apps.octo.entity import worker

    worker.switched(slug, before, body.mode)       # off → on: the sweep starts here
    return {"ok": True, "slug": slug, "mode": body.mode, "before": before}

