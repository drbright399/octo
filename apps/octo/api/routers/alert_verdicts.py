"""Human verdicts on ALERTS (v0.17.2, Rick's decisions A and B, 2026-10-06).

  POST /api/v1/alerts/{slug}/{event_id}/ack        analyst+ (scoped) — ACKNOWLEDGE:
                                                   {note? ≤ 500, repeat_24h?, seen_hits?,
                                                   seen_last? — what the list showed:
                                                   the ack never covers more}
  POST /api/v1/alerts/{slug}/{event_id}/expected   analyst+ (scoped) — THIS IS
                                                   EXPECTED: {reason ≥ 10, review_days
                                                   1..90 (default 90), remote? — a
                                                   network alert only}
  GET  /api/v1/alerts/expected?tenant=&state=       analyst+ (scoped) — Settings →
                                                   Threats: every condition with its
                                                   review date and status
  POST /api/v1/alerts/expected/{id}/revoke          analyst+ (scoped) — {reason}
  POST /api/v1/alerts/{slug}/verdicts/{verdict_id}/recall
                                                   analyst+ (scoped) — RECALL an
                                                   acknowledgement: {reason ≥ 10}
                                                   (v0.17.5; final — acknowledging
                                                   again is a new ack)
  POST /api/v1/alerts/{slug}/verdicts/{verdict_id}/notes
                                                   analyst+ (scoped) — a NOTE under
                                                   an acknowledgement (recalled or
                                                   not): {note 1..500}

ROLES: a viewer (a client user) is 403 on every route here — they never see
the alert list, a verdict or a vendor detail. AUDIT BEFORE WRITE: each
change appends its row to the global audit chain (who, when, what, the note
or reason; client_slug = the tenant) and only then writes the registry; a
write that fails after its row appends `<action>_failed`. An expected
condition created or revoked tells the OTHER admins (it suppresses a
Yellow, like a threat exception — design 6.7).

WHAT THEY CHANGE: the alert's place in the "needs attention" list and its
contribution to the site's Yellow (`apps.octo.verdicts`) — never the event
(it stays stored, whole) and never an incident (Red / Black come only from
incidents; nothing here reads or writes one). EXPECTED is refused for a
NextDNS 'csam' block, an alert an incident rests on, a decoy alert, an
alert that would open a Red / Black, a Datto ransomware / threat detection,
a RocketCyber alert (v0.17.3: by SOURCE, whatever it names — Rick,
2026-10-07: "too vague to just do a sweeping expected tag on") and an alert
that names no device (`verdicts.keys.expected_refusal`); "repeats for 24 h"
for a RocketCyber alert, an alert that names no device and a CSAM lookup
(`verdicts.keys.repeat_refusal`). The revoke route answers the same 404
for a rule that does not exist and one outside the caller's scope.

RECALL / NOTES (v0.17.5; Rick, 2026-10-08 — he acknowledged a client's
alerts, then learned the context and could not go back to add it): both are
rows of `alert_verdict_followup` (append-only, migration 048) on an ACK — the
ack row itself is never touched, its own note never edited. A recalled ack
covers nothing (`verdicts.state`: its alert, the other rows of its vendor
alert and its repeats need attention again and count towards the site's
colour). The same 404 for a verdict that does not exist, one of another
tenant and a tenant outside the caller's scope; 409 for a second recall and
for a recall / note on a label that is not an ack (an expected RULE is
revoked above). The bodies are read leniently — a body the console proxy
sends empty (`{}`), or none at all, gets the plain "required" message, not a
schema error.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.models import AuditReason
from apps.octo.api.role_gates import resolve_caller_scope, session_analyst_plus
from apps.octo.auth import sessions
from apps.octo.db import connect, transaction
from apps.octo.fleet import build, sources
from apps.octo.threat import audit as taudit
from apps.octo.threat import notify
from apps.octo.verdicts import annotate, occurrences
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import TenantVerdicts

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

_SLUG = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


def _reason10(value: str) -> str:
    text = " ".join(value.split())
    if len(text) < vstore.REASON_MIN:
        raise ValueError(f"a reason of at least {vstore.REASON_MIN} characters is required")
    return text


ExpectedReason = Annotated[str, Field(min_length=vstore.REASON_MIN, max_length=500),
                           AfterValidator(_reason10)]


def _note(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = " ".join(value.split())
    return text or None


def _seen_last(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if vstore.parse(value) is None:
        raise ValueError("seen_last is an ISO-8601 time")
    return value


class AckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: Annotated[Optional[str], Field(default=None, max_length=vstore.NOTE_MAX),
                    AfterValidator(_note)] = None
    repeat_24h: bool = False
    # What the analyst SAW (a coalesced row's count and last-seen as the
    # list showed it): the ack covers no more than that — hits that arrived
    # while the form was open re-surface it.
    seen_hits: Optional[int] = Field(default=None, ge=1, le=10**9)
    seen_last: Annotated[Optional[str], Field(default=None, max_length=40),
                         AfterValidator(_seen_last)] = None


class ExpectedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: ExpectedReason
    review_days: int = Field(default=vstore.REVIEW_DEFAULT_DAYS, ge=1,
                             le=vstore.REVIEW_MAX_DAYS)
    remote: Optional[str] = Field(default=None, min_length=2, max_length=253)


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: AuditReason


class RecallIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Checked in the route (plain messages); this bound only stops abuse.
    reason: Optional[str] = Field(default=None, max_length=4000)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: Optional[str] = Field(default=None, max_length=4000)


class FollowUpOut(BaseModel):
    followup_id: int
    verdict_id: int
    event_id: int
    tenant_slug: str
    kind: Literal["note", "recall"]
    at: str


class VerdictOut(BaseModel):
    verdict_id: int
    event_id: int
    tenant_slug: str
    verdict: str
    at: str
    repeat_until: Optional[str] = None
    rule_id: Optional[int] = None


class ExpectedListResponse(BaseModel):
    rows: list[dict[str, Any]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _in_scope(info: sessions.SessionInfo, slug: str) -> bool:
    """Is the tenant active and in the caller's scope."""
    try:
        active = sources.tenants()
    except sqlite3.Error:
        raise APIError("SERVICE_UNAVAILABLE", "the registry could not be read") from None
    scope = resolve_caller_scope(info.operator_id)
    return slug in active and (scope == ["*"] or slug in scope)


def _scoped(info: sessions.SessionInfo, slug: str) -> str:
    """The tenant, if active and in the caller's scope — else the same 404."""
    if not _in_scope(info, slug):
        raise APIError("NOT_FOUND", "no such alert in your scope")
    return slug


def _alert(slug: str, event_id: int) -> dict[str, Any]:
    row = occurrences.event_rows(slug, [event_id]).get(event_id)
    if row is None:
        raise APIError("NOT_FOUND", "no such alert in your scope")
    from apps.octo.threat import store as incident_store

    if row.get("source") == incident_store.EVENT_SOURCE:
        raise APIError("VALIDATION_FAILED", "an incident's own record is not an alert — act on "
                                            "the incident instead")
    return row


def _write(info: sessions.SessionInfo, action: str, slug: str, target: str, fn: Any) -> Any:
    """The registry write the row before it audited; `<action>_failed` when
    it does not happen."""
    try:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                return fn(reg)
        finally:
            reg.close()
    except Exception as exc:
        try:
            taudit.human(info.operator_id, f"{action}_failed", slug, "alert", target,
                         after={"error": type(exc).__name__},
                         reason=f"the recorded {action} was not written: {type(exc).__name__}")
        except Exception:  # noqa: BLE001
            logger.error("[alerts] %s_failed could not be audited", action)
        if isinstance(exc, vstore.FollowUpConflict):
            raise APIError("CONFLICT", str(exc)) from None
        if isinstance(exc, ValueError):
            raise APIError("VALIDATION_FAILED", str(exc)) from None
        raise APIError("SERVICE_UNAVAILABLE", "the verdict could not be written") from None


# ---------------------------------------------------------------------------
# Acknowledge
# ---------------------------------------------------------------------------

def _covered(a: annotate.Annotated, body: AckIn) -> tuple[Optional[int], Optional[str]]:
    """(hits, last-seen) the ack covers. A coalesced row: what the analyst
    SAW (`seen_*`), never more than the row holds now — hits that arrived
    after the list was read re-surface it (an older client that sends
    nothing covers the row as it is now). One event: no count, its own time
    (a later version of the same vendor alert is then known to be newer)."""
    if a.hits is None:
        return None, a.occurrence.last_at or None
    hits = min(body.seen_hits, a.hits) if body.seen_hits else a.hits
    last = a.last_seen
    seen, now_last = vstore.parse(body.seen_last), vstore.parse(a.last_seen)
    if seen is not None and (now_last is None or seen < now_last):
        last = vstore.iso(seen)
    return hits, last


@router.post("/{slug}/{event_id}/ack", response_model=VerdictOut)
def acknowledge(
    body: AckIn,
    slug: str = Path(..., min_length=1, max_length=64, pattern=_SLUG),
    event_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> VerdictOut:
    """The analyst saw it: it leaves "needs attention" and stops counting
    towards its site's Yellow until a NEW occurrence re-surfaces it. The
    event itself is untouched."""
    _scoped(info, slug)
    row = _alert(slug, event_id)
    a = annotate.one(slug, row)
    if body.repeat_24h and a.repeat_refusal:
        raise APIError("VALIDATION_FAILED", a.repeat_refusal)
    now = _now()
    until = now + timedelta(hours=vstore.REPEAT_HOURS) if body.repeat_24h else None
    hits_at, last_seen_at = _covered(a, body)
    target = f"{slug}:{event_id}"
    after = {"event_id": event_id, "source": a.key.source, "device_key": a.key.device_key,
             "signature_key": a.key.signature_key, "alert_ref": a.key.ref,
             "hits_at": hits_at, "last_seen_at": last_seen_at,
             "hits_now": a.hits, "last_seen_now": a.last_seen,
             "repeat_until": vstore.iso(until) if until else None}
    taudit.human(info.operator_id, "alert.ack", slug, "alert", target, after=after,
                 reason=body.note or "acknowledged")
    vid = _write(info, "alert.ack", slug, target, lambda reg: vstore.record(
        reg, slug=slug, event_id=event_id, key=a.key, verdict=vstore.ACK,
        actor=info.operator_id, at=now, note=body.note, hits_at=hits_at,
        last_seen_at=last_seen_at, repeat_until=until))
    build.invalidate()
    return VerdictOut(verdict_id=vid, event_id=event_id, tenant_slug=slug, verdict=vstore.ACK,
                      at=vstore.iso(now), repeat_until=vstore.iso(until) if until else None)


# ---------------------------------------------------------------------------
# Expected
# ---------------------------------------------------------------------------

@router.post("/{slug}/{event_id}/expected", response_model=VerdictOut)
def mark_expected(
    body: ExpectedIn,
    request: Request,
    slug: str = Path(..., min_length=1, max_length=64, pattern=_SLUG),
    event_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> VerdictOut:
    """A known condition: matching alerts are labelled "expected (rule #N)"
    until the review date — grey, not Yellow, still stored."""
    _scoped(info, slug)
    row = _alert(slug, event_id)
    a = annotate.one(slug, row)
    if a.refusal:
        raise APIError("CONFLICT", a.refusal)
    remote = None
    if body.remote is not None:
        if a.key.family != "unifi_ips":
            raise APIError("VALIDATION_FAILED", "a remote is only for a network (IPS) alert")
        try:
            remote = vstore.normalize_remote(body.remote)
        except ValueError as exc:
            raise APIError("VALIDATION_FAILED", str(exc)) from None
    now = _now()
    review = now + timedelta(days=body.review_days)
    title = _title(request, row, a.payload)
    target = f"{slug}:{event_id}"
    taudit.human(info.operator_id, "expected.create", slug, "expected_condition", target,
                 after={"event_id": event_id, "source": a.key.source,
                        "device_key": a.key.device_key, "signature_key": a.key.signature_key,
                        "remote": remote, "review_at": vstore.iso(review), "label": title},
                 reason=body.reason)

    def write(reg: sqlite3.Connection) -> tuple[int, int]:
        rid = vstore.add_expected(reg, slug=slug, key=a.key, remote=remote, label=title,
                                  reason=body.reason, origin_event_id=event_id,
                                  by=info.operator_id, now=now, review_at=review)
        vid = vstore.record(reg, slug=slug, event_id=event_id, key=a.key,
                            verdict=vstore.EXPECTED, actor=info.operator_id, at=now,
                            note=body.reason, hits_at=a.hits, last_seen_at=a.last_seen,
                            rule_id=rid)
        return rid, vid

    rid, vid = _write(info, "expected.create", slug, target, write)
    notify.notify_admins(
        kind="threat_registry", slug=slug, exclude=info.operator_id,
        title=f"Expected condition #{rid} at {slug} (review {vstore.iso(review)[:10]})",
        body=f"Operator #{info.operator_id} marked \"{title}\" expected"
             f"{f' from {remote}' if remote else ''} — matching alerts no longer turn the "
             f"site yellow until {vstore.iso(review)[:10]}: {body.reason}",
        request_id=f"expected:{rid}")
    build.invalidate()
    return VerdictOut(verdict_id=vid, event_id=event_id, tenant_slug=slug,
                      verdict=vstore.EXPECTED, at=vstore.iso(now), rule_id=rid)


def _title(request: Request, row: dict[str, Any], payload: dict[str, Any]) -> str:
    from apps.octo.ingest.presentation import clean_line

    text = ""
    try:
        from apps.octo.api.routers.dashboard import _presenters

        present = _presenters(getattr(request.app.state, "adapter_registry", None)) \
            .get(str(row.get("source") or ""))
        if callable(present):
            text = present(payload).headline
    except Exception:  # noqa: BLE001 — a label never fails the route
        text = ""
    return clean_line(text or row.get("event_type") or "alert", 240) or "alert"


@router.get("/expected", response_model=ExpectedListResponse)
def list_expected(
    response: Response,
    tenant: Optional[str] = Query(default=None, max_length=64),
    state: Literal["active", "all"] = Query(default="active"),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> ExpectedListResponse:
    response.headers["Cache-Control"] = "no-store"
    scope = resolve_caller_scope(info.operator_id)
    if tenant is not None:
        _scoped(info, tenant)
    now = _now()
    rules = [r for r in vstore.expected_rules(tenant)
             if (scope == ["*"] or r.slug in scope) and (state == "all" or r.active(now))]
    names = sources.operator_display_names(
        {str(x) for r in rules for x in (r.created_by, r.revoked_by) if x})
    rows = []
    for r in rules:
        d = r.as_dict(now)
        d["created_by_name"] = names.get(str(r.created_by))
        d["revoked_by_name"] = names.get(str(r.revoked_by)) if r.revoked_by else None
        rows.append(d)
    return ExpectedListResponse(rows=rows)


@router.post("/expected/{rule_id}/revoke", response_model=ExpectedListResponse)
def revoke_expected(
    body: RevokeIn,
    response: Response,
    rule_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> ExpectedListResponse:
    rule = vstore.get_rule(rule_id)
    # One answer for "no such rule" and "a rule outside your scope": the id
    # space is never an oracle.
    if rule is None or not _in_scope(info, rule.slug):
        raise APIError("NOT_FOUND", "no such expected condition in your scope")
    if rule.revoked_at:
        raise APIError("CONFLICT", "this expected condition is already revoked")
    target = str(rule_id)
    taudit.human(info.operator_id, "expected.revoke", rule.slug, "expected_condition", target,
                 before={"signature_key": rule.signature_key, "review_at": rule.review_at},
                 reason=body.reason)

    def write(reg: sqlite3.Connection) -> None:
        if not vstore.revoke_expected(reg, rule_id, by=info.operator_id, reason=body.reason):
            raise ValueError("this expected condition is already revoked")

    _write(info, "expected.revoke", rule.slug, target, write)
    notify.notify_admins(
        kind="threat_registry", slug=rule.slug, exclude=info.operator_id,
        title=f"Expected condition #{rule_id} at {rule.slug} revoked",
        body=f"Operator #{info.operator_id} revoked \"{rule.label}\": {body.reason}",
        request_id=f"expected:{rule_id}:revoke")
    build.invalidate()
    return list_expected(response, tenant=rule.slug, state="all", info=info)


# ---------------------------------------------------------------------------
# Recall / notes on an acknowledgement (v0.17.5)
# ---------------------------------------------------------------------------

_NO_ACK = "no such acknowledgement in your scope"


def _followup_text(value: Optional[str], *, what: str, minimum: int = 1) -> str:
    """The text as it is recorded (whitespace collapsed) — or a plain 422."""
    text = vstore.collapse(value)
    if len(text) < minimum:
        raise APIError("VALIDATION_FAILED",
                       f"a {what} of at least {minimum} characters is required"
                       if minimum > 1 else f"a {what} is required")
    if len(text) > vstore.NOTE_MAX:
        raise APIError("VALIDATION_FAILED", f"a {what} is at most {vstore.NOTE_MAX} characters")
    return text


def _scoped_ack(info: sessions.SessionInfo, slug: str, verdict_id: int) -> vstore.Verdict:
    """The tenant's acknowledgement — ONE 404 for a tenant outside the
    caller's scope (or not active), a verdict that does not exist and another
    tenant's (the id space is never an oracle); 409 for a label that is not
    an ack."""
    if not _in_scope(info, slug):
        raise APIError("NOT_FOUND", _NO_ACK)
    v = vstore.get_verdict(verdict_id)
    if v is None or v.slug != slug:
        raise APIError("NOT_FOUND", _NO_ACK)
    if v.verdict != vstore.ACK:
        raise APIError("CONFLICT", vstore.NOT_AN_ACK)
    return v


@router.post("/{slug}/verdicts/{verdict_id}/recall", response_model=FollowUpOut)
def recall_ack(
    body: Optional[RecallIn] = None,
    slug: str = Path(..., min_length=1, max_length=64, pattern=_SLUG),
    verdict_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> FollowUpOut:
    """The acknowledgement no longer covers anything: its alert (and the
    other rows of its vendor alert, and its "repeats for 24 h") needs
    attention again and counts towards the site's colour. The ack stays in
    the history; the recall is final (acknowledge again = a new ack)."""
    reason = _followup_text(body.reason if body else None, what="reason",
                            minimum=vstore.REASON_MIN)
    v = _scoped_ack(info, slug, verdict_id)
    if v.recalled:
        raise APIError("CONFLICT", vstore.ALREADY_RECALLED)
    now = _now()
    target = f"{slug}:verdict:{verdict_id}"
    taudit.human(info.operator_id, "alert.ack_recall", slug, "alert_verdict", target,
                 before={"verdict_id": v.id, "event_id": v.event_id, "acked_by": v.actor,
                         "acked_at": v.at, "source": v.source, "device_key": v.device_key,
                         "signature_key": v.signature_key, "alert_ref": v.alert_ref,
                         "repeat_until": v.repeat_until},
                 after={"recalled": True}, reason=reason)
    fid = _write(info, "alert.ack_recall", slug, target, lambda reg: vstore.add_followup(
        reg, verdict_id=v.id, slug=slug, kind=vstore.RECALL, actor=info.operator_id,
        text=reason, at=now))
    build.invalidate()
    return FollowUpOut(followup_id=fid, verdict_id=v.id, event_id=v.event_id, tenant_slug=slug,
                       kind="recall", at=vstore.iso(now))


@router.post("/{slug}/verdicts/{verdict_id}/notes", response_model=FollowUpOut)
def note_ack(
    body: Optional[NoteIn] = None,
    slug: str = Path(..., min_length=1, max_length=64, pattern=_SLUG),
    verdict_id: int = Path(..., ge=1),
    info: sessions.SessionInfo = Depends(session_analyst_plus),
) -> FollowUpOut:
    """Context learnt after the acknowledgement, shown under it (newest
    last) — recalled or not. The ack's own note is never edited; nothing
    else changes (the alert's place and the colour stay)."""
    note = _followup_text(body.note if body else None, what="note")
    v = _scoped_ack(info, slug, verdict_id)
    now = _now()
    target = f"{slug}:verdict:{verdict_id}"
    taudit.human(info.operator_id, "alert.ack_note", slug, "alert_verdict", target,
                 after={"verdict_id": v.id, "event_id": v.event_id, "recalled": v.recalled},
                 reason=note)
    fid = _write(info, "alert.ack_note", slug, target, lambda reg: vstore.add_followup(
        reg, verdict_id=v.id, slug=slug, kind=vstore.NOTE, actor=info.operator_id, text=note,
        at=now))
    return FollowUpOut(followup_id=fid, verdict_id=v.id, event_id=v.event_id, tenant_slug=slug,
                       kind="note", at=vstore.iso(now))


def verdicts_for(slug: str, now: Optional[datetime] = None) -> Optional[TenantVerdicts]:
    try:
        return TenantVerdicts.load(slug, now)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[alerts] verdicts of %s not read (%s)", slug, type(exc).__name__)
        return None
