"""What a CLIENT user (viewer) sees of an incident — design 6.9 + Rick's
section 9.2.

  * Neutral text only: no vendor, rule, device, indicator, coordinate or
    pulse — never anything an operator typed.
  * Visible after an operator ACKNOWLEDGES, or after 60 minutes
    unacknowledged, whichever comes first (`client_visible_at`, stamped by
    the worker; computed here too, so the page never waits on it). A
    REOPENED incident is new to triage again: its clock restarts at the
    reopen (the store clears its acknowledgement and its stamp), so a
    record once closed — even as a false positive — never reaches the
    client before someone has looked at it again.
  * FR-rule incidents are internal (never shown).
  * A RESTRICTED incident (B7, CSAM — v0.17.1) is never shown to a client
    user unless the MSP's switch (`registry.csam_client_notice`, admin+,
    audited, OFF by default) lets its neutral line through — and it never
    offers either action (no device action of any kind: the evidence is
    preserved and the user involved is not tipped off).
  * Exactly TWO actions on an open, visible incident:
      "Lock down my network and contact my analyst"   (kind 'lockdown')
      "Allow this traffic"                            (kind 'allow')
    In slice 1 both only RECORD the client's decision (audited, with the
    client user's id), page the analysts in scope and show a confirmation.
    Nothing is blocked, isolated or unblocked. On BLACK, "Allow" is
    recorded as a REQUEST an analyst must confirm; on RED it is recorded as
    the client's decision.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import Any, Optional

from apps.octo.threat import lockdown
from apps.octo.threat.store import BLACK, RED, Incident, parse

VISIBLE_AFTER = timedelta(minutes=60)

LINE_BLACK = "Urgent security incident: your IT provider has been alerted"
LINE_BLACK_ACKED = "Urgent security incident: your IT provider is responding"
LINE_CONTAINED = "Security incident contained: your IT provider is monitoring"
LINE_RED = "Security issue under investigation by your IT provider"
LINE_WATCH = "Recently resolved security incident: under watch"

ACTION_LOCKDOWN = "lockdown"
ACTION_ALLOW = "allow"
ACTIONS: tuple[tuple[str, str], ...] = (
    (ACTION_LOCKDOWN, "Lock down my network and contact my analyst"),
    (ACTION_ALLOW, "Allow this traffic"),
)

CONFIRM_LOCKDOWN = (
    "Recorded. Your analyst has been paged and will contact you. Nothing on your network has "
    "been changed yet. " + lockdown.LIFE_SAFETY_NOTICE.capitalize() + "."
)
CONFIRM_ALLOW_RED = (
    "Recorded: you chose to allow this traffic. Your analyst has been notified and will "
    "review it."
)
CONFIRM_ALLOW_BLACK = (
    "Recorded as a request: your analyst must confirm it before anything changes. Your "
    "analyst has been paged."
)


def ref(slug: str, incident_id: int) -> str:
    """Opaque: never the tenant slug or the record id in a client's URL."""
    return "i-" + hashlib.sha256(f"incident:{slug}:{incident_id}".encode()).hexdigest()[:20]


def internal(inc: Incident) -> bool:
    if inc.rule_id.upper().startswith("FR"):
        return True
    if inc.restricted:
        from apps.octo.threat import registry

        return not registry.csam_client_notice()
    return False


def clock_start(inc: Incident) -> Optional[datetime]:
    """When the client's 60-minute clock started: detection — or the latest
    REOPEN (`stages`), which makes the record new to triage again."""
    reopens = [parse(s.get("at")) for s in inc.stages
               if isinstance(s, dict) and s.get("kind") == "reopen"]
    reopens = [d for d in reopens if d is not None]
    return max(reopens) if reopens else parse(inc.detected_at)


def visible_at(inc: Incident) -> Optional[datetime]:
    """When the client may see it: the earliest of the stamp, the ack, and
    the clock's start (detection, or the latest reopen) + 60 min."""
    cands = [d for d in (parse(inc.client_visible_at), parse(inc.acknowledged_at)) if d]
    t0 = clock_start(inc)
    if t0 is not None:
        cands.append(t0 + VISIBLE_AFTER)
    return min(cands) if cands else None


def visible(inc: Incident, now: datetime, *, watch_days: int = 7) -> bool:
    if internal(inc):
        return False
    at = visible_at(inc)
    if at is None or at > now:
        return False
    if inc.is_open:
        return True
    # A closed incident shows only as the true-positive watch.
    closed = parse(inc.closed_at)
    return bool(inc.true_positive and closed and now - closed <= timedelta(days=watch_days))


def line(inc: Incident, now: datetime, *, watch_days: int = 7) -> Optional[str]:
    if not visible(inc, now, watch_days=watch_days):
        return None
    if not inc.is_open:
        return LINE_WATCH
    if inc.contained:
        return LINE_CONTAINED
    if inc.tier == BLACK:
        return LINE_BLACK_ACKED if inc.acked else LINE_BLACK
    return LINE_RED


# Worst first: what the client's global strip says when several incidents
# are visible (an unacknowledged Black outranks everything; a resolved one
# under watch ranks last).
LINE_ORDER = (LINE_BLACK, LINE_BLACK_ACKED, LINE_RED, LINE_CONTAINED, LINE_WATCH)


def worst_line(items: list[dict[str, Any]]) -> Optional[str]:
    """The strip's line: the worst `status_neutral` among a client user's
    visible items (`payload` dicts) — never "has been alerted" once the
    provider is responding, never the Red line for a contained one."""
    lines = [i.get("status_neutral") for i in items if i.get("status_neutral") in LINE_ORDER]
    return min(lines, key=LINE_ORDER.index) if lines else None


def confirmation(kind: str, tier: str) -> str:
    if kind == ACTION_LOCKDOWN:
        return CONFIRM_LOCKDOWN
    return CONFIRM_ALLOW_BLACK if tier == BLACK else CONFIRM_ALLOW_RED


def decision_status(kind: str, tier: str) -> str:
    """'pending_analyst' for a Black allow (the block stays until an analyst
    confirms); 'recorded' otherwise."""
    return "pending_analyst" if (kind == ACTION_ALLOW and tier == BLACK) else "recorded"


def payload(inc: Incident, now: datetime, *, decisions: Optional[list[dict[str, Any]]] = None,
            watch_days: int = 7) -> Optional[dict[str, Any]]:
    """The whole of what a client user receives about one incident, or None
    (not visible). Only: an opaque ref, the tier, the neutral line, when,
    the two actions (open only) and the client's OWN recorded decisions
    (kind, status, when, the confirmation) — no device, no indicator, no
    rule, no operator text, no acknowledgement detail."""
    text = line(inc, now, watch_days=watch_days)
    if text is None:
        return None
    mine = [{"kind": d["kind"], "status": d["status"], "created_at": d["created_at"],
             "confirmation": confirmation(d["kind"], d["tier_at_request"])}
            for d in (decisions or []) if d.get("requested_role") == "client"]
    return {
        "ref": ref(inc.slug, inc.id),
        "tier": inc.tier if inc.is_open else None,
        "status_neutral": text,
        "opened_at": inc.detected_at,
        "actions": [{"kind": k, "label": label} for k, label in ACTIONS]
        if inc.is_open and not inc.restricted else [],
        "decisions": mine,
    }


__all__ = ["ACTIONS", "BLACK", "RED", "payload", "ref", "visible", "line", "worst_line"]
