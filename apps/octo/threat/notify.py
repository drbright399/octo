"""notify_threat() — paging for Red and Black (design 6.5).

WHO. `RECIPIENT_ROLES` of operator notices excludes analysts; this path does
not: the analysts whose scope holds the tenant, every admin and super_admin
whose scope holds it (`*` holds every tenant), active and not removed. Each
step is an in-app notice (`operator_notices`, kinds threat_*) per recipient
plus an e-mail through the configured 'resend' integration (none configured →
'not_configured', nothing sent). Every step has an IDEMPOTENT request id
(`inc:<slug>:<id>:step<n>@<ladder start>`): a step is never sent twice to one
person, whatever restarts in between. Nothing here raises into a caller.

BLACK, until acknowledged (24/7):
  step 1  T0         everyone in scope; notice + e-mail
  step 2  T+5 min    e-mail again
  step 3  T+15 min   the super_admins (a pager plugs in here later)
  step 4  T+30 min   everyone; then every 30 min (step 5 = T+60, …)
          T+60 min   audit `incident.unacked_60m` (once)
  acknowledged, no activity 2 h → remind the owner; 4 h → re-escalate to the
  admins.
RED:
  step 1  T0         notice + e-mail
          T+60 min   audit `incident.unacked_60m` (once; no page)
  step 3  T+4 h      again — within business hours (the next business-hours
                     moment after T+4 h; OCTO_BUSINESS_TZ, Mon–Fri 08–17)
  then a daily 08:00 digest of the unacknowledged Reds until acknowledged
  (`red_digest`).
RESTRICTED (B7, CSAM — v0.17.1): the same 24/7 Black ladder (no business-
hours deferral), to the admins and super_admins in scope only (an analyst
cannot open it), with ONE neutral text — "Restricted Black incident at
<tenant> — open Athena" in-app, "restricted Black incident — open Athena" by
e-mail — never the domain, the URL, the device or the category.
A missed run (a restart) sends T0 if it was never sent and then only the
LATEST due step — never a burst of every page missed; the 60-minute audit is
written whichever steps were jumped.

A step is DONE only when its page was written: a step whose notices could
not be written (the registry busy past its timeout, a full disk) is not
counted (`escalation_step` stops before it), so the next pass sends it again
— the idempotent request ids make that retry safe (nobody is paged twice).

E-mails transit a third-party provider: they carry the tier, the incident
number, its age and "sign in to Athena" — never the tenant's name, a device,
an indicator, an operator's free text or a credential. The in-app notice (on
the bundle) carries the tenant and the summary. `send()` enforces it: a
caller that gives no e-mail text of its own gets the NEUTRAL one, never the
in-app title and body.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Any, Callable, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import format_utc_ms
from apps.octo.threat import audit as taudit
from apps.octo.threat.store import BLACK, RED, Incident, parse

logger = logging.getLogger(__name__)

THREAT_ROLES = ("analyst", "admin", "super_admin")
TITLE_MAX, BODY_MAX = 200, 2000
BLACK_EMAIL_AGAIN = timedelta(minutes=5)
BLACK_SUPER = timedelta(minutes=15)
BLACK_EVERYONE = timedelta(minutes=30)
UNACKED_AUDIT = timedelta(minutes=60)
RED_AGAIN = timedelta(hours=4)
ACK_REMIND = timedelta(hours=2)
ACK_REESCALATE = timedelta(hours=4)
DIGEST_HOUR = 8
BUSINESS_START, BUSINESS_END = time(8, 0), time(17, 0)
TZ_ENV = "OCTO_BUSINESS_TZ"
DEFAULT_TZ = "America/Chicago"

# Tests swap this for a fake (no e-mail ever leaves a test).
MAILER_FACTORY: Callable[[], Optional[Callable[[str, str, str], bool]]]


def _default_mailer() -> Optional[Callable[[str, str, str], bool]]:
    from apps.octo.auth import email_sender

    return email_sender.resend_instance_mailer()


MAILER_FACTORY = _default_mailer


def business_tz() -> ZoneInfo:
    try:
        return ZoneInfo(os.environ.get(TZ_ENV, "").strip() or DEFAULT_TZ)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo(DEFAULT_TZ)


def in_business_hours(at: datetime) -> bool:
    local = at.astimezone(business_tz())
    return local.weekday() < 5 and BUSINESS_START <= local.time() < BUSINESS_END


def next_business_moment(at: datetime) -> datetime:
    """`at` itself when inside business hours, else the next opening."""
    tz = business_tz()
    local = at.astimezone(tz)
    for _ in range(8):
        if local.weekday() < 5 and local.time() < BUSINESS_END:
            if local.time() >= BUSINESS_START:
                return local.astimezone(timezone.utc)
            return local.replace(hour=BUSINESS_START.hour, minute=0, second=0,
                                 microsecond=0).astimezone(timezone.utc)
        local = (local + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return at


# ---------------------------------------------------------------------------
# Recipients
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Recipient:
    id: int
    username: str
    email: Optional[str]
    roles: frozenset[str]


def recipients(conn: sqlite3.Connection, slug: str, *, audience: str = "everyone",
               exclude: Optional[int] = None) -> list[Recipient]:
    """Active operators holding an analyst / admin / super_admin role whose
    scope holds `slug` (`slug` '*': every such operator — a bundle-wide
    notice). `audience`: 'everyone' | 'super_admin' | 'admins'
    (admin + super_admin) | 'owner:<id>'."""
    rows = conn.execute(
        "SELECT o.id, o.username, o.email, r.role_name, r.scope_slugs FROM operators o "
        "JOIN operator_roles r ON r.operator_id = o.id "
        "WHERE o.disabled_at IS NULL AND o.removed_at IS NULL "
        f"AND r.role_name IN ({','.join('?' * len(THREAT_ROLES))}) ORDER BY o.id",
        THREAT_ROLES).fetchall()
    by_id: dict[int, dict[str, Any]] = {}
    for r in rows:
        try:
            scope = json.loads(r["scope_slugs"] or "[]") or []
        except (TypeError, ValueError):
            scope = []
        if slug != "*" and "*" not in scope and slug not in scope:
            continue
        entry = by_id.setdefault(int(r["id"]), {"username": r["username"], "email": r["email"],
                                                "roles": set()})
        entry["roles"].add(r["role_name"])
    out = []
    for oid, e in sorted(by_id.items()):
        roles = frozenset(e["roles"])
        if exclude is not None and oid == exclude:
            continue
        if audience == "super_admin" and "super_admin" not in roles:
            continue
        if audience == "admins" and not roles & {"admin", "super_admin"}:
            continue
        if audience.startswith("owner:") and str(oid) != audience.split(":", 1)[1]:
            continue
        out.append(Recipient(oid, str(e["username"]), (e["email"] or None), roles))
    return out


@dataclass
class Sent:
    request_id: str
    recipients: list[int] = field(default_factory=list)
    notices: list[int] = field(default_factory=list)
    emailed: dict[str, list[int]] = field(default_factory=dict)
    error: Optional[str] = None


NEUTRAL_SUBJECT = "Athena: a security notice is waiting for you"
NEUTRAL_BODY = ("A security notice is waiting for you in Athena. Sign in to Athena to read "
                "it. The client's name, devices, indicators and anyone's notes are not sent by "
                "e-mail.\n")
ADMIN_SUBJECT = "Athena: a Tier Black change needs your review"
ADMIN_BODY = ("A Tier Black registry or incident change was made that needs your peer review. "
              "Sign in to Athena to see it. The client's name, devices, indicators and the "
              "operator's notes are not sent by e-mail.\n")


def send(slug: str, *, kind: str, title: str, body: str, request_id: str,
         audience: str = "everyone", email_subject: Optional[str] = None,
         email_body: Optional[str] = None, exclude: Optional[int] = None) -> Sent:
    """One notice per recipient who has none with this request id yet, then
    the e-mail copy — the caller's NEUTRAL e-mail text, or the generic
    neutral one: the in-app title and body (tenant, device, free text) never
    leave the bundle. Never raises."""
    out = Sent(request_id)
    try:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                for r in recipients(reg, slug, audience=audience, exclude=exclude):
                    seen = reg.execute(
                        "SELECT 1 FROM operator_notices WHERE request_id = ? AND recipient_id = ? "
                        "LIMIT 1", (request_id, r.id)).fetchone()
                    if seen is not None:
                        continue
                    cur = reg.execute(
                        "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, "
                        "target_slug, change_request_id, title, body, request_id) "
                        "VALUES (?, ?, 0, ?, NULL, NULL, ?, ?, ?)",
                        (r.id, kind, "global" if slug == "*" else slug, title[:TITLE_MAX],
                         body[:BODY_MAX], request_id))
                    out.recipients.append(r.id)
                    out.notices.append(int(cur.lastrowid))
        finally:
            reg.close()
    except Exception as exc:  # noqa: BLE001 — paging is never fatal to the caller
        logger.error("[notify-threat] notices %s not written (%s)", request_id,
                     type(exc).__name__)
        out.error = type(exc).__name__
        return out
    if out.notices:
        out.emailed = _email(out.notices, email_subject or NEUTRAL_SUBJECT,
                             email_body or NEUTRAL_BODY)
    return out


def _email(notice_ids: list[int], subject: str, body: str) -> dict[str, list[int]]:
    states: dict[str, list[int]] = {"sent": [], "failed": [], "not_configured": [],
                                    "no_address": []}
    try:
        mailer = MAILER_FACTORY()
    except Exception:  # noqa: BLE001
        mailer = None
    try:
        reg = connect(paths.registry_db_path())
        try:
            marks = ",".join("?" * len(notice_ids))
            rows = reg.execute(
                f"SELECT n.id, n.recipient_id, o.email FROM operator_notices n "
                f"JOIN operators o ON o.id = n.recipient_id WHERE n.id IN ({marks})",
                notice_ids).fetchall()
            results: list[tuple[str, int]] = []
            for r in rows:
                if mailer is None:
                    state = "not_configured"
                elif not (r["email"] or "").strip():
                    state = "no_address"
                else:
                    try:
                        state = "sent" if mailer(r["email"].strip(), subject, body) else "failed"
                    except Exception:  # noqa: BLE001
                        state = "failed"
                states[state].append(int(r["recipient_id"]))
                results.append((state, int(r["id"])))
            now = format_utc_ms(datetime.now(timezone.utc))
            with transaction(reg):
                for state, nid in results:
                    reg.execute("UPDATE operator_notices SET email_state = ?, "
                                "email_attempted_at = ? WHERE id = ?",
                                (state, None if state == "not_configured" else now, nid))
        finally:
            reg.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("[notify-threat] e-mail outcome not recorded (%s)", type(exc).__name__)
    return states


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    n: int
    due: datetime
    audience: str
    kind: str
    email_only: bool = False
    page: bool = True


def _black_steps(t0: datetime, now: datetime) -> list[Step]:
    steps = [Step(1, t0, "everyone", "threat_black"),
             Step(2, t0 + BLACK_EMAIL_AGAIN, "everyone", "threat_escalation", email_only=True),
             Step(3, t0 + BLACK_SUPER, "super_admin", "threat_escalation"),
             Step(4, t0 + BLACK_EVERYONE, "everyone", "threat_escalation")]
    n, due = 5, t0 + 2 * BLACK_EVERYONE
    while due <= now:
        steps.append(Step(n, due, "everyone", "threat_escalation"))
        n, due = n + 1, due + BLACK_EVERYONE
    return steps


def _red_steps(t0: datetime) -> list[Step]:
    return [Step(1, t0, "everyone", "threat_red"),
            Step(2, t0 + UNACKED_AUDIT, "everyone", "threat_red", page=False),
            Step(3, next_business_moment(t0 + RED_AGAIN), "everyone", "threat_escalation")]


def steps_for(inc: Incident, now: datetime) -> list[Step]:
    t0 = inc.ladder_t0() or now
    steps = _black_steps(t0, now) if inc.tier == BLACK else _red_steps(t0)
    if inc.restricted:
        # A RESTRICTED incident (B7) is admin+ only: the analysts are not
        # paged (they could not open it); the super_admin step stays.
        steps = [Step(s.n, s.due, "admins" if s.audience == "everyone" else s.audience,
                      s.kind, s.email_only, s.page) for s in steps]
    return steps


def request_id(inc: Incident, n: int) -> str:
    return f"inc:{inc.slug}:{inc.id}:step{n}@{inc.ladder_started_at or inc.detected_at}"


RESTRICTED_SUBJECT = "Athena: restricted Black incident — open Athena"
RESTRICTED_BODY = ("A restricted Black incident is open. Open Athena to see it (admins only). "
                   "Nothing about it is sent by e-mail.\n")


def restricted_title(tenant_name: str) -> str:
    """The ONLY text a restricted incident's page carries (Rick, 2026-10-06):
    no domain, no URL, no device, no category."""
    return f"Restricted Black incident at {tenant_name} — open Athena"


def _texts(inc: Incident, step: Step, now: datetime, tenant_name: str) -> tuple[str, str, str,
                                                                                 str]:
    age = max(0, int((now - (inc.ladder_t0() or now)).total_seconds() // 60))
    if inc.restricted:
        # The e-mail transits a third party: not even the tenant's name.
        title = restricted_title(tenant_name)
        body = (f"{title}. Incident #{inc.id}, unacknowledged for {age} min. Restricted: "
                "admins only — acknowledge it in Athena.")
        return title, body, RESTRICTED_SUBJECT, RESTRICTED_BODY
    word = "BLACK" if inc.tier == BLACK else "RED"
    where = f" on {inc.device_label or inc.device_ref}" if (inc.device_label or inc.device_ref) \
        else ""
    title = f"{word}: {inc.summary}{where} — {tenant_name}"
    if step.n > 1:
        title = f"{word} still unacknowledged ({age} min): {inc.summary} — {tenant_name}"
    body = (f"{word} incident #{inc.id} at {tenant_name}: {inc.summary}{where}. "
            f"Opened {inc.detected_at} by {inc.rule_id}; unacknowledged for {age} min. "
            "Acknowledge it in Athena (Fleet → the banner, or the site's drawer). "
            "Black and Red never fade on their own; only a person closes them.")
    subject = f"Athena: {word} incident #{inc.id} — unacknowledged {age} min"
    ebody = (f"A {word} security incident (#{inc.id}) is open and not acknowledged "
             f"({age} min).\n\nSign in to Athena to see it and acknowledge it. The client's "
             "name, devices and indicators are not sent by e-mail.\n")
    return title, body, subject, ebody


def notify_threat(inc: Incident, now: datetime, *, tenant_name: str) -> list[Sent]:
    """Run the incident's ladder up to `now`: everything due and not yet
    done (`escalation_step`), paged once each. Returns what was sent; the
    caller records the new step (`store.set_ladder`)."""
    if not inc.is_open or inc.acked:
        return []
    out: list[Sent] = []
    due = [s for s in steps_for(inc, now) if s.due <= now and s.n > inc.escalation_step]
    if not due:
        return out
    if any(s.due >= (inc.ladder_t0() or now) + UNACKED_AUDIT for s in due) \
            and not _audited_60m(inc):
        taudit.system("incident.unacked_60m", inc.slug, "incident", str(inc.id),
                      after={"tier": inc.tier, "rule": inc.rule_id,
                             "ladder_started_at": inc.ladder_started_at},
                      reason=f"{inc.tier} incident not acknowledged within 60 minutes",
                      request_id=f"{request_id(inc, 0)}:unacked60")
    pages = [s for s in due if s.page]
    send_steps = []
    if pages and pages[0].n == 1:
        send_steps.append(pages[0])
    if pages and pages[-1] not in send_steps:
        send_steps.append(pages[-1])
    failed: list[int] = []
    for s in send_steps:
        title, body, subject, ebody = _texts(inc, s, now, tenant_name)
        sent = send(inc.slug, kind=s.kind, title=title, body=body,
                    request_id=request_id(inc, s.n), audience=s.audience,
                    email_subject=subject, email_body=ebody)
        out.append(sent)
        if sent.error is not None:
            failed.append(s.n)
    # Done up to (not including) the first step whose page was not written:
    # it is sent again next pass (idempotent ids — nobody gets it twice).
    inc.escalation_step = max(inc.escalation_step,
                              (min(failed) - 1) if failed else due[-1].n)
    return out


def _audited_60m(inc: Incident) -> bool:
    try:
        g = connect(paths.global_audit_db_path(), read_only=True)
        try:
            return g.execute("SELECT 1 FROM audit_log WHERE action = 'incident.unacked_60m' "
                             "AND request_id = ? LIMIT 1",
                             (f"{request_id(inc, 0)}:unacked60",)).fetchone() is not None
        finally:
            g.close()
    except sqlite3.Error:
        return False


def acked_followup(inc: Incident, now: datetime, *, last_activity: Optional[datetime],
                   tenant_name: str) -> list[Sent]:
    """An acknowledged BLACK with no activity: 2 h → remind its owner (the
    assignee, else whoever acknowledged); 4 h → re-escalate to the admins."""
    if not inc.is_open or not inc.acked or inc.tier != BLACK:
        return []
    since = last_activity or parse(inc.acknowledged_at) or now
    idle = now - since
    owner = inc.assigned_to or inc.acknowledged_by or ""
    out: list[Sent] = []
    base = f"inc:{inc.slug}:{inc.id}:ack@{since.strftime('%Y%m%dT%H%M%S')}"
    if inc.restricted:
        hours = int(idle.total_seconds() // 3600)
        if idle >= ACK_REMIND and owner.isdigit():
            out.append(send(inc.slug, kind="threat_escalation",
                            title=f"Reminder: {restricted_title(tenant_name)} — no activity for "
                                  f"{hours} h",
                            body="An acknowledged restricted incident you own has had no "
                                 "activity for 2 hours.",
                            request_id=f"{base}:remind", audience=f"owner:{owner}",
                            email_subject=RESTRICTED_SUBJECT, email_body=RESTRICTED_BODY))
        if idle >= ACK_REESCALATE:
            out.append(send(inc.slug, kind="threat_escalation",
                            title=f"Re-escalated: {restricted_title(tenant_name)} — no activity "
                                  f"for {hours} h",
                            body="An acknowledged restricted incident has had no activity for "
                                 "4 hours.",
                            request_id=f"{base}:reescalate", audience="admins",
                            email_subject=RESTRICTED_SUBJECT, email_body=RESTRICTED_BODY))
        return out
    if idle >= ACK_REMIND and owner.isdigit():
        out.append(send(inc.slug, kind="threat_escalation",
                        title=f"Reminder: BLACK #{inc.id} at {tenant_name} — no activity for "
                              f"{int(idle.total_seconds() // 3600)} h",
                        body=f"You own BLACK incident #{inc.id} ({inc.summary}). Nothing has been "
                             "recorded on it for 2 hours: add a note, mark it contained or "
                             "close it.",
                        request_id=f"{base}:remind", audience=f"owner:{owner}",
                        email_subject=f"Athena: BLACK incident #{inc.id} — reminder",
                        email_body="An acknowledged BLACK incident you own has had no activity "
                                   "for 2 hours. Sign in to Athena.\n"))
    if idle >= ACK_REESCALATE:
        out.append(send(inc.slug, kind="threat_escalation",
                        title=f"Re-escalated: BLACK #{inc.id} at {tenant_name} — no activity for "
                              f"{int(idle.total_seconds() // 3600)} h",
                        body=f"BLACK incident #{inc.id} ({inc.summary}) was acknowledged but has "
                             "had no activity for 4 hours.",
                        request_id=f"{base}:reescalate", audience="admins",
                        email_subject=f"Athena: BLACK incident #{inc.id} — re-escalated",
                        email_body="An acknowledged BLACK incident has had no activity for 4 "
                                   "hours. Sign in to Athena.\n"))
    return out


def digest_due(now: datetime) -> Optional[str]:
    """The local date whose 08:00 digest is due at `now` (None before 08:00)."""
    local = now.astimezone(business_tz())
    if local.hour < DIGEST_HOUR:
        return None
    return local.date().isoformat()


def red_digest(unacked: dict[str, list[Incident]], now: datetime, *,
               tenant_names: dict[str, str]) -> list[Sent]:
    """The daily 08:00 digest: per tenant with unacknowledged Reds, one
    notice per recipient per local day (request id `digest:<date>:<slug>`)."""
    day = digest_due(now)
    if day is None:
        return []
    out = []
    for slug, incs in sorted(unacked.items()):
        reds = [i for i in incs if i.tier == RED and i.is_open and not i.acked]
        if not reds:
            continue
        name = tenant_names.get(slug, slug)
        lines = "; ".join(f"#{i.id} {i.summary}" for i in reds[:10])
        out.append(send(
            slug, kind="threat_red",
            title=f"Daily digest: {len(reds)} unacknowledged Red incident"
                  f"{'' if len(reds) == 1 else 's'} at {name}",
            body=f"Still not acknowledged: {lines}. Red never fades on its own.",
            request_id=f"digest:{day}:{slug}",
            email_subject=f"Athena: daily digest — {len(reds)} unacknowledged Red "
                          f"incident{'' if len(reds) == 1 else 's'}",
            email_body="Red incidents are still not acknowledged. Sign in to Athena.\n"))
    return out


def notify_client_decision(inc: Incident, decision: dict[str, Any], *,
                           tenant_name: str) -> Sent:
    """A client's 'lock down' / 'allow' pages the analysts in scope (and the
    admins) at once."""
    kind = decision.get("kind")
    what = ("asked to LOCK DOWN their network and to be contacted" if kind == "lockdown"
            else "asked to ALLOW the traffic (an analyst must confirm)"
            if decision.get("status") == "pending_analyst"
            else "chose to ALLOW the traffic")
    return send(
        inc.slug, kind="threat_client",
        title=f"Client decision on {inc.tier.upper()} #{inc.id} at {tenant_name}: {kind}",
        body=f"A client user at {tenant_name} {what} on incident #{inc.id} ({inc.summary}). "
             "Nothing was changed on their network — contact them. "
             "911 / life-safety systems are never blocked.",
        request_id=f"inc:{inc.slug}:{inc.id}:decision{decision.get('id')}",
        email_subject=f"Athena: client decision on incident #{inc.id} — contact the client",
        email_body="A client user recorded a decision on an open security incident. Sign in "
                   "to Athena and contact them.\n")


def notify_admins(*, kind: str, title: str, body: str, request_id: str, slug: str = "global",
                  exclude: Optional[int] = None) -> Sent:
    """A registry change that can suppress or bound a tier (a brake, an
    exception, an asset tag set or cleared, the canary allowlist) or a Black
    closed / reclassified — every OTHER admin is told. The in-app notice
    carries the detail; the e-mail is FIXED and neutral (no tenant, no
    device, no binding, no free text)."""
    return send("*" if slug == "global" else slug, kind=kind, title=title, body=body,
                request_id=request_id, audience="admins", exclude=exclude,
                email_subject=ADMIN_SUBJECT, email_body=ADMIN_BODY)
