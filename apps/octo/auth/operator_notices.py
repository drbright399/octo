"""Operator notices — the OTHER admins are told when one person applied a
consequential tenant change alone (v0.10 item 7, migration 035).

Two-person approval is the default for merging and offboarding a tenant; a
super_admin may instead apply one on their own typed attestation (the
"attested single-person exception", `api.routers.admin_tenants`). Every other
admin+ operator — active, not removed, not the actor — then gets:

  in-app   one `operator_notices` row each, created INSIDE the registry
           transaction that applies the change, under a SAVEPOINT: a
           committed change always has its notices, and a failure to create
           them rolls back only the savepoint — never the change. The failure
           CLASS is returned so the caller records it in the change's audit
           marker. The console shows a recipient their open notices on every
           load until they acknowledge them (audited).
  e-mail   after the change committed (a background task — the network is
           never touched while the registry write lock is held), through the
           configured 'resend' integration instance only
           (`email_sender.resend_instance_mailer`). No instance → every notice
           is marked 'not_configured' and nothing is sent. Each recipient's
           outcome lands on their notice (email_state) and the batch in ONE
           'operator_notice_email' audit row. Nothing here ever raises into
           the change: notification failure is recorded, never fatal.

What an e-mail says: the kind of change, its change-request number, the
operator id of the actor and the time. NOT the tenants' names — the message
transits a third-party mail provider, and a tenant slug names a client; the
in-app notice (on the bundle) carries them. Never the typed attestation, never
a credential.
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from apps.octo import paths
from apps.octo.auth import audit, email_sender
from apps.octo.db import connect, transaction
from apps.octo.ingest.timestamps import utcnow_iso

logger = logging.getLogger(__name__)

KINDS: tuple[str, ...] = ("single_attested_merge", "single_attested_offboard")
# Notices the PLATFORM raises (actor 0), not about one change — migration 038.
# 'mapping_review': tenant mappings made from a name match, to re-review
# (`apps.octo.instances.mapping_review`, the same-name fix).
# 'entity_review' (migration 040): entity resolution hit something only a
# human can settle — a rule against an operator decision, two sites claiming
# one alert, a profile whose traffic comes from none of its client's sites
# (`apps.octo.entity.worker`).
SYSTEM_KINDS: tuple[str, ...] = ("mapping_review", "entity_review")
SYSTEM_ACTOR_ID = 0
EMAIL_STATES: tuple[str, ...] = ("pending", "sent", "failed", "not_configured", "no_address")
# Roles whose holders are told. Viewers are client users; analysts do not
# manage tenants.
RECIPIENT_ROLES: tuple[str, ...] = ("admin", "super_admin")
LIST_MAX = 50
TITLE_MAX = 200
BODY_MAX = 2000

_SAVEPOINT = "operator_notices"


@dataclass(frozen=True)
class Recipient:
    id: int
    username: str
    email: str | None


@dataclass
class NoticeBatch:
    """What `notify_other_admins` did inside the caller's transaction."""
    # Who was to be told (the other admin+ operators) …
    recipients: list[int] = field(default_factory=list)
    # … and the notices actually created for them ([] on failure).
    notice_ids: list[int] = field(default_factory=list)
    # The failure CLASS when the notices could not be created (the change
    # still applies; the caller records this). None = created (possibly
    # zero of them: nobody else to tell).
    error: str | None = None

    def audit_json(self) -> dict[str, Any]:
        return {"recipients": list(self.recipients), "notices": list(self.notice_ids),
                "error": self.error}


def other_admins(conn: sqlite3.Connection, actor_id: int) -> list[Recipient]:
    """admin+ operators other than the actor, not disabled, not removed."""
    marks = ",".join("?" * len(RECIPIENT_ROLES))
    rows = conn.execute(
        "SELECT o.id, o.username, o.email FROM operators o "
        "WHERE o.id != ? AND o.disabled_at IS NULL AND o.removed_at IS NULL "
        f"AND EXISTS (SELECT 1 FROM operator_roles r WHERE r.operator_id = o.id "
        f"            AND r.role_name IN ({marks})) "
        "ORDER BY o.id",
        (actor_id, *RECIPIENT_ROLES),
    ).fetchall()
    return [Recipient(int(r[0]), str(r[1]), (r[2] or None)) for r in rows]


def notify_other_admins(
    conn: sqlite3.Connection, *, kind: str, actor_id: int, subject_slug: str,
    target_slug: str | None, change_request_id: int, title: str, body: str,
    request_id: str,
) -> NoticeBatch:
    """Inside the caller's registry transaction: one notice per other admin,
    under a savepoint. Never raises — a failure rolls back the savepoint only
    and comes back as `NoticeBatch.error`."""
    if kind not in KINDS:
        raise ValueError(f"notice kind must be one of {', '.join(KINDS)}")
    try:
        conn.execute(f"SAVEPOINT {_SAVEPOINT}")
    except Exception as exc:  # noqa: BLE001 — never fatal to the change
        logger.error("[notices] could not open savepoint: %s", type(exc).__name__)
        return NoticeBatch(error=type(exc).__name__)
    recipients: list[Recipient] = []
    try:
        recipients = other_admins(conn, actor_id)
        ids: list[int] = []
        for r in recipients:
            cur = conn.execute(
                "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, "
                "target_slug, change_request_id, title, body, request_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (r.id, kind, actor_id, subject_slug, target_slug, change_request_id,
                 title[:TITLE_MAX], body[:BODY_MAX], request_id),
            )
            ids.append(int(cur.lastrowid))
        conn.execute(f"RELEASE {_SAVEPOINT}")
        return NoticeBatch(recipients=[r.id for r in recipients], notice_ids=ids)
    except Exception as exc:  # noqa: BLE001 — never fatal to the change
        logger.error("[notices] could not create notices: %s", type(exc).__name__)
        try:
            conn.execute(f"ROLLBACK TO {_SAVEPOINT}")
            conn.execute(f"RELEASE {_SAVEPOINT}")
        except Exception as inner:  # noqa: BLE001
            logger.error("[notices] savepoint rollback failed: %s", type(inner).__name__)
        # Who was NOT told stays on record (the caller's audit marker).
        return NoticeBatch(recipients=[r.id for r in recipients], error=type(exc).__name__)


def all_admins(conn: sqlite3.Connection) -> list[Recipient]:
    """Every admin+ operator, not disabled, not removed (a platform notice
    has no actor to leave out)."""
    return other_admins(conn, SYSTEM_ACTOR_ID)


def notify_admins_system(
    conn: sqlite3.Connection, *, kind: str, title: str, body: str, request_id: str,
    subject_slug: str = "global",
) -> list[int]:
    """Inside the caller's registry transaction: one PLATFORM notice (actor
    0) per admin+ operator who has none with this `request_id` yet — so the
    same notice is never raised twice for one person, and an admin added
    later gets it at the next call. Returns the ids created. Raises on a
    registry fault (the caller decides; startup callers swallow it)."""
    if kind not in SYSTEM_KINDS:
        raise ValueError(f"system notice kind must be one of {', '.join(SYSTEM_KINDS)}")
    ids: list[int] = []
    for r in all_admins(conn):
        seen = conn.execute(
            "SELECT 1 FROM operator_notices WHERE kind = ? AND request_id = ? "
            "AND recipient_id = ? LIMIT 1", (kind, request_id, r.id),
        ).fetchone()
        if seen is not None:
            continue
        cur = conn.execute(
            "INSERT INTO operator_notices (recipient_id, kind, actor_id, subject_slug, "
            "target_slug, change_request_id, title, body, request_id, email_state) "
            "VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?, 'not_configured')",
            (r.id, kind, SYSTEM_ACTOR_ID, subject_slug, title[:TITLE_MAX], body[:BODY_MAX],
             request_id),
        )
        ids.append(int(cur.lastrowid))
    return ids


# ---------------------------------------------------------------------------
# Reads / acknowledgement (the recipient's own notices only)
# ---------------------------------------------------------------------------

THREAT_KIND_PREFIX = "threat_"


def _limited(threat_scope: Optional[list[str]]) -> tuple[str, list[Any]]:
    """The extra WHERE for a caller BELOW admin (an analyst — Tier Black's
    paging, 044): only the `threat_*` notices, and only about tenants still
    in their scope (`threat_scope`; ['*'] = every tenant). None = no limit
    (admin+)."""
    if threat_scope is None:
        return "", []
    sql = " AND substr(kind, 1, ?) = ?"
    args: list[Any] = [len(THREAT_KIND_PREFIX), THREAT_KIND_PREFIX]
    if threat_scope == ["*"]:
        return sql, args
    if not threat_scope:
        return " AND 0", []
    return (sql + f" AND subject_slug IN ({','.join('?' * len(threat_scope))})",
            args + list(threat_scope))


def list_for(
    conn: sqlite3.Connection, operator_id: int, *, include_acknowledged: bool = False,
    limit: int = LIST_MAX, threat_scope: Optional[list[str]] = None,
) -> list[sqlite3.Row]:
    extra, args = _limited(threat_scope)
    sql = "SELECT * FROM operator_notices WHERE recipient_id = ?" + extra
    if not include_acknowledged:
        sql += " AND acknowledged_at IS NULL"
    sql += " ORDER BY id DESC LIMIT ?"
    return conn.execute(sql, (operator_id, *args, max(1, min(limit, LIST_MAX)))).fetchall()


def open_count(conn: sqlite3.Connection, operator_id: int, *,
               threat_scope: Optional[list[str]] = None) -> int:
    extra, args = _limited(threat_scope)
    return int(conn.execute(
        "SELECT COUNT(*) FROM operator_notices WHERE recipient_id = ? AND acknowledged_at IS NULL"
        + extra, (operator_id, *args),
    ).fetchone()[0])


def get_for(conn: sqlite3.Connection, notice_id: int, operator_id: int, *,
            threat_scope: Optional[list[str]] = None) -> sqlite3.Row | None:
    """The notice — only when it is the operator's own (else None: another
    admin's notice is not theirs to see or acknowledge) and, below admin, a
    threat notice about a tenant still in their scope (`_limited`)."""
    extra, args = _limited(threat_scope)
    return conn.execute(
        "SELECT * FROM operator_notices WHERE id = ? AND recipient_id = ?" + extra,
        (notice_id, operator_id, *args),
    ).fetchone()


def acknowledge(
    conn: sqlite3.Connection, notice_id: int, operator_id: int, *, now: str | None = None,
) -> bool:
    """Inside the caller's transaction. True when this call acknowledged it
    (False: already acknowledged, or not the operator's)."""
    return conn.execute(
        "UPDATE operator_notices SET acknowledged_at = ? "
        "WHERE id = ? AND recipient_id = ? AND acknowledged_at IS NULL",
        (now or utcnow_iso(), notice_id, operator_id),
    ).rowcount == 1


def acknowledge_for_change(
    conn: sqlite3.Connection, change_request_id: int, operator_id: int, *, now: str | None = None,
) -> list[int]:
    """The operator's open notices about one change, acknowledged (reviewing
    the change after the fact is having seen it). Returns their ids."""
    ids = [int(r[0]) for r in conn.execute(
        "SELECT id FROM operator_notices WHERE change_request_id = ? AND recipient_id = ? "
        "AND acknowledged_at IS NULL ORDER BY id", (change_request_id, operator_id),
    ).fetchall()]
    for nid in ids:
        acknowledge(conn, nid, operator_id, now=now)
    return ids


# ---------------------------------------------------------------------------
# E-mail copy — after commit, never raises
# ---------------------------------------------------------------------------

_KIND_WORDS = {"single_attested_merge": "merge", "single_attested_offboard": "offboard"}


def email_text(*, kind: str, change_request_id: int, actor_id: int, at: str) -> tuple[str, str]:
    """(subject, body) of the e-mail copy — no tenant names, no attestation."""
    what = _KIND_WORDS.get(kind, "change")
    subject = f"Athena: single-person tenant {what} applied (change #{change_request_id})"
    body = (
        f"A super admin applied a tenant {what} on their own typed attestation, "
        "without a second approver (the attested single-person exception).\n\n"
        f"Change request: #{change_request_id}\n"
        f"Applied by: operator #{actor_id}\n"
        f"At: {at} (UTC)\n\n"
        "Tenant names are not sent by e-mail. Sign in to Athena to see the change and "
        "acknowledge this notice; an admin other than the one who applied it can record "
        "a post-review under Settings → Tenants → Single-person changes.\n"
    )
    return subject, body


def _append_system_audit(
    *, action: str, slug: str, change_request_id: int, after: dict[str, Any],
    reason: str, request_id: str,
) -> None:
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor="system", actor_kind="system", action=action,
            target_kind="tenant_change_request", target_id=str(change_request_id),
            client_slug=slug, after_state=after, reason=reason,
            request_id=request_id or str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()


def email_notices(
    notice_ids: list[int], *, kind: str, actor_id: int, subject_slug: str,
    change_request_id: int, request_id: str,
) -> Optional[dict[str, Any]]:
    """Send the e-mail copy of the given notices and record the outcome —
    per notice (email_state) and as ONE 'operator_notice_email' audit row.
    Returns the recorded outcome; None when even recording failed (logged).
    Never raises."""
    try:
        return _email_notices(
            notice_ids, kind=kind, actor_id=actor_id, subject_slug=subject_slug,
            change_request_id=change_request_id, request_id=request_id,
        )
    except Exception as exc:  # noqa: BLE001 — notification is never fatal
        logger.error("[notices] e-mail delivery failed: %s", type(exc).__name__)
        try:
            _append_system_audit(
                action="operator_notice_email_failed", slug=subject_slug,
                change_request_id=change_request_id,
                after={"kind": kind, "change_request_id": change_request_id,
                       "notices": list(notice_ids), "error": type(exc).__name__},
                reason=f"e-mail copy of the notices could not be sent or recorded: "
                       f"{type(exc).__name__}",
                request_id=request_id,
            )
        except Exception as inner:  # noqa: BLE001
            logger.error("[notices] could not audit the e-mail failure: %s",
                         type(inner).__name__)
        return None


def _email_notices(
    notice_ids: list[int], *, kind: str, actor_id: int, subject_slug: str,
    change_request_id: int, request_id: str,
) -> dict[str, Any]:
    reg = connect(paths.registry_db_path())
    try:
        if notice_ids:
            marks = ",".join("?" * len(notice_ids))
            rows = reg.execute(
                f"SELECT n.id, n.recipient_id, n.created_at, o.email FROM operator_notices n "
                f"JOIN operators o ON o.id = n.recipient_id "
                f"WHERE n.id IN ({marks}) ORDER BY n.id", list(notice_ids),
            ).fetchall()
        else:
            rows = []
        mailer = email_sender.resend_instance_mailer() if rows else None
        outcome: dict[str, list[int]] = {s: [] for s in EMAIL_STATES if s != "pending"}
        states: list[tuple[str, int]] = []
        for r in rows:
            if mailer is None:
                state = "not_configured"
            elif not (r["email"] or "").strip():
                state = "no_address"
            else:
                subject, body = email_text(
                    kind=kind, change_request_id=change_request_id, actor_id=actor_id,
                    at=r["created_at"],
                )
                state = "sent" if mailer(r["email"].strip(), subject, body) else "failed"
            outcome[state].append(int(r["recipient_id"]))
            states.append((state, int(r["id"])))
        now = utcnow_iso()
        with transaction(reg):
            for state, nid in states:
                reg.execute(
                    "UPDATE operator_notices SET email_state = ?, email_attempted_at = ? "
                    "WHERE id = ?",
                    (state, None if state == "not_configured" else now, nid),
                )
    finally:
        reg.close()
    summary = (
        "e-mail not configured (no Resend integration) — in-app notices only"
        if outcome["not_configured"] else
        f"e-mail copy: {len(outcome['sent'])} sent, {len(outcome['failed'])} failed, "
        f"{len(outcome['no_address'])} without an address"
    )
    after = {"kind": kind, "change_request_id": change_request_id,
             "notices": list(notice_ids), **outcome}
    _append_system_audit(
        action="operator_notice_email", slug=subject_slug,
        change_request_id=change_request_id, after=after, reason=summary,
        request_id=request_id,
    )
    return after
