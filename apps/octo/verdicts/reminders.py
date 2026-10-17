"""The review reminder of an expected condition — 7 days before its review
date, ONE notice to the admins in the tenant's scope (the tier worker's
fleet-wide pass calls `send_due`; idempotent by the notice's request id and
the condition's `reminded_at`). On the review date the condition simply
stops matching: there is no silent renewal — keeping it means a person
marks the alert expected again (a new decision, a new rule)."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from apps.octo import paths
from apps.octo.db import connect, transaction
from apps.octo.verdicts import store as vstore

logger = logging.getLogger(__name__)


def send_due(now: datetime) -> list[int]:
    """Remind the admins of every condition within 7 days of review. Returns
    the condition ids reminded. Never raises."""
    from apps.octo.threat import audit as taudit
    from apps.octo.threat import notify

    done: list[int] = []
    for rule in vstore.due_reminders(now):
        day = rule.review_at[:10]
        sent = notify.notify_admins(
            kind="threat_registry", slug=rule.slug,
            title=f"Expected condition #{rule.id} at {rule.slug} reaches its review on {day}",
            body=(f"\"{rule.label}\" stops being labelled expected on {day} (no renewal). "
                  f"Reason given: {rule.reason}. Review it in Settings → Threats; to keep it, "
                  "mark a new alert of it expected again."),
            request_id=f"expected:{rule.id}:review")
        if sent.error:
            continue
        taudit.system("expected.review_reminder", rule.slug, "expected_condition", str(rule.id),
                      after={"review_at": rule.review_at, "recipients": sent.recipients},
                      reason="an expected condition reaches its review date within 7 days")
        try:
            reg = connect(paths.registry_db_path())
            try:
                with transaction(reg):
                    vstore.mark_reminded(reg, rule.id, now)
            finally:
                reg.close()
        except Exception as exc:  # noqa: BLE001 — the notice id keeps it to one notice
            logger.warning("[verdicts] reminder of #%s not stamped (%s)", rule.id,
                           type(exc).__name__)
            continue
        done.append(rule.id)
    return done


def send_due_safely(now: datetime) -> Optional[list[int]]:
    try:
        return send_due(now)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[verdicts] review reminders failed (%s)", type(exc).__name__)
        return None
