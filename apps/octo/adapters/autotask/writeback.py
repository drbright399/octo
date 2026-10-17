"""Autotask write-back worker (P4-c2).

Mirror of `poller.py` but in the opposite direction: reads
`autotask_push_state` rows in 'pending' state across all tenants in
this adapter instance's tenant↔company map, builds Autotask Ticket /
TicketCharge payloads, POSTs them, and stamps the result back on the
Athena-side records.

----------------------------------------------------------------------
HANDOFF NOTE TO ZACK
----------------------------------------------------------------------
This file is INTENTIONALLY a scaffold. The Athena-side orchestration
(queue scan, state advance, retry, audit) is complete and exercised
by tests. The Autotask-specific field mappings have `TODO(zack)`
markers — fill those in with the real Autotask Ticket entity shape
your prior MSP experience covered better than mine.

Field-mapping reference + the open questions are in the 2026-05-14
Autotask write-back hand-off (archived outside the repo on 2026-10-16;
ask a maintainer for it).

The minimum to make this functional end-to-end:
  1. Replace the `_build_ticket_payload` placeholder with the real
     Ticket entity shape (accountID, status, priority, queueID,
     queueDetailID, issueType, subIssueType, etc.).
  2. Add a picklist-sync step so the static maps below match the
     MSP's live picklists. Use the autotask_picklist_cache table from
     migration 015 — there's already a row for it per instance.
  3. Decide the strategy for charge ordering (we POST the ticket
     first, then each charge — fine for now, but watch for partial-
     failure where ticket succeeds but a charge fails).
----------------------------------------------------------------------
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from apps.octo import paths
from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
)
from apps.octo.adapters.autotask.poller import (
    load_tenant_routing,
)
from apps.octo.adapters.autotask.writes_switch import instance_writes_enabled

logger = logging.getLogger(__name__)


DEFAULT_TICK_INTERVAL_SEC = 20.0
"""How often the writeback worker scans the outbox. Tighter than the
poller (which polls Autotask) because this scan is local-SQLite only."""


# ---------------------------------------------------------------------------
# Outbound picklist maps (Athena → Autotask): the INVERSE of the inbound AW03
# maps in poller.py, and kept in sync with them (a test round-trips both).
#
# TODO(zack): verify against the live AW03 picklist. Slice 1 replaces both
# directions with the picklist mirror (`autotask_picklist_values`).
#
# AW03 priority picklist: 1 = High, 2 = Medium, 3 = Low, 4 = Critical,
# 5 = Informational. The factory map this replaced (critical→1 … low→4) sent
# an Athena "low" as Critical on this instance.
# ---------------------------------------------------------------------------

ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY: dict[str, int] = {
    "critical": 4,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 5,
}

# No "closed" / "reopened": AW03 has no such ids (12 / 13 were the factory
# guess). An Athena status outside this map is never translated into one.
ATHENA_STATUS_TO_AUTOTASK: dict[str, int] = {
    "new": 1,
    "in_progress": 8,
    "waiting_customer": 7,
    "waiting_vendor": 9,
    "resolved": 5,
}

# Outbound only: a REOPENED Athena ticket is open work again, so it is created
# as New. A CLOSED one is never created at all (`TicketNotSendable`): a New
# ticket in the dispatch queue for finished work is the one thing this must
# not do, and a create that completes a ticket is the gated slice-3 action.
_OUTBOUND_STATUS_ALIASES: dict[str, str] = {"reopened": "new"}


class TicketNotSendable(ValueError):
    """The Athena row cannot become an Autotask ticket as it stands (e.g. it
    is closed in Athena). The pusher fails the row; nothing is POSTed."""


def _outbound_status(status: Optional[str]) -> int:
    key = _OUTBOUND_STATUS_ALIASES.get(status or "", status or "")
    if key not in ATHENA_STATUS_TO_AUTOTASK:
        raise TicketNotSendable(
            f"the ticket is {status or 'without a status'} in Athena; it is not "
            "created in Autotask")
    return ATHENA_STATUS_TO_AUTOTASK[key]


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _build_ticket_payload(
    *,
    autotask_company_id: int,
    ticket_row: sqlite3.Row,
) -> dict[str, Any]:
    """Convert an Athena tickets.db row into an Autotask Ticket entity
    payload. Raises TicketNotSendable for a row Autotask must not get (a
    ticket already closed in Athena).

    TODO(zack): this is the minimum viable shape. Autotask Tickets has
    many additional fields — queueID, queueDetailID, issueType,
    subIssueType, source, resolvedByResourceID, etc. — that the
    operator's workflow probably wants populated. Wire them in here.
    The Athena ticket fields you'd want to map FROM include:
      - assignee_operator_id   → assignedResourceID (via
        autotask_operator_resource_map lookup)
      - queue                  → queueID (free-text in Athena;
        will need a queue↔queueID map)
      - source_event_id        → externalID or a custom field
      - opened_at              → createDate
    """
    severity = ticket_row["severity"]
    status = ticket_row["status"]
    return {
        "companyID": autotask_company_id,
        "title": ticket_row["title"],
        "description": ticket_row["description"] or "",
        "priority": ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY.get(
            severity, ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY["medium"]),
        "status": _outbound_status(status),
        # `billingCodeID` is optional — Autotask uses account default
        # when not supplied. NOTE: Autotask uses an Integer ID, but we
        # store as TEXT for picklist-opacity, so coerce only when set.
        **(
            {"billingCodeID": int(ticket_row["billing_code_id"])}
            if (ticket_row["billing_code_id"] or "").isdigit() else {}
        ),
        # NEVER `contractID` (PSA write design, invariant 1): Autotask uses
        # the company default contract. The local `contract_id` column stays
        # Athena-side metadata only, and the client's send guard refuses a
        # payload that names it.
        # `dueDateTime` defaults to now+24h per the strategic decision
        # (Autotask round-trip design). TODO(zack): per-tenant override.
        "dueDateTime": _due_iso_now_plus(24),
    }


def _build_charge_payload(
    *,
    autotask_ticket_id: int,
    charge_row: sqlite3.Row,
) -> dict[str, Any]:
    """Convert an Athena ticket_charges row into an Autotask
    TicketCharge entity payload. TODO(zack): verify field names — the
    Autotask docs distinguish chargeType / billableToAccount / status
    that we're not currently setting."""
    payload: dict[str, Any] = {
        "ticketID": autotask_ticket_id,
        "name": charge_row["name"],
        "description": charge_row["description"] or "",
        "unitCost": float(charge_row["unit_cost"] or 0),
        "unitPrice": float(charge_row["unit_price"] or 0),
        "unitQuantity": float(charge_row["quantity"] or 0),
        "isBillableToCompany": bool(charge_row["is_billable"]),
    }
    if charge_row["billing_code_id"]:
        try:
            payload["billingCodeID"] = int(charge_row["billing_code_id"])
        except ValueError:
            pass
    return payload


def _due_iso_now_plus(hours: int) -> str:
    from datetime import timedelta
    dt = datetime.now(timezone.utc) + timedelta(hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _digest(obj: dict[str, Any]) -> str:
    """Short hex digest of the JSON payload — surfaces in
    autotask_push_log so the operator can confirm "same payload"
    across retries without storing the full body."""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Per-tenant outbox scan
# ---------------------------------------------------------------------------

def _select_pending(
    tenant_slug: str, *, max_batch: int = 50,
) -> list[sqlite3.Row]:
    """Return the next batch of tickets to push for `tenant_slug`.

    Picks rows where `autotask_push_state.state = 'pending'` AND the
    ticket has push_to_autotask=1 (defense-in-depth — if the operator
    flipped the opt-in OFF between enqueue and now, we don't push).
    Oldest-queued first so retries don't starve."""
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    if not tdb.exists():
        return []
    conn = sqlite3.connect(f"file:{tdb}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute(
            "SELECT t.id AS ticket_id, t.title, t.description, t.severity, "
            "       t.status, t.assignee_operator_id, t.queue, "
            "       t.source_event_id, t.opened_at, "
            "       t.push_to_autotask, t.is_billable, "
            "       t.billing_code_id, t.contract_id, "
            "       s.attempts AS push_attempts, "
            "       s.queued_by_operator_id "
            "  FROM tickets t "
            "  JOIN autotask_push_state s ON s.ticket_id = t.id "
            " WHERE s.state = 'pending' AND t.push_to_autotask = 1 "
            " ORDER BY s.queued_at ASC LIMIT ?",
            (max_batch,),
        ).fetchall())
    finally:
        conn.close()


def _mark_in_flight(tenant_slug: str, ticket_id: int) -> bool:
    """CLAIM the row: 'pending' → 'in_flight' in one conditional UPDATE. True
    only for the caller whose UPDATE moved it; a row another pusher already
    claimed (or that left 'pending' since it was selected) returns False and
    must not be sent — Autotask tickets are permanent, so a lost claim is a
    skipped row, never a second POST."""
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(tdb)
    try:
        cur = conn.execute(
            "UPDATE autotask_push_state "
            "SET state = 'in_flight', "
            "    attempts = attempts + 1, "
            "    last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
            "WHERE ticket_id = ? AND state = 'pending'",
            (ticket_id,),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def _mark_pushed(
    tenant_slug: str, ticket_id: int, autotask_ticket_id: str,
) -> None:
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(tdb)
    try:
        conn.execute(
            "UPDATE tickets SET autotask_id = ?, "
            "  last_autotask_sync_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
            "  updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
            "WHERE id = ?",
            (autotask_ticket_id, ticket_id),
        )
        conn.execute(
            "UPDATE autotask_push_state SET state = 'pushed', "
            "  autotask_ticket_id = ?, last_error = NULL "
            "WHERE ticket_id = ?",
            (autotask_ticket_id, ticket_id),
        )
        conn.commit()
    finally:
        conn.close()


def _mark_failed(
    tenant_slug: str, ticket_id: int, error_message: str,
) -> None:
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(tdb)
    try:
        conn.execute(
            "UPDATE autotask_push_state SET state = 'failed', "
            "  last_error = ? WHERE ticket_id = ?",
            (error_message[:2000], ticket_id),
        )
        conn.commit()
    finally:
        conn.close()


def _log_attempt(
    tenant_slug: str, *,
    ticket_id: int, action: str, outcome: str,
    payload: dict[str, Any],
    autotask_response_id: Optional[str] = None,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    operator_id: Optional[int] = None,
) -> None:
    """Append a row to autotask_push_log. Append-only — never UPDATE."""
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(tdb)
    try:
        conn.execute(
            "INSERT INTO autotask_push_log "
            "(ticket_id, action, outcome, autotask_response_id, "
            " error_code, error_message, payload_digest, operator_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, action, outcome, autotask_response_id,
             error_code, error_message, _digest(payload), operator_id),
        )
        conn.commit()
    finally:
        conn.close()


def _list_unpushed_charges(
    tenant_slug: str, ticket_id: int,
) -> list[sqlite3.Row]:
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(f"file:{tdb}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute(
            "SELECT id, name, description, unit_cost, unit_price, "
            "       quantity, is_billable, billing_code_id "
            "  FROM ticket_charges "
            " WHERE ticket_id = ? AND autotask_charge_id IS NULL "
            " ORDER BY id ASC",
            (ticket_id,),
        ).fetchall())
    finally:
        conn.close()


def _mark_charge_pushed(
    tenant_slug: str, charge_id: int, autotask_charge_id: str,
) -> None:
    tdb = paths.client_dir(tenant_slug) / "tickets.db"
    conn = sqlite3.connect(tdb)
    try:
        conn.execute(
            "UPDATE ticket_charges SET autotask_charge_id = ?, "
            "  last_pushed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
            "WHERE id = ?",
            (autotask_charge_id, charge_id),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class AutotaskPusher:
    """Run loop: scan every mapped tenant's tickets.db for pending push
    rows, build payload, POST, advance state.

    Lifecycle mirrors AutotaskPoller — start()/stop()/tick_once(). Both
    workers can run side-by-side under the same AutotaskSourceAdapter.
    """

    def __init__(
        self,
        *,
        client: AutotaskClient,
        adapter_instance_id: int,
        tick_interval_sec: float = DEFAULT_TICK_INTERVAL_SEC,
        max_batch_per_tenant: int = 25,
        writes_enabled: Optional[Callable[[], bool]] = None,
    ) -> None:
        self._client = client
        self._instance_id = adapter_instance_id
        # The kill switch, re-read before every send (writes_switch.py). The
        # default reads THIS instance's persisted switch from the registry
        # and fails closed — a pusher whose live stop never arrived still
        # sends nothing once the switch is off.
        self._writes_enabled: Callable[[], bool] = writes_enabled or (
            lambda: instance_writes_enabled(adapter_instance_id))
        self._tick_interval = tick_interval_sec
        self._max_batch = max_batch_per_tenant
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        # Counters surfaced in the integration-status UI.
        self.last_cycle_pushed = 0
        self.last_cycle_failed = 0
        self.last_cycle_charges_pushed = 0
        self.last_cycle_refused = False

    def _allowed(self) -> bool:
        try:
            return self._writes_enabled() is True
        except Exception:  # noqa: BLE001 — the switch fails CLOSED
            logger.exception("Autotask pusher: writes switch unreadable — not sending")
            return False

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stopping.set()
        try:
            await asyncio.wait_for(self._task, timeout=self._tick_interval + 5.0)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.to_thread(self.tick_once)
            except AutotaskAuthError as e:
                logger.error("Autotask pusher auth failure (will retry): %s", e)
            except AutotaskClientError as e:
                logger.error("Autotask pusher client error (will retry): %s", e)
            except Exception:  # noqa: BLE001
                logger.exception("Autotask pusher crashed in tick_once")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._tick_interval,
                )
            except asyncio.TimeoutError:
                pass

    def tick_once(self) -> None:
        """One synchronous push cycle across every mapped tenant. Test-
        callable without an event loop."""
        allowed = self._allowed()
        self.last_cycle_pushed = 0
        self.last_cycle_failed = 0
        self.last_cycle_charges_pushed = 0
        self.last_cycle_refused = not allowed
        if not allowed:
            return

        # tenant_company_map: {at_company_id: tenant_slug}. The
        # writeback worker iterates by tenant, but needs the company_id
        # for the Ticket payload, so we invert it here.
        routing = load_tenant_routing(self._instance_id)
        tenant_to_company = {slug: aid for aid, slug in routing.items()}

        for tenant_slug, at_company_id in tenant_to_company.items():
            for row in _select_pending(tenant_slug, max_batch=self._max_batch):
                # Re-checked before EVERY send: a switch-off mid-cycle stops
                # the next POST, and the row stays 'pending' (untouched).
                if not self._allowed():
                    self.last_cycle_refused = True
                    return
                ticket_id = row["ticket_id"]
                if not _mark_in_flight(tenant_slug, ticket_id):
                    # Claimed by someone else (or no longer pending): theirs.
                    continue
                try:
                    payload = _build_ticket_payload(
                        autotask_company_id=at_company_id, ticket_row=row,
                    )
                except TicketNotSendable as exc:
                    msg = str(exc)
                    _mark_failed(tenant_slug, ticket_id, msg)
                    _log_attempt(
                        tenant_slug, ticket_id=ticket_id,
                        action="create_ticket", outcome="error",
                        payload={"status": row["status"]},
                        error_code="NOT_SENDABLE",
                        error_message=msg,
                        operator_id=row["queued_by_operator_id"],
                    )
                    self.last_cycle_failed += 1
                    continue
                try:
                    resp = self._client.create_ticket(payload)
                except (AutotaskAuthError, AutotaskClientError) as exc:
                    msg = str(exc)
                    _mark_failed(tenant_slug, ticket_id, msg)
                    _log_attempt(
                        tenant_slug, ticket_id=ticket_id,
                        action="create_ticket", outcome="error",
                        payload=payload,
                        error_code=exc.__class__.__name__,
                        error_message=msg,
                        operator_id=row["queued_by_operator_id"],
                    )
                    self.last_cycle_failed += 1
                    continue

                # Autotask returns `{"itemId": <id>}` on POST.
                at_ticket_id = resp.get("itemId")
                if at_ticket_id is None:
                    _mark_failed(tenant_slug, ticket_id,
                                 "Autotask POST returned no itemId")
                    _log_attempt(
                        tenant_slug, ticket_id=ticket_id,
                        action="create_ticket", outcome="error",
                        payload=payload,
                        error_code="MISSING_ITEM_ID",
                        error_message="Autotask returned 2xx with no itemId",
                        operator_id=row["queued_by_operator_id"],
                    )
                    self.last_cycle_failed += 1
                    continue

                _mark_pushed(tenant_slug, ticket_id, str(at_ticket_id))
                _log_attempt(
                    tenant_slug, ticket_id=ticket_id,
                    action="create_ticket", outcome="success",
                    payload=payload,
                    autotask_response_id=str(at_ticket_id),
                    operator_id=row["queued_by_operator_id"],
                )
                self.last_cycle_pushed += 1

                # Push each unpushed charge. Partial-failure note: if a
                # charge fails the ticket is already created on the AT
                # side; we leave the charge in the unpushed pile so a
                # retry POST /push-to-autotask will retry just the
                # charges (the ticket-side is idempotent because
                # autotask_id is now set, so we'll add charge-only
                # mode in P4-c2 follow-up). TODO(zack).
                for ch in _list_unpushed_charges(tenant_slug, ticket_id):
                    if not self._allowed():
                        self.last_cycle_refused = True
                        return
                    ch_payload = _build_charge_payload(
                        autotask_ticket_id=at_ticket_id, charge_row=ch,
                    )
                    try:
                        ch_resp = self._client.create_ticket_charge(ch_payload)
                    except (AutotaskAuthError, AutotaskClientError) as exc:
                        _log_attempt(
                            tenant_slug, ticket_id=ticket_id,
                            action="create_charge", outcome="error",
                            payload=ch_payload,
                            error_code=exc.__class__.__name__,
                            error_message=str(exc),
                            operator_id=row["queued_by_operator_id"],
                        )
                        continue
                    ch_id = ch_resp.get("itemId")
                    if ch_id is not None:
                        _mark_charge_pushed(
                            tenant_slug, ch["id"], str(ch_id),
                        )
                        _log_attempt(
                            tenant_slug, ticket_id=ticket_id,
                            action="create_charge", outcome="success",
                            payload=ch_payload,
                            autotask_response_id=str(ch_id),
                            operator_id=row["queued_by_operator_id"],
                        )
                        self.last_cycle_charges_pushed += 1
