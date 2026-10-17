"""Slice 0 of the PSA write design, outbound side (pure unit, no DB): the
AW03 outbound maps, the ticket payload, and the client's send guard.

Even with the writes switch off nothing here can be sent — these pin what
WOULD go out if the switch were flipped (or the code rolled back), so a
"low" can never again become an Autotask Critical."""
from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from apps.octo.adapters.autotask.client import (
    AutotaskClient,
    AutotaskConfig,
    AutotaskForbiddenFieldError,
    refuse_forbidden_fields,
)
from apps.octo.adapters.autotask.poller import (
    autotask_priority_to_severity,
    autotask_status_to_athena,
)
from apps.octo.adapters.autotask.writeback import (
    ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY,
    ATHENA_STATUS_TO_AUTOTASK,
    TicketNotSendable,
    _build_ticket_payload,
)


def _row(**over: Any) -> sqlite3.Row:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    values = {"title": "Printer offline", "description": "", "severity": "low",
              "status": "new", "billing_code_id": None, "contract_id": None}
    values.update(over)
    cols = ", ".join(f"? AS {k}" for k in values)
    return conn.execute(f"SELECT {cols}", tuple(values.values())).fetchone()


def test_outbound_low_is_3_not_critical():
    """AW03: 1 High, 2 Medium, 3 Low, 4 Critical, 5 Informational."""
    assert ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY["low"] == 3
    assert ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY["critical"] == 4
    assert ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY == {
        "critical": 4, "high": 1, "medium": 2, "low": 3, "info": 5}
    payload = _build_ticket_payload(autotask_company_id=9001, ticket_row=_row(severity="low"))
    assert payload["priority"] == 3
    assert payload["priority"] != 4


def test_outbound_severity_round_trips_through_the_inbound_map():
    for severity, value in ATHENA_SEVERITY_TO_AUTOTASK_PRIORITY.items():
        assert autotask_priority_to_severity(value) == severity


def test_outbound_status_has_no_closed_or_reopened_and_round_trips():
    assert "closed" not in ATHENA_STATUS_TO_AUTOTASK
    assert "reopened" not in ATHENA_STATUS_TO_AUTOTASK
    assert 12 not in ATHENA_STATUS_TO_AUTOTASK.values()
    assert 13 not in ATHENA_STATUS_TO_AUTOTASK.values()
    for status, value in ATHENA_STATUS_TO_AUTOTASK.items():
        assert autotask_status_to_athena(value) == status
    # Reopened is open work again: created as New (never an invented 13).
    payload = _build_ticket_payload(autotask_company_id=9001, ticket_row=_row(status="reopened"))
    assert payload["status"] == ATHENA_STATUS_TO_AUTOTASK["new"]


@pytest.mark.parametrize("status", ["closed", None, "", "bogus"])
def test_closed_ticket_is_never_built_as_a_new_autotask_ticket(status):
    """A ticket already closed in Athena must not land in the dispatch queue
    as a New Autotask ticket (nor as an invented 12): the payload builder
    refuses it, and so does anything outside the map."""
    with pytest.raises(TicketNotSendable):
        _build_ticket_payload(autotask_company_id=9001, ticket_row=_row(status=status))


def test_ticket_payload_never_carries_contract_id():
    payload = _build_ticket_payload(
        autotask_company_id=9001, ticket_row=_row(contract_id="4711", billing_code_id="29682"),
    )
    assert not any(k.lower() == "contractid" for k in payload)
    assert payload["billingCodeID"] == 29682


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method: str, url: str, **_kw: Any) -> Any:
        self.calls.append((method, url))
        raise AssertionError("no request may be made")


def test_client_send_guard_refuses_contract_id_before_any_http():
    rec = _Recorder()
    client = AutotaskClient(
        AutotaskConfig(username="api@example.test", secret="x", integration_code="y",
                       zone_url="https://zone.example.test/atservicesrest/v1.0/"),
        http_request=rec,
    )
    for key in ("contractID", "ContractId", "contractid"):
        with pytest.raises(AutotaskForbiddenFieldError):
            client.create_ticket({"companyID": 9001, "title": "t", key: 1})
        with pytest.raises(AutotaskForbiddenFieldError):
            client.create_ticket_charge({"ticketID": 1, key: 1})
    assert rec.calls == []
    refuse_forbidden_fields("Tickets", {"companyID": 9001})          # fine
    refuse_forbidden_fields("Tickets", ["contractID"])                # not an object: no-op
