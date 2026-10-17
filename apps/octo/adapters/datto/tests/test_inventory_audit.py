"""The Datto device AUDIT (v0.17.3, Rick's decision A of 2026-10-07: "useful
to know what device is throwing the alert") — the REAL DattoClient /
InventoryPoller / entity consumer against the fake Datto transport.

  * the client keeps FOUR values of the audit (the BIOS / base-board serial,
    the system manufacturer and model) — never the user name, a network
    interface, a MAC or an address, a UDF, a URL or the software;
  * a placeholder serial ("To Be Filled By O.E.M.", "Default string", all
    zeros, …) is none; vendor text is cleaned and bounded;
  * the budget: at most 40 audits a round (one audit round per 30 minutes),
    a device again after 7 days, missing devices and device types without a
    `device` audit never asked;
  * an HTTP 429 ends the round and holds the next ones (the device lists
    too — one hold); a failed audit is tried again NEXT round, behind the
    devices not tried yet;
  * each round logs COUNTS only — never a serial, a model or a uid.

Fictional tenants and devices; documentation / RFC 1918 addresses only."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

import pytest

from apps.octo.adapters.datto.client import (
    AUDIT_FIELDS,
    DattoAuditShapeError,
    DattoClientError,
    DattoNotFoundError,
)
from apps.octo.adapters.datto.inventory import (
    AUDIT_MAX_PER_ROUND,
    audit_record,
    is_placeholder_serial,
    ocsf_device,
)
from apps.octo.adapters.datto.tests.fake_datto import (
    AUDIT_PATH_PREFIX,
    AUDIT_SECRETS,
    device_audit,
    inventory_device,
    real_client,
)
from apps.octo.adapters.datto.tests.test_inventory import T0, _devices, inv  # noqa: F401
from apps.octo.entity.db import TenantDB
from apps.octo.tests.instances.test_manager import bedrock_root  # noqa: F401


def _audit_calls(transport) -> list[str]:
    return [p[len(AUDIT_PATH_PREFIX):] for _m, p in transport.calls
            if p.startswith(AUDIT_PATH_PREFIX)]


def _fleet(transport, n: int, *, site: str = "site-a", prefix: str = "dev") -> list[str]:
    uids = [f"{prefix}-{i:04d}" for i in range(n)]
    transport.site_devices[site] = [inventory_device(u, f"WS-{u}", site_uid=site) for u in uids]
    for i, u in enumerate(uids):
        transport.audits[u] = device_audit(serial=f"EXAMPLE-SN-{i:04d}")
    return uids


# ---------------------------------------------------------------------------
# The client: four values, nothing else
# ---------------------------------------------------------------------------

def test_the_client_keeps_only_the_four_allowlisted_values(inv):  # noqa: F811
    transport, _poller, _clock, _rec = inv
    transport.audits["dev-1"] = device_audit()
    got = real_client(transport).device_audit("dev-1")
    assert set(got) == {f"{o}.{f}" for o, f in AUDIT_FIELDS} == {
        "bios.serialNumber", "baseBoard.serialNumber", "systemInfo.manufacturer",
        "systemInfo.model"}
    assert got == {"bios.serialNumber": "EXAMPLE-SN-0001", "baseBoard.serialNumber":
                   "EXAMPLE-MB-0001", "systemInfo.manufacturer": "Example Computers Inc.",
                   "systemInfo.model": "Example Model 7090"}
    blob = json.dumps(got).lower()
    for secret in AUDIT_SECRETS + ("username", "macaddress", "udf", "url", "software"):
        assert secret.lower() not in blob, secret
    # Never a user name, an interface, a URL — by name, at the socket's edge.
    assert not [f for o, f in AUDIT_FIELDS if f.lower() in ("username", "macaddress")
                or "url" in f.lower() or o in ("networkInterfaces", "udf", "software")]


@pytest.mark.parametrize("body", [
    {"bios": {"serialNumber": 12345}, "baseBoard": {"serialNumber": ["A"]},
     "systemInfo": {"manufacturer": {"x": 1}, "model": True}},   # wrong-typed values
    {"bios": {"serialNumber": None}, "systemInfo": {"model": None}},  # named, null
    {"bios": {"serialNumber": "x" * 3}, "baseBoard": None, "systemInfo": []},
])
def test_a_missing_or_wrong_typed_key_is_none(inv, body):  # noqa: F811
    transport, _poller, _clock, _rec = inv
    transport.audits["dev-1"] = body
    got = real_client(transport).device_audit("dev-1")
    assert set(got) == {f"{o}.{f}" for o, f in AUDIT_FIELDS}
    assert all(v is None for k, v in got.items() if k != "bios.serialNumber")
    assert audit_record(got) == {"serial": None, "manufacturer": None, "model": None}


@pytest.mark.parametrize("body", [
    {},                                                       # nothing at all
    {"bios": None, "baseBoard": "x", "systemInfo": []},       # wrong-typed objects
    {"error": "fixture: something went wrong"},               # an error object, HTTP 200
    {"bios": {"serial": "EXAMPLE-SN-0001"},                   # another shape: none of
     "system": {"manufacturer": "Example"}},                  # the four keys named
    [{"bios": {"serialNumber": "EXAMPLE-SN-0001"}}],          # not an object
])
def test_an_answer_naming_none_of_the_four_fields_is_a_failed_audit(inv, body):  # noqa: F811
    """Not "this device has no serial" (stored, stamped for 7 days, and a
    first live round reading 'serials found 0 · failed 0'): an answer this
    build cannot read is a FAILED audit."""
    transport, _poller, _clock, _rec = inv
    transport.audits["dev-1"] = body
    with pytest.raises(DattoAuditShapeError) as err:
        real_client(transport).device_audit("dev-1")
    assert isinstance(err.value, DattoClientError)
    assert "EXAMPLE" not in str(err.value) and "fixture" not in str(err.value)


def test_a_uid_not_shaped_like_one_is_never_sent_and_404_is_its_own_error(inv):  # noqa: F811
    transport, _poller, _clock, _rec = inv
    client = real_client(transport)
    for bad in ("../account", "a/b", "", "x" * 200):
        with pytest.raises(ValueError):
            client.device_audit(bad)
    assert _audit_calls(transport) == []
    with pytest.raises(DattoNotFoundError):
        client.device_audit("dev-unknown")


# ---------------------------------------------------------------------------
# Placeholder serials, cleaning
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("serial", [
    "To Be Filled By O.E.M.", "to be filled by o.e.m", "TO BE FILLED BY OEM", "Default string",
    "System Serial Number", "0", "None", "N/A", "n/a", "NA", "0000000000", "00000000-0000-0000",
    "   ", "", "\t\n", "Not Specified", "Unknown", "Chassis Serial Number", "XXXXXXXXXX",
    "........", "-", None, 1234, ["SN"],
])
def test_a_placeholder_serial_is_none(serial):
    assert is_placeholder_serial(serial)
    rec = audit_record({"bios.serialNumber": serial, "baseBoard.serialNumber": serial})
    assert rec["serial"] is None


def test_the_base_board_serial_stands_in_and_vendor_text_is_cleaned_and_bounded():
    rec = audit_record({"bios.serialNumber": "Default string",
                        "baseBoard.serialNumber": "  MB-‮1234\x00 5678  ",
                        "systemInfo.manufacturer": "System manufacturer",
                        "systemInfo.model": "Example​ Model " + "9" * 200})
    assert rec["serial"] == "MB- 1234 5678"
    assert rec["manufacturer"] is None                     # a placeholder too
    assert rec["model"].startswith("Example") and len(rec["model"]) <= 80
    assert "‮" not in json.dumps(rec, ensure_ascii=False)
    long = audit_record({"bios.serialNumber": "S" + "N" * 300})
    assert len(long["serial"]) == 64
    real = audit_record({"bios.serialNumber": "EXAMPLE-SN-0001",
                         "baseBoard.serialNumber": "EXAMPLE-MB-0001"})
    assert real["serial"] == "EXAMPLE-SN-0001"             # the BIOS serial first


def test_ocsf_names_the_serial_vendor_and_model_at_the_boundary():
    rec = audit_record({"bios.serialNumber": "EXAMPLE-SN-0001",
                        "systemInfo.manufacturer": "Example Computers Inc.",
                        "systemInfo.model": "Example Model 7090"})
    o = ocsf_device({"uid": "dev-1"}, site_uid="site-a", polled_at="2026-10-07T12:00:00.000Z",
                    audit=rec)
    d = o["device"]
    assert d["hw_info"] == {"serial_number": "EXAMPLE-SN-0001"}
    assert (d["vendor_name"], d["model"], d["uid"]) == \
        ("Example Computers Inc.", "Example Model 7090", "dev-1")
    assert o["class_uid"] == 5001 and o["metadata"]["version"] == "1.3.0"
    bare = ocsf_device({"uid": "dev-2"}, site_uid="site-a", polled_at="x",
                       audit=audit_record({}))
    assert not {"hw_info", "vendor_name", "model"} & set(bare["device"])


# ---------------------------------------------------------------------------
# The poller: stored, budgeted, never a hot loop
# ---------------------------------------------------------------------------

def test_an_audit_is_stored_on_the_device_and_nothing_else_of_it(inv, caplog):  # noqa: F811
    transport, poller, clock, _rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    transport.site_devices["site-b"] = [inventory_device("dev-b1", "BAKERY-PC",
                                                         site_uid="site-b")]
    transport.audits["dev-1"] = device_audit()
    transport.audits["dev-b1"] = device_audit(serial="To Be Filled By O.E.M.",
                                              baseboard_serial="Default string",
                                              manufacturer="Example Builder", model="Mini")
    caplog.set_level(logging.DEBUG)
    out = poller.run_once()
    assert out["audits"] == {"read": 2, "serials": 1, "failed": 0}
    (row,) = _devices()
    assert (row["serial"], row["manufacturer"], row["model"], row["audit_at"]) == \
        ("EXAMPLE-SN-0001", "Example Computers Inc.", "Example Model 7090",
         "2026-10-01T14:00:00.000Z")
    (bakery,) = _devices("example-bakery")                  # switch OFF: still audited (D)
    assert (bakery["serial"], bakery["manufacturer"], bakery["model"]) == \
        (None, "Example Builder", "Mini")
    assert bakery["audit_at"] == "2026-10-01T14:00:00.000Z"   # "no serial" is an answer
    for slug in ("acme-corp", "example-bakery"):
        blob = json.dumps(_devices(slug)) + TenantDB.for_tenant(slug).path.read_bytes() \
            .decode("latin-1")
        for secret in AUDIT_SECRETS:
            assert secret.lower() not in blob.lower(), secret
    # The log line is COUNTS only.
    assert "[datto-inventory] audits read 2 · serials found 1 · failed 0" in caplog.text
    for word in ("EXAMPLE-SN", "Example Model", "Example Computers", "dev-1", "dev-b1",
                 "Mini") + AUDIT_SECRETS:
        assert word.lower() not in caplog.text.lower(), word


def test_forty_a_round_then_again_after_seven_days(inv):  # noqa: F811
    transport, poller, clock, _rec = inv
    uids = _fleet(transport, 100)
    transport.site_devices["site-b"] = []
    out = poller.run_once()
    assert out["audits"]["read"] == AUDIT_MAX_PER_ROUND == 40
    assert len(_audit_calls(transport)) == 40
    # A second call inside the same 30 minutes reads no audit (nor a list).
    clock.t = T0 + timedelta(minutes=10)
    assert "audits" not in poller.run_once() and len(_audit_calls(transport)) == 40
    for step in (1, 2):
        clock.t = T0 + timedelta(minutes=30 * step)
        poller.run_once()
    calls = _audit_calls(transport)
    assert len(calls) == 100 and sorted(calls) == uids          # each device ONCE
    assert all(r["serial"] for r in _devices())
    clock.t = T0 + timedelta(minutes=120)
    assert poller.run_once()["audits"] == {"read": 0, "serials": 0, "failed": 0}
    # Seven days on, the oldest audits are read again — 40 a round.
    clock.t = T0 + timedelta(days=7, minutes=1)
    assert poller.run_once()["audits"]["read"] == 40
    assert len(_audit_calls(transport)) == 140


def test_missing_devices_and_devices_without_a_device_audit_are_never_asked(inv):  # noqa: F811
    transport, poller, clock, _rec = inv
    transport.site_devices["site-a"] = [
        inventory_device("dev-pc", "WS-1", site_uid="site-a"),
        inventory_device("dev-gone", "WS-2", site_uid="site-a"),
        inventory_device("dev-esx", "ESX-1", site_uid="site-a", category="ESXi Host"),
        inventory_device("dev-prn", "PRN-1", site_uid="site-a", category="Printer"),
        inventory_device("dev-sw", "SW-1", site_uid="site-a", category="Network Device")]
    transport.site_devices["site-b"] = []
    transport.audit_status = 502                       # nothing is read this round
    poller.run_once()
    assert sorted(_audit_calls(transport)) == ["dev-gone", "dev-pc"]
    transport.audit_status = None
    transport.audits.update({"dev-pc": device_audit(), "dev-gone": device_audit()})
    transport.site_devices["site-a"] = [d for d in transport.site_devices["site-a"]
                                        if d["uid"] != "dev-gone"]
    clock.t = T0 + timedelta(minutes=30)
    out = poller.run_once()
    assert out["audits"] == {"read": 1, "serials": 1, "failed": 0}
    assert _audit_calls(transport)[-1:] == ["dev-pc"]   # dev-gone is missing now: skipped
    assert "dev-esx" not in _audit_calls(transport) and "dev-prn" not in _audit_calls(transport)


def test_a_failed_audit_is_tried_next_round_behind_the_untried_ones(inv):  # noqa: F811
    transport, poller, clock, _rec = inv
    uids = _fleet(transport, 45)
    transport.site_devices["site-b"] = []
    broken = uids[:5]
    for u in broken:
        del transport.audits[u]                        # 404 for these five
    out = poller.run_once()
    assert out["audits"] == {"read": 35, "serials": 35, "failed": 5}
    first = _audit_calls(transport)
    assert len(first) == 40 and len(set(first)) == 40  # never twice in a round
    # Next round: the five never tried go FIRST, then the five that failed.
    clock.t = T0 + timedelta(minutes=30)
    out = poller.run_once()
    second = _audit_calls(transport)[40:]
    assert second[:5] == uids[40:] and sorted(second[5:]) == broken
    assert out["audits"] == {"read": 5, "serials": 5, "failed": 5}
    # The vendor fixes them: the round after reads them.
    for i, u in enumerate(broken):
        transport.audits[u] = device_audit(serial=f"EXAMPLE-SN-B{i}")
    clock.t = T0 + timedelta(minutes=60)
    assert poller.run_once()["audits"] == {"read": 5, "serials": 5, "failed": 0}


def test_an_unreadable_audit_shape_is_failed_not_stamped_and_logged_as_such(inv, caplog):  # noqa: F811
    """The first live round must SHOW a shape this build does not read: the
    devices count as failed (never "read · serials found 0"), nothing is
    stored or stamped, they are asked again next round — and once Datto's
    answer is readable they are read at once, not after 7 days."""
    transport, poller, clock, _rec = inv
    uids = _fleet(transport, 3)
    transport.site_devices["site-b"] = []
    for u in uids:
        transport.audits[u] = {"error": "fixture", "deviceAudit": {"sn": "EXAMPLE-SN-X"}}
    caplog.set_level(logging.INFO)
    out = poller.run_once()
    assert out["audits"] == {"read": 0, "serials": 0, "failed": 3}
    assert "[datto-inventory] audits read 0 · serials found 0 · failed 3" in caplog.text
    assert "3 audits answered in a shape this build does not read" in caplog.text
    for word in uids + ["EXAMPLE-SN-X", "fixture"]:
        assert word.lower() not in caplog.text.lower(), word
    assert all(r["audit_at"] is None and r["serial"] is None for r in _devices())
    for i, u in enumerate(uids):
        transport.audits[u] = device_audit(serial=f"EXAMPLE-SN-{i:04d}")
    clock.t = T0 + timedelta(minutes=30)
    assert poller.run_once()["audits"] == {"read": 3, "serials": 3, "failed": 0}
    assert all(r["serial"] and r["audit_at"] for r in _devices())


def test_a_429_on_an_audit_ends_the_round_and_holds_the_lists_too(inv, caplog):  # noqa: F811
    """Datto blocks an IP that keeps calling after HTTP 429 — and the alerts
    poller shares that IP and token: one 429 on an audit stops the audits AND
    holds the next rounds (device lists included) exactly as a 429 on a list
    does."""
    transport, poller, clock, _rec = inv
    _fleet(transport, 10)
    transport.site_devices["site-b"] = []
    transport.audit_status, transport.audit_retry_after = 429, "1800"
    caplog.set_level(logging.INFO)
    out = poller.run_once()
    assert len(_audit_calls(transport)) == 1 and out.get("held_until")
    assert out["audits"] == {"read": 0, "serials": 0, "failed": 1}
    assert "HTTP 429" in caplog.text
    lists = len([p for _m, p in transport.calls if p.startswith("/api/v2/site/")])
    clock.t = T0 + timedelta(minutes=20)              # Retry-After: 30 min
    assert poller.run_once().get("held_until")
    assert len(_audit_calls(transport)) == 1
    assert len([p for _m, p in transport.calls if p.startswith("/api/v2/site/")]) == lists
    # The hold is the INVENTORY's: the alerts poller's reads (same client,
    # same token) are never held by it.
    assert poller._client.fetch_alerts_since("2026-10-01T00:00:00Z") == []
    transport.audit_status = None
    clock.t = T0 + timedelta(minutes=31)
    out = poller.run_once()
    assert not out.get("held_until") and out["sites"] == 2
    assert out["audits"] == {"read": 10, "serials": 10, "failed": 0}


def test_a_429_on_a_list_reads_no_audit_and_a_403_ends_the_audits(inv):  # noqa: F811
    transport, poller, clock, _rec = inv
    _fleet(transport, 3)
    transport.site_devices["site-b"] = []
    transport.data_status = 429
    out = poller.run_once()
    assert out.get("held_until") and "audits" not in out and _audit_calls(transport) == []
    transport.data_status = 200
    clock.t = T0 + timedelta(minutes=31)
    transport.audit_status = 403
    out = poller.run_once()
    assert len(_audit_calls(transport)) == 1           # the user: every audit would fail
    assert out["audits"] == {"read": 0, "serials": 0, "failed": 1}
    assert not out.get("held_until")                   # a 403 is not a throttle


def test_an_audit_never_creates_a_device_nor_writes_an_unmapped_site(inv):  # noqa: F811
    from apps.octo.entity.feeders.datto import DattoInventoryFeeder

    transport, poller, _clock, rec = inv
    transport.site_devices["site-a"] = [inventory_device("dev-1", "WS-1", site_uid="site-a")]
    transport.site_devices["site-b"] = []
    transport.audits["dev-1"] = device_audit()
    poller.run_once()
    feeder = DattoInventoryFeeder()
    base = {"instance_id": rec.id, "audited_at": "2026-10-01T15:00:00.000Z",
            "serial": "EXAMPLE-SN-9999", "manufacturer": None, "model": None}
    assert feeder.on_audit("acme-corp", {**base, "site_uid": "site-a",
                                         "device_uid": "dev-new"}) is False
    # site-b is the bakery's: never written into acme-corp's file.
    assert feeder.on_audit("acme-corp", {**base, "site_uid": "site-b",
                                         "device_uid": "dev-1"}) is False
    assert feeder.on_audit("acme-corp", {**base, "instance_id": rec.id + 1,
                                         "site_uid": "site-a", "device_uid": "dev-1"}) is False
    assert [r["device_uid"] for r in _devices()] == ["dev-1"]
    assert _devices()[0]["serial"] == "EXAMPLE-SN-0001"
    assert feeder.audit_due("acme-corp", rec.id, ["site-b"], "2027-01-01T00:00:00.000Z",
                            10) == []
