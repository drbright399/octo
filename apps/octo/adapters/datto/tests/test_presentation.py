"""What a Datto alert SAYS: headline / detail / event_type from its payload.

The production defect: every Datto row on the dashboard read "alert" with
nothing under it. The payloads below are the shapes observed live on the first
real onboarding (eventlog_ctx, comp_script_ctx) plus classes Datto's API
documents — and one nobody has seen, because a row must never be blank again.

Real classes throughout: DattoSourceAdapter, DattoPoller, DattoClient and
SqliteIngestSink; only the vendor socket is fake (fake_datto.py).
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import unicodedata

import pytest

from apps.octo import client_provisioning
from apps.octo.adapters.datto import DattoSourceAdapter
from apps.octo.adapters.datto.poller import DattoPoller
from apps.octo.adapters.datto.presentation import present_alert
from apps.octo.adapters.datto.tests.fake_datto import FakeDattoTransport, real_client
from apps.octo.ingest import SqliteIngestSink
from apps.octo.ingest.presentation import DETAIL_MAX, DETAIL_MAX_LINES, HEADLINE_MAX

WINDOWS_4625 = (
    "An account failed to log on.\r\n\r\n"
    "Subject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n"
    "\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\n"
    "Logon Type:\t\t\t3\r\n\r\n"
    "Account For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n"
    "\tAccount Name:\t\talice\r\n\tAccount Domain:\t\tEXAMPLE\r\n\r\n"
    "Failure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n"
    "\tStatus:\t\t\t0xC000006D\r\n\r\n"
    "Network Information:\r\n\tWorkstation Name:\tWS-EXAMPLE-01\r\n"
    "\tSource Network Address:\t192.0.2.44\r\n"
)


def api_alert(context: dict, *, priority: str = "High", **over) -> dict:
    """The /api/v2 alert object, as the poller receives it."""
    alert = {
        "alertUid": "0a1b2c3d-aaaa-bbbb-cccc-000000000001",
        "priority": priority,
        "timestamp": 1_790_000_000_000,       # epoch MILLISECONDS
        "resolved": False,
        "resolvedBy": None,
        "resolvedOn": None,
        "muted": False,
        "ticketNumber": None,
        "autoresolveMins": 0,
        "diagnostics": "",
        "alertMonitorInfo": {"sendsEmails": False, "createsTicket": False},
        "alertSourceInfo": {
            "deviceName": "WS-EXAMPLE-01",
            "deviceUid": "dev-uid-0001",
            "siteName": "Example Site",
            "siteUid": "site-uid-0001",
        },
        "responseActions": [],
        "alertContext": context,
    }
    alert.update(over)
    return alert


EVENTLOG = {
    "@class": "eventlog_ctx", "logName": "Security", "code": "4625", "type": "0",
    "source": "Microsoft-Windows-Security-Auditing", "description": WINDOWS_4625,
    "triggerCount": 5, "lastTriggered": 1_790_000_000_000, "causedSuspension": False,
}
COMP_SCRIPT = {
    "@class": "comp_script_ctx",
    "samples": {
        "DIAG": "Backup job 'Nightly' has not completed in 26 hours.\n"
                "Last success: 2026-09-19 01:00\nRepository: local",
        "STATUS": "FAILED",
    },
}


# ---------------------------------------------------------------------------
# The two classes seen live
# ---------------------------------------------------------------------------

def test_eventlog_headline_is_the_vendors_own_sentence():
    shown = present_alert(api_alert(EVENTLOG))
    assert shown.event_type == "datto.eventlog"
    assert shown.headline == "Event log · Security 4625 — An account failed to log on"
    # Detail: the lines that SAY something — section headers and 'Name: -'
    # blanks dropped, tabs collapsed, facts last.
    lines = shown.detail.split("\n")
    assert "Account Name: alice" in lines
    assert "Failure Reason: Unknown user name or bad password." in lines
    assert "Source Network Address: 192.0.2.44" in lines
    assert "Subject:" not in lines and "Account Name: -" not in lines
    assert "Source: Microsoft-Windows-Security-Auditing · Triggered 5 times" in lines
    assert shown.device == "WS-EXAMPLE-01" and shown.site == "Example Site"


# A 4625 as Windows actually writes it: every section, including the ones
# that are nothing but null placeholders (S-1-0-0, 0x0, '-').
WINDOWS_4625_FULL = (
    "An account failed to log on.\r\n\r\n"
    "Subject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n"
    "\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\n"
    "Logon Type:\t\t\t3\r\n\r\n"
    "Account For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n"
    "\tAccount Name:\t\talice\r\n\tAccount Domain:\t\tEXAMPLE\r\n\r\n"
    "Failure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n"
    "\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC0000064\r\n\r\n"
    "Process Information:\r\n\tCaller Process ID:\t0x0\r\n\tCaller Process Name:\t-\r\n\r\n"
    "Network Information:\r\n\tWorkstation Name:\tWS-EXAMPLE-01\r\n"
    "\tSource Network Address:\t192.0.2.44\r\n\tSource Port:\t\t0\r\n\r\n"
    "Detailed Authentication Information:\r\n\tLogon Process:\t\tNtLmSsp \r\n"
    "\tAuthentication Package:\tNTLM\r\n\tTransited Services:\t-\r\n"
    "\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n"
)


def test_a_full_windows_event_keeps_the_facts_and_shows_where_it_was_cut():
    """The placeholder lines Windows writes (null SID, 0x0, '-') say nothing
    and are dropped FIRST, so the source address of a failed logon is inside
    the line budget; what is still cut is marked, with the source/trigger
    tail kept as the last line."""
    shown = present_alert(api_alert({**EVENTLOG, "description": WINDOWS_4625_FULL}))
    lines = shown.detail.split("\n")
    assert len(lines) <= DETAIL_MAX_LINES
    assert "Source Network Address: 192.0.2.44" in lines
    assert "Account Name: alice" in lines and "Logon Type: 3" in lines
    for placeholder in ("Security ID: S-1-0-0", "Logon ID: 0x0", "Caller Process ID: 0x0",
                        "Caller Process Name: -", "Transited Services: -"):
        assert placeholder not in lines
    assert lines[-1] == "Source: Microsoft-Windows-Security-Auditing · Triggered 5 times"
    assert "…" in lines                     # something WAS cut, and it shows
    assert lines.index("…") == len(lines) - 2
    # The feed's two-line clamp now opens on facts, not on placeholders.
    assert lines[0] == "Logon Type: 3" and lines[1] == "Account Name: alice"


def test_a_short_windows_event_has_no_cut_marker():
    shown = present_alert(api_alert(EVENTLOG))
    assert "…" not in shown.detail.split("\n")


def test_eventlog_without_a_description_still_says_what_it_is():
    ctx = {k: v for k, v in EVENTLOG.items() if k != "description"}
    shown = present_alert(api_alert(ctx))
    assert shown.headline == (
        "Event log · Security 4625 — source Microsoft-Windows-Security-Auditing"
    )


def test_component_monitor_headline_is_first_line_of_diag():
    shown = present_alert(api_alert(COMP_SCRIPT))
    assert shown.event_type == "datto.comp_script"
    assert shown.headline == (
        "Component monitor — Backup job 'Nightly' has not completed in 26 hours"
    )
    assert shown.detail.split("\n") == [
        "Last success: 2026-09-19 01:00", "Repository: local", "Status: FAILED",
    ]


def test_component_monitor_with_only_a_status():
    shown = present_alert(api_alert(
        {"@class": "comp_script_ctx", "samples": {"STATUS": "Disk SMART warning"}},
    ))
    assert shown.headline == "Component monitor — Disk SMART warning"


# ---------------------------------------------------------------------------
# Documented classes, built defensively from their evident field names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("context, event_type, headline", [
    ({"@class": "online_offline_status_ctx", "status": "OFFLINE"},
     "datto.online_offline_status", "Device offline"),
    ({"@class": "perf_disk_usage_ctx", "diskName": "C:", "totalVolume": 500.0,
      "freeSpace": 30.0, "unitOfMeasure": "GB"},
     "datto.perf_disk_usage", "Disk usage 94% on C:"),
    ({"@class": "perf_resource_usage_ctx", "type": "CPU", "percentage": 97.0},
     "datto.perf_resource_usage", "CPU usage 97%"),
    ({"@class": "perf_resource_usage_ctx", "type": "MEMORY", "percentage": 91.5},
     "datto.perf_resource_usage", "Memory usage 91.5%"),
    ({"@class": "srvc_status_ctx", "serviceName": "Spooler", "status": "STOPPED"},
     "datto.srvc_status", "Service — Spooler: STOPPED"),
    ({"@class": "patch_ctx", "result": "Install failed", "info": "KB5030211"},
     "datto.patch", "Patch — Install failed: KB5030211"),
    ({"@class": "antivirus_ctx", "productName": "Example AV", "status": "NOT_RUNNING"},
     "datto.antivirus", "Antivirus — Example AV: NOT_RUNNING"),
])
def test_documented_classes(context, event_type, headline):
    shown = present_alert(api_alert(context))
    assert (shown.event_type, shown.headline) == (event_type, headline)
    assert shown.detail                     # never an empty second line


def test_disk_usage_detail_carries_the_numbers():
    shown = present_alert(api_alert({
        "@class": "perf_disk_usage_ctx", "diskName": "C:", "totalVolume": 500.0,
        "freeSpace": 30.0, "unitOfMeasure": "GB",
    }))
    assert shown.detail.split("\n")[0] == "30 of 500 GB free"


def test_a_known_class_with_none_of_its_fields_falls_back_to_generic():
    shown = present_alert(api_alert(
        {"@class": "perf_disk_usage_ctx", "volumeLabel": "DATA", "note": "nearly full"},
    ))
    assert shown.headline.startswith("Disk usage — ")
    assert "nearly full" in shown.headline


# ---------------------------------------------------------------------------
# A class nobody has seen — and nothing at all
# ---------------------------------------------------------------------------

def test_unknown_class_is_never_blank():
    shown = present_alert(api_alert({
        "@class": "vm_snapshot_ctx", "vmName": "db01", "snapshotAgeDays": 12,
        "status": "STALE", "snapshotUid": "f00f-1234",
    }))
    assert shown.event_type == "datto.vm_snapshot"
    # class label + the most informative short fields; the uid is not one.
    assert shown.headline == "Vm snapshot — status: STALE · vm name: db01 · snapshot age days: 12"
    assert "snapshot uid: f00f-1234" in shown.detail.split("\n")


def test_unknown_class_with_a_message_like_field_uses_it():
    shown = present_alert(api_alert(
        {"@class": "new_thing_ctx", "reason": "Certificate expires in 3 days.\nRenew it."},
    ))
    assert shown.headline == "New thing — Certificate expires in 3 days"
    assert shown.detail.split("\n")[0] == "Renew it."


def test_empty_context_uses_diagnostics_then_a_plain_sentence():
    with_diag = present_alert(api_alert({}, diagnostics="Agent heartbeat missed.\nlast seen 09:00"))
    assert with_diag.headline == "Datto alert — Agent heartbeat missed"
    assert "Diagnostics: last seen 09:00" in with_diag.detail

    nothing = present_alert(api_alert({"@class": "mystery_ctx"}))
    assert nothing.headline == "Mystery alert on WS-EXAMPLE-01"
    assert nothing.detail == "High priority — WS-EXAMPLE-01 · Example Site"
    assert nothing.event_type == "datto.mystery"


@pytest.mark.parametrize("junk", [None, [], "text", 7, {"alertContext": "nope"},
                                  {"alertContext": {"@class": 5, "samples": [1, 2]}}])
def test_malformed_envelopes_never_raise_and_never_blank(junk):
    shown = present_alert(junk)
    assert shown.headline and shown.event_type == "datto.alert"


# ---------------------------------------------------------------------------
# Hostile vendor text
# ---------------------------------------------------------------------------

def _has_invisible(text: str) -> bool:
    return any(
        unicodedata.category(ch) in ("Cc", "Cf") and ch != "\n" for ch in text
    )


def test_control_and_bidi_characters_are_removed():
    nasty = "Logon\x00 failed\x1b[31m for‮ alice​\x07.\nsecond\x08 line"
    shown = present_alert(api_alert(
        {"@class": "eventlog_ctx", "logName": "Sec\x00urity", "code": "4625\r\n",
         "description": nasty},
    ))
    assert shown.headline == "Event log · Security 4625 — Logon failed[31m for alice"
    assert not _has_invisible(shown.headline) and not _has_invisible(shown.detail)
    assert "\n" not in shown.headline


def test_fifty_thousand_characters_are_bounded():
    shown = present_alert(api_alert(
        {"@class": "eventlog_ctx", "logName": "L" * 50_000, "code": "C" * 50_000,
         "description": ("A" * 50_000) + "\n" + "\n".join(["B" * 5_000] * 400)},
    ))
    assert len(shown.headline) <= HEADLINE_MAX and shown.headline.endswith("…")
    assert len(shown.detail) <= DETAIL_MAX
    assert len(shown.event_type) <= 64


def test_markup_stays_text_and_cannot_forge_a_type():
    shown = present_alert(api_alert({
        "@class": "<script>alert(1)</script>_ctx",
        "message": "<img src=x onerror=alert(1)> disk full",
    }))
    # Left as the characters they are (the console renders text nodes) …
    assert "<img src=x onerror=alert(1)> disk full" in shown.headline
    # … but free vendor text never becomes a machine label.
    assert shown.event_type == "datto.script_alert_1_script"
    assert all(ch.isalnum() or ch in "._" for ch in shown.event_type)


def test_a_huge_context_is_not_walked_forever():
    ctx = {"@class": "wide_ctx", **{f"k{i:05d}": "v" * 100 for i in range(20_000)}}
    shown = present_alert(api_alert(ctx))
    assert shown.headline.startswith("Wide — ") and len(shown.detail) <= DETAIL_MAX


# ---------------------------------------------------------------------------
# Webhook shape
# ---------------------------------------------------------------------------

def _webhook(**over) -> dict:
    body = {
        "event": "alert_raised",
        "alertUid": "0a1b2c3d-aaaa-bbbb-cccc-000000000002",
        "alertCategory": "Event Log",
        "alertType": "Event Log Monitor",
        "alertContext": {"message": "An account failed to log on.\nAccount Name: alice"},
        "device": {"hostname": "WS-EXAMPLE-02"},
        "siteUid": "site-uid-0001",
        "siteName": "Example Site",
    }
    body.update(over)
    return body


def test_webhook_shape_headline_and_detail():
    shown = present_alert(_webhook())
    assert shown.headline == "Event Log — An account failed to log on"
    assert shown.detail == "Account Name: alice"
    # The SAME machine label the API shape gets (see the next test).
    assert shown.event_type == "datto.eventlog"
    assert (shown.device, shown.site) == ("WS-EXAMPLE-02", "Example Site")
    assert shown.fallback is False


@pytest.mark.parametrize("alert_type, api_class", [
    ("Event Log Monitor", "eventlog_ctx"),
    ("Event Log", "eventlog_ctx"),
    ("Disk Usage Monitor", "perf_disk_usage_ctx"),
    ("Disk Usage", "perf_disk_usage_ctx"),
    ("Online Status Monitor", "online_offline_status_ctx"),
    ("Offline", "online_offline_status_ctx"),
    ("Component Monitor", "comp_script_ctx"),
    ("CPU Usage Monitor", "perf_resource_usage_ctx"),
    ("Memory Usage", "perf_resource_usage_ctx"),
    ("Service Monitor", "srvc_status_ctx"),
    ("Service Resource Usage Monitor", "srvc_resource_usage_ctx"),
    ("Process Monitor", "process_status_ctx"),
    ("Patch Monitor", "patch_ctx"),
    ("Antivirus Monitor", "antivirus_ctx"),
    ("Anti-Virus Status", "antivirus_ctx"),
    ("Ransomware Monitor", "ransomware_ctx"),
    ("Software Monitor", "sw_action_ctx"),
    ("SNMP Monitor", "custom_snmp_ctx"),
    ("WMI Monitor", "wmi_ctx"),
    ("File/Folder Size Monitor", "fs_object_ctx"),
    ("Security Management", "sec_management_ctx"),
    ("Backup Monitor", "backup_management_ctx"),
    ("Windows Defender", "endpoint_security_windows_defender_ctx"),
    ("Endpoint Security Threat", "endpoint_security_threat_ctx"),
])
def test_the_webhook_and_api_shapes_of_one_alert_class_share_an_event_type(alert_type, api_class):
    """An instance usually has polling AND the webhook on: the same alert
    arrives twice, in two shapes. The triage worker's recurrence signature
    joins on event_type, so the two must agree."""
    via_webhook = present_alert(_webhook(alertType=alert_type, alertCategory="Anything"))
    via_api = present_alert(api_alert({"@class": api_class, "message": "x"}))
    assert via_webhook.event_type == via_api.event_type
    assert via_webhook.event_type.startswith("datto.")


def test_a_monitor_name_the_table_does_not_know_keeps_its_own_bounded_slug():
    """Not guessed into a class — and never free text in a machine column."""
    shown = present_alert(_webhook(alertType="Custom Widget Monitor 3000"))
    assert shown.event_type == "datto.custom_widget_monitor_3000"
    long_name = present_alert(_webhook(alertType="X" * 500 + " <b>!</b>"))
    assert len(long_name.event_type) <= 64
    assert all(ch.isalnum() or ch in "._" for ch in long_name.event_type)
    # Whole words only: a name that merely CONTAINS a known word is not that class.
    assert present_alert(_webhook(alertType="Fanatical Monitor")).event_type == "datto.fanatical_monitor"
    # The category is the fallback when there is no alert type at all.
    assert present_alert(_webhook(alertType="", alertCategory="Event Log")).event_type == "datto.eventlog"


def test_a_recognised_alert_is_not_flagged_as_a_fallback():
    for shown in (present_alert(api_alert(EVENTLOG)), present_alert(api_alert(COMP_SCRIPT))):
        assert shown.fallback is False


def test_a_payload_the_presenter_recognises_nothing_in_is_flagged():
    """Dev synthetic traffic files rows under 'datto' without Datto's shape.
    The headline is the last-resort label — and says so, so a reader holding
    a stored summary can keep it instead."""
    shown = present_alert({"synthetic": True, "host": "ws-1", "scenario": "Malware", "severity": "critical"})
    assert shown.headline == "Datto alert" and shown.fallback is True
    for junk in (None, [], "text", 7, {"alertContext": "nope"}):
        assert present_alert(junk).fallback is True
    # Diagnostics alone are recognised text, not a fallback.
    assert present_alert(api_alert({}, diagnostics="Agent heartbeat missed.")).fallback is False


def test_webhook_resolved_is_marked_and_keeps_its_type():
    raised = present_alert(_webhook())
    resolved = present_alert(_webhook(event="alert_resolved", resolved=True))
    assert resolved.headline == f"[resolved] {raised.headline}"
    assert resolved.event_type == raised.event_type


def test_webhook_unsubstituted_variables_are_not_shown():
    shown = present_alert(_webhook(
        alertCategory="[alert_category]", alertType="[alert_type]",
        alertContext={"message": "[alert_message]"}, siteName="[site_name]",
        device={"hostname": "[device_hostname]"},
    ))
    assert shown.headline == "Datto alert" and "[" not in shown.detail
    assert shown.event_type == "datto.alert" and shown.device is None


# ---------------------------------------------------------------------------
# Severity — all five Datto priorities, both shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("priority, severity", [
    ("Critical", "critical"), ("High", "high"), ("Moderate", "medium"),
    ("Low", "low"), ("Information", "info"),
    ("CRITICAL", "critical"), ("moderate", "medium"), (" information ", "info"),
])
def test_all_five_priorities_map(priority, severity):
    adapter = DattoSourceAdapter()
    assert adapter.extract_event(api_alert(EVENTLOG, priority=priority)).severity == severity
    assert adapter.extract_event(_webhook(alertPriority=priority)).severity == severity


# ---------------------------------------------------------------------------
# Through the real adapter, poller and sink: what lands in events.db
# ---------------------------------------------------------------------------

def test_extract_event_carries_headline_and_type_and_stays_deterministic():
    adapter = DattoSourceAdapter()
    raw = api_alert(EVENTLOG)
    event = adapter.extract_event(raw)
    assert event.summary == "Event log · Security 4625 — An account failed to log on"
    assert event.event_type == "datto.eventlog"
    assert event.received_at == "2026-09-21T14:13:20.000Z"    # epoch ms → UTC
    assert event == adapter.extract_event(raw)
    assert event.payload is raw                                # payload untouched


def test_polled_alerts_are_stored_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path))
    from apps.octo.auth import bootstrap
    bootstrap.init_data_root()
    client_provisioning.create_client("acme", "Acme")

    # No tenant map in this test: the site uid IS the client slug.
    source_info = {**api_alert({})["alertSourceInfo"], "siteUid": "acme"}
    transport = FakeDattoTransport()
    transport.alerts = [
        api_alert(EVENTLOG, alertSourceInfo=source_info),
        api_alert(COMP_SCRIPT, alertUid="0a1b2c3d-aaaa-bbbb-cccc-000000000009",
                  priority="Moderate", alertSourceInfo=source_info),
    ]
    poller = DattoPoller(
        adapter=DattoSourceAdapter(), client=real_client(transport),
        sink=SqliteIngestSink(tmp_path), default_tenant_slug="acme",
        initial_cursor="1970-01-01T00:00:00.000Z",
    )
    asyncio.run(poller._drain_once())

    conn = sqlite3.connect(tmp_path / "clients" / "acme" / "events.db")
    rows = conn.execute(
        "SELECT event_type, severity, summary, source_host, payload "
        "FROM events ORDER BY id"
    ).fetchall()
    conn.close()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        ("datto.eventlog", "high",
         "Event log · Security 4625 — An account failed to log on"),
        ("datto.comp_script", "medium",
         "Component monitor — Backup job 'Nightly' has not completed in 26 hours"),
    ]
    assert rows[0][3] == "WS-EXAMPLE-01"
    assert json.loads(rows[0][4])["alertContext"]["description"] == WINDOWS_4625
