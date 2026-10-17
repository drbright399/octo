"""A Datto RMM alert in ONE deterministic line, parsed by class (no LLM):
event log, performance (value + threshold), service / process state,
antivirus / backup / ransomware / software, device status, component
diagnostics, a fallback first sentence — with the host, open / resolved,
the NOC flag and the full text for the "details" expander. All fixtures
are synthetic (Example / Acme names, no real client)."""
from __future__ import annotations

from apps.octo.enrich.datto_summary import first_sentence, summarize


def alert(ctx: dict, **env) -> dict:
    return {"alertUid": "0000aaaa-0000-0000-0000-000000000001", "priority": "High",
            "alertSourceInfo": {"deviceUid": "dev-1", "deviceName": "EXAMPLE-SRV"},
            "alertContext": ctx, **env}


def line(ctx: dict, **env) -> str:
    return summarize(alert(ctx, **env))["line"]


def test_one_line_per_class():
    assert line({"@class": "eventlog_ctx", "logName": "System", "code": 7031,
                 "source": "Service Control Manager",
                 "description": "The Spooler service terminated unexpectedly."}) == \
        "Event 7031 · Service Control Manager · System log"
    assert line({"@class": "perf_resource_usage_ctx", "type": "CPU", "percentage": 97.0,
                 "threshold": 90}) == "CPU usage 97% (threshold 90%)"
    assert line({"@class": "perf_disk_usage_ctx", "diskName": "C:", "totalVolume": 200,
                 "freeSpace": 18, "unitOfMeasure": "GB"}) == "Disk usage 91% on C:"
    assert line({"@class": "srvc_status_ctx", "serviceName": "Spooler",
                 "status": "Stopped"}) == "Service Spooler is stopped"
    assert line({"@class": "process_status_ctx", "processName": "backupd.exe",
                 "status": "NOT_RUNNING"}) == "Process backupd.exe is not_running"
    assert line({"@class": "antivirus_ctx", "productName": "Example AV",
                 "status": "Not running"}) == "Antivirus — Example AV: Not running"
    assert line({"@class": "backup_management_ctx", "productName": "Example Backup",
                 "status": "Failed"}) == "Backup — Example Backup: Failed"
    assert line({"@class": "ransomware_ctx", "state": "Detected",
                 "affectedDirectories": "D:\\Shares"}) == \
        "Ransomware detection: Detected (D:\\Shares)"
    assert line({"@class": "sw_action_ctx", "actionType": "INSTALL",
                 "softwareName": "Example Tool", "version": "2.1"}) == \
        "Software install: Example Tool 2.1"
    assert line({"@class": "online_offline_status_ctx", "status": "OFFLINE"}) == \
        "Device offline"
    assert line({"@class": "comp_script_ctx", "samples": {
        "DIAG": "Backup job 'Nightly' failed. Check the destination share.\nmore",
        "STATUS": "Failed"}}) == "Backup job 'Nightly' failed"


def test_an_unknown_class_falls_back_to_the_first_sentence_and_the_text_is_kept():
    s = summarize(alert({"@class": "brand_new_ctx",
                         "message": "Something new happened. Second sentence."}))
    assert s["line"] == "Brand new — Something new happened"
    assert s["class"] == "brand_new_ctx" and s["host"] == "EXAMPLE-SRV"
    assert s["resolved"] is False and s["priority"] == "High" and s["noc"] is False
    full = summarize(alert({"@class": "eventlog_ctx", "logName": "System", "code": "7031",
                            "source": "Service Control Manager",
                            "description": "First line.\nSecond line with detail."}))
    assert any("Second line with detail" in d for d in full["details"])


def test_resolved_and_noc():
    s = summarize(alert({"@class": "srvc_status_ctx", "serviceName": "Spooler",
                         "status": "Running"}, resolved=True))
    assert s["resolved"] is True and s["line"] == "Service Spooler is running"
    noc = summarize(alert({"@class": "comp_script_ctx", "samples": {"DIAG": "Disk degraded."}},
                          alertType="DNOC - RAID health"))
    assert noc["noc"] is True and noc["line"] == "NOC: Disk degraded"
    assert summarize(alert({"@class": "eventlog_ctx", "logName": "Application",
                            "code": "1000", "source": "Application Error"},
                           alertType="Monitor")).get("noc") is False


def test_vendor_text_is_cleaned_and_bounded():
    s = summarize(alert({"@class": "srvc_status_ctx", "serviceName": "Spool\u202eer\x00" * 50,
                         "status": "Stopped"}))
    assert "\u202e" not in s["line"] and "\x00" not in s["line"] and len(s["line"]) <= 200
    assert first_sentence(None) == "" and first_sentence("One. Two.") == "One"
    assert summarize("not an alert")["line"] == "Datto alert"
