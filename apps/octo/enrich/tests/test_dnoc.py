"""The Datto NOC's triage reports in one line — memory with its PRESSURE
signals (commit, hard faults, non-reclaimable, the top process), CPU with
its queue and kernel time, services with their state and downtime, disk
with free space and what the cleanup reclaimed. Synthetic reports in the
DNOC layout (Example names, no real client)."""
from __future__ import annotations

from apps.octo.enrich import dnoc
from apps.octo.enrich.datto_summary import summarize

MEMORY = """DNOCMemoryTriage

DNOC MEMORY MONITOR - HIGH UTILIZATION ALERT
Incident ID: 0000
NOC Service Level: DNOC.SRV.Manage
Computer: EXAMPLE-SQL
Current Memory Utilization: 91.7%
Configured Alert Threshold: 90.0%

--- RAM Overview ---
Total Memory: 31.88 GB
Used Memory: 29.23 GB (91.7%)
Free Memory: 2.65 GB (8.3%)

--- Pressure Signals (real memory health) ---
Available Memory (reclaimable + free): 4,120 MB
Standby Cache (OS-reclaimable): 1.37 GB
In-Use (non-reclaimable): 27.86 GB (87.4%)
Hard Page Faults per sec: 0.4

Assessment:
  - Hard page faults >50/sec not observed.

--- Commit Charge ---
Committed Memory: 25.10 GB
Commit Limit: 36.63 GB
Commit Utilization: 68.5%

--- Top Memory Processes ---
1. sqlservr [Microsoft SQL Server database engine]
   PID: 4012
   Working Set: 20,312 MB
   Private Memory: 20,480 MB
   Handles: 1500

2. ExampleService
   PID: 5120
   Working Set: 610 MB
   Private Memory: 1,104 MB
   Handles: 900

--- CPU Snapshot (cross-context) ---
CPU Utilization: 4.1%
Top CPU processes at this moment:
  - sqlservr (PID 4012): 2.0% CPU
"""

CPU = """DNOCCPUTriage

DNOC CPU MONITOR - HIGH UTILIZATION ALERT
Computer: EXAMPLE-APP
Current CPU Utilization: 97.5%
Configured Alert Threshold: 90.0%

--- CPU Detail ---
Logical Processors: 8
Overall CPU Utilization: 97.5%

--- Pressure Signals ---
Processor Queue Length: 12 (per-core: 1.50)
Kernel (Privileged) Time: 40.2%

--- Top CPU Processes ---
1. endpointprotection
   PID: 2200
   CPU Utilization: 61.0%
   Threads: 120
"""

SERVICE = """DNOC Service Monitor v1.2.3  |  2026-10-01 08:00:00  |  EXAMPLE-SRV
=====================================================================
AUTOMATIC SERVICES STOPPED - (1 service(s) affected)
=====================================================================

SUMMARY
  [1] Example Jump Client - support.example.com (example-svc-0001)
      What we found  : This service was stopped when we checked.
      What we did    : We attempted to restart this service, but it did not come back up.
      Current status : Stopped - we will keep retrying automatically
--- NEW FAILURES (full troubleshooting detail) ---
[1]  example-svc-0001  (Example Jump Client - support.example.com)

SERVER
  Hostname       : EXAMPLE-SRV
  Service        : example-svc-0001
  Display name   : Example Jump Client - support.example.com

STATE
  State          : Stopped
  Start type     : Auto
  Downtime       : 12d 3h 10m

REMEDIATION
  Performed      : 2
  Successful     : 0
  Failed         : 2

  Attempt #1
    Method       : Start-Service
    State        : Stopped -> Start Pending -> Stopped
    Result       : FAILED
"""

DISK = """DNOC Disk Remediation - ABOVE THRESHOLD 1 (manual review required)
AlertKey            : EXAMPLE-PC|C|T1

Hostname            : EXAMPLE-PC
Drive               : C:
Volume Name         : OS

DISK SPACE - BEFORE
  Drive : C:
  Total : 237.47 GB
  Used  : 222.30 GB  (93.61%)
  Free  : 15.17 GB  (6.39%)

DISK SPACE - AFTER
  Total : 237.47 GB
  Used  : 222.25 GB  (93.59%)
  Free  : 15.22 GB  (6.41%)

CLEANUP RESULTS
  Total reclaimed : 0 bytes
  CONFIG WARNING  : NO CLEANUP TASKS ARE ENABLED in the component configuration.
"""


def ctx(source: str, text: str) -> dict:
    return {"@class": "eventlog_ctx", "logName": "Application", "code": "12000",
            "source": source, "description": text}


def test_memory_line_carries_the_pressure_signals_not_only_utilization():
    assert dnoc.line(ctx("DNOCMemoryMonitor", MEMORY)) == (
        "NOC memory 91.7% (threshold 90%) · commit 68.5% · 0.4 hard faults/s · "
        "non-reclaimable 87.4% · top sqlservr 20.0 GB")


def test_cpu_line():
    assert dnoc.line(ctx("DNOCCpuMonitoring", CPU)) == (
        "NOC CPU 97.5% (threshold 90%) · queue 1.50/core · kernel 40.2% · "
        "top endpointprotection 61%")


def test_service_line():
    assert dnoc.line(ctx("DNOCServiceMonitor", SERVICE)) == (
        "NOC service: Example Jump Client - support.example.com — stopped, restart failed, "
        "down 12d 3h 10m")


def test_a_self_resolved_service_says_so():
    report = ("DNOC Service Monitor v1.2.3  |  2026-10-01 08:00:00  |  EXAMPLE-SRV\n"
              "---------------------------------------------------------------------\n"
              "TICKET AVOIDED - ExampleAgent (ExampleAgent Service)\n"
              "    Initial state : StopPending\n    Final state   : Running\n"
              "    Outcome       : Resolved during transitional grace window\n")
    assert dnoc.line(ctx("DNOCServiceMonitor", report)) == \
        "NOC service: ExampleAgent — ticket avoided, now running"


def test_percentages_round_cleanly():
    assert dnoc._pct("95.98") == "96%" and dnoc._pct("68.54") == "68.5%"


def test_disk_line():
    assert dnoc.line(ctx("DNOCDiskRemediation", DISK)) == (
        "NOC disk C: 93.6% used, 15.22 GB free of 237.47 GB · reclaimed 0 bytes · "
        "no cleanup tasks enabled")


def test_the_summary_uses_it_and_flags_noc_once():
    s = summarize({"alertUid": "0000aaaa-0000-0000-0000-000000000001", "priority": "High",
                   "alertSourceInfo": {"deviceUid": "dev-1", "deviceName": "EXAMPLE-SQL"},
                   "alertContext": ctx("DNOCMemoryMonitor", MEMORY)})
    assert s["noc"] is True
    assert s["line"].startswith("NOC memory 91.7%") and not s["line"].startswith("NOC: NOC")


def test_an_unknown_or_unreadable_report_falls_back():
    assert dnoc.line(ctx("DNOCSomethingNew", MEMORY)) == ""
    assert dnoc.line(ctx("DNOCMemoryMonitor", "no layout here")) == ""
    assert dnoc.line(ctx("Service Control Manager", MEMORY)) == ""
    s = summarize({"alertContext": ctx("DNOCMemoryMonitor", "garbled")})
    assert s["line"] and s["noc"] is True


def test_vendor_text_is_cleaned_and_bounded():
    hostile = MEMORY.replace("sqlservr", "sql‮servr\x00" + "x" * 500)
    out = dnoc.line(ctx("DNOCMemoryMonitor", hostile))
    assert "‮" not in out and "\x00" not in out and len(out) <= 200
