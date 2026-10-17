"""Datto NOC alerts KEYED BY WHAT THEY ARE ABOUT (v0.17.3, Rick's decision C
of 2026-10-07).

The case: a vendor's remote-access services are kept STOPPED on purpose
on a regulated server; the Datto NOC's DNOCServiceMonitor keeps
raising "service stopped" for them and an analyst marks those Expected. With
v0.17.2's key (event-log code + source + log) that rule would ALSO have
hidden a later DNOC alert for SQL Server stopping on the same server. Now:

  * a service report's key carries the SORTED set of affected services —
    every service name the report gives, wherever it gives it (SUMMARY,
    "Service :" fields, "TICKET AVOIDED" headlines) — and how many the report
    says are affected: {A} and {A, B} are two keys — an Expected rule for
    {A} never covers {A, B}; a report that says more are affected than it
    names is a digest of its names and its shape;
  * a disk report's key carries its drive; memory / CPU keep the monitor
    alone (their v0.17.2 key, unchanged);
  * a report that cannot be read keeps the old key (a narrower key only ever
    matches LESS — never quieter);
  * key parts are cleaned and bounded; a service name's digits are KEPT
    (two BeyondTrust Jump Clients, MSSQL$PROD1 / MSSQL$PROD2 are different
    services); a set too long for the key becomes a digest of the WHOLE set,
    never a prefix.

Synthetic reports in the DNOC layouts (`test_dnoc`), Example names only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from apps.octo.enrich import dnoc
from apps.octo.enrich.tests.test_dnoc import CPU, DISK, MEMORY, SERVICE, ctx
from apps.octo.verdicts import keys
from apps.octo.verdicts import store as vstore
from apps.octo.verdicts.state import EXPECTED, OPEN, Occurrence, TenantVerdicts

BASE = "datto:eventlog_ctx|application|{}|12000"
NOW = datetime(2026, 10, 7, 15, 0, tzinfo=timezone.utc)

JUMP_ONLY = """DNOC Service Monitor v1.2.3  |  2026-10-07 08:00:00  |  EXAMPLE-SRV
=====================================================================
AUTOMATIC SERVICES STOPPED - (1 service(s) affected)
=====================================================================

SUMMARY
  [1] BeyondTrust Jump Client [support.example.com] (bomgar-ps-1700000001-2001)
      What we found  : This service was stopped when we checked.
      Current status : Stopped - we will keep retrying automatically
--- NEW FAILURES (full troubleshooting detail) ---
STATE
  State          : Stopped
  Downtime       : 3d 1h 10m
"""

JUMP_AND_SQL = """DNOC Service Monitor v1.2.3  |  2026-10-09 08:00:00  |  EXAMPLE-SRV
=====================================================================
AUTOMATIC SERVICES STOPPED - (2 service(s) affected)
=====================================================================

SUMMARY
  [1] SQL Server (MSSQLSERVER) (MSSQLSERVER)
      What we found  : This service was stopped when we checked.
      Current status : Stopped - we will keep retrying automatically
  [2] BeyondTrust Jump Client [support.example.com] (bomgar-ps-1700000001-2001)
      What we found  : This service was stopped when we checked.
      Current status : Stopped - we will keep retrying automatically
--- NEW FAILURES (full troubleshooting detail) ---
STATE
  State          : Stopped
  Downtime       : 5d 1h 10m
"""

SQL_ONLY = JUMP_AND_SQL.replace("(2 service(s) affected)", "(1 service(s) affected)").replace(
    "  [2] BeyondTrust Jump Client [support.example.com] (bomgar-ps-1700000001-2001)\n"
    "      What we found  : This service was stopped when we checked.\n"
    "      Current status : Stopped - we will keep retrying automatically\n", "")

AVOIDED = ("DNOC Service Monitor v1.2.3  |  2026-10-01 08:00:00  |  EXAMPLE-SRV\n"
           "---------------------------------------------------------------------\n"
           "TICKET AVOIDED - ExampleAgent (ExampleAgent Service)\n"
           "    Initial state : StopPending\n    Final state   : Running\n")


def _payload(source: str, text: str, *, device: str = "dev-srv") -> dict:
    return {"alertUid": "0000aaaa-0000-0000-0000-000000000001", "priority": "High",
            "alertSourceInfo": {"deviceUid": device, "deviceName": "EXAMPLE-SRV"},
            "alertContext": ctx(source, text)}


def _key(source: str, text: str, **kw) -> keys.AlertKey:
    return keys.alert_key({"source": "datto"}, _payload(source, text, **kw))


def test_a_service_report_is_keyed_by_its_sorted_set_of_services():
    jump = _key("DNOCServiceMonitor", JUMP_ONLY)
    assert jump.signature_key == BASE.format("dnocservicemonitor") + \
        "|services=1:bomgar-ps-1700000001-2001"
    both = _key("DNOCServiceMonitor", JUMP_AND_SQL)
    assert both.signature_key == BASE.format("dnocservicemonitor") + \
        "|services=2:bomgar-ps-1700000001-2001,mssqlserver"
    sql = _key("DNOCServiceMonitor", SQL_ONLY)
    assert sql.signature_key.endswith("|services=1:mssqlserver")
    assert len({jump.signature_key, both.signature_key, sql.signature_key}) == 3
    # The SAME services in another order (and other downtimes / dates): one key.
    swapped = JUMP_AND_SQL.replace("[1] SQL Server", "[9] SQL Server").replace(
        "5d 1h 10m", "6d 2h 0m")
    assert _key("DNOCServiceMonitor", swapped).signature_key == both.signature_key
    # The device is still the device uid: the key never spans servers.
    assert jump.device_key == "dev-srv"


def test_an_expected_rule_for_one_service_never_covers_another_set():
    jump = _key("DNOCServiceMonitor", JUMP_ONLY)
    rule = vstore.ExpectedRule(
        3, "acme-corp", "datto", jump.device_key, jump.signature_key, None,
        "NOC service: BeyondTrust Jump Client — stopped",
        "the vendor's remote access, kept stopped on purpose (regulated)", 41, 7,
        vstore.iso(NOW - timedelta(days=1)), vstore.iso(NOW + timedelta(days=60)))
    tv = TenantVerdicts("acme-corp", [], [rule], now=NOW)

    def state(text: str) -> str:
        k = _key("DNOCServiceMonitor", text)
        at = vstore.iso(NOW - timedelta(minutes=5))
        return tv.state(Occurrence(99, k, at, at)).status

    assert state(JUMP_ONLY.replace("3d 1h 10m", "4d 1h 10m")) == EXPECTED   # the same again
    assert state(JUMP_AND_SQL) == OPEN                  # {A} never covers {A, B}
    assert state(SQL_ONLY) == OPEN                      # nor {B}
    # Nor the same services on ANOTHER server.
    other = _key("DNOCServiceMonitor", JUMP_ONLY, device="dev-other")
    at = vstore.iso(NOW - timedelta(minutes=5))
    assert tv.state(Occurrence(98, other, at, at)).status == OPEN


def test_the_other_service_layouts_name_their_service():
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", SERVICE)) == \
        "services=1:example-svc-0001"
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", AVOIDED)) == "services=1:exampleagent"
    field_only = ("DNOC Service Monitor v1.2.3  |  2026-10-01  |  EXAMPLE-SRV\n"
                  "SERVER\n  Hostname       : EXAMPLE-SRV\n  Service        : Spooler\n"
                  "STATE\n  State          : Stopped\n")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", field_only)) == "services=1:spooler"
    # The lines are unchanged by the key's parse.
    assert dnoc.line(ctx("DNOCServiceMonitor", AVOIDED)) == \
        "NOC service: ExampleAgent — ticket avoided, now running"
    assert dnoc.line(ctx("DNOCServiceMonitor", JUMP_AND_SQL)).startswith(
        "NOC services (2): SQL Server (MSSQLSERVER); BeyondTrust Jump Client")


def test_disk_is_keyed_by_its_drive_memory_and_cpu_keep_their_key():
    disk = _key("DNOCDiskRemediation", DISK)
    assert disk.signature_key == BASE.format("dnocdiskremediation") + "|drive=c:"
    d_drive = DISK.replace("Drive               : C:", "Drive               : D:")
    assert _key("DNOCDiskRemediation", d_drive).signature_key.endswith("|drive=d:")
    # Memory / CPU: the monitor alone — v0.17.2's key, so its acks still match.
    assert _key("DNOCMemoryMonitor", MEMORY).signature_key == BASE.format("dnocmemorymonitor")
    assert _key("DNOCCpuMonitoring", CPU).signature_key == BASE.format("dnoccpumonitoring")
    assert dnoc.signature_part(ctx("DNOCMemoryMonitor", MEMORY)) == ""


def test_an_unreadable_or_unknown_report_keeps_the_old_key():
    old = BASE.format("dnocservicemonitor")
    assert _key("DNOCServiceMonitor", "garbled").signature_key == old
    # A headline that names no service: no key part (its line is unchanged).
    headline = ("DNOC Service Monitor v1.2.3\nAUTOMATIC SERVICES STOPPED - "
                "(2 service(s) affected)\n")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", headline)) is None
    assert _key("DNOCServiceMonitor", headline).signature_key == old
    assert _key("DNOCDiskRemediation", "no drive here").signature_key == \
        BASE.format("dnocdiskremediation")
    assert _key("DNOCSomethingNew", JUMP_ONLY).signature_key == BASE.format("dnocsomethingnew")
    # Not a DNOC source: never a part, whatever the text.
    plain = keys.alert_key({"source": "datto"}, _payload("Service Control Manager", JUMP_ONLY))
    assert plain.signature_key == BASE.format("service control manager")
    assert dnoc.signature_part({"source": None, "description": JUMP_ONLY}) is None


def test_key_parts_are_cleaned_bounded_and_never_a_prefix():
    hostile = JUMP_ONLY.replace(
        "(bomgar-ps-1700000001-2001)", "(Evil|Svc,‮Name\x00 42)")
    k = _key("DNOCServiceMonitor", hostile)
    part = k.signature_key.rsplit("|", 1)[1]
    assert part == "services=1:evil svc name 42"
    assert "‮" not in k.signature_key and "\x00" not in k.signature_key
    # Many long service names: a digest of the WHOLE set, bounded — two sets
    # sharing a long prefix never share a key.
    items = "".join(f"  [{i}] Example Service {i} (example-service-{chr(97 + i) * 30})\n"
                    for i in range(1, 12))
    many = JUMP_ONLY.replace("(1 service(s) affected)", "(11 service(s) affected)").replace(
        "  [1] BeyondTrust Jump Client [support.example.com] (bomgar-ps-1700000001-2001)\n",
        items)
    fewer = many.replace(items.splitlines(keepends=True)[-1], "").replace(
        "(11 service(s) affected)", "(10 service(s) affected)")
    k_many, k_fewer = _key("DNOCServiceMonitor", many), _key("DNOCServiceMonitor", fewer)
    assert k_many.signature_key.split("|")[-1].startswith("services=11:sha256:")
    assert k_many.signature_key != k_fewer.signature_key
    assert len(k_many.signature_key) <= keys.SIG_MAX
    # Even with a long log name and source the part never falls under the
    # SIG_MAX cut: a list that fits a short key is a digest in a long one.
    five = "".join(f"  [{i}] Example Service {i} (example-service-{chr(97 + i) * 18})\n"
                   for i in range(1, 6))
    report = JUMP_ONLY.replace("(1 service(s) affected)", "(5 service(s) affected)").replace(
        "  [1] BeyondTrust Jump Client [support.example.com] (bomgar-ps-1700000001-2001)\n",
        five)
    short = _key("DNOCServiceMonitor", report).signature_key
    assert short.split("|")[-1].startswith("services=5:example-service-bbb")
    long_log = _payload("DNOCServiceMonitor", report)
    long_log["alertContext"]["logName"] = "L" * 200
    long_log["alertContext"]["source"] = "DNOCServiceMonitor" + "x" * 200
    k_long = keys.alert_key({"source": "datto"}, long_log)
    assert len(k_long.signature_key) <= keys.SIG_MAX
    assert k_long.signature_key.split("|")[-1].startswith("services=5:sha256:")
    assert len(k_long.signature_key.split("|")[-1]) == len("services=5:sha256:") + 32


# ---------------------------------------------------------------------------
# Review fixes: the key names EVERY service, keeps a name's digits, and a
# report that names fewer services than it says are affected never keys as
# the ones it names
# ---------------------------------------------------------------------------

HEAD = "DNOC Service Monitor v1.2.3  |  2026-10-07 08:00:00  |  EXAMPLE-SRV\n"


def _summary(display: str, name: str) -> str:
    return (HEAD + "AUTOMATIC SERVICES STOPPED - (1 service(s) affected)\n"
            "SUMMARY\n"
            f"  [1] {display} ({name})\n"
            "      Current status : Stopped - we will keep retrying automatically\n"
            "--- NEW FAILURES (full troubleshooting detail) ---\n"
            "STATE\n  State          : Stopped\n  Downtime       : 3d 1h 10m\n")


def _expected_rule_on(text: str) -> TenantVerdicts:
    k = _key("DNOCServiceMonitor", text)
    rule = vstore.ExpectedRule(
        3, "acme-corp", "datto", k.device_key, k.signature_key, None,
        "NOC service — stopped", "kept stopped on purpose by the vendor (regulated)", 41, 7,
        vstore.iso(NOW - timedelta(days=1)), vstore.iso(NOW + timedelta(days=60)))
    return TenantVerdicts("acme-corp", [], [rule], now=NOW)


def _status(tv: TenantVerdicts, text: str) -> str:
    at = vstore.iso(NOW - timedelta(minutes=5))
    return tv.state(Occurrence(99, _key("DNOCServiceMonitor", text), at, at)).status


def test_two_beyondtrust_clients_or_two_sql_instances_are_two_keys():
    """A service name's digits are its identity: masked, every BeyondTrust
    Jump Client ('bomgar-ps-<id>-<id>') on a server — and MSSQL$PROD1 /
    MSSQL$PROD2 — would share one key, and an Expected rule made for one
    vendor's stopped client would hide another vendor's client stopping."""
    vendor_a = _summary("BeyondTrust Jump Client [support.vendor-a.example]",
                        "bomgar-ps-1700000001-2001")
    vendor_b = _summary("BeyondTrust Jump Client [support.vendor-b.example]",
                        "bomgar-ps-1811111111-3007")
    part_a = dnoc.signature_part(ctx("DNOCServiceMonitor", vendor_a))
    part_b = dnoc.signature_part(ctx("DNOCServiceMonitor", vendor_b))
    assert part_a == "services=1:bomgar-ps-1700000001-2001"
    assert part_b == "services=1:bomgar-ps-1811111111-3007"
    tv = _expected_rule_on(vendor_a)
    assert _status(tv, vendor_a.replace("3d 1h 10m", "9d 0h 0m")) == EXPECTED
    assert _status(tv, vendor_b) == OPEN
    prod1 = _summary("SQL Server (PROD1)", "MSSQL$PROD1")
    prod2 = _summary("SQL Server (PROD2)", "MSSQL$PROD2")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", prod1)) == "services=1:mssql$prod1"
    assert _status(_expected_rule_on(prod1), prod2) == OPEN
    # Case is not identity (Windows service names are case-insensitive).
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", prod1.replace(
        "(MSSQL$PROD1)", "(mssql$prod1)"))) == "services=1:mssql$prod1"


def test_every_service_the_report_names_is_in_the_key():
    """Not only the first match: a headline naming A and a "Service :" field
    naming B, two "TICKET AVOIDED" headlines, a headline past the report's
    first lines — each names its service in the key, so the key of {A, B}
    is never the key of {A}."""
    jump_alone = HEAD + "TICKET AVOIDED - bomgar-ps-1700000001-2001 (BeyondTrust Jump Client)\n"
    jump_and_sql = (HEAD + "TICKET AVOIDED - bomgar-ps-1700000001-2001 (BeyondTrust Jump Client)\n"
                    "AUTOMATIC SERVICES STOPPED - (1 service(s) affected)\n"
                    "SERVER\n  Hostname       : EXAMPLE-SRV\n  Service        : MSSQLSERVER\n"
                    "STATE\n  State          : Stopped\n")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", jump_alone)) == \
        "services=1:bomgar-ps-1700000001-2001"
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", jump_and_sql)) == \
        "services=2:bomgar-ps-1700000001-2001,mssqlserver"
    tv = _expected_rule_on(jump_alone)
    assert _status(tv, jump_alone) == EXPECTED
    assert _status(tv, jump_and_sql) == OPEN            # SQL Server stopped is never hidden
    two_avoided = AVOIDED + "TICKET AVOIDED - MSSQLSERVER (SQL Server)\n" \
        "    Initial state : StopPending\n    Final state   : Running\n"
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", two_avoided)) == \
        "services=2:exampleagent,mssqlserver"
    assert _status(_expected_rule_on(AVOIDED), two_avoided) == OPEN
    late = AVOIDED + "".join(f"    Note {i}        : retried\n" for i in range(8)) + \
        "TICKET AVOIDED - Spooler (Print Spooler)\n"
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", late)) == \
        "services=2:exampleagent,spooler"
    # The lines are unchanged: still the first headline's.
    assert dnoc.line(ctx("DNOCServiceMonitor", two_avoided)) == \
        "NOC service: ExampleAgent — ticket avoided, now running"


def _blocks(*services: str, affected: int | None = None) -> str:
    n = len(services) if affected is None else affected
    out = HEAD + f"AUTOMATIC SERVICES STOPPED - ({n} service(s) affected)\n"
    for i, svc in enumerate(services, 1):
        out += (f"SERVER\n  Hostname       : EXAMPLE-SRV\n  Service        : {svc}\n"
                f"  Display name   : Example display {i}\n"
                "STATE\n  State          : Stopped\n  Downtime       : 2d 4h 0m\n")
    return out


def test_a_report_without_a_summary_names_every_detail_block():
    """One detail block per service, no SUMMARY: every "Service :" field is
    read (not the first one only) — {BTJumpA, MSSQLSERVER} and {BTJumpA,
    Spooler} are two keys."""
    with_sql, with_spooler = _blocks("BTJumpA", "MSSQLSERVER"), _blocks("BTJumpA", "Spooler")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", with_sql)) == \
        "services=2:btjumpa,mssqlserver"
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", with_spooler)) == \
        "services=2:btjumpa,spooler"
    assert _status(_expected_rule_on(with_sql), with_spooler) == OPEN
    assert _status(_expected_rule_on(with_sql), with_sql.replace("2d 4h 0m", "3d 0h 5m")) == \
        EXPECTED
    # Display names only (no "Service :" field): every one of them.
    displays = (HEAD + "AUTOMATIC SERVICES STOPPED - (2 service(s) affected)\n"
                "SERVER\n  Display name   : Example Agent\nSERVER\n  Display name   : Print Spooler\n")
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", displays)) == \
        "services=2:example agent,print spooler"


def test_a_report_naming_fewer_services_than_affected_is_a_digest():
    """The report says three are affected and names two: its names alone
    would key {A, B, C} like {A, B, D}. The key is a digest of the names AND
    the report's shape (numbers masked) — the same report again (another
    date, another downtime) keeps it; another unnamed service does not."""
    def report(third: str, *, downtime: str = "2d 4h 0m", date: str = "2026-10-07") -> str:
        return (_blocks("BTJumpA", "MSSQLSERVER", affected=3)
                .replace("2d 4h 0m", downtime).replace("2026-10-07", date)
                + f"ALSO STOPPED\n  {third} was stopped too\n")

    a = dnoc.signature_part(ctx("DNOCServiceMonitor", report("Spooler")))
    assert a is not None and a.startswith("services=3:partial:sha256:")
    assert len(a) == len("services=3:partial:sha256:") + 32
    assert "btjumpa" not in a and "spooler" not in a
    again = dnoc.signature_part(ctx("DNOCServiceMonitor", report(
        "Spooler", downtime="5d 1h 2m", date="2026-10-09")))
    assert again == a
    assert dnoc.signature_part(ctx("DNOCServiceMonitor", report("W3SVC"))) != a
    # Never the key of the two it names, nor of the same names with three.
    assert a != dnoc.signature_part(ctx("DNOCServiceMonitor", _blocks("BTJumpA", "MSSQLSERVER")))
    tv = _expected_rule_on(report("Spooler"))
    assert _status(tv, report("Spooler", downtime="6d 0h 0m")) == EXPECTED
    assert _status(tv, report("W3SVC")) == OPEN
    # Fits the signature: under SIG_MAX with the rest of the key.
    k = _key("DNOCServiceMonitor", report("Spooler"))
    assert k.signature_key.endswith("|" + a) and len(k.signature_key) <= keys.SIG_MAX
