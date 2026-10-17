"""Datto RMM quick-job stdout/stderr round-trip — wrapper, normalize, store, route."""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.octo.adapters.datto import job_output
from apps.octo.adapters.datto.job_output import (
    JobOutputRecord,
    JobOutputStore,
    WatermarkSettings,
    build_relay_wrapper,
    normalize_job_output,
)
from apps.octo.api.errors import APIError
from apps.octo.api.routers import webhooks
from apps.octo.tests.security import fakes

_WATERMARK_ENV = (
    "OCTO_JOB_BANNER_LABEL", "OCTO_JOB_USER_AGENT", "OCTO_JOB_USER_AGENT_SHELL",
    "OCTO_JOB_RMM_TENANT",
)


@pytest.fixture(autouse=True)
def _no_watermark_env(monkeypatch):
    # The defaults are under test: a deployment's env must not leak in.
    for var in _WATERMARK_ENV:
        monkeypatch.delenv(var, raising=False)


def _wrap(shell="powershell", script="Get-Date", **kw):
    args = dict(job_name="athena-triage-0001", job_uid="u-1",
                ingest_url="https://octo.example/hook", token="tok", shell=shell)
    args.update(kw)
    return build_relay_wrapper(script, **args)


# --------------------------------------------------------------------------- #
# wrapper builder
# --------------------------------------------------------------------------- #

def test_wrapper_powershell_embeds_body_and_metadata():
    out = build_relay_wrapper(
        "Get-Service | Out-String",
        job_name="svc-check",
        job_uid="job-123",
        ingest_url="https://octo.example/api/v1/webhooks/datto/job-output",
        token="tok-abc",
        shell="powershell",
    )
    assert "Get-Service | Out-String" in out
    assert "$ATHENA_JOB         = 'svc-check'" in out
    assert "$ATHENA_JOB_UID     = 'job-123'" in out
    assert "'tok-abc'" in out
    assert "https://octo.example/api/v1/webhooks/datto/job-output" in out
    # both streams captured (merged) and stderr isolated
    assert "*>&1 | Out-String" in out
    assert "$Error" in out and "STDERR (isolated)" in out
    assert "X-Webhook-Token" in out
    # identification-only watermark (verify by job ID in the RMM job log)
    assert out.startswith("<# ATHENA AUTOMATION | job svc-check ")
    # placeholders fully substituted
    assert "__ATHENA_" not in out


def test_wrapper_posix_is_heredoc_free_and_captures_stderr():
    out = build_relay_wrapper(
        "echo hi; ls /nope",
        job_name="probe",
        job_uid="j9",
        ingest_url="https://octo.example/hook",
        token="t",
        shell="posix",
    )
    assert "echo hi; ls /nope" in out
    assert ">\"$__OUT\" 2>\"$__ERR\"" in out  # stdout + stderr split
    assert "base64" in out and "curl" in out  # no-dependency relay
    assert "stdout_b64" in out and "stderr_b64" in out
    assert "python3 -c" not in out  # no python3 invocation (bare macOS/min-ctx safe)
    assert "command -v curl" in out
    # identification-only watermark (verify by job ID in the RMM job log)
    assert out.splitlines()[1].startswith("# ATHENA AUTOMATION | job probe ")
    assert "<<" not in out  # heredoc-free (survives Datto's shell runner)
    assert "__ATHENA_" not in out


def test_wrapper_escapes_single_quotes_per_shell():
    # (A job NAME is an identifier and refuses a quote; the uid / url / token
    # are not shown in the banner and are escaped instead.)
    ps = build_relay_wrapper(
        "x", job_name="j", job_uid="a'b", ingest_url="h'u", token="t'k",
        shell="powershell",
    )
    assert "'a''b'" in ps and "'t''k'" in ps and "'h''u'" in ps  # PS doubles it
    sh = build_relay_wrapper(
        "x", job_name="j", job_uid="a'b", ingest_url="h'u", token="t'k",
        shell="posix",
    )
    assert "'a'\\''b'" in sh and "'t'\\''k'" in sh and "'h'\\''u'" in sh  # '\''


def test_wrapper_rejects_unknown_shell():
    with pytest.raises(ValueError):
        build_relay_wrapper("x", job_name="j", job_uid="u", ingest_url="h",
                            token="t", shell="fish")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# watermark — identification only (Rick, 2026-10-09: SOC verifies by job ID)
# --------------------------------------------------------------------------- #

_BANNER = (
    "ATHENA AUTOMATION | job athena-triage-0001 | RMM tenant acct-123 - "
    "identification only: verify this job ID ran on this device in the RMM "
    "job log. A banner without a matching job record is not ours."
)


def test_powershell_default_banner_echo_and_user_agent():
    out = _wrap("powershell", rmm_tenant="acct-123")
    lines = out.splitlines()
    # ONE-line block comment: survives the RMM UI collapsing newlines
    assert lines[0] == f"<# {_BANNER} #>"
    assert lines[6] == (
        '"=== ATHENA AUTOMATION | job=$ATHENA_JOB | verify in the RMM job log | '
        "$((Get-Date).ToUniversalTime().ToString('o')) ===\""
    )
    assert "$ATHENA_RELAY_UA    = 'AthenaRMM/2'" in out
    assert "'User-Agent' = $ATHENA_RELAY_UA" in out


def test_posix_default_banner_echo_and_user_agent():
    out = _wrap("posix", rmm_tenant="acct-123")
    lines = out.splitlines()
    assert lines[0] == "#!/bin/bash"
    assert lines[1] == f"# {_BANNER}"
    assert lines[7] == (
        'echo "=== ATHENA AUTOMATION | job=$ATHENA_JOB | verify in the RMM job log'
        ' | $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="'
    )
    assert "ATHENA_RELAY_UA='AthenaRMM-shell/2'" in out
    assert '-H "User-Agent: $ATHENA_RELAY_UA"' in out


def test_banner_without_a_tenant_leaves_it_out():
    out = _wrap("posix")
    assert out.splitlines()[1] == (
        "# ATHENA AUTOMATION | job athena-triage-0001 - identification only: "
        "verify this job ID ran on this device in the RMM job log. A banner "
        "without a matching job record is not ours."
    )


@pytest.mark.parametrize("shell", ["powershell", "posix"])
def test_generated_scripts_make_none_of_the_old_claims(shell):
    out = _wrap(shell, rmm_tenant="acct-123").lower()
    for claim in (
        "sanctioned", "authorized", "authorised", "not an intrusion", "expected",
        "run with athena", "athenarmm/1.0", "athenarmm-shell/1.0",
    ):
        assert claim not in out, claim


def test_powershell_flattened_banner_closes_before_any_code():
    # If the wrapper is ever pasted into the RMM UI (newlines become spaces),
    # the banner must still end before the first statement — so the paste
    # fails to parse, loudly — instead of a `#` line comment swallowing the
    # whole script silently. (The wrapper is not flatten-SAFE: it is
    # dispatched as a multi-line script; see the template comment.)
    flat = _wrap("powershell", rmm_tenant="acct-123").replace("\n", " ")
    assert flat.startswith("<# ")
    assert flat.index(" #>") < flat.index("$ATHENA_RELAY_URI")
    assert flat.count("#>") == 1


@pytest.mark.parametrize("shell", ["powershell", "posix"])
def test_job_id_is_in_the_banner_and_the_echo_line(shell):
    job = "athena-q-20261009T120000Z-7f3a"
    out = _wrap(shell, job_name=job)
    banner = out.splitlines()[0 if shell == "powershell" else 1]
    assert f"| job {job} " in banner
    echo = next(line for line in out.splitlines() if "=== ATHENA AUTOMATION" in line)
    assert "job=$ATHENA_JOB |" in echo
    # ... and $ATHENA_JOB is that same id (the escaped single-quoted literal)
    assigned = re.search(r"^\$?ATHENA_JOB\s*=\s*'(.*)'$", out, re.MULTILINE)
    assert assigned is not None and assigned.group(1) == job


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_posix_first_output_line_names_the_job_id(tmp_path):
    # Runs the real wrapper; the relay targets a closed local port and fails
    # (best-effort), which is fine — only the echoed first line is checked.
    out = _wrap("posix", script="echo body-ran", job_name="athena-q-0042",
                ingest_url="http://127.0.0.1:9/never")
    run = subprocess.run(["bash", "-c", out], capture_output=True, text=True,
                         timeout=60, cwd=tmp_path)
    first = run.stdout.splitlines()[0]
    assert re.fullmatch(
        r"=== ATHENA AUTOMATION \| job=athena-q-0042 \| verify in the RMM job log"
        r" \| \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ===", first,
    ), first
    assert "body-ran" in run.stdout


def test_label_user_agents_and_tenant_come_from_env(monkeypatch):
    monkeypatch.setenv("OCTO_JOB_BANNER_LABEL", "ACME OPS")
    monkeypatch.setenv("OCTO_JOB_USER_AGENT", "AcmeRMM/7 (ops)")
    monkeypatch.setenv("OCTO_JOB_USER_AGENT_SHELL", "AcmeRMM-sh/7")
    monkeypatch.setenv("OCTO_JOB_RMM_TENANT", "acct-9")
    ps = _wrap("powershell")
    assert ps.startswith("<# ACME OPS | job athena-triage-0001 | RMM tenant acct-9 - ")
    assert '"=== ACME OPS | job=$ATHENA_JOB | verify in the RMM job log | ' in ps
    assert "$ATHENA_RELAY_UA    = 'AcmeRMM/7 (ops)'" in ps
    sh = _wrap("posix")
    assert sh.splitlines()[1].startswith("# ACME OPS | job athena-triage-0001 | ")
    assert 'echo "=== ACME OPS | job=$ATHENA_JOB | ' in sh
    assert "ATHENA_RELAY_UA='AcmeRMM-sh/7'" in sh
    for out in (ps, sh):
        assert "ATHENA AUTOMATION" not in out and "AthenaRMM" not in out
    # an explicit tenant (what the dispatch layer has in hand) wins over env
    assert "| RMM tenant acct-explicit - " in _wrap("posix", rmm_tenant="acct-explicit")


def test_blank_env_falls_back_to_the_defaults(monkeypatch):
    for var in _WATERMARK_ENV:
        monkeypatch.setenv(var, "   ")
    assert WatermarkSettings.from_env() == WatermarkSettings()
    assert WatermarkSettings().rmm_tenant is None


_BAD_LABELS = [
    "",
    " LEADING",
    "TRAILING ",
    "X" * 49,
    "OPS #> Remove-Item C:\\ <#",   # breaks out of the PowerShell block comment
    'OPS"; rm -rf / #',            # breaks out of the echo string
    "OPS `whoami`",
    "OPS $(whoami)",
    "OPS $env:X",
    "OPS 'x'",
    "OPS\nrm -rf /",
    "OPS\r",
    "OPS | job forged",
    "ÄTHENA",                       # printable ASCII only
    "ATHENA\u202eNOITAMOTUA",       # no bidi tricks
    # the banner identifies; it never vouches
    "AUTHORIZED ACTION", "Authorised ops", "SANCTIONED", "NOT AN INTRUSION",
    "expected job", "Approved maintenance", "LEGIT OPS", "SAFE JOB",
    "TRUSTED OPS", "whitelisted", "Benign",
]


@pytest.mark.parametrize("label", _BAD_LABELS)
def test_bad_labels_are_refused(label, monkeypatch):
    with pytest.raises(ValueError):
        WatermarkSettings(label=label)
    if label and label == label.strip():
        monkeypatch.setenv("OCTO_JOB_BANNER_LABEL", label)
        with pytest.raises(ValueError) as ei:
            _wrap("powershell")
        # names the variable, never echoes the value
        assert "OCTO_JOB_BANNER_LABEL" in str(ei.value)
        assert label.strip() not in str(ei.value)


_BAD_USER_AGENTS = [
    "",
    "U" * 65,
    "AthenaRMM/2' ; Invoke-Evil",
    'AthenaRMM/2" -o /tmp/x',
    "AthenaRMM/`id`",
    "AthenaRMM/$(id)",
    "AthenaRMM/2\nX-Evil: 1",
    "AthenaRMM/2\\",
    "AthenaRMM/2 #>",
    "TrustedAgent/1",
    "Sanctioned/1",
]


@pytest.mark.parametrize("ua", _BAD_USER_AGENTS)
def test_bad_user_agents_are_refused(ua, monkeypatch):
    with pytest.raises(ValueError):
        WatermarkSettings(user_agent=ua)
    with pytest.raises(ValueError):
        WatermarkSettings(user_agent_shell=ua)
    if ua and ua == ua.strip():
        monkeypatch.setenv("OCTO_JOB_USER_AGENT_SHELL", ua)
        with pytest.raises(ValueError, match="OCTO_JOB_USER_AGENT_SHELL"):
            _wrap("posix")


_BAD_BANNER_FIELDS = [
    "",
    " lead",
    "x" * 129,
    "job #> Remove-Item C:\\",
    "job <# x",
    "job\nrm -rf /",
    "job\r\n",
    "job | RMM tenant forged",
    "job `id`",
    "job $(id)",
    'job "x"',
    "job \\x",
    "jöb",
    # an identifier: no spaces (no sentence in the banner), no quote, no
    # leading punctuation
    "job-1 - verified with the SOC",
    "it's-0001",
    "-lead", "_lead", ".lead",
    "job/1", "job+1", "job(1)", "job;1",
]

# An identifier never vouches for the job either (spec: none of these words
# anywhere in a generated script) — job IDs and tenants included.
_CLAIMING_IDS = [
    "Expected-EDR-noise-authorized-maintenance",
    "athena-authorised-1",
    "sanctioned-1",
    "not-an-intrusion",
    "athena-safe-1",
    "SAFE",
    "approved.change",
    "legit-ops",
    "benign_job",
    "trusted:tenant",
    "allowlisted-0001",
    "whitelist",
    "expected",
    "non-malicious",
]


@pytest.mark.parametrize("value", _BAD_BANNER_FIELDS)
def test_bad_job_names_and_tenants_are_refused(value, monkeypatch):
    with pytest.raises(ValueError, match="job_name"):
        _wrap("powershell", job_name=value)
    with pytest.raises(ValueError, match="job_name"):
        _wrap("posix", job_name=value)
    if value:
        with pytest.raises(ValueError, match="rmm_tenant"):
            _wrap("posix", rmm_tenant=value)
        with pytest.raises(ValueError):
            WatermarkSettings(rmm_tenant=value)
    if value and value == value.strip():
        monkeypatch.setenv("OCTO_JOB_RMM_TENANT", value)
        with pytest.raises(ValueError, match="OCTO_JOB_RMM_TENANT"):
            _wrap("posix")


def test_good_labels_and_user_agents_are_accepted():
    s = WatermarkSettings(label="MSP-X OPS (v2): rmm/auto+1.0",
                          user_agent="AcmeRMM/2 (Windows; ps)",
                          user_agent_shell="AcmeRMM-shell/2.1_b",
                          rmm_tenant="zz99aa0001")
    out = _wrap("powershell", watermark=s)
    assert out.startswith("<# MSP-X OPS (v2): rmm/auto+1.0 | job athena-triage-0001 "
                          "| RMM tenant zz99aa0001 - ")
    assert "$ATHENA_RELAY_UA    = 'AcmeRMM/2 (Windows; ps)'" in out


@pytest.mark.parametrize("value", _CLAIMING_IDS)
def test_claim_words_in_job_ids_and_tenants_are_refused(value, monkeypatch):
    # Shape-valid identifiers, refused ONLY for the claim they carry.
    assert job_output._BANNER_FIELD_RE.fullmatch(value)
    with pytest.raises(ValueError) as ref:
        _wrap("posix", job_name="sanctioned-0")
    for shell in ("powershell", "posix"):
        with pytest.raises(ValueError, match="job_name") as ei:
            _wrap(shell, job_name=value)
        # the same fixed message for every value: it never echoes the value
        assert str(ei.value) == str(ref.value)
        with pytest.raises(ValueError, match="rmm_tenant"):
            _wrap(shell, rmm_tenant=value)
    with pytest.raises(ValueError):
        WatermarkSettings(rmm_tenant=value)
    monkeypatch.setenv("OCTO_JOB_RMM_TENANT", value)
    with pytest.raises(ValueError, match="OCTO_JOB_RMM_TENANT"):
        _wrap("posix")


@pytest.mark.parametrize("value", [
    "athena-20261009T120000Z-0123456789abcdef", "svc-check", "j", "A1",
    "acct.9:exampleplat_2", "x" * 128,
])
def test_identifier_shaped_job_ids_and_tenants_are_accepted(value):
    out = _wrap("posix", job_name=value, rmm_tenant=value)
    assert out.splitlines()[1].startswith(
        f"# ATHENA AUTOMATION | job {value} | RMM tenant {value} - ")
    assert f"ATHENA_JOB='{value}'" in out


def test_new_job_id_is_fresh_unguessable_and_banner_safe():
    ids = {job_output.new_job_id() for _ in range(2000)}
    assert len(ids) == 2000  # never reused: one ID = one dispatch
    for job_id in list(ids)[:50]:
        assert re.fullmatch(r"athena-\d{8}T\d{6}Z-[0-9a-f]{16}", job_id), job_id
        # what the dispatch layer hands to the wrapper is accepted as-is
        for shell in ("powershell", "posix"):
            assert f"| job {job_id} - " in _wrap(shell, job_name=job_id)


def test_new_job_id_stamps_utc_and_takes_a_prefix():
    from datetime import datetime, timedelta, timezone
    local = datetime(2026, 10, 9, 7, 0, 5, tzinfo=timezone(timedelta(hours=-5)))
    job_id = job_output.new_job_id("acme-q", now=local)
    assert re.fullmatch(r"acme-q-20261009T120005Z-[0-9a-f]{16}", job_id), job_id


@pytest.mark.parametrize("prefix", ["", "bad prefix", "x'y", "authorized", "p" * 95])
def test_new_job_id_refuses_a_bad_prefix(prefix):
    with pytest.raises(ValueError, match="prefix"):
        job_output.new_job_id(prefix)


@pytest.mark.parametrize("shell", ["powershell", "posix"])
def test_placeholders_are_filled_in_one_pass(shell):
    # A value that names another placeholder is never expanded again.
    out = _wrap(shell, script="BODY-MARKER", job_name="x__ATHENA_BODY__",
                job_uid="__ATHENA_TOKEN__", token="secret-tok")
    assert out.count("BODY-MARKER") == 1
    assert out.count("secret-tok") == 1


def test_module_defaults_are_the_documented_ones():
    assert job_output.DEFAULT_BANNER_LABEL == "ATHENA AUTOMATION"
    assert job_output.DEFAULT_USER_AGENT == "AthenaRMM/2"
    assert job_output.DEFAULT_USER_AGENT_SHELL == "AthenaRMM-shell/2"


# --------------------------------------------------------------------------- #
# normalize
# --------------------------------------------------------------------------- #

def test_normalize_accepts_camelcase_and_coerces_exit():
    rec = normalize_job_output(
        {"hostname": "HOST1", "job": "j", "jobUid": "u-1", "ts": "2026-06-14T00:00:00Z",
         "exit": "3", "stdout": "out", "stderr": "err"}
    )
    assert rec.hostname == "HOST1" and rec.job_uid == "u-1" and rec.exit_code == 3
    assert rec.stdout == "out" and rec.stderr == "err"


def test_normalize_tolerates_missing_fields_and_bad_exit():
    rec = normalize_job_output({"stdout": "only"})
    assert rec.hostname == "" and rec.job_uid == "" and rec.exit_code == 0
    rec2 = normalize_job_output({"exit": "not-an-int"})
    assert rec2.exit_code == 0


def test_normalize_clips_oversize_output():
    rec = normalize_job_output({"stdout": "x" * 1_000_000})
    assert len(rec.stdout) == 400_000


def test_normalize_rejects_non_object():
    with pytest.raises(ValueError):
        normalize_job_output(["not", "a", "dict"])  # type: ignore[arg-type]


def test_normalize_decodes_base64_streams():
    import base64
    rec = normalize_job_output({
        "hostname": "H", "jobUid": "u",
        "stdout_b64": base64.b64encode("héllo out".encode()).decode(),
        "stderr_b64": base64.b64encode(b"oops err").decode(),
    })
    assert rec.stdout == "héllo out" and rec.stderr == "oops err"


def test_normalize_bad_base64_degrades_to_empty():
    rec = normalize_job_output({"stdout_b64": "%%%not base64%%%"})
    assert rec.stdout == ""


# --------------------------------------------------------------------------- #
# redaction (field note #14: an agent's --license_key landed in job output)
# --------------------------------------------------------------------------- #

def _service_line(key: str) -> str:
    return (r'Name  : RocketAgent' "\n"
            r'Path  : "C:\Program Files\RocketAgent\agent.exe" --license_key '
            f"{key} --mode service\n")


def test_normalize_redacts_a_license_key_command_line():
    rec = normalize_job_output({"jobUid": "u-1", "stdout": _service_line(fakes.LICENSE_KEY),
                                "stderr": ""})
    assert fakes.LICENSE_KEY not in rec.stdout
    assert "--license_key [REDACTED:cli-secret-flag] --mode service" in rec.stdout
    assert "RocketAgent" in rec.stdout and rec.redactions == 1


def test_normalize_redacts_the_posix_base64_streams_too():
    import base64
    token = "Authorization: Bearer " + fakes.rand("job-bearer", 40)
    rec = normalize_job_output({
        "jobUid": "u-2",
        "stdout_b64": base64.b64encode(token.encode()).decode(),
        "stderr_b64": base64.b64encode(b"curl --token " + fakes.rand("job-tok", 24).encode()).decode(),
    })
    assert rec.stdout == "Authorization: Bearer [REDACTED:bearer-token]"
    assert rec.stderr == "curl --token [REDACTED:cli-secret-flag]"
    assert rec.redactions == 2


def test_normalize_keeps_hashes_and_ordinary_output():
    digest = fakes.rand("job-digest", 64, fakes.HEX).upper()
    text = (f"Algorithm Hash Path\nSHA256    {digest} C:\\ProgramData\\x.exe\n"
            "Status Running, StartType Automatic\n")
    rec = normalize_job_output({"stdout": text})
    assert rec.stdout == text and rec.redactions == 0


def test_store_never_writes_a_secret_even_from_a_hand_built_record(tmp_path: Path):
    store = JobOutputStore(tmp_path)
    rec = JobOutputRecord("H", "j", "uid-9", "ts", 0, _service_line(fakes.LICENSE_KEY),
                          "Key Content            : " + fakes.rand("job-wifi", 14))
    path = store.save(rec)
    on_disk = path.read_text()
    assert fakes.LICENSE_KEY not in on_disk and "[REDACTED:wifi-key-content]" in on_disk
    got = store.get("uid-9")
    assert got is not None and got.redactions == 2  # the count survives the round trip
    assert fakes.LICENSE_KEY not in got.stdout


def test_redaction_is_idempotent_through_normalize_and_store(tmp_path: Path):
    rec = normalize_job_output({"jobUid": "u-3", "stdout": _service_line(fakes.LICENSE_KEY)})
    again = normalize_job_output(rec.to_dict())
    assert again.stdout == rec.stdout and again.redactions == rec.redactions == 1
    store = JobOutputStore(tmp_path)
    store.save(rec)
    assert store.get("u-3") == rec


def test_redaction_happens_before_the_cap():
    key = fakes.LICENSE_KEY
    head = "x" * (400_000 - 30)
    rec = normalize_job_output({"stdout": head + " --license_key " + key})
    assert key[:8] not in rec.stdout and len(rec.stdout) == 400_000


def test_powershell_relay_does_not_wrap_long_values():
    # Out-String at the host width would split a long service command line
    # (and a key in it) across lines; the relay asks for one line.
    out = build_relay_wrapper("Get-CimInstance Win32_Service | Format-List Name, PathName",
                              job_name="svc", job_uid="u", ingest_url="https://octo.example/x",
                              token="tok-abc", shell="powershell")
    assert "*>&1 | Out-String -Width 4096" in out


def test_normalize_redacts_wrapped_format_list_and_registry_output():
    key = fakes.rand("job-wrap", 32)
    reg = fakes.rand("job-reg", 32)
    text = ('Name     : RocketAgent\n'
            'PathName : "C:\\Program Files\\Rocket\\agent.exe" --license_key ' + key[:12] + "\n"
            "           " + key[12:] + " --mode service\n\n"
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Rocket\n"
            "    LicenseKey    REG_SZ    " + reg + "\n"
            "    InstallDir    REG_SZ    C:\\Program Files\\Rocket\n")
    rec = normalize_job_output({"jobUid": "u-wrap", "stdout": text})
    for part in (key[:12], key[12:], reg):
        assert part not in rec.stdout
    assert "--mode service" in rec.stdout and "InstallDir    REG_SZ    C:\\Program Files\\Rocket" in rec.stdout
    assert rec.redactions == 2


def test_route_stores_redacted_output(monkeypatch):
    saved: list = []
    _patch(monkeypatch, instance=_instance(), creds={"DATTO_JOB_OUTPUT_TOKEN": "s3cret"},
           saved=saved)
    body = json.dumps({"hostname": "HOST1", "jobUid": "u-43", "exit": 0,
                       "stdout": _service_line(fakes.LICENSE_KEY), "stderr": ""}).encode()
    _run(webhooks.datto_job_output(_FakeRequest(body, headers={"x-webhook-token": "s3cret"})))
    assert saved and fakes.LICENSE_KEY not in saved[0].stdout and saved[0].redactions == 1


# --------------------------------------------------------------------------- #
# store
# --------------------------------------------------------------------------- #

def test_store_round_trip(tmp_path: Path):
    store = JobOutputStore(tmp_path)
    rec = JobOutputRecord("H", "job", "uid-7", "ts", 0, "so", "se")
    path = store.save(rec)
    assert path.exists()
    got = store.get("uid-7")
    assert got is not None and got.stdout == "so" and got.stderr == "se"
    assert store.get("missing") is None


def test_store_sanitizes_path_traversal(tmp_path: Path):
    store = JobOutputStore(tmp_path)
    rec = JobOutputRecord("H", "j", "../../etc/passwd", "ts", 0, "x", "")
    path = store.save(rec)
    # file stays inside base_dir; traversal chars are neutralized
    assert tmp_path in path.parents
    assert ".." not in path.name


# --------------------------------------------------------------------------- #
# route
# --------------------------------------------------------------------------- #

class _FakeRequest:
    def __init__(self, body: bytes, headers=None, query=None):
        self._body = body
        self.headers = headers or {}
        self.query_params = query or {}

    async def body(self) -> bytes:
        return self._body


def _run(coro):
    return asyncio.run(coro)


def _patch(monkeypatch, *, instance, creds, saved):
    monkeypatch.setattr(
        webhooks, "list_instances", lambda **k: ([instance] if instance else [])
    )
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: creds))

    class _FakeStore:
        @classmethod
        def default(cls):
            return cls()

        def save(self, record):
            saved.append(record)
            return None

    monkeypatch.setattr(webhooks, "JobOutputStore", _FakeStore)


def _instance():
    return SimpleNamespace(vendor_slug="datto", cred_ref="ref-1", default_tenant_slug=None)


def test_route_no_instance_is_the_generic_401_not_a_404(monkeypatch):
    # Same reject as a bad token — a 404 let callers enumerate integrations.
    _patch(monkeypatch, instance=None, creds={}, saved=[])
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_job_output(_FakeRequest(b"{}")))
    assert ei.value.code == "AUTH_INVALID"


def test_route_missing_token_config_rejects(monkeypatch):
    _patch(monkeypatch, instance=_instance(), creds={}, saved=[])
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_job_output(_FakeRequest(b"{}", headers={"x-webhook-token": "x"})))
    assert ei.value.code == "AUTH_INVALID"


def test_route_wrong_token_rejects(monkeypatch):
    _patch(monkeypatch, instance=_instance(), creds={"DATTO_JOB_OUTPUT_TOKEN": "right"},
           saved=[])
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_job_output(
            _FakeRequest(b"{}", headers={"x-webhook-token": "wrong"})))
    assert ei.value.code == "AUTH_INVALID"


def test_route_valid_token_stores(monkeypatch):
    saved: list = []
    _patch(monkeypatch, instance=_instance(), creds={"DATTO_JOB_OUTPUT_TOKEN": "s3cret"},
           saved=saved)
    body = json.dumps({"hostname": "HOST1", "jobUid": "u-42", "exit": 0,
                       "stdout": "ok", "stderr": ""}).encode()
    res = _run(webhooks.datto_job_output(
        _FakeRequest(body, headers={"x-webhook-token": "s3cret"})))
    assert res["stored"] is True and res["jobUid"] == "u-42"
    assert saved and saved[0].hostname == "HOST1" and saved[0].stdout == "ok"


def test_route_rejects_token_via_query_param(monkeypatch):
    # Header only: a ?token= would land the secret in URLs / access logs, and
    # the relay wrapper has only ever sent the X-Webhook-Token header.
    saved: list = []
    _patch(monkeypatch, instance=_instance(), creds={"DATTO_JOB_OUTPUT_TOKEN": "s3cret"},
           saved=saved)
    body = json.dumps({"jobUid": "q-1", "stdout": "via-query"}).encode()
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_job_output(_FakeRequest(body, query={"token": "s3cret"})))
    assert ei.value.code == "AUTH_INVALID" and saved == []


def test_route_alert_secret_does_not_open_job_output(monkeypatch):
    # The two secrets are scoped: the alert-webhook one must not authorize here.
    saved: list = []
    _patch(monkeypatch, instance=_instance(), creds={"DATTO_WEBHOOK_SECRET": "alert"},
           saved=saved)
    with pytest.raises(APIError) as ei:
        _run(webhooks.datto_job_output(
            _FakeRequest(b"{}", headers={"x-webhook-token": "alert"})))
    assert ei.value.code == "AUTH_INVALID" and saved == []
