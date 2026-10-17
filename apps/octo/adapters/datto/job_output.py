"""Datto RMM quick-job stdout/stderr round-trip.

Datto's RMM API does not return quick-job stdout/stderr — historically the only
way to read job output was to download it from the RMM web UI by hand, which
breaks any programmatic (or autonomous) workflow. This module closes that gap.

Producer side: every dispatched quick-job is wrapped with a small relay
header/footer (:func:`build_relay_wrapper`) that captures *all* streams
(stdout **and** stderr) and POSTs them to OCTO's ingest route
(``POST /api/v1/webhooks/datto/job-output``), correlated by ``jobUid``. The
wrapper still echoes to stdout so the RMM UI keeps working as a fallback, and a
relay failure never fails the underlying job.

The wrapper carries a watermark (comment banner + first output line) that
IDENTIFIES the job — label, job ID, RMM tenant — and never vouches for it: any
text in a script can be copied onto another script, so the SOC verifies an
Athena job in the RMM job log — a record with this job ID that ran on THIS
device at the time of the alert — never by the banner. A real job ID copied
from an earlier job (script-block logs, the agent's cache) has a record, but
for another device or another time. Job IDs come from :func:`new_job_id`: one
per dispatch, with a random part. See :class:`WatermarkSettings`.

Consumer side: :func:`normalize_job_output` validates the posted envelope and
:class:`JobOutputStore` persists it keyed by ``jobUid`` so the output can be read
without an RMM-UI download.

Secret-shaped substrings are redacted before the output is stored or handed
on (``[REDACTED:<detector>]``): on normalize, again on save, and on every read
back. A loose filter once dumped service command lines, including an agent's
``--license_key``, into job output (field note #14). The detectors are the
repo scanner's (``apps.octo.security.secret_patterns``), so one list covers
code, copies and job output. File hashes and encoded command lines are kept:
they are triage evidence, not secrets.

Auth for the ingest route is a **scoped, write-only token**
(``DATTO_JOB_OUTPUT_TOKEN``), distinct from the alert-webhook secret — it only
authorizes posting job output and is the only secret embedded on endpoints, so
it can be rotated independently.

The wrapper builder is pure (no I/O beyond reading its env settings) so it is
fully unit-testable; the dispatch layer that calls it lands with the Datto
action/quick-job slice.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Optional

from apps.octo.security.secret_patterns import redact as redact_secrets

logger = logging.getLogger(__name__)

# Output is capped so a runaway job cannot post an unbounded body. Matches the
# webhook router's 1 MB ceiling with headroom for the JSON envelope.
MAX_OUTPUT_CHARS = 400_000
# Redaction runs before the final cap, on a little more than will be kept, so
# a secret straddling the cap is not cut into an unrecognizable half.
_REDACT_WINDOW = MAX_OUTPUT_CHARS + 4_096

Shell = Literal["powershell", "posix"]

_JOBUID_SAFE = re.compile(r"[^A-Za-z0-9._-]")


# --------------------------------------------------------------------------- #
# Watermark — identification only, never a claim of authorization
# --------------------------------------------------------------------------- #

# Rick, 2026-10-09: the old banner (it called the job authorized, sanctioned,
# "not an intrusion") became public, so anyone with code execution on a
# managed endpoint could paste it onto a malicious script for an analyst to
# dismiss. The banner now only says WHICH job this is; the SOC verifies that
# job ID ran on this device in the RMM job log. A banner without a matching job record is not ours.

DEFAULT_BANNER_LABEL = "ATHENA AUTOMATION"
DEFAULT_USER_AGENT = "AthenaRMM/2"              # PowerShell relay
DEFAULT_USER_AGENT_SHELL = "AthenaRMM-shell/2"  # POSIX relay

# Per-deployment settings — env, like OCTO_JOB_OUTPUT_DIR below.
ENV_BANNER_LABEL = "OCTO_JOB_BANNER_LABEL"
ENV_USER_AGENT = "OCTO_JOB_USER_AGENT"
ENV_USER_AGENT_SHELL = "OCTO_JOB_USER_AGENT_SHELL"
ENV_RMM_TENANT = "OCTO_JOB_RMM_TENANT"

# The label goes LITERALLY into the comment banner and into a double-quoted
# echo string (PowerShell and POSIX): an allowlist, so no quote, backtick, `$`,
# backslash, `#`, `<`, `>`, `|` or control character can ever appear.
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/+()-]{0,47}")
# The User-Agent sits in an escaped single-quoted literal; allowlisted as well.
_UA_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/+();-]{0,63}")
# Job ID / tenant appear verbatim inside the comment banner (`<# ... #>` /
# `# ...`), elsewhere through an escaped literal. They are IDENTIFIERS, so an
# ID-shaped allowlist: no space (an id cannot carry a sentence into the
# banner), no quote, no comment delimiter, no `|`, nothing non-ASCII.
_BANNER_FIELD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
# A label, User-Agent, job ID or tenant identifies; it may not vouch for the
# job — no claim word anywhere in the generated banner / echo / headers.
_CLAIM_RE = re.compile(
    r"authori[sz]|sanction|approv|legit|benign|trusted|whitelist|allowlist"
    r"|expected|intrusion|malicious|\bsafe\b",
    re.IGNORECASE,
)


def _check_label(value: Any, what: str) -> str:
    text = "" if value is None else str(value)
    if not _LABEL_RE.fullmatch(text) or text != text.rstrip():
        raise ValueError(
            f"{what}: 1-48 characters, a letter or digit first, then only "
            "letters, digits, spaces and . _ : / + ( ) -"
        )
    if _CLAIM_RE.search(text):
        raise ValueError(
            f"{what}: the job banner identifies a job, it never claims the job "
            "is authorized / expected / safe — the SOC verifies by job ID"
        )
    return text


def _check_user_agent(value: Any, what: str) -> str:
    text = "" if value is None else str(value)
    if not _UA_RE.fullmatch(text) or text != text.rstrip():
        raise ValueError(
            f"{what}: 1-64 characters, a letter or digit first, then only "
            "letters, digits, spaces and . _ : / + ( ) ; -"
        )
    if _CLAIM_RE.search(text):
        raise ValueError(
            f"{what}: a User-Agent identifies the relay, it never claims the "
            "job is authorized / expected / safe"
        )
    return text


def _check_banner_field(value: Any, what: str) -> str:
    text = "" if value is None else str(value)
    if not _BANNER_FIELD_RE.fullmatch(text):
        raise ValueError(
            f"{what}: 1-128 characters, a letter or digit first, then only "
            "letters, digits and . _ : - (an identifier, shown verbatim in the "
            "job banner)"
        )
    if _CLAIM_RE.search(text):
        raise ValueError(
            f"{what}: an identifier in the job banner never claims the job is "
            "authorized / expected / safe — the SOC verifies by job ID"
        )
    return text


def new_job_id(prefix: str = "athena", *, now: Optional[datetime] = None) -> str:
    """A fresh job ID for ONE dispatch: ``<prefix>-<UTC yyyymmddThhmmssZ>-<16 hex>``.

    The dispatch layer calls this once per quick job and sends the result both
    as ``job_name`` to :func:`build_relay_wrapper` and as the Datto quick job's
    ``jobName``, so the banner, the first output line and the RMM job log carry
    the same ID. It is never reused: one ID = one dispatch = one record (its
    devices, its time) in the job log. The random part (64 bits) means an ID
    cannot be guessed — a forged banner has to copy a real one, whose record
    then shows another device or another time.
    """
    _check_banner_field(prefix, "prefix")
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    # Re-checked whole: a long prefix must not yield an ID over the bound.
    return _check_banner_field(
        f"{prefix}-{stamp:%Y%m%dT%H%M%SZ}-{secrets.token_hex(8)}", "prefix",
    )


@dataclass(frozen=True)
class WatermarkSettings:
    """What the job banner and the relay's User-Agent say, per deployment.

    ``label`` heads the comment banner and the echoed first output line;
    ``user_agent`` / ``user_agent_shell`` are the PowerShell / POSIX relay's
    User-Agent; ``rmm_tenant`` (optional) names the RMM account the jobs are
    created under (e.g. the Datto account UID) so the SOC knows which RMM's
    job log to check. Every field is validated on construction — a bad value
    raises ``ValueError``, it is never silently replaced.
    """

    label: str = DEFAULT_BANNER_LABEL
    user_agent: str = DEFAULT_USER_AGENT
    user_agent_shell: str = DEFAULT_USER_AGENT_SHELL
    rmm_tenant: Optional[str] = None

    def __post_init__(self) -> None:
        _check_label(self.label, "label")
        _check_user_agent(self.user_agent, "user_agent")
        _check_user_agent(self.user_agent_shell, "user_agent_shell")
        if self.rmm_tenant is not None:
            _check_banner_field(self.rmm_tenant, "rmm_tenant")

    @classmethod
    def from_env(
        cls, environ: Optional[Mapping[str, str]] = None,
    ) -> "WatermarkSettings":
        """``OCTO_JOB_BANNER_LABEL`` / ``OCTO_JOB_USER_AGENT`` /
        ``OCTO_JOB_USER_AGENT_SHELL`` / ``OCTO_JOB_RMM_TENANT``; unset or blank
        = the default. An invalid value raises ``ValueError`` naming the
        variable (never echoing the value)."""
        env = os.environ if environ is None else environ

        def read(var: str, default: str, check: Callable[[Any, str], str]) -> str:
            raw = (env.get(var) or "").strip()
            return check(raw, var) if raw else default

        return cls(
            label=read(ENV_BANNER_LABEL, DEFAULT_BANNER_LABEL, _check_label),
            user_agent=read(ENV_USER_AGENT, DEFAULT_USER_AGENT, _check_user_agent),
            user_agent_shell=read(
                ENV_USER_AGENT_SHELL, DEFAULT_USER_AGENT_SHELL, _check_user_agent,
            ),
            rmm_tenant=read(ENV_RMM_TENANT, "", _check_banner_field) or None,
        )


def job_banner(label: str, job_id: str, rmm_tenant: Optional[str] = None) -> str:
    """The one-line banner text, without the shell's comment markers."""
    where = f" | RMM tenant {rmm_tenant}" if rmm_tenant else ""
    return (
        f"{label} | job {job_id}{where} - identification only: verify this job "
        "ID ran on this device in the RMM job log. A banner without a matching "
        "job record is not "
        "ours."
    )


# --------------------------------------------------------------------------- #
# Wrapper builder (producer)
# --------------------------------------------------------------------------- #

# PowerShell wrapper (Windows). `__ATHENA_BODY__` is replaced with the job body,
# run inside a scriptblock whose every stream is merged for the UI/log, with the
# error stream additionally isolated into a dedicated `stderr` field.
# The banner is a `<# ... #>` BLOCK comment on purpose: if the script is ever
# pasted into the RMM UI's ad-hoc command field, which collapses newlines to
# spaces, a leading `#` line comment would swallow the whole script silently
# (exit 0, no output). The block comment closes on its own line, so such a
# paste fails to PARSE instead — loudly. The wrapper itself is NOT
# flatten-safe (newline-separated statements, a multi-line hashtable, backtick
# continuations): dispatch it as a multi-line quick-job / component script.
_PS_TEMPLATE = r"""<# __ATHENA_BANNER__ #>
$ATHENA_RELAY_URI   = '__ATHENA_URL__'
$ATHENA_RELAY_TOKEN = '__ATHENA_TOKEN__'
$ATHENA_RELAY_UA    = '__ATHENA_UA__'
$ATHENA_JOB         = '__ATHENA_JOB__'
$ATHENA_JOB_UID     = '__ATHENA_JOBUID__'
"=== __ATHENA_LABEL__ | job=$ATHENA_JOB | verify in the RMM job log | $((Get-Date).ToUniversalTime().ToString('o')) ==="
$ErrorActionPreference = 'Continue'
$Error.Clear()

# -Width 4096: no wrapping at the host width, so a long value (a service
# command line with a key in it) reaches the ingest route on one line.
$__merged = & {
__ATHENA_BODY__
} *>&1 | Out-String -Width 4096

$__stderr = (@($Error) | ForEach-Object { $_.ToString() }) -join "`n"
$__exit   = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 0 }

try {
  $payload = @{
    hostname = $env:COMPUTERNAME
    job      = $ATHENA_JOB
    jobUid   = $ATHENA_JOB_UID
    ts       = (Get-Date).ToUniversalTime().ToString('o')
    exit     = $__exit
    stdout   = $__merged
    stderr   = $__stderr
  } | ConvertTo-Json -Compress -Depth 5
  Invoke-RestMethod -Uri $ATHENA_RELAY_URI -Method Post `
    -ContentType 'application/json' `
    -Headers @{ 'X-Webhook-Token' = $ATHENA_RELAY_TOKEN; 'User-Agent' = $ATHENA_RELAY_UA } `
    -Body $payload -TimeoutSec 30 | Out-Null
  "ATHENA-RELAY: ok (stdout=$($__merged.Length)c stderr=$($__stderr.Length)c)"
} catch {
  "ATHENA-RELAY: failed - $($_.Exception.Message)"
}

$__merged
if ($__stderr) { "`n--- STDERR (isolated) ---`n$__stderr" }
"""

# POSIX shell wrapper (Linux/macOS). Heredoc-free so it survives Datto's shell
# ad-hoc runner; falls back gracefully if python3 is unavailable.
_POSIX_TEMPLATE = r"""#!/bin/bash
# __ATHENA_BANNER__
ATHENA_RELAY_URI='__ATHENA_URL__'
ATHENA_RELAY_TOKEN='__ATHENA_TOKEN__'
ATHENA_RELAY_UA='__ATHENA_UA__'
ATHENA_JOB='__ATHENA_JOB__'
ATHENA_JOB_UID='__ATHENA_JOBUID__'
echo "=== __ATHENA_LABEL__ | job=$ATHENA_JOB | verify in the RMM job log | $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
__OUT=$(mktemp); __ERR=$(mktemp)
{
__ATHENA_BODY__
} >"$__OUT" 2>"$__ERR"
__EX=$?
# base64 the streams so arbitrary output is JSON-safe WITHOUT a JSON tool.
# No python3 dependency: bare macOS ships neither python3 nor jq, and the Datto
# agent's minimal exec context may not expose python3 either. base64 + curl are
# universal on macOS/Linux; the ingest route base64-decodes stdout_b64/stderr_b64.
__SO=$(base64 < "$__OUT" | tr -d '\n')
__SE=$(base64 < "$__ERR" | tr -d '\n')
__TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
__BODY="{\"hostname\":\"$(hostname)\",\"job\":\"$ATHENA_JOB\",\"jobUid\":\"$ATHENA_JOB_UID\",\"ts\":\"$__TS\",\"exit\":$__EX,\"stdout_b64\":\"$__SO\",\"stderr_b64\":\"$__SE\"}"
if command -v curl >/dev/null 2>&1; then
  curl -s -m 30 -X POST "$ATHENA_RELAY_URI" \
    -H "X-Webhook-Token: $ATHENA_RELAY_TOKEN" \
    -H "Content-Type: application/json" \
    -H "User-Agent: $ATHENA_RELAY_UA" \
    --data "$__BODY" >/dev/null 2>&1 && echo "ATHENA-RELAY: ok" || echo "ATHENA-RELAY: failed"
else
  echo "ATHENA-RELAY: curl missing - output not relayed"
fi
cat "$__OUT"; [ -s "$__ERR" ] && { echo "--- STDERR (isolated) ---"; cat "$__ERR"; }
rm -f "$__OUT" "$__ERR"
"""

# Every placeholder is filled in ONE pass, so a value that happens to contain
# another placeholder's name (a job name with "__ATHENA_BODY__" in it) is never
# expanded a second time.
_PLACEHOLDER_RE = re.compile(r"__ATHENA_[A-Z]+__")


def _ps_lit(value: str) -> str:
    """Escape a value for a PowerShell single-quoted string literal."""
    return value.replace("'", "''")


def _sh_lit(value: str) -> str:
    """Escape a value for a POSIX single-quoted string literal."""
    return value.replace("'", "'\\''")


def build_relay_wrapper(
    script: str,
    *,
    job_name: str,
    job_uid: str,
    ingest_url: str,
    token: str,
    shell: Shell = "powershell",
    rmm_tenant: Optional[str] = None,
    watermark: Optional[WatermarkSettings] = None,
) -> str:
    """Wrap a quick-job ``script`` so its output relays to OCTO's ingest route.

    The returned script runs ``script`` unchanged, captures stdout+stderr, POSTs
    a JSON envelope (``hostname/job/jobUid/ts/exit/stdout/stderr``) to
    ``ingest_url`` authenticated by ``token``, and still echoes output for the
    RMM UI. Relay is best-effort and never fails the underlying job.

    ``token`` is provided by the caller from the vault at dispatch time and must
    be the scoped write-only ingest token — never hardcode it.

    Watermark: ``job_name`` is the JOB ID that the banner and the first output
    line show and the SOC looks up in the RMM job log. Datto assigns its own
    job uid only when the job is created — after this script is built — so the
    dispatch layer MUST send this exact ``job_name`` as the quick job's
    ``jobName``: that is the name the RMM job log shows. The dispatch layer
    MUST also take it from :func:`new_job_id` — a fresh ID per dispatch,
    never reused — because the SOC's check is "a record with this ID ran on
    THIS device at the time of the alert": a reused or guessable ID makes that
    record ambiguous. It must be an identifier (1-128 of letters, digits,
    ``. _ : -``, a letter or digit first, no claim word), else ``ValueError``.
    ``rmm_tenant`` (else ``watermark.rmm_tenant``) names the RMM account, same
    rules; with neither, the banner leaves the tenant out. ``watermark``
    defaults to :meth:`WatermarkSettings.from_env`.
    """
    if shell not in ("powershell", "posix"):
        raise ValueError(f"unsupported shell: {shell!r}")
    settings = watermark if watermark is not None else WatermarkSettings.from_env()
    job_id = _check_banner_field(job_name, "job_name")
    tenant = (
        _check_banner_field(rmm_tenant, "rmm_tenant") if rmm_tenant
        else settings.rmm_tenant
    )
    if shell == "powershell":
        template, esc, user_agent = _PS_TEMPLATE, _ps_lit, settings.user_agent
    else:
        template, esc, user_agent = _POSIX_TEMPLATE, _sh_lit, settings.user_agent_shell
    values = {
        # Literal — validated, never escaped (they sit in a comment / an echo):
        "__ATHENA_BANNER__": job_banner(settings.label, job_id, tenant),
        "__ATHENA_LABEL__": settings.label,
        # Single-quoted literals — escaped:
        "__ATHENA_URL__": esc(ingest_url),
        "__ATHENA_TOKEN__": esc(token),
        "__ATHENA_UA__": esc(user_agent),
        "__ATHENA_JOB__": esc(job_id),
        "__ATHENA_JOBUID__": esc(job_uid),
        # The job itself, verbatim.
        "__ATHENA_BODY__": script,
    }
    return _PLACEHOLDER_RE.sub(lambda m: values[m.group(0)], template)


# --------------------------------------------------------------------------- #
# Payload normalization (consumer)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class JobOutputRecord:
    """A validated, normalized quick-job output relayed from an endpoint.

    ``stdout`` / ``stderr`` are already redacted; ``redactions`` counts the
    secret-shaped values replaced (never the values themselves)."""

    hostname: str
    job: str
    job_uid: str
    ts: str
    exit_code: int
    stdout: str
    stderr: str
    redactions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "job": self.job,
            "jobUid": self.job_uid,
            "ts": self.ts,
            "exit": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "redactions": self.redactions,
        }


def _clip(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    return text[:limit]


def _decode_stream(envelope: dict[str, Any], plain_key: str, b64_key: str) -> str:
    """Resolve an output stream from either the plain field (PowerShell relay,
    which JSON-encodes natively) or the base64 field (POSIX relay, which has no
    JSON tool so it base64s the bytes). Invalid base64 degrades to empty.
    Returns a little more than :data:`MAX_OUTPUT_CHARS`; the caller redacts,
    then caps."""
    b64 = envelope.get(b64_key)
    if b64 is not None:
        try:
            return base64.b64decode(str(b64), validate=False).decode(
                "utf-8", "replace"
            )[:_REDACT_WINDOW]
        except (binascii.Error, ValueError):
            return ""
    return _clip(envelope.get(plain_key), _REDACT_WINDOW)


def _scrub(text: str) -> tuple[str, int]:
    """Redact secret-shaped values, then cap the stream."""
    clean, count = redact_secrets(text)
    return clean[:MAX_OUTPUT_CHARS], count


def redact_record(record: JobOutputRecord) -> JobOutputRecord:
    """The record with its streams redacted (idempotent: a redaction marker
    is never redacted again)."""
    stdout, n_out = _scrub(record.stdout)
    stderr, n_err = _scrub(record.stderr)
    if not (n_out or n_err):
        return record
    return replace(record, stdout=stdout, stderr=stderr,
                   redactions=record.redactions + n_out + n_err)


def normalize_job_output(envelope: dict[str, Any]) -> JobOutputRecord:
    """Validate + normalize a posted job-output envelope.

    Tolerant of missing optional fields; only an absurdly large body is
    rejected upstream (router caps the raw bytes). ``jobUid``/``job`` accept the
    relay's camelCase keys; ``exit`` is coerced to int (default 0). Both
    streams come back redacted (see the module docstring).
    """
    if not isinstance(envelope, dict):
        raise ValueError("job-output body is not a JSON object")
    try:
        exit_code = int(envelope.get("exit", 0) or 0)
    except (TypeError, ValueError):
        exit_code = 0
    try:
        prior = max(0, int(envelope.get("redactions", 0) or 0))  # a stored record read back
    except (TypeError, ValueError):
        prior = 0
    stdout, n_out = _scrub(_decode_stream(envelope, "stdout", "stdout_b64"))
    stderr, n_err = _scrub(_decode_stream(envelope, "stderr", "stderr_b64"))
    return JobOutputRecord(
        hostname=_clip(envelope.get("hostname"), 255),
        job=_clip(envelope.get("job"), 255),
        job_uid=_clip(envelope.get("jobUid") or envelope.get("job_uid"), 128),
        ts=_clip(envelope.get("ts"), 64),
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        redactions=prior + n_out + n_err,
    )


# --------------------------------------------------------------------------- #
# Store (consumer persistence)
# --------------------------------------------------------------------------- #

_DEFAULT_DIR = "/var/lib/octo/state/datto-job-output"


@dataclass(frozen=True)
class JobOutputStore:
    """File-backed store of relayed job output, keyed by ``jobUid``.

    One JSON file per job under ``base_dir``. Deliberately simple + flat
    (operational artifact, not tenant telemetry); the action layer reads it back
    by jobUid. Filenames are sanitized to defeat path traversal.
    """

    base_dir: Path

    @classmethod
    def default(cls) -> "JobOutputStore":
        return cls(Path(os.environ.get("OCTO_JOB_OUTPUT_DIR", _DEFAULT_DIR)))

    def _path_for(self, job_uid: str) -> Path:
        safe = _JOBUID_SAFE.sub("_", job_uid).strip("._") or "no-jobuid"
        return self.base_dir / f"{safe[:128]}.json"

    def save(self, record: JobOutputRecord) -> Path:
        # Redact again: a record built anywhere but normalize_job_output must
        # not reach the disk with a secret in it.
        record = redact_record(record)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(record.job_uid)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record.to_dict(), ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)  # atomic on the same filesystem
        return path

    def get(self, job_uid: str) -> Optional[JobOutputRecord]:
        path = self._path_for(job_uid)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return normalize_job_output(data)
