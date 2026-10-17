#!/usr/bin/env python3
"""buoy-heartbeat.py — periodic fleet-status push to OCTO.

Sibling to buoy-forwarder. Posts a JSON snapshot of the buoy's
system load, service-unit states, and last-event-relayed timestamp
to /api/v1/buoy/heartbeat every INTERVAL_SEC seconds. OCTO upserts
the row in registry.db::buoys and the dashboard renders it.

Coexists with buoy-forwarder (which already posts ingest events).
No state or config overlap — separate /etc, separate /var/lib.

Environment:
  OCTO_URL          Base URL of the OCTO admin API (tailnet
                    address + bedrock port — set in the env file)
  OCTO_SLUG         This buoy's tenant slug (e.g. "alpha")
  OCTO_TOKEN_FILE   Path to bearer token file (read at startup;
                    file mode SHOULD be 0600)
  SERVICES          Comma-separated systemd unit names to probe.
                    Default: a sensible Athena-Buoy default set.
                    Also used as the whitelist for tail-log /
                    restart-service buoy commands (slice 11).
  LAST_EVENT_FILE   Optional path that buoy-forwarder writes its
                    last-success ISO timestamp into. If present,
                    its contents are forwarded as last_event_at.
  INTERVAL_SEC      Heartbeat cadence in seconds (default 60).
  STATE_DIR         Where the JSONL retry queue lives.
  HTTP_TIMEOUT_SEC  Per-request timeout (default 15).
  QUEUE_MAX         Max queued heartbeats while OCTO unreachable
                    (default 60 — i.e. one hour at 60s cadence).
  COMMAND_TIMEOUT_SEC  Wall-clock timeout per buoy command
                    handler invocation (default 60).
  LOG_LEVEL         Default INFO.

Boot-time assertion: resolves bearer via /api/v1/whoami and refuses
to start if the resolved slug doesn't match OCTO_SLUG. Loud failure
beats silently heartbeating as the wrong tenant.

Stdlib-only by design (matches buoy-forwarder.py style — no pip
install on the appliance).

Rick + Claude Code, 2026-05-15 — Buoy Heartbeat slice 3.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


LOG = logging.getLogger("buoy-heartbeat")


# ---------------------------------------------------------------------------
# Config (read once at startup)
# ---------------------------------------------------------------------------

# The units a healthy buoy runs. `octo-forwarder` (Suricata → the legacy
# threat-intel API) was retired 2026-09-29 with the legacy host. Every
# watched unit is reported with its `is-enabled` state; OCTO shows a
# disabled one as RETIRED only when the bundle's operator list says so
# (OCTO_BUOY_RETIRED_UNITS, default octo-forwarder — `apps.octo.api.
# buoy_health`); any other disabled unit is a fault (a security tool
# switched off on the buoy must never read as healthy).
#
# Deploy note: a SERVICES override in the buoy's env file replaces this
# list. Buoys that run a parallel-run forwarder unit
# (`buoy-forwarder-<suffix>`, with the legacy `buoy-forwarder` stopped
# and disabled) rely on that override — keep it until the units are
# renamed back, or the real forwarder is not watched at all.
DEFAULT_SERVICES = (
    "tailscaled",
    "wazuh-agent",
    "opencanary",
    "suricata",
    "buoy-forwarder",
    "pihole-FTL",
    "nextdns",
)


class Config:
    octo_url: str
    octo_slug: str
    token: str
    services: tuple[str, ...]
    last_event_file: Optional[Path]
    interval_sec: int
    state_dir: Path
    http_timeout_sec: int
    queue_max: int
    lat: Optional[float]
    lng: Optional[float]

    @classmethod
    def load(cls) -> "Config":
        c = cls()
        c.octo_url = _require_env("OCTO_URL").rstrip("/")
        c.octo_slug = _require_env("OCTO_SLUG")
        token_path = Path(_require_env("OCTO_TOKEN_FILE"))
        c.token = token_path.read_text().strip()
        if not c.token:
            raise RuntimeError(f"OCTO_TOKEN_FILE {token_path} is empty")

        services_env = os.environ.get("SERVICES", "").strip()
        c.services = tuple(s.strip() for s in services_env.split(",") if s.strip()) \
                     or DEFAULT_SERVICES

        lef = os.environ.get("LAST_EVENT_FILE", "").strip()
        c.last_event_file = Path(lef) if lef else None

        c.interval_sec = int(os.environ.get("INTERVAL_SEC", "60"))
        if not (10 <= c.interval_sec <= 3600):
            raise RuntimeError(
                f"INTERVAL_SEC out of range (10..3600): {c.interval_sec}"
            )

        c.state_dir = Path(os.environ.get("STATE_DIR", "/var/lib/buoy-heartbeat"))
        c.state_dir.mkdir(parents=True, exist_ok=True)

        c.http_timeout_sec = int(os.environ.get("HTTP_TIMEOUT_SEC", "15"))
        c.queue_max = int(os.environ.get("QUEUE_MAX", "60"))

        # Optional geo coords for the Fleet map view (2026-05-19 fleet
        # redesign). Operator sets these once at install in
        # /etc/buoy-heartbeat/heartbeat.env. Buoys without LAT/LNG keep
        # heartbeating fine — they just don't render on the map.
        c.lat = _parse_float_env("LAT")
        c.lng = _parse_float_env("LNG")
        if c.lat is not None and not (-90.0 <= c.lat <= 90.0):
            raise RuntimeError(f"LAT out of range [-90, 90]: {c.lat}")
        if c.lng is not None and not (-180.0 <= c.lng <= 180.0):
            raise RuntimeError(f"LNG out of range [-180, 180]: {c.lng}")
        return c


def _require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"required env var missing: {name}")
    return v


def _parse_float_env(name: str) -> Optional[float]:
    """Read an optional float env var. Empty / unset → None. Non-numeric
    raises so misconfigurations surface loud at boot, not silently."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError as e:
        raise RuntimeError(f"env var {name} not a valid float: {raw!r}") from e


# ---------------------------------------------------------------------------
# System-metric gatherers (best-effort — None on failure)
# ---------------------------------------------------------------------------

def _read_uptime_sec() -> int:
    """First float in /proc/uptime is seconds-since-boot."""
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def _read_loadavg() -> tuple[Optional[float], Optional[float], Optional[float]]:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return (float(parts[0]), float(parts[1]), float(parts[2]))
    except (OSError, ValueError, IndexError):
        return (None, None, None)


def _read_mem_mb() -> tuple[Optional[int], Optional[int]]:
    """Returns (used_mb, total_mb). 'Used' = total - available."""
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                kb = int(rest.strip().split()[0])
                info[k.strip()] = kb
        total_kb = info.get("MemTotal", 0)
        avail_kb = info.get("MemAvailable", info.get("MemFree", 0))
        if total_kb <= 0:
            return (None, None)
        used_kb = max(0, total_kb - avail_kb)
        return (used_kb // 1024, total_kb // 1024)
    except (OSError, ValueError, IndexError):
        return (None, None)


def _read_disk_pct(path: str = "/") -> Optional[int]:
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total <= 0:
            return None
        used = total - free
        return int(round(used * 100 / total))
    except OSError:
        return None


def _read_service_states(units: tuple[str, ...]) -> dict[str, str]:
    """`systemctl is-active <unit>` for each unit; map to 'active' /
    'inactive' / 'failed' / 'missing'. systemd exits non-zero for
    inactive — we read stdout regardless and treat empty as 'missing'."""
    out: dict[str, str] = {}
    for unit in units:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=5,
            )
            state = (r.stdout.strip() or "missing")
            out[unit] = state
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            out[unit] = "unknown"
    return out


def _read_enabled_states(units: tuple[str, ...]) -> dict[str, str]:
    """`systemctl is-enabled <unit>` for each unit: 'enabled' / 'disabled' /
    'masked' / 'static' / … as systemd says it; 'not-found' when it prints
    nothing (no unit file); 'unknown' when systemctl could not be run. Sent
    beside the active state so OCTO can tell a unit an operator retired
    (disabled / masked AND on the bundle's retired list: grey, not a fault)
    from one that should be running and is not (degraded)."""
    out: dict[str, str] = {}
    for unit in units:
        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", unit],
                capture_output=True, text=True, timeout=5,
            )
            out[unit] = (r.stdout.strip().splitlines() or ["not-found"])[0][:32] or "not-found"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            out[unit] = "unknown"
    return out


def _read_last_event_at(path: Optional[Path]) -> Optional[str]:
    """buoy-forwarder is expected to write its last-success ISO timestamp
    into LAST_EVENT_FILE (if configured). Best-effort — None if absent or
    unreadable. The shape isn't validated here; if buoy-forwarder writes
    something non-ISO, OCTO just stores it verbatim."""
    if path is None:
        return None
    try:
        s = path.read_text().strip()
        return s or None
    except OSError:
        return None


def _gather_heartbeat(config: Config) -> dict[str, Any]:
    """Build the heartbeat payload for one cycle.

    `services` shape per the 2026-05-19 contract extension (project_
    heartbeat_service_contract_extension):

        { unit_name: { state, version?, stat?, last_activity? }, ... }

    OCTO accepts both the new dict-of-dicts shape (this) and the
    legacy flat `{ unit_name: state }` for backwards compat on old
    daemons. We always emit the new shape; the run_probes flag is here
    purely as a kill-switch if a buoy's probes are pathologically slow."""
    load_1, load_5, load_15 = _read_loadavg()
    mem_used, mem_total = _read_mem_mb()
    states = _read_service_states(config.services)
    # Lazy + dual-path import — heartbeat.py runs both as part of the
    # apps.octo package in dev/tests AND as a standalone script at
    # /usr/local/bin/buoy-heartbeat.py on the buoy (with services.py
    # dropped next to it by install-step2.sh).
    try:
        from apps.octo.buoy.services import probe_all  # type: ignore[import-not-found]
    except ImportError:
        from services import probe_all  # type: ignore[import-not-found,no-redef]
    services_payload = probe_all(states)
    # Enablement beside each unit's state (v0.11): disabled + on OCTO's
    # retired list ⇒ retired on the console, not degraded.
    for unit, enabled in _read_enabled_states(tuple(services_payload)).items():
        entry = services_payload.get(unit)
        if isinstance(entry, dict):
            entry["enabled"] = enabled
    payload: dict[str, Any] = {
        "slug": config.octo_slug,
        "hostname": socket.gethostname(),
        "uptime_sec": _read_uptime_sec(),
        "interval_sec": config.interval_sec,
        "load_1": load_1,
        "load_5": load_5,
        "load_15": load_15,
        "mem_used_mb": mem_used,
        "mem_total_mb": mem_total,
        "disk_used_pct": _read_disk_pct("/"),
        "services": services_payload,
        "last_event_at": _read_last_event_at(config.last_event_file),
    }
    # Geo coords are optional — only include keys when configured so
    # OCTO sees explicit nulls only for buoys that have NEVER reported
    # coords (vs ones the operator deliberately cleared).
    if config.lat is not None:
        payload["lat"] = config.lat
    if config.lng is not None:
        payload["lng"] = config.lng
    return payload


# ---------------------------------------------------------------------------
# HTTP — boot-check + heartbeat POST
# ---------------------------------------------------------------------------

def _http_request(
    config: Config, method: str, path: str,
    body: Optional[dict] = None,
) -> tuple[int, dict[str, Any]]:
    url = f"{config.octo_url}{path}"
    data: Optional[bytes] = None
    headers = {
        "Authorization": f"Bearer {config.token}",
        "Accept": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=config.http_timeout_sec) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:
                payload = {"_raw": text}
            return (resp.status, payload)
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(text) if text else {}
        except json.JSONDecodeError:
            payload = {"_raw": text}
        return (e.code, payload)


def _assert_slug_matches(config: Config) -> None:
    """Boot-time check: /whoami's resolved slug MUST match OCTO_SLUG.
    Refuses to start on mismatch — loud failure beats heartbeating as
    the wrong tenant. Mirrors buoy-forwarder's startup contract."""
    status, body = _http_request(config, "GET", "/api/v1/whoami")
    if status != 200:
        raise RuntimeError(
            f"/whoami probe failed: HTTP {status} body={body!r}"
        )
    resolved = body.get("slug")
    if resolved != config.octo_slug:
        raise RuntimeError(
            f"slug mismatch: OCTO_SLUG={config.octo_slug!r} "
            f"but bearer resolves to slug={resolved!r}. Refusing to start."
        )
    LOG.info("whoami OK: slug=%s kind=%s", resolved, body.get("kind"))


def _post_heartbeat_with_response(
    config: Config, payload: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """POST the heartbeat. Returns the parsed response body on accepted
    upsert (2xx + body.accepted=True), None on rejection.

    The response body may include `pending_commands` — a list of queued
    operator commands the buoy should execute. The main loop dispatches
    those; `_post_heartbeat_with_response` itself does NOT execute them
    (so that a handler like `refresh`, which itself calls this function,
    cannot trigger recursive dispatch)."""
    status, body = _http_request(config, "POST", "/api/v1/buoy/heartbeat", payload)
    if 200 <= status < 300 and body.get("accepted"):
        LOG.debug(
            "heartbeat ok next_by=%s pending=%d",
            body.get("next_expected_by"),
            len(body.get("pending_commands") or []),
        )
        return body
    LOG.warning("heartbeat rejected: HTTP %s body=%r", status, body)
    return None


def _post_heartbeat(config: Config, payload: dict[str, Any]) -> bool:
    """Bool-returning wrapper for callers that don't need the response
    body (e.g. `_drain_queue`, which forwards stale snapshots and
    intentionally ignores pending_commands from drain responses to
    avoid double-dispatch)."""
    return _post_heartbeat_with_response(config, payload) is not None


# ---------------------------------------------------------------------------
# JSONL retry queue (handles OCTO blips up to QUEUE_MAX entries)
# ---------------------------------------------------------------------------

def _queue_path(config: Config) -> Path:
    return config.state_dir / "queue.jsonl"


def _enqueue(config: Config, payload: dict[str, Any]) -> None:
    qp = _queue_path(config)
    try:
        lines = qp.read_text().splitlines() if qp.exists() else []
    except OSError:
        lines = []
    lines.append(json.dumps(payload, separators=(",", ":")))
    if len(lines) > config.queue_max:
        # Drop the oldest. The newest snapshot is always more relevant
        # than stale 1-hour-old metrics on reconnect.
        lines = lines[-config.queue_max:]
    try:
        qp.write_text("\n".join(lines) + "\n")
    except OSError as e:
        LOG.error("failed to enqueue: %s", e)


def _drain_queue(config: Config) -> None:
    qp = _queue_path(config)
    if not qp.exists():
        return
    try:
        lines = qp.read_text().splitlines()
    except OSError:
        return
    remaining: list[str] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue  # drop unparseable
        ok = _post_heartbeat(config, payload)
        if not ok:
            # OCTO still flaky — re-queue this and everything after.
            remaining = lines[i:]
            break
    try:
        if remaining:
            qp.write_text("\n".join(remaining) + "\n")
        else:
            qp.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Slice 11 — command executor (buoy-side)
#
# Operators queue commands at a buoy via POST /api/v1/buoy/{slug}/command
# (slice 7, server-side). OCTO returns queued commands inline on the next
# heartbeat response under `pending_commands`. The main loop calls
# `_dispatch_pending_commands` after each successful heartbeat; each
# pending command runs through a per-kind handler, and the result is
# POSTed back to /api/v1/buoy/command/{id}/result.
#
# Handler contract: each returns CommandResult =
#   (ok: bool, exit_code: int, stdout_tail: str, stderr_tail: str,
#    error_msg: Optional[str])
# stdout/stderr are tail-truncated to fit the server's 64KB cap.
# ---------------------------------------------------------------------------

RESULT_TAIL_MAX_BYTES = 64 * 1024
TAIL_LOG_MAX_LINES = 200

# Return type for command handlers.
CommandResult = tuple[bool, int, str, str, Optional[str]]


def _command_timeout_sec() -> int:
    """Read at call-time (rather than at module import) so tests can
    monkey-patch the env var without re-importing the module."""
    try:
        return max(1, int(os.environ.get("COMMAND_TIMEOUT_SEC", "60")))
    except ValueError:
        return 60


def _tail_bytes(s: str, max_bytes: int = RESULT_TAIL_MAX_BYTES) -> str:
    """Return the trailing slice of `s` whose UTF-8 encoding fits in
    `max_bytes`. Used to clamp stdout/stderr to the server's 64KB cap
    while preserving the most-recent (most informative) output."""
    b = s.encode("utf-8", errors="replace")
    if len(b) <= max_bytes:
        return s
    # Decode the trailing slice; replace the head byte if it lands
    # mid-codepoint so we never emit invalid UTF-8.
    return b[-max_bytes:].decode("utf-8", errors="replace")


def _handle_ping(config: Config, args: dict[str, str]) -> CommandResult:
    """ping — confirms the daemon is alive + reachable. The fact that
    the buoy was able to fetch + dispatch this command IS the signal;
    no further work needed."""
    msg = f"pong from {socket.gethostname()} slug={config.octo_slug}"
    return (True, 0, msg, "", None)


def _handle_refresh(config: Config, args: dict[str, str]) -> CommandResult:
    """refresh — gather + push a fresh heartbeat ahead of schedule.
    Useful when an operator wants to see updated service states without
    waiting for the next INTERVAL_SEC tick.

    Returns the fresh services_json as stdout so the UI can show "what
    was the state when refresh was honored?" inline with the command
    history."""
    payload = _gather_heartbeat(config)
    # Use the response-returning variant but IGNORE pending_commands —
    # otherwise we'd recursively dispatch any commands queued between
    # the triggering heartbeat and this refresh, doubling them.
    body = _post_heartbeat_with_response(config, payload)
    if body is None:
        return (False, 1, "", "fresh heartbeat POST rejected by OCTO",
                "heartbeat_post_failed")
    services_snapshot = json.dumps(
        payload.get("services", {}), separators=(",", ":"), sort_keys=True,
    )
    return (True, 0, services_snapshot, "", None)


def _handle_tail_log(config: Config, args: dict[str, str]) -> CommandResult:
    """tail-log — last N lines from `journalctl -u <unit>`.

    Args:
      unit  (required) systemd unit name. MUST be in config.services
            whitelist (i.e. one of the units this buoy heartbeats on).
      lines (optional) line count, 1..TAIL_LOG_MAX_LINES, default 100.

    Whitelisting the unit prevents operators from tailing arbitrary
    journals via this surface (defense in depth — the server-side
    args validator already filters, but the buoy doesn't trust)."""
    unit = (args or {}).get("unit", "").strip()
    if not unit:
        return (False, 2, "", "missing required arg 'unit'", "args_invalid")
    if unit not in config.services:
        return (False, 2, "",
                f"unit {unit!r} not in SERVICES whitelist",
                "unit_not_whitelisted")
    try:
        n_lines = int((args or {}).get("lines", "100"))
    except (TypeError, ValueError):
        n_lines = 100
    n_lines = max(1, min(n_lines, TAIL_LOG_MAX_LINES))
    try:
        r = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(n_lines), "--no-pager"],
            capture_output=True, text=True, timeout=_command_timeout_sec(),
        )
        return (
            r.returncode == 0,
            r.returncode,
            _tail_bytes(r.stdout),
            _tail_bytes(r.stderr),
            None,
        )
    except subprocess.TimeoutExpired:
        return (False, 124, "", "journalctl timed out", "command_timeout")
    except (FileNotFoundError, OSError) as e:
        return (False, 1, "", str(e), "exec_failed")


def _handle_restart_service(config: Config, args: dict[str, str]) -> CommandResult:
    """restart-service — `systemctl restart <unit>`.

    Args:
      unit (required) systemd unit name. MUST be in config.services
           whitelist. Restricting to the monitored set means an
           operator can only restart units this buoy explicitly
           reports on — no arbitrary service control."""
    unit = (args or {}).get("unit", "").strip()
    if not unit:
        return (False, 2, "", "missing required arg 'unit'", "args_invalid")
    if unit not in config.services:
        return (False, 2, "",
                f"unit {unit!r} not in SERVICES whitelist",
                "unit_not_whitelisted")
    try:
        r = subprocess.run(
            ["systemctl", "restart", unit],
            capture_output=True, text=True, timeout=_command_timeout_sec(),
        )
        return (
            r.returncode == 0,
            r.returncode,
            _tail_bytes(r.stdout),
            _tail_bytes(r.stderr),
            None,
        )
    except subprocess.TimeoutExpired:
        return (False, 124, "", "systemctl restart timed out", "command_timeout")
    except (FileNotFoundError, OSError) as e:
        return (False, 1, "", str(e), "exec_failed")


def _handle_not_implemented(kind: str) -> CommandResult:
    """Stub for command kinds present in the schema CHECK constraint
    but not yet built buoy-side (reboot, update — slice TBD).

    Returns a clear failure rather than silently dropping so the UI can
    render "not implemented yet" instead of "queued forever." Exit code
    78 = "configuration error" per sysexits.h convention."""
    return (False, 78, "",
            f"command_kind={kind} is not implemented in this daemon "
            "(slice 11 ships ping/refresh/tail-log/restart-service only). "
            "Future slice will add reboot/update.",
            "not_implemented")


COMMAND_DISPATCH: dict[str, Any] = {
    "ping":            _handle_ping,
    "refresh":         _handle_refresh,
    "tail-log":        _handle_tail_log,
    "restart-service": _handle_restart_service,
    # reboot + update intentionally absent — _dispatch_command routes
    # those to _handle_not_implemented. A future slice replaces these
    # entries with real handlers under the appropriate role/step-up
    # gating (server enforces role; buoy executes whatever the server
    # allowed through to it).
}


def _dispatch_command(config: Config, cmd: dict[str, Any]) -> CommandResult:
    """Look up handler for `cmd['command_kind']`, invoke with `cmd['args']`,
    return CommandResult. Defensive against:
      - unknown / unimplemented kinds → returns not_implemented stub
      - non-dict args → coerced to empty dict
      - handler exceptions → caught + returned as handler_exception"""
    kind = cmd.get("command_kind", "")
    args = cmd.get("args")
    if not isinstance(args, dict):
        args = {}
    handler = COMMAND_DISPATCH.get(kind)
    if handler is None:
        return _handle_not_implemented(kind)
    try:
        return handler(config, args)
    except Exception as e:
        LOG.error(
            "dispatch error for kind=%s id=%s: %s",
            kind, cmd.get("id"), e, exc_info=False,
        )
        return (False, 1, "", str(e), "handler_exception")


def _post_command_result(
    config: Config, cmd_id: int, result: CommandResult,
) -> bool:
    """POST the result back to /api/v1/buoy/command/{id}/result.

    On failure: log and return False; the row stays in 'dispatched'
    server-side until expires_at flips it to 'expired'. Future slice
    can add a result-retry queue; for v1 we accept that a dropped
    result POST means the operator sees "dispatched" until TTL."""
    ok, exit_code, stdout, stderr, error_msg = result
    body: dict[str, Any] = {
        "ok": ok,
        "exit_code": exit_code,
        "stdout_tail": stdout,
        "stderr_tail": stderr,
    }
    if error_msg is not None:
        body["error"] = error_msg
    status, resp = _http_request(
        config, "POST", f"/api/v1/buoy/command/{cmd_id}/result", body,
    )
    if 200 <= status < 300:
        LOG.info(
            "command result posted: id=%s ok=%s exit=%d", cmd_id, ok, exit_code,
        )
        return True
    LOG.warning(
        "command result POST failed: id=%s HTTP %s body=%r",
        cmd_id, status, resp,
    )
    return False


def _dispatch_pending_commands(
    config: Config, pending: list[dict[str, Any]],
) -> None:
    """Run each pending command in order, POSTing the result back.
    A failure in one command does NOT halt the others — each runs in
    its own try block via `_dispatch_command`."""
    if not pending:
        return
    LOG.info("dispatching %d pending command(s)", len(pending))
    for cmd in pending:
        cmd_id = cmd.get("id")
        if not isinstance(cmd_id, int):
            LOG.warning(
                "skipping pending command with non-integer id: %r", cmd,
            )
            continue
        kind = cmd.get("command_kind", "?")
        LOG.info("→ dispatching id=%s kind=%s", cmd_id, kind)
        result = _dispatch_command(config, cmd)
        _post_command_result(config, cmd_id, result)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

_running = True


def _handle_sigterm(_signum, _frame) -> None:
    global _running
    LOG.info("shutdown signal received; finishing current cycle and exiting")
    _running = False


def _setup_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=getattr(logging, level, logging.INFO),
    )


def main() -> int:
    _setup_logging()
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)

    try:
        config = Config.load()
    except Exception as e:
        LOG.critical("config load failed: %s", e)
        return 2

    LOG.info(
        "starting buoy-heartbeat: octo=%s slug=%s interval=%ds units=%s",
        config.octo_url, config.octo_slug, config.interval_sec,
        ",".join(config.services),
    )

    try:
        _assert_slug_matches(config)
    except Exception as e:
        LOG.critical("boot-time slug assertion failed: %s", e)
        return 2

    while _running:
        cycle_start = time.monotonic()
        try:
            payload = _gather_heartbeat(config)
            response = _post_heartbeat_with_response(config, payload)
            if response is None:
                _enqueue(config, payload)
            else:
                _drain_queue(config)
                # Slice 11: execute any operator-queued commands OCTO
                # returned inline. Dispatch errors are caught per-command
                # so one bad command doesn't kill the cycle.
                _dispatch_pending_commands(
                    config, response.get("pending_commands") or [],
                )
        except Exception as e:
            LOG.error("cycle error: %s", e, exc_info=False)

        # Sleep with early-exit on SIGTERM. Re-check _running every second
        # so a shutdown signal doesn't have to wait the full interval.
        elapsed = time.monotonic() - cycle_start
        remaining = max(0.0, config.interval_sec - elapsed)
        slept = 0.0
        while _running and slept < remaining:
            time.sleep(min(1.0, remaining - slept))
            slept += 1.0

    LOG.info("shutdown clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
