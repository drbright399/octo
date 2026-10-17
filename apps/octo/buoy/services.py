"""Buoy-side service probes — slice for the heartbeat contract extension.

Per the heartbeat contract extension, the heartbeat
`services` field is growing from `{name → state}` (slice 3 shape) to
`{name → {state, version, stat, last_activity}}` (this slice). That
lets the fleet drawer's Management → ServiceGrid render real per-unit
metadata instead of "—" placeholders.

This module is the buoy-side data producer:

  - `ServiceProbe` is the contract — one probe per service unit.
  - Built-in probes cover the default Athena-buoy set (tailscaled,
    wazuh-agent, pihole-FTL, nextdns, suricata, opencanary,
    buoy-forwarder, octo-forwarder).
  - `probe_all(units)` returns the per-unit dict ready to drop into
    the heartbeat payload.
  - `last_activity_from_systemd(unit)` is the generic fallback for
    "when did this unit last become active" — works for any systemd
    unit, no per-unit knowledge needed.

Stdlib-only by design (matches buoy-forwarder portability bar — no pip
install on the appliance). All probes are best-effort: any failure
yields None for that field rather than blowing up the whole heartbeat.

Coverage for v1:
  - version:        per-unit best-effort (shell out to the right `--version` flag)
  - stat:           DEFERRED (per-unit activity stat needs per-unit logic;
                              ServiceGrid falls back to "—" for now)
  - last_activity:  generic via `systemctl show -p ActiveEnterTimestamp`

Adding a probe: subclass nothing — just add a function with the
`probe(unit)` signature that returns a `ServiceProbeResult`, then
register it in `_BUILT_IN_PROBES` keyed by unit name.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

LOG = logging.getLogger("buoy-heartbeat")

_PROBE_TIMEOUT_SEC = 3.0


@dataclass(frozen=True)
class ServiceProbeResult:
    """One service's probe output. All fields are optional — None means
    "the probe couldn't determine it" (the daemon emits that as JSON
    null, not as a string)."""
    state:         str                       # active / inactive / failed / missing / unknown
    version:       Optional[str] = None
    stat:          Optional[str] = None
    last_activity: Optional[str] = None      # ISO-8601 UTC

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"state": self.state}
        if self.version       is not None: d["version"]       = self.version
        if self.stat          is not None: d["stat"]          = self.stat
        if self.last_activity is not None: d["last_activity"] = self.last_activity
        return d


# A probe takes (unit_name, state) and returns the assembled result.
# We pass state in because we already collected it for the heartbeat;
# avoids each probe re-running `systemctl is-active`.
ServiceProbe = Callable[[str, str], ServiceProbeResult]


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a command best-effort. Returns (rc, stdout, stderr).
    Any exception (FileNotFoundError, TimeoutExpired, OSError) →
    rc=-1, captured stderr."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_PROBE_TIMEOUT_SEC,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except (FileNotFoundError, OSError) as e:
        return -1, "", str(e)


def last_activity_from_systemd(unit: str) -> Optional[str]:
    """ActiveEnterTimestamp from `systemctl show <unit>`.

    Output shape: `ActiveEnterTimestamp=Sun 2026-05-18 04:21:53 UTC`
    or empty if the unit never entered active state. Returns ISO-8601
    UTC or None.

    We don't strictly need the timestamp in UTC — systemd shows it in
    local time by default — but converting via `date -u` is cheap.
    """
    rc, out, _err = _run(["systemctl", "show", "-p", "ActiveEnterTimestamp", unit])
    if rc != 0 or not out:
        return None
    # Output: "ActiveEnterTimestamp=Sun 2026-05-18 04:21:53 UTC"
    _, _, raw = out.partition("=")
    raw = raw.strip()
    if not raw:
        return None
    # Try to extract YYYY-MM-DD HH:MM:SS from the raw string. systemd's
    # human-readable format includes a day-of-week prefix + tz suffix
    # which `date -d` can re-parse.
    rc2, iso, _ = _run(["date", "-u", "-d", raw, "+%Y-%m-%dT%H:%M:%SZ"])
    if rc2 == 0 and iso:
        return iso
    return None


def _first_semver(text: str) -> Optional[str]:
    """Find the first `X.Y[.Z[-tag]]` pattern in `text`. Common shape
    across version probes. Returns the match or None."""
    m = re.search(r"\b(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)\b", text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Per-unit probes
# ---------------------------------------------------------------------------

def _probe_tailscaled(unit: str, state: str) -> ServiceProbeResult:
    rc, out, _ = _run(["tailscale", "version"])
    version = _first_semver(out) if rc == 0 else None
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_wazuh_agent(unit: str, state: str) -> ServiceProbeResult:
    rc, out, _ = _run(["/var/ossec/bin/wazuh-control", "info"])
    version = None
    if rc == 0:
        # Output line like: "WAZUH_VERSION="v4.9.2""
        m = re.search(r'WAZUH_VERSION="?v?(\d+\.\d+\.\d+)"?', out)
        if m:
            version = m.group(1)
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_pihole(unit: str, state: str) -> ServiceProbeResult:
    rc, out, _ = _run(["pihole-FTL", "--version"])
    version = _first_semver(out) if rc == 0 else None
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_nextdns(unit: str, state: str) -> ServiceProbeResult:
    rc, out, _ = _run(["nextdns", "version"])
    version = _first_semver(out) if rc == 0 else None
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_suricata(unit: str, state: str) -> ServiceProbeResult:
    # `suricata -V` prints to stderr historically; some versions stdout.
    rc, out, err = _run(["suricata", "-V"])
    combined = (out + " " + err).strip()
    version = _first_semver(combined) if rc in (0, 1) else None
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_opencanary(unit: str, state: str) -> ServiceProbeResult:
    # opencanary has no canonical --version flag. Try `pip show`.
    rc, out, _ = _run(["pip", "show", "opencanary"])
    version = None
    if rc == 0:
        m = re.search(r"^Version:\s*(\S+)$", out, re.MULTILINE)
        if m:
            version = m.group(1)
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_forwarder(unit: str, state: str) -> ServiceProbeResult:
    """buoy-forwarder + octo-forwarder are our own daemons. They write
    a VERSION file at /etc/<unit>/VERSION (or fall back to None)."""
    candidates = [
        f"/etc/{unit}/VERSION",
        f"/usr/local/share/{unit}/VERSION",
    ]
    version = None
    for path in candidates:
        try:
            with open(path) as f:
                version = f.read().strip() or None
                break
        except OSError:
            continue
    return ServiceProbeResult(
        state=state, version=version,
        last_activity=last_activity_from_systemd(unit),
    )


def _probe_default(unit: str, state: str) -> ServiceProbeResult:
    """No version probe registered for this unit — still return the
    systemd last-activity timestamp, which is generic across all units."""
    return ServiceProbeResult(
        state=state,
        last_activity=last_activity_from_systemd(unit),
    )


_BUILT_IN_PROBES: dict[str, ServiceProbe] = {
    "tailscaled":     _probe_tailscaled,
    "wazuh-agent":    _probe_wazuh_agent,
    "pihole-FTL":     _probe_pihole,
    "nextdns":        _probe_nextdns,
    "suricata":       _probe_suricata,
    "opencanary":     _probe_opencanary,
    "buoy-forwarder": _probe_forwarder,
    "octo-forwarder": _probe_forwarder,
}


# ---------------------------------------------------------------------------
# Top-level entrypoint
# ---------------------------------------------------------------------------

def probe_all(
    states: dict[str, str],
    extra_probes: Optional[dict[str, ServiceProbe]] = None,
) -> dict[str, dict[str, object]]:
    """Run probes for each (unit, state) pair. Returns the per-unit
    dict shape ready to drop into the heartbeat payload's `services`
    field.

    `extra_probes` is a per-deploy override hook — a buoy with a
    custom service can register its own probe via env-driven config.
    """
    registry = dict(_BUILT_IN_PROBES)
    if extra_probes:
        registry.update(extra_probes)

    out: dict[str, dict[str, object]] = {}
    for unit, state in states.items():
        probe = registry.get(unit, _probe_default)
        try:
            result = probe(unit, state)
        except Exception as e:  # noqa: BLE001 — probe failure must not break heartbeat
            LOG.warning("service probe failed for %s: %s", unit, e)
            result = ServiceProbeResult(state=state)
        out[unit] = result.to_dict()
    return out
