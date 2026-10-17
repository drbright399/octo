"""OpenCanary adapter for buoy-forwarder v2.

Source: /var/log/opencanary.log (JSON-lines). Each line is one honeypot
event from the OpenCanary daemon. The adapter tails the log (inode +
offset, like Suricata) and emits one ForwardEvent per surviving record.

All-honeypot-hits-are-interesting (Phase B.1 spec + Doc 2026-04-26):
`severity="high"` for every forwarded record. Shallow decides if a hit is
real-attack vs scan noise; the adapter doesn't filter on severity.

Operational records dropped: logtype 1000-1999 (boot/ping/debug/config —
the daemon's own telemetry, not honeypot trips). Forward everything else.

Event type derived from logtype via a mapping table:
  ssh / http / rdp / telnet / ftp / smb / mysql / mssql / tftp / redis /
  git / vnc / sip / snmp / ntp / portscan / httpproxy / generic / unknown
A logtype not in the table (and not in the 1xxx operational range) is
forwarded as `opencanary.unknown` so future OpenCanary additions don't get
silently dropped — fail-open posture.

State file: STATE_DIR/opencanary/state.json
  { "inode": int, "offset": int }
Same shape as Suricata adapter; rotation handled by inode-change detection.

Credential-key renaming (added 2026-04-26 after the first site deploy):
OpenCanary captures attacker-tried credentials in `logdata.PASSWORD` /
`logdata.USERNAME` / etc. Field names like `password`/`username`/`api_key`
match OCTO's sensitive-data guard, which rejects the entire event, so the
*keys* are renamed via `_sanitize_credential_keys` before yielding (the
renamed keys — "honeypot_pw_attempt" etc. — don't match the guard's
allowlist regex). The tried user name is kept; every tried SECRET is NOT
(Tier Black, 2026-10-03): a decoy that looks like a real server is exactly
where a person types a REAL password, so only its length leaves the buoy
("[redacted: 12 chars]") — the design's R6 rule, "the submitted password is
never stored".
"""
from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path
from typing import Iterator, Optional

from .base import EventSeverity, ForwardEvent, SensorAdapter


log = logging.getLogger("opencanary-adapter")

# Per-call yield caps. Same rationale as suricata adapter:
#   _BATCH_MAX  — hard event count
#   _TIME_MAX_S — wall-clock seconds in iter_events
# Whichever fires first ends the call. See suricata.py for full notes.
_BATCH_MAX = 200
_TIME_MAX_S = 5.0


# OpenCanary logtype → service name. From upstream OpenCanary modules.
# Values not in this map and >= 2000 are forwarded as "unknown".
# Values in the 1000-1999 range are dropped (operational telemetry).
_LOGTYPE_SERVICE: dict[int, str] = {
    # FTP
    2000: "ftp",
    # HTTP
    3000: "http", 3001: "http", 3002: "http",
    # SSH
    4000: "ssh", 4001: "ssh", 4002: "ssh",
    # SMB + port scans
    5000: "smb",
    5001: "portscan", 5002: "portscan", 5003: "portscan",
    5004: "portscan", 5005: "portscan",
    # Telnet
    6001: "telnet",
    # HTTP proxy
    7001: "httpproxy",
    # MySQL
    8001: "mysql",
    # MSSQL
    9001: "mssql", 9002: "mssql",
    # TFTP
    10001: "tftp",
    # Redis
    11001: "redis",
    # Git
    12001: "git",
    # VNC
    13001: "vnc",
    # RDP
    14001: "rdp",
    # SIP
    15001: "sip",
    # SNMP
    16001: "snmp",
    # NTP
    17001: "ntp",
    # Generic / user
    99000: "generic", 99001: "generic", 99002: "generic",
}


# Credential field-name renames — keys match OCTO guard's _CRED_KEY_RE
# (`^(password|passwd|api[_-]?key|secret|access[_-]?token|auth[_-]?token|`
# `bearer|private[_-]?key)$` case-insensitive). Plus username variants
# because honeypot capture pairs them with passwords.
# KEYS are renamed so the guard's field-name regex doesn't match; a tried
# user name keeps its value, a tried SECRET does not (`redacted`, below).
_CRED_KEY_RENAMES: dict[str, str] = {
    "password":     "honeypot_pw_attempt",
    "passwd":       "honeypot_pw_attempt",
    "username":     "honeypot_user_attempt",
    "user":         "honeypot_user_attempt",
    "api_key":      "honeypot_api_key_attempt",
    "api-key":      "honeypot_api_key_attempt",
    "apikey":       "honeypot_api_key_attempt",
    "secret":       "honeypot_secret_attempt",
    "access_token": "honeypot_access_token_attempt",
    "access-token": "honeypot_access_token_attempt",
    "auth_token":   "honeypot_auth_token_attempt",
    "auth-token":   "honeypot_auth_token_attempt",
    "bearer":       "honeypot_bearer_attempt",
    "private_key":  "honeypot_private_key_attempt",
    "private-key":  "honeypot_private_key_attempt",
}


# Every renamed key that carries a tried SECRET (all but the user name): its
# value is replaced by `redacted()` — Tier Black R6 (design 4.4): "the
# submitted password is never stored". The same marker is recognised on the
# bundle (`apps.octo.threat.evaluators.REDACTED_RE`), which also redacts
# whatever an older forwarder still sends.
_SECRET_ATTEMPT_KEYS = frozenset(v for v in _CRED_KEY_RENAMES.values()
                                 if v != "honeypot_user_attempt")


def redacted(secret: str) -> str:
    """The stored stand-in for a tried secret: its length only."""
    return f"[redacted: {len(secret)} chars]"


def _sanitize_credential_keys(obj):
    """Recursively rename credential-looking dict keys to non-trigger names,
    and replace every tried SECRET (a password, a key, a token — not the
    user name) by its length (`redacted`).

    Operates on values too so nested logdata structures are fully sanitized.
    Lists/scalars pass through unchanged.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            new_k = _CRED_KEY_RENAMES.get(k.lower() if isinstance(k, str) else k, k)
            if new_k in _SECRET_ATTEMPT_KEYS and isinstance(v, (str, int)) \
                    and not isinstance(v, bool):
                # The tried SECRET itself never leaves the buoy: someone may
                # have typed a REAL password into the decoy. Its length only.
                out[new_k] = redacted(str(v))
                continue
            out[new_k] = _sanitize_credential_keys(v)
        return out
    if isinstance(obj, list):
        return [_sanitize_credential_keys(x) for x in obj]
    return obj


def _logtype_to_service(logtype: Optional[int]) -> Optional[str]:
    """Map logtype → service name. Returns None if it should be dropped (operational)."""
    if logtype is None:
        return "unknown"
    try:
        lt = int(logtype)
    except (TypeError, ValueError):
        return "unknown"
    if 1000 <= lt < 2000:
        return None  # operational telemetry — drop
    return _LOGTYPE_SERVICE.get(lt, "unknown")


class OpenCanaryAdapter:
    """Tails OpenCanary's JSON-lines log; yields one event per honeypot hit."""

    name = "opencanary"

    def __init__(
        self,
        log_path: Path,
        state_dir: Path,
        hostname: Optional[str] = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.state_dir = Path(state_dir) / self.name
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self._hostname = hostname or socket.gethostname()
        self._inode: Optional[int] = None
        self._offset: int = 0
        self._load_state()

    # --- state ---

    def _load_state(self) -> None:
        if not self.state_file.exists():
            log.info("no prior state at %s — starting at end of log", self.state_file)
            try:
                st = self.log_path.stat()
                self._inode = st.st_ino
                self._offset = st.st_size
            except FileNotFoundError:
                self._inode = None
                self._offset = 0
            self._persist_state()
            return
        try:
            data = json.loads(self.state_file.read_text())
            self._inode = int(data.get("inode")) if data.get("inode") is not None else None
            self._offset = int(data.get("offset", 0))
            log.info("resumed from inode=%s offset=%s", self._inode, self._offset)
        except (json.JSONDecodeError, ValueError, OSError) as e:
            log.warning("state file corrupt (%s); resetting to tail", e)
            self._inode = None
            self._offset = 0

    def _persist_state(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": self._inode, "offset": self._offset}))
        os.replace(tmp, self.state_file)

    # --- main API ---

    def iter_events(self) -> Iterator[ForwardEvent]:
        if not self.log_path.exists():
            return  # OpenCanary not running yet

        try:
            st = self.log_path.stat()
        except FileNotFoundError:
            return

        # Rotation detection
        if self._inode is not None and st.st_ino != self._inode:
            log.info(
                "log rotation detected (old inode=%s, new inode=%s); resuming from offset 0",
                self._inode, st.st_ino,
            )
            self._inode = st.st_ino
            self._offset = 0
        elif self._inode is None:
            self._inode = st.st_ino

        # Shrink (truncate) detection
        if st.st_size < self._offset:
            log.warning(
                "log file shrank (was %s, now %s) without inode change; resetting to 0",
                self._offset, st.st_size,
            )
            self._offset = 0

        if st.st_size == self._offset:
            return

        # Cap at _BATCH_MAX events OR _TIME_MAX_S seconds (same rationale as suricata).
        import time as _time
        yielded_count = 0
        deadline = _time.monotonic() + _TIME_MAX_S
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                while True:
                    line_start = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # partial — wait for completion
                        self._offset = line_start
                        break
                    self._offset = f.tell()
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    event = self._line_to_event(line)
                    if event is not None:
                        yield event
                        yielded_count += 1
                        if yielded_count >= _BATCH_MAX or _time.monotonic() >= deadline:
                            # Either cap reached — let other adapters poll this cycle.
                            break
        except OSError as e:
            log.warning("read error on %s: %s; will retry next cycle", self.log_path, e)
            return

        self._persist_state()

    def graceful_shutdown(self) -> None:
        self._persist_state()

    # --- per-line transform ---

    def _line_to_event(self, line: str) -> Optional[ForwardEvent]:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as e:
            log.debug("skipping unparseable opencanary line: %s; line[:200]=%r", e, line[:200])
            return None

        service = _logtype_to_service(record.get("logtype"))
        if service is None:
            return None  # operational telemetry — dropped

        # Rename credential-looking keys before yielding (OCTO's guard rejects
        # whole events on field names like `password`) and keep only the
        # LENGTH of a tried secret (it may be someone's real password).
        sanitized_record = _sanitize_credential_keys(record)

        return {
            "event_type": f"opencanary.{service}",
            "severity": "high",  # all hits are interesting; Shallow triages
            "source_host": self._hostname,
            "data": {
                "raw_canary": sanitized_record,
                "_buoy": self._hostname,
                "_adapter": self.name,
                "_adapter_version": "1.0",
            },
        }


__all__ = [
    "OpenCanaryAdapter",
    "_logtype_to_service",
    "_LOGTYPE_SERVICE",
    "_sanitize_credential_keys",
    "redacted",
    "_CRED_KEY_RENAMES",
]
