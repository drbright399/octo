"""Slice 1's automated rules over stored events — R6 (deception) and R2-W
(Wazuh malware). Pure functions: one stored event in, one `Outcome` out; the
engine decides what an outcome does (both rules are SHADOW: a would-fire
row, never a colour).

R6 (buoy OpenCanary, `opencanary.<service>` events):
  * a PLAINTEXT CREDENTIAL attempt on an SSH, RDP, HTTP, FTP or MSSQL canary
    from an INTERNAL address that is not on the tenant's scanner allowlist
    (N15: Datto network-discovery nodes, our scanners, the buoy itself)
    → R6 (Red);
  * any other touch of a canary (a port scan, a connection without a
    credential, an external source, an allowlist that cannot be read) →
    a Yellow condition ("decoy touched"), never Red;
  * SMB / NTLM negotiation and SNMP probes → ignored (printers and MFPs
    browse the network all day);
  * an allowlisted scanner → ignored;
  * the submitted PASSWORD IS NEVER STORED — not by a rule (its LENGTH
    only: a salted fast hash of a real password typed into a decoy could be
    cracked offline, and a random salt makes it useless for correlation),
    and not in events.db: the forwarder sends only "[redacted: N chars]",
    and the ingest route redacts whatever an older forwarder still sends
    (`redact_canary_secrets`).
R2-W (Wazuh alerts):
  * rule.level ≥ 12 AND a malware group: a VirusTotal POSITIVE (`virustotal`
    with a positive verdict), a YARA match (`yara`), a rootcheck TROJAN
    (`rootcheck` whose description names a trojan) → R2-W (Red);
  * every other alert, level 12 or not → nothing here (the Yellow
    condition tiering of Wazuh is unchanged).
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from apps.octo.threat import rules

INCIDENT, YELLOW, IGNORE = "incident", "yellow", "ignore"

# OpenCanary logtypes (`buoy/forwarder/adapters/opencanary.py`).
CREDENTIAL_LOGTYPES = {
    2000: "ftp",               # FTP login attempt
    3001: "http",              # HTTP login attempt
    4002: "ssh",               # SSH login attempt
    9001: "mssql", 9002: "mssql",
    14001: "rdp",
}
CREDENTIAL_SERVICES = ("ssh", "rdp", "http", "ftp", "mssql")
IGNORED_SERVICES = ("smb", "snmp", "ntlm")
IGNORED_LOGTYPES = {5000, 16001}
USER_KEYS = ("honeypot_user_attempt", "USERNAME", "username", "user")
PASSWORD_KEYS = ("honeypot_pw_attempt", "PASSWORD", "password", "passwd")
# Every key a tried SECRET can arrive under (the forwarder's renames and the
# raw OpenCanary names) — never the user name.
SECRET_KEYS = frozenset((
    "honeypot_pw_attempt", "honeypot_api_key_attempt", "honeypot_secret_attempt",
    "honeypot_access_token_attempt", "honeypot_auth_token_attempt",
    "honeypot_bearer_attempt", "honeypot_private_key_attempt",
    "password", "passwd", "api_key", "apikey", "secret", "access_token", "auth_token",
    "bearer", "private_key"))
# The forwarder's stand-in for a tried secret (`opencanary.redacted`).
REDACTED_RE = re.compile(r"^\[redacted: (\d+) chars\]$")

WAZUH_MIN_LEVEL = 12
_POSITIVE = ("1", "true", "yes", "malicious")


@dataclass
class Outcome:
    kind: str                          # INCIDENT | YELLOW | IGNORE
    rule_id: Optional[str] = None
    tier: Optional[str] = None
    fact_key: str = ""
    fact_kind: str = ""
    device_ref: Optional[str] = None
    summary: str = ""
    why: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("payload")
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw) if isinstance(raw, str) and raw else {}
    except (ValueError, RecursionError):
        return {}
    return out if isinstance(out, dict) else {}


_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def _private(ip: Optional[str]) -> bool:
    """A LAN address (RFC 1918 / ULA) — Python's `is_private` would also
    call the documentation ranges private."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _INTERNAL_NETS)


def _first(d: dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, (str, int)) and str(v) != "":
            return str(v)
    return None


def redacted(secret: str) -> str:
    """The stored stand-in for a tried secret (the forwarder's format)."""
    if REDACTED_RE.match(secret):
        return secret
    return f"[redacted: {len(secret)} chars]"


def secret_length(value: str) -> int:
    """A tried secret's length — from the forwarder's stand-in, or of the
    value an older forwarder still sent."""
    m = REDACTED_RE.match(value)
    return int(m.group(1)) if m else len(value)


def redact_canary_secrets(obj: Any) -> Any:
    """Every tried SECRET in an OpenCanary record (any depth) replaced by its
    length — the ingest route's guard against a forwarder that still sends
    the value. The user name is kept."""
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            secret = isinstance(k, str) and k.lower() in SECRET_KEYS
            if secret and isinstance(v, (str, int)) and not isinstance(v, bool):
                out[k] = redacted(str(v))
            else:
                out[k] = redact_canary_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_canary_secrets(x) for x in obj]
    return obj


# ---------------------------------------------------------------------------
# R6 — deception
# ---------------------------------------------------------------------------

def is_canary(row: dict[str, Any]) -> bool:
    return str(row.get("event_type") or "").startswith("opencanary.")


def r6(row: dict[str, Any], *, allowlist: Optional[set[str]]) -> Outcome:
    """One stored OpenCanary event → R6 / Yellow / ignore. `allowlist`: the
    tenant's scanner IPs (None = unreadable: never Red, at most Yellow)."""
    p = _payload(row)
    canary = p.get("raw_canary") if isinstance(p.get("raw_canary"), dict) else p
    service = str(row.get("event_type") or "").split(".", 1)[-1].lower()
    try:
        logtype = int(canary.get("logtype")) if canary.get("logtype") is not None else None
    except (TypeError, ValueError):
        logtype = None
    if logtype in CREDENTIAL_LOGTYPES:
        service = CREDENTIAL_LOGTYPES[logtype]
    src = _first(canary, ("src_host", "src_ip", "SRC_HOST")) or ""
    dst_port = canary.get("dst_port")
    eid = row.get("id")
    base = Outcome(IGNORE, fact_key=f"evt:{eid}:R6", fact_kind="canary",
                   device_ref=f"ip:{src}" if src else None,
                   attrs={"service": service, "src_ip": src or None,
                          "dst_port": dst_port if isinstance(dst_port, int) else None})
    if service in IGNORED_SERVICES or logtype in IGNORED_LOGTYPES:
        base.why = "SMB / NTLM / SNMP — ignored"
        return base
    if src and allowlist is not None and src in allowlist:
        base.why = "allowlisted scanner — ignored"
        return base
    logdata = canary.get("logdata") if isinstance(canary.get("logdata"), dict) else {}
    password = _first(logdata, PASSWORD_KEYS)
    user = _first(logdata, USER_KEYS)
    credential = service in CREDENTIAL_SERVICES and (password is not None or user is not None)
    if password is not None:
        base.attrs["password"] = {"length": secret_length(password)}     # never the value
    base.attrs["user_present"] = user is not None
    if credential and _private(src) and allowlist is not None:
        r = rules.RULES["R6"]
        base.kind, base.rule_id, base.tier = INCIDENT, r.id, rules.RED
        base.fact_kind = "canary_credential"
        base.summary = f"credential tried on a decoy ({service.upper()}) from {src}"
        base.why = "plaintext credential on a canary from an internal address not allowlisted"
        return base
    base.kind, base.fact_kind = YELLOW, "canary_touch"
    base.summary = f"decoy touched ({service}) from {src or 'unknown address'}"
    base.why = ("credential attempt, but the scanner allowlist could not be read"
                if credential and allowlist is None else
                "credential attempt from an external address" if credential else
                "port touch")
    return base


# ---------------------------------------------------------------------------
# R2-W — Wazuh malware groups
# ---------------------------------------------------------------------------

def is_wazuh(row: dict[str, Any]) -> bool:
    return str(row.get("source") or "") == "wazuh" or \
        str(row.get("event_type") or "").startswith("wazuh")


def _vt_positive(p: dict[str, Any]) -> bool:
    data = p.get("data") if isinstance(p.get("data"), dict) else {}
    vt = data.get("virustotal") if isinstance(data.get("virustotal"), dict) else {}
    if str(vt.get("malicious", "")).strip().lower() in _POSITIVE:
        return True
    try:
        return int(vt.get("positives") or 0) > 0
    except (TypeError, ValueError):
        return False


def r2_wazuh(row: dict[str, Any]) -> Outcome:
    p = _payload(row)
    rule = p.get("rule") if isinstance(p.get("rule"), dict) else {}
    try:
        level = int(rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0
    groups = {str(g).lower() for g in (rule.get("groups") or []) if isinstance(g, str)}
    desc = str(rule.get("description") or "")
    agent = p.get("agent") if isinstance(p.get("agent"), dict) else {}
    host = str(agent.get("name") or row.get("source_host") or "").strip()
    out = Outcome(IGNORE, fact_key=f"evt:{row.get('id')}:R2-W", fact_kind="wazuh_malware",
                  device_ref=host or None,
                  attrs={"level": level, "groups": sorted(groups), "rule": rule.get("id")})
    if level < WAZUH_MIN_LEVEL:
        out.why = f"level {level} < {WAZUH_MIN_LEVEL}"
        return out
    hit = None
    if "virustotal" in groups and _vt_positive(p):
        hit = "VirusTotal positive"
    elif "yara" in groups:
        hit = "YARA match"
    elif "rootcheck" in groups and "trojan" in desc.lower():
        hit = "rootcheck trojan"
    if hit is None:
        out.why = "level ≥ 12 but not a malware group"
        return out
    r = rules.RULES["R2-W"]
    out.kind, out.rule_id, out.tier = INCIDENT, r.id, rules.RED
    out.summary = f"malware verdict on {host or 'a monitored host'} ({hit})"
    out.why = hit
    return out
