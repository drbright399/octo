"""OCSF at the NextDNS adapter boundary (the build rule: an adapter maps its
events to OCSF — class, category and the key fields — where they enter).

Pinned to OCSF 1.3.0, the UniFi adapter's pin.

  security_block   DNS Activity (4003, Network Activity 4), Query (1);
                   disposition Blocked (2), action Denied; `query.hostname`
                   = the blocked domain, `src_endpoint.ip` = the client IP
                   NextDNS saw (the site's public address for gateway
                   traffic), `device.uid` / `device.name` = the NextDNS app's
                   device; the profile is a label (`nextdns:<profile>`).
                   Projected at READ time (`project_block`) for the entity
                   enrichment — stored block payloads are never rewritten.
  device_silent    Detection Finding (2004, Findings 2), Create — DERIVED:
                   the NextDNS app stopped reporting from a computer Datto
                   RMM shows online; `device` = the computer (Datto hostname,
                   NextDNS device id as `uid_alt`)
  device_restored  Detection Finding (2004), Close (3)
"""
from __future__ import annotations

from typing import Any, Optional

OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "NextDNS", "vendor_name": "NextDNS"}
SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


def _drop_empty(value: Any) -> Any:
    if isinstance(value, dict):
        out = {k: _drop_empty(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    if isinstance(value, list):
        return [x for x in (_drop_empty(v) for v in value) if x not in (None, "", {}, [])]
    return value


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def project_block(payload: dict[str, Any], *, time_ms: Optional[int] = None) -> dict[str, Any]:
    """A stored security-block payload as OCSF DNS Activity (4003)."""
    log = _m(payload.get("log"))
    signal = _m(payload.get("signal"))
    device = _m(log.get("device"))
    sev = SEVERITY_ID.get(str(signal.get("level") or "low"), 2)
    return _drop_empty({
        "class_uid": 4003, "class_name": "DNS Activity",
        "category_uid": 4, "category_name": "Network Activity",
        "activity_id": 1, "activity_name": "Query", "type_uid": 400301,
        "severity_id": sev, "severity": SEVERITY_NAME[sev],
        "time": time_ms,
        "disposition_id": 2, "disposition": "Blocked", "action_id": 2, "action": "Denied",
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT),
                     "uid": payload.get("vendor_event_id"),
                     "original_time": log.get("timestamp"),
                     "labels": [f"nextdns:{payload.get('profile_id')}"],
                     "profiles": ["security_control"]},
        "query": {"hostname": log.get("domain")},
        "src_endpoint": {"ip": log.get("clientIp")},
        "device": {"uid": device.get("id"), "name": device.get("name"),
                   "model": device.get("model")},
        "firewall_rule": {"name": signal.get("reason_label"), "uid": signal.get("reason_id")},
        "unmapped": {"nextdns": {"client": log.get("client"), "protocol": log.get("protocol"),
                                 "root": log.get("root"),
                                 "reasons": log.get("reasons")}},
    })


def project_device_finding(
    kind: str, *, time_ms: int, severity: str, event_uid: str, profile_id: str, title: str,
    hostname: Optional[str], device_name: Optional[str], nextdns_device_id: Optional[str],
    datto_uid: Optional[str], original_time: str, last_report: Optional[str] = None,
    silent_since: Optional[str] = None,
) -> dict[str, Any]:
    """Detection Finding (2004) for the device-silence check. When the device
    last reported and since when the silence is verified ride in `unmapped`
    (no OCSF attribute says "last heard from")."""
    activity = 3 if kind == "device_restored" else 1
    sev = SEVERITY_ID.get(severity, 2)
    return _drop_empty({
        "class_uid": 2004, "class_name": "Detection Finding",
        "category_uid": 2, "category_name": "Findings",
        "activity_id": activity, "activity_name": "Close" if activity == 3 else "Create",
        "type_uid": 200400 + activity, "severity_id": sev, "severity": SEVERITY_NAME[sev],
        "time": int(time_ms),
        "status_id": 4 if activity == 3 else 1, "status": "Resolved" if activity == 3 else "New",
        "metadata": {"version": OCSF_VERSION, "product": dict(PRODUCT), "uid": event_uid,
                     "original_time": original_time, "labels": [f"nextdns:{profile_id}"]},
        "finding_info": {"uid": event_uid, "title": title, "types": ["DNS filtering coverage"],
                         "analytic": {"name": "NextDNS device silence", "type_id": 1,
                                      "type": "Rule", "uid": "athena.entity.E1"}},
        "device": {"hostname": hostname, "name": device_name, "uid": datto_uid,
                   "uid_alt": nextdns_device_id, "type_id": 2, "type": "Desktop"},
        "message": title,
        "unmapped": {"nextdns": {"last_report": last_report, "silent_since": silent_since}},
    })
