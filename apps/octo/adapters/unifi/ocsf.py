"""OCSF at the UniFi adapter boundary (the build rule: every adapter maps its
events to OCSF — class, category and the key fields — where they enter).

Pinned to OCSF 1.3.0. Each UniFi event KIND has exactly one OCSF class and
activity (`KIND_CLASS`); `project()` builds the OCSF object that is stored
with every signal (payload `ocsf`) and that the roll-ups record by class.
Choices the vendor's data leaves open are marked "best fit":

  ips_threat       Detection Finding (2004, Findings 2), Create; disposition
                   Blocked (2) for THREAT_BLOCKED, Detected (15) for
                   THREAT_DETECTED; endpoints under evidences[]
  rogue_ap         Detection Finding (2004), Create
  admin_activity   Authentication (3002, IAM 3), Logon (1)
  config_change    Entity Management (3004, IAM 3), Update (3)
  wan_down         Network Activity (4001, Network 4), Fail (4) — best fit
  wan_failover     Network Activity (4001), Other (99) — best fit
  wan_restored     Network Activity (4001), Open (1) — best fit
  vpn_down         Network Activity (4001), Close (2) — best fit
  system_event     Base Event (0, Uncategorized 0) — an unknown event the
                   vendor rates HIGH / VERY_HIGH (fail-safe signal)
  mac_anomaly      Detection Finding (2004), Create — DERIVED by entity
                   resolution's MAC-anomaly rule; the MAC under
                   evidences[].src_endpoint
  isp_outage       Incident Finding (2005, Findings 2), Create; DERIVED by the
                   Fleet v2 ISP-outage correlator (>= N sites on one ISP ASN
                   losing WAN within minutes): one finding per affected site
                   under finding_info_list, impact = the site count
                   (`project_isp_outage`)
  roll-ups         firewall_block → Network Activity Refuse (5); client
                   connect / disconnect / roam → Network Activity Open (1) /
                   Close (2) / Other (99); isp_quality, wan_flap → Network
                   Activity Other (99); device, other → Base Event (0)

The UniFi site is the organisational unit: `device.org.ou_uid` =
"unifi:<hostId>/<siteId>" (entity resolution adds the Athena site as an
enrichment later; the observed values are never rewritten). The reporting
gateway is `device`; the LAN client and the remote end of an IPS event are
`evidences[].src_endpoint` / `dst_endpoint`.
"""
from __future__ import annotations

from typing import Any, Optional

OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "UniFi Network", "vendor_name": "Ubiquiti"}

CATEGORIES = {0: "Uncategorized", 2: "Findings", 3: "Identity & Access Management",
              4: "Network Activity"}
CLASSES = {
    0: ("Base Event", 0),
    2004: ("Detection Finding", 2),
    2005: ("Incident Finding", 2),
    3002: ("Authentication", 3),
    3004: ("Entity Management", 3),
    4001: ("Network Activity", 4),
}
ACTIVITIES = {
    0: {0: "Unknown", 99: "Other"},
    2004: {1: "Create", 2: "Update", 3: "Close"},
    2005: {1: "Create", 2: "Update", 3: "Close"},
    3002: {1: "Logon", 2: "Logoff"},
    3004: {1: "Create", 2: "Read", 3: "Update", 4: "Delete"},
    4001: {1: "Open", 2: "Close", 4: "Fail", 5: "Refuse", 6: "Traffic", 99: "Other"},
}
# kind → (class_uid, activity_id)
KIND_CLASS: dict[str, tuple[int, int]] = {
    "ips_threat": (2004, 1),
    "rogue_ap": (2004, 1),
    "admin_activity": (3002, 1),
    "config_change": (3004, 3),
    "wan_down": (4001, 4),
    "wan_failover": (4001, 99),
    "wan_restored": (4001, 1),
    "vpn_down": (4001, 2),
    "system_event": (0, 99),
    "mac_anomaly": (2004, 1),
    "isp_outage": (2005, 1),
    "firewall_block": (4001, 5),
    "client_connect": (4001, 1),
    "client_disconnect": (4001, 2),
    "client_roam": (4001, 99),
    "isp_quality": (4001, 99),
    "wan_flap": (4001, 99),
    "device": (0, 99),
    "other": (0, 99),
}
SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
DISPOSITION = {"blocked": (2, "Blocked"), "detected": (15, "Detected")}
DEVICE_TYPE_ROUTER = (12, "Router")


def class_of(kind: str) -> tuple[int, int]:
    return KIND_CLASS.get(kind, KIND_CLASS["other"])


def _drop_empty(value: Any) -> Any:
    if isinstance(value, dict):
        out = {k: _drop_empty(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", {}, [])}
    if isinstance(value, list):
        return [x for x in (_drop_empty(v) for v in value) if x not in (None, "", {}, [])]
    return value


def endpoint(ip: Optional[str] = None, port: Optional[int] = None, mac: Optional[str] = None,
             hostname: Optional[str] = None, name: Optional[str] = None) -> dict[str, Any]:
    return _drop_empty({"ip": ip, "port": port, "mac": mac, "hostname": hostname, "name": name})


def project(
    kind: str,
    *,
    time_ms: int,
    severity: str,
    event_uid: str,
    scope: str,
    site_name: str,
    console_name: str,
    title: str,
    original_time: str,
    vendor: dict[str, Any],
    src: Optional[dict[str, Any]] = None,
    dst: Optional[dict[str, Any]] = None,
    protocol: Optional[str] = None,
    disposition: Optional[str] = None,
    analytic: Optional[dict[str, Any]] = None,
    actor_name: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """The OCSF object for one UniFi event of `kind`."""
    class_uid, activity_id = class_of(kind)
    class_name, category_uid = CLASSES[class_uid]
    sev = SEVERITY_ID.get(severity, 1)
    out: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": CATEGORIES[category_uid],
        "activity_id": activity_id,
        "activity_name": ACTIVITIES[class_uid].get(activity_id, "Other"),
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": sev,
        "severity": SEVERITY_NAME[sev],
        "time": int(time_ms),
        "metadata": {
            "version": OCSF_VERSION,
            "product": dict(PRODUCT),
            "uid": event_uid,
            "original_time": original_time,
            "labels": [f"unifi:{scope}"],
        },
        "device": {
            "type_id": DEVICE_TYPE_ROUTER[0],
            "type": DEVICE_TYPE_ROUTER[1],
            "name": console_name or None,
            "org": {"ou_uid": f"unifi:{scope}", "ou_name": site_name or None},
        },
        "message": title,
        "unmapped": {"unifi": vendor},
    }
    if class_uid == 2004:
        out["status_id"] = 1
        out["status"] = "New"
        out["finding_info"] = _drop_empty({
            "uid": event_uid, "title": title,
            "types": [vendor.get("subcategory") or vendor.get("category") or "UniFi"],
            "analytic": analytic,
        })
        evidence = _drop_empty({"src_endpoint": src, "dst_endpoint": dst,
                                "connection_info": {"protocol_name": protocol}})
        if evidence:
            out["evidences"] = [evidence]
        if disposition in DISPOSITION:
            did, dname = DISPOSITION[disposition]
            out["disposition_id"] = did
            out["disposition"] = dname
            out["action_id"] = 2 if disposition == "blocked" else 1
            out["action"] = "Denied" if disposition == "blocked" else "Allowed"
            out["metadata"]["profiles"] = ["security_control"]
    elif class_uid in (3002, 3004):
        if actor_name:
            out["actor"] = {"user": {"name": actor_name}}
        if src:
            out["src_endpoint"] = src
    elif class_uid == 4001:
        if src:
            out["src_endpoint"] = src
        if dst:
            out["dst_endpoint"] = dst
    if extra:
        out.update(extra)
    return _drop_empty(out)


# Incident Finding impact / priority (OCSF 1.3.0): 1 Low, 2 Medium, 3 High,
# 4 Critical. The site count is the impact.
IMPACT = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
FLEET_PRODUCT = {"name": "Athena fleet correlation", "vendor_name": "Athena"}


def project_isp_outage(
    *,
    vid: str,
    time_ms: int,
    original_time: str,
    asn: int,
    isp: str,
    sites: int,
    since: str,
    affected: list[dict[str, Any]],
) -> dict[str, Any]:
    """The OCSF Incident Finding (2005) of ONE ISP outage: N sites on one
    ASN losing their internet within minutes. Each affected site is one
    finding_info (its UniFi scope as uid); the provider and ASN are labels.
    Severity HIGH; impact High from 5 sites, else Medium."""
    class_uid, activity_id = KIND_CLASS["isp_outage"]
    impact_id = 3 if sites >= 5 else 2
    title = f"ISP outage: {isp} — {sites} sites"
    out: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": CLASSES[class_uid][0],
        "category_uid": CLASSES[class_uid][1],
        "category_name": CATEGORIES[CLASSES[class_uid][1]],
        "activity_id": activity_id,
        "activity_name": ACTIVITIES[class_uid][activity_id],
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": SEVERITY_ID["high"],
        "severity": SEVERITY_NAME[SEVERITY_ID["high"]],
        "time": int(time_ms),
        "status_id": 1,
        "status": "New",
        "impact_id": impact_id,
        "impact": IMPACT[impact_id],
        "priority_id": impact_id,
        "priority": IMPACT[impact_id],
        "desc": (f"{sites} sites on {isp} (AS{asn}) lost their internet connection within "
                 f"minutes of each other, since {since} — one provider problem."),
        "message": title,
        "finding_info_list": [
            _drop_empty({
                "uid": f"unifi:{a.get('scope')}",
                "title": f"{a.get('site_name')} — {a.get('why')}",
                "types": ["WAN down"],
                "first_seen_time_dt": a.get("since"),
            }) for a in affected
        ],
        "metadata": {
            "version": OCSF_VERSION,
            "product": dict(FLEET_PRODUCT),
            "uid": vid,
            "original_time": original_time,
            "labels": ["unifi", f"asn:{int(asn)}"],
        },
        "unmapped": {"isp": {"name": isp, "asn": int(asn)}, "sites": int(sites)},
    }
    return _drop_empty(out)
