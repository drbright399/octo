"""What an alert IS for a human verdict — its DEVICE key and its SIGNATURE
key (deterministic, from the stored event alone), and whether it may be
marked EXPECTED at all.

The same keys come out of a stored event AND out of the coalescing ledgers
the Fleet counts Yellow from (`unifi_key` over a UniFi bucket's scope +
subject, `nextdns_key` over a NextDNS bucket's columns), so an expected
condition made from one alert matches the counts of the next ones.

  UniFi IPS      device = the site + the LAN client (MAC, else its address);
                 signature = the threat (id or name) + direction + action —
                 the coalescing subject without the client: a "blocked"
                 condition never hides a "detected, NOT blocked" one.
  UniFi other    device = the site (the MAC for a MAC anomaly); signature =
                 kind + subject.
  NextDNS block  device = profile + device id (else the client address);
                 signature = reason + the root the ledger buckets it under
                 (a known-benign rule's `kb:<id>`, `*` for a cross-domain
                 reason, else the root domain).
  Datto RMM      device = the device uid (else its host name); signature =
                 the monitor: the alert context's class + the fields that
                 name WHAT it watches (event log: log / source / code; a
                 service, process, product, disk, counter …) — never a
                 value that changes per alert.
                 A component (script) monitor and a class not listed add
                 the SHAPE of their message (first line, numbers masked).
                 A Datto NOC report (an event-log alert whose source starts
                 "DNOC", v0.17.3) adds what it is ABOUT (`enrich.dnoc.
                 signature_part`): the sorted set of affected services —
                 every service name the report gives, digits kept
                 (DNOCServiceMonitor) — or the drive (DNOCDiskRemediation) —
                 an expected condition for a vendor's remote-access
                 services kept stopped on purpose never covers "SQL Server
                 stopped" on the same server; {A} and {A, B} are different
                 keys. Memory / CPU: the monitor alone (unchanged). A report
                 that cannot be read keeps the plain code + source + log key.
  RocketCyber    no device (an incident names no host); signature = the
                 incident title. Acknowledged one incident at a time — a
                 SOURCE rule (Rick, 2026-10-07: "too vague to just do a
                 sweeping expected tag on"): never expected, never "repeats
                 for 24 h", WHATEVER its payload names (a hostname too) —
                 `ACK_ONLY_SOURCES`.
  Wazuh          device = the agent; signature = the rule id.
  OpenCanary     device = the source address; signature = the event type.
  anything else  device = source_host; signature = source + event type.

`ref` is the VENDOR's identity of the alert a stored row belongs to (a
Datto alert uid — its raise and its resolution are two rows; a RocketCyber
incident id — every stored version is a row): an acknowledgement of one row
covers the other rows of the same alert (`state.TenantVerdicts`).

EXPECTED is never allowed for (`expected_refusal`): Athena's own incident
records; an alert that is evidence of an incident (Red / Black); a NextDNS
'csam' block (v0.17.1 makes it an automated Black); a decoy (canary) alert
(R6's input — a known scanner goes on the scanner allowlist instead); a
Wazuh alert R2-W would open a Red on; a Datto ransomware or endpoint-threat
DETECTION (a malware verdict, like R2-W's — acknowledged one at a time, or
confirmed as a threat); a RocketCyber alert (`ACK_ONLY_SOURCES`: by source,
whatever it names); an alert that names no device (`device_refusal`).
`expected_eligible_bucket` says the same for a ledger bucket the Fleet
counts. "Repeats for 24 h" (`repeat_refusal`) is never for a RocketCyber
alert, an alert that names no device or a CSAM lookup.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional

KEY_MAX = 300
SIG_MAX = 400
CSAM = "csam"
EXPECTED_SOURCES = ("unifi", "nextdns", "datto", "rocketcyber", "wazuh")
# Sources whose alerts are ACKNOWLEDGED ONE AT A TIME: never an expected
# condition, never "repeats for 24 h" — by SOURCE, whatever an alert's
# payload names (Rick, 2026-10-07: RocketCyber alerts "are too vague to just
# do a sweeping expected tag on"). The API refuses, the evaluator ignores
# any such rule or repeat-ack the registry may hold.
ACK_ONLY_SOURCES = frozenset({"rocketcyber"})


@dataclass(frozen=True)
class AlertKey:
    source: str
    device_key: str
    signature_key: str
    family: str
    """'unifi_ips' | 'unifi' | 'nextdns' | 'datto' | 'rocketcyber' | 'wazuh'
    | 'canary' | 'other'."""
    remote: Optional[str] = None
    """A network alert's remote address (UniFi IPS)."""
    ref: Optional[str] = None
    """The vendor's alert identity ('datto:<alert uid>', 'rocketcyber:<incident
    id>') — the rows of ONE alert share it."""


def _t(value: Any, limit: int = 160) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    text = " ".join("".join(c if c.isprintable() else " " for c in str(value)).split())
    return text[:limit]


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def payload_of(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("payload")
    if isinstance(raw, dict):
        return raw
    try:
        out = json.loads(raw) if isinstance(raw, str) and raw else {}
    except (ValueError, RecursionError):
        return {}
    return out if isinstance(out, dict) else {}


def _key(device: str, sig: str) -> tuple[str, str]:
    return device[:KEY_MAX], sig[:SIG_MAX]


# ---------------------------------------------------------------------------
# UniFi
# ---------------------------------------------------------------------------

def unifi_key(scope: str, kind: str, subject: str, *, remote: Optional[str] = None) -> AlertKey:
    """The keys of a UniFi signal from its site scope, kind and coalescing
    subject (an event's `signal.subject`, a ledger bucket's `subject`)."""
    scope, kind, subject = _t(scope, 200), _t(kind, 40), str(subject or "")[:400]
    if kind == "ips_threat":
        parts = subject.split("|")
        client = parts[0] if parts else "?"
        rest = "|".join(parts[1:]) if len(parts) > 1 else subject
        device, sig = _key(f"{scope}|{client}", f"unifi.ips_threat:{rest}")
        return AlertKey("unifi", device, sig, "unifi_ips", remote)
    if kind == "mac_anomaly":
        mac, _, anomaly = subject.partition("|")
        device, sig = _key(f"{scope}|{mac}", f"unifi.mac_anomaly:{anomaly}")
        return AlertKey("unifi", device, sig, "unifi")
    device, sig = _key(scope, f"unifi.{kind or 'signal'}:{subject}")
    return AlertKey("unifi", device, sig, "unifi")


def _unifi(payload: dict[str, Any], event_type: str) -> AlertKey:
    kind = _t(payload.get("kind"), 40) or event_type.removeprefix("unifi.")
    subject = str(_m(payload.get("signal")).get("subject") or "")
    if not subject:
        ev = _m(payload.get("event"))
        subject = _t(ev.get("event") or ev.get("title"), 120)
    ips = _m(payload.get("ips"))
    remote = _t(ips.get("remote_ip"), 45) or None
    return unifi_key(str(payload.get("scope") or ""), kind, subject, remote=remote)


# ---------------------------------------------------------------------------
# NextDNS
# ---------------------------------------------------------------------------

def nextdns_key(profile_id: str, device: str, root: str, reason: str) -> AlertKey:
    """The keys of a NextDNS block from a ledger bucket's columns (profile,
    device, root, reason) — or the same values read off its stored alert."""
    dev, sig = _key(f"{_t(profile_id, 64)}|{_t(device, 64)}",
                    f"nextdns:{_t(reason, 64) or 'unknown'}|{_t(root, 253)}")
    return AlertKey("nextdns", dev, sig, "nextdns")


def _nextdns(payload: dict[str, Any], event_type: str) -> AlertKey:
    kind = _t(payload.get("kind"), 40)
    if kind != "security_block":
        dev, sig = _key(_t(payload.get("profile_id"), 64),
                        f"nextdns.{kind or event_type.removeprefix('nextdns.') or 'event'}")
        return AlertKey("nextdns", dev, sig, "nextdns")
    log, signal = _m(payload.get("log")), _m(payload.get("signal"))
    device = _t(_m(log.get("device")).get("id"), 64) or _t(log.get("clientIp"), 64)
    domain = _t(log.get("domain"), 253).lower().rstrip(".")
    root = _t(log.get("root"), 253).lower().rstrip(".") or domain
    benign = _m(signal.get("known_benign"))
    if benign.get("rule_id") is not None:
        root = f"kb:{_t(benign.get('rule_id'), 64)}"
    elif signal.get("cross_domain"):
        root = "*"
    return nextdns_key(_t(payload.get("profile_id"), 64), device, root,
                       _t(signal.get("reason_id"), 64))


def nextdns_reasons(payload: dict[str, Any]) -> set[str]:
    """Every reason id a NextDNS alert names (its primary and the log
    line's)."""
    out = {_t(_m(payload.get("signal")).get("reason_id"), 64).lower()}
    for r in _m(payload.get("log")).get("reasons") or []:
        rid = r.get("id") if isinstance(r, dict) else r
        out.add(_t(rid, 64).lower())
    return {r for r in out if r}


# ---------------------------------------------------------------------------
# Datto RMM
# ---------------------------------------------------------------------------

# The context fields that name WHAT a monitor watches, per class.
_DATTO_SIG_FIELDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "eventlog_ctx": (("logName",), ("source",), ("code", "eventId")),
    "perf_resource_usage_ctx": (("type", "resource"),),
    "perf_disk_usage_ctx": (("diskName", "disk", "drive", "path"),),
    "perf_mon_ctx": (("counterName", "counter", "name"),),
    "srvc_status_ctx": (("serviceName", "service", "name"),),
    "srvc_resource_usage_ctx": (("serviceName", "service", "name"),),
    "process_status_ctx": (("processName", "process", "name"),),
    "process_resource_usage_ctx": (("processName", "process", "name"),),
    # The status too: "not running" is not "not up to date".
    "antivirus_ctx": (("productName", "product", "name"), ("status", "state")),
    "sec_management_ctx": (("productName", "product", "name"), ("status", "state")),
    "backup_management_ctx": (("productName", "name"), ("jobName",)),
    "sw_action_ctx": (("softwareName", "name", "software"), ("actionType", "action")),
    "custom_snmp_ctx": (("displayName", "monitorInstance", "name"),),
    "wmi_ctx": (("displayName", "name", "query"),),
    "fs_object_ctx": (("path", "objectName", "name"),),
    "patch_ctx": (),
    "online_offline_status_ctx": (),
    "ransomware_ctx": (("rwextension",), ("affectedDirectories", "watchPaths")),
}
# Detections (a malware verdict on the device): never "expected" — a
# pattern-wide label on one would hide the next, different detection.
DATTO_DETECTION_CLASSES = frozenset({"ransomware_ctx", "endpoint_security_threat_ctx"})
_MESSAGE_KEYS = ("DIAG", "diagnostic", "message", "description")


def _ci(ctx: dict[str, Any], names: tuple[str, ...]) -> str:
    lowered = {k.lower(): v for k, v in list(ctx.items())[:64] if isinstance(k, str)}
    for n in names:
        v = lowered.get(n.lower())
        if v not in (None, "") and not isinstance(v, (dict, list)):
            return _t(v, 120).lower()
    return ""


def datto_class(payload: dict[str, Any]) -> str:
    """The alert context's class, else the class its monitor name denotes
    (the webhook shape), else its type / category."""
    from apps.octo.adapters.datto.presentation import _class_for_vendor_type

    ctx = _m(payload.get("alertContext"))
    cls = _t(ctx.get("@class"), 64)
    if cls:
        return cls.lower()
    for v in (payload.get("alertType"), payload.get("alertCategory")):
        mapped = _class_for_vendor_type(v if isinstance(v, str) else None)
        if mapped:
            return mapped
    return (_t(payload.get("alertType"), 64) or _t(payload.get("alertCategory"), 64)
            or "alert").lower()


def _shape(text: Any) -> str:
    """A message's SHAPE — its first line, lower-case, every number '#' (a
    count, a size, a date never splits one monitor in two)."""
    if not isinstance(text, str):
        return ""
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    return re.sub(r"\d+", "#", _t(first, 160).lower())[:120]


def _datto_message(payload: dict[str, Any], ctx: dict[str, Any]) -> str:
    from apps.octo.adapters.datto.fields import _alert_message

    samples = _m(ctx.get("samples"))
    for source in (samples, ctx):
        lowered = {k.lower(): v for k, v in list(source.items())[:64] if isinstance(k, str)}
        for name in _MESSAGE_KEYS:
            value = lowered.get(name.lower())
            if isinstance(value, str) and value.strip():
                return _shape(value)
    return _shape(_alert_message(payload))


def datto_monitor_signature(payload: dict[str, Any]) -> str:
    """class|field|field — the monitor, never a per-alert value. A component
    (script) monitor and a class the table does not know add the SHAPE of
    their message (numbers masked): two unrelated monitors with the same
    sample names — or two alert types of an unknown class — never share one
    key."""
    cls = datto_class(payload)
    ctx = _m(payload.get("alertContext"))
    fields = _DATTO_SIG_FIELDS.get(cls)
    if fields is not None:
        parts = [_ci(ctx, f) for f in fields]
        if cls == "eventlog_ctx":
            parts += _dnoc_part(ctx, room=SIG_MAX - len("datto:|") - len("|".join([cls, *parts])))
    elif cls == "comp_script_ctx":
        samples = _m(ctx.get("samples"))
        parts = [",".join(sorted(k.lower() for k in list(samples)[:16]
                                 if isinstance(k, str))), _datto_message(payload, ctx)]
    else:
        parts = [_t(payload.get("alertType"), 64).lower(), _datto_message(payload, ctx)]
    return "|".join([cls, *parts])


def _dnoc_part(ctx: dict[str, Any], *, room: int) -> list[str]:
    """A Datto NOC report's own key part (its services / its drive) — [] for
    any other event-log alert, a memory / CPU report, or a report that does
    not say (the plain code + source + log key stays). A part longer than
    the `room` the signature has left becomes a digest of the whole part:
    the signature's cut at SIG_MAX must never fall inside it."""
    from apps.octo.enrich import dnoc

    if not dnoc.is_dnoc(ctx):
        return []
    try:
        part = dnoc.signature_part(ctx)
    except Exception:  # noqa: BLE001 — a vendor report never breaks a key
        part = None
    if not part:
        return []
    return [part if len(part) <= room else dnoc.compact(part)]


def datto_device(payload: dict[str, Any]) -> str:
    from apps.octo.adapters.datto.fields import _alert_device_uid, _alert_host

    return _t(_alert_device_uid(payload), 128) or (_t(_alert_host(payload), 128) or "").lower()


def _ref(prefix: str, value: Any) -> Optional[str]:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    text = _t(value, 128)
    return f"{prefix}:{text}" if text else None


def _datto(payload: dict[str, Any]) -> AlertKey:
    from apps.octo.adapters.datto.fields import _alert_uid

    dev, sig = _key(datto_device(payload), f"datto:{datto_monitor_signature(payload)}")
    return AlertKey("datto", dev, sig, "datto", ref=_ref("datto", _alert_uid(payload)))


# ---------------------------------------------------------------------------
# The rest
# ---------------------------------------------------------------------------

def _title_key(text: str) -> str:
    return re.sub(r"\d+", "#", _t(text, 160).lower())


def alert_key(row: dict[str, Any], payload: Optional[dict[str, Any]] = None) -> AlertKey:
    """The keys of one stored event row ({source, event_type, source_host,
    payload})."""
    p = payload if payload is not None else payload_of(row)
    source = _t(row.get("source"), 40) or "unknown"
    event_type = _t(row.get("event_type"), 80)
    host = _t(row.get("source_host"), 128)
    if source == "unifi":
        return _unifi(p, event_type)
    if source == "nextdns":
        return _nextdns(p, event_type)
    if source == "datto":
        return _datto(p)
    if source == "rocketcyber":
        dev, sig = _key("", f"rocketcyber:{_title_key(p.get('title') or event_type)}")
        return AlertKey(source, dev, sig, "rocketcyber", ref=_ref("rocketcyber", p.get("id")))
    if event_type.startswith("opencanary."):
        canary = _m(p.get("raw_canary")) or p
        src = _t(canary.get("src_host") or canary.get("src_ip"), 64)
        dev, sig = _key(src, f"canary:{event_type}")
        return AlertKey(source, dev, sig, "canary")
    if source == "wazuh" or event_type.startswith("wazuh"):
        rule, agent = _m(p.get("rule")), _m(p.get("agent"))
        dev, sig = _key(_t(agent.get("name"), 128) or host,
                        f"wazuh:{_t(rule.get('id'), 32) or event_type}")
        return AlertKey(source, dev, sig, "wazuh")
    dev, sig = _key(host, f"{source}:{event_type or 'event'}")
    return AlertKey(source, dev, sig, "other")


# ---------------------------------------------------------------------------
# Eligibility for EXPECTED
# ---------------------------------------------------------------------------

def is_csam(row: dict[str, Any], payload: Optional[dict[str, Any]] = None) -> bool:
    if _t(row.get("source"), 40) != "nextdns":
        return False
    p = payload if payload is not None else payload_of(row)
    return CSAM in nextdns_reasons(p)


NO_DEVICE = ("this alert names no device — an expected condition would cover the whole "
             "client; acknowledge each one instead")
NO_DEVICE_REPEAT = ("this alert names no device — \"repeats for 24 h\" would cover the whole "
                    "client; acknowledge it alone")
CSAM_REFUSAL = "a CSAM lookup is never expected — Athena treats it as Black"
CSAM_REPEAT = "a CSAM lookup is acknowledged one at a time — never \"repeats for 24 h\""
ROCKETCYBER_REFUSAL = ("RocketCyber alerts are acknowledged one at a time — too vague for an "
                       "expected condition (Rick, 2026-10-07)")
ROCKETCYBER_REPEAT = ("RocketCyber alerts are acknowledged one at a time — too vague for "
                      "\"repeats for 24 h\" (Rick, 2026-10-07)")


_ACK_ONLY_SIG_PREFIXES = tuple(f"{s}:" for s in sorted(ACK_ONLY_SOURCES))


def ack_only(source: Any, signature_key: Any = "") -> bool:
    """Does this source (an alert's, a key's, a stored rule's / verdict's) —
    or this signature key's prefix — name a source whose alerts are
    acknowledged one at a time (`ACK_ONLY_SOURCES`)."""
    return _t(source, 40).lower() in ACK_ONLY_SOURCES or \
        str(signature_key or "").startswith(_ACK_ONLY_SIG_PREFIXES)


def ack_only_key(key: AlertKey) -> bool:
    return ack_only(key.source, key.signature_key) or key.family in ACK_ONLY_SOURCES


def device_refusal(key: AlertKey) -> Optional[str]:
    """An alert that names no device is acknowledged one at a time: a device-
    less rule (or repeat-ack) would cover the whole client."""
    return NO_DEVICE if not key.device_key.strip() else None


def is_csam_key(key: AlertKey) -> bool:
    return key.signature_key.startswith(f"nextdns:{CSAM}|")


def expected_refusal(row: dict[str, Any], payload: Optional[dict[str, Any]] = None, *,
                     linked_incident: bool = False) -> Optional[str]:
    """Why this alert may NOT be marked expected (operator wording), or None."""
    from apps.octo.threat import evaluators, store

    p = payload if payload is not None else payload_of(row)
    source = _t(row.get("source"), 40)
    if source == store.EVENT_SOURCE:
        return "an incident's own record is not an alert"
    if linked_incident:
        return "this alert is evidence of an incident (Red / Black) — it is never expected"
    if ack_only(source):
        return ROCKETCYBER_REFUSAL
    if is_csam(row, p):
        return CSAM_REFUSAL
    if source == "datto" and datto_class(p) in DATTO_DETECTION_CLASSES:
        return ("a ransomware / threat detection is never expected — acknowledge each one, or "
                "confirm it as a threat")
    if evaluators.is_canary(row):
        return ("decoy (canary) alerts feed the deception rule (R6) — put a known scanner on "
                "the scanner allowlist instead")
    if evaluators.is_wazuh(row) and evaluators.r2_wazuh(dict(row, payload=p)).kind == \
            evaluators.INCIDENT:
        return "this alert would open a Red (R2-W malware verdict) — it is never expected"
    return device_refusal(alert_key(row, p))


def repeat_refusal(key: AlertKey, *, csam: bool = False) -> Optional[str]:
    """Why "acknowledge repeats for 24 h" is not offered for this alert, or
    None: a RocketCyber alert (by source), an alert that names no device, a
    CSAM lookup."""
    if ack_only_key(key):
        return ROCKETCYBER_REPEAT
    if not key.device_key.strip():
        return NO_DEVICE_REPEAT
    if csam or is_csam_key(key):
        return CSAM_REPEAT
    return None


def expected_eligible_bucket(key: AlertKey) -> bool:
    """A ledger bucket (UniFi / NextDNS) the Fleet counts: never a CSAM
    block (a line naming 'csam' among its reasons is always bucketed under
    it — `classification.classify_line`), never a device-less one, never an
    acknowledge-only source's."""
    return not is_csam_key(key) and not ack_only_key(key) and device_refusal(key) is None
