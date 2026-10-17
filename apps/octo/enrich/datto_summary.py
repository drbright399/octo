"""A Datto RMM alert in ONE deterministic line (v0.17.2, C.2) — parsed from
the alert context by its class, no LLM:

  eventlog            "Event 7031 · Service Control Manager · System log"
  Datto NOC report    its facts (`dnoc`): memory with its pressure signals,
                      CPU with its queue, a service with its downtime, a
                      disk with its free space
  performance         "CPU usage 97% (threshold 90%)", "Disk usage 91% on C:"
  service / process   "Service Spooler is stopped"
  antivirus, security, backup, ransomware, software
                      "<product>: <status>" / "Software install: <name> <version>"
  device status       "Device offline"
  component (script)  its diagnostic's first sentence
  anything else       the first sentence of the alert's own text

with the device's host name, open / resolved, and whether it came from the
Datto NOC ("DNOC" — its monitor or category says so). The full text (the
presentation's detail lines) goes behind a "details" expander. All of it is
vendor text: cleaned and bounded (`ingest.presentation`).
"""
from __future__ import annotations

import re
from typing import Any, Optional

from apps.octo.adapters.datto.fields import _alert_host, _alert_is_resolved, _alert_priority
from apps.octo.adapters.datto.presentation import _get, _num, _text, present_alert
from apps.octo.enrich import dnoc
from apps.octo.ingest.presentation import clean_line, clean_lines
from apps.octo.verdicts.keys import datto_class

LINE_MAX = 200
_NOC_RE = re.compile(r"(?<![a-z])d?noc(?![a-z])", re.IGNORECASE)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def _m(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def first_sentence(text: Any) -> str:
    lines = clean_lines(text) if text is not None else []
    first = lines[0] if lines else ""
    return clean_line(_SENTENCE_RE.split(first, maxsplit=1)[0].rstrip("."), LINE_MAX)


def _pct(value: Optional[float]) -> str:
    if value is None:
        return ""
    return f"{int(value)}%" if float(value).is_integer() else f"{round(value, 1)}%"


def _perf(ctx: dict[str, Any], cls: str) -> str:
    value = _num(ctx, "percentage", "usage", "value", "currentValue", "sample")
    threshold = _num(ctx, "threshold", "thresholdValue", "limit", "triggerValue")
    if cls == "perf_disk_usage_ctx":
        disk = _text(ctx, "diskName", "disk", "drive", "path", limit=64)
        total, free = _num(ctx, "totalVolume", "total", "size"), _num(ctx, "freeSpace", "free")
        if value is None and total and free is not None and 0 <= free <= total:
            value = round((1 - free / total) * 100)
        metric = "Disk usage"
        where = f" on {disk}" if disk else ""
    else:
        kind = _text(ctx, "type", "resource", "counterName", "counter", "serviceName",
                     "processName", "name", limit=48)
        metric = (kind.upper() if 0 < len(kind) <= 4 else kind) or "Usage"
        metric = metric if cls == "perf_mon_ctx" else f"{metric} usage"
        where = ""
    if value is None:
        return ""
    unit = "" if cls == "perf_mon_ctx" else "%"
    shown = (_pct(value) if unit else clean_line(value, 24))
    limit = f" (threshold {_pct(threshold) if unit else clean_line(threshold, 24)})" \
        if threshold is not None else ""
    return f"{metric} {shown}{where}{limit}"


def _line(payload: dict[str, Any], cls: str) -> str:
    ctx = _m(payload.get("alertContext"))
    if cls == "eventlog_ctx":
        noc = dnoc.line(ctx)
        if noc:
            return noc
        code = _text(ctx, "code", "eventId", limit=16)
        source = _text(ctx, "source", limit=80)
        log = _text(ctx, "logName", limit=48)
        parts = [f"Event {code}" if code else "Event", source, f"{log} log" if log else ""]
        return " · ".join(p for p in parts if p)
    if cls in ("perf_resource_usage_ctx", "perf_disk_usage_ctx", "perf_mon_ctx",
               "srvc_resource_usage_ctx", "process_resource_usage_ctx"):
        return _perf(ctx, cls)
    if cls in ("srvc_status_ctx", "process_status_ctx"):
        name = _text(ctx, "serviceName", "processName", "service", "process", "name", limit=80)
        state = _text(ctx, "status", "state", limit=40).lower()
        what = "Service" if cls == "srvc_status_ctx" else "Process"
        if name and state:
            return f"{what} {name} is {state}"
        return f"{what} {name or state}".strip() if (name or state) else ""
    if cls in ("antivirus_ctx", "sec_management_ctx", "backup_management_ctx"):
        product = _text(ctx, "productName", "product", "jobName", "name", limit=80)
        status = _text(ctx, "status", "state", "result", limit=80)
        label = {"antivirus_ctx": "Antivirus", "sec_management_ctx": "Security",
                 "backup_management_ctx": "Backup"}[cls]
        body = ": ".join(x for x in (product, status) if x)
        return f"{label} — {body}" if body else ""
    if cls == "ransomware_ctx":
        state = _text(ctx, "state", "status", limit=60)
        where = _text(ctx, "affectedDirectories", "watchPaths", limit=80)
        return "Ransomware detection" + (f": {state}" if state else "") + \
            (f" ({where})" if where else "")
    if cls == "sw_action_ctx":
        action = _text(ctx, "actionType", "action", limit=32).lower()
        name = _text(ctx, "softwareName", "name", "software", limit=80)
        version = _text(ctx, "version", limit=32)
        body = " ".join(x for x in (name, version) if x)
        return f"Software {action or 'change'}: {body}" if body else ""
    if cls == "online_offline_status_ctx":
        status = _text(ctx, "status", "state", limit=32).lower()
        return "Device offline" if "offline" in status else \
            "Device online" if "online" in status else ""
    if cls == "comp_script_ctx":
        samples = _m(_get(ctx, "samples"))
        return first_sentence(_get(samples, "DIAG", "diagnostic", "message")
                              or _get(samples, "STATUS"))
    return ""


def is_noc(payload: dict[str, Any]) -> bool:
    ctx = _m(payload.get("alertContext"))
    text = " ".join(str(x) for x in (payload.get("alertType"), payload.get("alertCategory"),
                                     ctx.get("@class"), _m(payload.get("alertMonitorInfo"))
                                     .get("name"), payload.get("monitorName"))
                    if isinstance(x, str))
    return bool(_NOC_RE.search(text)) or dnoc.is_dnoc(ctx)


def summarize(payload: Any) -> dict[str, Any]:
    """{line, class, host, resolved, priority, noc, details}."""
    env = payload if isinstance(payload, dict) else {}
    cls = datto_class(env)
    shown = present_alert(env)
    try:
        line = _line(env, cls)
    except Exception:  # noqa: BLE001 — a summary never breaks the drawer
        line = ""
    if not line:
        line = first_sentence(shown.headline.removeprefix("[resolved] ")) or "Datto alert"
    noc = is_noc(env)
    if noc and not line.lower().startswith("noc"):
        line = f"NOC: {line}"
    return {
        "line": clean_line(line, LINE_MAX),
        "class": cls,
        "host": clean_line(_alert_host(env), 128) or None,
        "resolved": _alert_is_resolved(env),
        "priority": clean_line(_alert_priority(env), 24) or None,
        "noc": noc,
        "details": [clean_line(d, 400) for d in (shown.detail or "").splitlines() if d][:40],
    }
