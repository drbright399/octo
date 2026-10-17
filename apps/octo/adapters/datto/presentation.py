"""What a Datto RMM alert SAYS — a headline and a detail from its own payload.

Datto's API alert object carries no ready-made message: the human text lives
inside `alertContext`, whose shape depends on its "@class". Two classes were
observed live (eventlog_ctx, comp_script_ctx); the others below are written
DEFENSIVELY from the field names Datto's API documents — every builder reads
candidates, tolerates their absence, and hands over to `_generic()` when it
finds nothing. `_generic()` works for a class nobody has seen yet, so a Datto
row always says something.

The webhook shape (operator-templated, `alertContext.message`) goes through
the same function and yields the same kind of result — including the same
`event_type` as the API shape for the monitor names this module knows (see
`_TYPE_WORDS_TO_CLASS`), so one alert class arriving through both doors is
one class to the triage worker.

All vendor text is untrusted: see `apps.octo.ingest.presentation`.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from apps.octo.adapters.datto.fields import (
    _alert_host,
    _alert_is_resolved,
    _alert_priority,
    _alert_site_name,
    _as_dict,
    _first,
    _is_unsubstituted_token,
)
from apps.octo.ingest.presentation import (
    DETAIL_MAX_LINES,
    HEADLINE_MAX,
    LABEL_MAX,
    EventPresentation,
    clean_block,
    clean_line,
    clean_lines,
    humanize_key,
    safe_event_type,
    slugify,
)

FALLBACK_EVENT_TYPE = "datto.alert"

_CLASS_LABELS: dict[str, str] = {
    "eventlog_ctx": "Event log",
    "comp_script_ctx": "Component monitor",
    "online_offline_status_ctx": "Device status",
    "perf_resource_usage_ctx": "Resource usage",
    "perf_disk_usage_ctx": "Disk usage",
    "perf_mon_ctx": "Performance monitor",
    "patch_ctx": "Patch",
    "srvc_status_ctx": "Service",
    "srvc_resource_usage_ctx": "Service resource usage",
    "process_status_ctx": "Process",
    "process_resource_usage_ctx": "Process resource usage",
    "antivirus_ctx": "Antivirus",
    "ransomware_ctx": "Ransomware",
    "sw_action_ctx": "Software change",
    "custom_snmp_ctx": "SNMP monitor",
    "wmi_ctx": "WMI monitor",
    "fs_object_ctx": "File/folder monitor",
    "sec_management_ctx": "Security management",
    "backup_management_ctx": "Backup",
    "ping_ctx": "Ping",
    "temperature_ctx": "Temperature",
    "fan_ctx": "Fan",
    "psu_ctx": "Power supply",
    "endpoint_security_threat_ctx": "Endpoint security threat",
    "endpoint_security_windows_defender_ctx": "Windows Defender",
}

# Keys whose value IS the message: shown without a "key:" prefix, tried first.
_MESSAGE_KEYS = (
    "message", "description", "info", "reason", "details", "detail", "diag",
    "diagnostics", "text", "summary", "error", "errormessage", "output",
)
# Then the keys that say what state something is in / what it is called.
_STATE_WORDS = ("status", "state", "result", "condition", "action")
_NAME_WORDS = ("name", "path", "product", "type", "value", "sample", "threshold")
_MAX_CONTEXT_KEYS = 64
_MAX_FACTS = 12


# ---------------------------------------------------------------------------
# Reading the context defensively
# ---------------------------------------------------------------------------

def _get(ctx: dict[str, Any], *names: str) -> Any:
    """First present value among `names`, matching keys case-insensitively."""
    lowered = {k.lower(): v for k, v in list(ctx.items())[:_MAX_CONTEXT_KEYS]
               if isinstance(k, str)}
    for name in names:
        if name.lower() in lowered:
            value = lowered[name.lower()]
            if value is not None and value != "":
                return value
    return None


def _text(ctx: dict[str, Any], *names: str, limit: int = LABEL_MAX) -> str:
    return _scalar(_get(ctx, *names), limit)


def _num(ctx: dict[str, Any], *names: str) -> Optional[float]:
    value = _get(ctx, *names)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip()[:32].rstrip("%"))
        except ValueError:
            return None
    else:
        return None
    return number if number == number and abs(number) != float("inf") else None


def _scalar(value: Any, limit: int = 160) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        parts = [clean_line(v, 48) for v in value[:5] if not isinstance(v, (dict, list))]
        return clean_line(", ".join(p for p in parts if p), limit)
    text = clean_line(value, limit)
    return "" if _is_unsubstituted_token(text) else text


def _is_id_key(key: str) -> bool:
    k = key.lower()
    return k in ("uid", "id", "guid") or k.endswith(("uid", "guid")) or k.endswith("_id")


def _facts(ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(raw_key, shown_key, value) for every scalar in the context, one level
    of nesting flattened, most informative first. Deterministic."""
    flat: list[tuple[str, Any]] = []
    for key in sorted(k for k in list(ctx)[:_MAX_CONTEXT_KEYS] if isinstance(k, str)):
        if key == "@class":
            continue
        value = ctx[key]
        if isinstance(value, dict):
            for sub in sorted(k for k in list(value)[:16] if isinstance(k, str)):
                flat.append((sub, value[sub]))
        else:
            flat.append((key, value))

    def rank(item: tuple[str, Any]) -> tuple[int, str]:
        k = item[0].lower()
        if k in _MESSAGE_KEYS:
            return (0, f"{_MESSAGE_KEYS.index(k):02d}")
        if _is_id_key(k):
            return (4, k)
        if any(w in k for w in _STATE_WORDS):
            return (1, k)
        if any(w in k for w in _NAME_WORDS):
            return (2, k)
        return (3, k)

    out: list[tuple[str, str, str]] = []
    for key, value in sorted(flat, key=rank):
        shown = _scalar(value)
        if shown:
            out.append((key, humanize_key(key) or "value", shown))
    return out


def _fact_lines(ctx: dict[str, Any], *, skip: tuple[str, ...] = ()) -> list[str]:
    skipped = {s.lower() for s in skip}
    return [
        f"{shown_key}: {value}"
        for key, shown_key, value in _facts(ctx)
        if key.lower() not in skipped
    ][:_MAX_FACTS]


# Values Windows writes when a field does not apply: the null SID, the null
# logon id / process id, and the plain dash. A line carrying one says nothing.
_WINDOWS_NULL_VALUES = frozenset({"", "-", "s-1-0-0", "0x0"})


def _windows_event_lines(lines: list[str]) -> list[str]:
    """Windows event text is mostly 'Section:' headers and 'Key: -' blanks.
    Keep the lines that say something."""
    kept: list[str] = []
    for line in lines:
        if line.endswith(":"):
            continue
        _, sep, value = line.partition(": ")
        if sep and value.strip().lower() in _WINDOWS_NULL_VALUES:
            continue
        kept.append(line)
    return kept


def _bounded_body(lines: list[str], *, reserve: int) -> list[str]:
    """At most DETAIL_MAX_LINES - `reserve` lines, ending in an explicit '…'
    line when some were dropped — so a tail appended after this stays inside
    the block's line budget AND the cut is visible (clean_block only marks
    a cut it makes itself)."""
    budget = max(1, DETAIL_MAX_LINES - reserve)
    if len(lines) <= budget:
        return list(lines)
    return lines[: budget - 1] + ["…"]


def _join(label: str, body: str) -> str:
    return f"{label} — {body}" if body else label


# ---------------------------------------------------------------------------
# Per-class builders → (headline, detail_lines). "" headline = use _generic.
# ---------------------------------------------------------------------------

Built = tuple[str, list[str]]


def _generic(ctx: dict[str, Any], label: str) -> Built:
    facts = _facts(ctx)
    if not facts:
        return "", []
    key, shown_key, value = facts[0]
    if key.lower() in _MESSAGE_KEYS:
        lines = clean_lines(_get(ctx, key)) or [value]
        rest = lines[1:] + _fact_lines(ctx, skip=(key,))
        return _join(label, lines[0].rstrip(".") or lines[0]), rest
    informative = [f for f in facts if not _is_id_key(f[0])] or facts
    body = " · ".join(f"{sk}: {v}" for _, sk, v in informative[:3])
    return _join(label, body), _fact_lines(ctx)


def _eventlog(ctx: dict[str, Any], label: str) -> Built:
    log = _text(ctx, "logName", limit=48)
    code = _text(ctx, "code", "eventId", limit=16)
    source = _text(ctx, "source")
    lines = clean_lines(_get(ctx, "description", "message"))
    what = " ".join(x for x in (log, code) if x)
    prefix = f"{label} · {what}" if what else label
    first = lines[0].rstrip(".") if lines else ""
    if not first and source:
        first = f"source {source}"
    if not what and not first:
        return "", []
    tail: list[str] = []
    if source:
        tail.append(f"Source: {source}")
    triggered = _num(ctx, "triggerCount")
    if triggered is not None and triggered > 1:
        tail.append(f"Triggered {int(triggered)} times")
    if _get(ctx, "causedSuspension") is True:
        tail.append("Caused suspension: yes")
    # The tail (source, trigger count) is always kept; the event body gives
    # way, and says so with a '…' line rather than looking complete.
    detail = _bounded_body(_windows_event_lines(lines[1:]), reserve=1 if tail else 0)
    if tail:
        detail.append(" · ".join(tail))
    return _join(prefix, first), detail


def _comp_script(ctx: dict[str, Any], label: str) -> Built:
    samples = _as_dict(_get(ctx, "samples"))
    if not samples:
        return "", []
    diag = clean_lines(_get(samples, "DIAG", "diagnostic", "message"))
    status = _text(samples, "STATUS", limit=160)
    first = (diag[0] if diag else status).rstrip(".")
    if not first:
        return _generic(samples, label)
    detail = diag[1:]
    if status and diag:
        detail.append(f"Status: {status}")
    detail += _fact_lines(samples, skip=("DIAG", "STATUS", "diagnostic", "message"))
    return _join(label, first), detail


def _online_offline(ctx: dict[str, Any], label: str) -> Built:
    status = _text(ctx, "status", "state", limit=32).lower()
    if "offline" in status:
        return "Device offline", _fact_lines(ctx, skip=("status",))
    if "online" in status:
        return "Device online", _fact_lines(ctx, skip=("status",))
    return "", []


def _perf_resource(ctx: dict[str, Any], label: str) -> Built:
    pct = _num(ctx, "percentage", "usage", "value")
    kind = _text(ctx, "type", "resource", limit=32)
    if pct is None:
        return "", []
    kind = kind.upper() if 0 < len(kind) <= 4 else kind.capitalize()
    subject = f"{kind} usage" if kind else label
    return f"{subject} {clean_line(pct)}%", _fact_lines(ctx)


def _perf_disk(ctx: dict[str, Any], label: str) -> Built:
    disk = _text(ctx, "diskName", "disk", "drive", "path", limit=64)
    total = _num(ctx, "totalVolume", "total", "size")
    free = _num(ctx, "freeSpace", "free")
    unit = _text(ctx, "unitOfMeasure", "unit", limit=12)
    where = f" on {disk}" if disk else ""
    if total and free is not None and 0 <= free <= total:
        used = round((1 - free / total) * 100)
        of = f"{clean_line(free)} of {clean_line(total)}{' ' + unit if unit else ''} free"
        return f"Disk usage {used}%{where}", [of] + _fact_lines(ctx)
    pct = _num(ctx, "percentage", "usage")
    if pct is not None:
        return f"Disk usage {clean_line(pct)}%{where}", _fact_lines(ctx)
    return "", []


def _named(name_keys: tuple[str, ...], state_keys: tuple[str, ...]) -> Callable[..., Built]:
    """'<label> — <name>: <state>' from whichever of the two is present."""

    def build(ctx: dict[str, Any], label: str) -> Built:
        name = _text(ctx, *name_keys)
        state = _text(ctx, *state_keys, limit=160)
        body = f"{name}: {state}" if name and state else (name or state)
        return (_join(label, body), _fact_lines(ctx)) if body else ("", [])

    return build


_BUILDERS: dict[str, Callable[[dict[str, Any], str], Built]] = {
    "eventlog_ctx": _eventlog,
    "comp_script_ctx": _comp_script,
    "online_offline_status_ctx": _online_offline,
    "perf_resource_usage_ctx": _perf_resource,
    "perf_disk_usage_ctx": _perf_disk,
    "perf_mon_ctx": _named(("counterName", "counter", "name"), ("value", "currentValue")),
    "patch_ctx": _named(("result", "status"), ("info", "patchName", "name")),
    "srvc_status_ctx": _named(("serviceName", "service", "name"), ("status", "state")),
    "srvc_resource_usage_ctx": _named(("serviceName", "service", "name"), ("usage", "percentage")),
    "process_status_ctx": _named(("processName", "process", "name"), ("status", "state")),
    "process_resource_usage_ctx": _named(("processName", "process", "name"), ("usage", "percentage")),
    "antivirus_ctx": _named(("productName", "product", "name"), ("status", "state")),
    "sec_management_ctx": _named(("productName", "product", "name"), ("status", "state")),
    "backup_management_ctx": _named(("productName", "jobName", "name"), ("status", "state", "result")),
    "ransomware_ctx": _named(("state", "status"), ("affectedDirectories", "watchPaths", "rwextension")),
    "sw_action_ctx": _named(("softwareName", "name", "software"), ("actionType", "action", "version")),
    "custom_snmp_ctx": _named(("displayName", "monitorInstance", "name"), ("currentValue", "value")),
    "wmi_ctx": _named(("displayName", "name", "query"), ("value", "currentValue")),
    "fs_object_ctx": _named(("path", "objectName", "name"), ("condition", "sample", "status")),
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _label_for(name: Optional[str]) -> str:
    if not name:
        return ""
    known = _CLASS_LABELS.get(name.strip().lower())
    if known:
        return known
    if name.strip().lower().endswith("_ctx"):
        words = clean_line(name.strip()[:-4].replace("_", " "), LABEL_MAX)
        return words[:1].upper() + words[1:]
    return clean_line(name, 48)


# The webhook shape carries no `alertContext.@class` — only the monitor name
# Datto substitutes into [alert_type] / [alert_category]. The machine label
# must not depend on which door an alert came through (the triage worker's
# recurrence signature joins on source + event_type + host, and an instance
# usually has BOTH polling and the webhook on), so the monitor names are
# mapped onto the API's class slugs. Matched on whole words of the slug, most
# specific first; a name this table does not know keeps its own bounded slug
# rather than being guessed into a class.
_TYPE_WORDS_TO_CLASS: tuple[tuple[str, str], ...] = (
    ("event_log", "eventlog_ctx"),
    ("eventlog", "eventlog_ctx"),
    ("component", "comp_script_ctx"),
    ("online", "online_offline_status_ctx"),
    ("offline", "online_offline_status_ctx"),
    ("device_status", "online_offline_status_ctx"),
    ("disk_usage", "perf_disk_usage_ctx"),
    ("disk_space", "perf_disk_usage_ctx"),
    ("service_resource", "srvc_resource_usage_ctx"),
    ("process_resource", "process_resource_usage_ctx"),
    ("resource_usage", "perf_resource_usage_ctx"),
    ("cpu", "perf_resource_usage_ctx"),
    ("memory", "perf_resource_usage_ctx"),
    ("performance", "perf_mon_ctx"),
    ("patch", "patch_ctx"),
    ("service", "srvc_status_ctx"),
    ("process", "process_status_ctx"),
    ("antivirus", "antivirus_ctx"),
    ("anti_virus", "antivirus_ctx"),
    ("ransomware", "ransomware_ctx"),
    ("software", "sw_action_ctx"),
    ("snmp", "custom_snmp_ctx"),
    ("wmi", "wmi_ctx"),
    ("file", "fs_object_ctx"),
    ("folder", "fs_object_ctx"),
    ("security_management", "sec_management_ctx"),
    ("backup", "backup_management_ctx"),
    ("ping", "ping_ctx"),
    ("temperature", "temperature_ctx"),
    ("fan", "fan_ctx"),
    ("power_supply", "psu_ctx"),
    ("psu", "psu_ctx"),
    ("windows_defender", "endpoint_security_windows_defender_ctx"),
    ("defender", "endpoint_security_windows_defender_ctx"),
    ("endpoint_security", "endpoint_security_threat_ctx"),
)


def _class_for_vendor_type(name: Optional[str]) -> Optional[str]:
    """The `_ctx` class a webhook's monitor name unambiguously denotes, else
    None ("Disk Usage Monitor" → perf_disk_usage_ctx)."""
    if not name:
        return None
    padded = f"_{slugify(name, 96)}_"
    for words, cls in _TYPE_WORDS_TO_CLASS:
        if f"_{words}_" in padded:
            return cls
    return None


def present_alert(envelope: Any) -> EventPresentation:
    """Headline + detail for a Datto alert in EITHER inbound shape. Never
    raises, never returns a blank headline."""
    env = envelope if isinstance(envelope, dict) else {}
    ctx = _as_dict(env.get("alertContext"))
    at_class = _first(ctx.get("@class"))
    alert_type = _first(env.get("alertType"))
    category = _first(env.get("alertCategory"))

    machine = (
        at_class
        or _class_for_vendor_type(alert_type) or alert_type
        or _class_for_vendor_type(category) or category
        or ""
    )
    slug = slugify(machine[:-4] if machine.lower().endswith("_ctx") else machine)
    event_type = safe_event_type(f"datto.{slug}" if slug else "", FALLBACK_EVENT_TYPE)

    label = _label_for(at_class) or _label_for(category) or _label_for(alert_type)
    device = clean_line(_alert_host(env), 128) or None
    site = clean_line(_alert_site_name(env), 128) or None

    headline, detail = "", []
    try:
        builder = _BUILDERS.get((at_class or alert_type or "").strip().lower())
        if builder is not None:
            headline, detail = builder(ctx, label or "Datto alert")
        if not headline:
            headline, detail = _generic(ctx, label or "Datto alert")
    except Exception:  # noqa: BLE001 — presentation must never break ingest or a feed
        headline, detail = "", []

    diagnostics = clean_lines(env.get("diagnostics"))
    if not headline and diagnostics:
        headline = _join(label or "Datto alert", diagnostics[0].rstrip("."))
        diagnostics = diagnostics[1:]
    fallback = not headline
    if fallback:
        headline = f"{label} alert" if label else "Datto alert"
        if device:
            headline += f" on {device}"
    detail = list(detail) + [f"Diagnostics: {d}" for d in diagnostics[:3]]

    if not detail:
        priority = clean_line(_alert_priority(env), 24)
        where = " · ".join(x for x in (device, site) if x)
        bits = [f"{priority} priority" if priority else "", where]
        detail = [" — ".join(b for b in bits if b)]

    if _alert_is_resolved(env):
        headline = f"[resolved] {headline}"

    return EventPresentation(
        event_type=event_type,
        headline=clean_line(headline, HEADLINE_MAX) or "Datto alert",
        detail=clean_block(detail),
        device=device,
        site=site,
        fallback=fallback,
    )
