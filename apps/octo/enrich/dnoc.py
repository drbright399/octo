"""Datto NOC (DNOC) triage reports in ONE line (v0.17.2) — no LLM.

The Datto NOC's monitors write a structured triage report into the Windows
event log, and Datto raises it as an event-log alert (`eventlog_ctx`) whose
`source` names the monitor. Its own one-liner would be "Event 12000 ·
DNOCMemoryMonitor · Application log" — nothing an analyst can act on. The
report itself carries the facts that settle most of these tickets, so the
line is built from them:

  DNOCMemoryMonitor     "NOC memory 91.7% (threshold 90%) · commit 78% ·
                         0.4 hard faults/s · non-reclaimable 85% · top sqlservr
                         20.0 GB" — the PRESSURE signals, not only the
                         utilization (a SQL Server holding its cache reads
                         90 %+ and is healthy; commit and hard faults say
                         whether it is short of memory).
  DNOCCpuMonitoring     "NOC CPU 97.5% (threshold 90%) · queue 1.5/core ·
                         kernel 40% · top endpointprotection 61%"
  DNOCServiceMonitor    "NOC service: <display name> — stopped, restart
                         failed, down 12d 3h" ("NOC services (2): …");
                         "NOC service: <name> — ticket avoided, now running"
  DNOCDiskRemediation   "NOC disk C: 92% used, 15.2 GB free of 237 GB ·
                         reclaimed 0 bytes · no cleanup tasks enabled"

A report this module does not know (or a layout it cannot read) yields ""
and the caller falls back to its generic line. Every value is vendor text:
cleaned and bounded (`ingest.presentation.clean_line`).

KEYS (v0.17.3): the same parse names WHAT a report is about for the alert's
signature (`verdicts.keys` — acknowledge "repeats", expected conditions,
"N repeats since"), `signature_part`:

  DNOCServiceMonitor    the SORTED set of affected services — EVERY service
                        name the report gives, wherever: the SUMMARY items'
                        "(name)", every "Service :" field, every "TICKET
                        AVOIDED - <name>" headline (the "Display name :"
                        fields only when it names none of those) — and how
                        many the report says are affected. A vendor's
                        remote-access services kept stopped on purpose on a
                        regulated server must not hide a future "SQL Server
                        stopped" on it: {A} and {A, B} are two keys, and a
                        layout that names B somewhere else than A still
                        names B in the key
  DNOCDiskRemediation   the drive letter
  memory / CPU          nothing more (the monitor — already in the key)

Service names are lower-cased, cleaned and bounded — their DIGITS ARE KEPT
(unlike a message shape): a service name is that service's identity on the
machine, and two BeyondTrust Jump Clients of two vendors
("bomgar-ps-<id>-<id>") or MSSQL$PROD1 / MSSQL$PROD2 are different services.
A name that changes on an update only ever makes the key miss (the alert
comes back — louder, never quieter). A report that says more services are
affected than it names is keyed by a digest of its names AND its shape
(`_partial`: numbers masked, like a message shape): two different sets never
share a key. A report this cannot read gives None: the caller keeps the plain
code + source + log key (a narrower key only ever matches LESS — never
quieter).
"""
from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from apps.octo.ingest.presentation import clean_line, clean_lines

PART_MAX = 80
# A key's service list: at most this long, else a digest of the whole set.
KEY_SERVICES_MAX = 200
PART_MEMO_MAX = 4096
_PART_MEMO: dict[tuple[str, str], Optional[str]] = {}
_PART_LOCK = threading.Lock()
_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 ().%/+-]{1,60}?)\s*:\s+(.+)$")
_SECTION_RE = re.compile(r"^\s*-{2,}\s*(.+?)\s*-{2,}\s*$")
_CAPS_SECTION_RE = re.compile(r"^\s*([A-Z][A-Z /-]{2,40})\s*$")
_PROC_RE = re.compile(r"^\s*\d{1,3}\.\s+(\S+)")
_NUM_RE = re.compile(r"-?\d[\d,]*(?:\.\d+)?")
_SUMMARY_ITEM_RE = re.compile(r"^\s*\[\d{1,3}\]\s+(.+?)\s*$")
_AFFECTED_RE = re.compile(r"\((\d{1,4}) service\(s\) affected\)", re.IGNORECASE)
# "TICKET AVOIDED - RocketAgent (RocketAgent Service)": one service, its own
# headline (no SUMMARY block).
_ONE_SERVICE_RE = re.compile(r"^([A-Z][A-Z ]{3,40}) - (.+?)(?: \([^()]*\))?$")


def is_dnoc(ctx: dict[str, Any]) -> bool:
    source = ctx.get("source")
    return isinstance(source, str) and source.strip().upper().startswith("DNOC")


def _key(label: str) -> str:
    return " ".join(label.lower().split())


def parse(text: Any) -> tuple[dict[str, str], dict[str, list[dict[str, str]]]]:
    """({label: value} — the first occurrence, plus "<section>/<label>" for
    every section-qualified one; {section: [process entries]} for the "Top
    … Processes" sections, each entry {name, <label>: value})."""
    fields: dict[str, str] = {}
    procs: dict[str, list[dict[str, str]]] = {}
    section = ""
    for raw in clean_lines(text, line_limit=400)[:400]:
        m = _SECTION_RE.match(raw)
        if m:
            section = _key(m.group(1))
            continue
        caps = _CAPS_SECTION_RE.match(raw)
        if caps and ":" not in raw:
            section = _key(caps.group(1))
            continue
        if section.startswith("top ") and section.endswith("processes"):
            p = _PROC_RE.match(raw)
            if p:
                procs.setdefault(section, []).append({"name": clean_line(p.group(1), PART_MAX)})
                continue
        kv = _KV_RE.match(raw)
        if not kv:
            continue
        label, value = _key(kv.group(1)), clean_line(kv.group(2), PART_MAX)
        if section.startswith("top ") and section.endswith("processes") and procs.get(section):
            procs[section][-1].setdefault(label, value)
            continue
        fields.setdefault(label, value)
        if section:
            fields.setdefault(f"{section}/{label}", value)
    return fields, procs


def _num(value: Optional[str]) -> Optional[float]:
    m = _NUM_RE.search(value or "")
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", ""))
    except ValueError:
        return None


def _pct(value: Optional[str]) -> str:
    n = _num(value)
    if n is None:
        return ""
    r = round(n, 1)
    return f"{int(r)}%" if float(r).is_integer() else f"{r}%"


def _mb(value: Optional[str]) -> str:
    """'20,480 MB' → '20.0 GB'; under a GB stays in MB."""
    n = _num(value)
    if n is None:
        return ""
    unit = (value or "").upper()
    if "GB" in unit:
        return f"{round(n, 1)} GB"
    return f"{round(n / 1024, 1)} GB" if n >= 1024 else f"{int(n)} MB"


def _memory(f: dict[str, str], procs: dict[str, list[dict[str, str]]]) -> str:
    used = _pct(f.get("current memory utilization"))
    if not used:
        return ""
    limit = _pct(f.get("configured alert threshold"))
    parts = [f"NOC memory {used}" + (f" (threshold {limit})" if limit else "")]
    commit = _pct(f.get("commit utilization"))
    if commit:
        parts.append(f"commit {commit}")
    faults = _num(f.get("hard page faults per sec"))
    if faults is not None:
        parts.append(f"{round(faults, 1):g} hard faults/s")
    inuse = f.get("in-use (non-reclaimable)") or ""
    held = re.search(r"\(([\d.,]+)\s*%\)", inuse)
    if held:
        parts.append(f"non-reclaimable {_pct(held.group(1))}")
    top = (procs.get("top memory processes") or [None])[0]
    if top and top.get("name"):
        size = _mb(top.get("private memory") or top.get("working set"))
        parts.append(f"top {top['name']}" + (f" {size}" if size else ""))
    return " · ".join(parts)


def _cpu(f: dict[str, str], procs: dict[str, list[dict[str, str]]]) -> str:
    used = _pct(f.get("current cpu utilization") or f.get("overall cpu utilization"))
    if not used:
        return ""
    limit = _pct(f.get("configured alert threshold"))
    parts = [f"NOC CPU {used}" + (f" (threshold {limit})" if limit else "")]
    queue = f.get("processor queue length") or ""
    per_core = re.search(r"per-core:\s*([\d.]+)", queue)
    if per_core:
        parts.append(f"queue {per_core.group(1)}/core")
    elif _num(queue) is not None:
        parts.append(f"queue {_num(queue):g}")
    kernel = _pct(f.get("kernel (privileged) time"))
    if kernel:
        parts.append(f"kernel {kernel}")
    top = (procs.get("top cpu processes") or [None])[0]
    if top and top.get("name"):
        share = _pct(top.get("cpu utilization"))
        parts.append(f"top {top['name']}" + (f" {share}" if share else ""))
    return " · ".join(parts)


@dataclass
class _Services:
    """What a DNOCServiceMonitor report says about its services."""
    names: list[str] = field(default_factory=list)
    """Display names, in the report's order (the line)."""
    ids: list[str] = field(default_factory=list)
    """Service names (the key) — every one the report gives: the SUMMARY
    items' trailing "(name)" (an item without one: the item itself), every
    "Service :" field, every one-service headline's name; the "Display
    name :" fields only when there is none of those."""
    affected: Optional[int] = None
    headline: str = ""
    one: Optional[tuple[str, str]] = None
    """("TICKET AVOIDED", name) — a one-service report (no SUMMARY)."""


def _services(text: Any, f: dict[str, str]) -> _Services:
    lines = clean_lines(text, line_limit=400)[:400]
    out = _Services()
    in_summary = False
    # The key reads the WHOLE report (never only its first match): a layout
    # that names one service in its headline and another in a "Service :"
    # field, or two services in two headlines / two detail blocks, names
    # both — else {A, B} would key as {A} (an Expected rule on A hiding B).
    named: list[str] = []
    displays: list[str] = []
    for raw in lines:
        m = _AFFECTED_RE.search(raw)
        if m and out.affected is None:
            out.affected = int(m.group(1))
            out.headline = raw.split(" - (")[0].strip()
        if raw.strip().upper() == "SUMMARY":
            in_summary = True
            continue
        if in_summary:
            item = _SUMMARY_ITEM_RE.match(raw)
            if item:
                entry = item.group(1)
                out.names.append(clean_line(re.sub(r"\s*\([^()]*\)\s*$", "", entry), PART_MAX))
                short = re.search(r"\(([^()]*)\)\s*$", entry)
                named.append(clean_line(short.group(1) if short else entry, PART_MAX))
                continue
            if raw.startswith("---") or raw.startswith("==="):
                in_summary = False
        one = _ONE_SERVICE_RE.match(raw)
        # "… STOPPED - (2 service(s) affected)" names no service: a line,
        # never a key.
        if one and not raw.startswith("DNOC") and not _AFFECTED_RE.search(raw):
            named.append(clean_line(one.group(2), PART_MAX))
        kv = _KV_RE.match(raw)
        if kv and _key(kv.group(1)) == "service":
            named.append(clean_line(kv.group(2), PART_MAX))
        elif kv and _key(kv.group(1)) == "display name":
            displays.append(clean_line(kv.group(2), PART_MAX))
    out.ids = [i for i in named if i] or [d for d in displays if d]
    if not out.names and f.get("display name"):
        out.names = [f["display name"]]
    if not out.names:
        for raw in lines[:6]:
            one = _ONE_SERVICE_RE.match(raw)
            if one and not raw.startswith("DNOC"):
                out.one = (one.group(1).strip(), clean_line(one.group(2), PART_MAX))
                break
    return out


def _service(text: Any, f: dict[str, str]) -> str:
    facts = _services(text, f)
    names, affected, headline = facts.names, facts.affected, facts.headline
    if not names:
        if facts.one is not None:
            final = (f.get("final state") or "").lower()
            tail = [facts.one[0].lower()] + ([f"now {final}"] if final else [])
            return f"NOC service: {facts.one[1]} — {', '.join(tail)}"
        return ""
    count = affected or len(names)
    what = names[0] if count == 1 else f"{'; '.join(names[:2])}" + ("; …" if count > 2 else "")
    head = "NOC service" if count == 1 else f"NOC services ({count})"
    state = (f.get("state/state") or f.get("current status") or "").split(" - ")[0].lower()
    failed = _num(f.get("failed")) or 0
    tail = []
    if state:
        tail.append(state + (", restart failed" if failed and state.startswith("stop") else ""))
    elif headline:
        tail.append(headline.lower())
    down = f.get("downtime")
    if down:
        tail.append(f"down {down}")
    return f"{head}: {what}" + (f" — {', '.join(tail)}" if tail else "")


def _disk(f: dict[str, str]) -> str:
    drive = f.get("drive") or ""
    after = "disk space - after"
    before = "disk space - before"
    used = f.get(f"{after}/used") or f.get(f"{before}/used") or f.get("used")
    free = f.get(f"{after}/free") or f.get(f"{before}/free") or f.get("free")
    total = f.get(f"{after}/total") or f.get(f"{before}/total") or f.get("total")
    if not (used or free):
        return ""
    share = re.search(r"\(([\d.,]+)\s*%\)", used or "")
    free_amount = re.sub(r"\s*\(.*$", "", free or "").strip()
    total_amount = (total or "").strip()
    head = f"NOC disk {drive}".rstrip()
    body = []
    if share:
        body.append(f"{_pct(share.group(1))} used")
    if free_amount:
        body.append(f"{free_amount} free" + (f" of {total_amount}" if total_amount else ""))
    parts = [f"{head} " + ", ".join(body)] if body else [head]
    reclaimed = f.get("cleanup results/total reclaimed") or f.get("total reclaimed")
    if reclaimed:
        parts.append(f"reclaimed {reclaimed}")
    if any(k.endswith("config warning") for k in f) and \
            "no cleanup" in (f.get("config warning") or "").lower():
        parts.append("no cleanup tasks enabled")
    return " · ".join(parts)


def monitor(ctx: dict[str, Any]) -> Optional[str]:
    """'memory' | 'cpu' | 'service' | 'disk' — the DNOC monitor a report
    comes from (its event-log source); None when it is not one this module
    reads."""
    if not is_dnoc(ctx):
        return None
    source = str(ctx.get("source") or "").strip().lower()
    for kind in ("memory", "cpu", "service", "disk"):
        if kind in source:
            return kind
    return None


def line(ctx: dict[str, Any]) -> str:
    """The DNOC report's line, "" when it is not one this module reads."""
    kind = monitor(ctx)
    if kind is None:
        return ""
    text = ctx.get("description")
    f, procs = parse(text)
    if kind == "memory":
        out = _memory(f, procs)
    elif kind == "cpu":
        out = _cpu(f, procs)
    elif kind == "service":
        out = _service(text, f)
    else:
        out = _disk(f)
    return clean_line(out, 200)


def _key_text(value: Any) -> str:
    """A service name as a key part: cleaned, bounded, lower-case (Windows
    service names are case-insensitive), the signature's own separators
    ('|', ',') never inside it. Digits are KEPT — they are part of the
    service's identity (`bomgar-ps-<id>-<id>`, MSSQL$PROD1): masked, two
    different services would share one key and an Expected rule on one
    would hide the other."""
    text = clean_line(value, PART_MAX).lower()
    return " ".join(text.replace("|", " ").replace(",", " ").split())


_DRIVE_RE = re.compile(r"^([a-z]):?\\?$", re.IGNORECASE)


def signature_part(ctx: dict[str, Any]) -> Optional[str]:
    """What a DNOC report is ABOUT, for its alert's signature key:
    'services=<n>:<a>,<b>' (the sorted set of affected service names, <n> =
    how many the report says are affected) for a service report,
    'drive=<x>:' for a disk report, '' for memory / CPU (the monitor alone).
    None when it is not a DNOC report this module reads, or the report does
    not say (no service name, no drive) — the caller keeps its old key."""
    kind = monitor(ctx)
    if kind is None:
        return None
    if kind in ("memory", "cpu"):
        return ""
    text = ctx.get("description")
    # Every Datto alert of 30 days is keyed on a drawer read ("N repeats"):
    # the same report is parsed once (bounded memo, keyed by a digest).
    memo = (kind, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
            if isinstance(text, str) else "")
    with _PART_LOCK:
        if memo in _PART_MEMO:
            return _PART_MEMO[memo]
    part = _part(kind, text)
    with _PART_LOCK:
        if len(_PART_MEMO) >= PART_MEMO_MAX:
            _PART_MEMO.pop(next(iter(_PART_MEMO)))
        _PART_MEMO[memo] = part
    return part


def _part(kind: str, text: Any) -> Optional[str]:
    f, _procs = parse(text)
    if kind == "disk":
        drive = _DRIVE_RE.match((f.get("drive") or "").strip())
        return f"drive={drive.group(1).lower()}:" if drive else None
    facts = _services(text, f)
    ids = sorted({k for k in (_key_text(i) for i in facts.ids) if k})
    if not ids:
        return None
    count = max(facts.affected or 0, len(ids))
    if count > len(ids):
        return _partial(count, ids, text)
    part = f"services={count}:{','.join(ids)}"
    return compact(part) if len(part) > KEY_SERVICES_MAX else part


def _partial(count: int, ids: list[str], text: Any) -> str:
    """A report that says more services are affected (`count`) than it
    names (`ids`) — a layout this module does not fully read. Its names
    alone would key {A, B} and {A, C} alike (an Expected rule on one hiding
    the other), so the key is a digest of the names AND of the report's
    SHAPE (every line, lower-case, numbers masked like a message shape: a
    date, a downtime or a count never splits it; another service's line
    does): 'services=<n>:partial:sha256:<32 hex>'."""
    shape = "\n".join(re.sub(r"\d+", "#", ln.lower())
                      for ln in clean_lines(text, line_limit=400)[:400])
    digest = hashlib.sha256(f"{','.join(ids)}\n{shape}".encode("utf-8", "replace"))
    return f"services={count}:partial:sha256:{digest.hexdigest()[:32]}"


def compact(part: str) -> str:
    """A key part that does not fit, as a bounded digest of the WHOLE part
    ('services=3:sha256:<32 hex>') — never cut to a prefix: two different
    service sets would share it (a rule on one would cover the other)."""
    head, _, _rest = part.partition(":")
    return f"{head}:sha256:{hashlib.sha256(part.encode()).hexdigest()[:32]}"
