"""NextDNS alerts as an operator reads them.

Four event types, all SIGNALS (events.db):

  nextdns.security_block       a blocked lookup with a signal-class reason —
                               the FIRST of its bucket: HIGH per (profile,
                               device, root domain, reason) per clock hour;
                               DGA per (profile, device, reason) per hour;
                               MEDIUM / LOW per (profile, device, reason) per
                               UTC day, any domain. Later hits are counted on
                               it, not raised again
  nextdns.protection_lapsed    an active profile stopped reporting queries
                               (during a fleet-wide outage it says so: it is
                               grouped under the fleet signal)
  nextdns.protection_restored  …and started again
  nextdns.fleet_dns_outage     at least half the watched sites stopped
                               reporting at once — ONE signal, HIGH, in the
                               operator's own (internal) tenant
  nextdns.device_silent        the NextDNS app stopped reporting from a
                               computer Datto RMM shows online (entity
                               resolution's device check), MEDIUM
  nextdns.device_restored      …and it reports again, LOW

A security block a KNOWN-BENIGN rule matched (`signal.known_benign`) keeps
its alert but at the rule's level (LOW), and says so: "known benign — still
blocked".

Title: "NextDNS blocked <reason label> — <device name or client IP>".

The blocked DOMAIN is the IOC. It is masked here exactly like the dashboard's
threat-intel pulse (`api.indicator_mask`, owner decision 2026-09-28 (a)):
the headline never carries it, the detail shows only the masked form, and
the full name is read through the step-up-gated search (the stored payload).
The headline is also what the adapter stores as `events.summary`, so the
alerts feed and ticket summaries never quote the domain either.
"""
from __future__ import annotations

from typing import Any, Optional

from apps.octo.adapters.nextdns.classification import classify_line, classify_reason
from apps.octo.api.indicator_mask import mask_indicator
from apps.octo.ingest.presentation import EventPresentation, clean_block, clean_line

EVENT_BLOCK = "nextdns.security_block"
EVENT_LAPSED = "nextdns.protection_lapsed"
EVENT_RESTORED = "nextdns.protection_restored"
EVENT_FLEET = "nextdns.fleet_dns_outage"
EVENT_DEVICE_SILENT = "nextdns.device_silent"
EVENT_DEVICE_RESTORED = "nextdns.device_restored"
EVENT_TYPES = (EVENT_BLOCK, EVENT_LAPSED, EVENT_RESTORED, EVENT_FLEET, EVENT_DEVICE_SILENT,
               EVENT_DEVICE_RESTORED)

KIND_TO_EVENT = {
    "security_block": EVENT_BLOCK,
    "protection_lapsed": EVENT_LAPSED,
    "protection_restored": EVENT_RESTORED,
    "fleet_dns_outage": EVENT_FLEET,
    "device_silent": EVENT_DEVICE_SILENT,
    "device_restored": EVENT_DEVICE_RESTORED,
}

HEADLINE_PREFIX = "NextDNS "
LAPSED_ACTION = "DNS filtering stopped reporting — check the site's UniFi DNS/NextDNS setup"
# Why a profile lapsed (payload `cause`) → the first line of the detail.
LAPSE_CAUSE_TEXT = {
    "not_visible": (
        "NextDNS no longer shows this profile to Athena's API key (HTTP 404) — it was "
        "deleted, or is no longer shared with the account. The site's DNS filtering can "
        "no longer be watched: check the profile at my.nextdns.io and the site's UniFi "
        "DNS/NextDNS setup"
    ),
    "not_accessible": (
        "NextDNS refuses this profile to Athena's API key (HTTP 403) and no longer lists "
        "it for the key — it may no longer be shared with the account. The site's DNS "
        "filtering can no longer be watched: check the profile's sharing at my.nextdns.io"
    ),
    "logs_off": (
        "Logging was turned off for this profile at NextDNS, so its queries are no longer "
        "reported — turn logging back on at my.nextdns.io (Settings → Logs) if that was "
        "not intended"
    ),
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def event_type_of(payload: Any) -> str:
    return KIND_TO_EVENT.get(str(_mapping(payload).get("kind") or ""), EVENT_BLOCK)


def device_label(log: Any) -> str:
    """The device's NextDNS name, else the client IP, else a neutral word."""
    line = _mapping(log)
    device = _mapping(line.get("device"))
    name = clean_line(device.get("name"), 64)
    if name:
        return name
    ip = clean_line(line.get("clientIp"), 64)
    return ip or "an unidentified device"


def profile_label(payload: Any) -> str:
    p = _mapping(payload)
    name = clean_line(p.get("profile_name"), 80)
    pid = clean_line(p.get("profile_id"), 32)
    if name and pid:
        return f"{name} ({pid})"
    return name or pid or "a NextDNS profile"


def _hour_text(value: Any) -> str:
    text = clean_line(value, 32)
    return f"{text[:10]} {text[11:16]} UTC" if len(text) >= 16 else (text or "an unknown time")


def _reason_label(payload: dict[str, Any]) -> tuple[str, str, str]:
    """(label, reason id, level) — from the stored signal block, else the log."""
    signal = _mapping(payload.get("signal"))
    label = clean_line(signal.get("reason_label"), 80)
    rid = clean_line(signal.get("reason_id"), 64)
    level = clean_line(signal.get("level"), 16)
    if label and rid:
        return label, rid, level
    line = classify_line(_mapping(payload.get("log")).get("reasons"))
    if line.primary is not None:
        return line.primary.label, line.primary.id, line.level or ""
    return "a security threat", rid or "unknown", level or "low"


def present_block(payload: dict[str, Any]) -> EventPresentation:
    log = _mapping(payload.get("log"))
    who = device_label(log)
    label, rid, level = _reason_label(payload)
    benign = _mapping(_mapping(payload.get("signal")).get("known_benign"))
    if benign:
        headline = clean_line(f"NextDNS blocked a known-benign lookup "
                              f"({clean_line(benign.get('label'), 80)}) — {who}")
    else:
        headline = clean_line(f"NextDNS blocked {label} — {who}")
    domain = clean_line(log.get("domain"), 253)
    masked = mask_indicator(domain, "domain") if domain else "—"
    device = _mapping(log.get("device"))
    model = clean_line(device.get("model"), 64)
    ip = clean_line(log.get("clientIp"), 64)
    names = [clean_line(r.get("name") or r.get("id"), 64)
             for r in (log.get("reasons") if isinstance(log.get("reasons"), list) else [])
             if isinstance(r, dict)]
    vendor_reason = clean_line(classify_reason(rid).id or rid, 64)
    signal = _mapping(payload.get("signal"))
    span = "day" if signal.get("bucket_span") == "day" else "hour"
    repeats = (
        f"Repeat hits of this device and reason (any domain) in the same {span} are "
        "counted on this alert, not raised again."
        if signal.get("cross_domain") is True else
        f"Repeat hits of this device, domain and reason in the same {span} are counted "
        "on this alert, not raised again."
    )
    lines = [
        f"Blocked by NextDNS before any connection: {masked} "
        "(masked — the full name is in the step-up search).",
        *([f"Known benign: {clean_line(benign.get('label'), 80)} (Athena rule "
           f"#{benign.get('rule_id')}) — downgraded to {level or 'low'}, STILL BLOCKED by "
           f"NextDNS. {clean_line(benign.get('note'), 200)}"] if benign else []),
        f"Reason: {label} (NextDNS: {vendor_reason}) — {level or 'low'} signal."
        + (f" All reasons: {', '.join(n for n in names if n)}." if len(names) > 1 else ""),
        "Device: " + " · ".join(part for part in (
            clean_line(device.get("name"), 64), model, ip) if part) if (device or ip)
        else "Device: not identified by NextDNS.",
        f"NextDNS profile: {profile_label(payload)}.",
        repeats,
    ]
    return EventPresentation(
        event_type=EVENT_BLOCK,
        headline=headline,
        detail=clean_block([clean_line(x, 240) for x in lines]),
        device=who if who != "an unidentified device" else None,
        site=clean_line(payload.get("profile_name"), 80) or None,
    )


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def fleet_line(fleet: Any) -> str:
    """The grouping line of a site's lapse during a fleet-wide outage ("" when
    it is not part of one)."""
    f = _mapping(fleet)
    sites, watched = _count(f.get("sites")), _count(f.get("watched"))
    if not sites or not watched:
        return ""
    return (f"Part of a fleet-wide outage: {sites} of {watched} sites stopped reporting to "
            f"NextDNS at the same time (since {_hour_text(f.get('since'))}) — likely one "
            "shared cause, tracked as ONE incident: check NextDNS status and the UniFi DNS "
            "template first.")


def present_lapsed(payload: dict[str, Any]) -> EventPresentation:
    who = profile_label(payload)
    cause = payload.get("cause")
    hours = payload.get("zero_hours")
    hours = hours if isinstance(hours, int) and not isinstance(hours, bool) and hours > 0 else 2
    week = payload.get("queries_7d")
    if cause == "before_watch":
        week = week if isinstance(week, int) and not isinstance(week, bool) else 0
        lines = [
            f"{LAPSED_ACTION}.",
            f"No queries reached NextDNS in the last 24 hours, but {week} did in the "
            "last 7 days: the site stopped reporting before Athena started watching it.",
            "Athena raises this once and says so again when queries resume.",
        ]
    elif isinstance(cause, str) and cause in LAPSE_CAUSE_TEXT:
        lines = [
            f"{LAPSE_CAUSE_TEXT[cause]}.",
            "Athena raises this once and says so again when queries resume.",
        ]
    else:
        lines = [
            f"{LAPSED_ACTION}.",
            f"No queries reached NextDNS for {hours} consecutive hours (since "
            f"{_hour_text(payload.get('since'))}); the profile had been active.",
            "Athena raises this once and says so again when queries resume.",
        ]
    grouped = fleet_line(payload.get("fleet"))
    if grouped:
        lines.insert(1, grouped)
    return EventPresentation(
        event_type=EVENT_LAPSED,
        headline=clean_line(f"NextDNS stopped reporting — {who}"),
        detail=clean_block([clean_line(x, 320) for x in lines]),
        site=clean_line(payload.get("profile_name"), 80) or None,
    )


def present_restored(payload: dict[str, Any]) -> EventPresentation:
    who = profile_label(payload)
    queries = payload.get("queries")
    queries = queries if isinstance(queries, int) and not isinstance(queries, bool) else 0
    lapse = payload.get("lapse_event_id")
    lapse_text = (
        f"the lapse recorded as event #{lapse}"
        if isinstance(lapse, int) and not isinstance(lapse, bool) else "the recorded lapse"
    )
    since = payload.get("lapsed_since")
    lines = [
        f"DNS filtering resumed: {queries} queries in the hour from "
        f"{_hour_text(payload.get('restored_hour'))}, after {lapse_text}"
        + (f" (no queries since {_hour_text(since)})." if since else "."),
    ]
    return EventPresentation(
        event_type=EVENT_RESTORED,
        headline=clean_line(f"NextDNS reporting again — {who}"),
        detail=clean_block([clean_line(x, 240) for x in lines]),
        site=clean_line(payload.get("profile_name"), 80) or None,
    )


FLEET_ACTION = "check NextDNS status and the UniFi DNS template"


def present_fleet(payload: dict[str, Any]) -> EventPresentation:
    sites, watched = _count(payload.get("sites")), _count(payload.get("watched"))
    names = []
    for item in payload.get("profiles") if isinstance(payload.get("profiles"), list) else []:
        entry = _mapping(item)
        name = clean_line(entry.get("profile_name"), 60) or clean_line(entry.get("profile_id"), 32)
        if name:
            names.append(name)
    more = sites - len(names)
    lines = [
        f"{sites} of {watched} watched sites stopped reporting to NextDNS at the same time "
        f"(since {_hour_text(payload.get('since'))}) — one shared cause is likely: NextDNS "
        "itself (check its status page) or a DNS change pushed to many sites (the UniFi DNS "
        "template / gateway DNS settings).",
        "Sites: " + ", ".join(names) + (f" (+{more} more)." if more > 0 else "."),
        "Each site's own lapse is recorded in its client's tenant and grouped under this "
        "incident (not escalated one by one). Athena notes here when they report again.",
    ] if names else [
        f"{sites} of {watched} watched sites stopped reporting to NextDNS at the same time.",
    ]
    return EventPresentation(
        event_type=EVENT_FLEET,
        headline=clean_line(f"{sites} sites stopped reporting to NextDNS — {FLEET_ACTION}"),
        detail=clean_block([clean_line(x, 400) for x in lines]),
    )


def present_device(payload: dict[str, Any], restored: bool) -> EventPresentation:
    device = _mapping(payload.get("device"))
    datto = _mapping(payload.get("datto"))
    who = (clean_line(datto.get("hostname"), 64) or clean_line(device.get("name"), 64)
           or "a computer")
    hours = payload.get("silent_hours")
    hours = hours if isinstance(hours, int) and not isinstance(hours, bool) and hours > 0 else 0
    if restored:
        headline = clean_line(f"NextDNS reporting again from {who}")
        lines = [
            f"The NextDNS app on {who} reports queries again (the hour from "
            f"{_hour_text(payload.get('restored_hour'))}), after "
            + (f"event #{payload['silent_event_id']}"
               if isinstance(payload.get("silent_event_id"), int) else "the recorded silence")
            + f" (silent since {_hour_text(payload.get('silent_since'))}).",
        ]
    else:
        headline = clean_line(f"NextDNS stopped reporting from {who} — Datto shows it online")
        last = payload.get("last_report")
        if isinstance(last, str) and last:
            last_text = (f"last reported on {clean_line(last[:10], 10)}"
                         if payload.get("last_report_precision") == "day"
                         else f"last reported in the hour from {_hour_text(last)}")
        else:
            last_text = "no report from it seen since Athena started watching"
        lines = [
            f"The NextDNS app on {who} — {last_text}; verified silent while online for "
            f"{hours} hours since {_hour_text(payload.get('silent_since'))} — while Datto RMM "
            "shows the computer online. Its DNS is probably no longer filtered: check the "
            "NextDNS app / service on the computer (it can stop silently).",
            "Datto: " + " · ".join(x for x in (
                clean_line(datto.get("hostname"), 64), clean_line(datto.get("os"), 64),
                ("online since " + _hour_text(datto.get("online_since")))
                if datto.get("online_since") else "") if x),
            "NextDNS device: " + " · ".join(x for x in (
                clean_line(device.get("name"), 64), clean_line(device.get("model"), 64)) if x),
            f"NextDNS profile: {profile_label(payload)}.",
        ]
        if payload.get("profile_silent_too") is True:
            lines.append("The whole profile is silent too — see its own 'stopped reporting' "
                         "alert; this computer is one of the devices behind it.")
    return EventPresentation(
        event_type=EVENT_DEVICE_RESTORED if restored else EVENT_DEVICE_SILENT,
        headline=headline,
        detail=clean_block([clean_line(x, 320) for x in lines if x]),
        device=who if who != "a computer" else None,
        site=clean_line(payload.get("profile_name"), 80) or None,
    )


def present(payload: Any) -> EventPresentation:
    p = _mapping(payload)
    kind = event_type_of(p)
    if kind in (EVENT_DEVICE_SILENT, EVENT_DEVICE_RESTORED):
        return present_device(p, restored=kind == EVENT_DEVICE_RESTORED)
    if kind == EVENT_FLEET:
        return present_fleet(p)
    if kind == EVENT_LAPSED:
        return present_lapsed(p)
    if kind == EVENT_RESTORED:
        return present_restored(p)
    if not p.get("log"):
        return EventPresentation(EVENT_BLOCK, "NextDNS alert", fallback=True)
    return present_block(p)


def indicator_of(payload: Any) -> Optional[str]:
    """The IOC of a security block: the blocked domain (lower case)."""
    p = _mapping(payload)
    if event_type_of(p) != EVENT_BLOCK:
        return None
    domain = _mapping(p.get("log")).get("domain")
    if not isinstance(domain, str):
        return None
    text = domain.strip().rstrip(".").lower()
    if not text or len(text) > 253 or any(c.isspace() or not c.isprintable() for c in text):
        return None
    return text
