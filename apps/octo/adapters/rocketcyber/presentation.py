"""What a RocketCyber incident SAYS — headline, detail, severity, type.

The incident object (GET /v3/incidents, verified live 2026-09-29):

    {id, title, description, remediation, resolvedAt, publishedAt, createdAt,
     updatedAt, status: open|resolved|suppressed, accountId, accountName,
     eventCount, creatorName, psaId}

`title` is short (~65 chars); `description` (~2 KB) and `remediation`
(~1.8 KB) are markdown-ish SOC write-ups. There is NO severity field.

All of it is vendor text and untrusted (see `apps.octo.ingest.presentation`):
bounded before any work, markup reduced to its words, control / invisible
characters removed, every line and the whole block bounded again.
"""

from __future__ import annotations

import html
import re
from typing import Any, Optional

from shared_adapter_contract.types import Severity

from apps.octo.ingest.presentation import (
    DETAIL_MAX,
    DETAIL_MAX_LINES,
    HEADLINE_MAX,
    EventPresentation,
    clean_line,
    clean_lines,
)

# ONE machine label for every RocketCyber incident, whatever its status —
# like Datto, where an alert and its resolution share their class: the triage
# worker's recurrence signature joins on source + event_type + host, and an
# open incident and its later resolution are one kind of thing. The status is
# in the headline and the severity, not the type.
EVENT_TYPE = "rocketcyber.incident"

# EVERY headline (the stored `summary`) starts with this — the fallbacks
# included. The poller finds its own stored rows after a restart through the
# events table's summary index by this prefix (poller.py, `_stored_versions`).
HEADLINE_PREFIX = "RocketCyber"

# RocketCyber gives no severity, only a status. The mapping:
#   open       → high    a live incident a SOC analyst raised for a human to
#                        act on; high is what makes the triage worker escalate
#                        it. Not critical: that tier is reserved for vendors
#                        that SAY critical, and RocketCyber does not say.
#   resolved   → medium  the CLOSURE of an incident stored open. It must show
#   suppressed → medium  where the open row showed — the dashboard's default
#                        feed starts at medium — or a closed incident keeps
#                        looking live there. Medium is visible and never
#                        auto-escalated (the triage worker escalates high).
#   anything else → medium  a status this adapter does not know yet: visible
#                        on the dashboard, not escalated, until it is mapped.
_SEVERITY_BY_STATUS: dict[str, Severity] = {
    "open": "high",
    "suppressed": "medium",
    "resolved": "medium",
}
UNKNOWN_STATUS_SEVERITY: Severity = "medium"

_MAX_INPUT_CHARS = 16_384
_LINE_LIMIT = 240
_FACTS_MAX = 200
_REMEDIATION_MAX_LINES = 3
_REMEDIATION_MAX_CHARS = 300
_STATUS_MAX = 24


def incident_status(envelope: Any) -> str:
    """The lower-cased status, "" when absent or not text."""
    env = envelope if isinstance(envelope, dict) else {}
    value = env.get("status")
    return clean_line(value, _STATUS_MAX).lower() if isinstance(value, str) else ""


def severity_for_status(status: str) -> Severity:
    if not status:
        # An incident with no status at all is treated as the live case.
        return "high"
    return _SEVERITY_BY_STATUS.get(status, UNKNOWN_STATUS_SEVERITY)


def psa_ticket(envelope: Any) -> Optional[str]:
    """The PSA ticket RocketCyber attached (`psaId`: the ticket number its PSA
    integration created), cleaned and bounded — for a later link-back. None
    when absent."""
    env = envelope if isinstance(envelope, dict) else {}
    for key in ("psaId", "autotaskTicketId"):
        value = env.get(key)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, str)):
            text = clean_line(value, 64)
            if text:
                return text
    return None


# ---------------------------------------------------------------------------
# Markup → words
# ---------------------------------------------------------------------------

_BLOCK_TAG_RE = re.compile(r"(?i)<\s*(?:br\s*/?|/\s*(?:p|div|li|tr|h[1-6]|table|ul|ol))\s*>")
# Known HTML tag names only: "<user@example.test>" or "<WS-01>" in a SOC
# write-up is data, not markup, and must survive.
_TAG_RE = re.compile(
    r"(?i)</?(?:a|abbr|b|blockquote|br|code|div|em|font|h[1-6]|hr|i|img|li|ol|p|"
    r"pre|script|small|span|strong|style|sub|sup|table|tbody|td|th|thead|tr|u|ul)"
    r"(?:\s[^<>]{0,256})?\s*/?>"
)
_IMAGE_RE = re.compile(r"!\[([^\]\n]{0,200})\]\([^)\n]{0,2048}\)")
_LINK_RE = re.compile(r"\[([^\]\n]{0,200})\]\(([^)\n]{0,2048})\)")
_HEADING_RE = re.compile(r"^#{1,6}\s*")
_QUOTE_RE = re.compile(r"^(?:>\s*)+")
_BULLET_RE = re.compile(r"^(?:[-*+•]|\d{1,3}[.)])\s+")
_RULE_RE = re.compile(r"^[\s|:\-=*_+~#]*$")
_EMPHASIS_RE = re.compile(r"\*\*|~~|`")


def _link_text(match: re.Match) -> str:
    text = match.group(1).strip()
    # "[click here](https://…)" keeps its words; a bare "[](…)" keeps the target.
    return text or match.group(2).strip()


def _plain_lines(value: Any) -> list[str]:
    """The readable lines of a markdown-ish / HTML-ish vendor string: tags
    and markdown syntax reduced to the words they carry, table rows to
    'cell · cell', separators and blank lines dropped, each line cleaned and
    bounded. Never raises."""
    if not isinstance(value, str):
        return []
    text = value[:_MAX_INPUT_CHARS]
    text = _BLOCK_TAG_RE.sub("\n", text)
    text = _TAG_RE.sub("", text)
    text = html.unescape(text)
    out: list[str] = []
    for line in clean_lines(text, line_limit=_MAX_INPUT_CHARS):
        if _RULE_RE.fullmatch(line):
            continue
        line = _IMAGE_RE.sub(lambda m: m.group(1), line)
        line = _LINK_RE.sub(_link_text, line)
        line = _EMPHASIS_RE.sub("", line)
        line = _QUOTE_RE.sub("", line)
        line = _HEADING_RE.sub("", line)
        if line.startswith("|") or line.endswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            cells = [c for c in cells if c]
            line = f"{cells[0]}: {cells[1]}" if len(cells) == 2 else " · ".join(cells)
        if _BULLET_RE.match(line):
            line = "• " + _BULLET_RE.sub("", line, count=1)
        line = clean_line(line, _LINE_LIMIT)
        if line and any(ch.isalnum() for ch in line):
            out.append(line)
    return out


def _fit(lines: list[str], *, max_lines: int, max_chars: int) -> list[str]:
    """The leading lines that fit both budgets; a visible '…' line (inside
    the budget) when anything was left out."""
    if max_lines <= 0 or max_chars <= 0:
        return []
    kept: list[str] = []
    used = 0
    for line in lines:
        cost = len(line) + (1 if kept else 0)
        if len(kept) >= max_lines or used + cost > max_chars:
            break
        kept.append(line)
        used += cost
    else:
        return kept
    # Something was cut: make room for the marker.
    while kept and (len(kept) + 1 > max_lines or used + 2 > max_chars):
        used -= len(kept.pop()) + (1 if kept else 0)
    if not kept and lines and max_lines >= 2:
        first = clean_line(lines[0], max(1, min(_LINE_LIMIT, max_chars - 2)))
        kept, used = [first], len(first)
    return kept + ["…"]


def _facts_line(env: dict[str, Any], status: str) -> str:
    bits: list[str] = []
    customer = clean_line(env.get("accountName"), 96)
    if customer:
        bits.append(f"Customer: {customer}")
    count = env.get("eventCount")
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        bits.append(f"{count} event{'s' if count != 1 else ''}")
    ticket = psa_ticket(env)
    if ticket:
        bits.append(f"PSA ticket {ticket}")
    if status and status != "open":
        bits.append(f"Status: {status}")
    resolved = clean_line(env.get("resolvedAt"), 32)
    if resolved and status == "resolved":
        bits.append(f"Resolved {resolved}")
    return clean_line(" · ".join(bits), _FACTS_MAX)


def _headline(env: dict[str, Any], status: str) -> tuple[str, bool]:
    title_lines = _plain_lines(env.get("title"))
    title = " ".join(title_lines)
    if status in ("", "open"):
        suffix = ""
    else:
        suffix = f" — {status}"
    if title:
        body = clean_line(f"RocketCyber · {title}", HEADLINE_MAX - len(suffix))
        return body + suffix, False
    iid = env.get("id")
    label = (
        f"RocketCyber incident {iid}"
        if isinstance(iid, int) and not isinstance(iid, bool) else "RocketCyber incident"
    )
    return clean_line(label, HEADLINE_MAX - len(suffix)) + suffix, True


def present_incident(envelope: Any) -> EventPresentation:
    """Headline + detail for one RocketCyber incident. Never raises, never
    returns a blank headline.

    headline  'RocketCyber · <title>' — with ' — resolved' / ' — suppressed'
              (or the unknown status) appended, always kept whole
    detail    the description's first readable lines, then 'Remediation: …'
              (a few lines), then one facts line (customer · events · PSA
              ticket · status · resolved at), within DETAIL_MAX /
              DETAIL_MAX_LINES — the facts line always survives the cut
    site      the customer name
    """
    env = envelope if isinstance(envelope, dict) else {}
    try:
        status = incident_status(env)
        headline, fallback = _headline(env, status)
        facts = _facts_line(env, status)
        description = _plain_lines(env.get("description"))
        title_line = " ".join(_plain_lines(env.get("title"))).lower()
        if description and title_line and description[0].lower() == title_line:
            description = description[1:]
        remediation = _plain_lines(env.get("remediation"))
        if remediation:
            remediation[0] = clean_line(f"Remediation: {remediation[0]}", _LINE_LIMIT)

        facts_lines = [facts] if facts else []
        facts_chars = len(facts) + 1 if facts else 0
        rem = _fit(
            remediation,
            max_lines=_REMEDIATION_MAX_LINES,
            max_chars=_REMEDIATION_MAX_CHARS,
        )
        rem_chars = sum(len(x) + 1 for x in rem)
        desc = _fit(
            description,
            max_lines=DETAIL_MAX_LINES - len(rem) - len(facts_lines),
            max_chars=DETAIL_MAX - rem_chars - facts_chars,
        )
        detail = "\n".join(desc + rem + facts_lines)
        site = clean_line(env.get("accountName"), 128) or None
    except Exception:  # noqa: BLE001 — presentation must never break ingest or a feed
        return EventPresentation(
            event_type=EVENT_TYPE, headline="RocketCyber incident", fallback=True,
        )
    return EventPresentation(
        event_type=EVENT_TYPE,
        headline=headline or "RocketCyber incident",
        detail=detail[:DETAIL_MAX],
        device=None,        # incidents name no host field
        site=site,
        fallback=fallback,
    )
