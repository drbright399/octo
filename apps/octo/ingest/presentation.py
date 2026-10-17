"""Operator-facing presentation of an event — vendor-neutral types + text hygiene.

An adapter MAY offer ``present_event(payload) -> EventPresentation | None`` (a
static/class method, so the API layer can call it on the adapter CLASS without
starting anything). It turns the vendor's own payload into:

  * ``event_type`` — a stable machine label per alert class ("datto.eventlog")
  * ``headline``   — one short human line (the feed row's title, and what the
                     adapter stores as ``events.summary``)
  * ``detail``     — a longer, bounded, multi-line excerpt (derived at read
                     time from the stored payload; there is no column for it)

ALL vendor text is untrusted. Everything that reaches an operator goes through
``clean_line`` / ``clean_block``: input is bounded BEFORE any work is done on
it, control and invisible formatting characters are removed, whitespace is
collapsed and the result is bounded again. Markup is left as the characters it
is — the console renders these strings as text nodes, never as HTML.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Optional

from shared_adapter_contract.types import CanonicalEvent

HEADLINE_MAX = 160
DETAIL_MAX = 1000
DETAIL_MAX_LINES = 12
LABEL_MAX = 96
EVENT_TYPE_MAX = 64

# Never look at more than this much of one vendor string. A 2 MB "description"
# costs the same as a 16 KB one.
_MAX_INPUT_CHARS = 16_384

_WS_RE = re.compile(r"\s+")
_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n|\u2028|\u2029|\x0b|\x0c|\x85")
_EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")


@dataclass(frozen=True)
class EventPresentation:
    event_type: str
    headline: str
    detail: str = ""
    device: Optional[str] = None
    site: Optional[str] = None
    fallback: bool = False
    """True when the presenter recognised NOTHING in the payload and the
    headline is its last-resort label ("Datto alert"). A reader that already
    holds better text for the row (a stored summary) should keep that rather
    than replace it with the label."""


@dataclass(frozen=True)
class TypedCanonicalEvent(CanonicalEvent):
    """A CanonicalEvent that also carries its own machine event type.

    The sink stores ``event_type`` from here when its caller did not declare
    one, so every writer (poller, webhook) types the row the same way without
    each call site having to know. "" = untyped (the sink's historical
    "alert")."""

    event_type: str = ""


def _strip_invisible(text: str) -> str:
    """Drop control (Cc), format (Cf: zero-width, bidi overrides), surrogate
    and private-use characters. Tabs/newlines must already be handled by the
    caller — here they would be removed like any other control."""
    return "".join(
        ch for ch in text
        if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn")
    )


def _ellipsize(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 1)].rstrip() + "…"


def clean_line(value: Any, limit: int = HEADLINE_MAX) -> str:
    """One bounded, single-line, printable string from an untrusted value.
    Non-strings (other than plain numbers) yield ""."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        value = _format_number(value)
    if not isinstance(value, str):
        return ""
    text = value[:_MAX_INPUT_CHARS]
    text = _WS_RE.sub(" ", _LINE_SPLIT_RE.sub(" ", text).replace("\t", " "))
    text = _WS_RE.sub(" ", _strip_invisible(text)).strip()
    return _ellipsize(text, limit)


def clean_lines(value: Any, *, line_limit: int = 240) -> list[str]:
    """The non-blank lines of an untrusted multi-line string, each cleaned."""
    if not isinstance(value, str):
        return []
    out: list[str] = []
    for raw in _LINE_SPLIT_RE.split(value[:_MAX_INPUT_CHARS]):
        line = clean_line(raw, line_limit)
        if line:
            out.append(line)
    return out


def clean_block(
    lines: list[str], *, max_chars: int = DETAIL_MAX, max_lines: int = DETAIL_MAX_LINES,
) -> str:
    """Join already-cleaned lines into a bounded block; says so when cut."""
    kept = [ln for ln in lines if ln][:max_lines]
    text = "\n".join(kept)
    if len(text) > max_chars:
        return _ellipsize(text, max_chars)
    if len([ln for ln in lines if ln]) > max_lines:
        return _ellipsize(text + "\n…", max_chars)
    return text


def clean_text(value: Any, limit: int) -> str:
    """An untrusted multi-line string as a bounded block: line breaks kept,
    every line cleaned (control / format characters gone), blank lines
    dropped, the whole cut at `limit`. For text that was NOT produced by a
    presenter — an adapter's own summary — so every source gets the same
    hygiene before an operator, a CSV or a model sees it."""
    if not isinstance(value, str) or limit <= 0:
        return ""
    text = "\n".join(clean_lines(value, line_limit=limit))
    return text if len(text) <= limit else _ellipsize(text, limit)


def _format_number(value: float | int) -> str:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return ""
        return f"{value:.1f}".rstrip("0").rstrip(".")
    return str(value)


def humanize_key(key: str) -> str:
    """'serviceName' / 'service_name' → 'service name' (bounded, cleaned)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", key[:128]).replace("_", " ")
    return clean_line(spaced, 48).lower()


def safe_event_type(candidate: str, fallback: str) -> str:
    """`candidate` when it is a well-formed dotted machine label, else
    `fallback`. Keeps free vendor text out of a column rules will match on."""
    if (
        isinstance(candidate, str)
        and len(candidate) <= EVENT_TYPE_MAX
        and _EVENT_TYPE_RE.fullmatch(candidate)
    ):
        return candidate
    return fallback


def slugify(value: str, limit: int = 40) -> str:
    """Lower-case [a-z0-9_] slug of vendor text ('Event Log' → 'event_log')."""
    slug = re.sub(r"[^a-z0-9]+", "_", clean_line(value, 96).lower()).strip("_")
    return slug[:limit].strip("_")
