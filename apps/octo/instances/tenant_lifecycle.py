"""Tenant lifecycle vocabulary + the pure helpers every lifecycle path shares.

A tenant (a `clients` row) now says where it came from (`origin`), what it is
(`kind`), whether a human has looked at it (`review_state`), which compliance
regimes apply (`compliance_flags`) and whether AI may touch its data
(`ai_policy`) — migration 033. The enums live HERE, in code, not as free
text: the console offers them, the API refuses anything else, and adding one
is a code change with a test.

Also here: how a vendor site NAME is normalised for the "obvious match" rule
and turned into a slug for auto-creation. Both are pure functions over
UNTRUSTED vendor text — bounded, printable, deterministic — so the ingest
path (`tenant_autocreate`) and the admin API agree on what "the same name"
means. The tenant manager's looser "possible duplicate" HINT builds on the
same normalisation (`duplicate_hints`) — a hint for a human, never a match.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Iterable

from apps.octo.client_provisioning import (  # noqa: F401 — one vocabulary
    AI_POLICIES,
    KINDS,
    MAX_DISPLAY_NAME,
    ORIGINS,
    REVIEW_STATES,
)

# Curated compliance tags. 'none' is an explicit statement ("we checked, no
# regime applies") and cannot be combined with another tag.
COMPLIANCE_TAGS: tuple[str, ...] = (
    "hipaa", "cjis", "pci", "bipa", "glba", "ferpa", "none",
)

# Trailing legal suffixes that do not distinguish one business from another
# for the purpose of an OBVIOUS name match ("Acme Corp" == "Acme, Inc.").
_LEGAL_SUFFIXES: frozenset[str] = frozenset({
    "inc", "incorporated", "llc", "llp", "ltd", "limited", "co", "corp",
    "corporation", "company", "plc", "pllc", "pc", "lp", "gmbh",
})

MAX_SLUG_CHARS = 48
_NON_SLUG_RE = re.compile(r"[^a-z0-9]+")


def parse_compliance_flags(raw: Any) -> list[str]:
    """`clients.compliance_flags` (JSON text) → the tags in it, unknown values
    dropped, sorted. Never raises on a corrupt column."""
    try:
        values = json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (TypeError, ValueError):
        return []
    if not isinstance(values, list):
        return []
    return sorted({v for v in values if isinstance(v, str) and v in COMPLIANCE_TAGS})


def validate_compliance_flags(values: Iterable[Any]) -> list[str]:
    """The operator-supplied list, or ValueError with a message that names
    the vocabulary (safe to return to the caller)."""
    out: list[str] = []
    for v in values:
        if not isinstance(v, str) or v not in COMPLIANCE_TAGS:
            raise ValueError(
                f"compliance_flags must be a list of: {', '.join(COMPLIANCE_TAGS)}"
            )
        if v not in out:
            out.append(v)
    if "none" in out and len(out) > 1:
        raise ValueError("compliance_flags 'none' cannot be combined with other tags")
    return sorted(out)


def compliance_flags_json(values: Iterable[str]) -> str:
    return json.dumps(sorted(set(values)), separators=(",", ":"))


def normalise_name(value: Any) -> str:
    """The comparison key for a business name: casefolded, accents stripped,
    punctuation gone, whitespace collapsed, trailing legal suffixes removed
    ("Acme Corp." / "ACME, Inc" / "acme" → "acme"). "" for anything that is
    not usable text. Bounded so vendor input cannot make this expensive.

    LOOSE on purpose — the tenant manager's duplicate HINT builds on it. It is
    never a routing or suggestion key: "Acme Pharmacy, Inc." and "Acme Pharmacy
    LLC" normalise alike here and are still two businesses (`exact_name_key`)."""
    words = _name_words(value)
    while len(words) > 1 and words[-1] in _LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def _name_words(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    text = unicodedata.normalize("NFKD", value[:MAX_DISPLAY_NAME * 2])
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = "".join(c if c.isprintable() else " " for c in text).casefold()
    text = text.replace("&", " and ")
    return [w for w in _NON_SLUG_RE.split(text) if w]


def exact_name_key(value: Any) -> str:
    """The key under which two business names are the SAME NAME — and even
    then only a SUGGESTION for a human (the same-name rule, 2026-10-01): a
    name never routes traffic by itself. Casefolded, accents stripped,
    punctuation gone, whitespace collapsed — but legal suffixes KEPT:
    "Acme Pharmacy, Inc." and "Acme Pharmacy Inc" are the same name, "Acme Pharmacy,
    Inc." and "Acme Pharmacy LLC" are not (two different businesses can share
    every other word). "" for anything that is not usable text."""
    return " ".join(_name_words(value))


# ---------------------------------------------------------------------------
# Duplicate HINTS (Settings → Tenants). A hint is a chip a human reads before
# choosing to merge — never an automatic merge, never a routing decision (the
# ingest path never routes on a name at all: `exact_name_key` only ever
# makes a suggestion).
# ---------------------------------------------------------------------------

# Professional-entity suffixes the hint also ignores, on top of the legal
# ones ("Smith & Jones, P.A."). Deliberately NOT here: "group", "partners",
# "associates" — they are part of real names ("Acme Group").
_HINT_EXTRA_SUFFIXES: frozenset[str] = frozenset({"pa", "psc"})
# A shorter name that is the leading part of a longer one only pairs when it
# has at least this many words: "Acme Group" ~ "Acme Group Accounting",
# but a lone "Globex" is too generic to pair with "Globex Dental".
DUPLICATE_MIN_PREFIX_WORDS = 2
# Bound per tenant: the chip is a hint, not a report.
DUPLICATE_HINTS_PER_TENANT = 5


def duplicate_hint_key(value: Any) -> tuple[str, ...]:
    """The words a duplicate hint compares: `normalise_name`, then a trailing
    run of single letters read as one dotted abbreviation ("P.L.L.C." →
    "pllc") and stripped like any legal suffix, and a leading "the" dropped.
    () for anything `normalise_name` cannot use."""
    words = normalise_name(value).split()
    start = len(words)
    while start > 0 and len(words[start - 1]) == 1:
        start -= 1
    if len(words) - start >= 2:
        words = words[:start] + ["".join(words[start:])]
    suffixes = _LEGAL_SUFFIXES | _HINT_EXTRA_SUFFIXES
    while len(words) > 1 and words[-1] in suffixes:
        words.pop()
    if len(words) > 1 and words[0] == "the":
        words = words[1:]
    return tuple(words)


def duplicate_rule(a: tuple[str, ...], b: tuple[str, ...]) -> str | None:
    """Why two hint keys look like the same business, or None:
      'same-name'   identical after normalisation ("Acme Corp" / "ACME, Inc.");
      'name-prefix' the shorter name (≥ DUPLICATE_MIN_PREFIX_WORDS words) is
                    the leading part of the longer ("Acme Group PLLC" /
                    "Acme Group Accounting").
    Two names that merely START alike ("Acme Group Tax" / "Acme Group
    Accounting", "Globex Dental" / "Globex Legal") are NOT paired."""
    if not a or not b:
        return None
    if a == b:
        return "same-name"
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    if len(short) >= DUPLICATE_MIN_PREFIX_WORDS and long_[: len(short)] == short:
        return "name-prefix"
    return None


def duplicate_hints(named: Iterable[tuple[str, str]]) -> dict[str, list[tuple[str, str]]]:
    """(slug, display name) pairs → {slug: [(other slug, rule), …]}, symmetric,
    sorted, bounded per tenant. Both rules need the same first word, so only
    names sharing one are compared."""
    by_first: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
    for slug, name in named:
        key = duplicate_hint_key(name)
        if key:
            by_first.setdefault(key[0], []).append((slug, key))
    out: dict[str, list[tuple[str, str]]] = {}
    for group in by_first.values():
        for i, (slug_a, key_a) in enumerate(group):
            for slug_b, key_b in group[i + 1:]:
                rule = duplicate_rule(key_a, key_b)
                if rule is None:
                    continue
                out.setdefault(slug_a, []).append((slug_b, rule))
                out.setdefault(slug_b, []).append((slug_a, rule))
    return {slug: sorted(hits)[:DUPLICATE_HINTS_PER_TENANT] for slug, hits in out.items()}


def clean_display_name(value: Any) -> str:
    """Vendor site name → a display name: one printable line, bounded."""
    if not isinstance(value, str):
        return ""
    text = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return text if len(text) <= MAX_DISPLAY_NAME else text[: MAX_DISPLAY_NAME - 1].rstrip() + "…"


def slug_from_name(value: Any, *, fallback: str = "site") -> str:
    """A candidate slug (no collision handling) from a vendor name: NFKD,
    accents stripped, casefolded, every non-alphanumeric run → one hyphen,
    bounded. Legal suffixes are KEPT here ("acme-inc" and "acme-corp" stay
    distinct slugs; only matching ignores them). Falls back to `fallback`
    when nothing usable remains (all punctuation, non-Latin script)."""
    if not isinstance(value, str):
        return fallback
    text = unicodedata.normalize("NFKD", value[:MAX_DISPLAY_NAME])
    text = "".join(c for c in text if not unicodedata.combining(c)).casefold()
    base = _NON_SLUG_RE.sub("-", text).strip("-")[:MAX_SLUG_CHARS].strip("-")
    return base if base and base.isascii() else fallback
