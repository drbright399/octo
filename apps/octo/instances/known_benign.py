"""Known-benign rules — a small operator-editable list (registry
`known_benign_rules`, migration 040) that DOWNGRADES specific blocked
domains for specific reasons. It never allowlists: the vendor keeps blocking;
Athena only files the alert at the rule's level (LOW), labelled "known
benign", with the rule's note.

Seeded with the Samsung connectivity probe: "www.g" + three or more "o" +
"gle.com" ("www\\.go{3,}gle\\.com") under NextDNS threat-intelligence-feeds
(on that feed since 2026-09-24) → LOW (Rick, 2026-10-01: downgrade it in
Athena, keep it blocked, never allowlist it).

A rule matches a blocked line when its domain matches (`exact`: equal;
`suffix`: equal or a subdomain; `regex`: the whole name, a RESTRICTED regex)
AND every signal-class reason of the line is one of the rule's reasons — a
probe that is ALSO on another feed is not downgraded.

Restricted regex (operator-entered, so it must be cheap and predictable):
lower-case letters, digits, '-', '.' (ALWAYS a literal dot, escaped or not),
character classes [..], quantifiers ? * + {n} {n,} {n,m} on a single
character or class — at most 4 quantifiers, at most 2 of them WIDE (* + {n,}
or {n,m} with m > n + 1: a bounded range is as costly to backtrack as an
unbounded one) — at most 200 characters; no wildcard, groups, alternation,
anchors, backreferences or lookarounds (the whole name must match). With at
most two wide quantifiers (the others ? / {n} / {n,n+1}: at most 2 ways
each) matching stays at most quadratic in a 253-character name: no
catastrophic backtracking from an admin's typo. (Before, four bounded
'{0,999}' ranges were accepted: 0.16 s per line per rule.)
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from apps.octo import paths
from apps.octo.db import connect

CACHE_SEC = 60.0
MATCH_KINDS = ("exact", "suffix", "regex")
LEVELS = ("low", "medium")
MAX_QUANTIFIERS = 4
MAX_UNBOUNDED = 2

_TOKEN_RE = re.compile(
    r"\\\.|\[[a-z0-9\-\.]+\]|[a-z0-9\-]|\.|"            # an atom
    r"\{\d{1,3}(,\d{0,3})?\}|[?*+]")                      # a quantifier


def _wide(tok: str) -> bool:
    """A quantifier with more than two ways to match (* + {n,} {n,m>n+1}) —
    each one multiplies the backtracking; ? {n} {n,n+1} at most double it."""
    if tok in "*+":
        return True
    if not tok.startswith("{") or "," not in tok:
        return False
    lo, _, hi = tok[1:-1].partition(",")
    if not hi:
        return True
    return int(hi) - int(lo or 0) > 1


class RuleError(ValueError):
    """An invalid known-benign rule (operator-safe text)."""


def validate_pattern(kind: str, pattern: str) -> str:
    if kind not in MATCH_KINDS:
        raise RuleError(f"match must be one of {', '.join(MATCH_KINDS)}")
    text = (pattern or "").strip().lower()
    if not text or len(text) > 200:
        raise RuleError("the pattern must be 1-200 characters")
    if kind in ("exact", "suffix"):
        if not re.fullmatch(r"[a-z0-9\-\.]+", text) or ".." in text or text.startswith("."):
            raise RuleError("an exact / suffix rule is a plain domain name (letters, digits, "
                            "'-' and '.')")
        return text.rstrip(".")
    pos = 0
    quantifiers = 0
    unbounded = 0
    prev_atom = False
    out: list[str] = []
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if m is None:
            raise RuleError(f"unsupported regex syntax at position {pos + 1} — only letters, "
                            "digits, '-', '\\.', [classes] and ? * + {n,m} are allowed")
        tok = m.group(0)
        is_quant = tok in "?*+" or tok.startswith("{")
        if is_quant:
            if not prev_atom:
                raise RuleError("a quantifier must follow a character or a [class]")
            quantifiers += 1
            if _wide(tok):
                unbounded += 1
            prev_atom = False
        else:
            prev_atom = True
        out.append("\\." if tok == "." else tok)
        pos = m.end()
    if quantifiers > MAX_QUANTIFIERS or unbounded > MAX_UNBOUNDED:
        raise RuleError(f"at most {MAX_QUANTIFIERS} quantifiers, {MAX_UNBOUNDED} of them "
                        "wide (* + {n,} or {n,m} with m > n + 1)")
    canonical = "".join(out)
    try:
        re.compile(canonical)
    except re.error as exc:
        raise RuleError(f"not a valid pattern: {exc}") from None
    return canonical


@dataclass(frozen=True)
class Rule:
    id: int
    vendor: str
    match_kind: str
    pattern: str
    reasons: tuple[str, ...]
    level: str
    label: str
    note: str
    enabled: bool
    _compiled: Optional[re.Pattern] = None

    def matches_domain(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        if self.match_kind == "exact":
            return d == self.pattern
        if self.match_kind == "suffix":
            return d == self.pattern or d.endswith("." + self.pattern)
        return bool(self._compiled is not None and self._compiled.fullmatch(d))

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "vendor": self.vendor, "match_kind": self.match_kind,
                "pattern": self.pattern, "reasons": list(self.reasons), "level": self.level,
                "label": self.label, "note": self.note, "enabled": self.enabled}


def _row_rule(r: sqlite3.Row) -> Optional[Rule]:
    try:
        reasons = json.loads(r["reasons"] or "[]")
        pattern = validate_pattern(r["match_kind"], r["pattern"])
    except (ValueError, RuleError):
        return None
    compiled = re.compile(pattern) if r["match_kind"] == "regex" else None
    return Rule(int(r["id"]), r["vendor"], r["match_kind"], pattern,
                tuple(sorted(str(x).strip().lower() for x in reasons if isinstance(x, str))),
                r["level"], r["label"], r["note"] or "", bool(r["enabled"]), compiled)


_lock = threading.Lock()
_cache: dict[str, tuple[float, list[Rule]]] = {}


def load(*, fresh: bool = False) -> list[Rule]:
    """Every rule (enabled or not). [] when the registry predates 040 or
    cannot be read (nothing is downgraded — fail safe: an alert keeps its
    level). Cached a minute per registry."""
    now = time.monotonic()
    key = str(paths.registry_db_path())
    with _lock:
        hit = _cache.get(key)
        if not fresh and hit is not None and now - hit[0] < CACHE_SEC:
            return list(hit[1])
    try:
        reg = connect(paths.registry_db_path(), read_only=True)
    except (sqlite3.Error, FileNotFoundError):
        return []
    try:
        rows = reg.execute("SELECT * FROM known_benign_rules ORDER BY id").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        reg.close()
    rules = [r for r in (_row_rule(x) for x in rows) if r is not None]
    with _lock:
        _cache[key] = (now, rules)
    return list(rules)


def reset() -> None:
    with _lock:
        _cache.clear()


def match(vendor: str, domain: Optional[str], signal_reasons: Iterable[str]) -> Optional[Rule]:
    """The first enabled rule that covers this blocked line, or None."""
    if not domain:
        return None
    reasons = {str(r).strip().lower() for r in signal_reasons if r}
    if not reasons:
        return None
    for rule in load():
        if not rule.enabled or rule.vendor != vendor:
            continue
        if rule.reasons and not reasons <= set(rule.reasons):
            continue
        if rule.matches_domain(domain):
            return rule
    return None
