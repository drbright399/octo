"""Secret-shaped detectors: ONE set shared by the repo scanner and runtime redaction.

Users:

* ``scripts/scan_sensitive.py``: the git hooks (``--staged`` / ``--range``),
  ``--tree``, and the public-export gate (``--publish``).
* ``apps.octo.adapters.datto.job_output``: quick-job output is redacted before
  it is stored or handed on (field note #14: a service command line carried an
  agent's ``--license_key`` into job output).

Stdlib only. The scanner runs from a git hook in any clone with a bare
``python3``, so nothing here may import a third-party package or the rest of
``apps.octo``.

The two purposes share the detectors but not the thresholds:

* ``scan``: find secrets in files. A value has to look real (not a
  placeholder, not an identifier, enough character variety) before it counts,
  so the hook only blocks when it should.
* ``redact``: scrub text that is about to be stored. Any value in a
  secret-shaped slot is replaced, real-looking or not. Generic high-entropy
  strings are scan-only: in job output they are file hashes and encoded
  command lines, which are triage evidence.

Publish-only detectors (LAN / tailnet / public IPs, home and mount paths,
memory-slug links, paths into an agent memory store and home-directory
project slugs (``memory-path``, guardrails v9), tailnet names, e-mail
addresses, NextDNS profile ids, opaque tokens in URL paths, PSA ticket
numbers) are not secrets, or cannot be told apart from an id. They run only
with ``scan_sensitive.py --publish``:
the public-export gate and, since 2026-10-15 (Rick: the private repo meets
the public standard too), every git hook. Two narrow exemptions keep
third-party metadata out of the way: an e-mail address in a dependency
lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock,
Cargo.lock: package authors in license metadata) is not reported; a secret in
a lockfile still is. The one ticket-number fixture, ``T20000101.0001``, is
never reported.

Passwords on command lines (``cli-password``, guardrails v5): ``sshpass -p``,
``curl -u user:<pw>``, ``mysql -p<pw>``, ``net use ... /user:<u> <pw>``,
``smbclient -U user%<pw>``, ``PGPASSWORD=``, ``rdesktop -p`` / ``xfreerdp
/p:`` / ``-p:``, ``ldapsearch -w``, ``cmdkey /pass:``, ``psexec -p``; since
guardrails v6 also ``ConvertTo-SecureString '<pw>' -AsPlainText``,
``plink`` / ``pscp`` / ``psftp -pw``, ``sqlcmd`` / ``bcp`` / ``ipmitool`` /
``zip`` / ``unzip -P``, ``winrs -p:``, ``docker login -p``, ``7z -p<pw>``,
``redis-cli -a`` and ``REDISCLI_AUTH=``. The option is found first; the
program is then looked up on the same command line (no backtracking over the
line), so ``mkdir -p`` or ``grep -w`` never count. A value the shell expands
(``$(...)``, a bare ``(...)``, ``${...}``, ``$script:Name``, cmd's ``!NAME!``)
is no finding; redaction scrubs it all the same. Every option list in a
program check matches one way and is bounded (a ReDoS in v6's docker login). Each option shape is a
detector of its own (all report ``cli-password``): a candidate one family
rejects (``-p:<pw>`` is no ``mysql -p<pw>`` without mysql) never hides what
another family finds at the same place (``xfreerdp -p:<pw>``).

Shapes added after the 2026-10-15 secret sweep: ``whsec_`` webhook signing
secrets, 32-byte keys written as 44-character base64 (Fernet, WireGuard,
``*_KEY_BASE64=``) with or without a key-like name, IT Glue ``ITG.`` keys,
Telegram bot tokens, Cloudflare tunnel tokens (one ``eyJ`` segment holding
``a`` / ``t`` / ``s``), Wi-Fi / UniFi names (``psk``, ``wpa_psk``,
``x_passphrase``, ``x_iapp_key``, ``x_ipsec_pre_shared_key``), labels in prose
(``Signing key: <v>``), and ``sig=`` after a JSON-escaped ``\\u0026`` or an
HTML ``&amp;``.
"""
from __future__ import annotations

import base64
import binascii
import bisect
import ipaddress
import json
import math
import re
import sys
import threading
from collections import Counter
from dataclasses import dataclass
from typing import AbstractSet, Callable, Literal, Optional, Tuple, Union

Purpose = Literal["scan", "redact"]

#: Inline allow marker. It must carry a reason. Assembled from two parts so
#: this file never contains a bare marker of its own.
ALLOW_MARKER = "scan-sensitive" + ": allow"


@dataclass(frozen=True)
class Context:
    """Where the text came from. ``path`` is repo-relative, or empty for text
    that is not a file (job output)."""

    path: str = ""
    generated: bool = False  # lockfiles, minified bundles, source maps


@dataclass(frozen=True)
class Hit:
    detector: str
    start: int  # span of the sensitive value
    end: int
    value: str
    secret: bool = True  # False for publish-only (not secret, just not public)


#: A check returns False to drop the candidate, True to keep it, or a string
#: to keep it under that detector name (one regex, several verdicts).
Check = Callable[[str, "re.Match[str]", Purpose, Context], Union[bool, str]]


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: "re.Pattern[str]"
    #: The group holding the sensitive value; "value" = assignment value; a
    #: tuple = the first of those named groups that took part in the match.
    group: Union[int, str, tuple[str, ...]] = 0
    check: Optional[Check] = None
    scan: bool = True
    redact: bool = True
    publish_only: bool = False
    redact_pattern: Optional["re.Pattern[str]"] = None
    #: Lower-case text every match contains (any one of them): a text holding
    #: none of them is skipped without running the pattern.
    needles: tuple[str, ...] = ()
    #: Every name its hits carry, the first by default (empty = ``name``): a
    #: check's string verdict picks another. Several detectors may report
    #: under one name (the ``cli-password`` families); ``name`` stays unique
    #: (it is the priority).
    reports: tuple[str, ...] = ()
    #: Redaction only: where a value the pattern bounds really ends (matched
    #: from the end of the value). A bounded value keeps a rejected
    #: candidate's cost constant (the search restarts one character later,
    #: and an unbounded value would run to the end of the token every time);
    #: a longer value is still scrubbed whole.
    redact_tail: Optional["re.Pattern[str]"] = None

    @property
    def reported(self) -> tuple[str, ...]:
        return self.reports or (self.name,)


# Non-ASCII characters that re.IGNORECASE (Unicode simple case folding)
# matches to an ASCII letter. fold_lower() maps them first, so a needle (or a
# local-block literal) is never missed where the pattern itself would match;
# test_secret_patterns checks this table against every code point.
ASCII_FOLDS = {"\u0130": "i", "\u0131": "i", "\u017f": "s", "\u212a": "k"}
_FOLD_TABLE = str.maketrans(ASCII_FOLDS)


def fold_lower(text: str) -> str:
    """``text`` lower-cased, with the characters case-insensitive matching
    folds to ASCII letters folded first: for substring prechecks."""
    if not text.isascii() and any(c in text for c in ASCII_FOLDS):
        text = text.translate(_FOLD_TABLE)
    return text.lower()


# --------------------------------------------------------------------------- #
# Value heuristics
# --------------------------------------------------------------------------- #

def shannon_entropy(value: str) -> float:
    """Bits per character."""
    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def char_classes(value: str) -> int:
    """How many of lower / upper / digit / other the value uses."""
    return sum((
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ))


# Template slots and variable references ($VAR, {{ x }}, <your-key>, %VAR%)
# are judged by _template(): a generated password may start with "$", "{",
# "<", "(", "[" or "%" too.
_PLACEHOLDER_SHAPE = re.compile(
    r"""^(?:
        @\(.*\)$ | @\{.*\}$             # PowerShell @(...) / @{...}
      | __[A-Za-z0-9_]+__$              # __TEMPLATE_SLOT__
      | \#[0-9A-Fa-f]{3,8}$             # a colour
      | (?:env|vault|op|file|secret|secrets|ref|keyring|awssm|gcpsm|azkv|sops):
      | (?:os\.environ|os\.getenv|process\.env|import\.meta\.env|getenv|Deno\.env|ENV\[)
    )""",
    re.X,
)
_REPEATED = re.compile(r"^(.{1,4}?)\1{3,}.{0,4}$", re.S)
# "0000" / "zzzz": a padding run. Six in a row in a long value (about once in
# 20 000 random 64-char hex strings, far rarer for base64), four in a short one.
_RUN_LONG = re.compile(r"(.)\1{5,}")
_RUN_SHORT = re.compile(r"(.)\1{3,}")
_PLACEHOLDER_WORD = re.compile(
    r"example|sample|dummy|fake|fixture|placeholder|change[-_ ]?me|replace[-_ ]?(?:me|this|with)"
    r"|your[-_ ]|redacted|not[-_ ]?a[-_ ]?real|notreal|lorem|ipsum|xxxx|\*\*\*|\.\.\.|…"
    r"|todo|fixme|insert[-_ ]|test|mock|bogus|stub|synthetic|non[-_]?secret"
    r"|do[-_]?not[-_]?use",
    re.I,
)
# Text every _PLACEHOLDER_WORD match holds (after fold_lower): a value with
# none of them is not searched. The alternation is tried at every character
# (~90 ns each), and every candidate of every detector is judged with it.
_PLACEHOLDER_ANCHORS = (
    "example", "sample", "dummy", "fake", "fixture", "placeholder", "change", "replace", "your",
    "redacted", "real", "lorem", "ipsum", "xxxx", "***", "...", "\u2026", "todo", "fixme", "insert",
    "test", "mock", "bogus", "stub", "synthetic", "secret", "use",
)


def _placeholder_word(value: str) -> bool:
    folded = fold_lower(value)
    return any(a in folded for a in _PLACEHOLDER_ANCHORS) and _PLACEHOLDER_WORD.search(value) is not None


# Published documentation / test-vector values (RFC 6238 style TOTP example,
# AWS documentation keys): public by design.
_KNOWN_EXAMPLES = frozenset({
    "JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})
# Words a fixture is built from. A value made only of these (plus a short
# number) is visibly fake: "my-api-key", "secret123", "s3cret", "alice:bob".
_FAKE_VOCAB = frozenset("""
a an the my our your some any new old other another this that
secret secrets password passwd pass pw pwd passphrase token tokens tok key keys apikey api
value val values str string text data blob body header payload
foo bar baz qux quux hello world abc abcd abcdef xyz
dev local localhost prod staging demo admin root user username users operator alice bob carol
alert right wrong good bad valid invalid correct incorrect expired revoked rotated original
first second third one two three alpha beta gamma delta weak strong legacy temp temporary
shared signing client server access refresh bearer auth session cookie csrf nonce salt seed master
hook webhook relay job output ingest integration license code cred creds credential credentials
super top very hunter letmein qwerty welcome open sesame
""".split())
_LEET = str.maketrans("013457$@", "oieastsa")
_SEQUENCES = (
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "asdfghjkl",
)


def _digits_fake(run: str) -> bool:
    return len(run) <= 3 or len(set(run)) == 1 or any(run in s for s in _SEQUENCES[:2])


def _has_sequence(value: str, n: int = 6) -> bool:
    return any(s[i:i + n] in value for s in _SEQUENCES for i in range(len(s) - n + 1))


def _vocab_fake(value: str) -> bool:
    for form in (value.lower(), value.lower().translate(_LEET)):
        tokens = re.findall(r"[a-z]+|[0-9]+", form)
        if tokens and any(t.isalpha() for t in tokens) and all(
            (t in _FAKE_VOCAB) if t.isalpha() else _digits_fake(t) for t in tokens
        ):
            return True
    return False


def _wordlike(segment: str) -> bool:
    """An alphabetic run that reads as words (camelCase included): lower-case
    runs of 3+ letters cover at least half of it. Random letters rarely do."""
    if not segment.isalpha():
        return False
    return sum(len(r) for r in re.findall(r"[a-z]{3,}", segment)) * 2 >= len(segment)


_STAMP = re.compile(r"^\d{8}(?:T\d{4,6}Z?)?$")


def _made_of_words(value: str, *, need_vocab: bool = True) -> bool:
    """``tempPass-issued-by-admin``, ``weak-token-31``, ``k-123456``: segments
    that are words, very short, a fake number or a date stamp. ``need_vocab``:
    and at least one fixture word (a passphrase of real words is not a
    fixture just for being words)."""
    segments = [s for s in re.split(r"[-_.:/+ ]+", value) if s]
    if len(segments) < 2:
        return False
    alpha = [s for s in segments if s.isalpha()]
    for s in segments:
        if s.isalpha():
            if not (len(s) <= 3 or _wordlike(s)):
                return False
        elif s.isdigit():
            if not (_digits_fake(s) or _STAMP.match(s)):
                return False
        elif not _STAMP.match(s):
            return False
    if not need_vocab:
        return True
    return any(s.lower() in _FAKE_VOCAB for s in alpha) or all(len(s) == 1 for s in alpha)


_B64_SEGMENT = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")


def _decodes_to_placeholder(value: str) -> bool:
    """A base64 segment that decodes to readable fixture text
    (``whsec_<base64 of 'sample-key'>``, a JWT whose payload says "fixture")."""
    segments = _B64_SEGMENT.findall(value)
    segments += [p for s in segments for p in re.split(r"[_-]", s) if len(p) >= 8]
    for seg in segments:
        body = seg.rstrip("=")
        for alt in (body.replace("-", "+").replace("_", "/"),):
            try:
                raw = base64.b64decode(alt + "=" * (-len(alt) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            text = raw.decode("ascii", "ignore")
            if len(text) >= 0.9 * len(raw) and len(text) >= 4 and (
                _placeholder_word(text) or _vocab_fake(text) or _made_of_words(text)
                or _has_sequence(text)  # base64 of "ABCDEFGHIJKLMNOP"
            ):
                return True
    return False


def _camel_words(value: str) -> bool:
    """An identifier made of words: ``useFleetDeviceStatusQueryV2Options``,
    ``DattoKey2``, ``SecurePassword``. Words of three or more letters cover
    most of its letters and it carries at most a couple of digits; random
    mixed-case text almost never does."""
    if not re.fullmatch(r"_*[A-Za-z][A-Za-z0-9_]*", value):
        return False
    letters = sum(c.isalpha() for c in value)
    digits = sum(c.isdigit() for c in value)
    if not letters or digits > max(2, len(value) // 12):
        return False
    words = re.findall(r"[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])", value)
    if not any(len(w) >= 3 and w[-1].islower() for w in words):
        return False  # all capitals: an acronym run, or random letters
    covered = sum(len(w) for w in words if len(w) >= 3)
    return covered * 10 >= letters * 8


_SLOT = re.compile(
    r"""\$\{[^{}\n]{0,200}\}|\$\([^()\n]{0,200}\)|\$env:[A-Za-z_]\w*|\$\d
      | \$(?P<var>[A-Za-z_][A-Za-z0-9_]*)
      | %(?P<pct>[A-Za-z_][A-Za-z0-9_]*)%
      | \{\{[^{}\n]{0,200}\}\}
      | \{(?P<brace>[^{}\n]{0,200})\} | <(?P<angle>[^<>\n]{0,200})>
      | \((?P<paren>[^()\n]{0,200})\) | \[(?P<square>[^\[\]\n]{0,200})\]""",
    re.X | re.I,
)


def _name_like(ident: str) -> bool:
    return bool(
        _identifier(ident)
        or _camel_words(ident)
        or (re.fullmatch(r"[A-Z][A-Z0-9_]*", ident) and sum(c.isdigit() for c in ident) <= 2)
    )


def _slot_ok(m: "re.Match[str]") -> bool:
    for group in ("var", "pct"):
        if m.group(group) is not None:
            return _name_like(m.group(group))
    for group in ("brace", "angle", "paren", "square"):
        if m.group(group) is not None:
            return _benign_piece(m.group(group))
    return True


def _template(value: str) -> bool:
    """``$VAR``, ``${VAR}``, ``$(cmd)``, ``$env:NAME``, ``%VAR%``,
    ``{{ x }}``, ``{name}-{env}``, ``<your-key>``, ``[REDACTED]``: a value
    made of references and slots, plus at most a little literal text. A
    generated password that merely starts with ``$`` / ``{`` / ``<`` / ``[``
    / ``(`` / ``%`` is not one."""
    if value[:1] not in "${<([%":
        return False
    rest: list[str] = []
    pos = 0
    for m in _SLOT.finditer(value):
        ok = _slot_ok(m)
        if pos == 0 and (m.start() != 0 or not ok):
            return False  # the opening character does not open a slot
        if not ok:
            continue
        rest.append(value[pos:m.start()])
        pos = m.end()
    if pos == 0:
        return False
    rest.append(value[pos:])
    remainder = "".join(rest)
    return len(re.sub(r"[\W_]", "", remainder)) <= 3 or _benign_piece(remainder)


def looks_placeholder(value: str) -> bool:
    """True when the value is visibly not a real secret."""
    v = value.strip()
    if not v:
        return True
    return bool(
        v in _KNOWN_EXAMPLES
        or _PLACEHOLDER_SHAPE.match(v)
        or _template(v)
        or (v.startswith("--") and _next_flag(v))  # a CSS custom property / a CLI flag
        or (v[0] in "*&" and len(v) > 1 and _name_part(v[1:]))  # YAML *alias / &anchor
        or _REPEATED.match(v)
        or (_RUN_SHORT if len(v) <= 16 else _RUN_LONG).search(v)
        or _placeholder_word(v)
        or _has_sequence(v)
        or _vocab_fake(v)
        or _decodes_to_placeholder(v)
    )


_IDENT_LIKE = re.compile(
    r"""^_*(?:
        [a-z]+                                           # a lower-case word
      | [a-z][a-z0-9]*(?:[_.\-][a-z][a-z0-9]*)+[_.\-]?   # some_name, secret_b32, a-b.c, prefix-
      | [A-Z][A-Z0-9]*(?:[_\-][A-Z0-9]+)+                # CONSTANT_NAME, UPPER-KEBAB
    )$""",
    re.X,
)

_PATH_OR_URL = re.compile(
    r"^(?:\.{0,2}/|~/|[A-Za-z]:[\\/]|[A-Za-z][A-Za-z0-9+.-]*://"
    r"|(?:[\w.-]+/)+[\w-]+\.[A-Za-z0-9]{1,6}$)"  # src/index.css
)
# An escaped string ("KEY=<value>\nOTHER=..."), not one value.
_ESCAPED = re.compile(r"\\(?:[nrt0]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})")
# License / registration keys written in equal dash groups mixing letters and
# digits (X7KQ-9MPL-3RTZ-8WNB): a key, not an UPPER-KEBAB constant name.
_KEY_GROUPS = re.compile(r"^[A-Za-z0-9]{4,8}(?:-[A-Za-z0-9]{4,8}){2,}$")


def _key_groups(value: str) -> bool:
    if not _KEY_GROUPS.match(value):
        return False
    groups = value.split("-")
    return (
        len({len(g) for g in groups}) == 1
        and sum(c.isdigit() for c in value) >= 1
        and sum(c.isalpha() for c in value) >= 2
    )


def _benign_piece(piece: str) -> bool:
    """A piece of a list, a slot or a path that is visibly not secret."""
    p = piece.strip().strip("'\"")
    if len(p) <= 3 or p.isdigit() or _name_part(p) or _PATH_OR_URL.match(p):
        return True
    if looks_placeholder(p) or _made_of_words(p, need_vocab=False):
        return True
    for sep in (r"[\\/]+", ":"):  # %APPDATA%\Vendor\agent, 10:viewer:client_a:sess1
        parts = [x for x in re.split(sep, p) if x]
        if len(parts) >= 2 and all(
            len(x) <= 3 or x.isdigit() or _name_part(x) or _made_of_words(x, need_vocab=False)
            for x in parts
        ):
            return True
    return False


def _name_part(part: str) -> bool:
    """A name: some_name, CONSTANT, camelCase, a word with a short number (sess1)."""
    return bool(
        _IDENT_LIKE.match(part)
        or _wordlike(part.lstrip("_"))
        or _camel_words(part)
        or re.fullmatch(r"_*[a-z]{1,12}\d{1,3}", part)
    )


def _kv_list(value: str) -> bool:
    """Two or more ``name=value`` pairs joined by ``;`` or ``&`` whose names
    are names: a connection string or a query. The search resumes inside
    it, so the secret pair in it (``...;Password=...``) is judged on its own."""
    pieces = [p for p in re.split(r"[;&]", value) if p.strip()]
    if len(pieces) < 2:
        return False
    for piece in pieces:
        name, eq, _ = piece.partition("=")
        name = name.strip()
        if not eq or not re.fullmatch(r"[A-Za-z_][\w .-]{0,40}", name):
            return False
        if not all(len(w) <= 3 or _name_part(w) for w in re.split(r"[ .\-_]+", name) if w):
            return False
    return True


def _structured(value: str) -> bool:
    """A list, a ``name=value`` structure or an escaped string, not one
    secret. Only when it really is one: a generated password full of ``,;&=``
    is still a password."""
    if _ESCAPED.search(value) or _kv_list(value):
        return True
    if re.search(r"[,;&|]", value):
        pieces = [p for p in re.split(r"[,;&|]", value) if p.strip()]
        if len(pieces) >= 2 and all(
            _benign_piece(p) or ("=" in p and all(_benign_piece(s) for s in p.split("=", 1)))
            for p in pieces
        ):
            return True
    body = value.rstrip("=")
    if "=" in body:
        name, _, rest = body.partition("=")
        if (_identifier(name) or _name_part(name)) and _benign_piece(rest):
            return True  # sslmode=require, type=bearer
    return False


def _identifier(value: str) -> bool:
    value = value.rstrip("=:")  # "DATTO_API_KEY=": a prefix being built, not a value
    if not value or _key_groups(value):
        return False
    if _IDENT_LIKE.match(value) or (value.lstrip("_").isalpha() and _wordlike(value.lstrip("_"))):
        return True
    # settings.api_key, os.environ, req.headers.Authorization: a dotted path
    # of NAMES. Random text with a dot in it is not one.
    dotted = value.split(".")
    if len(dotted) >= 2 and all(dotted) and all(len(d) <= 32 and _name_part(d) for d in dotted):
        return True
    # operator_id:role:tenant -- a format description, not a secret
    parts = [p for p in value.split(":") if p]
    return len(parts) >= 2 and all(_IDENT_LIKE.match(p) or _wordlike(p) for p in parts)


_WHITESPACE = re.compile(r"\s")


def _strip_escaped_newlines(value: str) -> str:
    """``value`` without the escaped ``\\n`` / ``\\r`` / ``\\t`` it ends with. A
    loop from the end, not ``re.sub(r"(?:\\\\[nrt])+$")``: the regex retries
    the run from every position, quadratic in a long run of them."""
    end = len(value)
    while end >= 2 and value[end - 2] == "\\" and value[end - 1] in "nrt":
        end -= 2
    return value[:end]


def looks_real(
    value: str,
    *,
    min_len: int = 8,
    min_classes: int = 2,
    min_entropy: float = 2.5,
) -> bool:
    """True when ``value`` could be a real credential (scan purpose)."""
    v = _strip_escaped_newlines(value.strip())  # "KEY=<value>\n" inside a string
    if len(v) < min_len or _WHITESPACE.search(v):  # str.isspace, in C: a hot path
        return False
    if _identifier(v) or _PATH_OR_URL.match(v) or _structured(v):
        return False
    if looks_placeholder(v) or _made_of_words(v):
        return False
    return char_classes(v) >= min_classes and shannon_entropy(v) >= min_entropy


_NOT_A_VALUE = re.compile(
    r"^(?:true|false|none|null|nil|yes|no|on|off|enabled|disabled|required|optional"
    r"|-?\d{1,5}|\[REDACTED.*|\*+)$",
    re.I,
)
_FLAG = re.compile(r"^--?(?P<body>[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*)$")


def _next_flag(value: str) -> bool:
    """``--mode``, ``-Force``, ``--non-interactive``: the next option, so the
    secret flag before it carried no value. ``-<random>`` is a value that
    happens to start with a dash."""
    m = _FLAG.match(value)
    if m is None:
        return False
    body = m.group("body")
    return len(body) <= 3 or _identifier(body) or _wordlike(body) or _camel_words(body)


def redactable(value: str) -> bool:
    """True when a value in a secret-shaped slot should be scrubbed (redact
    purpose): anything but the next flag, a boolean, a short number or a
    redaction. Even "$..." goes: in job output a real password can start
    with "$"."""
    v = value.strip()
    return len(v) >= 3 and not _NOT_A_VALUE.match(v) and not _next_flag(v)


def mask(value: str) -> str:
    """Masked form for output: a short prefix and the length, never the value."""
    n = len(value)
    keep = 4 if n >= 20 else (2 if n >= 10 else 0)
    return f"{value[:keep]}***({n})"


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

def _real(**kw) -> Check:
    def check(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
        return redactable(value) if purpose == "redact" else looks_real(value, **kw)
    return check


def _not_placeholder(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    return purpose == "redact" or not looks_placeholder(value)


def _alnum_mix(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if purpose == "redact":
        return True
    body = re.sub(r"^[a-z]+[-_](?:[a-z]+[-_])?", "", value)  # drop the sk- / re_ prefix
    return (
        not looks_placeholder(value)
        and any(c.isdigit() for c in body)
        and any(c.isalpha() for c in body)
    )


def _private_key_body(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if purpose == "redact":
        return True
    # A real key has a base64 body right after the header; a fixture with
    # "...", "FAKE" or no body at all is visibly not one.
    tail = m.string[m.end():m.end() + 300]
    return re.search(r"[A-Za-z0-9+/=]{40,}", tail) is not None


def _jwt(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if purpose == "redact":
        return True
    # A fixture JWT says so in its payload ({"sub": "fixture"}).
    return not _decodes_to_placeholder(value.split(".")[1])


def _bitlocker(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if purpose == "redact":
        return True
    # Every block of a genuine recovery password is a multiple of 11.
    return all(int(g) % 11 == 0 for g in value.split("-")) and len(set(value)) > 3


def _product_key(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    body = value.replace("-", "")
    if not (any(c.isdigit() for c in body) and any(c.isalpha() for c in body)):
        return False
    return purpose == "redact" or not looks_placeholder(value)


def _cli_flag(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if purpose == "redact":
        return redactable(value)
    return looks_real(value, min_len=8)


_NON_SECRET_SUFFIX = frozenset("""
name names type types kind id ids url uri urls uris path paths file files dir dirs env var vars
ref refs header headers len length size ttl expiry expires at count counts field fields prefix
suffix version policy label hint placeholder help mode scope scopes endpoint endpoints format
regex re pattern class cls hash hashes digest fingerprint alg algorithm source store description
desc title text message msg error errors status state required enabled configured present set
valid lifetime rotation rotated usage limit limits max min index idx kid column col table param
params arg args option options flag input display masked mask chars bytes bits rounds iterations
cost budget used remaining total cache location provider handler factory fn func callback
validator schema model request response req resp result results timeout interval delay age ts
time date created updated last exists missing reset hashed sha256 stats
""".split())


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _non_secret_name(name: str) -> bool:
    bare = name.strip("'\"[]-$")
    if bare.lower() in ("pwd", "oldpwd"):  # the shell's working directory
        return True
    parts = [p for p in re.split(r"[_.\-]+", _snake(bare)) if p]
    return bool(parts) and (
        parts[-1] in _NON_SECRET_SUFFIX
        or any(p in ("hash", "hashed", "digest", "fingerprint") for p in parts)
    )


def _assignment(
    min_len: int,
    min_classes: int,
    min_entropy: float,
    name_ok: Optional[Callable[[str], bool]] = None,
) -> Check:
    def check(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
        name = m.group("name")
        if (name_ok is not None and not name_ok(name)) or _non_secret_name(name):
            return False
        if m.string[max(0, m.start("name") - 2):m.start("name")] == "${":
            # ${NAME:?message} / ${NAME:+alt} require or test the variable:
            # no value here. ${NAME:-default} / ${NAME:=default}: the default
            # is a literal and is judged like any other value.
            if value[:1] in ("?", "+"):
                return False
            if value[:1] in ("-", "="):
                value = value[1:]
        if purpose == "redact":
            return redactable(value)
        return looks_real(
            value, min_len=min_len, min_classes=min_classes, min_entropy=min_entropy
        )
    return check


def _labelled(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """``Signing key: <v>``: the word before the matched `` key`` / `` code``
    / ... must be a label word; then the value is judged like an assignment."""
    if _LABEL_FIRST_WORD.search(m.string, max(0, m.start() - 24), m.start()) is None:
        return False
    if purpose == "redact":
        return redactable(value)
    return looks_real(value, min_len=8, min_classes=2, min_entropy=2.5)


# Words that name a digest / an identifier, not a secret. They count only as
# a word of the name directly in front of the value ("sha256": <v>,
# fileSha256 = <v>, commit <v>), never as a substring ("SHARED_KEY") or a
# word somewhere earlier on the line ({"version": 2, "k": <v>}).
_DIGEST_WORDS = frozenset("""
sha sha1 sha224 sha256 sha384 sha512 sha3 md5 md4 crc crc32 digest digests checksum checksums
integrity hash hashes hashed etag fingerprint fingerprints thumbprint nonce uuid guid
revision revisions rev oid objectid object blob tree sri commit commits build version
pubkey public pub
""".split())
_DIGEST_SUFFIXES = ("digest", "hash", "checksum", "sum", "fingerprint", "thumbprint", "sha1",
                    "sha256", "sha512", "md5")
# A Markdown table whose header names one of these is a checksum table.
_TABLE_DIGEST_WORDS = frozenset("""
sha sha1 sha224 sha256 sha384 sha512 sha3 md5 crc crc32 digest digests checksum checksums
integrity hash hashes etag commit commits sri
""".split())
# sha256_hex, public_key, build_id, objectId: a digest word, then one of these.
_QUALIFIERS = frozenset("hex value val b64 base64 str string raw bytes id key text".split())
# A 40 / 64-hex value right after one of these is a git object name.
_GIT_WORDS = frozenset("""
to at from onto reverted revert reverts cherry pick picked picks commit commits merge merged
merges base head parent parents rebased rebase reset fixup squash tag tagged checkout ref sha
""".split())
_HEX_ONLY_CONTEXT = frozenset({"expected", "want", "wanted", "golden"})
_SSH_PUBKEY = re.compile(
    r"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
    r"[ \t]+$"
)
_UUID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_ULID = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
# One start per token (a lookbehind on its own class): without it every
# "eyJ" in the 4 kB window before a candidate was a start that ran to the end
# of its token.
_JWT_PREFIX = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.$")


def _name_words(name: str) -> list[str]:
    """``fileSha256`` -> [file, sha256]; ``SHARED_KEY`` -> [shared, key]."""
    return [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])\d*|[A-Z]?[a-z]+\d*|\d+", name)]


def _nearest_name(before: str) -> list[str]:
    """The words of the name directly in front of a value: the last
    identifier-ish run before it, past quotes, separators and brackets."""
    m = re.search(r"([A-Za-z][A-Za-z0-9_.\-]{0,80})[^A-Za-z0-9\n]{0,12}$", before)
    return _name_words(m.group(1)) if m else []


def _digest_word(word: str) -> bool:
    return word in _DIGEST_WORDS or word.endswith(_DIGEST_SUFFIXES)


def _names_digest(words: list[str], value: str) -> bool:
    if not words:
        return False
    if _digest_word(words[-1]):
        return True
    if len(words) >= 2 and words[-1] in _QUALIFIERS and _digest_word(words[-2]):
        return True
    hexonly = re.fullmatch(r"[0-9a-fA-F]+", value) is not None
    if hexonly and words[-1] in _HEX_ONLY_CONTEXT:
        return True
    return hexonly and len(value) in (40, 64) and words[-1] in _GIT_WORDS


_TABLES = threading.local()


def _table_header_names_digest(text: str, line_start: int) -> bool:
    """A Markdown table row whose header (the first line of its run of
    ``|`` lines) names a digest column (``| file | md5 |``). Each row's
    header is remembered on the way up, so a long table costs one walk."""
    if not text[line_start:line_start + 8].lstrip().startswith("|"):
        return False
    if getattr(_TABLES, "text", None) is not text:
        _TABLES.text, _TABLES.top, _TABLES.digest = text, {}, {}
    tops: dict[int, int] = _TABLES.top
    visited: list[int] = []
    pos = line_start
    while True:
        if pos in tops:
            top = tops[pos]
            break
        visited.append(pos)
        prev_start = text.rfind("\n", 0, pos - 1) + 1 if pos else 0
        if pos == 0 or not text[prev_start:pos].lstrip().startswith("|"):
            top = pos
            break
        pos = prev_start
    for row in visited:
        tops[row] = top
    if top == line_start:
        return False  # the row is the first line: no header above it
    digest: dict[int, bool] = _TABLES.digest
    if top not in digest:
        line_end = text.find("\n", top)
        header = text[top:line_end if line_end != -1 else len(text)]
        digest[top] = any(w.endswith(_DIGEST_SUFFIXES) or w in _TABLE_DIGEST_WORDS
                          for w in _name_words(header))
    return digest[top]


def _list_header_names_digest(text: str, line_start: int) -> bool:
    """An indented list item whose header (the nearest less-indented line
    above, a few lines up at most) names a digest:
    ``sha256 pinned for the models:`` / ``   tinyllama   <hex>``."""
    line_end = text.find("\n", line_start)
    line = text[line_start:line_end if line_end != -1 else len(text)]
    indent = len(line) - len(line.lstrip())
    if indent == 0:
        return False
    pos = line_start
    for _ in range(20):
        if pos == 0:
            return False
        prev = text.rfind("\n", 0, pos - 1) + 1
        above = text[prev:pos - 1]
        if not above.strip():
            return False
        if len(above) - len(above.lstrip()) < indent:
            return any(w.endswith(_DIGEST_SUFFIXES) or w in _TABLE_DIGEST_WORDS
                       for w in _name_words(above))
        pos = prev
    return False


_URL_BREAK = re.compile(r"[\s\"'<>`{}\[\]]")
_URL_SECRET_HINT = re.compile(
    r"(?i)webhook|hooks|/bot|token|secret|key|sig|signature|auth|passw|credential|session_?key"
)


def _url_path_id(text: str, start: int, end: int) -> bool:
    """A run inside a URL's host / path (a session, document or commit id),
    not its query or user-info, and not a webhook / bot / token URL (those
    carry the secret in the path)."""
    scheme = text.rfind("://", max(0, start - 512), start)
    if scheme == -1 or _URL_BREAK.search(text, scheme, start):
        return False
    head = text[scheme:start]
    if any(c in head for c in "?#&=") or text[end:end + 1] in ("@", ":"):
        return False
    return not _URL_SECRET_HINT.search(head + text[start:end])


def _hash_context(text: str, start: int, end: int) -> bool:
    """A digest, not a secret: named as one directly in front of it (on this
    line, or on the line above when this one only opens a literal), a
    Markdown checksum table, an OpenSSH public key, or a checksum listing
    (``<hex>  <file>``)."""
    value = text[start:end]
    line_start = text.rfind("\n", 0, start) + 1
    before = text[max(line_start, start - 120):start]
    if before.endswith("base64,") or _SSH_PUBKEY.search(before):
        return True
    if _names_digest(_nearest_name(before), value):
        return True
    if not before.strip(" \t\"'`(=:[{,") and line_start > 0:
        prev_start = text.rfind("\n", 0, line_start - 1) + 1
        if _names_digest(_nearest_name(text[max(prev_start, line_start - 160):line_start - 1]), value):
            return True
    if _table_header_names_digest(text, line_start) or _list_header_names_digest(text, line_start):
        return True
    line_end = text.find("\n", end)
    after = text[end:line_end if line_end != -1 else len(text)]
    return not text[line_start:start].strip() and re.match(r"^\s+\*?\S+\s*$", after) is not None


def _upper_digit_key(value: str) -> bool:
    """A key in an upper-case-and-digits alphabet (base32 seeds, integration
    codes, vendor API keys): 24+ characters, letters and digits well mixed."""
    return (
        re.fullmatch(r"[A-Z0-9]{24,}", value) is not None
        and not re.fullmatch(r"[0-9A-F]+", value)
        and sum(c.isdigit() for c in value) >= 3
        and sum(c.isalpha() for c in value) >= 6
        and not _ULID.match(value)
        and shannon_entropy(value) >= 3.8
    )


def _high_entropy(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> Union[bool, str]:
    if ctx.generated or _UUID.match(value):
        return False
    if len(value.rstrip("=")) < 32 and not _upper_digit_key(value):
        return False  # under 32 characters only an upper-case + digits key counts
    if _hash_context(m.string, m.start(), m.end()) or _url_path_id(m.string, m.start(), m.end()):
        return False
    if (value.startswith("eyJ") and m.string[m.end():m.end() + 1] == ".") or \
            _JWT_PREFIX.search(m.string, max(0, m.start() - 4096), m.start()):
        return False  # a part of a JWT: the jwt detector judges the whole token
    seps = sum(value.count(c) for c in "_-/+")
    if seps / len(value) > 0.12 or _made_of_words(value, need_vocab=False):  # names, paths
        return False
    if _camel_words(value) or looks_placeholder(value):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
            return False
        return "hex-secret" if shannon_entropy(value) >= 3.0 else False
    if _upper_digit_key(value):
        return "high-entropy-string"
    if not (any(c.isdigit() for c in value) and any(c.isupper() for c in value)
            and any(c.islower() for c in value)):
        return False
    if shannon_entropy(value) < 4.0:
        return False
    return "high-entropy-string"  # a 32-byte base64 key: fernet-or-base64-key, before this


# --- shapes added after the 2026-10-15 sweep ------------------------------ #

def _key_bytes(value: str) -> Optional[bytes]:
    """The 32 bytes a canonical 44-character base64 (or base64url) value
    encodes, else None. Canonical: re-encoding gives the value back, as every
    encoder writes it (random text of the same shape is canonical one time in
    four)."""
    if len(value) != 44 or value[43] != "=" or value[42] == "=":
        return None
    urlsafe = "-" in value or "_" in value
    if urlsafe and ("+" in value or "/" in value):
        return None  # two alphabets: not one encoding
    std = value.replace("-", "+").replace("_", "/") if urlsafe else value
    try:
        raw = base64.b64decode(std, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 and base64.b64encode(raw).decode() == std else None


_PEM_ANY_HEADER = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")


def _in_public_pem(text: str, start: int, end: int) -> bool:
    """A body line of a PEM block that is not a private key (a certificate,
    a public key): its last line can be 44 characters with one ``=``."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if text[line_start:start].strip() or text[end:line_end if line_end != -1 else len(text)].strip():
        return False
    begin = text.rfind("-----BEGIN ", max(0, start - 20000), start)
    if begin == -1 or "-----END " in text[begin:start]:
        return False
    header = _PEM_ANY_HEADER.match(text, begin)
    return header is not None and "PRIVATE" not in header.group(1)


def _base64_key(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """32 random bytes in base64: a Fernet key, a WireGuard private key, an
    ``*_KEY_BASE64`` value. Found with or without a key-like name, also as
    ``NAME=<v>`` inside a longer string. Not a key: an all-zero / repeated /
    sequence placeholder, base64 of readable text, a named digest
    (``sha256: <v>``, ``h1:<v>`` in go.sum), a WireGuard ``PublicKey``, a
    certificate line."""
    if purpose == "redact" or ctx.generated:
        return False
    raw = _key_bytes(value)
    if raw is None or len(set(raw)) < 20 or shannon_entropy(value) < 4.0:
        return False
    if sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) >= 29:
        return False  # readable text, not key material
    if looks_placeholder(value):
        return False
    text, start, end = m.string, m.start(), m.end()
    if text[max(0, start - 3):start] == "h1:":
        return False  # go.sum: h1:<sha256 base64>
    return not (_hash_context(text, start, end) or _in_public_pem(text, start, end))


def _whsec(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """``whsec_<base64>``: a Svix / Resend / Stripe webhook signing secret. A
    visibly fake one (base64 of fixture text) stays quiet."""
    if purpose == "redact":
        return True
    body = value[len("whsec_"):].rstrip("=")
    return (
        char_classes(body) >= 2
        and shannon_entropy(body) >= 3.5
        and not looks_placeholder(value)
        and not looks_placeholder(body)
    )


def _mixed_secret(part: str, *, min_entropy: float = 3.5) -> bool:
    """A generated token part: upper, lower and digits, varied, not a placeholder."""
    return (
        any(c.isdigit() for c in part)
        and any(c.isupper() for c in part)
        and any(c.islower() for c in part)
        and shannon_entropy(part) >= min_entropy
        and not looks_placeholder(part)
    )


def _telegram(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """``<bot id>:<35 characters>``: a Telegram bot token."""
    return purpose == "redact" or _mixed_secret(value.partition(":")[2])


def _itglue(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """``ITG.<key>[.<secret>]``: an IT Glue API key."""
    if purpose == "redact":
        return True
    body = value[len("ITG."):]
    return (
        any(c.isdigit() for c in body)
        and any(c.isalpha() for c in body)
        and shannon_entropy(body) >= 3.0
        and not looks_placeholder(body)
    )


def _decode_json_segment(value: str) -> object:
    body = value.rstrip("=")
    try:
        raw = base64.b64decode(body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4),
                               validate=True)
        return json.loads(raw)
    # JSONDecodeError and UnicodeDecodeError are ValueErrors; a deeply nested
    # array can exhaust the recursion limit on Pythons before 3.12.
    except (binascii.Error, ValueError, RecursionError):
        return None


def _cf_tunnel(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """One ``eyJ...`` segment (not a JWT part) that decodes to
    ``{"a": <account>, "t": <tunnel id>, "s": <secret>}``: a Cloudflare tunnel
    token (``cloudflared tunnel run --token``)."""
    obj = _decode_json_segment(value)
    if not isinstance(obj, dict) or not all(isinstance(obj.get(k), str) for k in ("a", "t", "s")):
        return False
    secret = obj["s"]
    return purpose == "redact" or (len(secret) >= 16 and not looks_placeholder(secret))


# --- passwords on command lines (guardrails v5; one detector per family since v6) --- #

_CLI_BARE = r"[^\s'\"`;|&<>]"            # a bare word: up to a blank or a shell metacharacter
_CLI_NOT_SWITCH = r"[^\s'\"`;|&<>/*]"    # ... that is not a /switch or a * (prompt)
# A bare PowerShell argument that is a literal: not a $variable, a (sub-expression),
# an @array / @splat or the next -Parameter.
_CLI_PS_LITERAL = r"[^\s'\"`;|&<>$(@-]"
_CLI_VALUE_GROUPS = ("vs", "vd", "vu")
_CLI_USER_SECRET_GROUPS = ("vs", "vd", "vq", "ve", "vu")


def _cli_value(first: str = _CLI_BARE) -> str:
    """A value on a command line: ``'...'``, ``"..."`` or a bare word
    (groups :data:`_CLI_VALUE_GROUPS`)."""
    return (rf"(?:'(?P<vs>[^'\n]{{1,200}})'|\"(?P<vd>[^\"\n]{{1,200}})\""
            rf"|(?P<vu>{first}{_CLI_BARE}{{0,199}}))")


def _cli_user_secret(sep: str) -> str:
    """``user<sep>secret`` (curl ``user:pass``, smbclient ``user%pass``),
    quoted whole, with the secret quoted alone, or bare. The value is the
    secret; the user name before the first separator stays out of it
    (groups :data:`_CLI_USER_SECRET_GROUPS`)."""
    return (
        rf"(?:'[^'\n{sep}]{{0,120}}{sep}(?P<vs>[^'\n]{{1,200}})'"
        rf"|\"[^\"\n{sep}]{{0,120}}{sep}(?P<vd>[^\"\n]{{1,200}})\""
        rf"|[^\s'\"`;|&<>{sep}]{{0,120}}{sep}(?:'(?P<vq>[^'\n]{{1,200}})'"
        rf"|\"(?P<ve>[^\"\n]{{1,200}})\"|(?P<vu>{_CLI_BARE}{{1,200}})))"
    )


def _program(names: str, *, ignore_case: bool = False) -> "re.Pattern[str]":
    return re.compile(rf"(?<![\w.-])(?:{names})(?:\.exe)?(?![\w.-])", re.I if ignore_case else 0)


def _ps_param(name: str, shortest: int) -> str:
    """A PowerShell parameter name or any prefix of it down to ``shortest``
    characters (PowerShell takes an unambiguous prefix): ``asplaintext``,
    ``asplain``, ``a``. Used under ``(?i)``."""
    nested = ""
    for c in reversed(name[shortest:]):
        nested = f"(?:{re.escape(c)}{nested})?"
    return re.escape(name[:shortest]) + nested


_CMD_BREAK = (";", "|", "&&", "$(", "`")
_CONTINUED = ("\\", "`", "^")  # a line continued by sh / PowerShell / cmd


def _command_before(text: str, start: int, limit: int = 600) -> str:
    """The command an option at ``start`` belongs to, up to the option: its
    line, continuation lines joined, from the last ``;`` / ``|`` / ``&&`` /
    ``$(`` / backtick. Bounded, so a hostile line stays linear."""
    floor = max(0, start - limit)
    line_start = text.rfind("\n", floor, start) + 1 or floor
    head = text[line_start:start]
    for _ in range(8):
        if line_start <= floor or len(head) >= limit:
            break
        end = line_start - 1  # the "\n"
        if text[end - 1:end] == "\r":
            end -= 1
        if text[end - 1:end] not in _CONTINUED:
            break
        prev = text.rfind("\n", floor, end) + 1 or floor
        head = text[prev:end - 1] + " " + head
        line_start = prev
    cut = 0
    for brk in _CMD_BREAK:
        at = head.rfind(brk)
        if at != -1:
            cut = max(cut, at + len(brk))
    return head[cut:]


def _command_after(text: str, end: int, limit: int = 300) -> str:
    """The rest of the command after ``end``: its line, continuation lines
    joined, up to the next ``;`` / ``|`` / ``&&``. Bounded like
    :func:`_command_before`."""
    ceiling = min(len(text), end + limit)
    parts: list[str] = []
    pos = end
    for _ in range(8):
        stop = text.find("\n", pos, ceiling)
        line = text[pos:stop if stop != -1 else ceiling].rstrip("\r")
        if stop == -1 or not line.endswith(_CONTINUED):
            parts.append(line)
            break
        parts.append(line[:-1])
        pos = stop + 1
    rest = " ".join(parts)
    for brk in (";", "|", "&&"):
        at = rest.find(brk)
        if at != -1:
            rest = rest[:at]
    return rest


#: A program the option must share its command line with: the regex, and
#: cheap lower-case substrings of every name it matches (the needles).
_Program = Tuple["re.Pattern[str]", Tuple[str, ...]]


def _cli_check(program: Optional[_Program], after: Optional["re.Pattern[str]"]) -> Check:
    """A password given to a known program on its command line. The option
    alone (``-p``, ``-u``, ``-w``, ``/user:``) is everywhere; the program must
    be on the same command line (``after``: and this after the option, e.g.
    ``-AsPlainText``). Then the value is judged like any secret: ``$VAR``,
    ``${VAR}``, ``%VAR%``, ``<pw>``, ``****``, ``password`` or ``changeme``
    stay quiet, and so, when scanning, does what the shell expands
    (_cli_reference: ``$(...)``, ``(...)``, ``$script:Name``, ``!NAME!``);
    redaction scrubs those too."""
    def check(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
        if program is not None:
            rx, needles = program
            command = _command_before(m.string, m.start())
            folded = fold_lower(command)
            if not any(n in folded for n in needles) or rx.search(command) is None:
                return False
        if after is not None and after.search(m.group(0) + _command_after(m.string, m.end())) is None:
            return False
        v = value.strip()
        if purpose == "redact":
            return redactable(v)  # job output: even "$(...)" goes
        if _cli_reference(v, _cli_quote(m)):
            return False
        return looks_real(v, min_len=6, min_classes=2, min_entropy=2.0)
    return check


# What a shell or PowerShell expands, not a literal password (scan purpose):
# $(...) / ${...} (sh and PowerShell, bare or in double quotes), a
# scope-qualified PowerShell variable ($script:Name, $using:Name, $env:Name),
# a bare (...) expression (PowerShell: -P (Get-Secret sql)), and cmd's
# delayed expansion !NAME!. In single quotes sh and PowerShell expand
# nothing, so only !NAME! (cmd has no single quotes) counts there.
_CLI_EXPANDS = re.compile(
    r"\$\(|\$\{[^{}\n]{1,200}\}|\$(?:global|script|local|private|using|env):[A-Za-z_][A-Za-z0-9_]*",
    re.I,
)
_CLI_DELAYED = re.compile(r"!(?P<name>[A-Za-z_][A-Za-z0-9_]{0,80})!")


def _cli_quote(m: "re.Match[str]") -> str:
    """How the value was written: ``'`` (single quotes), ``"`` or ``""`` (bare)."""
    groups = m.re.groupindex
    for group, quote in (("vs", "'"), ("vq", "'"), ("vd", '"'), ("ve", '"')):
        if group in groups and m.group(group) is not None:
            return quote
    return ""


def _cli_reference(value: str, quote: str) -> bool:
    """A command-line value that the shell expands (see :data:`_CLI_EXPANDS`)."""
    delayed = _CLI_DELAYED.fullmatch(value)
    if delayed is not None and _name_like(delayed.group("name")):
        return True
    if quote == "'":
        return False
    if _CLI_EXPANDS.match(value):
        return True
    return quote == "" and value.startswith("(")


# Anchored at the option, never at the program: a lazy "program ... option"
# gap would be retried over the whole line for every program name.
_CLI_OPT = r"(?<![\w-])"
_MYSQL = r"mysql(?:dump|admin|import|check|show|pump|sh|binlog|slap)?|mariadb(?:-(?:dump|admin|import|check|show|slap))?"
_NET_USE: _Program = (re.compile(r"(?<![\w.-])net(?:\.exe)?[ \t]+use\b", re.I), ("net",))
_AS_PLAIN_TEXT = re.compile(r"(?i)(?<![\w-])-" + _ps_param("asplaintext", 1) + r"(?![\w-])")
_CTSS_SWITCH = rf"-(?:{_ps_param('asplaintext', 1)}|{_ps_param('force', 1)})(?::\$true)?"

#: (family, pattern, value groups, program on the same command line or None
#: when the pattern names it, needles when it does, what must follow).
_CLI_FAMILIES: tuple[tuple[str, str, tuple[str, ...], Optional[_Program], tuple[str, ...],
                           Optional["re.Pattern[str]"]], ...] = (
    # sshpass -p <pw>, after its own options (-e, -v, -f <file>, -d <fd>, -P
    # <prompt>): each option one way (the letter after the dash picks the
    # form), at most 8 of them
    ("sshpass",
     rf"(?<![\w.-])sshpass(?:\.exe)?(?:[ \t]+-[ev]\S*|[ \t]+-[fdP][ \t]*\S+){{0,8}}[ \t]+-p[ \t]*{_cli_value()}",
     _CLI_VALUE_GROUPS, None, ("sshpass",), None),
    # the variables these tools read a password from
    ("env", rf"(?<![\w-])(?:PGPASSWORD|SSHPASS|MYSQL_PWD|REDISCLI_AUTH)[ \t]*=[ \t]*{_cli_value()}",
     _CLI_VALUE_GROUPS, None, ("pgpassword", "sshpass", "mysql_pwd", "rediscli_auth"), None),
    # mysql / mariadb -p<pw> (glued: "-p <word>" names a database) or --pass[word]=<pw>
    # (mysql takes any unambiguous prefix of an option); rdesktop -p<pw>; 7z -p<pw>
    ("glued-p", rf"{_CLI_OPT}(?:-p|--pass(?:w(?:o(?:r(?:d)?)?)?)?=)(?=\S){_cli_value()}",
     _CLI_VALUE_GROUPS,
     (_program(rf"{_MYSQL}|rdesktop|(?i:7z[arzg]?)"), ("mysql", "mariadb", "rdesktop", "7z")), (), None),
    # rdesktop / psexec / docker login -p <pw>. docker's global options before
    # "login" match one way each (a dash or two, then a character that is not
    # a dash), at most 12 of them: an option list that could split "--x" as
    # "-" + "-x" or "--" + "x" doubled the work per option (ReDoS).
    ("spaced-p", rf"{_CLI_OPT}-p[ \t]+{_cli_value()}", _CLI_VALUE_GROUPS,
     (re.compile(r"(?i:(?<![\w.-])(?:rdesktop|psexec(?:64)?|paexec)(?:\.exe)?(?![\w.-]))"
                 r"|(?<![\w.-])(?:docker|podman|nerdctl)(?:\.exe)?"
                 r"(?:[ \t]+--?[\w.][\w.-]*(?:=\S*)?){0,12}[ \t]+login(?![\w-])"),
      ("rdesktop", "psexec", "paexec", "login")), (), None),
    # curl -u / -U / --user / --proxy-user user:<pw> (also in a flag cluster: -sSfu)
    ("curl", rf"{_CLI_OPT}(?:-[A-Za-z]{{0,8}}[uU][ \t]*|--(?:proxy-)?user(?:[ \t]*=[ \t]*|[ \t]+))"
             rf"{_cli_user_secret(':')}",
     _CLI_USER_SECRET_GROUPS, (_program("curl"), ("curl",)), (), None),
    # smbclient / rpcclient -U / --user user%<pw>
    ("smb", rf"{_CLI_OPT}(?:-U[ \t]*|--user(?:=|[ \t]+)){_cli_user_secret('%')}",
     _CLI_USER_SECRET_GROUPS,
     (_program("smbclient|rpcclient|smbget|smbcacls|smbtree"), ("smb", "rpcclient")), (), None),
    # net use \\host\share /user:<u> <pw>, or net use [X:] \\host\share <pw> [/user:<u>]
    ("net-user", rf"(?i:{_CLI_OPT}/u(?:ser)?:)(?:\"[^\"\n]{{0,120}}\"|[^\s\"]{{1,120}})[ \t]+"
                 rf"{_cli_value(_CLI_NOT_SWITCH)}",
     _CLI_VALUE_GROUPS, _NET_USE, (), None),
    ("net-share", rf"(?<![\w\\])\\\\[^\s\\]{{1,120}}\\[^\s]{{0,240}}[ \t]+{_cli_value(_CLI_NOT_SWITCH)}",
     _CLI_VALUE_GROUPS, _NET_USE, (), None),
    # xfreerdp /p:<pw> or -p:<pw>; winrs -p:<pw> / -password:<pw>
    ("colon-p", rf"{_CLI_OPT}[/-]p(?:assword)?:{_cli_value()}", _CLI_VALUE_GROUPS,
     (_program(r"xfreerdp3?|wlfreerdp|sdl-freerdp3?|(?i:winrs)"), ("freerdp", "winrs")), (), None),
    # ldapsearch / ldapmodify / ... -w <pw>
    ("ldap", rf"{_CLI_OPT}-w[ \t]*{_cli_value()}", _CLI_VALUE_GROUPS,
     (_program("ldap(?:search|modify|add|delete|whoami|passwd|compare|modrdn|exop)"), ("ldap",)), (), None),
    # cmdkey /pass:<pw>
    ("slash-pass",
     rf"(?i:{_CLI_OPT}/pass:){_cli_value()}", _CLI_VALUE_GROUPS,
     (_program("cmdkey", ignore_case=True), ("cmdkey",)), (), None),
    # PuTTY: plink / pscp / psftp / putty -pw <pw>
    ("putty", rf"{_CLI_OPT}-pw[ \t]+{_cli_value()}", _CLI_VALUE_GROUPS,
     (_program("plink|pscp|psftp|putty|kitty", ignore_case=True), ("plink", "pscp", "psftp", "putty", "kitty")),
     (), None),
    # sqlcmd / bcp / osql / isql / ipmitool / zip / unzip -P <pw>
    ("upper-p", rf"{_CLI_OPT}-P[ \t]*{_cli_value()}", _CLI_VALUE_GROUPS,
     (_program("sqlcmd|bcp|osql|isql|ipmitool|zip|unzip", ignore_case=True),
      ("sqlcmd", "bcp", "osql", "isql", "ipmitool", "zip")), (), None),
    # redis-cli -a <pw> / --pass <pw>
    ("redis", rf"{_CLI_OPT}(?:-a|--pass)[ \t]+{_cli_value()}", _CLI_VALUE_GROUPS,
     (_program("redis-cli|valkey-cli|keydb-cli"), ("redis-cli", "valkey-cli", "keydb-cli")), (), None),
    # ConvertTo-SecureString [-String] '<pw>' -AsPlainText [-Force] (switches in any order)
    ("securestring",
     rf"(?i:(?<![\w-])ConvertTo-SecureString(?:[ \t]+{_CTSS_SWITCH}){{0,2}}[ \t]+"
     rf"(?:-{_ps_param('string', 2)}(?:[ \t]*:[ \t]*|[ \t]+))?){_cli_value(_CLI_PS_LITERAL)}",
     _CLI_VALUE_GROUPS, None, ("convertto-securestring",), _AS_PLAIN_TEXT),
)


def _cli_detectors() -> tuple["Detector", ...]:
    """One detector per family, each reporting ``cli-password``."""
    return tuple(
        Detector(f"cli-password:{family}", re.compile(pattern), group=groups,
                 check=_cli_check(program, after), needles=program[1] if program else needles,
                 reports=("cli-password",))
        for family, pattern, groups, program, needles, after in _CLI_FAMILIES
    )


# --- publish-only: ids that may grant access ------------------------------ #

# Hosts whose URL paths carry public ids, never credentials: font files,
# model names, the session link every agent commit carries (an id behind a
# sign-in), documentation and package registries.
_URL_TOKEN_SAFE_HOST = re.compile(
    r"(?:^|\.)(?:fonts\.googleapis\.com|fonts\.gstatic\.com|huggingface\.co|hf\.co|claude\.ai"
    r"|example\.(?:com|org|net)|[a-z0-9-]+\.example|localhost|registry\.npmjs\.org"
    r"|pypi\.org|files\.pythonhosted\.org|unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)$",
    re.I,
)
_URL_HOST = re.compile(r"[^/?#\s]*")


def _camel_identifier(run: str) -> bool:
    """camelCase that reads as words (``getDeviceStatusForSiteV2``), not random
    mixed case: _camel_words, and capitalised lower-case words of 3+ letters
    cover 60% of the letters. A random 21-character token passes about 0.4%
    of the time (_camel_words alone: 1.4%)."""
    letters = sum(c.isalpha() for c in run)
    lower_words = sum(len(w) for w in re.findall(r"[A-Z]?[a-z]{3,}", run))
    return _camel_words(run) and lower_words * 10 >= letters * 6


def _url_path_token(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """An opaque token in a URL path or query value (a vendor deep link: a
    dashboard share, a signed download): 16+ characters of mixed case and
    digits, entropy 3.5+. Not a token: words and identifiers (model names,
    font families, slugs), hex (git SHAs, content hashes), UUIDs, a hashed
    file name (``index-<hash>.js``), a digest, a host on the safe list."""
    if purpose == "redact" or ctx.generated:
        return False
    run = max(re.findall(r"[A-Za-z0-9]+", value), key=len, default="")  # "//-----": no run
    if len(run) < 16 or re.fullmatch(r"[0-9A-Fa-f]+", run):
        return False
    if not (any(c.isupper() for c in run) and any(c.islower() for c in run)
            and any(c.isdigit() for c in run)):
        return False
    if shannon_entropy(run) < 3.5 or _camel_identifier(run) or _made_of_words(value, need_vocab=False):
        return False
    if looks_placeholder(value) or any(_digest_word(w) for w in re.split(r"[-_]+", value.lower())):
        return False
    text, start = m.string, m.start()
    scheme = text.rfind("://", max(0, start - 2048), start)
    if scheme == -1 or _URL_BREAK.search(text, scheme, start):
        return False
    authority = _URL_HOST.match(text, scheme + 3).group(0)
    host = authority.rpartition("@")[2].split(":")[0]
    return scheme + 3 + len(authority) < start and not _URL_TOKEN_SAFE_HOST.search(host)


_NEXTDNS_FAKE = frozenset({
    "abc123", "123abc", "a1b2c3", "1a2b3c", "abcdef", "fedcba", "123456", "654321", "000000",
    "ffffff", "c0ffee", "deadbe", "abcabc", "123123",
})


def _nextdns_id(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """A NextDNS profile id (6 hex characters) in a NextDNS URL or a
    ``nextdns ... profile`` setting: whoever has it can resolve through that
    profile and fill its logs."""
    v = value.lower()
    return v not in _NEXTDNS_FAKE and not looks_placeholder(v)


# --- publish-only --------------------------------------------------------- #

_DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737 documentation
    "192.0.0.0/24", "198.18.0.0/15",                       # IETF / benchmarking
))
_TAILNET = ipaddress.ip_network("100.64.0.0/10")
_RANGE_DEFINITIONS = frozenset({
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/0", "224.0.0.0/4", "240.0.0.0/4",
})
_WELL_KNOWN_PUBLIC = frozenset({
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "100.100.100.100",
})


def _ip_kind(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> Union[bool, str]:
    cidr = m.group("cidr") or ""
    if f"{value}{cidr}" in _RANGE_DEFINITIONS or value.startswith("255.") or value in _WELL_KNOWN_PUBLIC:
        return False
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:  # AddressValueError: not an address (the pattern takes ASCII digits only)
        return False
    if (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved
            or any(ip in n for n in _DOC_NETS)):
        return False
    if ip in _TAILNET:
        return "ip-tailnet"
    if ip.is_private or ip.is_link_local:
        return "ip-private"
    return "ip-public"


_DOC_EMAIL_DOMAIN = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|[a-z0-9-]+\.example|example|test|invalid|localhost"
    r"|local|users\.noreply\.github\.com|noreply\.github\.com)$",
    re.I,
)


#: Dependency lockfiles: the package manager writes them, and their license
#: metadata names the third-party authors. Only the e-mail detector skips
#: them; every secret detector still reads them.
LOCKFILE = re.compile(
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Cargo\.lock)$"
)


def _email(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    if LOCKFILE.search(ctx.path) and m.string != ctx.path:
        return False  # the lockfile's contents; an address in its own path still counts
    local, _, domain = value.rpartition("@")
    if local.lower() in ("noreply", "no-reply", "git", "user", "you", "someone", "name"):
        return False
    return not _DOC_EMAIL_DOMAIN.search(domain)


#: The one ticket number tests and docs may carry (docs/NON-NEGOTIABLES.md).
PSA_TICKET_FIXTURE = "T20000101.0001"


def _psa_ticket(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """An Autotask-style ticket number (``T`` + yyyymmdd + ``.`` + 4 digits)
    names a client's support case: never public. The documented fixture
    ``T20000101.0001`` is not reported."""
    return value.upper() != PSA_TICKET_FIXTURE


# An agent's memory store (Claude Code keeps it in .claude/projects/<project
# slug>/memory/) holds the operator's working notes: a link or a path into it
# is dead in any other checkout and says what the notes are about. Two forms
# (guardrails v9), whatever precedes them (/home/<u>/, ~/, ../../../, $HOME/,
# C:\Users\<u>\):
#
# * .claude/projects/<any slug>/memory, with '/' or '\' (doubled in an
#   escaped string), in any case; the hit runs on through what follows it
#   (the note's file name) up to a blank, a quote, a bracket or a list
#   separator, so the masked excerpt shows none of it;
# * the project-directory slug made of a home directory, on its own:
#   -home-<user>..., -Users-<user>... (macOS), C--Users-<user>... (Windows):
#   it carries a user name and the operator's directory layout. Not after a
#   word character, '.', '#' or '-' (at-home-lab, --home-dir, a Markdown
#   anchor #-home-page), a drive letter only before -Users- (v--home-dir is
#   no slug), and never a placeholder (-home-<user>, -home-$USER).
#
# Note names on their own (no path, no brackets) are not reported: they are
# allowed unless they name a client or our infrastructure, which the
# local-block terms catch.
_PATH_SEP = r"[/\\]{1,2}"
_MEMORY_PATH = (
    rf"(?i:(?<![\w.-])\.claude{_PATH_SEP}projects{_PATH_SEP}[^/\\\s]{{1,255}}{_PATH_SEP}"
    r"memory(?![\w-])(?!\.[\w-]))"
    rf"(?:{_PATH_SEP}[^\s'\"`<>()\[\]{{}}|,;]{{0,255}})?"
    r"|(?<![\w.#-])(?:-home|(?:[A-Za-z]-)?-Users)-[A-Za-z0-9_][A-Za-z0-9._-]{0,250}"
)


# --------------------------------------------------------------------------- #
# Detectors (order = priority when two overlap)
# --------------------------------------------------------------------------- #

# The value of an assignment: quoted (also JSON-escaped: \"...\" in a
# notebook or an exported component), or a bare token; optionally on the
# next line after a "(" (Python) or a YAML block-scalar indicator (| >-).
# Named groups so the span of whichever form matched can be recovered.
_VALUE_GROUPS = ("edq", "esq", "dq", "sq", "bq", "uq")
_VALUE = (
    r"""(?:\([ \t]*(?:\r?\n[ \t]*)?|[|>][-+]?[0-9]?[ \t]*\r?\n[ \t]+)?"""
    r"""(?:\\"(?P<edq>[^"\\\n]{1,400})\\"|\\'(?P<esq>[^'\\\n]{1,400})\\'"""
    r"""|"(?P<dq>[^"\n]{1,400})"|'(?P<sq>[^'\n]{1,400})'|`(?P<bq>[^`\n]{1,400})`"""
    r"""|(?P<uq>[^\s'"`,;&(){}\[\]<>]{1,400}))"""
)
_SEP = r"""(?:\\?["']?\]?[ \t]*(?::=|=>|(?<![=!<>:])=(?![=>~])|:(?![:/=]))[ \t]*)"""
# Factored by first letter (always under (?i)): the name lookahead tries this
# at every offset of every identifier, and a flat alternation costs twice as
# much. Wi-Fi and UniFi: wpa_psk / wpaPsk, x_passphrase, x_iapp_key,
# x_ipsec_pre_shared_key.
_SECRET_WORD = (
    r"(?:a(?:pi[_-]?key|pikey|ccess[_-]?key|uth[_-]?key)"
    r"|c(?:lient[_-]?secret|redentials?|onn(?:ection)?[_-]?str(?:ing)?)"
    r"|e(?:ncryption[_-]?key)|f(?:ernet(?:[_-]?key)?)|i(?:ntegration[_-]?code|app[_-]?key)"
    r"|l(?:icense[_-]?key)|m(?:aster[_-]?key)"
    r"|p(?:assw(?:or)?d|asswd|assphrase|wd|rivate[_-]?key|re[_-]?shared[_-]?key|sk(?![a-z]))"
    r"|s(?:ecret|igning[_-]?key)|token)"
)
# A label in prose or a docstring ("Signing key: <v>", "API key = <v>"): the
# pattern starts at the second word (cheap to find); _labelled checks the first.
_LABEL_FIRST_WORD = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:api|access|auth|signing|encryption|fernet|master|license|licence"
    r"|activation|registration|install(?:ation)?|enrol(?:l)?ment|pre-?shared|shared|private"
    r"|wi-?fi|wpa|network|integration|webhook|client|app|service[ -]account)$"
)
# Factored by first letter like _SECRET_WORD (tried at every word start):
# Datto, Autotask, RocketCyber, NextDNS, UniFi, Resend, Cloudflare / CF, Wazuh,
# Infocyte, IT Glue, Kaseya, Tailscale / TS, OpenAI, Anthropic, GitHub / GH,
# Slack, AWS, Azure, MS Graph / Graph, M365, SentinelOne, Huntress,
# ScreenConnect, ConnectWise, TeamViewer, Splashtop, Sophos, Duo, Okta,
# Google, GCP, Twilio, SendGrid, Mailgun, Postmark, PagerDuty, Discord,
# Telegram, OCTO, Athena.
_VENDOR = (
    r"(?:A(?:UTOTASK|NTHROPIC|WS|ZURE|THENA)|C(?:LOUDFLARE|F|ONNECTWISE)|D(?:ATTO|UO|ISCORD)"
    r"|G(?:ITHUB|H|RAPH|OOGLE|CP)|HUNTRESS|I(?:NFOCYTE|T_?GLUE)|KASEYA|M(?:S_?GRAPH|365|AILGUN)"
    r"|NEXTDNS|O(?:PENAI|KTA|CTO)|P(?:AGERDUTY|OSTMARK)|R(?:OCKET_?CYBER|ESEND)"
    r"|S(?:ENTINEL_?ONE|CREENCONNECT|LACK|PLASHTOP|OPHOS|ENDGRID)"
    r"|T(?:AILSCALE|S|EAMVIEWER|WILIO|ELEGRAM)|UNIFI|WAZUH)"
)
_VENDOR_SUFFIX = (
    r"(?:API_?KEY|AUTH_?KEY|SECRET_?KEY|API_?SECRET|CLIENT_?SECRET|WEBHOOK_?SECRET|PRIVATE_?KEY"
    r"|ACCESS_?TOKEN|INTEGRATION_?CODE|LICENSE(?:_?KEY)?|KEY|SECRET|TOKEN|PASSWORD|PASS|PWD"
    r"|USERNAME|USER|CREDENTIALS?)"
)
_CLI_WORD = (
    r"(?:license[_-]?key|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|secret[_-]?key"
    r"|client[_-]?secret|secret|token|password|passwd|passphrase|pwd|integration[_-]?code"
    r"|registration[_-]?key|install(?:ation)?[_-]?key|site[_-]?key|activation[_-]?key"
    r"|product[_-]?key|enrol(?:l)?ment[_-]?key|join[_-]?key|pre[_-]?shared[_-]?key|psk)"
)
_VENDOR_PREFIX_RX = re.compile(rf"(?i){_VENDOR}_")
_VENDOR_SUFFIX_RX = re.compile(rf"(?i)_{_VENDOR_SUFFIX}$")
_REG_SECRET_NAME = re.compile(rf"(?i){_SECRET_WORD}|(?:key|licen[cs]e|serial)(?![a-z])")
_REGISTRY_PATH = re.compile(r"^(?:HK(?:LM|CU|CR|U|CC)\b|HKEY_|Registry::|Microsoft\.PowerShell)", re.I)


def _reg_value(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """``reg query`` output: ``LicenseKey    REG_SZ    <value>``."""
    name = m.group("name").strip()
    if not _REG_SECRET_NAME.search(name) or _non_secret_name(re.sub(r"\s+", "_", name)):
        return False
    if purpose == "redact":
        return redactable(value)
    return looks_real(value, min_len=8, min_classes=1, min_entropy=2.5)


def _key_slot(value: str, m: "re.Match[str]", purpose: Purpose, ctx: Context) -> bool:
    """Redact only: ``AccountKey : <v>``, ``/ACCT_KEY=<v>``, ``--key <v>``.
    Aggressive by design (job output is not code); paths stay."""
    name = m.groupdict().get("name") or ""
    if name and _non_secret_name(name):
        return False
    v = value.strip()
    return redactable(v) and not _PATH_OR_URL.match(v) and not _REGISTRY_PATH.match(v)


def _vendor_name(name: str) -> bool:
    """DATTO_API_KEY, AUTOTASK_INTEGRATION_CODE, ROCKETCYBER_..._TOKEN: a
    vendor prefix and a credential suffix."""
    return bool(_VENDOR_PREFIX_RX.match(name) and _VENDOR_SUFFIX_RX.search(name))


_PEM = r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
# A value on an option (--password=<v>, /ACCT_KEY=<v>) is bounded in the
# pattern; redaction goes on to the end of the word with this.
_FLAG_VALUE_TAIL = re.compile(r"[^\s'\"]*")
# Bounded by ASCII letters, digits and dots only: '_' joins words in a file
# or branch name (nmap_<ip>.xml, fix_<ip>, <ip>_dc), and an IP there is as
# public as anywhere else. ASCII digits only ([0-9], not \d): \d also takes
# Arabic-Indic or fullwidth digits, which no address is written in and which
# ipaddress refuses.
_IPV4 = (
    r"(?<![A-Za-z0-9.])(?P<ip>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))(?P<cidr>/[0-9]{1,2})?(?![A-Za-z0-9]|\.[0-9])"
)

DETECTORS: tuple[Detector, ...] = (
    Detector(
        "private-key", re.compile(_PEM), check=_private_key_body,
        redact_pattern=re.compile(
            # The whole block up to its END line; with no END in reach, the
            # header and every base64-looking line after it. The search for
            # END stops at the next BEGIN (no key holds one), so a flood of
            # headers costs the distance between them, not 16 000 characters
            # each (linear either way, but 4 s per MB).
            _PEM + r"(?:(?:(?!-----BEGIN )[\s\S]){0,16000}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
            r"|[^\n]*(?:\r?\n[ \t]*[A-Za-z0-9+/=:,\- ]{16,})*)"
        ),
    ),
    Detector("age-secret-key", re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{58}"), check=_not_placeholder),
    # Lines bounded (a key file's are short): unbounded, every header on a
    # long line scanned to its end for "Private-Lines" (quadratic).
    Detector("putty-private-key",
             re.compile(r"PuTTY-User-Key-File-\d+:[^\n]{0,512}(?:\n[^\n]{0,512}){0,6}Private-Lines")),
    Detector(
        "aws-access-key-id",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
        check=_not_placeholder,
    ),
    Detector(
        "github-token",
        re.compile(
            r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})"
            r"(?![A-Za-z0-9_])"
        ),
        check=_not_placeholder,
    ),
    Detector(
        # Bounded value: a rejected candidate's value can hold the next start
        # ("xoxb-xoxb-..."), so an unbounded one makes each restart run to the
        # end of the token again (quadratic). Real tokens are well under 250;
        # a token right after '-' is still found (and still redacted).
        "slack-token", re.compile(r"(?<![A-Za-z0-9])xox[abposre]-[A-Za-z0-9-]{10,250}"),
        check=_not_placeholder,
    ),
    Detector(
        "slack-webhook",
        re.compile(r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{20,}"),
        check=_not_placeholder,
    ),
    Detector(
        "anthropic-key", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}"),
        check=_alnum_mix,
    ),
    Detector(
        "openai-style-key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
        check=_alnum_mix,
    ),
    Detector(
        "resend-key", re.compile(r"(?<![A-Za-z0-9_])re_[A-Za-z0-9]{6,}_[A-Za-z0-9_]{16,}"),
        check=_alnum_mix,
    ),
    Detector(
        "stripe-key", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
        check=_not_placeholder,
    ),
    Detector(
        "google-api-key", re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
        check=_not_placeholder,
    ),
    Detector(
        "tailscale-key",
        re.compile(r"(?<![A-Za-z0-9_-])tskey-(?:[a-z]+-)?[A-Za-z0-9]{6,}-[A-Za-z0-9]{10,}"),
        check=_alnum_mix,
    ),
    Detector(
        "webhook-signing-secret",
        # Bounded value (quadratic otherwise, as for slack-token); real
        # signing secrets are 30-60 characters. '=' / '-' / '/' may precede it.
        re.compile(r"(?<![A-Za-z0-9_])whsec_[A-Za-z0-9+/_-]{24,200}={0,2}(?![A-Za-z0-9+/_=-])"),
        check=_whsec,
    ),
    Detector(
        "itglue-api-key",
        re.compile(
            r"(?<![A-Za-z0-9_.-])ITG\.[A-Za-z0-9]{16,128}(?:\.[A-Za-z0-9_-]{16,256})?(?![A-Za-z0-9_-])"
        ),
        check=_itglue,
    ),
    Detector(
        "telegram-bot-token",
        re.compile(r"(?<![A-Za-z0-9_:-])(?:bot)?(?P<v>[0-9]{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])"),
        group="v", check=_telegram,
    ),
    Detector(
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        ),
        check=_jwt,
    ),
    Detector(
        # One segment, not a JWT part: nothing but padding may follow it.
        "cloudflare-tunnel-token",
        re.compile(r"(?<![A-Za-z0-9+/_.-])eyJ[A-Za-z0-9+/_-]{40,1600}={0,2}(?![A-Za-z0-9+/_=.-])"),
        check=_cf_tunnel,
    ),
    Detector("fernet-token", re.compile(r"(?<![A-Za-z0-9_-])gAAAAA[A-Za-z0-9_-]{40,}={0,2}"),
             check=_not_placeholder),
    Detector(
        "bitlocker-recovery-key", re.compile(r"(?<![\d-])\d{6}(?:-\d{6}){7}(?![\d-])"),
        check=_bitlocker,
    ),
    Detector(
        "windows-product-key",
        re.compile(r"(?<![A-Za-z0-9-])[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}(?![A-Za-z0-9-])"),
        check=_product_key,
    ),
    Detector(
        "url-credentials",
        re.compile(
            r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@'\"<>{}]{0,64}:"
            r"(?P<v>[^\s/@'\"<>{}]{1,128})@[A-Za-z0-9.\[\]_-]+"
        ),
        group="v", check=_real(min_len=4, min_classes=1, min_entropy=1.5), needles=("://",),
    ),
    Detector(
        "bearer-token",
        re.compile(r"(?i)\bbearer[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{16,})"),
        group="v", check=_real(min_len=16, min_classes=2, min_entropy=3.0),
    ),
    Detector(
        "basic-auth-header",
        re.compile(
            r"(?i)\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?basic[ \t]+(?P<v>[A-Za-z0-9+/]{12,}={0,2})"
        ),
        group="v", check=_real(min_len=12, min_classes=2, min_entropy=3.0),
    ),
    Detector(
        "url-query-secret",
        re.compile(
            # & also as JSON's \u0026 and HTML's &amp; (a Teams / Power Automate
            # workflow URL's sig= in a JSON config or an HTML page). A value
            # ends at a backslash (an escaped &, \n, \"), except JSON's escaped
            # slash \/, which a value may carry (PHP's json_encode writes it).
            # A '?' that opens the next name= ends the value: otherwise each
            # "?key=" of a run is a candidate whose value runs to the end of
            # the line, and judging them all is quadratic.
            r"(?i)(?:[?&]|\\u0026|&amp;)(?:access_token|api_?key|key|token|secret|client_secret|password"
            r"|passwd|pwd|sig|signature|auth|code|license_?key)="
            r"(?P<v>(?:[^&\s'\"#<>\\?]|\\/|\?(?![\w.-]{1,40}=)){8,})"
        ),
        group="v", check=_real(min_len=12, min_classes=2, min_entropy=3.0),
    ),
    Detector(
        "cli-secret-flag",
        re.compile(
            rf"(?i)(?<![\w-])(?:--?|/(?=[a-z0-9_-]*?{_CLI_WORD}[=:]))"
            rf"(?P<name>[a-z0-9_-]*?{_CLI_WORD})(?:[ \t]*[=:][ \t]*|[ \t]+)"
            # Bounded: a rejected value ("--password=--password=...") would
            # otherwise run to the end of the token from every option in it.
            r"(?P<q>['\"]?)(?P<v>[^\s'\"]{3,400})"
        ),
        group="v", check=_cli_flag, redact_tail=_FLAG_VALUE_TAIL,
    ),
    Detector(
        # Redact only: --key <v>, --license <v>, /ACCT_KEY=<v>, -OrgKey <v>.
        "cli-key-flag",
        re.compile(
            r"(?i)(?<![\w-])(?:--?|/)(?=(?P<name>[a-z][a-z0-9_-]{0,40}))(?P=name)"
            r"(?:(?<=key)|(?<=license)|(?<=licence))"
            r"(?:[ \t]*[=:][ \t]*|[ \t]+)(?P<q>['\"]?)(?P<v>[^\s'\"]{3,400})"
        ),
        group="v", check=_key_slot, scan=False, redact_tail=_FLAG_VALUE_TAIL,
    ),
    Detector(
        "xml-secret-element",
        re.compile(
            r"(?i)<(?P<tag>keyMaterial|password|passwd|secret|client_?secret|api_?key"
            r"|license_?key|token|access_?token|private_?key)(?:[ \t\r\n][^<>]{0,300})?>"
            r"(?P<v>[^<]{3,})</(?P=tag)>"
        ),
        group="v", check=_real(min_len=8),
    ),
    Detector(
        "html-secret-field",
        re.compile(
            # <input name="api_key" value="..."> in either attribute order.
            rf"(?i)<(?:input|meta|param)\b(?=[^<>]{{0,400}}?\b(?:name|id)[ \t]*=[ \t]*[\"']"
            rf"(?P<name>[\w.\-\[\]]{{0,60}}?{_SECRET_WORD}[\w.\-\[\]]{{0,60}})[\"'])"
            r"[^<>]{0,400}?\b(?:value|content)[ \t]*=[ \t]*[\"'](?P<v>[^\"'\n]{1,400})[\"']"
        ),
        group="v", check=_assignment(min_len=8, min_classes=2, min_entropy=2.5),
    ),
    Detector(
        "registry-secret-value",
        re.compile(
            r"(?im)^[ \t]*(?P<name>[A-Za-z][\w .-]{0,80}?)[ \t]+REG_(?:SZ|EXPAND_SZ|MULTI_SZ)"
            r"[ \t]+(?P<v>[^\r\n]{1,400}?)[ \t]*$"
        ),
        group="v", check=_reg_value,
    ),
    Detector(
        "wifi-key-content",
        re.compile(r"(?im)^[ \t]*Key Content[ \t]*:[ \t]*(?P<v>\S[^\r\n]*)$"),
        group="v", check=_real(min_len=8, min_classes=1, min_entropy=2.0),
    ),
    Detector(
        # Before the named rules: KEY_BASE64=<v> is reported as what it is.
        "fernet-or-base64-key",
        re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{43}=(?![A-Za-z0-9+/_=-])"),
        check=_base64_key, redact=False,
    ),
    Detector(
        "vendor-credential",
        re.compile(
            # The whole identifier is taken atomically ((?=(…))(?P=…)) so a long
            # run cannot make the engine backtrack quadratically; the name's
            # shape is checked in Python (_vendor_name).
            rf"(?i)(?<![A-Za-z0-9_])(?={_VENDOR}_)(?=(?P<name>[A-Za-z0-9_]{{1,80}}))(?P=name)"
            rf"(?![A-Za-z0-9_]){_SEP}{_VALUE}"
        ),
        group="value",
        check=_assignment(min_len=8, min_classes=1, min_entropy=2.0, name_ok=_vendor_name),
    ),
    Detector(
        "secret-assignment",
        re.compile(
            rf"(?i)(?<![A-Za-z0-9_.\-])(?=[A-Za-z0-9_.\-]{{0,80}}?{_SECRET_WORD})"
            rf"(?=(?P<name>[A-Za-z0-9_.\-]{{1,120}}))(?P=name){_SEP}{_VALUE}"
        ),
        group="value", check=_assignment(min_len=8, min_classes=2, min_entropy=2.5),
    ),
    Detector(
        # A label in prose, a docstring or a note: "Signing key: <v>".
        "labelled-secret",
        re.compile(
            rf"(?i)(?<=[A-Za-z])[ ](?P<kw>key|code|secret|token|passphrase)(?![A-Za-z0-9_-])"
            rf"[ \t]*(?::|=)[ \t]*{_VALUE}"
        ),
        group="value", check=_labelled,
    ),
    # After the named rules (PGPASSWORD=<v> stays a secret-assignment):
    # sshpass -p <v>, curl -u user:<v>, mysql -p<v>, net use ... <v>, ...
    # One detector per option shape, all reported as cli-password.
    *_cli_detectors(),
    Detector(
        # Redact only: AccountKey : <v> (Format-List), ORG_KEY=<v>, "SiteKey": <v>.
        "key-named-value",
        re.compile(
            rf"(?i)(?<![A-Za-z0-9_.\-])(?=(?P<name>[A-Za-z][A-Za-z0-9_.\-]{{0,60}}))(?P=name)"
            rf"(?<=key)(?![A-Za-z0-9_]){_SEP}{_VALUE}"
        ),
        group="value", check=_key_slot, scan=False,
    ),
    Detector(
        "high-entropy-string",
        re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])"),
        check=_high_entropy, redact=False, reports=("high-entropy-string", "hex-secret"),
    ),
    # --- publish-only: not secrets, but never in a public copy ----------- #
    Detector("ip-address", re.compile(_IPV4), group="ip", check=_ip_kind,
             publish_only=True, redact=False, reports=("ip-private", "ip-public", "ip-tailnet")),
    Detector("tailnet-ipv6", re.compile(r"(?i)\bfd7a:115c:a1e0:[0-9a-f:]*"),
             publish_only=True, redact=False, needles=("fd7a:" + "115c:a1e0:",)),  # in parts: not a hit here
    Detector(
        "tailnet-name",
        re.compile(
            r"(?i)(?<![a-z0-9-])[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,6}"
            r"\.(?:ts\.net|beta\.tailscale\.net)\b"
        ),
        publish_only=True, redact=False, needles=("ts.net", "tailscale.net"),
    ),
    Detector(
        "home-path",
        re.compile(
            r"(?<![\w.])/(?:home|Users)/(?!<)[A-Za-z0-9._-]+|(?<![\w.])/mnt/[A-Za-z0-9._-]+"
            r"|(?<![\w.])/root/[A-Za-z0-9._-]+|\b[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._ -]+"
        ),
        publish_only=True, redact=False, needles=("/home/", "/users/", "/mnt/", "/root/", "users\\"),
    ),
    Detector("memory-path", re.compile(_MEMORY_PATH),
             publish_only=True, redact=False, needles=(".claude", "-home-", "-users-")),
    Detector("memory-link", re.compile(r"(?i)\[\[[a-z][a-z0-9_.-]{2,100}\]\]"),
             publish_only=True, redact=False, needles=("[[",)),
    Detector(
        "email-address",
        re.compile(
            r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,6}"
            r"\.[A-Za-z]{2,24}\b"
        ),
        check=_email, publish_only=True, redact=False, needles=("@",),
    ),
    Detector(
        "nextdns-profile-id",
        re.compile(
            r"(?i)(?:(?<![\w.-])(?:dns|my|api|apple|link-ip)\.nextdns\.io/(?:profiles/)?"
            r"|nextdns[\w.-]{0,40}?profile[\w-]{0,12}[\"'\]]{0,2}[ \t]*[:=][ \t]*[\"']?"
            r"|(?<![\w.-])(?=[0-9a-f]{6}\.dns\.nextdns\.io))"
            r"(?P<v>[0-9a-f]{6})(?![\w-])"
        ),
        group="v", check=_nextdns_id, publish_only=True, redact=False, needles=("nextdns",),
    ),
    Detector(
        # A path or query segment of a URL; the check finds the URL around it.
        "url-path-token",
        re.compile(
            r"(?<=[/=])[A-Za-z0-9_-]{16,256}(?=[/?&#;,)\]>\"'`\s]|\.(?![A-Za-z0-9])|$)"
        ),
        check=_url_path_token, publish_only=True, redact=False, needles=("://",),
    ),
    Detector(
        # T + yyyymmdd + '.' + 4 digits; also lower case, and joined by '_' (a branch name).
        "psa-ticket-id",
        re.compile(r"(?<![A-Za-z0-9])[Tt](?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\.\d{4}(?!\d)"),
        check=_psa_ticket, publish_only=True, redact=False, needles=("t19", "t20"),
    ),
)

#: Detector names: unique, the priority when two hits overlap. Not what a
#: finding is called (see REPORTED_NAMES).
DETECTOR_NAMES: tuple[str, ...] = tuple(d.name for d in DETECTORS)
_PRIORITY = {d.name: i for i, d in enumerate(DETECTORS)}
#: Every name a finding can carry (ip-address reports ip-private / ip-public /
#: ip-tailnet; every cli-password family reports cli-password).
REPORTED_NAMES: frozenset[str] = frozenset(n for d in DETECTORS for n in d.reported)
PUBLISH_ONLY_NAMES: frozenset[str] = frozenset(n for d in DETECTORS if d.publish_only for n in d.reported)


def _value_span(d: Detector, m: "re.Match[str]") -> Optional[tuple[int, int]]:
    if d.group == "value" or isinstance(d.group, tuple):
        for g in (_VALUE_GROUPS if d.group == "value" else d.group):
            if m.group(g) is not None:
                return m.span(g)
        return None
    if m.group(d.group) is None:
        return None
    return m.span(d.group)


def find_hits(
    text: str,
    ctx: Context = Context(),
    purpose: Purpose = "scan",
    *,
    publish: bool = False,
    only: Optional[AbstractSet[str]] = None,
) -> list[Hit]:
    """Every detector hit in ``text``; where two overlap, the earlier detector
    in :data:`DETECTORS` wins. Sorted by position.

    ``only``: the reported names wanted (a ref name judges token shapes and
    never-public values, not entropy). The others are dropped BEFORE overlaps
    are resolved, so a hit nobody asked for never hides one that was."""
    candidates: list[tuple[int, Hit]] = []
    lowered: Optional[str] = None
    for d in DETECTORS:
        if (purpose == "scan" and not d.scan) or (purpose == "redact" and not d.redact):
            continue
        if d.publish_only and not publish:
            continue
        if only is not None and not any(n in only for n in d.reported):
            continue
        if d.needles:
            if lowered is None:
                lowered = fold_lower(text)
            if not any(n in lowered for n in d.needles):
                continue
        candidates += detector_hits(d, text, ctx, purpose, only=only)
    if purpose == "redact":
        return _merge_overlaps(candidates, text)
    return _resolve_overlaps(candidates)


def detector_hits(
    d: Detector,
    text: str,
    ctx: Context = Context(),
    purpose: Purpose = "scan",
    *,
    only: Optional[AbstractSet[str]] = None,
) -> list[tuple[int, Hit]]:
    """``(priority, hit)`` for every candidate of one detector that its check
    keeps (overlaps not resolved; :func:`find_hits` does that across all
    detectors)."""
    pattern = d.redact_pattern if (purpose == "redact" and d.redact_pattern) else d.pattern
    out: list[tuple[int, Hit]] = []
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if m is None:
            break
        span = _value_span(d, m)
        value = text[span[0]:span[1]] if span else ""
        verdict: Union[bool, str] = bool(value) and _judge(d, value, m, purpose, ctx)
        if not verdict or span is None:
            # Rejected: resume just after the match start, so a secret
            # nested in a rejected candidate is still seen.
            pos = m.start() + 1
            continue
        name = verdict if isinstance(verdict, str) else d.reported[0]
        pos = max(m.end(), m.start() + 1)
        if only is not None and name not in only:
            continue
        start, end = span
        if purpose == "redact":
            if d.group == "value" and m.group("uq") is not None:
                # A bare value is cut at , ; & for scanning; job output is
                # scrubbed to the next blank instead ("password=abc&rest").
                end = _BARE_TAIL.match(text, end).end()
            elif d.redact_tail is not None:
                end = d.redact_tail.match(text, end).end()
            # The next candidate starts after the scrubbed span: one inside it
            # would overlap this hit and be dropped anyway, and judging each
            # (a run of NAME=v;NAME=v;... in one token) is quadratic.
            pos = max(pos, end)
        out.append((_PRIORITY[d.name], Hit(name, start, end, text[start:end], not d.publish_only)))
    return out


_CHECK_FAILURES: set[tuple[str, str, str]] = set()
_CHECK_FAILURES_LOCK = threading.Lock()


def _judge(d: Detector, value: str, m: "re.Match[str]", purpose: Purpose,
           ctx: Context) -> Union[bool, str]:
    """``d.check``, made total. A check that raises on some input is a bug,
    and a bug must neither stop the scan (no finding reported at all, and a
    traceback that may print the value) nor let a value through redaction:
    to scan, the candidate is no hit for that detector (every other detector
    still runs); to redact, it is scrubbed. Either way a warning on stderr
    names the detector and the exception type, never the value or the
    exception's message (which may quote it); once per detector, purpose and
    exception type in a process."""
    if d.check is None:
        return True
    try:
        return d.check(value, m, purpose, ctx)
    except Exception as exc:  # noqa: BLE001 - any bug in a check, see above
        key = (d.name, purpose, type(exc).__name__)
        with _CHECK_FAILURES_LOCK:
            first = key not in _CHECK_FAILURES
            _CHECK_FAILURES.add(key)
        if first:
            outcome = "scrubbed" if purpose == "redact" else "not reported by this detector"
            print(f"WARNING (secret_patterns): the {d.name} check failed ({type(exc).__name__}) on a "
                  f"{len(value)}-character candidate ({purpose}); it was {outcome}. This is a bug: "
                  "report the detector name (never the value).", file=sys.stderr)
        return purpose == "redact"


_BARE_TAIL = re.compile(r"[^\s'\"`<>]*")
# Format-List: "PathName : <value>", a long value wrapped onto lines indented
# to the value column.
_FORMAT_LIST_PROPERTY = re.compile(r"[ \t]*[^\s:][^:\r\n]{0,120}?[ \t]:[ \t]")
_TOKEN = re.compile(r"\S*")


def _value_column(text: str, start: int) -> Optional[int]:
    """The Format-List value column of the line holding ``start``: its own
    ``Name : `` prefix, or, on a continuation line (indented to that column),
    the property line a few lines above."""
    line_start = text.rfind("\n", 0, start) + 1
    m = _FORMAT_LIST_PROPERTY.match(text, line_start)
    if m is not None and m.end() <= start:
        return m.end() - line_start
    head = text[line_start:start]
    indent = len(head) - len(head.lstrip(" "))
    if indent == 0:
        return None
    pos = line_start
    for _ in range(16):
        if pos == 0:
            return None
        prev = text.rfind("\n", 0, pos - 1) + 1
        m = _FORMAT_LIST_PROPERTY.match(text, prev)
        if m is not None and m.end() - prev == indent:
            return indent
        if not text.startswith(" " * indent, prev):
            return None
        pos = prev
    return None


def _wrapped_tail(text: str, start: int, end: int) -> int:
    """Where a redacted value really ends: when it reaches the end of a
    Format-List line, the value continues on the next line if that line is
    indented exactly to the value column (PowerShell wraps at the host
    width, mid-token)."""
    if not text.startswith(("\n", "\r\n"), end):
        return end  # checked first: at most one hit per line gets further
    col = _value_column(text, start)
    if not col:
        return end
    for _ in range(64):
        if text.startswith("\r\n", end):
            nxt = end + 2
        elif text.startswith("\n", end):
            nxt = end + 1
        else:
            return end
        if text[nxt:nxt + col] != " " * col or text[nxt + col:nxt + col + 1].isspace() \
                or nxt + col >= len(text):
            return end
        end = _TOKEN.match(text, nxt + col).end()
    return end


def _merge_overlaps(candidates: list[tuple[int, Hit]], text: str) -> list[Hit]:
    """Redaction: the UNION of every overlapping candidate, labelled by the
    highest-priority detector in it. Dropping the lower-priority one (as a
    scan does) would leave its part of the text in clear: an assignment
    scrubbed to the end of its word, with a token shape inside that word,
    must scrub both."""
    merged: list[list] = []  # [start, end, priority, hit]
    for prio, hit in sorted(candidates, key=lambda c: (c[1].start, c[0])):
        if merged and hit.start < merged[-1][1]:
            last = merged[-1]
            last[1] = max(last[1], hit.end)
            if prio < last[2]:
                last[2], last[3] = prio, hit
            continue
        merged.append([hit.start, hit.end, prio, hit])
    return [Hit(h.detector, start, end, text[start:end], h.secret) for start, end, _, h in merged]


def _resolve_overlaps(candidates: list[tuple[int, Hit]]) -> list[Hit]:
    starts: list[int] = []
    kept: list[Hit] = []
    for _, hit in sorted(candidates, key=lambda c: (c[0], c[1].start)):
        i = bisect.bisect_left(starts, hit.start)
        if i > 0 and kept[i - 1].end > hit.start:
            continue
        if i < len(kept) and kept[i].start < hit.end:
            continue
        starts.insert(i, hit.start)
        kept.insert(i, hit)
    return kept


def redact(text: str) -> tuple[str, int]:
    """Replace every secret-shaped value in ``text`` with ``[REDACTED:<detector>]``.

    Returns the scrubbed text and how many values were replaced. Idempotent:
    a redaction marker is never itself redacted."""
    if not text:
        return text, 0
    hits = find_hits(text, purpose="redact")
    if not hits:
        return text, 0
    spans: list[tuple[int, int, str]] = []
    for h in hits:
        end = _wrapped_tail(text, h.start, h.end)
        if spans and h.start < spans[-1][1]:  # a wrapped tail reached the next hit
            spans[-1] = (spans[-1][0], max(spans[-1][1], end), spans[-1][2])
            continue
        spans.append((h.start, end, h.detector))
    out: list[str] = []
    pos = 0
    for start, end, detector in spans:
        out.append(text[pos:start])
        out.append(f"[REDACTED:{detector}]")
        pos = end
    out.append(text[pos:])
    return "".join(out), len(spans)
